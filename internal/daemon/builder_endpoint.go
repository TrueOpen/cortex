package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/natsidentity"
	"github.com/TrueOpen/cortex/internal/worker"
)

// Endpoint sources, reported in diagnostics so an operator can tell an
// authoritative resolution from a bootstrap one.
const (
	BuilderEndpointSourceDescriptor = "descriptor"
	BuilderEndpointSourceBootstrap  = "bootstrap"
)

// BuilderEndpoint is where a Builder's Nexus can be reached, plus the service
// key that signs its material.
type BuilderEndpoint struct {
	AuthorizationNonce uint64
	OperatorAddress    string
	Endpoint           string
	ServicePubkey      string
	// TLSPubkeyHash is the descriptor's tls_pubkey_hash as 64 lowercase hex, or
	// "" when the Builder published none. Callers put it in the request context
	// (builderclient.WithTLSPubkeyHash) so the dial checks the certificate key.
	TLSPubkeyHash     string
	Source            string
	DescriptorVersion uint64
	SnapshotHeight    uint64
}

// PinnedContext returns ctx carrying this endpoint's tls_pubkey_hash for the
// task-data client to verify at dial time; a nil-pin endpoint returns ctx as is.
func (e BuilderEndpoint) PinnedContext(ctx context.Context) context.Context {
	return builderclient.WithTLSPubkeyHash(ctx, e.TLSPubkeyHash)
}

// BuilderEndpointResolver resolves the Nexus endpoint of a Builder operator.
type BuilderEndpointResolver interface {
	ResolveBuilderEndpoint(ctx context.Context, operatorAddress string) (BuilderEndpoint, error)
}

// receivingBuilders is the single place that answers "which Builder receives
// this task's material". Today it reads the one compatibility operator persisted
// from an authenticated data-ready control sender and resolves that Builder's
// descriptor. The frozen contract publishes the authoritative per-task list in
// TaskBuilderSelectionState.selected_task_builders instead; when QueryTaskBuilders
// is serveable, this implementation changes and the Worker relay path does not.
type receivingBuilders struct {
	endpoints BuilderEndpointResolver
}

// NewReceivingBuilders adapts the Builder endpoint resolver into the Worker's
// receiving-Builder seam. A nil resolver yields a nil provider, so the Worker
// fails closed rather than relaying to an unverified endpoint.
func NewReceivingBuilders(endpoints BuilderEndpointResolver) worker.ReceivingBuilderProvider {
	if endpoints == nil {
		return nil
	}
	return receivingBuilders{endpoints: endpoints}
}

func (r receivingBuilders) ResolveReceivingBuilder(
	ctx context.Context,
	task worker.ReceivingBuilderRef,
) (worker.BuilderEndpoint, error) {
	return r.resolve(ctx, task, r.endpoints.ResolveBuilderEndpoint)
}

// RefreshReceivingBuilder re-reads past the descriptor cache
// (worker.ReceivingBuilderRefresher); it falls back to an ordinary resolve when the
// underlying resolver does not support refreshing.
func (r receivingBuilders) RefreshReceivingBuilder(
	ctx context.Context,
	task worker.ReceivingBuilderRef,
) (worker.BuilderEndpoint, error) {
	if refresher, ok := r.endpoints.(BuilderEndpointRefresher); ok {
		return r.resolve(ctx, task, refresher.RefreshBuilderEndpoint)
	}
	return r.resolve(ctx, task, r.endpoints.ResolveBuilderEndpoint)
}

func (r receivingBuilders) resolve(
	ctx context.Context,
	task worker.ReceivingBuilderRef,
	lookup func(context.Context, string) (BuilderEndpoint, error),
) (worker.BuilderEndpoint, error) {
	operator := strings.TrimSpace(task.AssignedBuilderOperator)
	if operator == "" || operator != task.AssignedBuilderOperator {
		return worker.BuilderEndpoint{}, fmt.Errorf(
			"receiving Builder operator is required and must be canonical",
		)
	}
	endpoint, err := lookup(ctx, operator)
	if err != nil {
		return worker.BuilderEndpoint{}, err
	}
	if endpoint.OperatorAddress != operator {
		return worker.BuilderEndpoint{}, fmt.Errorf(
			"resolve receiving Builder for task %s/%s: resolved identity %q does not match the assigned Builder %q",
			task.SessionID, task.TaskID, endpoint.OperatorAddress, operator,
		)
	}
	return worker.BuilderEndpoint{
		OperatorAddress:    endpoint.OperatorAddress,
		Endpoint:           endpoint.Endpoint,
		ServicePubkey:      endpoint.ServicePubkey,
		TLSPubkeyHash:      endpoint.TLSPubkeyHash,
		CurrentHeight:      endpoint.SnapshotHeight,
		AuthorizationNonce: endpoint.AuthorizationNonce,
	}, nil
}

// builderServiceKeyReader reads the bootstrap Builder's current service key from
// the latest committed state and reports the height it was served at, so the
// revocation check and the reported SnapshotHeight are bound to that one read. It
// replaces the earlier pairing of a /status height with a query pinned to it,
// which the chain rejects at a commit boundary.
type builderServiceKeyReader interface {
	CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error)
}

// builderEndpoints resolves a Builder endpoint from the authoritative on-chain
// descriptor, falling back to the locally configured ingress only for the one
// Builder an operator explicitly named, and only when plaintext transport was
// explicitly accepted. Static configuration is a bootstrap hint, never a
// substitute for the chain view.
type builderEndpoints struct {
	directory         *builderdirectory.Resolver
	keeper            builderServiceKeyReader
	bootstrapOperator string
	bootstrapEndpoint string
	allowBootstrap    bool
}

func newBuilderEndpoints(directory *builderdirectory.Resolver, keeper builderServiceKeyReader, bootstrapOperator, bootstrapEndpoint string, allowBootstrap bool) *builderEndpoints {
	return &builderEndpoints{
		directory:         directory,
		keeper:            keeper,
		bootstrapOperator: strings.TrimSpace(bootstrapOperator),
		bootstrapEndpoint: strings.TrimSpace(bootstrapEndpoint),
		allowBootstrap:    allowBootstrap,
	}
}

func (b *builderEndpoints) ResolveBuilderEndpoint(ctx context.Context, operatorAddress string) (BuilderEndpoint, error) {
	operator := strings.TrimSpace(operatorAddress)
	if operator == "" || operator != operatorAddress {
		return BuilderEndpoint{}, fmt.Errorf("Builder operator address is required and must be canonical")
	}
	var descriptorErr error
	if b.directory != nil {
		identity, err := b.directory.Resolve(ctx, operator)
		switch {
		case err == nil:
			pin := ""
			if hash, present := identity.EndpointTLSPubkeyHash.Hash(); present {
				pin = hash.String()
			}
			return BuilderEndpoint{
				OperatorAddress:    operator,
				Endpoint:           identity.Endpoint,
				ServicePubkey:      identity.ServicePubkey,
				AuthorizationNonce: identity.AuthorizationNonce,
				TLSPubkeyHash:      pin,
				Source:             BuilderEndpointSourceDescriptor,
				DescriptorVersion:  identity.DescriptorVersion,
				SnapshotHeight:     identity.SnapshotHeight,
			}, nil
		case errors.Is(err, builderdirectory.ErrNoCurrentDescriptor):
			// The only failure a bootstrap endpoint may answer.
			descriptorErr = err
		default:
			// A descriptor exists and did not verify. Under the on-chain model
			// that is either an unusable row or an endpoint Cortex must not
			// dial: an uncheckable tls_pubkey_hash, a plaintext endpoint without
			// the opt-in, a scheme this build cannot dial, a uri whose shape
			// consensus would never have accepted, a duplicate endpoint kind, a
			// descriptor_version the Builder's own row no longer calls current,
			// or a service key that is not ACTIVE for this Builder.
			//
			// None of the retired document failures apply: d8792e6 deleted
			// descriptor_uri, schema_version and expires_height, so there is no
			// document hash to mismatch, no expiry and no redirect to refuse.
			// Falling back would discard exactly the check that failed.
			return BuilderEndpoint{}, err
		}
	}
	endpoint, err := b.bootstrap(ctx, operator, descriptorErr)
	if err != nil {
		return BuilderEndpoint{}, err
	}
	return endpoint, nil
}

// RefreshBuilderEndpoint invalidates the descriptor cache and resolves again
// (BuilderEndpointRefresher).
func (b *builderEndpoints) RefreshBuilderEndpoint(ctx context.Context, operatorAddress string) (BuilderEndpoint, error) {
	if b.directory != nil {
		b.directory.Invalidate(strings.TrimSpace(operatorAddress))
	}
	return b.ResolveBuilderEndpoint(ctx, operatorAddress)
}

// bootstrap is the deliberately narrow escape hatch: it applies to exactly the
// Builder named in configuration, requires the plaintext opt-in, and still reads
// that Builder's current service key from chain so Builder-signed material can
// be verified.
func (b *builderEndpoints) bootstrap(ctx context.Context, operator string, descriptorErr error) (BuilderEndpoint, error) {
	switch {
	case b.bootstrapEndpoint == "" || b.bootstrapOperator == "":
		return BuilderEndpoint{}, endpointFailure(operator, descriptorErr, "no service descriptor and no configured bootstrap endpoint")
	case operator != b.bootstrapOperator:
		return BuilderEndpoint{}, endpointFailure(operator, descriptorErr, "the configured bootstrap endpoint belongs to another Builder")
	case !b.allowBootstrap:
		return BuilderEndpoint{}, endpointFailure(operator, descriptorErr, "a bootstrap endpoint requires nexus.allow_insecure_descriptor")
	case b.keeper == nil:
		return BuilderEndpoint{}, endpointFailure(operator, descriptorErr, "Keeper service key reader is required")
	}
	key, height, err := b.keeper.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, operator)
	if err != nil {
		return BuilderEndpoint{}, err
	}
	if height == 0 {
		return BuilderEndpoint{}, fmt.Errorf("resolve Builder %s bootstrap endpoint: Keeper served no committed height for the current service key", operator)
	}
	if err := builderdirectory.ValidateServiceKey(key, operator, height); err != nil {
		return BuilderEndpoint{}, err
	}
	if key.CurrentDescriptorVersion.Uint64() != 0 {
		return BuilderEndpoint{}, builderclient.Retryable(fmt.Errorf("Builder %s has a current descriptor; resolve its published endpoint before bootstrapping", operator))
	}
	return BuilderEndpoint{
		OperatorAddress:    operator,
		Endpoint:           b.bootstrapEndpoint,
		ServicePubkey:      key.ServicePubkey,
		AuthorizationNonce: key.AuthorizationNonce.Uint64(),
		Source:             BuilderEndpointSourceBootstrap,
		SnapshotHeight:     height,
	}, nil
}

func endpointFailure(operator string, descriptorErr error, reason string) error {
	if descriptorErr != nil {
		return fmt.Errorf("resolve Builder %s endpoint: %s: %w", operator, reason, descriptorErr)
	}
	return fmt.Errorf("resolve Builder %s endpoint: %s", operator, reason)
}

// natsSentinelIngress answers "which Builders may be asked for the NATS AUTH
// sentinel" (natsidentity.BuilderIngressResolver).
//
// Who is chosen: with nexus.builder_operator_address configured it is that one alone
// - config may only narrow the range this node accepts, never widen it - and without
// it every member of the active on-chain BuilderSet is offered in order, so
// consensus answers rather than a local file. A sentinel is public material and the
// one any live Builder hands over gets through the gate an operator-mode server puts
// at CONNECT, while the real identity is still decided by the on-chain binding inside
// auth_token; so a member being offline or serving no sentinel eliminates only itself
// (in integration the first member's genesis descriptor is exactly a plaintext
// endpoint nobody listens on, while nexus1 in the same set serves normally).
//
// Which origin is dialled: the same policy as the task-data client
// (TaskDataTransport), so an endpoint that descriptor resolution would refuse cannot
// be dialled from here either - the reason for that refusal travels out as this
// candidate's Err and into the summary error.
type natsSentinelIngress struct {
	operator string
	// members / endpoints are accessor functions rather than values: the Binder has to
	// be assembled before the NATS connection exists, while the BuilderSet and the
	// endpoint resolver take shape further down in runtime assembly. The sentinel is
	// fetched on the first (re)connect, by which time both are in place.
	members   func() *builderdirectory.Membership
	endpoints func() BuilderEndpointResolver
	transport builderclient.TaskDataTransport
}

func (r natsSentinelIngress) ResolveIngresses(ctx context.Context) ([]natsidentity.BuilderIngress, error) {
	operators, err := r.builders(ctx)
	if err != nil {
		return nil, err
	}
	endpoints := r.endpoints()
	if endpoints == nil {
		return nil, fmt.Errorf("resolve Builder ingress for the nats sentinel: endpoint resolver is unavailable")
	}
	candidates := make([]natsidentity.BuilderIngress, 0, len(operators))
	for _, operator := range operators {
		candidates = append(candidates, r.candidate(ctx, endpoints, operator))
	}
	return candidates, nil
}

// candidate resolves one candidate. A failed resolve is not an overall failure: the
// reason stays in Err for the sentinel source to summarise, and the next candidate
// is tried as usual.
func (r natsSentinelIngress) candidate(ctx context.Context, endpoints BuilderEndpointResolver, operator string) natsidentity.BuilderIngress {
	endpoint, err := endpoints.ResolveBuilderEndpoint(ctx, operator)
	if err != nil {
		return natsidentity.BuilderIngress{Operator: operator, Err: err}
	}
	parsed, err := builderclient.ParseNexusEndpoint(endpoint.Endpoint)
	if err != nil {
		return natsidentity.BuilderIngress{Operator: operator, Err: fmt.Errorf("ingress %q: %w", endpoint.Endpoint, err)}
	}
	if r.transport.DowngradeEndpointTLS {
		parsed = parsed.WithoutTLS()
	}
	if parsed.Plaintext && !r.transport.AllowInsecureEndpoint {
		return natsidentity.BuilderIngress{Operator: operator, Err: fmt.Errorf("ingress %s is plaintext: set nexus.allow_insecure_descriptor to accept it", parsed.DialURI)}
	}
	return natsidentity.BuilderIngress{Operator: operator, Endpoint: parsed.DialURI, TLSPubkeyHash: endpoint.TLSPubkeyHash}
}

// builders gives the candidate order: narrowed to one by config, otherwise the
// member order of the active on-chain BuilderSet.
func (r natsSentinelIngress) builders(ctx context.Context) ([]string, error) {
	if operator := strings.TrimSpace(r.operator); operator != "" {
		return []string{operator}, nil
	}
	members := r.members()
	if members == nil {
		return nil, fmt.Errorf("pick a Builder for the nats sentinel: the current BuilderSet is unreadable and nexus.builder_operator_address is not set")
	}
	set, err := members.Current(ctx)
	if err != nil {
		return nil, fmt.Errorf("pick a Builder for the nats sentinel: %w", err)
	}
	operators := make([]string, 0, len(set.Builders))
	for _, builder := range set.Builders {
		if operator := strings.TrimSpace(builder); operator != "" {
			operators = append(operators, operator)
		}
	}
	if len(operators) == 0 {
		return nil, fmt.Errorf("pick a Builder for the nats sentinel: the current BuilderSet has no active builder")
	}
	return operators, nil
}
