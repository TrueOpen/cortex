// Package builderdirectory resolves the authoritative network identity of a
// Builder operator: the endpoint its Nexus serves on, and the service key that
// signs its material.
//
// The endpoint list is on chain. ServiceDescriptorV1 carries
// repeated ServiceEndpointV1 in consensus state (TrueOpen/node
// contract/proto-v1-all-domains d8792e6
// proto/hub/v1/participant_identity.proto:31-33), so resolution is three
// chain reads and no network fetch. The earlier model — a descriptor_uri
// commitment plus an off-chain JSON document Cortex fetched and hashed — is
// gone: the frozen contract deleted descriptor_uri, schema_version and
// expires_height from the wire.
//
// BuilderSet membership, the current service key, and the descriptor are read at
// one pinned height; a Builder that left the active set still serves the Task
// data it received, so status is reported rather than enforced.
package builderdirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
)

// ErrNoCurrentDescriptor reports that the Builder has never published a service
// descriptor. It is the only resolution failure a caller may answer with a
// bootstrap endpoint: every other failure means a descriptor exists and did not
// verify, which must stay fail-closed.
var ErrNoCurrentDescriptor = errors.New("Builder has no current service descriptor")

// ErrPlaintextEndpoint reports a refused plaintext endpoint. It is a policy
// rejection, not a transport failure, so it must never be reported as
// retryable, and it is the one refusal nexus.allow_insecure_descriptor relaxes.
var ErrPlaintextEndpoint = errors.New("plaintext endpoint requires nexus.allow_insecure_descriptor")

// ErrPinnedPlaintextEndpoint reports a plaintext (http:// or grpc://) endpoint
// that nevertheless commits a tls_pubkey_hash.
//
// tls_pubkey_hash is sha256 of the certificate's SubjectPublicKeyInfo DER,
// published by nexus next to its self-signed certificate (TrueOpen/nexus#63)
// and checked by builderclient at dial time. On a TLS endpoint the pin is
// carried through Identity.EndpointTLSPubkeyHash for that check. On a plaintext
// endpoint there is no certificate to check it against, so a present pin is a
// contradiction in the published row: the operator asked for a key to be
// verified on a transport that has no key. It is refused under every
// configuration — nexus.allow_insecure_descriptor admits plaintext, it does not
// admit a check that can never run.
var ErrPinnedPlaintextEndpoint = errors.New(
	"endpoint publishes a tls_pubkey_hash on a plaintext scheme; a pin can only be checked on https:// or grpcs://, " +
		"so this row is contradictory and is refused",
)

// nexusEndpointKind is the endpoint Cortex resolves for Builder Task data. It is
// named explicitly, never inferred from list position or from the URI scheme:
// the descriptor may also carry OBJECT_GATEWAY_HTTPS and HEALTH_HTTPS, and those
// are different services.
const nexusEndpointKind = chainclient.EndpointKindNexusGRPC

// KeeperReader is the chain state this package needs. It is satisfied by
// *chainclient.KeeperHTTPClient.
//
// CommittedBuilder both starts the resolution and fixes the height it runs at:
// the height it reports is the height the application served Builder state from,
// so the descriptor and service-key reads pinned to it are queryable by
// construction. There is deliberately no chain-height reader here; CometBFT's
// /status height can lead the application's committed height, and pinning that
// made the chain reject the whole resolution.
type KeeperReader interface {
	CommittedBuilder(ctx context.Context, builderAddress string) (chainclient.BuilderStateSnapshot, uint64, error)
	ServiceDescriptor(ctx context.Context, participantType, operatorAddress string, snapshotHeight uint64) (chainclient.ServiceDescriptorSnapshot, error)
	CurrentServiceKey(ctx context.Context, participantType, operatorAddress string, snapshotHeight uint64) (chainclient.ServiceKeySnapshot, error)
}

// Identity is a resolved Builder network identity, valid as of SnapshotHeight.
type Identity struct {
	AuthorizationNonce uint64
	OperatorAddress    string
	// Endpoint is the NEXUS_GRPC uri exactly as the descriptor publishes it.
	Endpoint string
	// EndpointProtocolVersion is that endpoint's protocol_version. Consensus
	// requires it non-empty; it is carried through so a caller can refuse a
	// protocol it does not speak instead of discovering it at dial time.
	EndpointProtocolVersion string
	// EndpointTLSPubkeyHash is the optional pin on that endpoint. Absent is the
	// devnet norm and stays visibly absent: nothing downstream may read it as
	// "pinned to the zero digest".
	EndpointTLSPubkeyHash chainclient.OptionalHash32
	DescriptorVersion     uint64
	DescriptorHash        string
	ServiceAddress        string
	ServicePubkey         string
	SnapshotHeight        uint64
}

type Options struct {
	// AllowInsecure admits an http:// endpoint. It is a devnet-only concession:
	// nexus's ingress terminates no TLS at all (TrueOpen/nexus b201a98
	// internal/ingress/server.go:140-143 serves h2c), and V1 Task data is
	// application plaintext, so production must leave this false.
	//
	// It relaxes exactly one refusal, ErrPlaintextEndpoint. It does not relax
	// ErrPinnedPlaintextEndpoint, it does not admit grpc:// or grpcs://, and
	// there is nothing left for it to relax about document fetching because
	// there is no document.
	AllowInsecure bool
	// CacheTTL bounds how long a resolved identity is reused before the chain is
	// asked again. Zero selects DefaultCacheTTL. Correctness does not depend on
	// it: entries are dropped on the chain events that change them, and a value
	// read at a lower committed height never replaces a higher one.
	CacheTTL time.Duration
	// Now is injectable for tests; it defaults to wall clock UTC.
	Now func() time.Time
}

type Resolver struct {
	keeper        KeeperReader
	allowInsecure bool
	cache         *cache[Identity]
}

func New(keeper KeeperReader, opts Options) (*Resolver, error) {
	if keeper == nil {
		return nil, fmt.Errorf("builder directory requires a Keeper reader")
	}
	return &Resolver{
		keeper:        keeper,
		allowInsecure: opts.AllowInsecure,
		cache:         newCache[Identity](opts.CacheTTL, opts.Now),
	}, nil
}

// Resolve reads the Builder state, its current descriptor, and its current
// service key at one pinned height, and returns the identity only when the
// descriptor is the current one and its NEXUS_GRPC endpoint passes the transport
// rules. Any failure is fail-closed: callers must not fall back to a configured
// or self-reported endpoint.
//
// The pinned height is the height Keeper served the Builder state from, not a
// height read ahead of time from /status: every subsequent read is pinned to a
// height the application has already committed, and SnapshotHeight reports that
// same height.
//
// A successful resolution is cached for CacheTTL and shared by concurrent
// callers, so a burst of Tasks for one Builder is one resolution rather than one
// per Task. Failures are never cached, and an identity read at a lower committed
// height never replaces a higher one.
func (r *Resolver) Resolve(ctx context.Context, operatorAddress string) (Identity, error) {
	operator := strings.TrimSpace(operatorAddress)
	if operator == "" || operator != operatorAddress {
		return Identity{}, fmt.Errorf("Builder operator address is required and must be canonical")
	}
	return r.cache.get(ctx, operator, func(ctx context.Context) (Identity, uint64, error) {
		identity, err := r.resolveOnChain(ctx, operator)
		if err != nil {
			return Identity{}, 0, err
		}
		return identity, identity.SnapshotHeight, nil
	})
}

func (r *Resolver) resolveOnChain(ctx context.Context, operator string) (Identity, error) {
	builder, height, err := r.keeper.CommittedBuilder(ctx, operator)
	if err != nil {
		return Identity{}, normalizeRetryable(err)
	}
	if height == 0 {
		return Identity{}, builderclient.Retryable(fmt.Errorf("chain height is not available"))
	}
	descriptorVersion := builder.CurrentDescriptorVersion.Uint64()
	if descriptorVersion == 0 {
		return Identity{}, fmt.Errorf("%w: %s", ErrNoCurrentDescriptor, operator)
	}
	descriptor, err := r.keeper.ServiceDescriptor(ctx, chainclient.ParticipantTypeBuilder, operator, height)
	if err != nil {
		return Identity{}, normalizeRetryable(err)
	}
	// The frozen query selects no version, so freshness is a post-read identity
	// check against the Builder row's own current_descriptor_version.
	if err := descriptor.CurrentAtHeight(descriptorVersion, height); err != nil {
		return Identity{}, fmt.Errorf("Builder %s: %w", operator, err)
	}
	if descriptor.OperatorAddress != operator {
		return Identity{}, fmt.Errorf("Builder %s descriptor is published for %q", operator, descriptor.OperatorAddress)
	}
	serviceKey, err := r.keeper.CurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, operator, height)
	if err != nil {
		return Identity{}, normalizeRetryable(err)
	}
	if err := validateServiceKey(serviceKey, operator, height); err != nil {
		return Identity{}, err
	}
	if serviceKey.CurrentDescriptorVersion.Uint64() != descriptorVersion {
		return Identity{}, fmt.Errorf("Builder %s current service key and descriptor versions disagree", operator)
	}
	endpoint, err := descriptor.Endpoint(nexusEndpointKind)
	if err != nil {
		return Identity{}, fmt.Errorf("Builder %s: %w", operator, err)
	}
	if err := checkEndpointTransport(endpoint, r.allowInsecure); err != nil {
		return Identity{}, fmt.Errorf("Builder %s %s endpoint %s: %w", operator, endpoint.Kind, endpoint.URI, err)
	}
	return Identity{
		OperatorAddress:         operator,
		Endpoint:                endpoint.URI,
		EndpointProtocolVersion: endpoint.ProtocolVersion,
		EndpointTLSPubkeyHash:   endpoint.TLSPubkeyHash,
		DescriptorVersion:       descriptor.DescriptorVersion,
		DescriptorHash:          descriptor.DescriptorHash.String(),
		ServiceAddress:          serviceKey.ServiceAddress,
		ServicePubkey:           serviceKey.ServicePubkey,
		AuthorizationNonce:      serviceKey.AuthorizationNonce.Uint64(),
		SnapshotHeight:          height,
	}, nil
}

// normalizeRetryable restates Keeper transport failures with the builderclient
// marker so this package exposes exactly one retry contract to callers.
func normalizeRetryable(err error) error {
	if err != nil && chainclient.IsRetryable(err) && !builderclient.IsRetryable(err) {
		return builderclient.Retryable(err)
	}
	return err
}

// ValidateServiceKey rejects a service key that does not belong to the operator,
// is not active, or was revoked at or before the observed height.
func ValidateServiceKey(key chainclient.ServiceKeySnapshot, operator string, height uint64) error {
	return validateServiceKey(key, operator, height)
}

func validateServiceKey(key chainclient.ServiceKeySnapshot, operator string, height uint64) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if key.ParticipantType != chainclient.ParticipantTypeBuilder || key.OperatorAddress != operator {
		return fmt.Errorf("Keeper current service key does not belong to Builder %s", operator)
	}
	if !strings.EqualFold(strings.TrimSpace(key.Status), "ACTIVE") {
		return fmt.Errorf("Builder %s current service key status is %q", operator, key.Status)
	}
	if revoked := key.RevokedHeight.Uint64(); revoked != 0 && revoked <= height {
		return fmt.Errorf("Builder %s current service key was revoked at height %d", operator, revoked)
	}
	return nil
}

// CheckEndpointTransport is the exported transport rule, for callers that hold
// an endpoint they did not resolve through Resolve.
func CheckEndpointTransport(endpoint chainclient.ServiceEndpointSnapshot, allowInsecure bool) error {
	return checkEndpointTransport(endpoint, allowInsecure)
}

// checkEndpointTransport decides whether Cortex may dial an endpoint.
//
// Upstream has ONE endpoint validator, and it admits four schemes on every
// path. Node main 8dd6729's CanonicalServiceDescriptorEndpointFields describes
// itself as "the single Msg/Genesis endpoint validator and canonical field
// producer. HTTP remains allowed by the explicit Node deployment decision;
// credentials, query and fragment never are"
// (x/hub/types/participant_identity.go:182-184). Its scheme switch admits
// http, https, grpc and grpcs (:206-208); it refuses credentials, query and
// fragment (:202-204); and GenesisState.Validate calls exactly it
// (x/hub/types/genesis.go:779). The older split - an HTTPS-only write path
// in x/hub/keeper/identity_validation.go beside a four-scheme state
// invariant - is gone: at 8dd6729 that file is 96 lines and carries no endpoint
// rule at all.
//
// So the scheme set Cortex may meet in committed state is {http, https, grpc,
// grpcs}, whether the row arrived by MsgUpdateServiceDescriptor or by genesis.
// All four are now admissible here, and LOCAL POLICY narrows on transport
// security rather than on scheme spelling:
//
//  1. https:// and grpcs:// are TLS and are accepted. grpcs is an alias, not a
//     second transport: NEXUS_GRPC means gRPC over TLS either way, which is
//     what Cortex's Connect client dials.
//  2. http:// and grpc:// are plaintext and are refused unless AllowInsecure.
//     THE PLAINTEXT GATE IS NOT DEAD CODE: both are admitted upstream by
//     deliberate decision, and they are how an h2c nexus is published, because
//     nexus terminates no TLS at all (TrueOpen/nexus b201a98
//     internal/ingress/server.go:140-143). The devnet BuilderSet publishes
//     grpc:// today.
//  3. A present tls_pubkey_hash is carried through on https/grpcs for the
//     dial-time check in builderclient, and refused on a plaintext scheme,
//     where there is no certificate to check. See ErrPinnedPlaintextEndpoint.
//
// grpc:// and grpcs:// were previously refused outright on the grounds that the
// transport could not dial them. That was wrong about the deployed server: the
// ingress is connect-go and answers the Connect protocol over HTTP/1.1, so the
// existing client reaches it once the scheme is understood
// (builderclient.ParseNexusEndpoint records the measurement). The refusal cost
// real capability: grpcs://, the SECURE gRPC spelling, was rejected while
// https:// was accepted, and no configuration could relax it because the
// refusal was the scheme allowlist rather than the plaintext gate.
//
// An absent pin is allowed. That is not a silently disabled check: nothing was
// published, the transport falls back to hostname verification against the
// published host, and Identity.EndpointTLSPubkeyHash keeps reporting absent so
// nothing downstream can claim a pin was verified.
func checkEndpointTransport(endpoint chainclient.ServiceEndpointSnapshot, allowInsecure bool) error {
	if err := requireKnownKind(endpoint.Kind); err != nil {
		return err
	}
	// The published URI is classified but never rewritten here: SameEndpoint
	// compares the committed string exactly, and normalising it would accept a
	// configured value the chain does not carry. Rewriting happens at the dial
	// site only.
	parsed, err := builderclient.ParseNexusEndpoint(endpoint.URI)
	if err != nil {
		return err
	}
	if parsed.Plaintext && endpoint.TLSPubkeyHash.Present() {
		return ErrPinnedPlaintextEndpoint
	}
	if parsed.Plaintext && !allowInsecure {
		return ErrPlaintextEndpoint
	}
	return nil
}

// requireKnownKind is the closed-enum guard on the policy side. chainclient
// already refuses an unknown kind at decode; restating it here means a kind
// added to the enum without a transport decision fails closed rather than
// inheriting whichever branch happened to be reachable.
func requireKnownKind(kind chainclient.ServiceEndpointKind) error {
	switch kind {
	case chainclient.EndpointKindNexusGRPC,
		chainclient.EndpointKindObjectGatewayHTTPS,
		chainclient.EndpointKindHealthHTTPS:
		return nil
	default:
		return fmt.Errorf("endpoint kind %q has no transport rule in this build", kind)
	}
}

// SameEndpoint reports whether a configured endpoint refers to the same service
// as the resolved one.
//
// The comparison is byte-for-byte against the uri the descriptor publishes,
// because that is what consensus committed. The old resolver normalised both
// sides — lowercasing scheme and host, trimming a trailing slash — which was
// safe when the endpoint came out of a JSON document Cortex had already hashed,
// and is not safe now: any normalisation would accept a configured string the
// chain does not carry.
func (i Identity) SameEndpoint(configured string) error {
	if configured != i.Endpoint {
		return fmt.Errorf(
			"configured endpoint %q is not the %s endpoint Builder %s descriptor %d publishes (%q)",
			configured, nexusEndpointKind, i.OperatorAddress, i.DescriptorVersion, i.Endpoint,
		)
	}
	return nil
}
