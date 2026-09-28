package daemon

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/txclient"
)

const (
	UnsafeTrustedTransportMarker = "UNSAFE_TRUSTED_TRANSPORT"
	// UnsafeInsecureDescriptorMarker records that a plaintext http:// Builder
	// endpoint is accepted: both where the on-chain descriptor publishes it and
	// where the task-data transport dials it. V1 Task payloads are application
	// plaintext, so this exposes prompts and outputs on the wire.
	UnsafeInsecureDescriptorMarker = "UNSAFE_INSECURE_DESCRIPTOR"
	// UnsafeDescriptorTLSDowngradeMarker records that a Builder endpoint the
	// descriptor published as https:// or grpcs:// is dialled in the clear. It
	// is reported on top of UnsafeInsecureDescriptorMarker rather than instead
	// of it, because the downgrade cannot be configured without the plaintext
	// opt-in — the extra fact it carries is that consensus state asked for TLS
	// and this node is not honouring it.
	UnsafeDescriptorTLSDowngradeMarker = "UNSAFE_DESCRIPTOR_TLS_DOWNGRADE"
)

type DependencyOptions struct {
	ModelClient                modelservice.Client
	ModelTransport             modelservice.Transport
	NexusPublisher             builderclient.Publisher
	NexusSubscriber            builderclient.Subscriber
	NexusEnvelopeAuthenticator builderclient.BusEnvelopeAuthenticator
	NexusEnvelopeSigner        builderclient.BusEnvelopeSigner
	NexusToken                 string
	TaskDataClient             builderclient.TaskDataClient
	TxClient                   txclient.Client
	Keeper                     KeeperClient
	// NexusPublishObserver reports every outbound bus publish. It is attached to
	// the Builder client only, never to the publisher the runtime keeps for
	// readiness and shutdown, because those two paths type-assert the value for
	// its Probe and Close methods.
	NexusPublishObserver func(builderclient.PublishCompletion)
}

// KeeperClient is the runtime's Keeper injection point. It is deliberately
// minimal, and the runtime narrows it to richer capabilities where it needs
// them: TaskReceiptFactsReader for the frozen Task reads the Worker receipt and
// verifier result paths sign, TaskLiabilityReader, KeeperModelRegistryReader.
// The client BuildRuntimeWithOptions constructs on its own,
// *chainclient.KeeperABCIClient, implements all of them - task_facts.go asserts
// that one statically. A client injected through DependencyOptions.Keeper that
// does not implement TaskReceiptFactsReader still builds, and NewTaskFacts turns
// it into a reader that fails closed by name rather than a silent nil.
type KeeperClient interface {
	ChainHeight(context.Context) (uint64, error)
}

// ErrTypedNilKeeperClient refuses an injected Keeper that is an interface value
// holding a nil pointer, such as (*chainclient.KeeperABCIClient)(nil).
//
// That value is NOT == nil, so every `Keeper == nil` fallback in this package
// and in runtime.go treats it as a usable client, and every capability narrowing
// succeeds on it: the method set belongs to the type, not to the value. The
// first actual call then dereferences a nil receiver and panics somewhere far
// from the injection that caused it.
//
// It is refused here, at the one place a DependencyOptions.Keeper enters the
// daemon, rather than nil-checked at each use: the downstream code deliberately
// treats nil as "no Keeper configured", and a value that lies about being nil
// has no honest reading anywhere below this line.
var ErrTypedNilKeeperClient = errors.New("injected Keeper client is a typed nil")

// requireUsableKeeperClient is that refusal. reflect is the only way to ask an
// interface value whether the pointer inside it is nil; the alternative is
// waiting for the panic.
func requireUsableKeeperClient(keeper KeeperClient) error {
	if keeper == nil {
		return nil
	}
	value := reflect.ValueOf(keeper)
	switch value.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Interface:
		if value.IsNil() {
			return fmt.Errorf(
				"%w (%T): it is not == nil, so it would be selected as a usable Keeper and "+
					"panic on its first call; pass a constructed client or leave the option unset",
				ErrTypedNilKeeperClient, keeper)
		}
	}
	return nil
}

type Dependencies struct {
	Model                      modelservice.Client
	Builder                    builderclient.Client
	OutputPackages             builderclient.OutputPackageStore
	TaskData                   builderclient.TaskDataClient
	Subscriber                 builderclient.Subscriber
	NexusEnvelopeAuthenticator builderclient.BusEnvelopeAuthenticator
	NexusEnvelopeSigner        builderclient.BusEnvelopeSigner
	Keeper                     KeeperClient
	Tx                         txclient.Client
	Diagnostics                diagnostics.Diagnostics
}

func BuildDependencies(cfg config.Config, opts DependencyOptions) (Dependencies, error) {
	if err := cfg.Validate(); err != nil {
		return Dependencies{}, err
	}
	// Refused before the mode branch: a typed-nil Keeper is a caller fault
	// whatever the mode, and config.ModeFake returns from this function before
	// the option is ever read.
	if err := requireUsableKeeperClient(opts.Keeper); err != nil {
		return Dependencies{}, err
	}

	report := diagnostics.Diagnostics{
		Mode:                  cfg.Mode,
		ModelTransport:        cfg.ModelManagement.Transport,
		KeeperEndpoint:        cfg.Node.RPCEndpoint,
		NexusIngress:          cfg.Nexus.IngressURL,
		NexusNATS:             diagnostics.RedactEndpoint(cfg.Nexus.NATSURL),
		NexusEnvelopeAuthMode: cfg.Nexus.EnvelopeAuthMode,
		NexusBuilderOperator:  cfg.Nexus.BuilderOperatorAddress,
	}
	if cfg.Nexus.TrustedNATSDev() {
		report.SecurityWarnings = append(report.SecurityWarnings, UnsafeTrustedTransportMarker)
	}
	if cfg.Nexus.AllowInsecureDescriptor {
		report.SecurityWarnings = append(report.SecurityWarnings, UnsafeInsecureDescriptorMarker)
	}
	if cfg.Nexus.DowngradeDescriptorTLS {
		report.SecurityWarnings = append(report.SecurityWarnings, UnsafeDescriptorTLSDowngradeMarker)
	}
	deps := Dependencies{Diagnostics: report}

	if cfg.Mode == config.ModeFake {
		deps.Model = modelservice.NewFakeService()
		deps.Builder = builderclient.NewFakeClient()
		deps.Diagnostics.Dependencies = []diagnostics.DependencyStatus{
			fixtureReady("chain", cfg.Node.RPCEndpoint),
			fixtureReady("model_service", cfg.ModelManagement.Endpoint),
			fixtureReady("store", cfg.Store.Path),
			fixtureReady("keeper", cfg.Node.RPCEndpoint),
			fixtureReady("keeper_identity", cfg.LocalIdentity.OperatorAddress),
			fixtureReady("model_support", strings.Join(cfg.LocalIdentity.SupportedModelProfiles, ",")),
			fixtureReady("nexus", cfg.Nexus.IngressURL),
			fixtureReady("nexus_envelope_auth", "fixture"),
			fixtureReady("builder_descriptor", "fixture"),
			fixtureReady("tx_broadcaster", cfg.Node.RESTEndpoint),
		}
		return deps, nil
	}

	deps.Keeper = opts.Keeper
	if deps.Keeper == nil {
		nodeTransport, err := nodeHTTPTransport(cfg)
		if err != nil {
			return Dependencies{}, err
		}
		deps.Keeper = chainclient.NewKeeperABCIClientWithTransport(cfg.Node.RPCEndpoint, nodeTransport)
	}
	deps.Tx = opts.TxClient
	modelReady := opts.ModelClient != nil || opts.ModelTransport != nil || isLocalModelTransport(cfg) || isFakeModelTransport(cfg)
	authReady := opts.NexusEnvelopeAuthenticator != nil && opts.NexusEnvelopeSigner != nil
	authError := "canonical Nexus BusEnvelope signer and authenticator are required"
	if cfg.Nexus.TrustedNATSDev() {
		transportAuthenticated := strings.TrimSpace(opts.NexusToken) != "" || cfg.Nexus.NATSURLCredentials()
		authReady = transportAuthenticated && opts.NexusPublisher != nil && opts.NexusSubscriber != nil
		authError = "trusted_nats_dev requires an authenticated NATS transport (token file or URL credentials) and a publisher/subscriber ACL boundary"
	}
	// chain, keeper and store start unprobed: the readiness controller replaces
	// them with live results. nexus is labelled with the NATS URL because that is
	// what its probe exercises -- the publisher and subscriber transports. It used
	// to display the HTTP ingress URL while checking NATS, so an ingress URL whose
	// DNS had never resolved was reported ready.
	deps.Diagnostics.Dependencies = []diagnostics.DependencyStatus{
		unprobed("chain", cfg.Node.RPCEndpoint),
		modelStatus(modelEndpoint(cfg), isLocalModelTransport(cfg) || isFakeModelTransport(cfg), modelReady, "model transport is required"),
		unprobed("store", cfg.Store.Path),
		unprobed("keeper", cfg.Node.RPCEndpoint),
		realStatus("nexus", cfg.Nexus.NATSURL, opts.NexusPublisher != nil && opts.NexusSubscriber != nil, "nexus publisher and subscriber are required"),
		realStatus("nexus_envelope_auth", cfg.Nexus.NATSURL, authReady, authError),
		natsIdentityStatus(cfg),
		builderDescriptorStatus(cfg, false, "Builder service descriptor has not been verified yet"),
		txBroadcasterStatus(cfg, opts.TxClient != nil),
	}
	switch {
	case opts.ModelClient != nil:
		deps.Model = opts.ModelClient
	case opts.ModelTransport != nil:
		deps.Model = modelservice.NewRemoteClient(opts.ModelTransport)
	case isLocalModelTransport(cfg):
		// Only models bound to their chain repo_id are advertised or served.
		// The binding needs a chain read, so it happens in the model-service
		// readiness check (bindLocalModels), which keeps the node unready
		// until every configured model is bound and served.
		local := modelservice.NewLocalService(cfg.ModelManagement.Endpoint, cfg.LocalIdentity.ModelServiceID, cfg.ModelManagement.MaxConcurrency, cfg.ModelManagement.InferTimeout(), cfg.ModelManagement.ProbeTimeout())
		if resolver := newKeeperLocalProfileResolver(deps.Keeper); resolver != nil {
			local.SetProfileResolver(resolver)
		}
		deps.Model = local
	case isFakeModelTransport(cfg):
		fake, err := modelservice.NewSharedFakeService(cfg.LocalIdentity.ModelServiceID, cfg.TaskExecution.FixtureRoot, configuredModelIDs(cfg)...)
		if err != nil {
			return Dependencies{}, err
		}
		deps.Model = fake
		packages, err := builderclient.NewFixtureOutputPackageStore(cfg.TaskExecution.FixtureRoot)
		if err != nil {
			return Dependencies{}, err
		}
		deps.OutputPackages = packages
	}
	deps.Subscriber = opts.NexusSubscriber
	deps.NexusEnvelopeAuthenticator = opts.NexusEnvelopeAuthenticator
	deps.NexusEnvelopeSigner = opts.NexusEnvelopeSigner
	deps.TaskData = opts.TaskDataClient
	// The Builder client is a bus publisher and a local validator now: no Nexus
	// call takes cfg.Nexus.IngressURL as a target. The ingress URL survives only
	// as the readiness cross-check against the Builder's on-chain descriptor
	// (Runtime.checkBuilderDescriptorReadiness).
	deps.Builder = builderclient.NewNexusClient(builderclient.NewObservedPublisher(opts.NexusPublisher, opts.NexusPublishObserver))
	return deps, nil
}

type keeperCurrentModelProfileReader interface {
	CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error)
}

type keeperLocalProfileResolver struct {
	currentModelProfile keeperCurrentModelProfileReader
}

func newKeeperLocalProfileResolver(keeper KeeperClient) modelservice.LocalProfileResolver {
	reader, ok := keeper.(keeperCurrentModelProfileReader)
	if !ok {
		return nil
	}
	return keeperLocalProfileResolver{currentModelProfile: reader}
}

func (r keeperLocalProfileResolver) ResolveLocalProfile(ctx context.Context, modelID string, profileVersion string) (chainclient.CurrentProfileSnapshot, error) {
	snapshot, err := r.currentModelProfile.CurrentModelProfile(ctx, modelID, profileVersion)
	if err != nil {
		return chainclient.CurrentProfileSnapshot{}, err
	}
	return snapshot.Profile, nil
}

// natsIdentityDependency is the name of the "join NATS with the on-chain identity"
// dependency in diagnostics and health checks.
const natsIdentityDependency = "nexus_nats_identity"

// natsIdentityStatus reports whether joining NATS with the on-chain identity is
// configured (ADR-0016 decision three). Without a user key file it is marked
// optional-not-configured - that is the creds/token path, not something missing.
// Readiness is decided by the runtime's Binder probe.
func natsIdentityStatus(cfg config.Config) diagnostics.DependencyStatus {
	configured := strings.TrimSpace(cfg.Nexus.NATSUserKeyFile) != ""
	status := diagnostics.DependencyStatus{
		Name:       natsIdentityDependency,
		Endpoint:   diagnostics.RedactEndpoint(cfg.Nexus.NATSURL),
		Configured: configured,
		Optional:   !configured,
	}
	if configured {
		status.Error = "nats chain identity binding has not been built yet"
	}
	return status
}

// fixtureReady reports a dependency that is satisfied by a fixture rather than
// by a live check. Fake mode substitutes in-process fakes for every boundary, so
// claiming readiness there is truthful.
func fixtureReady(name string, endpoint string) diagnostics.DependencyStatus {
	return diagnostics.DependencyStatus{
		Name:       name,
		Endpoint:   diagnostics.RedactEndpoint(endpoint),
		Configured: strings.TrimSpace(endpoint) != "",
		Ready:      true,
	}
}

// unprobed reports a dependency whose readiness has not been established yet.
//
// This replaces a constructor that hardcoded Ready: true for chain, keeper and
// store. Those three were therefore reported ready for the lifetime of the
// process no matter what: on a devnet whose chain had been unreachable for
// hours, and whose nodes had already exited once on `invalid CometBFT latest
// block height "0"`, `cortexctl diagnostics` still said the chain was ready.
// Startup cannot know whether a remote boundary works, so it must not claim to.
func unprobed(name string, endpoint string) diagnostics.DependencyStatus {
	return diagnostics.DependencyStatus{
		Name:       name,
		Endpoint:   diagnostics.RedactEndpoint(endpoint),
		Configured: strings.TrimSpace(endpoint) != "",
		Ready:      false,
		Error:      "readiness probe has not completed yet",
	}
}

// realStatus, unprobed and fixtureReady are the three constructors every
// dependency row in this package is built by, so the endpoint credential
// stripping lives in them rather than at the two call sites that pass a NATS
// URL today. cortexctl prints this record and operators paste that output into
// issues; nexus.nats_url is the one configured value that routinely carries a
// password, and both the nexus and nexus_envelope_auth rows are labelled with
// it (they probe the NATS transport, not the HTTP ingress).
func realStatus(name string, endpoint string, ready bool, message string) diagnostics.DependencyStatus {
	status := diagnostics.DependencyStatus{
		Name:       name,
		Endpoint:   diagnostics.RedactEndpoint(endpoint),
		Configured: strings.TrimSpace(endpoint) != "",
		Ready:      ready,
	}
	if !ready {
		status.Error = message
	}
	return status
}

func modelStatus(endpoint string, local bool, ready bool, message string) diagnostics.DependencyStatus {
	status := realStatus("model_service", endpoint, ready, message)
	if local {
		status.Configured = true
	}
	return status
}

// configuredModelIDs lists the chain model identifiers this node declares
// support for. The fake model service advertises them so handraise eligibility
// can match real Keeper records without a live model service.
type keeperCurrentModelReader interface {
	CurrentModel(context.Context, string) (chainclient.CurrentModelSnapshot, error)
}

// bindLocalModels binds every configured model id to the repo_id its chain
// ModelState names, and refuses when the local vLLM does not serve that
// repository. The operator configures the model id explicitly; nothing is
// derived from the repository name.
func bindLocalModels(ctx context.Context, keeper KeeperClient, local *modelservice.LocalService, modelIDs []string) error {
	if len(modelIDs) == 0 {
		return fmt.Errorf("no model id is configured for the local model service")
	}
	reader, ok := keeper.(keeperCurrentModelReader)
	if !ok {
		return fmt.Errorf("Keeper client cannot read ModelState to bind local models")
	}
	for _, modelID := range modelIDs {
		model, err := reader.CurrentModel(ctx, modelID)
		if err != nil {
			return fmt.Errorf("query ModelState %s: %w", modelID, err)
		}
		if err := model.Validate(); err != nil {
			return err
		}
		if model.ModelID != modelID {
			return fmt.Errorf("ModelState %s answered for model %s", modelID, model.ModelID)
		}
		if err := local.BindModel(modelID, model.Provider, model.RepoID); err != nil {
			return err
		}
		if err := local.CheckServed(ctx, modelID); err != nil {
			return fmt.Errorf("model %s (%s %s): %w", modelID, model.Provider, model.RepoID, err)
		}
	}
	return nil
}

func configuredModelIDs(cfg config.Config) []string {
	profiles, err := cfg.LocalIdentity.ModelProfiles()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(profiles))
	ids := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		if _, ok := seen[profile.ModelID]; ok {
			continue
		}
		seen[profile.ModelID] = struct{}{}
		ids = append(ids, profile.ModelID)
	}
	return ids
}

// builderDescriptorStatus reports the Builder descriptor verification slot.
// Verification is only possible once an operator names the Builder that owns the
// configured ingress; until then the slot stays ready but unconfigured so a
// deployment without a published descriptor is not silently held down.
// txBroadcasterStatus records the direct Cosmos transaction path.
//
// Two things about it were misreported for as long as it existed. The endpoint
// is node.rest_endpoint, not node.rpc_endpoint: the probe reads the Cosmos Auth
// account over REST (txclient.Broadcaster) and never dials CometBFT RPC, so
// printing :26657 pointed operators at the wrong port. And it is Optional
// unless an enabled workload path actually submits a transaction — normal
// Worker and Verifier material goes through Nexus/Builder — which the workload
// gate already knew (workloadDependenciesReady) while the record did not.
func txBroadcasterStatus(cfg config.Config, ready bool) diagnostics.DependencyStatus {
	status := realStatus("tx_broadcaster", cfg.Node.RESTEndpoint, ready,
		"tx broadcaster is unavailable; it is required only for enabled direct transaction paths")
	status.Optional = !cfg.RequiresWorkloadTx()
	return status
}

func builderDescriptorStatus(cfg config.Config, verified bool, message string) diagnostics.DependencyStatus {
	if !cfg.Nexus.VerifiesBuilderDescriptor() {
		return diagnostics.DependencyStatus{Name: "builder_descriptor", Configured: false, Ready: true}
	}
	return realStatus("builder_descriptor", cfg.Nexus.BuilderOperatorAddress, verified, message)
}

func isLocalModelTransport(cfg config.Config) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.ModelManagement.Transport), "local")
}

func isFakeModelTransport(cfg config.Config) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.ModelManagement.Transport), "fake")
}

func modelEndpoint(cfg config.Config) string {
	if isFakeModelTransport(cfg) {
		return cfg.TaskExecution.FixtureRoot
	}
	return cfg.ModelManagement.Endpoint
}
