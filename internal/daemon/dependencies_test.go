package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type fakeModelTransport struct{}

func (fakeModelTransport) Invoke(_ context.Context, _ string, _ any, _ any) error {
	return nil
}

type injectedModelClient struct {
	*modelservice.FakeService
}

type fakePublisher struct{}

func (fakePublisher) Publish(_ context.Context, _ builderclient.PublishRequest) error {
	return nil
}

type fakeSubscriber struct{}

func (fakeSubscriber) Subscribe(context.Context, string, builderclient.MessageHandler) (builderclient.Subscription, error) {
	return nil, nil
}

type daemonKeeperProfileResolverStub struct {
	profile           chainclient.CurrentProfileSnapshot
	modelProfile      chainclient.CurrentModelProfileSnapshot
	profileCalls      int
	modelProfileCalls int
}

func (k *daemonKeeperProfileResolverStub) ChainHeight(context.Context) (uint64, error) {
	return 1, nil
}

func (k *daemonKeeperProfileResolverStub) CurrentProfile(context.Context, string, string) (chainclient.CurrentProfileSnapshot, error) {
	k.profileCalls++
	return k.profile, nil
}

func (k *daemonKeeperProfileResolverStub) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	k.modelProfileCalls++
	return k.modelProfile, nil
}

type daemonCurrentProfileOnlyKeeper struct {
	profile chainclient.CurrentProfileSnapshot
	calls   int
}

func (k *daemonCurrentProfileOnlyKeeper) ChainHeight(context.Context) (uint64, error) {
	return 1, nil
}

func (k *daemonCurrentProfileOnlyKeeper) CurrentProfile(context.Context, string, string) (chainclient.CurrentProfileSnapshot, error) {
	k.calls++
	return k.profile, nil
}

func TestBuildDependenciesFakeModeReturnsReadyFakes(t *testing.T) {
	deps, err := BuildDependencies(fakeConfig(), DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if deps.Diagnostics.Mode != config.ModeFake {
		t.Fatalf("Mode = %q", deps.Diagnostics.Mode)
	}
	if _, ok := deps.Model.(*modelservice.FakeService); !ok {
		t.Fatalf("Model = %T, want *modelservice.FakeService", deps.Model)
	}
	if _, ok := deps.Builder.(*builderclient.FakeClient); !ok {
		t.Fatalf("Builder = %T, want *builderclient.FakeClient", deps.Builder)
	}
	for _, name := range []string{"chain", "model_service", "store", "keeper", "nexus"} {
		status, ok := deps.Diagnostics.Dependency(name)
		if !ok {
			t.Fatalf("missing dependency %q", name)
		}
		if !status.Configured || !status.Ready {
			t.Fatalf("%s status = %#v, want configured and ready", name, status)
		}
	}
}

func TestBuildDependenciesWiresInjectedTaskDataClient(t *testing.T) {
	cfg := realConfig()
	cfg.TaskExecution.InputResolver = config.InputResolverNexus
	taskData := builderclient.NewFakeClient()
	deps, err := BuildDependencies(cfg, DependencyOptions{TaskDataClient: taskData})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if deps.TaskData != taskData {
		t.Fatalf("TaskData = %T, want injected %T", deps.TaskData, taskData)
	}
}

func TestBuildDependenciesRealModeReportsConfiguredIntegrationEndpoints(t *testing.T) {
	cfg := realConfig()
	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelTransport:  fakeModelTransport{},
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		NexusToken:      "token-1",
		TxClient:        txclient.NewFake(),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if deps.Diagnostics.Mode != config.ModeReal {
		t.Fatalf("Mode = %q", deps.Diagnostics.Mode)
	}
	if deps.Diagnostics.KeeperEndpoint != cfg.Node.RPCEndpoint {
		t.Fatalf("KeeperEndpoint = %q", deps.Diagnostics.KeeperEndpoint)
	}
	if deps.Keeper == nil {
		t.Fatalf("Keeper = nil")
	}
	if deps.Model == nil || deps.Builder == nil {
		t.Fatalf("Model=%T Builder=%T, want configured clients", deps.Model, deps.Builder)
	}
	// Boundaries that can be settled from configuration and injected adapters are
	// reported ready at construction.
	for _, name := range []string{"model_service", "nexus", "tx_broadcaster"} {
		status, ok := deps.Diagnostics.Dependency(name)
		if !ok || !status.Configured || !status.Ready {
			t.Fatalf("%s status = %#v ok=%v", name, status, ok)
		}
	}
	// Remote boundaries cannot be settled at construction. Reporting them ready
	// before probing is what let a devnet whose chain had been unreachable for
	// hours keep claiming the chain was fine.
	for _, name := range []string{"chain", "keeper", "store"} {
		status, ok := deps.Diagnostics.Dependency(name)
		if !ok || !status.Configured {
			t.Fatalf("%s status = %#v ok=%v, want configured", name, status, ok)
		}
		if status.Ready || status.Error == "" {
			t.Fatalf("%s status = %#v, want unprobed with an explanation until the readiness pass runs", name, status)
		}
	}
	authStatus, ok := deps.Diagnostics.Dependency("nexus_envelope_auth")
	if !ok || authStatus.Ready || authStatus.Error == "" {
		t.Fatalf("nexus_envelope_auth status = %#v ok=%v, want fail-closed", authStatus, ok)
	}
}

func TestBuildDependenciesReportsInjectedNexusEnvelopeAuthenticationReady(t *testing.T) {
	cfg := realConfig()
	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelTransport: fakeModelTransport{}, NexusPublisher: fakePublisher{}, NexusSubscriber: fakeSubscriber{}, TxClient: txclient.NewFake(),
		NexusEnvelopeAuthenticator: builderclient.BusEnvelopeAuthenticatorFunc(func(context.Context, string, builderclient.BusEnvelope) error { return nil }),
		NexusEnvelopeSigner: builderclient.BusEnvelopeSignerFunc(func(builderclient.BusEnvelope) ([]byte, error) {
			return []byte("test-envelope-signature"), nil
		}),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	status, ok := deps.Diagnostics.Dependency("nexus_envelope_auth")
	if !ok || !status.Configured || !status.Ready || status.Error != "" {
		t.Fatalf("nexus_envelope_auth status = %#v ok=%v, want ready", status, ok)
	}
}

// TestBuildDependenciesTrustedNATSDevRefusedInRealMode verifies that the unsafe
// dev-only transport boundary is rejected when mode is real.
func TestBuildDependenciesTrustedNATSDevRefusedInRealMode(t *testing.T) {
	cfg := realConfig()
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AuthTokenFile = "/run/secrets/nexus.token"
	opts := DependencyOptions{ModelTransport: fakeModelTransport{}, NexusPublisher: fakePublisher{}, NexusSubscriber: fakeSubscriber{}}
	if _, err := BuildDependencies(cfg, opts); err == nil || !strings.Contains(err.Error(), "nexus.envelope_auth_mode must not be trusted_nats_dev in real mode") {
		t.Fatalf("BuildDependencies() error = %v, want real mode refusal of trusted_nats_dev", err)
	}
}

// TestBuildDependenciesTrustedNATSDevReportsUnsafeMarkerInFakeMode verifies that
// fake mode still surfaces the unsafe-transport warning so operators can see it.
func TestBuildDependenciesTrustedNATSDevReportsUnsafeMarkerInFakeMode(t *testing.T) {
	cfg := realConfig()
	cfg.Mode = config.ModeFake
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AuthTokenFile = "/run/secrets/nexus.token"
	opts := DependencyOptions{ModelTransport: fakeModelTransport{}, NexusPublisher: fakePublisher{}, NexusSubscriber: fakeSubscriber{}}
	deps, err := BuildDependencies(cfg, opts)
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	encoded, err := json.Marshal(deps.Diagnostics)
	if err != nil {
		t.Fatalf("marshal diagnostics: %v", err)
	}
	if !strings.Contains(string(encoded), UnsafeTrustedTransportMarker) {
		t.Fatalf("diagnostics = %s, want unsafe marker", encoded)
	}
}

func TestBuildDependenciesRealModeUsesInjectedModelClient(t *testing.T) {
	cfg := realConfig()
	model := &injectedModelClient{FakeService: modelservice.NewFakeService()}
	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelClient:     model,
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		TxClient:        txclient.NewFake(),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if deps.Model != model {
		t.Fatalf("Model = %T, want injected model client", deps.Model)
	}
	status, ok := deps.Diagnostics.Dependency("model_service")
	if !ok || !status.Configured || !status.Ready || status.Error != "" {
		t.Fatalf("model_service status = %#v ok=%v, want ready injected client", status, ok)
	}
}

func TestBuildDependenciesRealModeUsesLocalModelService(t *testing.T) {
	cfg := realConfig()
	cfg.ModelManagement.Transport = "local"
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 4
	keeper := &daemonKeeperProfileResolverStub{
		profile:      daemonCurrentProfile("profile-only", 1, 11),
		modelProfile: chainclient.CurrentModelProfileSnapshot{Profile: daemonCurrentProfile("combined", 1, 13)},
	}

	deps, err := BuildDependencies(cfg, DependencyOptions{
		Keeper:          keeper,
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		TxClient:        txclient.NewFake(),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if _, ok := deps.Model.(*modelservice.LocalService); !ok {
		t.Fatalf("Model = %T, want *modelservice.LocalService", deps.Model)
	}
	if !localServiceHasProfileResolver(t, deps.Model) {
		t.Fatalf("local model service was not wired with Keeper profile resolver")
	}
	status, ok := deps.Diagnostics.Dependency("model_service")
	if !ok || !status.Configured || !status.Ready || status.Error != "" {
		t.Fatalf("model_service status = %#v ok=%v, want ready local model service", status, ok)
	}
}

// TestBuildDependenciesRefusesATypedNilKeeper covers the fourth state of the
// Keeper option, the one that is neither "unset", "unsupported capability" nor
// "usable": an interface value holding a nil pointer.
//
// It is not == nil, so every `Keeper == nil` fallback treats it as a client, and
// every capability narrowing succeeds on it because a method set belongs to the
// type. Remove the guard in BuildDependencies and this test does not fail with a
// wrong error - it panics on the nil dereference in the first Keeper call,
// which is precisely the outcome the guard exists to convert into a refusal.
func TestBuildDependenciesRefusesATypedNilKeeper(t *testing.T) {
	var typedNil *chainclient.KeeperABCIClient
	// The premise: an interface holding this is not nil, and it satisfies the
	// task-facts capability, so nothing downstream would decline it.
	var injected KeeperClient = typedNil
	if injected == nil {
		t.Fatal("a typed nil compared equal to nil; this test no longer models the fault")
	}
	if _, capable := injected.(TaskReceiptFactsReader); !capable {
		t.Fatal("the typed nil no longer satisfies TaskReceiptFactsReader; this test no longer models the fault")
	}
	// And the fault the guard converts into a refusal: reaching any Keeper call
	// with this value dereferences a nil receiver. If this ever stops panicking
	// the guard is protecting nothing and should go.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a typed-nil Keeper no longer panics on use; the fourth state is gone")
			}
		}()
		_, _ = NewTaskFacts(injected).TaskFacts(context.Background(), factsTestTaskID)
	}()

	for name, cfg := range map[string]config.Config{
		"real": realConfig(),
		"fake": fakeConfig(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BuildDependencies(cfg, DependencyOptions{
				Keeper:          injected,
				NexusPublisher:  fakePublisher{},
				NexusSubscriber: fakeSubscriber{},
				TxClient:        txclient.NewFake(),
			})
			if !errors.Is(err, ErrTypedNilKeeperClient) {
				t.Fatalf("BuildDependencies() error = %v, want ErrTypedNilKeeperClient", err)
			}
			if !strings.Contains(err.Error(), "chainclient.KeeperABCIClient") {
				t.Fatalf("refusal = %q, want it to name the injected type", err)
			}
		})
	}
}

func TestKeeperLocalProfileResolverPrefersCurrentModelProfile(t *testing.T) {
	keeper := &daemonKeeperProfileResolverStub{
		profile:      daemonCurrentProfile("profile-only", 1, 11),
		modelProfile: chainclient.CurrentModelProfileSnapshot{Profile: daemonCurrentProfile("combined", 1, 13)},
	}
	resolver := newKeeperLocalProfileResolver(keeper)
	if resolver == nil {
		t.Fatal("newKeeperLocalProfileResolver() = nil")
	}

	got, err := resolver.ResolveLocalProfile(context.Background(), "model", "1")
	if err != nil {
		t.Fatalf("ResolveLocalProfile() error = %v", err)
	}
	if got.ModelID != "combined" || got.RequiredTopK != 13 {
		t.Fatalf("ResolveLocalProfile() = %+v, want CurrentModelProfile profile", got)
	}
	if keeper.modelProfileCalls != 1 || keeper.profileCalls != 0 {
		t.Fatalf("resolver calls = model_profile:%d profile:%d, want CurrentModelProfile only", keeper.modelProfileCalls, keeper.profileCalls)
	}
}

// A Keeper client that cannot answer CurrentModelProfile yields no resolver, so
// the local service keeps its built-in defaults rather than failing every task.
func TestKeeperLocalProfileResolverAbsentWithoutModelProfileQuery(t *testing.T) {
	if resolver := newKeeperLocalProfileResolver(&daemonCurrentProfileOnlyKeeper{}); resolver != nil {
		t.Fatalf("newKeeperLocalProfileResolver() = %#v, want nil without a CurrentModelProfile query", resolver)
	}
}

func TestBuildDependenciesRealModeUsesSharedFakeModelService(t *testing.T) {
	const chainModelID = "ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"
	cfg := realConfig()
	cfg.ModelManagement.Transport = "fake"
	cfg.ModelManagement.Endpoint = ""
	cfg.TaskExecution.InputResolver = "fixture"
	cfg.TaskExecution.FixtureRoot = t.TempDir()
	cfg.LocalIdentity.SupportedModelProfiles = []string{chainModelID + "@1=llm_text_v1"}
	cfg.Nexus.SubscribeModels = []string{chainModelID}

	deps, err := BuildDependencies(cfg, DependencyOptions{
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		TxClient:        txclient.NewFake(),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	fake, ok := deps.Model.(*modelservice.FakeService)
	if !ok {
		t.Fatalf("Model = %T, want *modelservice.FakeService", deps.Model)
	}
	resp, err := fake.Health(context.Background(), modelservice.HealthRequest{})
	if err != nil {
		t.Fatalf("Health error = %v", err)
	}
	if resp.ModelServiceID != cfg.LocalIdentity.ModelServiceID {
		t.Fatalf("ModelServiceID = %q, want %q", resp.ModelServiceID, cfg.LocalIdentity.ModelServiceID)
	}
	if deps.OutputPackages == nil {
		t.Fatal("OutputPackages = nil, want shared fixture store")
	}
	if _, err := filepath.Abs(cfg.TaskExecution.FixtureRoot); err != nil {
		t.Fatalf("fixture root is invalid: %v", err)
	}

	// Handraise eligibility matches the configured model id against what the
	// model service advertises, so the wiring that passes the configured
	// profiles has to be exercised here. Constructing the fake directly would
	// still pass if BuildDependencies stopped forwarding them.
	capabilities, err := fake.ListCapabilities(context.Background(), modelservice.ListCapabilitiesRequest{
		RequestID: "deps-wiring", ModelServiceID: cfg.LocalIdentity.ModelServiceID,
	})
	if err != nil {
		t.Fatalf("ListCapabilities error = %v", err)
	}
	advertised := false
	for _, capability := range capabilities.Capabilities {
		if capability.ModelID == chainModelID && capability.Capability == modelservice.CapabilityLLMTextV1 {
			advertised = true
			break
		}
	}
	if !advertised {
		t.Fatalf("capabilities = %#v, want the configured chain model id advertised", capabilities.Capabilities)
	}
}

func localServiceHasProfileResolver(t *testing.T, client modelservice.Client) bool {
	t.Helper()
	value := reflect.ValueOf(client)
	if value.Kind() != reflect.Ptr || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		t.Fatalf("client = %T, want pointer to LocalService", client)
	}
	field := value.Elem().FieldByName("profileResolver")
	if !field.IsValid() || field.Kind() != reflect.Interface {
		t.Fatalf("client = %T, missing profileResolver interface field", client)
	}
	return !field.IsNil()
}

func daemonCurrentProfile(modelID string, profileVersion uint32, topK uint32) chainclient.CurrentProfileSnapshot {
	return chainclient.CurrentProfileSnapshot{
		ModelID:        modelID,
		ProfileVersion: chainclient.NewProfileVersion(profileVersion),
		RequiredTopK:   topK,
		VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
			Metrics: chainclient.CurrentMetricSpecSnapshot{
				ComparedTopK: topK,
				NumericScale: "NUMERIC_SCALE_FP_1E6",
			},
		},
	}
}

func TestBuildDependenciesRealModeRecordsMissingRuntimeAdapters(t *testing.T) {
	deps, err := BuildDependencies(realConfig(), DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	modelStatus, _ := deps.Diagnostics.Dependency("model_service")
	if modelStatus.Ready || modelStatus.Error != "model transport is required" {
		t.Fatalf("model status = %#v", modelStatus)
	}
	nexusStatus, _ := deps.Diagnostics.Dependency("nexus")
	if nexusStatus.Ready || nexusStatus.Error != "nexus publisher and subscriber are required" {
		t.Fatalf("nexus status = %#v", nexusStatus)
	}
	txStatus, _ := deps.Diagnostics.Dependency("tx_broadcaster")
	if txStatus.Ready || txStatus.Error != "tx broadcaster is unavailable; it is required only for enabled direct transaction paths" {
		t.Fatalf("tx broadcaster status = %#v", txStatus)
	}
	keeperStatus, _ := deps.Diagnostics.Dependency("keeper")
	if keeperStatus.Endpoint != "http://127.0.0.1:26657" {
		t.Fatalf("keeper status = %#v, want the configured endpoint recorded", keeperStatus)
	}
	if keeperStatus.Ready {
		t.Fatalf("keeper status = %#v, want unprobed until the readiness pass runs", keeperStatus)
	}
}

func TestBuildDependenciesRealModeRequiresNexusPublisherAndSubscriber(t *testing.T) {
	for name, opts := range map[string]DependencyOptions{
		"publisher only":  {NexusPublisher: fakePublisher{}},
		"subscriber only": {NexusSubscriber: fakeSubscriber{}},
	} {
		t.Run(name, func(t *testing.T) {
			deps, err := BuildDependencies(realConfig(), opts)
			if err != nil {
				t.Fatalf("BuildDependencies() error = %v", err)
			}
			status, ok := deps.Diagnostics.Dependency("nexus")
			if !ok {
				t.Fatalf("missing nexus dependency")
			}
			if status.Ready || status.Error != "nexus publisher and subscriber are required" {
				t.Fatalf("nexus status = %#v", status)
			}
		})
	}
}

func TestBuildDependenciesReturnsConfigValidationErrors(t *testing.T) {
	cfg := fakeConfig()
	cfg.ChainID = ""

	if _, err := BuildDependencies(cfg, DependencyOptions{}); err == nil {
		t.Fatalf("BuildDependencies() error = nil, want validation error")
	}
}

func TestBuildDependenciesKeepsDependencyStatusOrderDeterministic(t *testing.T) {
	deps, err := BuildDependencies(realConfig(), DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	want := []string{"chain", "model_service", "store", "keeper", "nexus", "nexus_envelope_auth", "nexus_nats_identity", "builder_descriptor", "tx_broadcaster"}
	if len(deps.Diagnostics.Dependencies) != len(want) {
		t.Fatalf("dependency count = %d, want %d", len(deps.Diagnostics.Dependencies), len(want))
	}
	for i, name := range want {
		if deps.Diagnostics.Dependencies[i].Name != name {
			t.Fatalf("dependency[%d] = %q, want %q", i, deps.Diagnostics.Dependencies[i].Name, name)
		}
	}
}

func fakeConfig() config.Config {
	return config.Config{
		Mode:            config.ModeFake,
		ChainID:         "trueopen-devnet-1",
		Admin:           config.AdminConfig{UDSPath: "/tmp/cortex.sock"},
		ModelManagement: config.ModelManagementConfig{Endpoint: "fake://model-management", Transport: "fake"},
		Node:            config.NodeConfig{RPCEndpoint: "fake://node"},
		Tx:              config.TxConfig{Enabled: true, MaxFeeAmount: 100, FeeDenom: "utrueopen", MaxAttempts: 2},
		Keeper:          config.KeeperConfig{APIURL: "fake://keeper"},
		Nexus:           config.NexusConfig{IngressURL: "fake://nexus", NATSURL: "fake://nats"},
		Artifacts:       config.ArtifactsConfig{Root: "/tmp/cortex-evidence"},
		Store:           config.StoreConfig{Path: ":memory:"},
		Signer:          config.SignerConfig{URI: "memory://operator"},
	}
}

func realConfig() config.Config {
	return config.Config{
		Mode:    config.ModeReal,
		ChainID: "trueopen-devnet-1",
		Admin:   config.AdminConfig{UDSPath: "/tmp/cortex.sock"},
		// A loopback endpoint: real mode allows plaintext only on the same host, and a model
		// service on another host must use TLS.
		ModelManagement: config.ModelManagementConfig{Endpoint: "127.0.0.1:9090", Transport: "grpc"},
		Node:            config.NodeConfig{RPCEndpoint: "http://127.0.0.1:26657", RESTEndpoint: "http://127.0.0.1:1317"},
		Tx:              config.TxConfig{Enabled: true, MaxFeeAmount: 1000, FeeDenom: "utrueopen", MaxAttempts: 3, PollAttempts: 20, GasLimit: 250000},
		Keeper:          config.KeeperConfig{APIURL: "https://keeper.devnet.trueopen.xyz"},
		// Every real-mode node can be drawn as a Worker now that duty selection
		// is retired, so an input resolver is unconditionally required.
		TaskExecution: config.TaskExecutionConfig{RetryDelayMS: 30000, InputResolver: config.InputResolverNexus},
		Nexus: config.NexusConfig{
			IngressURL: "https://nexus.devnet.trueopen.xyz", NATSURL: "tls://nexus.devnet.trueopen.xyz:4222",
			NATSCAFile: "/etc/cortex/nats-ca.pem", NATSUserKeyFile: "/etc/cortex/nats-user.nk", JetStreamStream: "TRUEOPEN_TASK",
		},
		Artifacts: config.ArtifactsConfig{Root: "/tmp/cortex-evidence"},
		Store:     config.StoreConfig{Path: "/tmp/cortex.kv"},
		Signer:    config.SignerConfig{URI: "http://127.0.0.1:9080", ReadinessProofIntervalMS: 30000},
		LocalIdentity: config.LocalIdentityConfig{
			OperatorAddress:        "trueopen1operator",
			ServiceKeyRef:          "memory://service-key",
			SupportedModelProfiles: []string{"c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@1=llm_text_v1"},
			ModelServiceID:         "daemon-model-service",
		},
		SelfRescue: config.SelfRescueConfig{
			Enabled:        false,
			MarginBlocks:   12,
			MaxFeeAmount:   1000,
			FeeDenom:       "utrueopen",
			AllowedTxTypes: []string{"MsgInferReceiptCommitOnlyTx", "MsgCommitTx", "MsgResultTx", "MsgWorkerRevealTx", "MsgSettleTx"},
		},
	}
}

func TestBuildDependenciesMarksInsecureDescriptorAcceptance(t *testing.T) {
	cfg := realConfig()
	cfg.Mode = config.ModeFake
	cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
	cfg.Nexus.AllowInsecureDescriptor = true

	deps, err := BuildDependencies(cfg, DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	warnings := strings.Join(deps.Diagnostics.SecurityWarnings, ",")
	if !strings.Contains(warnings, UnsafeInsecureDescriptorMarker) {
		t.Fatalf("security warnings = %v, want the insecure descriptor marker", deps.Diagnostics.SecurityWarnings)
	}
	if deps.Diagnostics.NexusBuilderOperator != "trueopen1builderoperator" {
		t.Fatalf("diagnostics builder operator = %q", deps.Diagnostics.NexusBuilderOperator)
	}
	status, ok := deps.Diagnostics.Dependency("builder_descriptor")
	if !ok || !status.Ready || !status.Configured {
		t.Fatalf("builder_descriptor status = %+v, want configured and ready", status)
	}
}

// TestBuildDependenciesInsecureDescriptorRefusedInRealMode verifies that the
// unsafe descriptor opt-in is rejected when mode is real.
func TestBuildDependenciesInsecureDescriptorRefusedInRealMode(t *testing.T) {
	cfg := realConfig()
	cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
	cfg.Nexus.AllowInsecureDescriptor = true
	if _, err := BuildDependencies(cfg, DependencyOptions{}); err == nil || !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor must be false in real mode") {
		t.Fatalf("BuildDependencies() error = %v, want real mode refusal of allow_insecure_descriptor", err)
	}
}

func TestBuildDependenciesLeavesDescriptorSlotUnconfiguredWithoutAnOperator(t *testing.T) {
	deps, err := BuildDependencies(realConfig(), DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	status, ok := deps.Diagnostics.Dependency("builder_descriptor")
	if !ok || !status.Ready || status.Configured {
		t.Fatalf("builder_descriptor status = %+v, want unconfigured and ready", status)
	}
}

// The whole claim of integration mode is that nothing about the wiring changes.
// Asserting it field by field would rot the moment a dependency is added, so
// this builds both modes from the same config and requires the same set of
// non-nil dependencies and the same per-dependency readiness. Only the security
// warnings may differ.
func TestBuildDependenciesIntegrationModeWiresTheSameSetAsRealMode(t *testing.T) {
	options := func() DependencyOptions {
		return DependencyOptions{
			ModelTransport:  fakeModelTransport{},
			NexusPublisher:  fakePublisher{},
			NexusSubscriber: fakeSubscriber{},
			NexusToken:      "token-1",
			TxClient:        txclient.NewFake(),
		}
	}
	realCfg := realConfig()
	realDeps, err := BuildDependencies(realCfg, options())
	if err != nil {
		t.Fatalf("BuildDependencies(real) error = %v", err)
	}

	integrationCfg := realConfig()
	integrationCfg.Mode = config.ModeIntegration
	integrationDeps, err := BuildDependencies(integrationCfg, options())
	if err != nil {
		t.Fatalf("BuildDependencies(integration) error = %v", err)
	}

	if integrationDeps.Diagnostics.Mode != config.ModeIntegration {
		t.Fatalf("Mode = %q, want the posture reported", integrationDeps.Diagnostics.Mode)
	}
	if (integrationDeps.Keeper == nil) != (realDeps.Keeper == nil) ||
		(integrationDeps.Model == nil) != (realDeps.Model == nil) ||
		(integrationDeps.Builder == nil) != (realDeps.Builder == nil) ||
		(integrationDeps.Tx == nil) != (realDeps.Tx == nil) {
		t.Fatalf("integration wiring differs from real: keeper=%v model=%v builder=%v tx=%v",
			integrationDeps.Keeper != nil, integrationDeps.Model != nil,
			integrationDeps.Builder != nil, integrationDeps.Tx != nil)
	}

	readiness := func(deps Dependencies) map[string]bool {
		state := map[string]bool{}
		for _, status := range deps.Diagnostics.Dependencies {
			state[status.Name] = status.Configured && status.Ready
		}
		return state
	}
	realReadiness, integrationReadiness := readiness(realDeps), readiness(integrationDeps)
	if !reflect.DeepEqual(realReadiness, integrationReadiness) {
		t.Fatalf("readiness differs:\n real        = %v\n integration = %v", realReadiness, integrationReadiness)
	}
}

// The relaxation integration mode exists for has to be visible without reading
// the config: both markers are reported, so a node cannot be running with a
// weakened envelope boundary while its diagnostics look clean.
func TestBuildDependenciesIntegrationModeReportsItsRelaxations(t *testing.T) {
	cfg := realConfig()
	cfg.Mode = config.ModeIntegration
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AllowInsecureDescriptor = true
	// With envelope signatures off the transport is the authentication
	// boundary, so an authenticated broker is still required.
	cfg.Nexus.NATSURL = "nats://app:secret@nexus.example.org:4222"

	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelTransport: fakeModelTransport{}, NexusPublisher: fakePublisher{},
		NexusSubscriber: fakeSubscriber{}, NexusToken: "token-1", TxClient: txclient.NewFake(),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	for _, marker := range []string{UnsafeTrustedTransportMarker, UnsafeInsecureDescriptorMarker} {
		found := false
		for _, warning := range deps.Diagnostics.SecurityWarnings {
			if warning == marker {
				found = true
			}
		}
		if !found {
			t.Fatalf("SecurityWarnings = %v, want %s reported", deps.Diagnostics.SecurityWarnings, marker)
		}
	}
}

// TestBuildDependenciesReportsEveryOutboundBusPublish wires the observer at the
// one seam every duty shares: worker handraise, verifier handraise, infer
// receipt, result reveal, verify result and model registration all publish
// through deps.Builder, so a report here covers all of them and none of the call
// sites has to remember to log.
func TestBuildDependenciesReportsEveryOutboundBusPublish(t *testing.T) {
	cfg := realConfig()
	var completions []builderclient.PublishCompletion
	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelTransport:  fakeModelTransport{},
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		NexusToken:      "token-1",
		TxClient:        txclient.NewFake(),
		NexusPublishObserver: func(completion builderclient.PublishCompletion) {
			completions = append(completions, completion)
		},
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if err := deps.Builder.Publish(context.Background(), builderclient.PublishRequest{
		Subject: builderclient.NATSWorkerHandraiseSubject("task-1"),
		TaskID:  "task-1", Payload: []byte("payload"), DedupID: "dedup-1",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(completions) != 1 {
		t.Fatalf("completions = %d, want 1; an outbound publish left no trace", len(completions))
	}
	if completions[0].Subject != builderclient.NATSWorkerHandraiseSubject("task-1") {
		t.Fatalf("subject = %q", completions[0].Subject)
	}
	if completions[0].Result != builderclient.PublishResultPublished {
		t.Fatalf("result = %q", completions[0].Result)
	}
}

// A node that dials a TLS-published Builder endpoint in the clear has to say so
// where an operator looks — the diagnostics warning set — and it says it on top
// of the plaintext marker rather than instead of it, because consensus state
// asked for TLS and this node is not honouring it.
func TestBuildDependenciesMarksDescriptorTLSDowngrade(t *testing.T) {
	cfg := realConfig()
	cfg.Mode = config.ModeFake
	cfg.Nexus.AllowInsecureDescriptor = true
	cfg.Nexus.DowngradeDescriptorTLS = true

	deps, err := BuildDependencies(cfg, DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	for _, marker := range []string{UnsafeInsecureDescriptorMarker, UnsafeDescriptorTLSDowngradeMarker} {
		found := false
		for _, warning := range deps.Diagnostics.SecurityWarnings {
			if warning == marker {
				found = true
			}
		}
		if !found {
			t.Fatalf("SecurityWarnings = %v, want %s reported", deps.Diagnostics.SecurityWarnings, marker)
		}
	}

	cfg.Nexus.DowngradeDescriptorTLS = false
	quiet, err := BuildDependencies(cfg, DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	for _, warning := range quiet.Diagnostics.SecurityWarnings {
		if warning == UnsafeDescriptorTLSDowngradeMarker {
			t.Fatalf("SecurityWarnings = %v, want no downgrade marker with the switch off", quiet.Diagnostics.SecurityWarnings)
		}
	}
}
