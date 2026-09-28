package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/observability/logtest"
	"github.com/TrueOpen/cortex/internal/outbox"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/txclient"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bussharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	"google.golang.org/protobuf/proto"
)

func TestHelpReturnsSuccess(t *testing.T) {
	var stdout bytes.Buffer
	cmd := newRootCommand(context.Background(), &stdout)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(--help) error = %v", err)
	}
	for _, want := range []string{"--config", "--chain-id", "--health-bind", "--store-path"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, stdout.String())
		}
	}
	for _, removed := range []string{"--store-sqlite-path", "--store-kv-path"} {
		if strings.Contains(stdout.String(), removed) {
			t.Fatalf("help retains removed store flag %q:\n%s", removed, stdout.String())
		}
	}
}

func TestNexusInboxCompletionLogIncludesSafeCorrelationFields(t *testing.T) {
	line := formatNexusInboxCompletion(outbox.InboxMessageCompletion{
		Subject: "trueopen.worker-assignment.task-1", Kind: builderclient.KindWorkerAssignmentNotify,
		TaskID: "task-1", MessageID: "message-1", JetStream: true,
		SizeBytes: 512, Result: outbox.InboxMessageResultProcessed, Duration: 1500 * time.Millisecond,
	})
	for _, want := range []string{
		"nexus inbox completed", `subject="trueopen.worker-assignment.task-1"`, `kind="WORKER_ASSIGNMENT_NOTIFY"`,
		`task="task-1"`, `message_id="message-1"`, "jetstream=true", "bytes=512",
		`result="processed"`, "duration_ms=1500",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("completion log %q missing %q", line, want)
		}
	}
	if strings.Contains(strings.ToLower(line), "acked") {
		t.Fatalf("completion log %q claims an ACK that happens after the inbox callback", line)
	}
}

// The readiness controller's Observe hook is the only place that sees why the
// workload is not starting. It must report the module and the reason to the
// log, not only to the health endpoint: /readyz names the dependency without
// the reason, and cortexctl diagnostics has to be asked.
func TestReadinessObserverLogsTheModuleAndReasonThatHoldTheWorkloadDown(t *testing.T) {
	cfg := config.Config{Mode: config.ModeReal}
	health := newRuntimeHealth(cfg)
	var records []observability.LogRecord
	observer := readinessObserver(health, &observability.ReadinessLog{Emit: func(record observability.LogRecord) { records = append(records, record) }})

	observer(daemon.WorkloadReadiness{
		Identity:     diagnostics.DependencyStatus{Name: "keeper_identity", Ready: true},
		ModelSupport: diagnostics.DependencyStatus{Name: "model_support", Ready: true},
		ModelService: diagnostics.DependencyStatus{
			Name: "model_service", Endpoint: "http://127.0.0.1:8000", Configured: true,
			Error: "modelservice health unhealthy: VLLM_HEALTH_UNAVAILABLE retryable",
		},
		Chain: diagnostics.DependencyStatus{Name: "chain", Ready: true},
	})

	messages := make([]string, 0, len(records))
	for _, record := range records {
		messages = append(messages, record.Message)
	}
	joined := strings.Join(messages, "\n")
	for _, want := range []string{
		`dependency not ready dep="model_service"`,
		`reason="modelservice health unhealthy: VLLM_HEALTH_UNAVAILABLE retryable"`,
		`workload not started: not_ready=`,
		"model_service",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("readiness log missing %q:\n%s", want, joined)
		}
	}
	if health.DependencyReady("model_service") {
		t.Fatal("health reports model_service ready after a not-ready snapshot")
	}
	if !health.DependencyReady("keeper_identity") || !health.DependencyReady("chain") {
		t.Fatal("health lost a ready dependency the snapshot reported")
	}
}

// The observer is only worth anything if the running daemon installs it, so
// this drives the real readiness controller and reads cortexd's own log.
func TestRealModeReadinessControllerLogsTheDependencyHoldingTheWorkloadDown(t *testing.T) {
	cfg := realConfigForRunnerTest(t)
	keeper := newTransitionKeeperClient(false)
	rt, err := daemon.BuildRuntimeWithOptions(context.Background(), cfg, daemon.RuntimeOptions{
		SigningClient:               stubSigner{},
		TrustInjectedSignerForTests: true,
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              &recordingNexusPublisher{},
		NexusSubscriber:             &lifecycleNexusSubscriber{},
		NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		KeeperEvents:                keeper,
		ChainStatus:                 keeper,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions returned error: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	captured := captureCortexdLogs(t)

	health := newRuntimeHealth(cfg)
	if err := health.Apply(rt.Dependencies.Diagnostics.Dependencies); err != nil {
		t.Fatalf("health.Apply returned error: %v", err)
	}
	runners, cleanup, err := runtimeRunnersWithHealth(cfg, rt, nil, health)
	if err != nil {
		t.Fatalf("runtimeRunnersWithHealth returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runTestRuntimeRunners(ctx, runners)
	defer func() {
		cancel()
		cleanup()
		for range runners {
			<-done
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		logged := captured.String()
		if strings.Contains(logged, `msg="dependency not ready`) && strings.Contains(logged, `dep=\"keeper_identity\"`) &&
			strings.Contains(logged, `msg="workload not started`) {
			if !strings.Contains(logged, "reason=") {
				t.Fatalf("readiness log named the module without a reason:\n%s", logged)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness never logged the dependency holding the workload down:\n%s", logged)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A nil health must not cost the log: the two reporting paths are independent.
func TestReadinessObserverLogsWithoutHealthWired(t *testing.T) {
	var records []observability.LogRecord
	observer := readinessObserver(nil, &observability.ReadinessLog{Emit: func(record observability.LogRecord) { records = append(records, record) }})

	observer(daemon.WorkloadReadiness{Store: diagnostics.DependencyStatus{Name: "store", Error: "ping store: closed"}})

	messages := make([]string, 0, len(records))
	for _, record := range records {
		messages = append(messages, record.Message)
	}
	if !strings.Contains(strings.Join(messages, "\n"), `dep="store"`) {
		t.Fatalf("readiness log did not report the failing module without health wired: %v", records)
	}
}

func TestNexusInboxCompletionLogEscapesAndBoundsCorrelationFields(t *testing.T) {
	line := formatNexusInboxCompletion(outbox.InboxMessageCompletion{
		Subject: "trueopen.worker-assignment.task-1\nforged", Kind: builderclient.BusMessageKind("ASSIGN\tNOTIFY"),
		TaskID: "task-1\x1b[31m", MessageID: "message\n\t\x1b" + strings.Repeat("x", 4096),
		Result: outbox.InboxMessageResultProcessed,
	})
	if strings.ContainsAny(line, "\n\t\x1b") {
		t.Fatalf("completion log contains raw control characters: %q", line)
	}
	for _, want := range []string{`\n`, `\t`, `\x1b`} {
		if !strings.Contains(line, want) {
			t.Fatalf("completion log %q missing visible escape %q", line, want)
		}
	}
	if len(line) > 1024 {
		t.Fatalf("completion log length = %d, want bounded output", len(line))
	}
}

func TestLegacySingleDashConfigFlagRemainsAccepted(t *testing.T) {
	args := normalizeLegacyDaemonArgs([]string{"-config", "custom.yaml"})
	if got := strings.Join(args, " "); got != "--config custom.yaml" {
		t.Fatalf("normalized args = %q", got)
	}
}

func TestEveryEnvironmentOverrideHasHighestPrecedenceFlag(t *testing.T) {
	// Derived from the allowlist rather than listed by hand: the documented
	// precedence is defaults < YAML < environment < flags, so an override
	// without a flag would silently break that ordering.
	cmd := newRootCommand(context.Background(), &bytes.Buffer{})
	keys := config.DeploymentOverrideKeys()
	if len(keys) == 0 {
		t.Fatal("DeploymentOverrideKeys() is empty")
	}
	for _, key := range keys {
		name := strings.ReplaceAll(key, "_", "-")
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("environment override %q has no --%s flag", key, name)
		}
	}
}

func TestNewDeploymentFlagsOverrideEnvironment(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cortex.yaml")
	contents := fakeDaemonConfigWithStore(filepath.Join(dir, "admin.sock"), filepath.Join(dir, "cortex.kv"))
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	for name, value := range map[string]string{
		"CORTEX_KEEPER_POLL_INTERVAL_MS":            "11",
		"CORTEX_KEEPER_MAX_LAG_BLOCKS":              "12",
		"CORTEX_TASK_RETRY_DELAY_MS":                "13",
		"CORTEX_NEXUS_SUBSCRIBE_MODELS":             "env-model",
		"CORTEX_NEXUS_SUBSCRIBE_TASKS":              "env-task",
		"CORTEX_NEXUS_ENVELOPE_AUTH_MODE":           "trusted_nats_dev",
		"CORTEX_SIGNER_READINESS_PROOF_INTERVAL_MS": "14",
		"CORTEX_SIGNER_PASSWORD_STDIN":              "false",
		"CORTEX_TASK_INPUT_RESOLVER":                "env-resolver",
		"CORTEX_TASK_FIXTURE_ROOT":                  "/env/fixtures",
		"CORTEX_STORE_PATH":                         filepath.Join(dir, "from-env.kv"),
	} {
		t.Setenv(name, value)
	}

	stop := errors.New("capture effective config")
	var captured config.Config
	previous := runtimeBuilder
	runtimeBuilder = func(_ context.Context, cfg config.Config) (*daemon.Runtime, error) {
		captured = cfg
		return nil, stop
	}
	t.Cleanup(func() { runtimeBuilder = previous })

	err := run(context.Background(), []string{
		"--config", configPath,
		"--keeper-poll-interval-ms", "21",
		"--keeper-max-lag-blocks", "22",
		"--task-retry-delay-ms", "23",
		"--nexus-subscribe-models", "flag-model-a,flag-model-b",
		"--nexus-subscribe-tasks", "flag-task",
		"--nexus-envelope-auth-mode", "strict",
		"--signer-readiness-proof-interval-ms", "24",
		"--signer-password-stdin",
		"--task-input-resolver", "fixture",
		"--task-fixture-root", "/flag/fixtures",
		"--store-path", filepath.Join(dir, "from-flag.kv"),
	})
	if !errors.Is(err, stop) {
		t.Fatalf("run() error = %v, want capture sentinel", err)
	}
	if captured.Keeper.PollIntervalMS != 21 || captured.Keeper.MaxLagBlocks != 22 || captured.TaskExecution.RetryDelayMS != 23 {
		t.Fatalf("numeric flag overrides not applied: keeper=%#v task=%#v", captured.Keeper, captured.TaskExecution)
	}
	if got := strings.Join(captured.Nexus.SubscribeModels, ","); got != "flag-model-a,flag-model-b" {
		t.Fatalf("SubscribeModels = %q", got)
	}
	if got := strings.Join(captured.Nexus.SubscribeTasks, ","); got != "flag-task" {
		t.Fatalf("SubscribeTasks = %q", got)
	}
	if captured.Nexus.EnvelopeAuthMode != config.NexusEnvelopeAuthStrict {
		t.Fatalf("EnvelopeAuthMode = %q, want flag override", captured.Nexus.EnvelopeAuthMode)
	}
	if captured.Signer.ReadinessProofIntervalMS != 24 || !captured.Signer.PasswordStdin {
		t.Fatalf("signer flag overrides not applied: %#v", captured.Signer)
	}
	if captured.TaskExecution.InputResolver != "fixture" || captured.TaskExecution.FixtureRoot != "/flag/fixtures" {
		t.Fatalf("task execution flag overrides not applied: %#v", captured.TaskExecution)
	}
	if captured.Store.Path != filepath.Join(dir, "from-flag.kv") {
		t.Fatalf("Store.Path = %q, want flag override", captured.Store.Path)
	}
}

func init() {
	signerForRuntime = func(*daemon.Runtime) signer.Signer { return stubSigner{} }
}

// stubSigner stands in for a signing service so daemon tests do not need one.
type stubSigner struct{}

func (stubSigner) SignDigest(context.Context, signer.DigestRequest) ([]byte, error) {
	return []byte(strings.Repeat("s", 64)), nil
}

func (stubSigner) CanSignCosmosTx() bool { return true }

func (stubSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return []byte("stub-tx-raw"), nil
}

func mainTestEnvelopeAuthenticator() builderclient.BusEnvelopeAuthenticator {
	return builderclient.BusEnvelopeAuthenticatorFunc(func(context.Context, string, builderclient.BusEnvelope) error { return nil })
}

func mainTestEnvelopeSigner() builderclient.BusEnvelopeSigner {
	// Bound to the envelope, not a constant: a stub that returns fixed bytes
	// regardless of what it was asked to sign cannot fail when the signing
	// preimage changes, which is exactly how a wrong-preimage bug once reached
	// main with every test green. These flows do not verify the signature, so the
	// value need not be a real secp256k1 one - it only has to move when the
	// digest moves.
	return builderclient.BusEnvelopeSignerFunc(func(envelope builderclient.BusEnvelope) ([]byte, error) {
		digest, err := builderclient.BusEnvelopeSignDigest(envelope)
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), digest[:]...), digest[:]...), nil
	})
}

// recordingKeeperServicePubkey is the compressed service key recordingKeeperClient
// binds to every operator it is asked about, and recordingKeeperServiceAddress is
// the Bech32 address that key derives. taskdataauth refuses a binding whose
// address is not the one its public key derives, so the two must stay in step.
const recordingKeeperServicePubkey = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var recordingKeeperServiceAddress = func() string {
	pubkey, err := hex.DecodeString(recordingKeeperServicePubkey)
	if err != nil {
		panic(err)
	}
	address, err := signer.AddressFromCompressedPublicKey("trueopen", pubkey)
	if err != nil {
		panic(err)
	}
	return address
}()

// mainTestTaskDataAuth builds the authenticator the runtime owns in production.
// The outbound WorkerHandraise envelope carries service_authorization_nonce
// (field 7) and source_snapshot_height (field 14), and the only admissible
// source for both is one committed read of this node's own ServiceKey binding,
// so a runtime assembled with an injected task-input resolver - which skips the
// authenticator the real wiring would have built - still needs one here.
func mainTestTaskDataAuth(t *testing.T, cfg config.Config) *taskdataauth.Authenticator {
	t.Helper()
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys:     &recordingKeeperClient{},
		Signer:          stubSigner{},
		ChainID:         cfg.ChainID,
		OperatorAddress: cfg.LocalIdentity.OperatorAddress,
		// The binding recordingKeeperClient serves for that operator.
		ServiceAddress: recordingKeeperServiceAddress,
		ServicePubkey:  recordingKeeperServicePubkey,
		ServiceKeyRef:  cfg.LocalIdentity.ServiceKeyRef,
		ExpiryBlocks:   12,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New() error = %v", err)
	}
	return auth
}

func TestDaemonStartsAdminSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "cortexd-*")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll returned error: %v", err)
		}
	})
	socketPath := filepath.Join(dir, "admin.sock")
	dbPath := filepath.Join(dir, "cortex.kv")
	configPath := filepath.Join(t.TempDir(), "dev.yaml")
	if err := os.WriteFile(configPath, []byte(`chain_id: local-cortex
admin:
  uds_path: `+socketPath+`
model_management:
  endpoint: fake://model-management
node:
  rpc_endpoint: fake://node
evidence:
  root: /tmp/cortex-evidence
store:
  path: `+dbPath+`
signer:
  uri: memory://operator
health:
  bind: 127.0.0.1:0
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, []string{"--config", configPath})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("run returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("daemon did not stop")
		}
	})

	client := adminapi.NewClient(socketPath)
	deadline := time.Now().Add(2 * time.Second)
	for {
		capability, err := client.Capability(context.Background())
		if err == nil {
			if !capability.ModelRegistry || capability.ChallengeVerifier {
				t.Fatalf("Capability = %#v", capability)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin socket did not become ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDaemonOpensConfiguredStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	socketPath := startDaemonWithConfig(t, fakeDaemonConfigWithStore("__ADMIN_SOCKET__", dbPath))
	client := adminapi.NewClient(socketPath)

	if _, err := client.Diagnostics(context.Background()); err != nil {
		t.Fatalf("Diagnostics returned error: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("configured Pebble store was not opened: %v", err)
	}
}

func TestDaemonBackedRegistrationSupportsDirectAndViaBuilder(t *testing.T) {
	socketPath := startDaemonForTest(t)
	client := adminapi.NewClient(socketPath)
	manifest := mustDaemonManifest(t)
	quote := modelregistry.FeeQuote{
		Height:              1,
		ExpiresAtHeight:     10,
		Denom:               "utrueopen",
		TreasuryDestination: "trueopen1treasury",
		FeeKind:             modelregistry.FeeKindRegistration,
		Amount:              100,
		GasLimit:            50,
	}

	direct, err := client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest: manifest,
		Quote:    quote,
		Mode:     modelregistry.SubmitDirect,
	})
	if err != nil {
		t.Fatalf("direct ModelRegister returned error: %v", err)
	}
	if direct.TxID == "" {
		t.Fatalf("direct TxID is empty: %#v", direct)
	}

	viaBuilder, err := client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest: manifest,
		Quote:    quote,
		Mode:     modelregistry.SubmitViaBuilder,
	})
	if err != nil {
		t.Fatalf("via-builder ModelRegister returned error: %v", err)
	}
	if viaBuilder.OutboxID == "" {
		t.Fatalf("via-builder OutboxID is empty: %#v", viaBuilder)
	}
}

func TestDaemonUsesConfiguredFeeDenomForTreasuryAndRegistration(t *testing.T) {
	for _, denom := range []string{"uusdc", "hyperlane/0x4444444444444444444444444444444444444444"} {
		t.Run(denom, func(t *testing.T) {
			cfg := strings.Replace(fakeDaemonConfig("__ADMIN_SOCKET__"), "fee_denom: utrueopen", "fee_denom: "+denom, 1)
			client := adminapi.NewClient(startDaemonWithConfig(t, cfg))
			treasury, err := client.TreasuryStatus(context.Background())
			if err != nil || treasury.Denom != denom {
				t.Fatalf("TreasuryStatus = %+v, %v; want denom %q", treasury, err, denom)
			}
			_, err = client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
				Manifest: mustDaemonManifest(t), Mode: modelregistry.SubmitDirect,
				Quote: modelregistry.FeeQuote{Height: 1, ExpiresAtHeight: 10, Denom: denom,
					TreasuryDestination: "trueopen1treasury", FeeKind: modelregistry.FeeKindRegistration,
					Amount: 100, GasLimit: 50},
			})
			if err != nil {
				t.Fatalf("registration with configured denom %q: %v", denom, err)
			}
		})
	}
}

func TestDaemonDiagnosticsExposeFakeModeWiring(t *testing.T) {
	socketPath := startDaemonForTest(t)
	client := adminapi.NewClient(socketPath)

	report, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatalf("Diagnostics returned error: %v", err)
	}
	if report.Mode != "fake" || report.ModelTransport != "fake" {
		t.Fatalf("Diagnostics = %#v", report)
	}
	status, ok := report.Dependency("nexus")
	if !ok || !status.Ready {
		t.Fatalf("nexus status = %#v ok=%v", status, ok)
	}
}

func TestDaemonDiagnosticsExposeRealModeConfiguredEndpoints(t *testing.T) {
	socketPath := startDaemonWithConfig(t, realDaemonConfig("__ADMIN_SOCKET__"))
	client := adminapi.NewClient(socketPath)

	report, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatalf("Diagnostics returned error: %v", err)
	}
	if report.Mode != "real" || report.KeeperEndpoint != "http://127.0.0.1:26657" {
		t.Fatalf("Diagnostics = %#v", report)
	}
	modelStatus, ok := report.Dependency("model_service")
	if !ok || modelStatus.Ready || !strings.Contains(modelStatus.Error, "modelservice health check failed") {
		t.Fatalf("model status = %#v ok=%v", modelStatus, ok)
	}
}

func TestDaemonRealModeExposesBoundaryBackedModelRegistry(t *testing.T) {
	socketPath := startDaemonWithConfig(t, realDaemonConfig("__ADMIN_SOCKET__"))
	client := adminapi.NewClient(socketPath)

	capability, err := client.Capability(context.Background())
	if err != nil {
		t.Fatalf("Capability returned error: %v", err)
	}
	if !capability.ModelRegistry {
		t.Fatalf("ModelRegistry capability = false, want true with boundary-backed real mode registry")
	}

	_, err = client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest: mustDaemonManifest(t),
		Quote: modelregistry.FeeQuote{
			Height:              1,
			ExpiresAtHeight:     30,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             modelregistry.FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode: modelregistry.SubmitDirect,
	})
	if err == nil || !strings.Contains(err.Error(), "registration signer is required") {
		t.Fatalf("ModelRegister direct error = %v, want offline operator signer requirement", err)
	}

	_, err = client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest: mustDaemonManifest(t),
		Quote: modelregistry.FeeQuote{
			Height:              1,
			ExpiresAtHeight:     30,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             modelregistry.FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode: modelregistry.SubmitViaBuilder,
	})
	if err == nil || !strings.Contains(err.Error(), "registration signer is required") {
		t.Fatalf("ModelRegister via-builder error = %v, want offline operator signer requirement", err)
	}
}

func TestDaemonDegradedModeStillRejectsOnlineOperatorRegistration(t *testing.T) {
	keeper := newTransitionKeeperClient(false)
	tx := txclient.NewFake()
	socketPath := startDaemonWithRuntimeBuilder(t, realDaemonConfig("__ADMIN_SOCKET__"), func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
		return daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
			SigningClient:               stubSigner{},
			TrustInjectedSignerForTests: true,
			ModelClient:                 modelservice.NewFakeService(),
			NexusPublisher:              &recordingNexusPublisher{},
			NexusSubscriber:             &recordingNexusSubscriber{},
			TxClient:                    tx,
			Keeper:                      keeper,
			KeeperEvents:                keeper,
			ChainStatus:                 keeper,
		})
	})
	client := adminapi.NewClient(socketPath)

	report, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatalf("Diagnostics returned error: %v", err)
	}
	identityStatus, ok := report.Dependency("keeper_identity")
	if !ok || identityStatus.Ready {
		t.Fatalf("keeper_identity status = %#v ok=%v, want degraded", identityStatus, ok)
	}
	_, err = client.CurrentModelRegister(context.Background(), modelregistry.CurrentRegisterRequest{Manifest: mustCurrentDaemonManifest(t)})
	if err == nil || !strings.Contains(err.Error(), "current model registration submitter is required") {
		t.Fatalf("CurrentModelRegister error = %v, want the online operator submission refused", err)
	}
	if len(tx.Requests()) != 0 {
		t.Fatal("operator registration reached the daemon service-key transaction client")
	}
}

func TestRuntimeRunnersGateAndRestartWorkloadWhileKeepingReadinessCurrent(t *testing.T) {
	cfg := realConfigForRunnerTest(t)
	keeper := newTransitionKeeperClient(false)
	subscriber := &lifecycleNexusSubscriber{errors: make(chan error, 1)}
	modelClient := &healthControlledModelClient{Client: modelservice.NewFakeService(), healthy: true}
	rt, err := daemon.BuildRuntimeWithOptions(context.Background(), cfg, daemon.RuntimeOptions{
		SigningClient:               stubSigner{},
		TrustInjectedSignerForTests: true,
		ModelClient:                 modelClient,
		NexusPublisher:              &recordingNexusPublisher{},
		NexusSubscriber:             subscriber,
		NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		KeeperEvents:                keeper,
		ChainStatus:                 keeper,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions returned error: %v", err)
	}
	if got := modelClient.LastModelServiceID(); got != cfg.LocalIdentity.ModelServiceID {
		t.Fatalf("model health service id = %q, want %q", got, cfg.LocalIdentity.ModelServiceID)
	}
	t.Cleanup(func() { _ = rt.Close() })
	health := observability.NewIntegrationHealth()
	if err := health.Apply(rt.Dependencies.Diagnostics.Dependencies); err != nil {
		t.Fatalf("health.Apply returned error: %v", err)
	}
	captured := captureCortexdLogs(t)
	runners, cleanup, err := runtimeRunnersWithHealth(cfg, rt, nil, health)
	if err != nil {
		t.Fatalf("runtimeRunnersWithHealth returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runTestRuntimeRunners(ctx, runners)
	t.Cleanup(func() {
		cancel()
		cleanup()
		for range runners {
			if err := <-done; err != nil {
				t.Fatalf("runtime runner returned error: %v", err)
			}
		}
	})

	waitForKeeperPoll(t, keeper)
	if got := subscriber.SubscribeCount(); got != 0 {
		t.Fatalf("workload subscriptions = %d before readiness, want 0", got)
	}
	if len(keeper.Positions()) == 0 {
		t.Fatal("Keeper event polling did not run in degraded mode")
	}
	assertReadyzStatus(t, health, http.StatusServiceUnavailable)

	keeper.SetReady(true)
	firstSubscriptions := waitForSubscriberStarts(t, subscriber, 1)
	assertReadyzStatus(t, health, http.StatusOK)
	subscriber.errors <- errors.New("consumer closed")
	subscriberErrorLog := waitForCortexdLogRecord(t, captured, "nexus subscriber delivery error")
	assertCortexdLogRecord(t, subscriberErrorLog, slog.LevelError, "nexus subscriber delivery error")
	if !strings.Contains(subscriberErrorLog, "source=internal/outbox/inbox_runner.go:") {
		t.Fatalf("subscriber error source = %q, want the domain caller", subscriberErrorLog)
	}
	keeper.SetReady(false)
	waitForSubscriberStops(t, subscriber, firstSubscriptions)
	assertReadyzStatus(t, health, http.StatusServiceUnavailable)
	waitForWorkloadDeactivation(t, rt)
	keeper.SetReady(true)
	secondSubscriptions := waitForSubscriberStarts(t, subscriber, firstSubscriptions+1)
	modelClient.SetHealthy(false)
	waitForSubscriberStops(t, subscriber, secondSubscriptions)
	assertReadyzStatus(t, health, http.StatusServiceUnavailable)
	if status, ok := rt.DiagnosticsSnapshot().Dependency("model_service"); !ok || status.Ready {
		t.Fatalf("live model_service diagnostics = %#v ok=%v, want unready", status, ok)
	}
	waitForWorkloadDeactivation(t, rt)
	modelClient.SetHealthy(true)
	waitForSubscriberStarts(t, subscriber, secondSubscriptions+1)
	assertReadyzStatus(t, health, http.StatusOK)
	if status, ok := rt.DiagnosticsSnapshot().Dependency("model_service"); !ok || !status.Ready {
		t.Fatalf("live model_service diagnostics = %#v ok=%v, want recovered", status, ok)
	}
}

// Fake mode runs neither the readiness controller nor the Keeper poller, so
// requiring either lifecycle dependency would leave it permanently unready.
func TestFakeRuntimeHealthDoesNotRequireLifecycleDependencies(t *testing.T) {
	health := newRuntimeHealth(config.Config{Mode: config.ModeFake})
	for _, name := range []string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support", "nexus", "nexus_envelope_auth", "builder_descriptor"} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s): %v", name, err)
		}
	}
	assertReadyzStatus(t, health, http.StatusOK)
}

func TestDaemonRealModeRejectsOnlineOperatorRegistration(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	socketPath := startDaemonWithConfig(t, realDaemonConfigWithStore("__ADMIN_SOCKET__", dbPath))
	client := adminapi.NewClient(socketPath)

	_, err := client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest: mustDaemonManifest(t),
		Quote: modelregistry.FeeQuote{
			Height:              1,
			ExpiresAtHeight:     30,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             modelregistry.FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode: modelregistry.SubmitViaBuilder,
	})
	if err == nil || !strings.Contains(err.Error(), "registration signer is required") {
		t.Fatalf("ModelRegister via-builder error = %v, want offline operator signer requirement", err)
	}
}

func TestDaemonRealModeAdmitsIncomingOrderAsCandidate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	subscriber := &recordingNexusSubscriber{}
	publisher := &recordingNexusPublisher{}
	keeper := &workerHandraiseWiringKeeper{recordingKeeperClient: &recordingKeeperClient{}}
	var runtime *daemon.Runtime
	contents := realDaemonConfigWithStoreAndSubscriptions("__ADMIN_SOCKET__", dbPath)
	contents = strings.Replace(contents, "subscribe_models: [1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c]", "subscribe_models: [099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f]", 1)
	contents = strings.Replace(contents, "supported_model_profiles: [1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c@1=llm_text_v1]", "supported_model_profiles: [099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f@1=llm_text_v1]", 1)
	contents = strings.Replace(contents, "  endpoint: 127.0.0.1:9090\n  transport: grpc", "  transport: fake", 1)
	contents = strings.Replace(contents, "  input_resolver: nexus", "  input_resolver: fixture\n  fixture_root: "+t.TempDir(), 1)
	socketPath := startDaemonWithRuntimeBuilder(t, contents, func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
		var err error
		runtime, err = daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
			SigningClient:               stubSigner{},
			TrustInjectedSignerForTests: true,
			ModelClient:                 modelservice.NewFakeService(),
			NexusPublisher:              publisher,
			NexusSubscriber:             subscriber,
			NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
			NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
			TxClient:                    txclient.NewFake(),
			Keeper:                      keeper,
			KeeperEvents:                keeper,
			ChainStatus:                 keeper,
			TaskInputResolver:           mainTaskInputResolver{},
		})
		if err != nil {
			return nil, err
		}
		runtime.TaskDataAuth = mainTestTaskDataAuth(t, cfg)
		return runtime, nil
	})
	_ = adminapi.NewClient(socketPath)

	waitForSubscription(t, subscriber, builderclient.NATSTaskOpenSubject(modelservice.FakeModelID))
	const sessionID = "6ae490f8c53918ded64f2c390f57adaeecc84f6beec9f9575fdf0beeb600fa16"
	const orderSequence = uint64(1)
	signedOrder, taskHash := mainTestSignedOrder(t, "trueopen-devnet-1", modelservice.FakeModelID, sessionID, orderSequence, 240)
	subject := builderclient.NATSTaskOpenSubject(modelservice.FakeModelID)
	now := time.Now().UTC()
	payload, err := builderclient.EncodeAuthenticatedBusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOrderBroadcast, ChainID: "trueopen-devnet-1", Subject: subject,
		SenderOperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", SenderParticipantType: builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: 23,
		// Within the 30s nexus.envelope_ttl_ms this daemon is configured with.
		IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
	}, &busv1.OrderBroadcastV1{SignedOrder: signedOrder}, mainTestEnvelopeSigner())
	if err != nil {
		t.Fatalf("EncodeAuthenticatedBusMessage returned error: %v", err)
	}
	if err := subscriber.Deliver(context.Background(), subject, builderclient.NATSMessage{
		Subject: subject,
		Data:    payload,
	}); err != nil {
		t.Fatalf("Deliver returned error: %v", err)
	}
	if err := subscriber.Deliver(context.Background(), subject, builderclient.NATSMessage{
		Subject: subject,
		Data:    payload,
	}); err != nil {
		t.Fatalf("duplicate Deliver returned error: %v", err)
	}

	candidate, err := layout.GetCandidateAdmission(context.Background(), runtime.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("Candidate returned error: %v", err)
	}
	if len(candidate.HandraisePayload) == 0 || codec.Hash(candidate.HandraiseDigest[:]) != codec.HashBytes(candidate.HandraisePayload) {
		t.Fatalf("candidate = %#v, want stable signed handraise", candidate)
	}
	published := publisher.Published()
	if len(published) != 1 || !bytes.Equal(published[0].Payload, candidate.HandraisePayload) {
		t.Fatalf("published handraises = %#v, want duplicate delivery deduplicated after candidate publish", published)
	}
}

func TestDaemonRealModeStartsKeeperPoller(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	sessionID := "2850189542823ff1df273b4e64bd741319a7d1b54fbceec48d7338ac5b3a3f03"
	orderSequence := uint64(1)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	orderDigest := codec.HashWithDomain("DAEMON_POLLER_ORDER", []byte(taskID))
	taskHash := codec.HashWithDomain("DAEMON_KEEPER_TASK", []byte(taskID))
	keeper := &recordingKeeperClient{pages: []chainclient.KeeperEventsPage{{
		ChainHeight:     20,
		FinalizedHeight: 12,
		LastEventHeight: 12,
		LastPosition:    chainclient.BlockEndPosition(12),
		Events: []chainclient.KeeperEvent{
			{Type: chainclient.KeeperEventAssignAcceptedPendingRandomness, TaskID: taskID, Height: 11, SessionID: sessionID, OrderSequence: orderSequence, OrderDigest: orderDigest, ModelID: modelservice.FakeModelID, ProfileVersion: "1"},
			{Type: chainclient.KeeperEventAssignmentFinalized, TaskID: taskID, Height: 12, SessionID: sessionID, OrderSequence: orderSequence, OrderDigest: orderDigest, Worker: "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k", WinnerConfirmHeight: 12, ModelID: "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c", ProfileVersion: "1", Payload: mustDaemonJSON(t, map[string]any{"input": "daemon poll prompt"})},
		},
	}}}
	contents := realDaemonConfigWithKeeperPolling("__ADMIN_SOCKET__", dbPath)
	var runtime *daemon.Runtime
	socketPath := startDaemonWithRuntimeBuilder(t, contents, func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
		var err error
		runtime, err = daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
			SigningClient:               stubSigner{},
			TrustInjectedSignerForTests: true,
			ModelTransport:              fakeModelTransport{},
			NexusPublisher:              &recordingNexusPublisher{},
			NexusSubscriber:             &recordingNexusSubscriber{},
			TxClient:                    txclient.NewFake(),
			Keeper:                      keeper,
			KeeperEvents:                keeper,
			TaskInputResolver:           mainTaskInputResolver{},
		})
		return runtime, err
	})
	_ = adminapi.NewClient(socketPath)

	waitForKeeperHeight(t, runtime.Store, 12)
	if len(keeper.Positions()) == 0 || keeper.Positions()[0] != (chainclient.EventPosition{}) {
		t.Fatalf("keeper positions = %#v, want first poll from zero position", keeper.Positions())
	}
	infer, err := layout.GetInferRecord(context.Background(), runtime.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if infer.TaskID != taskID || infer.Stage != layout.StageQueued {
		t.Fatalf("infer record = %#v, want Keeper assignment effect", infer)
	}
}

func TestKeeperPollerAppliesAssignmentEffectAndRunsProjector(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "runtime.db"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	defer db.Close()
	projector := &countingProjector{}
	const sessionID = "0d72bed1a2308510efdf635cdca46136d4679f216f5d93432fea034f19d153c7"
	const taskID = "projected-task"
	orderDigest := codec.HashWithDomain("PROJECTOR_EFFECT_ORDER", []byte(taskID))
	taskHash := codec.HashWithDomain("DAEMON_KEEPER_TASK", []byte(taskID))
	keeper := &recordingKeeperClient{pages: []chainclient.KeeperEventsPage{{
		ChainHeight:     20,
		FinalizedHeight: 13,
		LastEventHeight: 13,
		LastPosition:    chainclient.BlockEndPosition(13),
		Events: []chainclient.KeeperEvent{{
			Type:                chainclient.KeeperEventAssignmentFinalized,
			Height:              13,
			SessionID:           sessionID,
			TaskID:              taskID,
			OrderSequence:       1,
			OrderDigest:         orderDigest,
			Worker:              "projected-worker",
			WinnerConfirmHeight: 13,
			ModelID:             "projected-model",
			ProfileVersion:      "1",
		}},
	}}}
	rt := &daemon.Runtime{
		Store:        db,
		KeeperEvents: keeper,
		Dependencies: daemon.Dependencies{
			Keeper: keeper,
		},
		Reconciler: daemon.NewReconciler(daemon.ReconcilerOptions{TaskReader: keeper}),
	}
	manager := daemon.NewTaskRunner(daemon.TaskRunnerConfig{Store: db, LocalWorkerAddress: "projected-worker"})
	poller := newKeeperPollerWithTaskRunner(config.Config{
		Mode: config.ModeReal,
		Keeper: config.KeeperConfig{
			PollIntervalMS: 10,
		},
	}, rt, projector, manager)
	if poller == nil {
		t.Fatalf("newKeeperPoller returned nil")
	}

	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	if got := projector.Count(); got != 1 {
		t.Fatalf("projector RunOnce count = %d, want 1 after Keeper effect", got)
	}
	infer, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if infer.TaskID != taskID || infer.Stage != layout.StageQueued {
		t.Fatalf("infer record = %#v, want assignment effect", infer)
	}
	height, err := db.KeeperLastProcessedHeight(ctx)
	if err != nil || height != 13 {
		t.Fatalf("KeeperLastProcessedHeight = %d, %v, want 13", height, err)
	}
}

func TestRunProjectorRefreshesPeriodically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	projector := &countingProjector{after: func(count int) {
		if count >= 2 {
			cancel()
		}
	}}

	if err := runProjector(ctx, projector, time.Millisecond); err != nil {
		t.Fatalf("runProjector returned error: %v", err)
	}
	if got := projector.Count(); got < 2 {
		t.Fatalf("projector RunOnce count = %d, want at least 2", got)
	}
}

func TestDaemonRealModeReportsUnavailableNexus(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	socketPath := startDaemonWithRuntimeBuilder(t, realDaemonConfigWithInvalidNATS("__ADMIN_SOCKET__", dbPath), func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
		return daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
			SigningClient:               stubSigner{},
			TrustInjectedSignerForTests: true,
			TxClient:                    txclient.NewFake(),
			Keeper:                      &recordingKeeperClient{},
			KeeperEvents:                &recordingKeeperClient{},
		})
	})
	client := adminapi.NewClient(socketPath)

	report, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatalf("Diagnostics returned error: %v", err)
	}
	nexusStatus, ok := report.Dependency("nexus")
	if !ok || nexusStatus.Ready || !strings.Contains(nexusStatus.Error, "unsupported nexus nats url scheme") {
		t.Fatalf("nexus status = %#v ok=%v", nexusStatus, ok)
	}

}

func TestDaemonRealModePollsKeeperWhenNexusUnavailable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "runtime.db")
	keeper := &recordingKeeperClient{pages: []chainclient.KeeperEventsPage{{
		ChainHeight:     20,
		FinalizedHeight: 12,
		LastEventHeight: 12,
		LastPosition:    chainclient.BlockEndPosition(12),
		Events:          []chainclient.KeeperEvent{{Type: chainclient.KeeperEventAssignAcceptedPendingRandomness, TaskID: "task-nexus-down", Height: 12}},
	}}}
	var runtime *daemon.Runtime
	socketPath := startDaemonWithRuntimeBuilder(t, realDaemonConfigWithInvalidNATS("__ADMIN_SOCKET__", dbPath), func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
		var err error
		runtime, err = daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
			SigningClient:               stubSigner{},
			TrustInjectedSignerForTests: true,
			ModelTransport:              fakeModelTransport{},
			TxClient:                    txclient.NewFake(),
			Keeper:                      keeper,
			KeeperEvents:                keeper,
		})
		return runtime, err
	})
	_ = adminapi.NewClient(socketPath)

	waitForKeeperHeight(t, runtime.Store, 12)
	if len(keeper.Positions()) == 0 {
		t.Fatalf("keeper was not polled while nexus was unavailable")
	}
}

func TestNewTaskRunnerRestoresCompactActiveInferDocument(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "runtime.db"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	taskHash := codec.HashWithDomain("TASK_RUNNER_CONFIG_ORDER", []byte("task-runner-config"))
	task := store.InferTask{
		TaskID: identity.TaskIDString("0465d9d63a04057e9f6896371452af72510ed64ce158f94eab22453120955629", 1), SessionID: "0465d9d63a04057e9f6896371452af72510ed64ce158f94eab22453120955629",
		OrderSequence: 1, AssignmentDigest: codec.HashBytes([]byte("assignment")), ModelID: modelservice.FakeModelID,
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140, Stage: "queued",
		// Fields 11 and 12 of the task's TRUEOPEN_BUS_ENVELOPE_V1 identity are task
		// state, so a restored document that lost them could not publish.
		BuilderSetID: "7", BuilderSetHash: bytes.Repeat([]byte{0x5a}, 32),
	}
	if err := seedInferTask(ctx, db, taskHash, task); err != nil {
		t.Fatalf("seedInferTask returned error: %v", err)
	}

	cfg := config.Config{
		Mode:    config.ModeReal,
		ChainID: "chain-A",
		Artifacts: config.ArtifactsConfig{
			Root: filepath.Join(dir, "evidence"),
		},
		Keeper: config.KeeperConfig{
			PollIntervalMS: 1000,
			MaxLagBlocks:   1,
		},
		TaskExecution: config.TaskExecutionConfig{
			RetryDelayMS: 2500,
		},
		LocalIdentity: config.LocalIdentityConfig{
			OperatorAddress:        "worker-local",
			SupportedModelProfiles: []string{"099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f@1=llm_text_v1"},
			ModelServiceID:         "fake-model-service",
		},
	}
	runner, err := newTaskRunner(cfg, &daemon.Runtime{
		Store: db,
		Dependencies: daemon.Dependencies{
			Model:   modelservice.NewFakeService(),
			Builder: builderclient.NewFakeClient(),
			Tx:      txclient.NewFake(),
		},
	})
	if err != nil {
		t.Fatalf("newTaskRunner returned error: %v", err)
	}
	if runner == nil {
		t.Fatalf("newTaskRunner returned nil")
	}

	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	infer, verify := runner.ActiveTasks()
	if got, ok := infer[taskHash]; !ok || !reflect.DeepEqual(got, task) {
		t.Fatalf("active infer = %#v, want restored task %#v", infer, task)
	}
	if len(verify) != 0 {
		t.Fatalf("active verify = %#v, want independent empty document", verify)
	}
}

// Duty selection is retired, so both responsibilities now resolve to the one
// configured operator address unconditionally -- there is no configuration under
// which a node answers to one of them and not the other.
func TestBothResponsibilitiesUseOneCortexNodeIdentity(t *testing.T) {
	cfg := config.Config{LocalIdentity: config.LocalIdentityConfig{OperatorAddress: "trueopen1dualnode"}}
	workerAddress := cfg.LocalIdentity.OperatorAddress
	verifierAddress := cfg.LocalIdentity.OperatorAddress
	if workerAddress != "trueopen1dualnode" || verifierAddress != workerAddress {
		t.Fatalf("worker/verifier identities = %q/%q, want one cortex node address", workerAddress, verifierAddress)
	}
}

func TestEvidenceCleanupPlannerUsesFinalizedKeeperCursor(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "cleanup.db"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if advanced, err := db.AdvanceKeeperLastProcessedHeight(ctx, 321); err != nil || !advanced {
		t.Fatalf("AdvanceKeeperLastProcessedHeight returned advanced=%v error=%v", advanced, err)
	}
	planner := evidenceCleanupPlanner(config.Config{Artifacts: config.ArtifactsConfig{
		Root: filepath.Join(dir, "evidence"), RetentionPolicyVersion: "retention-v2",
	}}, &daemon.Runtime{Store: db})
	plan, err := planner(ctx)
	if err != nil {
		t.Fatalf("cleanup planner returned error: %v", err)
	}
	if plan.CurrentHeight != 321 || plan.RetentionPolicyVersion != "retention-v2" || plan.Digest == "" || len(plan.Items) != 0 {
		t.Fatalf("cleanup plan = %#v", plan)
	}
}

func TestRuntimeRunnersFailWhenTaskRunnerEvidenceStoreCannotOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	db, err := store.Open(ctx, filepath.Join(dir, "runtime.db"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Config{
		Mode:    config.ModeReal,
		ChainID: "chain-A",
		Artifacts: config.ArtifactsConfig{
			Root: filepath.Join(blocker, "evidence"),
		},
		Keeper: config.KeeperConfig{
			PollIntervalMS: 1000,
		},
		TaskExecution: config.TaskExecutionConfig{
			RetryDelayMS: 30000,
		},
		LocalIdentity: config.LocalIdentityConfig{
			OperatorAddress:        "worker-local",
			SupportedModelProfiles: []string{"099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f@1=llm_text_v1"},
			ModelServiceID:         "fake-model-service",
		},
	}
	rt := &daemon.Runtime{
		Store: db,
		Dependencies: daemon.Dependencies{
			Model:   modelservice.NewFakeService(),
			Builder: builderclient.NewFakeClient(),
			Tx:      txclient.NewFake(),
		},
	}

	_, _, err = runtimeRunners(cfg, rt, nil)
	if err == nil || !strings.Contains(err.Error(), "task runner evidence store") {
		t.Fatalf("runtimeRunners error = %v, want task runner evidence store failure", err)
	}
}

func TestNewTaskRunnerAllowsBuilderOnlyWorkloadWithoutTxClient(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "runtime.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := realConfigForRunnerTest(t)
	cfg.Tx.Enabled = false
	rt := &daemon.Runtime{
		Store: db,
		Dependencies: daemon.Dependencies{
			Model:       modelservice.NewFakeService(),
			Builder:     builderclient.NewFakeClient(),
			Diagnostics: diagnostics.Diagnostics{Dependencies: []diagnostics.DependencyStatus{{Name: "keeper_identity", Ready: true}}},
		},
	}

	runner, err := newTaskRunner(cfg, rt)
	if err != nil || runner == nil {
		t.Fatalf("newTaskRunner() = %#v, %v, want Builder-only runner without tx dependency", runner, err)
	}
}

func TestNewTaskRunnerAllowsWorkerHandraiseWithSelfRescueDisabledAndNoFeeCap(t *testing.T) {
	ctx := context.Background()
	cfg := realConfigForRunnerTest(t)
	cfg.LocalIdentity.SupportedModelProfiles = []string{"099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f@1=llm_text_v1"}
	cfg.LocalIdentity.ModelServiceID = "fake-model-service"
	cfg.ModelManagement.Transport = "fake"
	cfg.ModelManagement.Endpoint = ""
	cfg.TaskExecution.InputResolver = config.InputResolverFixture
	cfg.TaskExecution.FixtureRoot = t.TempDir()
	cfg.SelfRescue.Enabled = false
	cfg.SelfRescue.MaxFeeAmount = 0

	keeper := &workerHandraiseWiringKeeper{recordingKeeperClient: &recordingKeeperClient{}}
	publisher := &recordingNexusPublisher{}
	rt, err := daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
		SigningClient:               stubSigner{},
		TrustInjectedSignerForTests: true,
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              publisher,
		NexusSubscriber:             &recordingNexusSubscriber{},
		NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		KeeperEvents:                keeper,
		ChainStatus:                 keeper,
		TaskInputResolver:           mainTaskInputResolver{},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	rt.TaskDataAuth = mainTestTaskDataAuth(t, cfg)
	// The production daemon constructs TaskRunner before chain sync may activate
	// the workload. Its signing identity must therefore be resolved lazily.
	runner, err := newTaskRunner(cfg, rt)
	if err != nil || runner == nil {
		t.Fatalf("newTaskRunner() = %#v, %v", runner, err)
	}
	// Keeper event lag is unknown until the first poll, and an unknown lag must
	// not read as synced -- otherwise a node could activate and handraise on
	// stale state before confirming it has caught up. Report a synced page the
	// way the poller does.
	rt.ObserveChainProgress(daemon.ChainProgress{CursorHeight: 100, ChainHeight: 100})
	readiness := rt.CheckWorkloadReadiness(ctx)
	if !readiness.Ready() {
		t.Fatalf("workload readiness = %#v, want ready once caught up", readiness)
	}
	if err := rt.ActivateWorkload(readiness.ServiceAddress, readiness.ServicePubkey); err != nil {
		t.Fatalf("ActivateWorkload() error = %v", err)
	}
	if !rt.WorkloadActive() {
		t.Fatal("runtime workload is not active")
	}

	const sessionID = "0fedd8d512a2c5f844adfafad8efca6b813c9e1f0b69f1f715d12effd967fc9c"
	const orderSequence = uint64(1)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	signedOrder, taskHash := mainTestSignedOrder(t, cfg.ChainID, modelservice.FakeModelID, sessionID, orderSequence, 240)
	subject := builderclient.NATSTaskOpenSubject(modelservice.FakeModelID)
	now := time.Now().UTC()
	payload, err := builderclient.EncodeAuthenticatedBusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOrderBroadcast, ChainID: cfg.ChainID, Subject: subject,
		SenderOperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", SenderParticipantType: builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: 23,
		// Within the 30s nexus.envelope_ttl_ms this daemon is configured with.
		IssuedAt: now, ExpiresAt: now.Add(30 * time.Second),
	}, &busv1.OrderBroadcastV1{SignedOrder: signedOrder}, mainTestEnvelopeSigner())
	if err != nil {
		t.Fatalf("EncodeAuthenticatedBusMessage() error = %v", err)
	}
	if err := runner.HandleNexusMessage(ctx, builderclient.NATSMessage{Subject: subject, Data: payload}); err != nil {
		t.Fatalf("HandleNexusMessage() error = %v", err)
	}
	candidate, err := layout.GetCandidateAdmission(ctx, rt.Store, layout.StoredHash(taskHash))
	if err != nil || len(candidate.HandraisePayload) == 0 {
		t.Fatalf("Worker handraise candidate = %#v, %v, want one signed handraise", candidate, err)
	}
	published := publisher.Published()
	if len(published) != 1 || published[0].Subject != builderclient.NATSWorkerHandraiseSubject(taskID) || !bytes.Equal(published[0].Payload, candidate.HandraisePayload) {
		t.Fatalf("Worker handraise publishes = %#v, want candidate bytes", published)
	}
}

func TestRunReturnsRuntimeSetupErrorWithoutDeadlock(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "cortexd-runtime-error-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	db, err := store.Open(context.Background(), filepath.Join(dir, "runtime.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "real.yaml")
	contents := strings.ReplaceAll(realDaemonConfigWithStore(filepath.Join(dir, "admin.sock"), filepath.Join(dir, "configured.db")), "__ADMIN_SOCKET__", filepath.Join(dir, "admin.sock"))
	badEvidencePath := filepath.Join(dir, "evidence-file")
	if err := os.WriteFile(badEvidencePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile(evidence) error = %v", err)
	}
	contents = strings.Replace(contents, "/tmp/cortex-evidence", badEvidencePath, 1)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	previous := runtimeBuilder
	runtimeBuilder = func(context.Context, config.Config) (*daemon.Runtime, error) {
		return &daemon.Runtime{
			Store: db,
			Dependencies: daemon.Dependencies{
				Model: modelservice.NewFakeService(), Builder: builderclient.NewFakeClient(),
				Diagnostics: diagnostics.Diagnostics{Dependencies: []diagnostics.DependencyStatus{{Name: "keeper_identity", Ready: true}}},
			},
		}, nil
	}
	t.Cleanup(func() { runtimeBuilder = previous })

	errCh := make(chan error, 1)
	go func() { errCh <- run(context.Background(), []string{"--config", configPath}) }()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "task runner evidence store") {
			t.Fatalf("run() error = %v, want task runner evidence setup failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run() deadlocked after runtime runner setup failed")
	}
}

func startDaemonForTest(t *testing.T) string {
	t.Helper()
	return startDaemonWithConfig(t, fakeDaemonConfig("__ADMIN_SOCKET__"))
}

func startDaemonWithConfig(t *testing.T, contents string) string {
	t.Helper()
	return startDaemonWithRuntimeBuilder(t, contents, func(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
		keeper := &recordingKeeperClient{}
		return daemon.BuildRuntimeWithOptions(ctx, cfg, daemon.RuntimeOptions{
			SigningClient:               stubSigner{},
			TrustInjectedSignerForTests: true,
			NexusSubscriber:             &recordingNexusSubscriber{},
			TxClient:                    txclient.NewFake(),
			Keeper:                      keeper,
			KeeperEvents:                keeper,
			ChainStatus:                 keeper,
		})
	})
}

func startDaemonWithRuntimeBuilder(t *testing.T, contents string, builder func(context.Context, config.Config) (*daemon.Runtime, error)) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cortexd-*")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll returned error: %v", err)
		}
	})
	socketPath := filepath.Join(dir, "admin.sock")
	contents = strings.ReplaceAll(contents, "__ADMIN_SOCKET__", socketPath)
	if strings.Contains(contents, "__KV_PATH__") {
		contents = strings.ReplaceAll(contents, "__KV_PATH__", filepath.Join(dir, "cortex.kv"))
	}
	configPath := filepath.Join(t.TempDir(), "dev.yaml")
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	var earlyRunErr error
	previous := runtimeBuilder
	runtimeBuilder = builder
	go func() {
		errCh <- run(ctx, []string{"--config", configPath})
	}()
	t.Cleanup(func() {
		cancel()
		if earlyRunErr != nil {
			runtimeBuilder = previous
			return
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("run returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("daemon did not stop")
		}
		runtimeBuilder = previous
	})

	earlyRunErr = waitForAdminSocket(t, socketPath, errCh)
	if earlyRunErr != nil {
		t.Fatalf("run returned before admin socket became ready: %v", earlyRunErr)
	}
	return socketPath
}

func waitForKeeperHeight(t *testing.T, db *store.Store, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		height, err := db.KeeperLastProcessedHeight(context.Background())
		if err == nil && height == want {
			return
		}
		if err != nil {
			t.Fatalf("KeeperLastProcessedHeight returned error: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("Keeper processed height did not reach %d (got %d)", want, height)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type recordingNexusPublisher struct {
	mu        sync.Mutex
	published []builderclient.PublishRequest
}

type healthControlledModelClient struct {
	modelservice.Client
	mu                 sync.RWMutex
	healthy            bool
	lastModelServiceID string
}

func (c *healthControlledModelClient) Health(_ context.Context, request modelservice.HealthRequest) (modelservice.HealthResponse, error) {
	c.mu.Lock()
	healthy := c.healthy
	c.lastModelServiceID = request.ModelServiceID
	c.mu.Unlock()
	return modelservice.HealthResponse{RequestID: request.RequestID, ModelServiceID: request.ModelServiceID, Healthy: healthy}, nil
}

func (c *healthControlledModelClient) LastModelServiceID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastModelServiceID
}

func (c *healthControlledModelClient) SetHealthy(healthy bool) {
	c.mu.Lock()
	c.healthy = healthy
	c.mu.Unlock()
}

type fakeModelTransport struct{}

func (fakeModelTransport) Invoke(_ context.Context, _ string, _ any, _ any) error {
	return nil
}

type mainTaskInputResolver struct{}

func (mainTaskInputResolver) ResolveTaskInput(context.Context, daemon.TaskInputRef) ([]byte, error) {
	return []byte("main task input fixture"), nil
}

type recordingNexusSubscriber struct {
	mu       sync.Mutex
	handlers map[string]builderclient.MessageHandler
}

type recordingKeeperClient struct {
	mu        sync.Mutex
	pages     []chainclient.KeeperEventsPage
	positions []chainclient.EventPosition
	tasks     map[string]chainclient.TaskSnapshot
}

type workerHandraiseWiringKeeper struct{ *recordingKeeperClient }

func (*workerHandraiseWiringKeeper) TaskReceiptFacts(context.Context, string) (chainclient.TaskReceiptFactsAnswer, error) {
	return chainclient.TaskReceiptFactsAnswer{}, chainclient.ErrNotFound
}

func (*workerHandraiseWiringKeeper) CurrentCandidateMember(context.Context, string) (chainclient.CandidateMemberRefSnapshot, error) {
	return chainclient.CandidateMemberRefSnapshot{
		CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x31}, 32)),
		Slot:                    1, SlotVersion: 1, OperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
	}, nil
}

func (*workerHandraiseWiringKeeper) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return chainclient.VerifierCandidateMemberSnapshot{
		CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
			CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x31}, 32)),
			Slot:                    1, SlotVersion: 1, OperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		},
		InferReceiptHash: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x41}, 32)), ExpiryHeight: 220,
	}, nil
}

// daemonTestOperator is local_identity.operator_address in the real-mode test
// configs. The fake profiles name it as their proposer: the node serves its
// own registrations, which need no fetched manifest.
const daemonTestOperator = "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k"

func (*workerHandraiseWiringKeeper) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return chainclient.CurrentModelProfileSnapshot{
		Model: chainclient.CurrentModelSnapshot{ModelID: modelservice.FakeModelID, Status: "ACTIVE"},
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID: modelservice.FakeModelID, ProfileVersion: chainclient.NewProfileVersion(1), Status: "ACTIVE", MinStake: chainclient.NewUint64String(50),
			ProposerAddress: daemonTestOperator,
		},
	}, nil
}

func (*workerHandraiseWiringKeeper) ModelSupport(_ context.Context, operatorAddress, modelID string) (chainclient.ModelSupportSnapshot, error) {
	return chainclient.ModelSupportSnapshot{
		OperatorAddress: operatorAddress, ModelID: modelID,
		DeclaredSupport: true, SupportActive: true, SupportVersion: chainclient.NewUint64String(1),
		LastRefreshHeight: chainclient.NewUint64String(199), ActiveSupportStakeSnapshot: chainclient.NewUint64String(100),
	}, nil
}

type transitionKeeperClient struct {
	*recordingKeeperClient
	readinessMu sync.Mutex
	ready       bool
}

func newTransitionKeeperClient(ready bool) *transitionKeeperClient {
	return &transitionKeeperClient{recordingKeeperClient: &recordingKeeperClient{}, ready: ready}
}

func (k *transitionKeeperClient) SetReady(ready bool) {
	k.readinessMu.Lock()
	defer k.readinessMu.Unlock()
	k.ready = ready
}

func (k *transitionKeeperClient) isReady() bool {
	k.readinessMu.Lock()
	defer k.readinessMu.Unlock()
	return k.ready
}

// CommittedBuilderSet is the chain's membership authority. The set contains the
// Builder these tests configure, so a readiness failure is attributable to the
// fact under test rather than to an unreadable BuilderSet.
func (k *transitionKeeperClient) CommittedBuilderSet(context.Context) (chainclient.BuilderSetSnapshot, uint64, error) {
	var hash chainclient.HexHash
	for i := range hash {
		hash[i] = 0x5a
	}
	return chainclient.BuilderSetSnapshot{
		BuilderSetVersion: chainclient.Uint64String(7),
		BuilderSetID:      "builder-set-7",
		SetHash:           hash,
		Builders:          []string{"trueopen1builderoperator"},
		SnapshotHeight:    chainclient.Uint64String(20),
	}, 20, nil
}

func (k *transitionKeeperClient) Params(context.Context) (chainclient.ParamsSnapshot, error) {
	return chainclient.ParamsSnapshot{
		ServiceUnbondingPeriodBlocks: 100,
		DailySupportWindowBlocks:     30,
		MaxManifestURIBytes:          2048,
	}, nil
}

func (k *transitionKeeperClient) CurrentModelProfile(_ context.Context, modelID, _ string) (chainclient.CurrentModelProfileSnapshot, error) {
	if !k.isReady() {
		return chainclient.CurrentModelProfileSnapshot{}, chainclient.ErrNotFound
	}
	return chainclient.CurrentModelProfileSnapshot{
		Profile: chainclient.CurrentProfileSnapshot{ModelID: modelID, ProposerAddress: daemonTestOperator},
	}, nil
}

func (k *transitionKeeperClient) CortexNode(ctx context.Context, nodeID string) (chainclient.CortexNodeSnapshot, error) {
	if !k.isReady() {
		return chainclient.CortexNodeSnapshot{}, chainclient.ErrNotFound
	}
	return k.recordingKeeperClient.CortexNode(ctx, nodeID)
}

func (k *transitionKeeperClient) ModelCapability(ctx context.Context, nodeID, modelID string) (chainclient.ModelCapabilitySnapshot, error) {
	if !k.isReady() {
		return chainclient.ModelCapabilitySnapshot{}, chainclient.ErrNotFound
	}
	return k.recordingKeeperClient.ModelCapability(ctx, nodeID, modelID)
}

func (k *transitionKeeperClient) ModelSupport(ctx context.Context, nodeID, modelID string) (chainclient.ModelSupportSnapshot, error) {
	if !k.isReady() {
		return chainclient.ModelSupportSnapshot{}, chainclient.ErrNotFound
	}
	return k.recordingKeeperClient.ModelSupport(ctx, nodeID, modelID)
}

func (*transitionKeeperClient) Model(context.Context, string) (chainclient.ModelSnapshot, error) {
	return chainclient.ModelSnapshot{}, chainclient.ErrNotFound
}

func (*transitionKeeperClient) Profile(context.Context, string, string) (chainclient.ProfileSnapshot, error) {
	return chainclient.ProfileSnapshot{}, chainclient.ErrNotFound
}

type lifecycleNexusSubscriber struct {
	mu            sync.Mutex
	subscriptions int
	unsubscribed  int
	errors        chan error
}

func (s *lifecycleNexusSubscriber) Subscribe(context.Context, string, builderclient.MessageHandler) (builderclient.Subscription, error) {
	s.mu.Lock()
	s.subscriptions++
	s.mu.Unlock()
	return &lifecycleSubscription{onUnsubscribe: func() {
		s.mu.Lock()
		s.unsubscribed++
		s.mu.Unlock()
	}}, nil
}

func (s *lifecycleNexusSubscriber) SubscribeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subscriptions
}

func (s *lifecycleNexusSubscriber) UnsubscribeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsubscribed
}

func (s *lifecycleNexusSubscriber) Errors() <-chan error {
	return s.errors
}

type lifecycleSubscription struct {
	once          sync.Once
	onUnsubscribe func()
}

func (s *lifecycleSubscription) Unsubscribe() error {
	s.once.Do(s.onUnsubscribe)
	return nil
}

type countingProjector struct {
	mu    sync.Mutex
	count int
	after func(int)
}

func (p *countingProjector) RunOnce(context.Context) error {
	p.mu.Lock()
	p.count++
	count := p.count
	after := p.after
	p.mu.Unlock()
	if after != nil {
		after(count)
	}
	return nil
}

func (p *countingProjector) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

func (k *recordingKeeperClient) FinalizedEvents(_ context.Context, position chainclient.EventPosition) (chainclient.KeeperEventsPage, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.positions = append(k.positions, position)
	if len(k.pages) == 0 {
		return chainclient.KeeperEventsPage{ChainHeight: 20, FinalizedHeight: position.Height, LastPosition: position}, nil
	}
	page := k.pages[0]
	k.pages = k.pages[1:]
	if page.FinalizedHeight > position.Height && page.RangeStartHeight == 0 {
		page.RangeStartHeight = position.Height + 1
		page.RangeEndHeight = page.FinalizedHeight
		page.RangeComplete = true
		page.LastPosition = chainclient.BlockEndPosition(page.FinalizedHeight)
	}
	if k.tasks == nil {
		k.tasks = make(map[string]chainclient.TaskSnapshot)
	}
	for _, event := range page.Events {
		if event.Type != chainclient.KeeperEventAssignmentFinalized {
			continue
		}
		payloadHash := codec.HashWithDomain("DAEMON_KEEPER_PAYLOAD", []byte(event.TaskID))
		sessionID := event.SessionID
		if sessionID == "" {
			sessionID = "session-" + event.TaskID
		}
		orderSequence := event.OrderSequence
		if orderSequence == 0 {
			orderSequence = 1
		}
		orderDigest := event.OrderDigest
		if orderDigest == (codec.Hash{}) {
			orderDigest = codec.HashWithDomain("DAEMON_KEEPER_ORDER", []byte(event.TaskID))
		}
		modelID := event.ModelID
		if modelID == "" {
			modelID = "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c"
		}
		inferDeadline := event.Height + 100
		acceptedHash := codec.HashWithDomain("DAEMON_KEEPER_TASK", []byte(event.TaskID))
		k.tasks[event.TaskID] = chainclient.TaskSnapshot{
			Status:          "ASSIGNED",
			CurrentContract: true,
			Assignment: chainclient.AssignmentSnapshot{
				SessionID:                sessionID,
				TaskID:                   event.TaskID,
				OrderSequence:            chainclient.Uint64String(orderSequence),
				OrderDigest:              chainclient.HexHash{},
				SelectedWorker:           event.Worker,
				InferDeadlineHeight:      chainclient.Uint64String(inferDeadline),
				WinnerConfirmHeight:      chainclient.Uint64String(event.WinnerConfirmHeight),
				ModelID:                  modelID,
				ProfileVersion:           chainclient.NewProfileVersion(1),
				AcceptedOrderPayloadHash: chainclient.HexHash(payloadHash),
				TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{AcceptedTaskHash: chainclient.ProtoBytes32(acceptedHash[:])},
			},
		}
	}
	return page, nil
}

func (k *recordingKeeperClient) ChainHeight(context.Context) (uint64, error) {
	return 20, nil
}

func (k *recordingKeeperClient) Params(context.Context) (chainclient.ParamsSnapshot, error) {
	return chainclient.ParamsSnapshot{ServiceUnbondingPeriodBlocks: 100, DailySupportWindowBlocks: 30, MaxManifestURIBytes: 2048}, nil
}

func (k *recordingKeeperClient) ChainStatus(context.Context) (uint64, string, error) {
	return 200, "trueopen-devnet-1", nil
}

func (k *recordingKeeperClient) CortexNode(_ context.Context, nodeID string) (chainclient.CortexNodeSnapshot, error) {
	return chainclient.CortexNodeSnapshot{
		OperatorAddress:       nodeID,
		CurrentServiceAddress: recordingKeeperServiceAddress,
		CurrentServicePubkey:  recordingKeeperServicePubkey,
		AuthorizationNonce:    chainclient.Uint64String(1),
		Status:                "ACTIVE",
	}, nil
}

func (k *recordingKeeperClient) ServiceBond(_ context.Context, nodeID string) (chainclient.ServiceBondSnapshot, error) {
	return chainclient.ServiceBondSnapshot{
		OperatorAddress: nodeID,
		ActiveBond:      chainclient.Uint64String(500000),
		BondVersion:     chainclient.Uint64String(1),
		Status:          "ACTIVE",
	}, nil
}

func (k *recordingKeeperClient) CurrentServiceKey(_ context.Context, participantType, operatorAddress string, _ uint64) (chainclient.ServiceKeySnapshot, error) {
	return chainclient.ServiceKeySnapshot{
		ParticipantType:    participantType,
		OperatorAddress:    operatorAddress,
		ServiceAddress:     recordingKeeperServiceAddress,
		ServicePubkey:      recordingKeeperServicePubkey,
		AuthorizationNonce: chainclient.Uint64String(1),
		Status:             "ACTIVE",
	}, nil
}

// CommittedCurrentServiceKey answers with the binding and the height it was
// served at, which is what startup identity resolution reads.
func (k *recordingKeeperClient) CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	key, err := k.CurrentServiceKey(ctx, participantType, operatorAddress, 0)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, err
	}
	return key, 20, nil
}

func (k *recordingKeeperClient) ModelCapability(_ context.Context, nodeID, modelID string) (chainclient.ModelCapabilitySnapshot, error) {
	return chainclient.ModelCapabilitySnapshot{
		OperatorAddress: nodeID, ModelID: modelID,
		InferenceCapability: true, VerificationCapability: true, CapabilityVersion: chainclient.Uint64String(1),
	}, nil
}

func (k *recordingKeeperClient) ModelSupport(_ context.Context, nodeID, modelID string) (chainclient.ModelSupportSnapshot, error) {
	return chainclient.ModelSupportSnapshot{OperatorAddress: nodeID, ModelID: modelID, DeclaredSupport: true, SupportActive: true, SupportVersion: chainclient.Uint64String(1)}, nil
}

func (k *recordingKeeperClient) Task(_ context.Context, _ string, taskID string) (chainclient.TaskSnapshot, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.tasks[taskID], nil
}

func (k *recordingKeeperClient) Positions() []chainclient.EventPosition {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]chainclient.EventPosition(nil), k.positions...)
}

func (s *recordingNexusSubscriber) Subscribe(_ context.Context, subject string, handler builderclient.MessageHandler) (builderclient.Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlers == nil {
		s.handlers = make(map[string]builderclient.MessageHandler)
	}
	s.handlers[subject] = handler
	return fakeSubscription{}, nil
}

func (s *recordingNexusSubscriber) Deliver(ctx context.Context, subject string, msg builderclient.NATSMessage) error {
	s.mu.Lock()
	handler := s.handlers[subject]
	s.mu.Unlock()
	if handler == nil {
		return fmt.Errorf("missing handler for %s", subject)
	}
	return handler(ctx, msg)
}

type fakeSubscription struct{}

func (fakeSubscription) Unsubscribe() error { return nil }

func (p *recordingNexusPublisher) Publish(_ context.Context, req builderclient.PublishRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = append(p.published, builderclient.PublishRequest{
		Subject: req.Subject,
		TaskID:  req.TaskID,
		Payload: append([]byte(nil), req.Payload...),
	})
	return nil
}

func (p *recordingNexusPublisher) Published() []builderclient.PublishRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]builderclient.PublishRequest(nil), p.published...)
}

func waitForSubscription(t *testing.T, subscriber *recordingNexusSubscriber, subject string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		subscriber.mu.Lock()
		_, ok := subscriber.handlers[subject]
		subscriber.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("subscription %q did not start", subject)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForAdminSocket(t *testing.T, socketPath string, runErr <-chan error) error {
	t.Helper()
	client := adminapi.NewClient(socketPath)
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for {
		if _, err := client.Capability(context.Background()); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case err := <-runErr:
			return err
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("admin socket did not become ready: %v", lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func realConfigForRunnerTest(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	contents := strings.ReplaceAll(realDaemonConfigWithStore(filepath.Join(dir, "admin.sock"), filepath.Join(dir, "cortex.kv")), "__ADMIN_SOCKET__", filepath.Join(dir, "admin.sock"))
	path := filepath.Join(dir, "cortex.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("config.LoadFile returned error: %v", err)
	}
	cfg.Keeper.PollIntervalMS = 2
	cfg.Artifacts.Root = filepath.Join(dir, "evidence")
	return cfg
}

func runTestRuntimeRunners(ctx context.Context, runners []runtimeRunner) <-chan error {
	done := make(chan error, len(runners))
	for _, runner := range runners {
		runner := runner
		go func() { done <- runner(ctx) }()
	}
	return done
}

func waitForSubscriberStarts(t *testing.T, subscriber *lifecycleNexusSubscriber, minimum int) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		count := subscriber.SubscribeCount()
		if count >= minimum {
			return count
		}
		if time.Now().After(deadline) {
			t.Fatalf("workload subscriptions = %d, want at least %d", count, minimum)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitForKeeperPoll(t *testing.T, keeper *transitionKeeperClient) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(keeper.Positions()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Keeper event polling did not start")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitForWorkloadDeactivation(t *testing.T, rt *daemon.Runtime) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for rt.WorkloadActive() {
		if time.Now().After(deadline) {
			t.Fatal("workload boundaries remain active after readiness loss")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitForSubscriberStops(t *testing.T, subscriber *lifecycleNexusSubscriber, minimum int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		count := subscriber.UnsubscribeCount()
		if count >= minimum {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("workload unsubscriptions = %d, want at least %d", count, minimum)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func assertReadyzStatus(t *testing.T, health *observability.Health, want int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, want)
	}
}

func mustDaemonJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	return b
}

func fakeDaemonConfig(socketPath string) string {
	return fakeDaemonConfigWithStore(socketPath, "__KV_PATH__")
}

func fakeDaemonConfigWithStore(socketPath string, kvPath string) string {
	return `chain_id: local-cortex
admin:
  uds_path: ` + socketPath + `
model_management:
  endpoint: fake://model-management
node:
  rpc_endpoint: fake://node
evidence:
  root: /tmp/cortex-evidence
store:
  path: ` + kvPath + `
signer:
  uri: memory://operator
tx:
  fee_denom: utrueopen
health:
  bind: 127.0.0.1:0
`
}

func realDaemonConfig(socketPath string) string {
	return realDaemonConfigWithStore(socketPath, "__KV_PATH__")
}

// realDaemonConfigWithStore puts the local NATS user key file next to the store:
// when the runtime opens its own NATS connection it generates the key at that
// path, and the product default /etc/cortex is not writable in tests.
func realDaemonConfigWithStore(socketPath string, kvPath string) string {
	// Hanging it right beside the store path means the __KV_PATH__ placeholder is
	// substituted with the temp dir along with everything else.
	natsUserKeyFile := kvPath + ".nats-user.nk"
	return withNATSUserKeyFile(`mode: real
chain_id: trueopen-devnet-1
admin:
  uds_path: `+socketPath+`
model_management:
  endpoint: 127.0.0.1:9090
  transport: grpc
node:
  rpc_endpoint: http://127.0.0.1:26657
  rest_endpoint: http://127.0.0.1:1317
keeper:
  api_url: https://keeper.devnet.trueopen.xyz
task_execution:
  retry_delay_ms: 30000
  input_resolver: nexus
nexus:
  ingress_url: https://nexus.devnet.trueopen.xyz
  nats_url: tls://nexus.devnet.trueopen.xyz:4222
  nats_ca_file: /etc/cortex/nats-ca.pem
  nats_user_key_file: /etc/cortex/nats-user.nk
  jetstream_stream: TRUEOPEN_TASK
tx:
  enabled: true
  max_fee_amount: 1000
  fee_denom: utrueopen
  max_attempts: 3
  poll_attempts: 20
  gas_limit: 250000
evidence:
  root: /tmp/cortex-evidence
store:
  path: `+kvPath+`
signer:
  uri: http://127.0.0.1:9080
local_identity:
  operator_address: trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k
  service_key_ref: memory://service-key
  supported_model_profiles: [1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c@1=llm_text_v1]
  model_service_id: 1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c-service
self_rescue:
  enabled: false
  margin_blocks: 12
  max_fee_amount: 1000
  fee_denom: utrueopen
  allowed_tx_types: [MsgInferReceiptCommitOnlyTx, MsgCommitTx, MsgResultTx, MsgWorkerRevealTx, MsgSettleTx]
health:
  bind: 127.0.0.1:0
`, natsUserKeyFile)
}

// withNATSUserKeyFile moves the local NATS user key file into a temp dir: the
// runtime generates the key at that path when it opens its own NATS connection,
// and the default /etc/cortex is not writable in tests.
func withNATSUserKeyFile(cfg string, path string) string {
	return strings.Replace(cfg, "  nats_user_key_file: /etc/cortex/nats-user.nk", "  nats_user_key_file: "+path, 1)
}

func realDaemonConfigWithInvalidNATS(socketPath string, kvPath string) string {
	return strings.Replace(realDaemonConfigWithStore(socketPath, kvPath), "nats_url: tls://nexus.devnet.trueopen.xyz:4222", "nats_url: http://127.0.0.1:4222", 1)
}

func realDaemonConfigWithStoreAndSubscriptions(socketPath string, kvPath string) string {
	cfg := realDaemonConfigWithStore(socketPath, kvPath)
	return strings.Replace(cfg, "  nats_url: tls://nexus.devnet.trueopen.xyz:4222", "  nats_url: tls://nexus.devnet.trueopen.xyz:4222\n  subscribe_models: [1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c]\n  subscribe_tasks: [task-1]", 1)
}

func realDaemonConfigWithKeeperPolling(socketPath string, kvPath string) string {
	cfg := realDaemonConfigWithStore(socketPath, kvPath)
	cfg = strings.Replace(cfg, "  api_url: https://keeper.devnet.trueopen.xyz", "  api_url: https://keeper.devnet.trueopen.xyz\n  poll_interval_ms: 10\n  max_lag_blocks: 20", 1)
	return cfg
}

func mustDaemonManifest(t *testing.T) modelregistry.Manifest {
	t.Helper()
	manifest, err := modelregistry.GenerateManifest(modelregistry.ManifestInput{
		ModelID:        "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c",
		Version:        "2026-07-08",
		Digest:         "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Tokenizer:      "tiktoken-cl100k",
		ModelServiceID: "modelsvc-local",
		Verification: modelregistry.VerificationSpec{
			Method:         "trace_sample_v1",
			ProfileVersion: "1",
		},
		Pricing:       modelregistry.PricingSpec{Denom: "utrueopen", PromptUnitPrice: 1, CompletionUnitPrice: 2},
		TokenizerHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RuntimeVersion: "runtime-v1",
		RuntimeHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", QuantHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		HardwareTierFloor: 1, ResourceTier: "3",
		MinStake: 500000, ChallengeOpenWindowBlocks: 100, EpsilonParams: "epsilon-v1", TimeoutBootstrapProfile: "timeout-v1",
		SchemaHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MetadataHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	})
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	bytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var roundTrip modelregistry.Manifest
	if err := json.Unmarshal(bytes, &roundTrip); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	return roundTrip
}

func mustCurrentDaemonManifest(t *testing.T) modelregistry.CurrentManifest {
	t.Helper()
	hash := txclient.ProtoBytes32(strings.Repeat("ab", 32))
	manifest, err := modelregistry.GenerateCurrentManifest(modelregistry.CurrentManifestInput{
		Version: "2026-08-03", Tokenizer: "qwen-tokenizer", ModelServiceID: "modelsvc-local",
		Profile: txclient.ModelProfileProjectionMessage{Source: txclient.SourceRefMessage{Provider: "HUGGINGFACE", RepoID: "org/model", RepoType: "model", ResolverVersion: "HF_RESOLVER_V1", Revision: strings.Repeat("0a", 20), SourceURI: "hf://org/model@" + strings.Repeat("0a", 20)}, ModelID: txclient.ProtoBytes32(strings.Repeat("b2", 32)), ProfileVersion: 1, ManifestHash: hash, TokenizerHash: hash,
			RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1", RequiredTopK: 20, TaskTypes: []string{"TASK_TYPE_CHAT"}, GenerationType: "GENERATION_TYPE_SAMPLED",
			ResourceTier: 2, MinStake: txclient.CoinMessage{Denom: "utrueopen", Amount: 1_000_000}, ChallengeOpenWindowBlocks: 1_800,
			VerificationProfile: txclient.VerificationProfileMessage{VerificationProfileID: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", VerificationMode: "VERIFICATION_MODE_SINGLE_SAMPLE", TokenScope: "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				Metrics: txclient.MetricSpecMessage{CompareLogprobDiff: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6"}, CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: hash, MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1", EvidenceSchema: txclient.WorkerEvidenceSchemaV3(1<<30, 64<<20)},
			PricingProfile:          txclient.PricingProfileMessage{InitialOutputPrice: 10, VerifyRatioBPS: 1_000, MinOrderValue: 1_000},
			TimeoutBootstrapProfile: txclient.TimeoutBootstrapProfileMessage{InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50, CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000},
			SchemaHash:              hash, RegistrationFee: txclient.CoinMessage{Denom: "utrueopen", Amount: 10_000_000}, ManifestURI: "https://models.trueopen.example/manifests/org-model/v1.json"},
	})
	if err != nil {
		t.Fatalf("GenerateCurrentManifest: %v", err)
	}
	return manifest
}

// boundDurableSubscriber blocks inside Subscribe so a test can observe the
// window while the workload is starting, then fails the way builderclient does
// when a JetStream durable is still bound to a previous instance.
type boundDurableSubscriber struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *boundDurableSubscriber) Subscribe(context.Context, string, builderclient.MessageHandler) (builderclient.Subscription, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return nil, builderclient.Retryable(errors.New(`nats subscribe "trueopen.worker-assignment.*": consumer is already bound to a subscription`))
}

// The workload is only serving once its subscriptions exist. Signalling startup
// as soon as the runner goroutines are spawned reports a node as ready while
// inboxRunner.Start is still running -- and if that subscribe fails, /readyz
// answered 200 for a workload that never subscribed at all. Combined with the
// retry path, every attempt would flash ready.
func TestWorkloadReadinessWaitsForSubscriptionsToSucceed(t *testing.T) {
	cfg := realConfigForRunnerTest(t)
	keeper := newTransitionKeeperClient(true)
	subscriber := &boundDurableSubscriber{entered: make(chan struct{}), release: make(chan struct{})}
	rt, err := daemon.BuildRuntimeWithOptions(context.Background(), cfg, daemon.RuntimeOptions{
		SigningClient:               stubSigner{},
		TrustInjectedSignerForTests: true,
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              &recordingNexusPublisher{},
		NexusSubscriber:             subscriber,
		NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		KeeperEvents:                keeper,
		ChainStatus:                 keeper,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions returned error: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	health := newRuntimeHealth(cfg)
	if err := health.Apply(rt.Dependencies.Diagnostics.Dependencies); err != nil {
		t.Fatalf("health.Apply returned error: %v", err)
	}
	captured := captureCortexdLogs(t)
	runners, cleanup, err := runtimeRunnersWithHealth(cfg, rt, nil, health)
	if err != nil {
		t.Fatalf("runtimeRunnersWithHealth returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runTestRuntimeRunners(ctx, runners)
	released := false
	defer func() {
		cancel()
		if !released {
			close(subscriber.release)
		}
		cleanup()
		for range runners {
			<-done
		}
	}()

	select {
	case <-subscriber.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("workload never attempted to subscribe")
	}
	// Subscribe is still in flight: no subscription exists yet, so the node is
	// not serving and must not be reported as running.
	if health.DependencyReady(observability.DependencyWorkload) {
		t.Fatal("workload was reported as running before its subscriptions were established")
	}
	close(subscriber.release)
	released = true
	workloadFailureLog := waitForCortexdLogRecord(t, captured, "workload start failed")
	assertCortexdLogRecord(t, workloadFailureLog, slog.LevelError, "workload start failed")
	if !strings.Contains(workloadFailureLog, "source=internal/daemon/readiness_controller.go:") {
		t.Fatalf("workload retry source = %q, want the domain caller", workloadFailureLog)
	}
}

// The barrier must release on success, or the workload would never be reported
// as running at all.
func TestWorkloadReadinessReportedOnceSubscriptionsSucceed(t *testing.T) {
	cfg := realConfigForRunnerTest(t)
	keeper := newTransitionKeeperClient(true)
	rt, err := daemon.BuildRuntimeWithOptions(context.Background(), cfg, daemon.RuntimeOptions{
		SigningClient:               stubSigner{},
		TrustInjectedSignerForTests: true,
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              &recordingNexusPublisher{},
		NexusSubscriber:             &lifecycleNexusSubscriber{},
		NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		KeeperEvents:                keeper,
		ChainStatus:                 keeper,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions returned error: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	health := newRuntimeHealth(cfg)
	if err := health.Apply(rt.Dependencies.Diagnostics.Dependencies); err != nil {
		t.Fatalf("health.Apply returned error: %v", err)
	}
	runners, cleanup, err := runtimeRunnersWithHealth(cfg, rt, nil, health)
	if err != nil {
		t.Fatalf("runtimeRunnersWithHealth returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runTestRuntimeRunners(ctx, runners)
	defer func() {
		cancel()
		cleanup()
		for range runners {
			<-done
		}
	}()

	deadline := time.After(5 * time.Second)
	for !health.DependencyReady(observability.DependencyWorkload) {
		select {
		case <-deadline:
			t.Fatal("workload was never reported as running despite successful subscriptions")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// The startup barrier and the runner-error collector must not race as two
// independent consumers. If a runner other than the barrier participant has
// already failed and its error is queued, the group is failing, and the
// workload must never be reported as running even though the subscription
// itself succeeded.
//
// Note on scope: an exit only becomes observable to the group when the runner
// goroutine records it, so a subscription completing in the same instant a
// sibling returns is a genuine tie that no ordering can resolve -- and
// reporting ready there is correct, because nothing had failed yet. What must
// hold is that an exit the group could already have seen is never overtaken.
func TestWorkloadNotReportedWhenAnotherRunnerHasFailed(t *testing.T) {
	const iterations = 500
	var violations atomic.Int64
	for i := 0; i < iterations; i++ {
		barrier := newStartupBarrier()
		subscribed := barrier.expect()
		failed := make(chan struct{})

		runners := []runtimeRunner{
			// Stands in for builderRunner/taskRunner failing during startup.
			func(context.Context) error {
				defer close(failed)
				return errors.New("builder runner failed during startup")
			},
			// Stands in for the inbox runner subscribing successfully, after
			// the sibling failure has had time to reach the group.
			func(ctx context.Context) error {
				<-failed
				time.Sleep(100 * time.Microsecond)
				subscribed()
				<-ctx.Done()
				return nil
			},
		}
		barrier.seal()
		_ = runRuntimeRunnerGroupWithStarted(context.Background(), runners, func() {}, func() {
			violations.Add(1)
		}, barrier)
	}
	if got := violations.Load(); got != 0 {
		t.Fatalf("workload reported as running after a sibling runner had failed: %d / %d", got, iterations)
	}
}

// Health must track the live Builder descriptor verdict. Without it, a
// descriptor that is superseded, gets revoked, or stops publishing the
// configured ingress would stop the workload while /readyz kept reporting ready.
func TestReadinessObserverPublishesBuilderDescriptorFailureToHealth(t *testing.T) {
	var hash chainclient.HexHash
	for i := range hash {
		hash[i] = 0xef
	}
	descriptor, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, "trueopen1builderoperator", 4, hash, 120, 1,
		[]chainclient.ServiceEndpointSnapshot{{
			Kind:            chainclient.EndpointKindNexusGRPC,
			URI:             "https://committed.example.org",
			ProtocolVersion: "v1",
		}},
	)
	if err != nil {
		t.Fatalf("NewServiceDescriptorSnapshot returned error: %v", err)
	}
	directoryKeeper := descriptorDirectoryKeeper{descriptor: descriptor}
	resolver, err := builderdirectory.New(directoryKeeper, builderdirectory.Options{})
	if err != nil {
		t.Fatalf("builderdirectory.New returned error: %v", err)
	}

	cfg := realConfigForRunnerTest(t)
	// The configured ingress is not the endpoint the descriptor publishes.
	cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
	// The resolver is injected, so this runtime needs no descriptor-capable
	// Keeper; the input resolver does need one that can read service keys, and
	// every real-mode node now requires one because every node can be drawn as
	// the Worker.
	keeper := newTransitionKeeperClient(true)
	rt, err := daemon.BuildRuntimeWithOptions(context.Background(), cfg, daemon.RuntimeOptions{
		SigningClient:               stubSigner{},
		TrustInjectedSignerForTests: true,
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              &recordingNexusPublisher{},
		NexusSubscriber:             &lifecycleNexusSubscriber{},
		NexusEnvelopeAuthenticator:  mainTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         mainTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		KeeperEvents:                keeper,
		ChainStatus:                 keeper,
		BuilderDirectory:            resolver,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions returned error: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	health := newRuntimeHealth(cfg)
	// Every dependency starts ready, so only the readiness observer can flip the
	// Builder descriptor slot.
	for _, name := range []string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support",
		"nexus", "nexus_envelope_auth", "builder_descriptor", "tx_broadcaster",
		observability.DependencyChainSync, observability.DependencyWorkload} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s) returned error: %v", name, err)
		}
	}
	runners, cleanup, err := runtimeRunnersWithHealth(cfg, rt, nil, health)
	if err != nil {
		t.Fatalf("runtimeRunnersWithHealth returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runTestRuntimeRunners(ctx, runners)
	t.Cleanup(func() {
		cancel()
		cleanup()
		for range runners {
			if err := <-done; err != nil {
				t.Fatalf("runtime runner returned error: %v", err)
			}
		}
	})

	// Without the observer publishing it, health would keep reporting the stale
	// ready value while the descriptor check already stopped the workload.
	deadline := time.Now().Add(3 * time.Second)
	for health.DependencyReady("builder_descriptor") {
		if time.Now().After(deadline) {
			t.Fatal("health never learned that the Builder descriptor check failed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if status, ok := rt.DiagnosticsSnapshot().Dependency("builder_descriptor"); !ok || status.Ready ||
		!strings.Contains(status.Error, "is not the NEXUS_GRPC endpoint") {
		t.Fatalf("diagnostics builder_descriptor = %#v ok=%v, want the live conflict", status, ok)
	}
}

type descriptorDirectoryKeeper struct {
	descriptor chainclient.ServiceDescriptorSnapshot
}

func (k descriptorDirectoryKeeper) CommittedBuilder(context.Context, string) (chainclient.BuilderStateSnapshot, uint64, error) {
	return chainclient.BuilderStateSnapshot{
		Address:                  "trueopen1builderoperator",
		CurrentServiceKeyStatus:  "ACTIVE",
		RegisteredHeight:         chainclient.Uint64String(1),
		CurrentDescriptorVersion: chainclient.Uint64String(4),
	}, 900, nil
}

func (k descriptorDirectoryKeeper) ServiceDescriptor(context.Context, string, string, uint64) (chainclient.ServiceDescriptorSnapshot, error) {
	return k.descriptor, nil
}

func (k descriptorDirectoryKeeper) CurrentServiceKey(context.Context, string, string, uint64) (chainclient.ServiceKeySnapshot, error) {
	return chainclient.ServiceKeySnapshot{
		ParticipantType:          chainclient.ParticipantTypeBuilder,
		OperatorAddress:          "trueopen1builderoperator",
		CurrentDescriptorVersion: chainclient.Uint64String(4),
		ServiceAddress:           "trueopen1builderservice",
		ServicePubkey:            "02" + strings.Repeat("ef", 32),
		AuthorizationNonce:       chainclient.Uint64String(1),
		Status:                   "ACTIVE",
	}, nil
}

// mainTestSignedOrder builds the typed SignedOrderV2 the V2 broadcast carries
// and derives its frozen task_hash through nodewire, the digest authority.
func mainTestSignedOrder(t *testing.T, chainID, modelID, sessionID string, sequence, deadline uint64) (*bustaskv1.SignedOrderV2, codec.Hash) {
	t.Helper()
	session, err := hex.DecodeString(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	hash := bytes.Repeat([]byte{0x5a}, 32)
	amount := func(value string) *bussharedv1.Amount { return &bussharedv1.Amount{AtomicUnits: value} }
	signed := &bustaskv1.SignedOrderV2{
		Order: &bustaskv1.TaskOrderV3{
			SchemaVersion: 3, ChainId: chainID, UserAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
			SessionId: session, OrderSequence: sequence,
			ModelId: func() []byte { raw, _ := hex.DecodeString(modelID); return raw }(), ProfileVersion: 1, TaskType: bussharedv1.TaskType_TASK_TYPE_CHAT,
			InputHash: bytes.Repeat([]byte{0xaa}, 32), InputSizeBytes: 32,
			InputBucket: 1, OutputBudgetBucket: 1,
			GenerationParams: &bustaskv1.GenerationParamsV1{
				GenerationParamsSchemaVersion: 1, MaxOutputTokens: 128, MaxOutputDuration: 2000,
				DecodingParams: &bustaskv1.DecodingParamsV1{
					TopPPpm: 1_000_000, Seed: 1, RepetitionPenaltyPpm: 1_000_000,
					StopSequences: []string{}, StopTokenIds: []uint32{},
				},
			},
			PriceBid: amount("1"), MaxFee: amount("3000"),
			AssignmentPriorityFee: amount("0"), TxFeeReserve: amount("1000"),
			EarliestSubmitHeight: 100, OrderExpireHeight: deadline,
			DeadlinePolicy:       &bustaskv1.DeadlinePolicyV1{LatencyClass: bustaskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_STANDARD},
			TimeoutBucketVersion: 1, SessionAnchorHeight: 100,
			SessionAnchorBlockHash: hash, BuilderSetId: "7", BuilderSetHash: hash,
			PayloadMode:        bustaskv1.PayloadModeV1_PAYLOAD_MODE_V1_PLAINTEXT,
			InputKeyCommitment: make([]byte, 32),
		},
		SignatureScheme: "eip712",
		UserSignature:   append(bytes.Repeat([]byte{0x01}, 64), 27),
	}
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	taskHash, _, err := nodewire.TaskOrderHashAndFactsEnvelope(hex.EncodeToString(raw))
	if err != nil {
		t.Fatalf("derive task hash from typed signed order: %v", err)
	}
	return signed, taskHash
}

func seedInferTask(ctx context.Context, s *store.Store, h codec.Hash, task store.InferTask) error {
	orderDigest := task.OrderDigest
	if orderDigest == (codec.Hash{}) {
		orderDigest = task.AssignmentDigest
	}
	inputDigest := task.InputDigest
	if inputDigest == (codec.Hash{}) {
		inputDigest = codec.HashBytes([]byte(task.TaskID + ":input"))
	}
	tr := layout.TaskRecord{
		SessionID:              task.SessionID,
		OrderSequence:          task.OrderSequence,
		ModelID:                task.ModelID,
		ProfileVersion:         task.ProfileVersion,
		AssignmentOrderDigest:  layout.StoredHash(task.OrderDigest),
		AssignmentDigest:       layout.StoredHash(task.AssignmentDigest),
		AcceptedInputHash:      layout.StoredHash(task.InputDigest),
		WorkerAddress:          task.WorkerAddress,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		TaskBuilderSetID:       task.BuilderSetID,
		TaskBuilderSetHash:     task.BuilderSetHash,
		InputSizeBytes:         task.InputSizeBytes,
		InputCID:               task.InputCID,
		InputDigest:            layout.StoredHash(task.InputDigest),
	}
	stage := layout.RoleStage(task.Stage)
	if stage == "" {
		stage = layout.StageQueued
	}
	rec := layout.InferRecord{
		TaskID:              task.TaskID,
		WinnerConfirmHeight: task.WinnerConfirmHeight,
		InferDeadlineHeight: task.DeadlineHeight,
		Stage:               stage,
		RetryCount:          task.RetryCount,
		RetryAtUnixMilli:    task.RetryAtUnixMilli,
		RetryAtHeight:       task.RetryAtHeight,
		DeadlineHeight:      task.DeadlineHeight,
		LastError:           task.LastError,
		OutputCID:           task.OutputCID,
		OutputDigest:        layout.StoredHash(task.OutputDigest),
		ReceiptCID:          task.ReceiptCID,
		ReceiptDigest:       layout.StoredHash(task.ReceiptDigest),
	}
	if err := layout.MergeTask(ctx, s, layout.StoredHash(h), tr); err != nil {
		return err
	}
	return layout.MergeInfer(ctx, s, layout.StoredHash(h), rec)
}

// syncBuffer collects log output written from the readiness controller
// goroutine while the test reads it.
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestNexusPublishLogIncludesSafeCorrelationFields(t *testing.T) {
	line := formatNexusPublishCompletion(builderclient.PublishCompletion{
		Subject: "trueopen.handraise.worker.task-1", Kind: builderclient.KindWorkerHandraise,
		TaskID: "task-1", MessageID: "message-1", DedupID: "dedup-1", JetStream: false,
		SizeBytes: 512, Result: builderclient.PublishResultPublished, Duration: 1500 * time.Millisecond,
	})
	for _, want := range []string{
		"nexus publish completed", `subject="trueopen.handraise.worker.task-1"`, `kind="WORKER_HANDRAISE"`,
		`task="task-1"`, `message_id="message-1"`, `dedup_id="dedup-1"`, "jetstream=false", "bytes=512",
		`result="published"`, "duration_ms=1500",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("publish log %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "error=") {
		t.Fatalf("publish log %q reports an error on a delivered message", line)
	}
}

func TestNexusPublishLogReportsTheRefusalOfAFailedSend(t *testing.T) {
	line := formatNexusPublishCompletion(builderclient.PublishCompletion{
		Subject: "trueopen.handraise.worker.task-1", Kind: builderclient.KindWorkerHandraise,
		TaskID: "task-1", Result: builderclient.PublishResultFailed,
		Err: errors.New("nats: no responders\navailable"),
	})
	if !strings.Contains(line, `result="failed"`) {
		t.Fatalf("publish log %q does not report the failure", line)
	}
	if !strings.Contains(line, `error="nats: no responders`) {
		t.Fatalf("publish log %q drops the reason the send failed", line)
	}
	if strings.ContainsAny(line, "\n\t\x1b") {
		t.Fatalf("publish log contains raw control characters: %q", line)
	}
}

// TestCortexdReportsEveryOutboundBusPublish pins the wiring, not the format: the
// daemon must hand the runtime an observer, or the log line above is never
// reached in production.
func TestCortexdReportsEveryOutboundBusPublish(t *testing.T) {
	options := daemonRuntimeOptions()
	if options.NexusPublishObserver == nil {
		t.Fatal("cortexd builds the runtime without a publish observer; every send stays silent")
	}
	logged := captureCortexdLogs(t)
	tests := []struct {
		name       string
		completion builderclient.PublishCompletion
		level      slog.Level
	}{
		{
			name: "success",
			completion: builderclient.PublishCompletion{
				Subject: "trueopen.handraise.worker.task-1", Kind: builderclient.KindWorkerHandraise,
				TaskID: "task-1", Result: builderclient.PublishResultPublished,
			},
			level: slog.LevelInfo,
		},
		{
			name: "failure",
			completion: builderclient.PublishCompletion{
				Subject: "trueopen.handraise.worker.task-2", Kind: builderclient.KindWorkerHandraise,
				TaskID: "task-2", Result: builderclient.PublishResultFailed, Err: errors.New("nats unavailable"),
			},
			level: slog.LevelError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := logged.String()
			publisher := builderclient.NewObservedPublisher(nexusPublisherFunc(func(context.Context, builderclient.PublishRequest) error {
				return test.completion.Err
			}), options.NexusPublishObserver)
			_ = publisher.Publish(context.Background(), builderclient.PublishRequest{
				Subject: test.completion.Subject,
				TaskID:  test.completion.TaskID,
			})
			line := strings.TrimPrefix(logged.String(), before)
			assertCortexdLogRecord(t, line, test.level, "nexus publish completed")
			if !strings.Contains(line, "source=internal/builderclient/publish_observer.go:") {
				t.Fatalf("publish callback source = %q, want the domain caller", line)
			}
		})
	}
}

type nexusPublisherFunc func(context.Context, builderclient.PublishRequest) error

func (f nexusPublisherFunc) Publish(ctx context.Context, req builderclient.PublishRequest) error {
	return f(ctx, req)
}

func TestCortexdLogCallbackLevels(t *testing.T) {
	retryAt := time.Date(2026, time.September, 7, 20, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		level   slog.Level
		message string
		emit    func()
	}{
		{
			name: "successful inbox completion", level: slog.LevelInfo, message: "nexus inbox completed",
			emit: func() {
				logNexusInboxCompletion(outbox.InboxMessageCompletion{Subject: "trueopen.worker-assignment.task-1", Result: outbox.InboxMessageResultProcessed})
			},
		},
		{name: "refused inbox", level: slog.LevelError, message: "nexus inbox refused", emit: func() {
			logNexusInboxRefusal(errors.New("Nexus inbox refused trueopen.worker-assignment.task-1: invalid frame"))
		}},
		{name: "subscriber error", level: slog.LevelError, message: "nexus subscriber delivery error", emit: func() { logNexusSubscriberError(errors.New("consumer closed")) }},
		{
			name: "task runner waiting", level: slog.LevelInfo, message: "task runner waiting",
			emit: func() {
				logTaskRunnerDiagnostic(daemon.TaskRunnerDiagnostic{Source: "nexus_open_verify", Record: "task-1", Error: "window not ready", Waiting: true})
			},
		},
		{
			name: "task runner retry", level: slog.LevelError, message: "task runner retry",
			emit: func() {
				logTaskRunnerDiagnostic(daemon.TaskRunnerDiagnostic{Source: "infer", Record: "task-1", Error: "model unavailable", Count: 2, RetryAt: retryAt})
			},
		},
		{
			name: "task runner failure", level: slog.LevelError, message: "task runner failure",
			emit: func() {
				logTaskRunnerDiagnostic(daemon.TaskRunnerDiagnostic{Source: "nexus_order_broadcast", Record: "task-1", Error: "invalid frame"})
			},
		},
		{
			name: "quarantined effect", level: slog.LevelError, message: "quarantined Keeper effect",
			emit: func() {
				logQuarantinedKeeperEffect(daemon.ReconcilerEffect{Type: "assignment_finalized", TaskID: "task-1"}, errors.New("durable record conflict"))
			},
		},
		{name: "Keeper poll failure", level: slog.LevelError, message: "keeper poll failed", emit: func() { logKeeperPollFailure(2, time.Second, errors.New("rpc unavailable")) }},
		{name: "workload start retry", level: slog.LevelError, message: "workload start failed", emit: func() { logWorkloadStartFailure(errors.New("dependency changed")) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logged := captureCortexdLogs(t)
			test.emit()
			assertCortexdLogRecord(t, logged.String(), test.level, test.message)
		})
	}
}

func TestTaskRunnerDiagnosticLogKeepsFileAndLogicalSourcesDistinct(t *testing.T) {
	logged := captureCortexdLogs(t)
	logTaskRunnerDiagnostic(daemon.TaskRunnerDiagnostic{
		Source: "nexus_open_verify", Record: "task-1", Error: "window not ready", Waiting: true,
	})

	line := logged.String()
	if !strings.Contains(line, "source=cmd/cortexd/main_test.go:") {
		t.Fatalf("task runner diagnostic source = %q, want the domain caller file", line)
	}
	if got := strings.Count(line, " source="); got != 1 {
		t.Fatalf("task runner diagnostic has %d built-in source keys, want exactly one: %q", got, line)
	}
	if !strings.Contains(line, "diagnostic_source=nexus_open_verify") {
		t.Fatalf("task runner diagnostic = %q, want its logical source under diagnostic_source", line)
	}
}

func TestCortexdReadinessLogPreservesLevelsAndDomainSource(t *testing.T) {
	logged := captureCortexdLogs(t)
	readinessLog := newReadinessLog()
	readinessLog.Observe(false, []diagnostics.DependencyStatus{{Name: "keeper", Error: "rpc unavailable"}})

	line := logged.String()
	assertCortexdLogRecord(t, line, slog.LevelError, "dependency not ready")
	if !strings.Contains(line, "source=internal/observability/readiness_log.go:") {
		t.Fatalf("readiness source = %q, want the domain caller", line)
	}
}

func TestHealthHTTPServerErrorLogUsesErrorLevelAndSource(t *testing.T) {
	logged := captureCortexdLogs(t)
	server := newHealthHTTPServer("127.0.0.1:0", http.NewServeMux())
	if server.ErrorLog == nil {
		t.Fatal("health HTTP server ErrorLog is nil")
	}

	server.ErrorLog.Print("health HTTP server failure")
	line := logged.String()
	assertCortexdLogRecord(t, line, slog.LevelError, "health HTTP server failure")
	if !strings.Contains(line, "source=cmd/cortexd/main_test.go:") {
		t.Fatalf("health HTTP error source = %q, want the source-aware caller", line)
	}
}

func TestCortexdTaskTraceLogPreservesTheDomainSource(t *testing.T) {
	options := daemonRuntimeOptions()
	logged := captureCortexdLogs(t)
	options.TaskTraceObserver(observability.LogRecord{
		Level:   slog.LevelInfo,
		Message: `task trace event=order_broadcast task="task-1"`,
		PC:      reflect.ValueOf(daemon.NewTaskRunner).Pointer(),
	})

	line := logged.String()
	assertCortexdLogRecord(t, line, slog.LevelInfo, "task trace event=order_broadcast")
	if !strings.Contains(line, "source=internal/daemon/task_runner.go:") {
		t.Fatalf("task trace source = %q, want the daemon caller", line)
	}
	if strings.Contains(line, "source=cmd/cortexd/main.go:") {
		t.Fatalf("task trace attributed to the sink closure: %q", line)
	}
}

func captureCortexdLogs(t *testing.T) *syncBuffer {
	t.Helper()
	logged := &syncBuffer{}
	logtest.Install(t, observability.NewTextLogger(logged), log.Default())
	return logged
}

func waitForCortexdLogRecord(t *testing.T, logged *syncBuffer, message string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, line := range strings.Split(logged.String(), "\n") {
			if strings.Contains(line, "msg=") && strings.Contains(line, message) {
				return line
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("log never reported %q:\n%s", message, logged.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func assertCortexdLogRecord(t *testing.T, line string, level slog.Level, message string) {
	t.Helper()
	for _, want := range []string{"level=" + level.String(), "source="} {
		if !strings.Contains(line, want) {
			t.Fatalf("log record %q missing %q", line, want)
		}
	}
	if !strings.Contains(line, "msg="+message) && !strings.Contains(line, `msg="`+message) {
		t.Fatalf("log record %q missing message prefix %q", line, message)
	}
}

func TestDailySupportModelsListEveryConfiguredModelOnce(t *testing.T) {
	var cfg config.Config
	cfg.LocalIdentity.SupportedModelProfiles = []string{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b@1=llm_text_v1", "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a@2=llm_text_v1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b@3=llm_text_v1"}
	got := dailySupportModels(cfg)
	want := []string{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dailySupportModels = %#v, want %#v", got, want)
	}

	cfg.LocalIdentity.SupportedModelProfiles = []string{"model-a"}
	if got := dailySupportModels(cfg); len(got) != 0 {
		t.Fatalf("dailySupportModels for an unparseable entry = %#v, want none", got)
	}
}
