package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/outbox"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/worker"
)

var runtimeBuilder = buildDaemonRuntime

func buildDaemonRuntime(ctx context.Context, cfg config.Config) (*daemon.Runtime, error) {
	return daemon.BuildRuntimeWithOptions(ctx, cfg, daemonRuntimeOptions())
}

// daemonRuntimeOptions carries what cortexd, and only cortexd, adds to a runtime
// built from configuration: the logging seams. Tests build runtimes without
// them, which is why the observer is an option rather than a default inside the
// daemon package.
func daemonRuntimeOptions() daemon.RuntimeOptions {
	return daemon.RuntimeOptions{
		NexusPublishObserver: logNexusPublishCompletion,
		TaskTraceObserver: func(record observability.LogRecord) {
			observability.Emit(record)
		},
	}
}

func logNexusPublishCompletion(completion builderclient.PublishCompletion) {
	level := slog.LevelInfo
	if completion.Err != nil {
		level = slog.LevelError
	}
	observability.LogAtDepth(level, 1, formatNexusPublishCompletion(completion))
}

// signerForRuntime resolves the signer built during runtime construction. It
// is a variable so tests can inject a stub without standing up a signing
// service or a key file.
var signerForRuntime = func(rt *daemon.Runtime) signer.Signer { return rt.SigningClient() }

type projectionRunner interface {
	RunOnce(context.Context) error
}

func main() {
	observability.SetDefaultLogger(os.Stderr)
	if err := run(context.Background(), os.Args[1:]); err != nil {
		slog.Error("cortexd failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cmd := newRootCommand(ctx, os.Stdout)
	cmd.SetArgs(normalizeLegacyDaemonArgs(args))
	return cmd.Execute()
}

func normalizeLegacyDaemonArgs(args []string) []string {
	normalized := append([]string(nil), args...)
	for i, arg := range normalized {
		if arg == "-config" {
			normalized[i] = "--config"
		} else if strings.HasPrefix(arg, "-config=") {
			normalized[i] = "--" + strings.TrimPrefix(arg, "-")
		}
	}
	return normalized
}

type daemonFlags struct {
	configPath                   string
	mode                         string
	chainID                      string
	adminSocket                  string
	modelEndpoint                string
	modelTransport               string
	modelMaxConcurrency          string
	modelManifestDir             string
	nodeRPC                      string
	nodeREST                     string
	keeperAPI                    string
	keeperPollInterval           string
	keeperMaxLagBlocks           string
	taskRetryDelay               string
	taskMaxRetryAttempts         string
	taskInputResolver            string
	taskFixtureRoot              string
	taskMaxOutputBytes           string
	nexusIngress                 string
	nexusNATS                    string
	nexusAuthTokenFile           string
	nexusJetStreamStream         string
	nexusEnvelopeAuthMode        string
	nexusEnvelopeTTLMS           string
	nexusEnvelopeClockSkewMS     string
	nexusSubscribeModels         string
	nexusSubscribeTasks          string
	evidenceRoot                 string
	artifactsRoot                string
	storePath                    string
	signerURI                    string
	signerReadinessProofInterval string
	signerPasswordEnv            string
	signerPasswordFile           string
	signerPasswordStdin          bool
	operatorAddress              string
	serviceKeyRef                string
	modelProfiles                string
	modelServiceID               string
	nexusBuilderOperator         string
	nexusAllowInsecureDescriptor bool
	nexusDowngradeDescriptorTLS  bool
	nexusNATSCAFile              string
	nexusNATSCredsFile           string
	nexusNATSUserKeyFile         string
	modelServiceTLSCAFile        string
	modelServiceTLSPubkeyHash    string
	healthBind                   string
}

func newRootCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var values daemonFlags
	cmd := &cobra.Command{
		Use:           "cortexd",
		Short:         "Run the Cortex control-plane daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			overrides := make(map[string]string)
			for flagName, key := range map[string]string{
				"mode": "mode", "chain-id": "chain_id", "admin-socket": "admin_socket",
				"model-endpoint": "model_endpoint", "model-transport": "model_transport",
				"model-max-concurrency": "model_max_concurrency",
				"model-manifest-dir":    "model_manifest_dir",
				"node-rpc":              "node_rpc", "node-rest": "node_rest", "keeper-api": "keeper_api",
				"keeper-poll-interval-ms": "keeper_poll_interval_ms", "keeper-max-lag-blocks": "keeper_max_lag_blocks",
				"task-retry-delay-ms":     "task_retry_delay_ms",
				"task-max-retry-attempts": "task_max_retry_attempts",
				"task-input-resolver":     "task_input_resolver",
				"task-fixture-root":       "task_fixture_root",
				"task-max-output-bytes":   "task_max_output_bytes",
				"nexus-ingress":           "nexus_ingress", "nexus-nats": "nexus_nats",
				"nexus-auth-token-file": "nexus_auth_token_file", "nexus-envelope-auth-mode": "nexus_envelope_auth_mode",
				"nexus-jetstream-stream": "nexus_jetstream_stream",
				"nexus-envelope-ttl-ms":  "nexus_envelope_ttl_ms", "nexus-envelope-clock-skew-ms": "nexus_envelope_clock_skew_ms",
				"evidence-root":          "evidence_root",
				"artifacts-root":         "artifacts_root",
				"nexus-subscribe-models": "nexus_subscribe_models", "nexus-subscribe-tasks": "nexus_subscribe_tasks",
				"store-path": "store_path", "signer-uri": "signer_uri",
				"signer-readiness-proof-interval-ms": "signer_readiness_proof_interval_ms",
				"signer-password-env":                "signer_password_env", "signer-password-file": "signer_password_file",
				"signer-password-stdin": "signer_password_stdin",
				"operator-address":      "operator_address", "service-key-ref": "service_key_ref",
				"model-profiles":                  "model_profiles",
				"model-service-id":                "model_service_id",
				"nexus-builder-operator-address":  "nexus_builder_operator_address",
				"nexus-allow-insecure-descriptor": "nexus_allow_insecure_descriptor",
				"nexus-downgrade-descriptor-tls":  "nexus_downgrade_descriptor_tls",
				"nexus-nats-ca-file":              "nexus_nats_ca_file",
				"nexus-nats-creds-file":           "nexus_nats_creds_file",
				"nexus-nats-user-key-file":        "nexus_nats_user_key_file",
				"model-service-tls-ca-file":       "model_service_tls_ca_file",
				"model-service-tls-pubkey-hash":   "model_service_tls_pubkey_hash",
				"health-bind":                     "health_bind",
			} {
				if cmd.Flags().Changed(flagName) {
					overrides[key] = cmd.Flags().Lookup(flagName).Value.String()
				}
			}
			cfg, err := config.LoadFileWithOverrides(values.configPath, overrides)
			if err != nil {
				return err
			}
			return runDaemon(cmd.Context(), cfg)
		},
	}
	cmd.SetContext(ctx)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	flags := cmd.Flags()
	flags.StringVar(&values.configPath, "config", "configs/dev.yaml", "path to YAML config file")
	flags.StringVar(&values.mode, "mode", "", "runtime mode (overrides CORTEX_MODE)")
	flags.StringVar(&values.chainID, "chain-id", "", "chain ID (overrides CORTEX_CHAIN_ID)")
	flags.StringVar(&values.adminSocket, "admin-socket", "", "admin Unix socket path")
	flags.StringVar(&values.modelEndpoint, "model-endpoint", "", "model service endpoint")
	flags.StringVar(&values.modelTransport, "model-transport", "", "model transport: fake, local, or grpc")
	flags.StringVar(&values.modelMaxConcurrency, "model-max-concurrency", "", "concurrent inference requests the model service can hold (required for transport local)")
	flags.StringVar(&values.modelManifestDir, "model-manifest-dir", "", "directory of per-profile model manifests, named <model_id>@<profile_version>.json (required for transport local)")
	flags.StringVar(&values.nodeRPC, "node-rpc", "", "CometBFT RPC endpoint")
	flags.StringVar(&values.nodeREST, "node-rest", "", "Cosmos REST endpoint")
	flags.StringVar(&values.keeperAPI, "keeper-api", "", "deprecated Keeper REST endpoint (ignored for reads)")
	flags.StringVar(&values.keeperPollInterval, "keeper-poll-interval-ms", "", "Keeper polling interval in milliseconds")
	flags.StringVar(&values.keeperMaxLagBlocks, "keeper-max-lag-blocks", "", "maximum allowed Keeper lag in blocks")
	flags.StringVar(&values.taskRetryDelay, "task-retry-delay-ms", "", "task retry delay in milliseconds")
	flags.StringVar(&values.taskMaxRetryAttempts, "task-max-retry-attempts", "", "bound on task queue retries for rows with no protocol deadline")
	flags.StringVar(&values.taskInputResolver, "task-input-resolver", "", "task input resolver: fixture or nexus")
	flags.StringVar(&values.taskFixtureRoot, "task-fixture-root", "", "fixture root for the fixture input resolver")
	flags.StringVar(&values.taskMaxOutputBytes, "task-max-output-bytes", "", "bound on the Verifier output artifact fetch in bytes; 0 takes the built-in default")
	flags.StringVar(&values.nexusIngress, "nexus-ingress", "", "Nexus ingress endpoint")
	flags.StringVar(&values.nexusNATS, "nexus-nats", "", "Nexus NATS endpoint")
	flags.StringVar(&values.nexusAuthTokenFile, "nexus-auth-token-file", "", "Nexus token file path")
	flags.StringVar(&values.nexusJetStreamStream, "nexus-jetstream-stream", "", "JetStream stream Nexus publishes task frames to (required in real mode)")
	flags.StringVar(&values.nexusEnvelopeAuthMode, "nexus-envelope-auth-mode", "", "Nexus envelope auth mode: strict or trusted_nats_dev")
	flags.StringVar(&values.nexusEnvelopeTTLMS, "nexus-envelope-ttl-ms", "", "Nexus bus envelope TTL in milliseconds")
	flags.StringVar(&values.nexusEnvelopeClockSkewMS, "nexus-envelope-clock-skew-ms", "", "tolerated clock skew for Nexus bus envelope stamps in milliseconds")
	flags.StringVar(&values.nexusSubscribeModels, "nexus-subscribe-models", "", "comma-separated Nexus model subjects")
	flags.StringVar(&values.nexusSubscribeTasks, "nexus-subscribe-tasks", "", "comma-separated Nexus task subjects")
	flags.StringVar(&values.evidenceRoot, "evidence-root", "", "deprecated; use --artifacts-root")
	flags.StringVar(&values.artifactsRoot, "artifacts-root", "", "task artifacts root path")
	flags.StringVar(&values.storePath, "store-path", "", "Pebble database directory")
	flags.StringVar(&values.signerURI, "signer-uri", "", "signer service or key-file URI")
	flags.StringVar(&values.signerReadinessProofInterval, "signer-readiness-proof-interval-ms", "", "signer readiness proof interval in milliseconds")
	flags.StringVar(&values.signerPasswordEnv, "signer-password-env", "", "environment variable containing the signer password")
	flags.StringVar(&values.signerPasswordFile, "signer-password-file", "", "file containing the signer password")
	flags.BoolVar(&values.signerPasswordStdin, "signer-password-stdin", false, "read the signer password from standard input")
	flags.StringVar(&values.operatorAddress, "operator-address", "", "Cortex operator address")
	flags.StringVar(&values.serviceKeyRef, "service-key-ref", "", "service key reference")
	flags.StringVar(&values.modelProfiles, "model-profiles", "", "comma-separated model profile bindings")
	flags.StringVar(&values.modelServiceID, "model-service-id", "", "model service ID")
	flags.StringVar(&values.nexusBuilderOperator, "nexus-builder-operator-address", "", "Builder operator address that owns the configured Nexus ingress")
	flags.BoolVar(&values.nexusAllowInsecureDescriptor, "nexus-allow-insecure-descriptor", false, "allow a plaintext http:// Builder endpoint from the on-chain service descriptor (devnet only)")
	flags.BoolVar(&values.nexusDowngradeDescriptorTLS, "nexus-downgrade-descriptor-tls", false, "dial an https:// Builder endpoint from the on-chain service descriptor in plaintext; requires --nexus-allow-insecure-descriptor (devnet only)")
	flags.StringVar(&values.nexusNATSCAFile, "nexus-nats-ca-file", "", "NATS server certificate / CA PEM used to verify a tls:// NATS (ADR-0016)")
	flags.StringVar(&values.nexusNATSCredsFile, "nexus-nats-creds-file", "", "NATS creds file (user JWT + nkey seed) replacing the token (ADR-0016); retired in real mode")
	flags.StringVar(&values.nexusNATSUserKeyFile, "nexus-nats-user-key-file", "", "NATS user key seed file (ed25519 nkey); generated on first start when absent; cortexd binds it to its on-chain service key (ADR-0016 decision three); required in real mode for a remote NATS")
	flags.StringVar(&values.modelServiceTLSCAFile, "model-service-tls-ca-file", "", "model service certificate / CA PEM for the grpc transport")
	flags.StringVar(&values.modelServiceTLSPubkeyHash, "model-service-tls-pubkey-hash", "", "sha256 of the model service certificate SubjectPublicKeyInfo (64 lowercase hex)")
	flags.StringVar(&values.healthBind, "health-bind", "", "health HTTP bind address")
	return cmd
}

// receivingBuilderProvider preserves the verified Builder identity snapshot
// that the Worker needs to authenticate the storage confirmation.
func receivingBuilderProvider(rt *daemon.Runtime) worker.ReceivingBuilderProvider {
	if rt == nil {
		return nil
	}
	return daemon.NewReceivingBuilders(rt.BuilderEndpoints, rt.SelectedTaskBuilders)
}

// taskFactsReader exposes the Keeper's frozen section 16.2 Task reads to the
// Worker receipt path and the Verifier result path. The narrowing lives in
// daemon.NewTaskFacts, which fails closed by name for a Keeper that cannot serve
// them rather than returning a nil this callsite would have to interpret.
func taskFactsReader(rt *daemon.Runtime) taskfacts.Reader {
	if rt == nil {
		return nil
	}
	return daemon.NewTaskFacts(rt.Dependencies.Keeper)
}

func runDaemon(ctx context.Context, cfg config.Config) error {
	// The posture is announced before anything is built, so a node that came up
	// with relaxed envelope trust says so in its first log lines rather than
	// only in a diagnostics call nobody makes.
	if cfg.Mode == config.ModeIntegration {
		slog.Info("SECURITY WARNING: mode=integration: real dependencies with a relaxed Nexus envelope boundary; never promote this configuration to production")
	}
	if cfg.Nexus.TrustedNATSDev() {
		slog.Info("SECURITY WARNING: " + daemon.UnsafeTrustedTransportMarker + ": Nexus BusEnvelope signatures are disabled; trust is limited to the configured NATS token/ACL transport")
	}
	if cfg.Nexus.DowngradeDescriptorTLS {
		slog.Info("SECURITY WARNING: " + daemon.UnsafeDescriptorTLSDowngradeMarker + ": a Builder endpoint published as https:// or grpcs:// is dialled in plaintext; task prompts and outputs travel in the clear until the Builder republishes its descriptor")
	}

	runtime, err := runtimeBuilder(ctx, cfg)
	if err != nil {
		return err
	}
	defer runtime.Close()
	dependencies := runtime.Dependencies

	registry := newModelRegistry(cfg, runtime)
	modelRegistryEnabled := registry != nil
	taskManager, err := newTaskRunner(cfg, runtime)
	if err != nil {
		return err
	}
	adminServer := adminapi.NewServer(cfg.Admin.UDSPath, adminapi.New(adminapi.ServiceConfig{
		ModelRegistry: registry,
		TreasuryStatus: adminapi.TreasuryStatus{
			Destination: "trueopen1treasury",
			Denom:       cfg.Tx.FeeDenom,
		},
		Capability: adminapi.Capability{
			ModelRegistry:     modelRegistryEnabled,
			ChallengeVerifier: cfg.ChallengeVerifier.Enabled,
		},
		Diagnostics:                dependencies.Diagnostics,
		DiagnosticsProvider:        func(context.Context) diagnostics.Diagnostics { return runtime.DiagnosticsSnapshot() },
		EvidenceCleanupPlan:        evidenceCleanupPlanner(cfg, runtime),
		EvidenceCleanupExecute:     evidenceCleanupExecutor(cfg, runtime),
		EvidenceCleanupDiagnostics: evidenceCleanupDiagnostics(cfg, runtime),
		TaskQueueRequeue:           taskQueueRequeuer(runtime, taskManager),
		TaskQueueList:              taskQueueLister(runtime, taskManager),
		TaskSettlement:             taskSettlementSubmitter(runtime),
	}))
	if err := adminServer.Start(ctx); err != nil {
		return err
	}

	health := newRuntimeHealth(cfg)
	if cfg.Nexus.TrustedNATSDev() {
		health.SetWarning(daemon.UnsafeTrustedTransportMarker)
	}
	if cfg.Nexus.AllowInsecureDescriptor {
		health.SetWarning(daemon.UnsafeInsecureDescriptorMarker)
	}
	if cfg.Nexus.DowngradeDescriptorTLS {
		health.SetWarning(daemon.UnsafeDescriptorTLSDowngradeMarker)
	}
	if err := health.Apply(dependencies.Diagnostics.Dependencies); err != nil {
		return err
	}
	// Keeper reconciliation updates the in-memory model registry directly.
	// Do not attach an empty projector: an absent authoritative observation
	// source must not publish zero-valued operational state.
	var projector projectionRunner
	server := newHealthHTTPServer(cfg.Health.Bind, health.Handler())

	errCh := make(chan error, 1)
	go func() {
		slog.Info("cortexd health listening", "bind", cfg.Health.Bind)
		errCh <- server.ListenAndServe()
	}()

	runtimeCtx, stopRuntime := context.WithCancel(ctx)
	runtimeDone := make(chan struct{})
	defer func() {
		stopRuntime()
		<-runtimeDone
	}()
	runtimeErrCh := make(chan error, 1)
	runners, cleanupRuntime, err := runtimeRunnersWithHealthAndTaskRunner(cfg, runtime, projector, health, taskManager)
	if err != nil {
		stopRuntime()
		close(runtimeDone)
		_ = adminServer.Close()
		_ = server.Shutdown(context.Background())
		return err
	}
	// Appended here rather than inside runtimeRunners because it is the only
	// runner that needs the model registry, which is built in this function.
	if renewer := newSupportRenewer(cfg, runtime, registry); renewer != nil {
		runners = append(runners, renewer.Run)
	}
	if len(runners) > 0 {
		go func() {
			defer close(runtimeDone)
			defer cleanupRuntime()
			errCh := make(chan error, len(runners))
			for _, runner := range runners {
				runner := runner
				go func() {
					errCh <- runner(runtimeCtx)
				}()
			}
			var firstErr error
			for i := 0; i < len(runners); i++ {
				if err := <-errCh; err != nil {
					stopRuntime()
					if firstErr == nil {
						firstErr = err
					}
				}
			}
			// Every runner returning nil while the context is still live is not
			// a healthy idle state: nothing is polling Keeper or serving the
			// workload any more, but the process stays up and /readyz keeps
			// answering from the last dependency values it saw. Fail instead of
			// lingering as a node that looks available and does nothing.
			if firstErr == nil && runtimeCtx.Err() == nil {
				firstErr = errors.New("all runtime runners exited while the daemon was still running")
			}
			if firstErr != nil {
				runtimeErrCh <- firstErr
			}
		}()
	} else {
		close(runtimeDone)
	}

	select {
	case <-ctx.Done():
		stopRuntime()
		<-runtimeDone
		if err := adminServer.Close(); err != nil {
			return err
		}
		return server.Shutdown(context.Background())
	case err := <-runtimeErrCh:
		stopRuntime()
		_ = adminServer.Close()
		_ = server.Shutdown(context.Background())
		return err
	case err := <-errCh:
		stopRuntime()
		<-runtimeDone
		_ = adminServer.Close()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func newHealthHTTPServer(bind string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:     bind,
		Handler:  handler,
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}
}

func newRuntimeHealth(cfg config.Config) *observability.Health {
	// Fake mode runs neither the readiness controller nor the Keeper poller, so
	// neither lifecycle dependency can ever be satisfied there.
	dynamicRuntime := cfg.UsesRealDependencies()
	return observability.NewIntegrationHealthWithRuntimeRequirements(
		cfg.RequiresWorkloadTx(),
		dynamicRuntime,
		dynamicRuntime,
	)
}

func taskQueueRequeuer(rt *daemon.Runtime, managers ...*daemon.TaskRunner) func(context.Context, adminapi.TaskQueueRequeueRequest) (adminapi.TaskQueueRequeueResponse, error) {
	if rt == nil || rt.Store == nil {
		return nil
	}
	var manager *daemon.TaskRunner
	if len(managers) > 0 {
		manager = managers[0]
	}
	if manager == nil {
		manager = daemon.NewTaskRunner(daemon.TaskRunnerConfig{Store: rt.Store})
	}
	return func(ctx context.Context, req adminapi.TaskQueueRequeueRequest) (adminapi.TaskQueueRequeueResponse, error) {
		retryAt := time.Now().UTC().Add(time.Duration(req.RetryDelayMS) * time.Millisecond)
		record, err := manager.RequeueActiveTask(ctx, req.QueueID, req.Reason, retryAt)
		if err != nil {
			return adminapi.TaskQueueRequeueResponse{}, err
		}
		return adminapi.TaskQueueRequeueResponse{QueueID: record.QueueID, TaskID: record.TaskID, Status: record.Status, RetryCount: int(record.RetryCount), RetryAt: retryAt.Format(time.RFC3339), LastError: record.LastError}, nil
	}
}

func taskQueueLister(rt *daemon.Runtime, managers ...*daemon.TaskRunner) func(context.Context, adminapi.TaskQueueListRequest) (adminapi.TaskQueueListResponse, error) {
	if rt == nil || rt.Store == nil {
		return nil
	}
	var manager *daemon.TaskRunner
	if len(managers) > 0 {
		manager = managers[0]
	}
	if manager == nil {
		manager = daemon.NewTaskRunner(daemon.TaskRunnerConfig{Store: rt.Store})
	}
	return func(ctx context.Context, req adminapi.TaskQueueListRequest) (adminapi.TaskQueueListResponse, error) {
		records, err := manager.ListActiveTasks(ctx)
		if err != nil {
			return adminapi.TaskQueueListResponse{}, err
		}
		rows := make([]adminapi.TaskQueueRow, 0, len(records))
		for _, record := range records {
			if req.Status != "" && !strings.EqualFold(req.Status, record.Status) {
				continue
			}
			at := ""
			if record.RetryAtUnixMilli > 0 {
				at = time.UnixMilli(record.RetryAtUnixMilli).UTC().Format(time.RFC3339)
			}
			rows = append(rows, adminapi.TaskQueueRow{QueueID: record.QueueID, TaskID: record.TaskID, Role: record.Role, Stage: record.Stage, Status: record.Status, RetryCount: int(record.RetryCount), RetryAt: at, DueHeight: record.DueHeight, LastError: record.LastError, AutoHalted: record.AutoHalted, HaltCode: record.HaltCode, HaltReason: record.HaltReason})
			if req.Limit > 0 && len(rows) >= req.Limit {
				break
			}
		}
		return adminapi.TaskQueueListResponse{Rows: rows}, nil
	}
}

func evidenceCleanupPlanner(cfg config.Config, runtime *daemon.Runtime) func(context.Context) (evidence.CleanupPlan, error) {
	return func(ctx context.Context) (evidence.CleanupPlan, error) {
		if runtime == nil || runtime.Store == nil {
			return evidence.CleanupPlan{}, fmt.Errorf("evidence cleanup store is unavailable")
		}
		height := uint64(0)
		processedHeight, err := runtime.Store.KeeperLastProcessedHeight(ctx)
		if err != nil {
			return evidence.CleanupPlan{}, err
		}
		height = processedHeight
		return evidence.PlanCleanup(ctx, newEvidenceCleanupConfig(cfg, runtime, height))
	}
}

func evidenceCleanupExecutor(cfg config.Config, runtime *daemon.Runtime) func(context.Context, string) (evidence.CleanupResult, error) {
	return func(ctx context.Context, digest string) (evidence.CleanupResult, error) {
		if runtime == nil || runtime.Store == nil {
			return evidence.CleanupResult{}, fmt.Errorf("evidence cleanup store is unavailable")
		}
		height := uint64(0)
		processedHeight, err := runtime.Store.KeeperLastProcessedHeight(ctx)
		if err != nil {
			return evidence.CleanupResult{}, err
		}
		height = processedHeight
		cfg := newEvidenceCleanupConfig(cfg, runtime, height)
		cfg.ConfirmDigest = digest
		return evidence.Cleanup(ctx, cfg)
	}
}

func evidenceCleanupDiagnostics(cfg config.Config, runtime *daemon.Runtime) func(context.Context) (evidence.CleanupDiagnosticsReport, error) {
	return func(ctx context.Context) (evidence.CleanupDiagnosticsReport, error) {
		if runtime == nil || runtime.Store == nil {
			return evidence.CleanupDiagnosticsReport{}, fmt.Errorf("evidence cleanup store is unavailable")
		}
		height := uint64(0)
		processedHeight, err := runtime.Store.KeeperLastProcessedHeight(ctx)
		if err != nil {
			return evidence.CleanupDiagnosticsReport{}, err
		}
		height = processedHeight
		return evidence.CleanupDiagnostics(ctx, newEvidenceCleanupConfig(cfg, runtime, height))
	}
}

func newEvidenceCleanupConfig(cfg config.Config, runtime *daemon.Runtime, height uint64) evidence.CleanupConfig {
	return evidence.CleanupConfig{
		Root: cfg.Artifacts.Root, Index: &evidence.LayoutStoreIndex{Store: runtime.Store}, CurrentHeight: height,
		RetentionPolicyVersion: cfg.Artifacts.RetentionPolicyVersion,
		MinimumRetentionBlocks: cfg.Artifacts.MinimumRetentionBlocks,
		SweepGracePeriod:       cfg.Artifacts.SweepGracePeriod,
		TaskStatus: func(ctx context.Context, taskHash codec.Hash) (evidence.TaskCleanupStatus, error) {
			metadata, err := (&evidence.LayoutStoreIndex{Store: runtime.Store}).Evidence(ctx, taskHash)
			if err != nil {
				return evidence.TaskCleanupStatus{}, err
			}
			openChallenge := false
			if reader, ok := runtime.Dependencies.Keeper.(interface {
				TaskChallengeSummary(context.Context, string, string) (chainclient.TaskChallengeSummarySnapshot, error)
			}); ok && metadata.SessionID != "" && metadata.TaskID != "" {
				summary, err := reader.TaskChallengeSummary(ctx, metadata.SessionID, metadata.TaskID)
				if err != nil {
					return evidence.TaskCleanupStatus{}, err
				}
				openChallenge = summary.OpenChallengeCount > 0
			}
			return evidence.TaskCleanupStatus{TerminalOrSettled: metadata.TerminalOrSettled, OpenChallenge: openChallenge}, nil
		},
	}
}

func shouldStartNexusOutboxRunners(cfg config.Config, deps daemon.Dependencies) bool {
	if !cfg.UsesRealDependencies() {
		return false
	}
	status, ok := deps.Diagnostics.Dependency("nexus")
	return ok && status.Ready
}

type runtimeRunner func(context.Context) error

func runtimeRunners(cfg config.Config, rt *daemon.Runtime, projector projectionRunner) ([]runtimeRunner, func(), error) {
	return runtimeRunnersWithHealth(cfg, rt, projector, nil)
}

func runtimeRunnersWithHealth(cfg config.Config, rt *daemon.Runtime, projector projectionRunner, health *observability.Health) ([]runtimeRunner, func(), error) {
	if rt == nil {
		return nil, func() {}, nil
	}
	taskRunner, err := newTaskRunner(cfg, rt)
	if err != nil {
		return nil, func() {}, err
	}
	return runtimeRunnersWithHealthAndTaskRunner(cfg, rt, projector, health, taskRunner)
}

func runtimeRunnersWithHealthAndTaskRunner(cfg config.Config, rt *daemon.Runtime, projector projectionRunner, health *observability.Health, taskRunner *daemon.TaskRunner) ([]runtimeRunner, func(), error) {
	if rt == nil {
		return nil, func() {}, nil
	}
	var runners []runtimeRunner
	cleanup := func() {}
	poller := newKeeperPollerWithTaskRunner(cfg, rt, projector, taskRunner)
	if poller != nil {
		runners = append(runners, poller.Run)
	}
	if projector != nil && cfg.UsesRealDependencies() {
		runners = append(runners, func(ctx context.Context) error {
			return runProjector(ctx, projector, intervalFromMillis(cfg.Keeper.PollIntervalMS))
		})
	}
	if cfg.UsesRealDependencies() && rt.SupportsDynamicReadiness() {
		controller := daemon.NewReadinessController(daemon.ReadinessControllerConfig{
			Interval: intervalFromMillis(cfg.Keeper.PollIntervalMS),
			Check:    rt.CheckWorkloadReadiness,
			Stop:     rt.DeactivateWorkload,
			Observe:  readinessObserver(health, newReadinessLog()),
			ObserveWorkload: func(running bool) {
				if health == nil {
					return
				}
				_ = health.SetDependency(observability.DependencyWorkload, running)
			},
			OnRetryableFailure: logWorkloadStartFailure,
			Start: func(ctx context.Context, readiness daemon.WorkloadReadiness, started func()) error {
				if err := rt.ActivateWorkload(readiness.ServiceAddress, readiness.ServicePubkey); err != nil {
					return err
				}
				barrier := newStartupBarrier()
				workload, workloadCleanup, err := workloadRunnersWithTaskRunner(cfg, rt, barrier, taskRunner)
				if err != nil {
					return err
				}
				barrier.seal()
				return runRuntimeRunnerGroupWithStarted(ctx, workload, workloadCleanup, started, barrier)
			},
		})
		runners = append(runners, controller.Run)
		return runners, cleanup, nil
	}

	legacyWorkload, legacyCleanup, err := workloadRunnersWithTaskRunner(cfg, rt, nil, taskRunner)
	if err != nil {
		return nil, cleanup, err
	}
	// Without dynamic readiness the workload runners start unconditionally and
	// run for the process lifetime, so the workload is live from here on.
	if health != nil && len(legacyWorkload) > 0 {
		_ = health.SetDependency(observability.DependencyWorkload, true)
	}
	runners = append(runners, legacyWorkload...)
	cleanup = legacyCleanup
	return runners, cleanup, nil
}

// readinessRestateInterval bounds how often a boundary that stays down repeats
// its reason. Long enough that a node down for hours does not restate at the
// Keeper poll interval, short enough that a fresh log tail still says why the
// node is not serving.
const readinessRestateInterval = 5 * time.Minute

func newReadinessLog() *observability.ReadinessLog {
	return &observability.ReadinessLog{
		Emit: func(record observability.LogRecord) {
			observability.Emit(record)
		},
		Restate: readinessRestateInterval,
	}
}

// readinessObserver fans one readiness snapshot out to everything that reports
// it. The log is not optional decoration here: /readyz and cortexctl
// diagnostics only answer an operator who already suspects a problem and knows
// those surfaces exist, so a node that fails closed has to say which module
// held it down, and why, in its own log.
func readinessObserver(health *observability.Health, readinessLog *observability.ReadinessLog) func(daemon.WorkloadReadiness) {
	return func(readiness daemon.WorkloadReadiness) {
		statuses := readiness.DependencyStatuses()
		readinessLog.Observe(readiness.Ready(), statuses)
		if health == nil {
			return
		}
		for _, status := range statuses {
			_ = health.SetDependency(status.Name, status.Ready)
		}
	}
}

func workloadRunnersWithTaskRunner(cfg config.Config, rt *daemon.Runtime, barrier *startupBarrier, taskRunner *daemon.TaskRunner) ([]runtimeRunner, func(), error) {
	if rt == nil {
		return nil, func() {}, nil
	}
	var runners []runtimeRunner
	var subscriptions []builderclient.Subscription
	cleanup := func() {
		for _, subscription := range subscriptions {
			_ = subscription.Unsubscribe()
		}
	}
	dependencies := rt.Dependencies
	if cfg.UsesRealDependencies() && !cfg.Nexus.TrustedNATSDev() && dependencies.NexusEnvelopeAuthenticator == nil {
		return nil, cleanup, builderclient.ErrBusEnvelopeAuthenticationUnavailable
	}
	if shouldStartNexusOutboxRunners(cfg, dependencies) && rt.Store != nil && dependencies.Builder != nil {
		inboxConfig := outbox.InboxRunnerConfig{
			ModelIDs:     cfg.Nexus.SubscribeModels,
			TaskIDs:      cfg.Nexus.SubscribeTasks,
			AllTasks:     true,
			Refuse:       logNexusInboxRefusal,
			OnCompletion: logNexusInboxCompletion,
		}
		if taskRunner != nil {
			inboxConfig.Process = taskRunner.HandleNexusMessage
		}

		inboxRunner := outbox.NewInboxRunner(dependencies.Subscriber, inboxConfig)
		subscribed := barrier.expect()
		runners = append(runners, func(ctx context.Context) error {
			started, err := inboxRunner.Start(ctx)
			if err != nil {
				return err
			}
			subscriptions = append(subscriptions, started...)
			slog.Info("nexus inbox subscribed",
				slog.Int("subjects_count", len(started)),
				slog.String("subjects", strings.Join(outbox.InboxSubjects(inboxConfig), " ")))
			// The node is serving from here: its subscriptions exist.
			subscribed()
			<-ctx.Done()
			return nil
		})
		runners = append(runners, func(ctx context.Context) error {
			return inboxRunner.DrainErrors(ctx, logNexusSubscriberError)
		})
	} else if cfg.UsesRealDependencies() {
		nexusReady := shouldStartNexusOutboxRunners(cfg, dependencies)
		slog.Info("nexus inbox skipped",
			slog.Bool("nexus_ready", nexusReady),
			slog.Bool("store", rt.Store != nil),
			slog.Bool("builder", dependencies.Builder != nil))
	}

	if taskRunner != nil {
		runners = append(runners, taskRunner.Run)
	}
	return runners, cleanup, nil
}

func formatNexusInboxCompletion(completion outbox.InboxMessageCompletion) string {
	return fmt.Sprintf(
		"nexus inbox completed subject=%s kind=%s task=%s message_id=%s jetstream=%t bytes=%d result=%s duration_ms=%d",
		quoteNexusLogValue(completion.Subject), quoteNexusLogValue(string(completion.Kind)),
		quoteNexusLogValue(completion.TaskID), quoteNexusLogValue(completion.MessageID), completion.JetStream,
		completion.SizeBytes, quoteNexusLogValue(completion.Result), completion.Duration.Milliseconds(),
	)
}

// formatNexusPublishCompletion is the outbound counterpart of
// formatNexusInboxCompletion. A successful publish used to be silent, which left
// "did this node send its handraise" answerable only by elimination from the
// failure logs — and the precheck path that declines to raise a hand returns no
// error at all, so elimination could not distinguish "sent" from "never signed".
func formatNexusPublishCompletion(completion builderclient.PublishCompletion) string {
	line := fmt.Sprintf(
		"nexus publish completed subject=%s kind=%s task=%s message_id=%s dedup_id=%s jetstream=%t bytes=%d result=%s duration_ms=%d",
		quoteNexusLogValue(completion.Subject), quoteNexusLogValue(string(completion.Kind)),
		quoteNexusLogValue(completion.TaskID), quoteNexusLogValue(completion.MessageID),
		quoteNexusLogValue(completion.DedupID), completion.JetStream, completion.SizeBytes,
		quoteNexusLogValue(completion.Result), completion.Duration.Milliseconds(),
	)
	if completion.Err != nil {
		line += " error=" + quoteNexusLogValue(completion.Err.Error())
	}
	return line
}

// quoteNexusLogValue keeps these formatters' escaping identical to the
// readiness log's: one rule for every key=value line cortexd emits.
func quoteNexusLogValue(value string) string {
	return observability.QuoteLogValue(value)
}

// startupBarrier releases once every runner with a startup phase has reported
// that phase complete. Workload readiness waits on it, because spawning a
// runner goroutine is not the same as the runner having done its job: the Nexus
// inbox runner establishes its subscriptions inside its goroutine, and a node
// with no subscriptions is not serving no matter how many goroutines are alive.
type startupBarrier struct {
	mu      sync.Mutex
	pending int
	ready   chan struct{}
	closed  bool
}

func newStartupBarrier() *startupBarrier {
	return &startupBarrier{ready: make(chan struct{})}
}

// expect registers a startup phase and returns the signal that completes it.
func (b *startupBarrier) expect() func() {
	if b == nil {
		return func() {}
	}
	b.mu.Lock()
	b.pending++
	b.mu.Unlock()
	var once sync.Once
	return func() { once.Do(b.complete) }
}

func (b *startupBarrier) complete() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending--
	b.releaseLocked()
}

// seal declares that no further startup phases will be registered, releasing
// the barrier when there were none.
func (b *startupBarrier) seal() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked()
}

func (b *startupBarrier) releaseLocked() {
	if b.pending == 0 && !b.closed {
		b.closed = true
		close(b.ready)
	}
}

func (b *startupBarrier) Ready() <-chan struct{} {
	if b == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return b.ready
}

func runRuntimeRunnerGroupWithStarted(ctx context.Context, runners []runtimeRunner, cleanup func(), started func(), barrier *startupBarrier) error {
	defer cleanup()
	if len(runners) == 0 {
		<-ctx.Done()
		return nil
	}
	errCh := make(chan error, len(runners))
	groupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// exited counts runners that have returned. It is incremented before the
	// error is queued, so "a runner has finished" is observable even in the
	// window before its error reaches errCh.
	var exited atomic.Int64
	for _, runner := range runners {
		runner := runner
		go func() {
			err := runner(groupCtx)
			exited.Add(1)
			errCh <- err
		}()
	}

	var firstErr error
	remaining := len(runners)
	collect := func(err error) {
		remaining--
		if err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}

	// Startup phase. One loop consumes both runner exits and the startup
	// barrier, so a runner that has already exited is always observed before
	// the workload is reported as running. Racing a separate barrier goroutine
	// against this collector let a completed subscription report readiness
	// while another runner's failure was still sitting unread in errCh.
	startupPending := started != nil
	ready := barrier.Ready()
	for startupPending && remaining > 0 {
		// An already-finished runner wins over the barrier: its exit happened
		// first, whether or not its error has been collected yet.
		select {
		case err := <-errCh:
			collect(err)
			startupPending = false
			continue
		default:
			if exited.Load() > 0 {
				// A runner has returned; its error is on its way. Do not report
				// the workload as running, and let the collector below drain.
				startupPending = false
				continue
			}
		}
		select {
		case err := <-errCh:
			collect(err)
			// Any runner exiting during startup means the group is going down,
			// so the workload is not serving and is never reported as such.
			startupPending = false
		case <-ready:
			// A runner may have exited while the barrier was releasing. Consume
			// it if its error already landed; otherwise the exit counter still
			// reveals that one returned, so readiness is withheld either way.
			select {
			case err := <-errCh:
				collect(err)
			default:
				if exited.Load() == 0 {
					started()
				}
			}
			startupPending = false
		}
	}

	for remaining > 0 {
		collect(<-errCh)
	}
	return firstErr
}

func newTaskRunner(cfg config.Config, rt *daemon.Runtime) (*daemon.TaskRunner, error) {
	if !cfg.UsesRealDependencies() || rt == nil || rt.Store == nil || rt.Dependencies.Model == nil || rt.Dependencies.Builder == nil {
		return nil, nil
	}
	identityStatus, ok := rt.Dependencies.Diagnostics.Dependency("keeper_identity")
	if !rt.SupportsDynamicReadiness() && ok && !identityStatus.Ready {
		return nil, nil
	}
	var taskTx txclient.Client
	if rt.SupportsDynamicReadiness() {
		taskTx = rt.WorkloadTxClient()
	} else {
		taskTx = rt.Dependencies.Tx
	}
	profiles, err := cfg.LocalIdentity.ModelProfiles()
	if err != nil {
		return nil, err
	}
	profileCapabilities := make(map[string]string, len(profiles))
	for _, profile := range profiles {
		profileCapabilities[profile.ModelID+"\x00"+fmt.Sprintf("%d", profile.ProfileVersion)] = profile.Capability
	}
	evidenceStore, err := evidence.NewStore(cfg.Artifacts.Root, &evidence.LayoutStoreIndex{Store: rt.Store})
	if err != nil {
		return nil, fmt.Errorf("task runner evidence store: %w", err)
	}
	if err := daemon.RefuseLegacyState(context.Background(), rt.Store, evidenceStore); err != nil {
		return nil, err
	}
	fakeOutput := strings.EqualFold(strings.TrimSpace(cfg.ModelManagement.Transport), "fake")
	var handraiseEligibility daemon.HandraiseEligibility
	var taskReader daemon.KeeperTaskReader
	taskReader, _ = rt.Dependencies.Keeper.(daemon.KeeperTaskReader)
	var profileReader daemon.KeeperProfileReader
	profileReader, _ = rt.Dependencies.Keeper.(daemon.KeeperProfileReader)
	var candidateMemberReader daemon.CandidateMemberReader
	candidateMemberReader, _ = rt.Dependencies.Keeper.(daemon.CandidateMemberReader)
	var verifierMemberReader daemon.VerifierMemberReader
	verifierMemberReader, _ = rt.Dependencies.Keeper.(daemon.VerifierMemberReader)
	if !fakeOutput {
		keeper, ok := rt.Dependencies.Keeper.(daemon.KeeperHandraiseReader)
		if ok {
			handraiseEligibility = daemon.NewKeeperHandraiseEligibility(daemon.KeeperHandraiseEligibilityConfig{
				ChainStatus: rt, Keeper: keeper, Model: rt.Dependencies.Model,
				ChainID: cfg.ChainID, OperatorAddress: cfg.LocalIdentity.OperatorAddress, ModelServiceID: cfg.LocalIdentity.ModelServiceID,
				SelfRescueGasBudget: cfg.SelfRescue.MaxFeeAmount,
			})
		}
	}
	return daemon.NewTaskRunner(daemon.TaskRunnerConfig{
		Store:             rt.Store,
		Evidence:          evidenceStore,
		Model:             rt.Dependencies.Model,
		Builder:           rt.Dependencies.Builder,
		OutputPackages:    rt.Dependencies.OutputPackages,
		OutputConfirmer:   rt.OutputConfirmer,
		EvidenceConfirmer: rt.EvidenceConfirmer,
		VerifyCommitRelay: rt.VerifyCommitRelay,
		Trace:             rt.TaskTrace(),
		FakeOutput:        fakeOutput,
		TrustedNATSDev:    cfg.Nexus.TrustedNATSDev(),
		// FakeBus is deliberately not set from configuration. It disables
		// canonical order verification outright, and this function has already
		// returned for every mode but real, so the old
		// `cfg.Mode == config.ModeFake` was always false. Wiring it back would
		// not give fake mode a task loop; it would give a real bus a Worker
		// that accepts an OrderBroadcast disagreeing with its own signed_order.
		EnvelopeTTL:                cfg.Nexus.EnvelopeTTL(),
		EnvelopeClockSkew:          cfg.Nexus.EnvelopeClockSkew(),
		HandraiseEligibility:       handraiseEligibility,
		NexusEnvelopeAuthenticator: rt.Dependencies.NexusEnvelopeAuthenticator,
		NexusEnvelopeSigner:        rt.Dependencies.NexusEnvelopeSigner,
		Tx:                         taskTx,
		TxGasPayer:                 rt.ServiceAddress,
		TxFeeCap:                   txclient.Coin{Amount: cfg.Tx.MaxFeeAmount, Denom: cfg.Tx.FeeDenom},
		// taskTx above is read once, here, and on a dynamic-readiness node that
		// is before ActivateWorkload has run -- so it is nil for the whole
		// process on exactly the deployments that need it. The verifier commit
		// exit resolves the live client through this provider instead, the same
		// way ServiceIdentity resolves the live service address.
		TxProvider:            rt.WorkloadTxClient,
		CommitExitFeeCap:      txclient.Coin{Amount: cfg.CommitExitFeeCap(), Denom: cfg.Tx.FeeDenom},
		LocalWorkerAddress:    cfg.LocalIdentity.OperatorAddress,
		LocalVerifierAddress:  cfg.LocalIdentity.OperatorAddress,
		ModelServiceID:        cfg.LocalIdentity.ModelServiceID,
		ChainID:               cfg.ChainID,
		SignerAddress:         rt.ServiceAddress,
		SignerKeyRef:          cfg.LocalIdentity.ServiceKeyRef,
		SignerPubkey:          rt.ServicePubkey,
		Signer:                signerForRuntime(rt),
		ServiceIdentity:       rt.WorkloadIdentity,
		MaxConcurrency:        cfg.ModelManagement.MaxConcurrency,
		PollInterval:          intervalFromMillis(cfg.Keeper.PollIntervalMS),
		RetryDelay:            intervalFromMillis(cfg.TaskExecution.RetryDelayMS),
		MaxRetryDelay:         intervalFromMillis(cfg.TaskExecution.MaxRetryDelayMS),
		ChainStatus:           rt,
		MaxRetryAttempts:      cfg.TaskExecution.MaxRetryAttempts,
		MaxOutputBytes:        cfg.TaskExecution.MaxOutputBytes,
		InputResolver:         rt.TaskInputResolver,
		TaskData:              rt.Dependencies.TaskData,
		TaskDataAuth:          rt.TaskDataAuth,
		ReceivingBuilder:      receivingBuilderProvider(rt),
		TaskFacts:             taskFactsReader(rt),
		CandidateMemberReader: candidateMemberReader,
		VerifierMemberReader:  verifierMemberReader,
		ProfileCapabilities:   profileCapabilities,
		ProfileReader:         profileReader,
		TaskReader:            taskReader,
		Diagnostic:            logTaskRunnerDiagnostic,
		OnQuarantinedEffect:   logQuarantinedKeeperEffect,
	}), nil
}

func newKeeperPollerWithTaskRunner(cfg config.Config, rt *daemon.Runtime, projector projectionRunner, taskRunner *daemon.TaskRunner) *daemon.KeeperPoller {
	if !cfg.UsesRealDependencies() || rt == nil || rt.Store == nil || rt.Reconciler == nil || rt.KeeperEvents == nil {
		return nil
	}
	interval := time.Duration(cfg.Keeper.PollIntervalMS) * time.Millisecond
	return daemon.NewKeeperPoller(rt.Store, rt.KeeperEvents, rt.Reconciler, daemon.KeeperPollerConfig{
		Interval:             interval,
		MaxChainLag:          cfg.Keeper.MaxLagBlocks,
		ObserveChainProgress: rt.ObserveChainProgress,
		OnRetryableFailure:   logKeeperPollFailure,
		EffectSink: func(ctx context.Context, effects []daemon.ReconcilerEffect) error {
			if len(effects) > 0 {
				if taskRunner == nil {
					return fmt.Errorf("Keeper effects require infer/verify managers")
				}
				if err := taskRunner.ApplyReconcilerEffects(ctx, effects); err != nil {
					return err
				}
			}
			if projector != nil {
				return projector.RunOnce(ctx)
			}
			return nil
		},
	})
}

func logWorkloadStartFailure(err error) {
	observability.LogAtDepth(slog.LevelError, 1, "workload start failed, retrying on the next readiness tick", slog.Any("error", err))
}

func logNexusInboxRefusal(err error) {
	observability.LogAtDepth(slog.LevelError, 1, "nexus inbox refused", slog.Any("error", err))
}

func logNexusInboxCompletion(completion outbox.InboxMessageCompletion) {
	observability.LogAtDepth(slog.LevelInfo, 1, formatNexusInboxCompletion(completion))
}

func logNexusSubscriberError(err error) {
	observability.LogAtDepth(slog.LevelError, 1, "nexus subscriber delivery error", slog.Any("error", err))
}

func logTaskRunnerDiagnostic(diagnostic daemon.TaskRunnerDiagnostic) {
	// A wait is not a failure. The chain state this node needs is
	// materialized on a block that has not arrived yet, the frame stays in
	// redelivery, and nothing is wrong -- so it must not be logged with the
	// word an operator greps for when something is.
	attrs := []slog.Attr{
		slog.String("diagnostic_source", diagnostic.Source),
		slog.String("record", diagnostic.Record),
		slog.String("error", diagnostic.Error),
	}
	if diagnostic.Waiting {
		observability.LogAtDepth(slog.LevelInfo, 1, "task runner waiting", attrs...)
		return
	}
	if diagnostic.RetryAt.IsZero() {
		observability.LogAtDepth(slog.LevelError, 1, "task runner failure", attrs...)
		return
	}
	attrs = append(attrs,
		slog.Int64("count", diagnostic.Count),
		slog.String("retry_at", diagnostic.RetryAt.Format(time.RFC3339)))
	observability.LogAtDepth(slog.LevelError, 1, "task runner retry", attrs...)
}

func logQuarantinedKeeperEffect(effect daemon.ReconcilerEffect, err error) {
	observability.LogAtDepth(slog.LevelError, 1, "quarantined Keeper effect",
		slog.String("type", string(effect.Type)),
		slog.String("task", effect.TaskID),
		slog.Any("error", err))
}

func logKeeperPollFailure(attempt int, delay time.Duration, err error) {
	observability.LogAtDepth(slog.LevelError, 1, "keeper poll failed",
		slog.Int("attempt", attempt),
		slog.Duration("retry_in", delay),
		slog.Any("error", err))
}

func runProjector(ctx context.Context, projector projectionRunner, interval time.Duration) error {
	if projector == nil {
		return nil
	}
	if interval <= 0 {
		interval = time.Second
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := projector.RunOnce(ctx); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func intervalFromMillis(ms uint64) time.Duration {
	interval := time.Duration(ms) * time.Millisecond
	if interval <= 0 {
		return time.Second
	}
	return interval
}

// chainHeightLookupTimeout bounds the Keeper height lookup that operator
// registration paths block on.
const chainHeightLookupTimeout = 5 * time.Second

// fakeChainHeightValue keeps fake mode deterministic while still exercising the
// real height comparisons.
const fakeChainHeightValue = 1

func unavailableChainHeight() (uint64, error) {
	return 0, fmt.Errorf("Keeper chain height is unavailable")
}

func fakeChainHeight() (uint64, error) {
	return fakeChainHeightValue, nil
}

func newModelRegistry(cfg config.Config, rt *daemon.Runtime) *modelregistry.Registry {
	registryConfig := modelregistry.RegistryConfig{
		NowHeight:        unavailableChainHeight,
		Treasury:         "trueopen1treasury",
		FeeDenom:         cfg.Tx.FeeDenom,
		SelfTester:       cortexdSelfTest,
		FeeGrant:         modelregistry.StaticFeeGrant{Granter: cfg.LocalIdentity.OperatorAddress, Amount: cfg.Tx.MaxFeeAmount, GasLimit: cfg.Tx.GasLimit},
		MinGasGrant:      1,
		SupporterAddress: cfg.LocalIdentity.OperatorAddress,
		// Duty selection is retired: a node declares every profile it supports
		// for both responsibilities, because it can be drawn for either.
		InferenceCapability:        true,
		VerificationCapability:     true,
		RequireSupportConfirmation: cfg.UsesRealDependencies(),
	}
	if cfg.Mode == config.ModeFake {
		registryConfig.NowHeight = fakeChainHeight
		registryConfig.Signer = fakeModelRegistrationSigner
		registryConfig.FeeGrant = modelregistry.StaticFeeGrant{Granter: "operator", Amount: 1_000_000, GasLimit: 1_000_000}
		registryConfig.Submitter = fakeRegistrationSubmitter{}
		registryConfig.Outbox = fakeRegistrationOutbox{}
		return modelregistry.NewRegistry(registryConfig)
	}
	if rt == nil || rt.Store == nil {
		return nil
	}
	registryConfig.RegistrationSponsor = cfg.LocalIdentity.OperatorAddress
	registryConfig.ChainID = cfg.ChainID
	registryConfig.ProposerAddress = cfg.LocalIdentity.OperatorAddress
	if reader, ok := rt.Dependencies.Keeper.(modelregistry.RegistrationReader); ok {
		registryConfig.RegistrationReader = reader
	}
	if reader, ok := rt.Dependencies.Keeper.(modelregistry.CurrentRegistrationReader); ok {
		registryConfig.CurrentRegistrationReader = reader
	}
	signingClient := signerForRuntime(rt)
	// Registration is an offline operator action. cortexd deliberately has no
	// operator signer; production registration must use offline chain tooling.
	if rt.Dependencies.Keeper != nil {
		registryConfig.NowHeight = func() (uint64, error) {
			ctx, cancel := context.WithTimeout(context.Background(), chainHeightLookupTimeout)
			defer cancel()
			return rt.Dependencies.Keeper.ChainHeight(ctx)
		}
	}
	if rt.Dependencies.Builder != nil {
		registryConfig.Outbox = modelregistry.NewBuilderRegistrationPublisher(rt.Dependencies.Builder)
	}
	if rt.WorkloadTx != nil && cfg.Tx.Enabled && rt.TaskDataAuth != nil {
		registryConfig.SupportConfirmer = modelregistry.NewTxSupportConfirmer(rt.WorkloadTx, modelregistry.TxSupportConfirmerOptions{
			ChainID: cfg.ChainID, OperatorAddress: cfg.LocalIdentity.OperatorAddress,
			Signer: signingClient, ServiceKeyRef: cfg.LocalIdentity.ServiceKeyRef, ServiceAddress: rt.ServiceAddress,
			ServiceIdentity: func(ctx context.Context) (uint64, uint64, uint64, uint64, error) {
				nonce, height, err := rt.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
				if err != nil {
					return 0, 0, 0, 0, err
				}
				reader, ok := rt.Dependencies.Keeper.(interface {
					SupportSigningScopeAt(context.Context, uint64) (uint64, uint64, error)
				})
				if !ok {
					return 0, 0, 0, 0, fmt.Errorf("Keeper support signing scope reader is required")
				}
				epoch, expiry, err := reader.SupportSigningScopeAt(ctx, height)
				return nonce, height, epoch, expiry, err
			},
			GasPayer: rt.ServiceAddress, FeeCap: modelregistryTxFeeCap(cfg),
			SupportedModels: dailySupportModels(cfg),
		})
	}
	registry := modelregistry.NewRegistry(registryConfig)
	if rt.Reconciler != nil {
		rt.Reconciler.SetRegistry(registry)
	}
	return registry
}

// registrySupportConfirmer renews through the same Registry call
// `cortexctl daily-support` reaches over the admin socket, so the automatic
// path and the manual one cannot diverge in what they submit.
type registrySupportConfirmer struct {
	registry *modelregistry.Registry
}

func (c registrySupportConfirmer) RenewDailySupport(ctx context.Context, modelID string) error {
	_, err := c.registry.DailySupport(ctx, modelregistry.DailySupportRequest{ModelID: modelID, Enabled: true})
	return err
}

// newSupportRenewer wires the automatic renewal of declared model support.
//
// Nil outside real mode, or without a registry or a Keeper that can read
// identity: renewal submits a transaction against chain state, and there is
// nothing meaningful to do with a fake one.
func newSupportRenewer(cfg config.Config, rt *daemon.Runtime, registry *modelregistry.Registry) *daemon.SupportRenewer {
	if !cfg.UsesRealDependencies() || rt == nil || registry == nil {
		return nil
	}
	keeper, ok := rt.Dependencies.Keeper.(daemon.KeeperIdentityReader)
	if !ok {
		return nil
	}
	return daemon.NewSupportRenewer(daemon.SupportRenewerConfig{
		Identity:  cfg.LocalIdentity,
		Keeper:    keeper,
		Confirmer: registrySupportConfirmer{registry: registry},
		Height: func(ctx context.Context) (uint64, error) {
			return rt.Dependencies.Keeper.ChainHeight(ctx)
		},
		// Checked on the Keeper poll cadence. The check is three cheap reads
		// and renewal only fires near the end of a window measured in epochs,
		// so the frequency costs nothing and bounds how long a missed renewal
		// goes unnoticed.
		Interval: intervalFromMillis(cfg.Keeper.PollIntervalMS),
		OnRenewal: func(modelID string, remaining uint64) {
			slog.Info("renewed daily model support",
				slog.String("model", modelID), slog.Uint64("remaining_before_renewal", remaining))
		},
		OnFailure: func(modelID string, err error) {
			slog.Error("daily model support renewal failed",
				slog.String("model", modelID), slog.Any("error", err))
		},
	})
}

// dailySupportModels lists every model in local_identity.supported_model_profiles
// once. Support is model-scoped, and a daily support confirmation must carry the
// whole set, because Node keeps one record per (epoch, operator). An
// unparseable configuration yields no models, which the confirmer refuses
// rather than confirming a partial set.
func dailySupportModels(cfg config.Config) []string {
	refs, err := cfg.LocalIdentity.ModelProfiles()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(refs))
	models := make([]string, 0, len(refs))
	for _, ref := range refs {
		if _, ok := seen[ref.ModelID]; ok {
			continue
		}
		seen[ref.ModelID] = struct{}{}
		models = append(models, ref.ModelID)
	}
	return models
}

func modelregistryTxFeeCap(cfg config.Config) txclient.Coin {
	return txclient.Coin{Amount: cfg.Tx.MaxFeeAmount, Denom: cfg.Tx.FeeDenom}
}

func cortexdSelfTest(_ context.Context, manifest modelregistry.Manifest) (modelregistry.SelfTestResult, error) {
	return modelregistry.SelfTestResult{
		Passed: true,
		RegistrationMaterial: &modelregistry.RegistrationMaterial{
			ManifestHash: manifest.Hash,
		},
	}, nil
}

func fakeModelRegistrationSigner(_ context.Context, material modelregistry.RegistrationMaterial) (string, error) {
	return strings.Repeat("ab", 64), nil
}

type fakeRegistrationSubmitter struct{}

func (fakeRegistrationSubmitter) SubmitRegistration(_ context.Context, material modelregistry.RegistrationMaterial) (string, error) {
	return "tx-" + material.ManifestHash, nil
}

type fakeRegistrationOutbox struct{}

func (fakeRegistrationOutbox) WriteRegistration(_ context.Context, msg modelregistry.OutboxMessage) (string, error) {
	return "outbox-" + msg.Material.ManifestHash, nil
}
