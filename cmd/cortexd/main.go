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
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/buildinfo"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store/layout"
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
		TaskTraceObserver: func(record observability.LogRecord) {
			observability.Emit(record)
		},
	}
}

// signerForRuntime resolves the signer built during runtime construction. It
// is a variable so tests can inject a stub without standing up a signing
// service or a key file.
var signerForRuntime = func(rt *daemon.Runtime) signer.Signer { return rt.SigningClient() }

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
		} else if arg == "-version" {
			normalized[i] = "--version"
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
	nexusAuthTokenFile           string
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
	modelServiceTLSCAFile        string
	modelServiceTLSPubkeyHash    string
	nodeTLSCAFile                string
	nodeTLSPubkeyHash            string
	healthBind                   string
	dispatchBuilders             string
}

func newRootCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var values daemonFlags
	cmd := &cobra.Command{
		Use:           "cortexd",
		Short:         "Run the Cortex control-plane daemon",
		Version:       buildinfo.Current(),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			overrides := make(map[string]string)
			for flagName, key := range map[string]string{
				"mode": "mode", "chain-id": "chain_id", "admin-socket": "admin_socket",
				"model-endpoint": "model_endpoint", "model-transport": "model_transport",
				"model-max-concurrency": "model_max_concurrency",
				"node-rpc":              "node_rpc", "node-rest": "node_rest", "keeper-api": "keeper_api",
				"keeper-poll-interval-ms": "keeper_poll_interval_ms", "keeper-max-lag-blocks": "keeper_max_lag_blocks",
				"task-retry-delay-ms":     "task_retry_delay_ms",
				"task-max-retry-attempts": "task_max_retry_attempts",
				"task-input-resolver":     "task_input_resolver",
				"task-fixture-root":       "task_fixture_root",
				"task-max-output-bytes":   "task_max_output_bytes",
				"nexus-ingress":           "nexus_ingress",
				"nexus-auth-token-file":   "nexus_auth_token_file",
				"evidence-root":           "evidence_root",
				"artifacts-root":          "artifacts_root",
				"store-path":              "store_path", "signer-uri": "signer_uri",
				"signer-readiness-proof-interval-ms": "signer_readiness_proof_interval_ms",
				"signer-password-env":                "signer_password_env", "signer-password-file": "signer_password_file",
				"signer-password-stdin": "signer_password_stdin",
				"operator-address":      "operator_address", "service-key-ref": "service_key_ref",
				"model-profiles":                  "model_profiles",
				"model-service-id":                "model_service_id",
				"nexus-builder-operator-address":  "nexus_builder_operator_address",
				"nexus-allow-insecure-descriptor": "nexus_allow_insecure_descriptor",
				"nexus-downgrade-descriptor-tls":  "nexus_downgrade_descriptor_tls",
				"model-service-tls-ca-file":       "model_service_tls_ca_file",
				"model-service-tls-pubkey-hash":   "model_service_tls_pubkey_hash",
				"node-tls-ca-file":                "node_tls_ca_file",
				"node-tls-pubkey-hash":            "node_tls_pubkey_hash",
				"health-bind":                     "health_bind",
				"dispatch-builders":               "dispatch_builders",
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
	flags.StringVar(&values.nexusAuthTokenFile, "nexus-auth-token-file", "", "Nexus token file path")
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
	flags.StringVar(&values.modelServiceTLSCAFile, "model-service-tls-ca-file", "", "model service certificate / CA PEM for the grpc transport")
	flags.StringVar(&values.modelServiceTLSPubkeyHash, "model-service-tls-pubkey-hash", "", "sha256 of the model service certificate SubjectPublicKeyInfo (64 lowercase hex)")
	flags.StringVar(&values.nodeTLSCAFile, "node-tls-ca-file", "", "chain node certificate / CA PEM for the https node endpoints")
	flags.StringVar(&values.nodeTLSPubkeyHash, "node-tls-pubkey-hash", "", "sha256 of the chain node certificate SubjectPublicKeyInfo (64 lowercase hex)")
	flags.StringVar(&values.healthBind, "health-bind", "", "health HTTP bind address")
	flags.StringVar(&values.dispatchBuilders, "dispatch-builders", "", "comma-separated Builder operators to keep a standing handraise with (dispatch.builders)")
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
	// with a relaxed security posture says so in its first log lines rather than
	// only in a diagnostics call nobody makes.
	if cfg.Mode == config.ModeIntegration {
		slog.Info("SECURITY WARNING: mode=integration: real dependencies with relaxed Nexus security flags; never promote this configuration to production")
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
	if cfg.Nexus.AllowInsecureDescriptor {
		health.SetWarning(daemon.UnsafeInsecureDescriptorMarker)
	}
	if cfg.Nexus.DowngradeDescriptorTLS {
		health.SetWarning(daemon.UnsafeDescriptorTLSDowngradeMarker)
	}
	registerDispatchHealth(health, runtime)
	if err := health.Apply(dependencies.Diagnostics.Dependencies); err != nil {
		return err
	}
	health.AttachMetrics(observability.NewMetricsHandler(nodeStateSource(runtime, health, taskManager)))
	server := newHealthHTTPServer(cfg.Health.Bind, health.Handler())

	errCh := make(chan error, 1)
	go func() {
		slog.Info("cortexd health listening", "bind", cfg.Health.Bind, "version", buildinfo.Current())
		errCh <- server.ListenAndServe()
	}()

	runtimeCtx, stopRuntime := context.WithCancel(ctx)
	runtimeDone := make(chan struct{})
	defer func() {
		stopRuntime()
		<-runtimeDone
	}()
	runtimeErrCh := make(chan error, 1)
	runners, cleanupRuntime, err := runtimeRunnersWithHealthAndTaskRunner(cfg, runtime, health, taskManager)
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

// nodeStateSource reads what /metrics reports from the same state the admin
// socket serves: the diagnostics snapshot (chain cursor and tip), the readiness
// dependencies behind /readyz, and the task queue cortexctl task list shows.
func nodeStateSource(rt *daemon.Runtime, health *observability.Health, tasks *daemon.TaskRunner) observability.NodeStateSource {
	return func(ctx context.Context) (observability.NodeState, error) {
		report := rt.DiagnosticsSnapshot()
		ready, dependencies := health.Readiness()
		state := observability.NodeState{
			Version:           buildinfo.Current(),
			ChainCursorHeight: report.ChainCursorHeight,
			ChainTipHeight:    report.ChainTipHeight,
			ChainLagBlocks:    report.ChainLagBlocks,
			Ready:             ready,
			Dependencies:      dependencies,
		}
		if rt.Store != nil && rt.Dispatch != nil {
			answers, err := layout.DispatchAnswerCounts(ctx, rt.Store)
			if err != nil {
				return observability.NodeState{}, fmt.Errorf("read dispatch answers: %w", err)
			}
			for a, n := range answers {
				state.DispatchAnswers = append(state.DispatchAnswers, observability.DispatchAnswerRow{Builder: a.Builder, Answer: a.Answer, BuilderSide: a.BuilderSide, Count: n})
			}
		}
		if tasks == nil {
			return state, nil
		}
		records, err := tasks.ListActiveTasks(ctx)
		if err != nil {
			return observability.NodeState{}, fmt.Errorf("read task queue: %w", err)
		}
		for _, record := range records {
			state.TaskQueue = append(state.TaskQueue, observability.TaskQueueRow{Role: record.Role, Status: record.Status, AutoHalted: record.AutoHalted})
		}
		return state, nil
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
			if rec, ok, err := layout.DispatchScopeOwner(ctx, runtime.Store, layout.StoredHash(taskHash)); err != nil {
				return evidence.TaskCleanupStatus{}, err
			} else if ok {
				// A per-ticket evidence scope (S5 Q8) follows its task (S6 Q9).
				taskHash = codec.Hash(rec.TaskHash)
			}
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

type runtimeRunner func(context.Context) error

// outputStreamLimitsWarmRunner reads the governed stream limits once at
// startup. They are genesis-only and the Keeper client retains them, so this is
// the read the first task would have made, moved off the path between that
// task being admitted and its generation starting -- two sequential chain round
// trips, measured at 291ms on devnet.
//
// It never fails the daemon. A chain that is unreachable at boot is a state
// this node already recovers from, through the poller's retries and the
// readiness gate holding the workload back, and failing here would turn that
// into a node that refuses to come up. The limits stay lazily readable, so a
// warm that did not happen costs the first task exactly what it costs today.
//
// It also outlives its own work: the supervisor reads a runner returning while
// the daemon is still up as a component that died, and reports every runner
// having exited as a failure.
func outputStreamLimitsWarmRunner(keeper any) runtimeRunner {
	reader, ok := keeper.(chainclient.OutputStreamLimitsReader)
	if !ok || reader == nil {
		return nil
	}
	return func(ctx context.Context) error {
		if limits, err := reader.OutputStreamLimits(ctx); err != nil {
			observability.LogAtDepth(slog.LevelWarn, 1,
				"output stream limits were not read at startup, the first task will read them",
				slog.Any("error", err))
		} else {
			observability.LogAtDepth(slog.LevelInfo, 1, "output stream limits read at startup",
				slog.Uint64("min_output_stream_frame_bytes", uint64(limits.MinOutputStreamFrameBytes)),
				slog.Uint64("max_output_mmr_leaves", limits.MaxOutputMMRLeaves),
				slog.Uint64("snapshot_height", limits.SnapshotHeight))
		}
		<-ctx.Done()
		return nil
	}
}

func runtimeRunnersWithHealthAndTaskRunner(cfg config.Config, rt *daemon.Runtime, health *observability.Health, taskRunner *daemon.TaskRunner) ([]runtimeRunner, func(), error) {
	if rt == nil {
		return nil, func() {}, nil
	}
	var runners []runtimeRunner
	cleanup := func() {}
	poller := newKeeperPollerWithTaskRunner(cfg, rt, taskRunner)
	if poller != nil {
		runners = append(runners, poller.Run)
	}
	// Warmed alongside the poller rather than on its own, so a deployment with
	// no poller is not left with the warm as its only runner: one that returns
	// is the supervisor's signal that the runtime is finished.
	if poller != nil {
		if warm := outputStreamLimitsWarmRunner(rt.Dependencies.Keeper); warm != nil {
			runners = append(runners, warm)
		}
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
				return runRuntimeRunnerGroupWithStarted(ctx, workloadRunners(rt, taskRunner), started)
			},
		})
		runners = append(runners, controller.Run)
		return runners, cleanup, nil
	}

	legacyWorkload := workloadRunners(rt, taskRunner)
	// Without dynamic readiness the workload runners start unconditionally and
	// run for the process lifetime, so the workload is live from here on.
	if health != nil && len(legacyWorkload) > 0 {
		_ = health.SetDependency(observability.DependencyWorkload, true)
	}
	runners = append(runners, legacyWorkload...)
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

func workloadRunners(rt *daemon.Runtime, taskRunner *daemon.TaskRunner) []runtimeRunner {
	if rt == nil || taskRunner == nil {
		return nil
	}
	runners := []runtimeRunner{taskRunner.Run}
	if rt.Dispatch != nil {
		if plane := rt.Dispatch.Plane(); plane != nil {
			for _, run := range plane.Runners() {
				runners = append(runners, runtimeRunner(run))
			}
		}
	}
	return runners
}

func runRuntimeRunnerGroupWithStarted(ctx context.Context, runners []runtimeRunner, started func()) error {
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

	// The workload is reported as running unless a runner has already
	// returned: its exit happened first, whether or not its error has been
	// collected yet.
	if started != nil {
		select {
		case err := <-errCh:
			collect(err)
		default:
			if exited.Load() == 0 {
				started()
			}
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
	var verifierMemberReader daemon.VerifierMemberReader
	verifierMemberReader, _ = rt.Dependencies.Keeper.(daemon.VerifierMemberReader)
	if !fakeOutput {
		keeper, ok := rt.Dependencies.Keeper.(daemon.KeeperHandraiseReader)
		if ok {
			handraiseEligibility = daemon.NewKeeperHandraiseEligibility(daemon.KeeperHandraiseEligibilityConfig{
				ChainStatus: rt, Keeper: keeper, Model: rt.Dependencies.Model,
				ChainID: cfg.ChainID, OperatorAddress: cfg.LocalIdentity.OperatorAddress, ModelServiceID: cfg.LocalIdentity.ModelServiceID,
			})
		}
	}
	runnerCfg := daemon.TaskRunnerConfig{
		Store:                rt.Store,
		Evidence:             evidenceStore,
		Model:                rt.Dependencies.Model,
		Builder:              rt.Dependencies.Builder,
		OutputPackages:       rt.Dependencies.OutputPackages,
		OutputConfirmer:      rt.OutputConfirmer,
		EvidenceConfirmer:    rt.EvidenceConfirmer,
		VerifyCommitRelay:    rt.VerifyCommitRelay,
		Trace:                rt.TaskTrace(),
		FakeOutput:           fakeOutput,
		HandraiseEligibility: handraiseEligibility,
		Tx:                   taskTx,
		TxGasPayer:           rt.ServiceAddress,
		TxFeeCap:             txclient.Coin{Amount: cfg.Tx.MaxFeeAmount, Denom: cfg.Tx.FeeDenom},
		// taskTx above is read once, here, and on a dynamic-readiness node that
		// is before ActivateWorkload has run -- so it is nil for the whole
		// process on exactly the deployments that need it. The verifier commit
		// exit resolves the live client through this provider instead, the same
		// way ServiceIdentity resolves the live service address.
		TxProvider:           rt.WorkloadTxClient,
		CommitExitFeeCap:     txclient.Coin{Amount: cfg.CommitExitFeeCap(), Denom: cfg.Tx.FeeDenom},
		LocalWorkerAddress:   cfg.LocalIdentity.OperatorAddress,
		LocalVerifierAddress: cfg.LocalIdentity.OperatorAddress,
		ModelServiceID:       cfg.LocalIdentity.ModelServiceID,
		ChainID:              cfg.ChainID,
		SignerAddress:        rt.ServiceAddress,
		SignerKeyRef:         cfg.LocalIdentity.ServiceKeyRef,
		SignerPubkey:         rt.ServicePubkey,
		Signer:               signerForRuntime(rt),
		ServiceIdentity:      rt.WorkloadIdentity,
		MaxConcurrency:       cfg.ModelManagement.MaxConcurrency,
		PollInterval:         intervalFromMillis(cfg.Keeper.PollIntervalMS),
		RetryDelay:           intervalFromMillis(cfg.TaskExecution.RetryDelayMS),
		MaxRetryDelay:        intervalFromMillis(cfg.TaskExecution.MaxRetryDelayMS),
		ChainStatus:          rt,
		MaxRetryAttempts:     cfg.TaskExecution.MaxRetryAttempts,
		MaxOutputBytes:       cfg.TaskExecution.MaxOutputBytes,
		InputResolver:        rt.TaskInputResolver,
		TaskData:             rt.Dependencies.TaskData,
		TaskDataAuth:         rt.TaskDataAuth,
		ReceivingBuilder:     receivingBuilderProvider(rt),
		TaskFacts:            taskFactsReader(rt),
		VerifierMemberReader: verifierMemberReader,
		ProfileCapabilities:  profileCapabilities,
		ProfileReader:        profileReader,
		TaskReader:           taskReader,
		Diagnostic:           logTaskRunnerDiagnostic,
		OnQuarantinedEffect:  logQuarantinedKeeperEffect,
	}
	link := wireDispatchRunnerConfig(&runnerCfg, rt)
	runner := daemon.NewTaskRunner(runnerCfg)
	if link != nil {
		plane, err := newDispatchPlane(cfg, rt, runner, evidenceStore)
		if err != nil {
			return nil, err
		}
		link.Bind(plane)
	}
	return runner, nil
}

func newKeeperPollerWithTaskRunner(cfg config.Config, rt *daemon.Runtime, taskRunner *daemon.TaskRunner) *daemon.KeeperPoller {
	if !cfg.UsesRealDependencies() || rt == nil || rt.Store == nil || rt.Reconciler == nil || rt.KeeperEvents == nil {
		return nil
	}
	interval := time.Duration(cfg.Keeper.PollIntervalMS) * time.Millisecond
	poller := daemon.NewKeeperPoller(rt.Store, rt.KeeperEvents, rt.Reconciler, daemon.KeeperPollerConfig{
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
			return nil
		},
	})
	return poller
}

func logWorkloadStartFailure(err error) {
	observability.LogAtDepth(slog.LevelError, 1, "workload start failed, retrying on the next readiness tick", slog.Any("error", err))
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
	if rt.WorkloadTx != nil && cfg.Tx.Enabled && rt.TaskDataAuth != nil {
		registryConfig.SupportConfirmer = modelregistry.NewTxSupportConfirmer(rt.WorkloadTx, modelregistry.TxSupportConfirmerOptions{
			ChainID: cfg.ChainID, OperatorAddress: cfg.LocalIdentity.OperatorAddress,
			Signer: signingClient, ServiceKeyRef: cfg.LocalIdentity.ServiceKeyRef, ServiceAddress: rt.ServiceAddress,
			ServiceIdentity: func(ctx context.Context) (uint64, uint64, uint64, uint64, error) {
				nonce, height, err := rt.TaskDataAuth.CommittedServiceBinding(ctx)
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
