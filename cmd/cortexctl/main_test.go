package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/txclient"
)

func TestHelpReturnsSuccessAndListsCommands(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"--help"}, &stdout); err != nil {
		t.Fatalf("run(--help) error = %v", err)
	}
	for _, want := range []string{"model", "diagnostics", "evidence", "--admin-socket"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestBareCommandPrintsHelpAndFailsClosed(t *testing.T) {
	var stdout bytes.Buffer
	err := run(nil, &stdout)
	if err == nil || !strings.Contains(err.Error(), "subcommand is required") {
		t.Fatalf("run() error = %v, want subcommand-required error", err)
	}
	if !strings.Contains(stdout.String(), "Available Commands:") {
		t.Fatalf("bare command did not print help:\n%s", stdout.String())
	}
}

func TestUnknownNestedCommandFailsClosed(t *testing.T) {
	var stdout bytes.Buffer
	err := run([]string{"model", "manifest", "bogus"}, &stdout)
	if err == nil || !strings.Contains(err.Error(), `unknown command "bogus"`) {
		t.Fatalf("run(model manifest bogus) error = %v, want unknown-command error", err)
	}
}

func TestLegacySingleDashFlagsRemainAccepted(t *testing.T) {
	args := normalizeLegacyControlArgs([]string{
		"-admin-socket=/tmp/cortex.sock", "model", "manifest", "generate",
		"-format", "json", "-profile=profile.json", "-version", "v1",
		"-tokenizer", "tok", "-model-service", "svc", "-metadata", "owner=ops",
		"-manifest", "manifest.json", "-height", "7", "-dry-run", "-wait",
	})
	want := "--admin-socket=/tmp/cortex.sock model manifest generate --format json --profile=profile.json --version v1 --tokenizer tok --model-service svc --metadata owner=ops --manifest manifest.json --height 7 --dry-run --wait"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("normalized args = %q", got)
	}
}

func TestLegacySingleDashFormatExecutes(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"diagnostics", "-format", "json"}, &stdout); err != nil {
		t.Fatalf("run(diagnostics -format json) error = %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "{") {
		t.Fatalf("diagnostics output is not JSON: %s", stdout.String())
	}
}

func TestModelStatusUsesAdminSocketData(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"model", "status", "--format", "json", "--height", "77", "daemon-model"}, &stdout); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	out := stdout.String()
	for _, want := range []string{
		`"model_id": "daemon-model"`,
		`"chain_state": "REGISTERED"`,
		`"display_visibility": "VISIBLE"`,
		`"verification_label": "OFFICIAL"`,
		`"reward_state": "FEE_ONLY_NO_BLOCK_REWARD"`,
		`"support_state": "ACTIVE"`,
		`"risk":`,
		`"treasury":`,
		`"builder":`,
		`"emergency_freeze":`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %s missing %s", out, want)
		}
	}
}

func TestModelStatusJSONSeparatesProtocolDisplayVerificationAndRewardFields(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"model", "status", "--format", "json", "daemon-model"}, &stdout); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	var status map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("status JSON decode failed: %v\n%s", err, stdout.String())
	}

	want := map[string]string{
		"chain_state":        "REGISTERED",
		"display_visibility": "VISIBLE",
		"verification_label": "OFFICIAL",
		"reward_state":       "FEE_ONLY_NO_BLOCK_REWARD",
	}
	for field, value := range want {
		if got, ok := status[field].(string); !ok || got != value {
			t.Fatalf("%s = %#v, want %q", field, status[field], value)
		}
	}
	if status["chain_state"] == status["display_visibility"] || status["verification_label"] == status["reward_state"] {
		t.Fatalf("operator fields are collapsed instead of separated: %#v", status)
	}
}

func TestModelStatusTableIncludesOperatorProjectionFields(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"model", "status", "daemon-model"}, &stdout); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"last_p30_task_id",
		"p30_cutoff",
		"top10_cutoff",
		"mark_gate_open",
		"failure_risk_count",
		"treasury_balance",
		"hardware_tier_proof_role",
		"builder_missed_messages",
		"pending_task_fee",
		"claimable_task_fee",
		"task_finality_height",
		"claim_responsibility",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("model status table %q missing %q", out, want)
		}
	}
}

func TestModelListTableIncludesOperatorProjectionFields(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"model", "list"}, &stdout); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"support_state",
		"mark_gate_open",
		"treasury_balance",
		"builder_faulted_messages",
		"emergency_freeze_reason",
		"task_finality_height",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("model list table %q missing %q", out, want)
		}
	}
}

func TestTreasuryStatusAndCapabilityUseAdminSocket(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"treasury", "status", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("treasury status returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), `"destination": "trueopen1daemon"`) {
		t.Fatalf("treasury output = %s", stdout.String())
	}

	stdout.Reset()
	if err := run([]string{"capability", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("capability returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), `"model_registry": true`) || !strings.Contains(stdout.String(), `"challenge_verifier": false`) {
		t.Fatalf("capability output = %s", stdout.String())
	}
}

func TestDiagnosticsUsesAdminSocket(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"diagnostics", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("diagnostics returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		`"mode": "fake"`,
		`"model_transport": "fake"`,
		`"dependencies":`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("diagnostics output %s missing %s", out, want)
		}
	}
}

func TestEvidenceCleanupPrintsNonDestructivePlan(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"evidence", "cleanup", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("run evidence cleanup returned error: %v", err)
	}
	for _, want := range []string{`"current_height": 123`, `"retention_policy_version": "retention-v1"`, `"digest": "cleanup-plan-1"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("evidence cleanup output %q missing %q", stdout.String(), want)
		}
	}
}

func TestTaskRequeueUsesOwnerOnlyAdminSocket(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)
	var stdout bytes.Buffer
	if err := run([]string{"task", "requeue", "--format", "json", "--reason", "operator approved", "--retry-delay", "1s", "queue-failed"}, &stdout); err != nil {
		t.Fatalf("task requeue returned error: %v", err)
	}
	for _, want := range []string{`"queue_id": "queue-failed"`, `"status": "queued"`, `"retry_count": 2`, `"last_error": "operator approved"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("task requeue output %q missing %q", stdout.String(), want)
		}
	}
	stdout.Reset()
	if err := run([]string{"task", "requeue", "queue-failed"}, &stdout); err == nil || !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("task requeue missing reason error = %v", err)
	}
}

func TestManifestValidateReadsFileAndRejectsInvalidManifest(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"model_id":"missing-required-fields"}`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout bytes.Buffer
	if err := run([]string{"model", "manifest", "validate", "--manifest", path}, &stdout); err == nil {
		t.Fatalf("validate accepted invalid manifest, output = %s", stdout.String())
	}
}

func TestModelRegisterUsesAdminSocketAndReturnsRegistrationResult(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)
	manifestPath := writeTestManifest(t)

	var stdout bytes.Buffer
	err := run([]string{
		"model", "register",
		"--format", "json",
		"--manifest", manifestPath,
		"--dry-run",
	}, &stdout)
	if err != nil {
		t.Fatalf("register returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{`"dry_run": true`, `"status": "planned"`, `"registration_digest":`} {
		if !strings.Contains(out, want) {
			t.Fatalf("register output %s missing %s", out, want)
		}
	}
	for _, removed := range []string{`"material"`, `"tx_id"`, `"outbox_id"`} {
		if strings.Contains(out, removed) {
			t.Fatalf("register output %s still contains legacy field %s", out, removed)
		}
	}
}

func TestModelSelfTestUsesCurrentManifestProjection(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)
	manifestPath := writeTestManifest(t)

	var stdout bytes.Buffer
	if err := run([]string{"model", "self-test", "--manifest", manifestPath, "--format", "json"}, &stdout); err != nil {
		t.Fatalf("self-test returned error: %v", err)
	}
	for _, want := range []string{`"passed": true`, `"projection_validated": true`, `"profile_version": 1`} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("self-test output %s missing %s", stdout.String(), want)
		}
	}
}

func TestModelRegisterRejectsRemovedLegacyFlags(t *testing.T) {
	manifestPath := writeTestManifest(t)
	for _, legacyFlag := range []string{
		"--model-registration-fee=10000000",
		"--profile-registration-fee=10000000",
		"--wait=true",
		"--height=100",
		"--mode=direct",
		"--quote-expiry-height=120",
		"--fee-denom=utrueopen",
		"--treasury=trueopen1daemon",
		"--fee-amount=10000000",
		"--gas-limit=50",
	} {
		t.Run(strings.TrimPrefix(strings.SplitN(legacyFlag, "=", 2)[0], "--"), func(t *testing.T) {
			var stdout bytes.Buffer
			err := run([]string{"model", "register", "--manifest", manifestPath, legacyFlag}, &stdout)
			if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("run with %s error = %v, want undefined flag", legacyFlag, err)
			}
		})
	}
}

func TestModelManifestGenerateAcceptsCurrentProjectionFile(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)
	profilePath := writeCurrentProfile(t)

	var stdout bytes.Buffer
	err := run([]string{
		"model", "manifest", "generate", "--format", "json",
		"--profile", profilePath,
		"--version", "2026-07-28",
		"--tokenizer", "tiktoken-cl100k",
		"--model-service", "modelsvc-local",
		"--metadata", "environment=devnet",
	}, &stdout)
	if err != nil {
		t.Fatalf("manifest generate returned error: %v", err)
	}
	for _, want := range []string{
		`"manifest_schema_version": 3`,
		`"model_id": "daemon-model"`,
		`"runtime_class": "CAUSAL_LM_PREFILL_LOGPROBS_V1"`,
		`"registration_fee"`,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("manifest output %s missing %s", stdout.String(), want)
		}
	}
}

func TestSupportProducesOperatorOnlyIntentWithoutMutatingDaemonState(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"model", "support", "--format", "json", "unsupported-model"}, &stdout); err != nil {
		t.Fatalf("support intent returned error: %v", err)
	}
	for _, want := range []string{
		`"type_url": "/hub.v1.MsgDeclareModelSupport"`,
		`"operator_address": "trueopen1operator"`,
		`"profile_version": 1`,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("support intent %s missing %s", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "support_signature") || strings.Contains(stdout.String(), "service_signature") {
		t.Fatalf("operator-only intent contains a detached signature: %s", stdout.String())
	}

	stdout.Reset()
	if err := run([]string{"model", "status", "--format", "json", "unsupported-model"}, &stdout); err != nil {
		t.Fatalf("status returned error: %v", err)
	}
	if strings.Contains(stdout.String(), `"support_active": true`) {
		t.Fatalf("intent preparation mutated support state: %s", stdout.String())
	}
}

func TestEarningsStatusIsReadOnlyWalletSDKView(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"earnings", "status", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("earnings status returned error: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{`"read_only": true`, `"claim_responsibility": "wallet/SDK"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("earnings output %s missing %s", out, want)
		}
	}
}

func startTestAdminServer(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ctxctl-*")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll returned error: %v", err)
		}
	})
	socketPath := filepath.Join(dir, "cortex.sock")
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{})
	registry = modelregistry.NewRegistry(modelregistry.RegistryConfig{
		CurrentRegistrationReader: cliRegistrationReader{},
		ChainID:                   "trueopen-devnet-1",
		ProposerAddress:           "trueopen1operator",
		RegistrationReader:        cliRegistrationReader{},
		RegistrationSponsor:       "trueopen1operator",
		NowHeight:                 func() (uint64, error) { return 100, nil },
		Treasury:                  "trueopen1daemon",
		FeeDenom:                  "utrueopen",
		SelfTester:                passingSelfTest,
		Signer:                    fixedSigner,
		FeeGrant:                  modelregistry.StaticFeeGrant{Granter: "operator", Amount: 500, GasLimit: 50},
		MinGasGrant:               50,
		SupporterAddress:          "trueopen1operator",
		InferenceCapability:       true,
		VerificationCapability:    true,
	})
	registry.PutStatus(modelregistry.ModelStatus{
		ModelID:           "daemon-model",
		ChainState:        modelregistry.ChainStateRegistered,
		DisplayVisibility: modelregistry.DisplayVisible,
		VerificationLabel: modelregistry.VerificationOfficial,
		RewardState:       modelregistry.RewardEligibleIfMarked,
		Supported:         true,
	})
	registry.PutStatus(modelregistry.ModelStatus{
		ModelID:           "unsupported-model",
		ProfileVersion:    "1",
		ChainState:        modelregistry.ChainStateRegistered,
		DisplayVisibility: modelregistry.DisplayVisible,
		VerificationLabel: modelregistry.VerificationOfficial,
		RewardState:       modelregistry.RewardEligibleIfMarked,
	})
	server := adminapi.NewServer(socketPath, adminapi.New(adminapi.ServiceConfig{
		ModelRegistry:  registry,
		TreasuryStatus: adminapi.TreasuryStatus{Destination: "trueopen1daemon", Denom: "utrueopen", Balance: 42},
		Capability:     adminapi.Capability{ModelRegistry: true, ChallengeVerifier: false},
		Diagnostics: diagnostics.Diagnostics{
			Mode:           "fake",
			ModelTransport: "fake",
			Dependencies: []diagnostics.DependencyStatus{{
				Name:       "model_service",
				Endpoint:   "fake://model-management",
				Configured: true,
				Ready:      true,
			}},
		},
		EvidenceCleanupPlan: func(context.Context) (evidence.CleanupPlan, error) {
			return evidence.CleanupPlan{CurrentHeight: 123, RetentionPolicyVersion: "retention-v1", Digest: "cleanup-plan-1"}, nil
		},
		TaskSettlement: func(_ context.Context, req adminapi.TaskSettlementRequest) (adminapi.TaskSettlementResponse, error) {
			if strings.HasPrefix(req.TaskID, "cd") {
				return adminapi.TaskSettlementResponse{TaskID: req.TaskID, Submitted: true, Status: "INCLUDED", TxHash: "settlement-pending", IncludedHeight: 100, Error: "Keeper confirmation unavailable"}, nil
			}
			return adminapi.TaskSettlementResponse{TaskID: req.TaskID, Submitted: true, Confirmed: true, Status: "KEEPER_CONFIRMED", TxHash: "settlement-tx", IncludedHeight: 100}, nil
		},
		TaskQueueRequeue: func(_ context.Context, req adminapi.TaskQueueRequeueRequest) (adminapi.TaskQueueRequeueResponse, error) {
			return adminapi.TaskQueueRequeueResponse{QueueID: req.QueueID, TaskID: "task-1", Status: "queued", RetryCount: 2, RetryAt: "2099-01-01T00:00:00Z", LastError: req.Reason}, nil
		},
		TaskQueueList: func(_ context.Context, req adminapi.TaskQueueListRequest) (adminapi.TaskQueueListResponse, error) {
			if req.Status == "empty" {
				return adminapi.TaskQueueListResponse{}, nil
			}
			return adminapi.TaskQueueListResponse{Rows: []adminapi.TaskQueueRow{{
				QueueID: "queue-failed", TaskID: "task-1", Role: "worker", Stage: "infer",
				Status: "failed", RetryCount: 4828, DueHeight: 53235,
				LastError: "Nexus assign payload for task-1 is not available",
			}}}, nil
		},
	}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})
	return socketPath
}

type cliRegistrationReader struct{}

func (cliRegistrationReader) Params(context.Context) (chainclient.ParamsSnapshot, error) {
	return chainclient.ParamsSnapshot{}, nil
}

func (cliRegistrationReader) Model(context.Context, string) (chainclient.ModelSnapshot, error) {
	return chainclient.ModelSnapshot{}, chainclient.ErrNotFound
}

func (cliRegistrationReader) Profile(context.Context, string, string) (chainclient.ProfileSnapshot, error) {
	return chainclient.ProfileSnapshot{}, chainclient.ErrNotFound
}

func (cliRegistrationReader) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return chainclient.CurrentModelProfileSnapshot{}, chainclient.ErrNotFound
}

func writeTestManifest(t *testing.T) string {
	t.Helper()
	manifest, err := modelregistry.GenerateCurrentManifest(modelregistry.CurrentManifestInput{
		Version: "2026-08-03", Tokenizer: "qwen-tokenizer", ModelServiceID: "modelsvc-local", Profile: currentTestProfile(),
	})
	if err != nil {
		t.Fatalf("GenerateCurrentManifest returned error: %v", err)
	}
	bytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}

func writeCurrentProfile(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(currentTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func currentTestProfile() txclient.ModelProfileProjectionMessage {
	hash := txclient.ProtoBytes32(strings.Repeat("ab", 32))
	return txclient.ModelProfileProjectionMessage{ModelID: "daemon-model", ProfileVersion: 1, ManifestHash: hash, TokenizerHash: hash,
		RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1", RequiredTopK: 20, TaskTypes: []string{"TASK_TYPE_CHAT"}, GenerationType: "GENERATION_TYPE_SAMPLED",
		ResourceTier: 2, MinStake: txclient.CoinMessage{Denom: "utrueopen", Amount: 1_000_000}, ChallengeOpenWindowBlocks: 1_800,
		VerificationProfile: txclient.VerificationProfileMessage{VerificationProfileID: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", VerificationMode: "VERIFICATION_MODE_SINGLE_SAMPLE", TokenScope: "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
			Metrics: txclient.MetricSpecMessage{CompareLogprobDiff: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6"}, CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: hash, MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1", EvidenceSchema: txclient.WorkerValueEvidenceSchemaV2(1 << 30)},
		PricingProfile:          txclient.PricingProfileMessage{InitialOutputPrice: 10, VerifyRatioBPS: 1_000, MinOrderValue: 1_000},
		TimeoutBootstrapProfile: txclient.TimeoutBootstrapProfileMessage{InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50, CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000},
		SchemaHash:              hash, RegistrationFee: txclient.CoinMessage{Denom: "utrueopen", Amount: 10_000_000}}
}

func passingSelfTest(_ context.Context, manifest modelregistry.Manifest) (modelregistry.SelfTestResult, error) {
	return modelregistry.SelfTestResult{
		Passed: true,
		RegistrationMaterial: &modelregistry.RegistrationMaterial{
			ManifestHash: manifest.Hash,
		},
	}, nil
}

func fixedSigner(_ context.Context, material modelregistry.RegistrationMaterial) (string, error) {
	return "signed:" + material.ManifestHash, nil
}

// Task requeue takes a queue_id; the list command is the supported way for an
// operator to discover active execution identifiers.
func TestTaskListPrintsQueueIDsRequeueAccepts(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"task", "list", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("task list returned error: %v", err)
	}
	for _, want := range []string{
		`"queue_id": "queue-failed"`,
		`"retry_count": 4828`,
		`"due_height": 53235`,
		`"last_error": "Nexus assign payload for task-1 is not available"`,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("task list output %q missing %q", stdout.String(), want)
		}
	}

	// The identifier must be usable verbatim; the two commands are only a recovery
	// path together.
	var listed struct {
		Rows []struct {
			QueueID string `json:"queue_id"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil {
		t.Fatalf("Unmarshal task list output: %v", err)
	}
	if len(listed.Rows) != 1 {
		t.Fatalf("task list rows = %d, want 1", len(listed.Rows))
	}
	stdout.Reset()
	if err := run([]string{"task", "requeue", "--format", "json", "--reason", "pre-reset chain", listed.Rows[0].QueueID}, &stdout); err != nil {
		t.Fatalf("task requeue with listed queue id returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), `"queue_id": "queue-failed"`) {
		t.Fatalf("task requeue output %q did not act on the listed queue id", stdout.String())
	}
}

func TestTaskListRendersTableHeaderAndRejectsNegativeLimit(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"task", "list"}, &stdout); err != nil {
		t.Fatalf("task list returned error: %v", err)
	}
	for _, want := range []string{"queue_id\ttask_id\trole\tstage\tstatus", "queue-failed", "4828"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("task list table %q missing %q", stdout.String(), want)
		}
	}

	stdout.Reset()
	if err := run([]string{"task", "list", "--limit", "-1"}, &stdout); err == nil || !strings.Contains(err.Error(), "--limit") {
		t.Fatalf("task list negative limit error = %v", err)
	}
}

// An empty queue is the answer to the question, not a failure.
func TestTaskListReportsEmptyQueueWithoutError(t *testing.T) {
	socketPath := startTestAdminServer(t)
	t.Setenv("CORTEX_ADMIN_SOCKET", socketPath)

	var stdout bytes.Buffer
	if err := run([]string{"task", "list", "--status", "empty", "--format", "json"}, &stdout); err != nil {
		t.Fatalf("task list on empty queue returned error: %v", err)
	}
	if strings.Contains(stdout.String(), "queue-failed") {
		t.Fatalf("task list output %q, want no rows", stdout.String())
	}
}
