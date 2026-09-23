package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/observability/logtest"
	"github.com/TrueOpen/cortex/internal/txclient"
)

func TestAdminAPIDelegatesModelCommandsTreasuryAndCapability(t *testing.T) {
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{
		NowHeight:              func() (uint64, error) { return 100, nil },
		Treasury:               "trueopen1treasury",
		FeeDenom:               "utrueopen",
		SupporterAddress:       "trueopen1operator",
		InferenceCapability:    true,
		VerificationCapability: true,
		SelfTester: modelregistry.SelfTestFunc(func(_ context.Context, manifest modelregistry.Manifest) (modelregistry.SelfTestResult, error) {
			return modelregistry.SelfTestResult{
				Passed: true,
				RegistrationMaterial: &modelregistry.RegistrationMaterial{
					ManifestHash: manifest.Hash,
				},
			}, nil
		}),
		Signer: func(_ context.Context, material modelregistry.RegistrationMaterial) (string, error) {
			return strings.Repeat("ab", 64), nil
		},
		FeeGrant: modelregistry.StaticFeeGrant{Granter: "operator", Amount: 500, GasLimit: 50},
	})
	registry.PutStatus(modelregistry.ModelStatus{
		ModelID:           "llama-text-8b",
		ManifestHash:      "hash-1",
		ChainState:        "registered",
		DisplayVisibility: "public",
		VerificationLabel: "trace verified",
		RewardState:       "eligible",
	})
	api := New(ServiceConfig{
		ModelRegistry:  registry,
		TreasuryStatus: TreasuryStatus{Destination: "trueopen1treasury", Denom: "utrueopen", Balance: 1000},
		Capability:     Capability{ModelRegistry: true, ChallengeVerifier: false},
	})

	manifest, err := api.ModelManifestGenerate(context.Background(), modelregistry.ManifestInput{
		ModelID:        "llama-text-8b",
		Version:        "2026-07-08",
		Digest:         "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Tokenizer:      "tiktoken-cl100k",
		ModelServiceID: "modelsvc-local",
		Verification: modelregistry.VerificationSpec{
			Method:         "trace_sample_v1",
			ProfileVersion: "profile-v1",
		},
		Pricing:       modelregistry.PricingSpec{Denom: "utrueopen", PromptUnitPrice: 1, CompletionUnitPrice: 2},
		TokenizerHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RuntimeVersion: "runtime-v1",
		RuntimeHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", QuantHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		HardwareTierFloor: 1, ResourceTier: "3",
		MinStake: 500000, ChallengeOpenWindowBlocks: 100, EpsilonParams: "epsilon-v1", TimeoutBootstrapProfile: "timeout-v1",
		SchemaHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MetadataHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	})
	if err != nil {
		t.Fatalf("ModelManifestGenerate returned error: %v", err)
	}
	if err := api.ModelManifestValidate(context.Background(), manifest); err != nil {
		t.Fatalf("ModelManifestValidate returned error: %v", err)
	}
	if material, err := api.ModelSelfTest(context.Background(), manifest); err != nil || material.ManifestHash != manifest.Hash {
		t.Fatalf("ModelSelfTest material = %#v, err = %v", material, err)
	}
	if _, err := api.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest: manifest,
		Quote: modelregistry.FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             modelregistry.FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		DryRun: true,
	}); err != nil {
		t.Fatalf("ModelRegister dry-run returned error: %v", err)
	}
	if _, err := api.ModelStatus(context.Background(), modelregistry.StatusRequest{ModelID: "llama-text-8b"}); err != nil {
		t.Fatalf("ModelStatus returned error: %v", err)
	}
	if _, err := api.ModelList(context.Background(), modelregistry.ListRequest{}); err != nil {
		t.Fatalf("ModelList returned error: %v", err)
	}
	if _, err := api.ModelShow(context.Background(), modelregistry.ShowRequest{ModelID: "llama-text-8b"}); err != nil {
		t.Fatalf("ModelShow returned error: %v", err)
	}
	if _, err := api.ModelSupport(context.Background(), modelregistry.SupportRequest{ModelID: "llama-text-8b", ProfileVersion: "1", Supported: true}); err != nil {
		t.Fatalf("ModelSupport returned error: %v", err)
	}
	if _, err := api.ModelDailySupport(context.Background(), modelregistry.DailySupportRequest{ModelID: "llama-text-8b", Enabled: true}); err != nil {
		t.Fatalf("ModelDailySupport returned error: %v", err)
	}
	if got := api.TreasuryStatus(context.Background()); got.Destination != "trueopen1treasury" || got.Denom != "utrueopen" {
		t.Fatalf("TreasuryStatus = %#v", got)
	}
	if got := api.Capability(context.Background()); !got.ModelRegistry || got.ChallengeVerifier {
		t.Fatalf("Capability = %#v", got)
	}
}

func TestModelRegisterClientUsesStableRequestAndResponseContract(t *testing.T) {
	manifest := modelregistry.Manifest{ModelID: "llama-text-8b", Hash: "manifest-hash"}
	var requestBody []byte
	client := &Client{
		socketPath: "contract-test",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var err error
			requestBody, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"manifest_hash":"manifest-hash",
					"model":{"status":"planned"},
					"profile":{"status":"planned"},
					"dry_run":true
				}`)),
			}, nil
		})},
	}

	result, err := client.ModelRegister(context.Background(), modelregistry.RegisterRequest{
		Manifest:               manifest,
		ModelRegistrationFee:   10_000_000,
		ProfileRegistrationFee: 12_000_000,
		DryRun:                 true,
	})
	if err != nil {
		t.Fatalf("ModelRegister returned error: %v", err)
	}
	if !result.DryRun || result.ModelStage.Status != modelregistry.RegistrationStagePlanned || result.ProfileStage.Status != modelregistry.RegistrationStagePlanned {
		t.Fatalf("ModelRegister result = %#v", result)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(requestBody, &payload); err != nil {
		t.Fatalf("request JSON decode failed: %v", err)
	}
	for _, key := range []string{"manifest", "model_registration_fee", "profile_registration_fee", "dry_run"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("request JSON %s missing %q", requestBody, key)
		}
	}
	if string(payload["model_registration_fee"]) != "10000000" || string(payload["profile_registration_fee"]) != "12000000" || string(payload["dry_run"]) != "true" {
		t.Fatalf("request JSON has wrong registration values: %s", requestBody)
	}
	for _, key := range []string{"Manifest", "DryRun", "Quote", "Mode", "Wait", "quote", "mode", "wait"} {
		if _, ok := payload[key]; ok {
			t.Fatalf("request JSON %s contains legacy/unstable field %q", requestBody, key)
		}
	}
}

func TestCurrentModelRegisterClientUsesAtomicWireContract(t *testing.T) {
	manifest := currentAdminManifest(t)
	var requestBody []byte
	var requestPath string
	client := &Client{
		socketPath: "contract-test",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestPath = req.URL.Path
			var err error
			requestBody, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{
				"manifest_hash":"manifest-v3","registration_digest":"digest-1","status":"planned","dry_run":true
			}`))}, nil
		})},
	}

	result, err := client.CurrentModelRegister(context.Background(), modelregistry.CurrentRegisterRequest{Manifest: manifest, DryRun: true})
	if err != nil || !result.DryRun || result.Status != modelregistry.RegistrationStagePlanned || requestPath != "/v1/model/register" {
		t.Fatalf("CurrentModelRegister = %#v, %v; path %q", result, err, requestPath)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(requestBody, &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"manifest", "dry_run"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("request JSON %s missing %q", requestBody, key)
		}
	}
	for _, legacy := range []string{"model_registration_fee", "profile_registration_fee", "quote", "mode", "wait"} {
		if _, ok := payload[legacy]; ok {
			t.Fatalf("request JSON %s contains legacy field %q", requestBody, legacy)
		}
	}
}

func TestStandardModelRegisterEndpointAcceptsV3AndRejectsLegacyV2(t *testing.T) {
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{
		CurrentRegistrationReader: currentAdminReader{}, ChainID: "trueopen-devnet-1", ProposerAddress: "trueopen1operator",
	})
	server := &Server{service: New(ServiceConfig{ModelRegistry: registry})}
	mux := http.NewServeMux()
	server.registerRoutes(mux)

	manifest := currentAdminManifest(t)
	currentPayload, err := json.Marshal(modelregistry.CurrentRegisterRequest{Manifest: manifest, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	currentRecorder := httptest.NewRecorder()
	mux.ServeHTTP(currentRecorder, httptest.NewRequest(http.MethodPost, "/v1/model/register", strings.NewReader(string(currentPayload))))
	if currentRecorder.Code != http.StatusOK || !strings.Contains(currentRecorder.Body.String(), `"status":"planned"`) {
		t.Fatalf("current registration response = %d %s", currentRecorder.Code, currentRecorder.Body.String())
	}

	legacyPayload := `{"manifest":{"manifest_schema_version":2,"model_id":"legacy-model"},"model_registration_fee":10000000,"profile_registration_fee":10000000,"dry_run":true}`
	legacyRecorder := httptest.NewRecorder()
	mux.ServeHTTP(legacyRecorder, httptest.NewRequest(http.MethodPost, "/v1/model/register", strings.NewReader(legacyPayload)))
	if legacyRecorder.Code != http.StatusBadRequest || !strings.Contains(legacyRecorder.Body.String(), "unknown field") {
		t.Fatalf("legacy registration response = %d %s", legacyRecorder.Code, legacyRecorder.Body.String())
	}
}

type currentAdminReader struct{}

func (currentAdminReader) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return chainclient.CurrentModelProfileSnapshot{}, chainclient.ErrNotFound
}

func currentAdminManifest(t testing.TB) modelregistry.CurrentManifest {
	t.Helper()
	hash := txclient.ProtoBytes32(strings.Repeat("ab", 32))
	manifest, err := modelregistry.GenerateCurrentManifest(modelregistry.CurrentManifestInput{
		Version: "2026-08-03", Tokenizer: "qwen-tokenizer", ModelServiceID: "modelsvc-local",
		Profile: txclient.ModelProfileProjectionMessage{ModelID: "daemon-model", ProfileVersion: 1, ManifestHash: hash, TokenizerHash: hash,
			RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1", RequiredTopK: 20, TaskTypes: []string{"TASK_TYPE_CHAT"}, GenerationType: "GENERATION_TYPE_SAMPLED",
			ResourceTier: 2, MinStake: txclient.CoinMessage{Denom: "utrueopen", Amount: 1_000_000}, ChallengeOpenWindowBlocks: 1_800,
			VerificationProfile: txclient.VerificationProfileMessage{VerificationProfileID: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", VerificationMode: "VERIFICATION_MODE_SINGLE_SAMPLE", TokenScope: "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				Metrics: txclient.MetricSpecMessage{CompareLogprobDiff: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6"}, CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: hash, MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1", EvidenceSchema: txclient.WorkerValueEvidenceSchemaV2(1 << 30)},
			PricingProfile:          txclient.PricingProfileMessage{InitialOutputPrice: 10, VerifyRatioBPS: 1_000, MinOrderValue: 1_000},
			TimeoutBootstrapProfile: txclient.TimeoutBootstrapProfileMessage{InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50, CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000},
			SchemaHash:              hash, RegistrationFee: txclient.CoinMessage{Denom: "utrueopen", Amount: 10_000_000}},
	})
	if err != nil {
		t.Fatalf("GenerateCurrentManifest: %v", err)
	}
	return manifest
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestOwnerOnlySocketPermissionCheck(t *testing.T) {
	dir := shortTempDir(t)
	socketPath := filepath.Join(dir, "cortex.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer ln.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	if err := EnsureOwnerOnlySocket(socketPath); err != nil {
		t.Fatalf("EnsureOwnerOnlySocket owner-only returned error: %v", err)
	}

	openPath := filepath.Join(dir, "open.sock")
	openLn, err := net.Listen("unix", openPath)
	if err != nil {
		t.Fatalf("Listen open returned error: %v", err)
	}
	defer openLn.Close()
	if err := os.Chmod(openPath, 0o666); err != nil {
		t.Fatalf("Chmod open returned error: %v", err)
	}
	if err := EnsureOwnerOnlySocket(openPath); !errors.Is(err, ErrInsecureSocketPermissions) {
		t.Fatalf("EnsureOwnerOnlySocket open error = %v, want %v", err, ErrInsecureSocketPermissions)
	}

	regularPath := filepath.Join(dir, "regular.sock")
	if err := os.WriteFile(regularPath, []byte("regular"), 0o600); err != nil {
		t.Fatalf("WriteFile regular returned error: %v", err)
	}
	if err := EnsureOwnerOnlySocket(regularPath); !errors.Is(err, ErrInsecureSocketPermissions) {
		t.Fatalf("EnsureOwnerOnlySocket regular error = %v, want %v", err, ErrInsecureSocketPermissions)
	}

	linkPath := filepath.Join(dir, "link.sock")
	if err := os.Symlink(socketPath, linkPath); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	if err := EnsureOwnerOnlySocket(linkPath); !errors.Is(err, ErrInsecureSocketPermissions) {
		t.Fatalf("EnsureOwnerOnlySocket symlink error = %v, want %v", err, ErrInsecureSocketPermissions)
	}
}

func TestUnixSocketClientRoutesModelStatusTreasuryAndCapability(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "cortex.sock")
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{})
	registry.PutStatus(modelregistry.ModelStatus{
		ModelID:           "daemon-model",
		ChainState:        "registered",
		DisplayVisibility: "public",
		VerificationLabel: "official",
		RewardState:       "eligible",
	})
	server := NewServer(socketPath, New(ServiceConfig{
		ModelRegistry:  registry,
		TreasuryStatus: TreasuryStatus{Destination: "trueopen1daemon", Denom: "utrueopen", Balance: 42},
		Capability:     Capability{ModelRegistry: true, ChallengeVerifier: false},
	}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	client := NewClient(socketPath)
	status, err := client.ModelStatus(context.Background(), modelregistry.StatusRequest{ModelID: "daemon-model", Height: 77})
	if err != nil {
		t.Fatalf("ModelStatus returned error: %v", err)
	}
	if status.ChainState != "registered" || status.DisplayVisibility != "public" || status.VerificationLabel != "official" || status.RewardState != "eligible" {
		t.Fatalf("ModelStatus = %#v", status)
	}
	treasury, err := client.TreasuryStatus(context.Background())
	if err != nil {
		t.Fatalf("TreasuryStatus returned error: %v", err)
	}
	if treasury.Destination != "trueopen1daemon" || treasury.Balance != 42 {
		t.Fatalf("TreasuryStatus = %#v", treasury)
	}
	capability, err := client.Capability(context.Background())
	if err != nil {
		t.Fatalf("Capability returned error: %v", err)
	}
	if !capability.ModelRegistry || capability.ChallengeVerifier {
		t.Fatalf("Capability = %#v", capability)
	}
}

func TestServerHTTPErrorLogUsesErrorLevelAndSource(t *testing.T) {
	var logged bytes.Buffer
	logtest.Install(t, observability.NewTextLogger(&logged), log.Default())
	server := NewServer(filepath.Join(shortTempDir(t), "cortex.sock"), New(ServiceConfig{}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if server.server == nil || server.server.ErrorLog == nil {
		t.Fatal("admin HTTP server ErrorLog is nil")
	}

	server.server.ErrorLog.Print("admin HTTP server failure")
	line := logged.String()
	for _, want := range []string{"level=ERROR", "source=internal/adminapi/admin_test.go:", `msg="admin HTTP server failure"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("admin HTTP error log %q missing %q", line, want)
		}
	}
}

func TestUnixSocketClientRoutesProjectedModelStatus(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "cortex.sock")
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{})
	registry.PutStatus(modelregistry.ModelStatus{
		ModelID:             "projected-model",
		ManifestHash:        "manifest-1",
		ChainState:          modelregistry.ChainStateRegistered,
		DisplayVisibility:   modelregistry.DisplayVisible,
		VerificationLabel:   modelregistry.VerificationOfficial,
		RewardState:         modelregistry.RewardEligibleIfMarked,
		Supported:           true,
		DailySupportEnabled: true,
	})
	server := NewServer(socketPath, New(ServiceConfig{
		ModelRegistry: registry,
	}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	client := NewClient(socketPath)
	status, err := client.ModelStatusProjection(context.Background(), modelregistry.StatusRequest{ModelID: "projected-model"})
	if err != nil {
		t.Fatalf("ModelStatusProjection returned error: %v", err)
	}
	if status.RewardState != modelregistry.RewardFeeOnlyNoBlockReward || status.Support.SupportState != modelregistry.SupportActive {
		t.Fatalf("ModelStatusProjection = %#v", status)
	}
	if status.Risk.Counts == nil {
		t.Fatalf("ModelStatusProjection missing risk counts map: %#v", status)
	}
}

func TestAdminAPIDiagnostics(t *testing.T) {
	report := diagnostics.Diagnostics{
		Mode:           "real",
		ModelTransport: "grpc",
		KeeperEndpoint: "https://keeper.devnet.trueopen.xyz",
		NexusIngress:   "https://nexus.devnet.trueopen.xyz",
		NexusNATS:      "tls://nexus.devnet.trueopen.xyz:4222",
		Dependencies: []diagnostics.DependencyStatus{{
			Name:       "keeper",
			Endpoint:   "https://keeper.devnet.trueopen.xyz",
			Configured: true,
			Ready:      true,
		}},
	}
	api := New(ServiceConfig{Diagnostics: report})

	got := api.Diagnostics(context.Background())
	if got.Mode != "real" || got.KeeperEndpoint != report.KeeperEndpoint {
		t.Fatalf("Diagnostics = %#v", got)
	}
}

func TestAdminAPIDiagnosticsUsesLiveProvider(t *testing.T) {
	startup := diagnostics.Diagnostics{Dependencies: []diagnostics.DependencyStatus{{Name: "model_service", Ready: true}}}
	live := diagnostics.Diagnostics{Dependencies: []diagnostics.DependencyStatus{{Name: "model_service", Ready: false, Error: "unhealthy"}}}
	api := New(ServiceConfig{
		Diagnostics: startup,
		DiagnosticsProvider: func(context.Context) diagnostics.Diagnostics {
			return live
		},
	})

	got := api.Diagnostics(context.Background())
	status, ok := got.Dependency("model_service")
	if !ok || status.Ready || status.Error != "unhealthy" {
		t.Fatalf("live diagnostics = %#v", got)
	}
}

func TestUnixSocketClientRoutesDiagnostics(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "cortex.sock")
	report := diagnostics.Diagnostics{
		Mode:           "real",
		ModelTransport: "grpc",
		KeeperEndpoint: "https://keeper.devnet.trueopen.xyz",
		Dependencies: []diagnostics.DependencyStatus{{
			Name:       "model_service",
			Endpoint:   "127.0.0.1:9090",
			Configured: true,
			Ready:      false,
			Error:      "model transport is required",
		}},
	}
	server := NewServer(socketPath, New(ServiceConfig{
		Diagnostics: report,
		EvidenceCleanupPlan: func(context.Context) (evidence.CleanupPlan, error) {
			return evidence.CleanupPlan{CurrentHeight: 123, RetentionPolicyVersion: "retention-v1", Digest: "plan-1"}, nil
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

	client := NewClient(socketPath)
	got, err := client.Diagnostics(context.Background())
	if err != nil {
		t.Fatalf("Diagnostics returned error: %v", err)
	}
	if got.Mode != "real" || got.Dependencies[0].Error != "model transport is required" {
		t.Fatalf("Diagnostics = %#v", got)
	}
	plan, err := client.EvidenceCleanupPlan(context.Background())
	if err != nil {
		t.Fatalf("EvidenceCleanupPlan returned error: %v", err)
	}
	if plan.CurrentHeight != 123 || plan.Digest != "plan-1" {
		t.Fatalf("EvidenceCleanupPlan = %#v", plan)
	}
}

func TestEvidenceCleanupPlanFailsClosedWithoutPlanner(t *testing.T) {
	if _, err := New(ServiceConfig{}).EvidenceCleanupPlan(context.Background()); err == nil {
		t.Fatal("EvidenceCleanupPlan accepted missing planner")
	}
}

func TestTaskQueueRequeueValidatesOperatorRequestAndAvailability(t *testing.T) {
	ctx := context.Background()
	if _, err := New(ServiceConfig{}).TaskQueueRequeue(ctx, TaskQueueRequeueRequest{QueueID: "queue-1", Reason: "retry"}); err == nil {
		t.Fatal("TaskQueueRequeue accepted unavailable production handler")
	}
	var got TaskQueueRequeueRequest
	api := New(ServiceConfig{TaskQueueRequeue: func(_ context.Context, req TaskQueueRequeueRequest) (TaskQueueRequeueResponse, error) {
		got = req
		return TaskQueueRequeueResponse{QueueID: req.QueueID, TaskID: "task-1", Status: "queued", RetryCount: 2, LastError: req.Reason}, nil
	}})
	for _, req := range []TaskQueueRequeueRequest{{Reason: "reason"}, {QueueID: "queue-1"}} {
		if _, err := api.TaskQueueRequeue(ctx, req); err == nil {
			t.Fatalf("TaskQueueRequeue accepted invalid request %#v", req)
		}
	}
	response, err := api.TaskQueueRequeue(ctx, TaskQueueRequeueRequest{QueueID: " queue-1 ", Reason: " operator approved ", RetryDelayMS: 1000})
	if err != nil || response.Status != "queued" || got.QueueID != "queue-1" || got.Reason != "operator approved" {
		t.Fatalf("TaskQueueRequeue response=%#v request=%#v err=%v", response, got, err)
	}
}

func TestUnixSocketClientRoutesTaskQueueRequeue(t *testing.T) {
	socketPath := filepath.Join(shortTempDir(t), "cortex.sock")
	server := NewServer(socketPath, New(ServiceConfig{TaskQueueRequeue: func(_ context.Context, req TaskQueueRequeueRequest) (TaskQueueRequeueResponse, error) {
		return TaskQueueRequeueResponse{QueueID: req.QueueID, TaskID: "task-1", Status: "queued", RetryCount: 3, RetryAt: "2099-01-01T00:00:00Z", LastError: req.Reason}, nil
	}}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	response, err := NewClient(socketPath).TaskQueueRequeue(context.Background(), TaskQueueRequeueRequest{QueueID: "queue-1", Reason: "manual recovery"})
	if err != nil || response.QueueID != "queue-1" || response.Status != "queued" || response.RetryCount != 3 {
		t.Fatalf("TaskQueueRequeue response=%#v err=%v", response, err)
	}
}

func TestServerStartDoesNotRemoveDirectoryAtSocketPath(t *testing.T) {
	dir := shortTempDir(t)
	nested := filepath.Join(dir, "not-a-socket")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	server := NewServer(nested, New(ServiceConfig{}))

	if err := server.Start(context.Background()); err == nil {
		t.Fatalf("Start accepted directory socket path")
	}
	if info, err := os.Stat(nested); err != nil || !info.IsDir() {
		t.Fatalf("socket path directory was removed or changed: info=%#v err=%v", info, err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ctxadm-*")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("RemoveAll returned error: %v", err)
		}
	})
	return dir
}

func TestFormatResponseSupportsJSONAndTable(t *testing.T) {
	status := modelregistry.ModelStatus{
		ModelID:           "llama-text-8b",
		ChainState:        "registered",
		DisplayVisibility: "public",
		VerificationLabel: "trace verified",
		RewardState:       "eligible",
	}
	jsonOut, err := FormatResponse(status, FormatJSON)
	if err != nil {
		t.Fatalf("FormatResponse json returned error: %v", err)
	}
	var decoded modelregistry.ModelStatus
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("json output did not decode: %v\n%s", err, jsonOut)
	}
	if decoded.ChainState != status.ChainState || decoded.DisplayVisibility != status.DisplayVisibility {
		t.Fatalf("decoded status = %#v, want %#v", decoded, status)
	}

	tableOut, err := FormatResponse(status, FormatTable)
	if err != nil {
		t.Fatalf("FormatResponse table returned error: %v", err)
	}
	for _, want := range []string{"chain_state", "display_visibility", "verification_label", "reward_state"} {
		if !strings.Contains(tableOut, want) {
			t.Fatalf("table output %q missing %q", tableOut, want)
		}
	}
}

func TestFormatResponseStatusProjectionTableIncludesOperatorFields(t *testing.T) {
	projection := modelregistry.ProjectStatus(modelregistry.StatusObservation{
		ModelID:                 "llama-text-8b",
		ProfileVersion:          "profile-v1",
		ChainState:              modelregistry.ChainStateActive,
		DisplayVisibility:       modelregistry.DisplayVisible,
		VerificationLabel:       modelregistry.VerificationOfficial,
		DeclaredSupport:         true,
		SupportActive:           true,
		LastP30TaskID:           "task-p30",
		P30Cutoff:               30,
		Top10Cutoff:             90,
		MarkGateOpen:            true,
		LastMarkedTaskID:        "task-marked",
		HardwareTier:            "gpu-l4",
		HardwareTierProofTaskID: "verify-task-p30",
		HardwareTierProofRole:   "verifier",
		Treasury: modelregistry.TreasuryState{
			Denom:                   "utrueopen",
			Balance:                 1000,
			MaintenanceRate:         7,
			MaxReimbursementPerTask: 22,
		},
		Builder: modelregistry.BuilderObservation{
			Connected:       false,
			MissedMessages:  3,
			FaultedMessages: 1,
		},
		FailureClasses: []modelregistry.FailureClassObservation{
			{Class: modelregistry.FailureClassValueMismatch, Count: 2},
		},
		EmergencyFreezeAccepted: true,
		Earnings: modelregistry.EarningsObservation{
			PendingTaskFee:       12,
			ClaimableTaskFee:     34,
			TaskFinalityHeight:   100,
			ClaimableAfterHeight: 120,
		},
	})

	out, err := FormatResponse(projection, FormatTable)
	if err != nil {
		t.Fatalf("FormatResponse table returned error: %v", err)
	}
	for _, want := range []string{
		"last_p30_task_id",
		"p30_cutoff",
		"top10_cutoff",
		"mark_gate_open",
		"failure_risk_count",
		"treasury_balance",
		"maintenance_rate",
		"max_reimbursement_per_task",
		"hardware_tier_proof_role",
		"hardware_tier_proof_task_id",
		"builder_connected",
		"builder_missed_messages",
		"builder_faulted_messages",
		"emergency_freeze_reason",
		"verify-task-p30",
		"wallet/SDK",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("operator table output %q missing %q", out, want)
		}
	}
}

func TestTaskQueueListValidatesRequestAndNormalizesAllStatus(t *testing.T) {
	ctx := context.Background()
	if _, err := New(ServiceConfig{}).TaskQueueList(ctx, TaskQueueListRequest{}); err == nil {
		t.Fatal("TaskQueueList accepted unavailable production handler")
	}

	var got TaskQueueListRequest
	api := New(ServiceConfig{TaskQueueList: func(_ context.Context, req TaskQueueListRequest) (TaskQueueListResponse, error) {
		got = req
		return TaskQueueListResponse{}, nil
	}})

	// "all" is the operator-facing spelling of "no filter"; the store takes an
	// empty status. Passing "all" through would match a status column value that
	// does not exist and silently return nothing.
	if _, err := api.TaskQueueList(ctx, TaskQueueListRequest{Status: " ALL ", Limit: 10}); err != nil {
		t.Fatalf("TaskQueueList returned error: %v", err)
	}
	if got.Status != "" || got.Limit != 10 {
		t.Fatalf("normalized request = %#v, want empty status and limit 10", got)
	}

	if _, err := api.TaskQueueList(ctx, TaskQueueListRequest{Limit: -1}); err == nil {
		t.Fatal("TaskQueueList accepted a negative limit")
	}
	if _, err := api.TaskQueueList(ctx, TaskQueueListRequest{Limit: taskQueueListMaxLimit + 1}); err == nil {
		t.Fatal("TaskQueueList accepted a limit past the terminal-readable bound")
	}
}

func TestTaskQueueListTableTruncatesErrorAndJSONKeepsIt(t *testing.T) {
	long := strings.Repeat("x", 200)
	response := TaskQueueListResponse{Rows: []TaskQueueRow{{
		QueueID: "queue-failed", TaskID: "task-1", Role: "worker", Stage: "infer",
		Status: "failed", RetryCount: 4828, DueHeight: 53235, LastError: long,
	}}}

	table := formatTable(response)
	if strings.Contains(table, long) {
		t.Fatalf("table kept an unbounded error, breaking one row per line: %q", table)
	}
	if !strings.Contains(table, "...") {
		t.Fatalf("table = %q, want the error marked as truncated", table)
	}
	for _, want := range []string{"queue-failed", "4828", "53235"} {
		if !strings.Contains(table, want) {
			t.Fatalf("table = %q missing %q", table, want)
		}
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if !strings.Contains(string(encoded), long) {
		t.Fatal("json format dropped the full error; nothing else carries it")
	}
}

func TestEvidenceCleanupPlanTableUsesCompactKVFields(t *testing.T) {
	plan := evidence.CleanupPlan{CurrentHeight: 42, RetentionPolicyVersion: "v2", MinimumRetentionBlocks: 10, Digest: "plan", Items: []evidence.CleanupPlanItem{{
		TaskHash: "task-hash", DigestSHA256: "evidence-digest", SizeBytes: 123,
		CleanupHeight: 40, FinalityHeight: 20, TerminalOrSettled: false, Action: "delete",
	}}}
	table := formatTable(plan)
	for _, want := range []string{"task_hash\tdigest_sha256\tsize_bytes", "task-hash", "evidence-digest", "123", "false"} {
		if !strings.Contains(table, want) {
			t.Fatalf("table = %q, missing %q", table, want)
		}
	}
}
