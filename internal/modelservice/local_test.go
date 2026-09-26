package modelservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// newVLLMStub returns an httptest server that emulates vLLM's /v1/completions,
// branching on whether the request asks for prompt_logprobs (verify) or not
// (generate).
func newVLLMStub(t *testing.T, gen completionResponse, verify completionResponse) (*httptest.Server, *[]completionRequest) {
	return newVLLMStubWithModels(t, gen, verify, []string{"Qwen/Qwen3-8B"})
}

func newVLLMStubWithModels(t *testing.T, gen completionResponse, verify completionResponse, models []string) (*httptest.Server, *[]completionRequest) {
	t.Helper()
	var seen []completionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ListCapabilities reads capacity from vLLM's Prometheus endpoint, so a
		// stub that only serves /v1/models cannot answer it.
		if r.URL.Path == "/metrics" {
			writeVLLMMetrics(w, 0, 0)
			return
		}
		if r.URL.Path == "/v1/models" {
			if r.Method != http.MethodGet {
				http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("Authorization") != "Bearer EMPTY" {
				http.Error(w, "missing bearer auth", http.StatusUnauthorized)
				return
			}
			data := make([]map[string]any, 0, len(models))
			for _, model := range models {
				data = append(data, map[string]any{"id": model, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		}
		if r.URL.Path != "/v1/completions" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		var req completionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen = append(seen, req)
		w.Header().Set("Content-Type", "application/json")
		if req.PromptLogprobs != nil {
			_ = json.NewEncoder(w).Encode(verify)
			return
		}
		_ = json.NewEncoder(w).Encode(gen)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func newHealthStub(t *testing.T, status int, body string, seen *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer EMPTY" {
			http.Error(w, "missing bearer auth", http.StatusUnauthorized)
			return
		}
		if seen != nil {
			*seen = true
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeVLLMMetrics emits the two gauges LocalService reads, in the shape a real
// vLLM /metrics response carries them (labelled series, HELP/TYPE comments, and
// a longer metric sharing the waiting prefix).
func writeVLLMMetrics(w http.ResponseWriter, running, waiting float64) {
	fmt.Fprintf(w, `# HELP vllm:num_requests_running Number of requests in model execution batches.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{engine="0",model_name="Qwen/Qwen3-8B"} %.1f
# HELP vllm:num_requests_waiting Number of requests waiting to be processed.
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting{engine="0",model_name="Qwen/Qwen3-8B"} %.1f
vllm:num_requests_waiting_by_reason{engine="0",model_name="Qwen/Qwen3-8B",reason="capacity"} %.1f
vllm:num_requests_waiting_by_reason{engine="0",model_name="Qwen/Qwen3-8B",reason="deferred"} 0.0
`, running, waiting, waiting)
}

func newModelsStub(t *testing.T, status int, models []string, body string, seen *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			writeVLLMMetrics(w, 0, 0)
			return
		}
		if r.URL.Path != "/v1/models" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer EMPTY" {
			http.Error(w, "missing bearer auth", http.StatusUnauthorized)
			return
		}
		if seen != nil {
			*seen = true
		}
		w.WriteHeader(status)
		if status < 200 || status >= 300 {
			_, _ = w.Write([]byte(body))
			return
		}
		data := make([]map[string]any, 0, len(models))
		for _, model := range models {
			data = append(data, map[string]any{
				"id":     model,
				"object": "model",
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   data,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newMetadataStub(t *testing.T, models []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		// vLLM serves /metrics without the API-key bearer, so the stub does too.
		if r.URL.Path == "/metrics" {
			writeVLLMMetrics(w, 0, 0)
			return
		}
		if r.Header.Get("Authorization") != "Bearer EMPTY" {
			http.Error(w, "missing bearer auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/models":
			data := make([]map[string]any, 0, len(models))
			for _, model := range models {
				data = append(data, map[string]any{"id": model, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func genResponse() completionResponse {
	var resp completionResponse
	resp.Choices = append(resp.Choices, completionChoice{
		Text:           "hello world",
		FinishReason:   "stop",
		PromptTokenIDs: []int{1, 2, 3},
		TokenIDs:       []int{10, 11},
		Logprobs: &completionLogprobs{
			TokenLogprobs: []float64{-0.1, -0.2},
		},
	})
	return resp
}

func TestLocalServiceInferTokenCountAndWorkUnit(t *testing.T) {
	generated := genResponse()
	generated.Choices[0].Text = "€" // one token, three UTF-8 bytes: the test asserts that width
	generated.Choices[0].TokenIDs = []int{10}
	generated.Choices[0].Logprobs.TokenLogprobs = []float64{-0.1}

	srv, _ := newVLLMStub(t, generated, verifyResponse())
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	resp, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "infer-metering",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say cat"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if resp.GeneratedTokenCount != 1 || resp.WorkUnit != 1 {
		t.Fatalf("Infer() metering = %d tokens/%d work units, want 1/1", resp.GeneratedTokenCount, resp.WorkUnit)
	}
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if len(output.Data) != 3 {
		t.Fatalf("UTF-8 output byte length = %d, want 3 and distinct from token count", len(output.Data))
	}
}

func TestFakeServiceInferTokenCountAndWorkUnit(t *testing.T) {
	resp, err := NewFakeService().Infer(context.Background(), InferRequest{
		ModelID:    fakeModelID,
		Capability: CapabilityLLMTextV1,
		Input:      []byte("prompt"),
	})
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if resp.GeneratedTokenCount != fakeGeneratedTokenCount || resp.WorkUnit != fakeGeneratedTokenCount {
		t.Fatalf("Infer() metering = %d tokens/%d work units, want deterministic fixture %d/%d",
			resp.GeneratedTokenCount, resp.WorkUnit, fakeGeneratedTokenCount, fakeGeneratedTokenCount)
	}
}

func verifyResponse() completionResponse {
	var resp completionResponse
	resp.Choices = append(resp.Choices, completionChoice{
		PromptLogprobs: []map[string]logprobEntry{
			nil,
			{"2": {Logprob: -0.01, Rank: 1, DecodedToken: "b"}},
			{"3": {Logprob: -0.02, Rank: 1, DecodedToken: "c"}},
			{"10": {Logprob: -0.1, Rank: 1, DecodedToken: "hello"}},
			{"11": {Logprob: -0.2, Rank: 1, DecodedToken: "world"}},
		},
	})
	return resp
}

func TestLocalServiceImplementsClient(t *testing.T) {
	var _ Client = NewLocalService("", "svc", 4, 0, 0)
}

func TestLocalServiceHealthCallsVLLMHealthEndpoint(t *testing.T) {
	seen := false
	srv := newHealthStub(t, http.StatusOK, "", &seen)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	resp, err := svc.Health(context.Background(), HealthRequest{RequestID: "health-1"})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !resp.Healthy || resp.Error != nil || resp.RequestID != "health-1" || resp.ModelServiceID != "local-svc" {
		t.Fatalf("Health() = %+v, want healthy local response", resp)
	}
	if !seen {
		t.Fatalf("Health() did not call vLLM /health")
	}
}

func TestLocalServiceHealthReportsVLLMUnhealthy(t *testing.T) {
	srv := newHealthStub(t, http.StatusServiceUnavailable, "engine dead", nil)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	resp, err := svc.Health(context.Background(), HealthRequest{RequestID: "health-1"})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if resp.Healthy || resp.Error == nil {
		t.Fatalf("Health() = %+v, want unhealthy response with error", resp)
	}
	if resp.Error.Code != "VLLM_HEALTH_UNHEALTHY" || !resp.Error.Retryable || !strings.Contains(resp.Error.Message, "engine dead") {
		t.Fatalf("Health() error = %+v, want retryable vLLM unhealthy error", resp.Error)
	}
}

func TestLocalServiceHealthHonorsProbeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 50*time.Millisecond)
	start := time.Now()
	_, err := svc.Health(context.Background(), HealthRequest{RequestID: "health-timeout"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Health() error = nil, want timeout")
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("Health() took %v, want probe timeout ~50ms", elapsed)
	}
}

func TestLocalServiceInferHonorsInferTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"data":   []map[string]any{{"id": "Qwen/Qwen3-8B", "object": "model"}},
			})
			return
		}
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)

	svc := NewLocalService(srv.URL, "local-svc", 4, 50*time.Millisecond, 0)
	start := time.Now()
	_, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "infer-timeout",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("hi"),
	}))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Infer() error = nil, want timeout")
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("Infer() took %v, want infer timeout ~50ms", elapsed)
	}
}

func TestLocalServiceListCapabilitiesCallsVLLMModelsEndpoint(t *testing.T) {
	seen := false
	srv := newModelsStub(t, http.StatusOK, []string{"Qwen/Qwen3-8B", "second-model", "Qwen/Qwen3-8B", ""}, "", &seen)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if !seen {
		t.Fatalf("ListCapabilities() did not call vLLM /v1/models")
	}
	if resp.RequestID != "caps-1" || resp.ModelServiceID != "local-svc" {
		t.Fatalf("ListCapabilities() identity = %+v, want request/service ids", resp)
	}
	if resp.ResourceSnapshot.LoadedModels != 2 || len(resp.Capabilities) != 2 {
		t.Fatalf("ListCapabilities() = %+v, want two loaded model capabilities", resp)
	}
	wantModels := []string{localHuggingFaceModelID("Qwen/Qwen3-8B"), localHuggingFaceModelID("second-model")}
	for i, want := range wantModels {
		got := resp.Capabilities[i]
		if got.ModelID != want || got.Capability != CapabilityLLMTextV1 || !got.SupportsTrace || !got.SupportsCheckpoint || !got.SupportsBatchLog {
			t.Fatalf("Capabilities[%d] = %+v, want llm_text_v1 capability for %q", i, got, want)
		}
	}
}

func TestLocalServiceListCapabilitiesUnavailableIsRetryable(t *testing.T) {
	srv := newModelsStub(t, http.StatusServiceUnavailable, nil, "warming up", nil)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	_, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err == nil || !IsRetryable(err) {
		t.Fatalf("ListCapabilities() error = %v, want retryable error", err)
	}
}

func TestLocalServiceListCapabilitiesUsesGeneratedSystemModelIDAfterLoadModel(t *testing.T) {
	srv := newMetadataStub(t, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	modelID := testQwenModelID()

	load, err := svc.LoadModel(context.Background(), LoadModelRequest{RequestID: "load-1", ModelID: modelID, Capability: CapabilityLLMTextV1})
	if err != nil {
		t.Fatalf("LoadModel() error = %v", err)
	}
	if load.ModelID != modelID {
		t.Fatalf("LoadModel() ModelID = %q, want protocol model id", load.ModelID)
	}
	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	wantModelID := modelID
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != wantModelID {
		t.Fatalf("ListCapabilities() = %+v, want generated system model id %q", resp, wantModelID)
	}
}

func TestLocalServiceLoadModelRequiresMappedModelID(t *testing.T) {
	srv := newMetadataStub(t, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	_, err := svc.LoadModel(context.Background(), LoadModelRequest{RequestID: "load-1", ModelID: "model-random", Capability: CapabilityLLMTextV1})
	if err == nil || !strings.Contains(err.Error(), "not mapped to a vLLM served model") {
		t.Fatalf("LoadModel() error = %v, want explicit mapping failure", err)
	}
}

func TestLocalHuggingFaceModelIDUsesRegistryFormula(t *testing.T) {
	got := localHuggingFaceModelID("Qwen/Qwen3-8B")
	want := "hf-ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"
	if got != want {
		t.Fatalf("localHuggingFaceModelID() = %q, want %q", got, want)
	}
	if got := localHuggingFaceModelID(want); got != want {
		t.Fatalf("localHuggingFaceModelID(%q) = %q, want canonical %q", want, got, want)
	}
}

func testQwenModelID() string {
	return localHuggingFaceModelID("Qwen/Qwen3-8B")
}

func TestLocalServiceMapsVLLMModelNameToSystemModelID(t *testing.T) {
	servedModel := "Qwen/Qwen3-8B"
	systemModelID := localHuggingFaceModelID(servedModel)
	srv, seen := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{servedModel, "other-served-model"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	ctx := context.Background()

	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) != 2 || caps.Capabilities[0].ModelID != systemModelID {
		t.Fatalf("ListCapabilities() = %+v, want first capability for generated system model id %q", caps, systemModelID)
	}

	infer, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{
		RequestID:  "infer-1",
		ModelID:    systemModelID,
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	traceArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	var trace traceEnvelope
	if err := json.Unmarshal(traceArtifact.Data, &trace); err != nil {
		t.Fatalf("unmarshal trace: %v", err)
	}
	if trace.ModelID != systemModelID {
		t.Fatalf("trace model id = %q, want generated system model id", trace.ModelID)
	}
	checkpointArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.CheckpointRef})
	if err != nil {
		t.Fatalf("FetchArtifact(checkpoint) error = %v", err)
	}
	if _, err := svc.Verify(ctx, boundLocalVerifyFixture(t, VerifyRequest{
		RequestID:  "verify-1",
		ModelID:    systemModelID,
		Capability: CapabilityLLMTextV1,
		Sample:     []byte("seed"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: traceArtifact.Data, Checkpoint: checkpointArtifact.Data},
		},
	})); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	var genReq, verifyReq *completionRequest
	for i := range *seen {
		if (*seen)[i].PromptLogprobs == nil {
			genReq = &(*seen)[i]
		} else {
			verifyReq = &(*seen)[i]
		}
	}
	if genReq == nil || genReq.Model != servedModel {
		t.Fatalf("infer vLLM request = %+v, want served model %q", genReq, servedModel)
	}
	if verifyReq == nil || verifyReq.Model != servedModel {
		t.Fatalf("verify vLLM request = %+v, want served model %q", verifyReq, servedModel)
	}
}

func TestLocalServiceMapsSlashModelIDToVLLMModelName(t *testing.T) {
	servedModel := "Qwen/Qwen3-8B"
	modelID := localHuggingFaceModelID(servedModel)
	srv, seen := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{servedModel})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	_, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "infer-1",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if len(*seen) != 1 || (*seen)[0].Model != servedModel {
		t.Fatalf("infer vLLM requests = %+v, want served model %q", *seen, servedModel)
	}
}

func TestLocalServiceInferStoresAndServesArtifacts(t *testing.T) {
	srv, seen := newVLLMStub(t, genResponse(), verifyResponse())
	svc := NewLocalService(strings.TrimPrefix(srv.URL, "http://"), "local-svc", 4, 0, 0)
	ctx := context.Background()
	modelID := testQwenModelID()

	resp, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{
		RequestID:  "infer-1",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if resp.OutputRef == "" || resp.TraceRef == "" || resp.CheckpointRef == "" {
		t.Fatalf("Infer() refs incomplete: %+v", resp)
	}
	if resp.ModelServiceID != "local-svc" {
		t.Fatalf("Infer() ModelServiceID = %q, want local-svc", resp.ModelServiceID)
	}
	if resp.ModelID != modelID {
		t.Fatalf("Infer() ModelID = %q, want protocol model id", resp.ModelID)
	}

	output, err := svc.FetchArtifact(ctx, FetchArtifactRequest{
		RequestID:      "fetch-1",
		ModelServiceID: "local-svc",
		Ref:            resp.OutputRef,
	})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(output.Data) != "hello world" {
		t.Fatalf("output = %q, want %q", output.Data, "hello world")
	}

	traceArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{
		RequestID:      "fetch-trace-1",
		ModelServiceID: "local-svc",
		Ref:            resp.TraceRef,
	})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	var trace traceEnvelope
	if err := json.Unmarshal(traceArtifact.Data, &trace); err != nil {
		t.Fatalf("unmarshal trace: %v", err)
	}
	wantOut := []tokenLogprob{{TokenID: 10, Logprob: -0.1}, {TokenID: 11, Logprob: -0.2}}
	if len(trace.OutTokens) != len(wantOut) {
		t.Fatalf("trace.OutTokens = %+v, want %+v", trace.OutTokens, wantOut)
	}
	for i, got := range trace.OutTokens {
		if got.TokenID != wantOut[i].TokenID || got.Logprob != wantOut[i].Logprob {
			t.Fatalf("trace.OutTokens[%d] = %+v, want %+v", i, got, wantOut[i])
		}
	}
	if len(trace.InputTokenIDs) != 3 {
		t.Fatalf("trace.InputTokenIDs = %v, want len 3", trace.InputTokenIDs)
	}
	if trace.ModelID != modelID {
		t.Fatalf("trace model binding = %+v, want protocol model id", trace)
	}
	if trace.FinishReason != "stop" || trace.GeneratedTokenCount != 2 {
		t.Fatalf("trace finish/count = %q/%d, want stop/2", trace.FinishReason, trace.GeneratedTokenCount)
	}
	if trace.InputTokenIDsHash != hashTokenIDs([]int{1, 2, 3}) || trace.GeneratedTokenIDsHash != hashTokenIDs([]int{10, 11}) {
		t.Fatalf("trace token hashes = %q/%q, want input/generated token id hashes", trace.InputTokenIDsHash, trace.GeneratedTokenIDsHash)
	}
	if len(*seen) != 1 {
		t.Fatalf("seen requests = %d, want 1", len(*seen))
	}
	genReq := (*seen)[0]
	if genReq.Model != "Qwen/Qwen3-8B" {
		t.Fatalf("infer vLLM model = %q, want served model name", genReq.Model)
	}
	if genReq.MaxTokens != 128 || genReq.Logprobs == nil || *genReq.Logprobs != defaultTopK {
		t.Fatalf("infer generation params = %+v, want fixture max_tokens=128 logprobs=%d", genReq, defaultTopK)
	}
	if genReq.TopP != defaultTopP || genReq.TopK != defaultTopKSample || genReq.Seed == nil || *genReq.Seed != defaultSeed {
		t.Fatalf("infer sampling params = %+v, want top_p=%v top_k=%d seed=%d", genReq, defaultTopP, defaultTopKSample, defaultSeed)
	}
}

func TestLocalServiceVerifyUsesTokenIDPrompt(t *testing.T) {
	srv, seen := newVLLMStub(t, genResponse(), verifyResponse())
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	ctx := context.Background()
	modelID := testQwenModelID()

	infer, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{RequestID: "infer-1", ModelID: modelID, Capability: CapabilityLLMTextV1, Input: []byte("hi")}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	traceArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	checkpointArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.CheckpointRef})
	if err != nil {
		t.Fatalf("FetchArtifact(checkpoint) error = %v", err)
	}

	resp, err := svc.Verify(ctx, boundLocalVerifyFixture(t, VerifyRequest{
		RequestID:  "verify-1",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
		Sample:     []byte("seed"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: traceArtifact.Data, Checkpoint: checkpointArtifact.Data},
		},
	}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if resp.SampleValueSequenceRef == "" {
		t.Fatalf("Verify() SampleValueSequenceRef empty")
	}
	if resp.MainMismatchCount != 0 {
		t.Fatalf("Verify() MainMismatchCount = %d, want non-reject pass", resp.MainMismatchCount)
	}
	if len(resp.MaterialDigest) == 0 || len(resp.SampleDigest) == 0 {
		t.Fatalf("Verify() digests empty: %+v", resp)
	}
	sequence, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: resp.SampleValueSequenceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(sample sequence) error = %v", err)
	}
	var envelope verificationEnvelope
	if err := json.Unmarshal(sequence.Data, &envelope); err != nil {
		t.Fatalf("unmarshal sequence envelope: %v", err)
	}
	if envelope.Verdict != verdictPass || envelope.RawVerdict != verdictInconclusive || envelope.Metrics.FiniteCount != 2 {
		t.Fatalf("verification envelope = %+v, want inconclusive raw treated as pass", envelope)
	}
	if envelope.VerifierID != localVerifierID || envelope.Policy.PassMinFiniteCount != passMinFiniteCount {
		t.Fatalf("verification envelope = %+v, want verifier id and policy snapshot", envelope)
	}

	// The verify call must send the prompt as input+output token ids and max_tokens=1.
	var verifyReq *completionRequest
	for i := range *seen {
		if (*seen)[i].PromptLogprobs != nil {
			verifyReq = &(*seen)[i]
			break
		}
	}
	if verifyReq == nil {
		t.Fatalf("no prompt_logprobs request captured: %+v", *seen)
	}
	if verifyReq.MaxTokens != 1 {
		t.Fatalf("verify max_tokens = %d, want 1", verifyReq.MaxTokens)
	}
	if verifyReq.Model != "Qwen/Qwen3-8B" {
		t.Fatalf("verify vLLM model = %q, want served model name", verifyReq.Model)
	}
	if verifyReq.PromptLogprobs == nil || *verifyReq.PromptLogprobs != defaultTopK {
		t.Fatalf("verify prompt_logprobs = %v, want %d", verifyReq.PromptLogprobs, defaultTopK)
	}
	if verifyReq.TopP != defaultTopP || verifyReq.TopK != defaultTopKSample || verifyReq.Seed == nil || *verifyReq.Seed != defaultSeed {
		t.Fatalf("verify sampling params = %+v, want top_p=%v top_k=%d seed=%d", verifyReq, defaultTopP, defaultTopKSample, defaultSeed)
	}
	// JSON numbers decode into []interface{} of float64.
	promptIDs, ok := verifyReq.Prompt.([]any)
	if !ok {
		t.Fatalf("verify prompt type = %T, want []any", verifyReq.Prompt)
	}
	want := []int{1, 2, 3, 10, 11}
	if len(promptIDs) != len(want) {
		t.Fatalf("verify prompt = %v, want %v", promptIDs, want)
	}
	for i, v := range promptIDs {
		if int(v.(float64)) != want[i] {
			t.Fatalf("verify prompt[%d] = %v, want %d", i, v, want[i])
		}
	}
}

func TestLocalServiceUsesResolvedProfileForInferAndVerify(t *testing.T) {
	srv, seen := newVLLMStub(t, genResponse(), verifyResponse())
	modelID := testQwenModelID()
	resolver := staticLocalProfileResolver{profile: resolvedCurrentProfile(modelID, 3, 7)}
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetProfileResolver(resolver)
	ctx := context.Background()

	infer, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{
		RequestID:      "infer-1",
		ModelID:        modelID,
		ProfileVersion: "3",
		Capability:     CapabilityLLMTextV1,
		Input:          []byte("hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	traceArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	checkpointArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.CheckpointRef})
	if err != nil {
		t.Fatalf("FetchArtifact(checkpoint) error = %v", err)
	}

	verify, err := svc.Verify(ctx, boundLocalVerifyFixture(t, VerifyRequest{
		RequestID:      "verify-1",
		ModelID:        modelID,
		ProfileVersion: "3",
		Capability:     CapabilityLLMTextV1,
		Sample:         []byte("seed"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: traceArtifact.Data, Checkpoint: checkpointArtifact.Data},
		},
	}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	sequence, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: verify.SampleValueSequenceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(sequence) error = %v", err)
	}
	var envelope verificationEnvelope
	if err := json.Unmarshal(sequence.Data, &envelope); err != nil {
		t.Fatalf("unmarshal sequence envelope: %v", err)
	}
	if envelope.Policy.PassMinFiniteCount != 9 || envelope.Policy.RejectMeanAbsLogprobDiffMin != 0.5 {
		t.Fatalf("verification policy = %+v, want resolver thresholds", envelope.Policy)
	}

	var genReq, verifyReq *completionRequest
	for i := range *seen {
		if (*seen)[i].PromptLogprobs == nil {
			genReq = &(*seen)[i]
		} else {
			verifyReq = &(*seen)[i]
		}
	}
	if genReq == nil || genReq.Logprobs == nil || *genReq.Logprobs != 7 {
		t.Fatalf("infer request = %+v, want resolver logprobs=7", genReq)
	}
	if verifyReq == nil || verifyReq.PromptLogprobs == nil || *verifyReq.PromptLogprobs != 7 {
		t.Fatalf("verify request = %+v, want resolver prompt_logprobs=7", verifyReq)
	}
}

func TestLocalProfileSnapshotOverridesDefaults(t *testing.T) {
	profile, err := applyCurrentProfileSnapshot(defaultQwenSingleSampleProfile("m", "3", "served"), resolvedCurrentProfile("m", 3, 7))
	if err != nil {
		t.Fatalf("applyCurrentProfileSnapshot() error = %v", err)
	}
	if profile.RequiredTopK != 7 || profile.Sampling.Logprobs != 7 || profile.Sampling.PromptLogprobs != 7 || profile.Verification.ComparedTopK != 7 {
		t.Fatalf("resolved top-k = %+v, want all top-k fields from profile snapshot", profile)
	}
	if profile.Thresholds.PassMinFiniteCount != 9 || profile.Thresholds.RejectMeanAbsLogprobDiffMin != 0.5 {
		t.Fatalf("resolved thresholds = %+v, want FP_1E6 thresholds from profile snapshot", profile.Thresholds)
	}
	if !profile.Verification.RequireOutputTokenIDs || !profile.Verification.RequireFinishReason || profile.Verification.NumericScale != "FP_1E6" {
		t.Fatalf("resolved verification profile = %+v, want profile snapshot values", profile.Verification)
	}
}

func TestLocalServiceVerifyReportsMismatchesAndRecomputedSequence(t *testing.T) {
	mismatched := verifyResponse()
	mismatched.Choices[0].PromptLogprobs[4]["11"] = logprobEntry{Logprob: -0.9, Rank: 1, DecodedToken: "world"}
	srv, _ := newVLLMStub(t, genResponse(), mismatched)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	ctx := context.Background()
	modelID := testQwenModelID()

	infer, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{RequestID: "infer-1", ModelID: modelID, Capability: CapabilityLLMTextV1, Input: []byte("hi")}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	traceArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	checkpointArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.CheckpointRef})
	if err != nil {
		t.Fatalf("FetchArtifact(checkpoint) error = %v", err)
	}

	resp, err := svc.Verify(ctx, boundLocalVerifyFixture(t, VerifyRequest{
		RequestID:  "verify-1",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
		Sample:     []byte("seed"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: traceArtifact.Data, Checkpoint: checkpointArtifact.Data},
		},
	}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if resp.MainMismatchCount == 0 {
		t.Fatalf("MainMismatchCount = %d, want reject reasons", resp.MainMismatchCount)
	}
	wantPositions := []int{0, 1}
	if len(resp.SelectedPositionsOrCheckpoints) != len(wantPositions) {
		t.Fatalf("SelectedPositionsOrCheckpoints = %v, want %v", resp.SelectedPositionsOrCheckpoints, wantPositions)
	}
	for i, want := range wantPositions {
		if resp.SelectedPositionsOrCheckpoints[i] != want {
			t.Fatalf("SelectedPositionsOrCheckpoints[%d] = %d, want %d", i, resp.SelectedPositionsOrCheckpoints[i], want)
		}
	}

	sequence, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: resp.SampleValueSequenceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(sequence) error = %v", err)
	}
	var values []verificationValue
	var envelope verificationEnvelope
	if err := json.Unmarshal(sequence.Data, &envelope); err != nil {
		t.Fatalf("unmarshal sequence envelope: %v", err)
	}
	values = envelope.Values
	if envelope.Verdict != verdictReject || envelope.RawVerdict != verdictReject || len(envelope.RejectReasons) == 0 {
		t.Fatalf("verification envelope = %+v, want reject", envelope)
	}
	if envelope.Metrics.MeanAbsLogprobDiff <= rejectMeanAbsLogprobDiffMin {
		t.Fatalf("MeanAbsLogprobDiff = %v, want reject threshold breach", envelope.Metrics.MeanAbsLogprobDiff)
	}
	if len(values) != 2 || !values[0].Present || !values[1].Present || values[1].Logprob == nil || *values[1].Logprob != -0.9 {
		t.Fatalf("verification values = %+v, want recomputed mismatch on second token", values)
	}
}

func TestLocalServiceVerifyRejectsMismatchedCheckpoint(t *testing.T) {
	srv, _ := newVLLMStub(t, genResponse(), verifyResponse())
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	ctx := context.Background()
	modelID := testQwenModelID()

	infer, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{RequestID: "infer-1", ModelID: modelID, Capability: CapabilityLLMTextV1, Input: []byte("hi")}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	traceArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{ModelServiceID: "local-svc", Ref: infer.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	checkpointBytes, err := json.Marshal(traceEnvelope{
		Output:        "other output",
		InputTokenIDs: []int{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}

	_, err = svc.Verify(ctx, boundLocalVerifyFixture(t, VerifyRequest{
		RequestID:  "verify-1",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
		Sample:     []byte("seed"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: traceArtifact.Data, Checkpoint: checkpointBytes},
		},
	}))
	if err == nil || !strings.Contains(err.Error(), "checkpoint does not match trace") {
		t.Fatalf("Verify() error = %v, want checkpoint mismatch", err)
	}
}

func TestLocalServiceSingleSampleClassifierRejectsOnlyRejectThresholds(t *testing.T) {
	rejectMetrics := singleSampleMetrics{
		FiniteCount:          128,
		MeanAbsLogprobDiff:   rejectMeanAbsLogprobDiffMin + 0.001,
		AbsLogprobDiffP95:    0.05,
		AbsLogprobDiffP99:    0.10,
		RankDeltaNonzeroRate: 0.01,
		TopKJaccardMean:      floatPtr(0.94),
		UnionJSP99:           floatPtr(0.01),
		ComparedTopKCount:    128,
		ComparedRankCount:    128,
		MissingSelectedCount: 0,
	}
	verdict, reasons := classifySingleSampleWithThresholds(rejectMetrics, localSingleSampleThresholds())
	if verdict != verdictReject || len(reasons) != 1 || reasons[0] != "mean_abs_logprob_diff" {
		t.Fatalf("reject classify = %s reasons=%v, want mean_abs reject", verdict, reasons)
	}

	inconclusiveMetrics := singleSampleMetrics{
		FiniteCount:          128,
		MeanAbsLogprobDiff:   passMeanAbsLogprobDiffMax + 0.001,
		AbsLogprobDiffP95:    passAbsLogprobDiffP95Max + 0.001,
		AbsLogprobDiffP99:    passAbsLogprobDiffP99Max + 0.001,
		RankDeltaNonzeroRate: passRankMismatchRateMax + 0.001,
		TopKJaccardMean:      floatPtr(passTopKJaccardMeanMin - 0.001),
		UnionJSP99:           floatPtr(passUnionJSP99Max + 0.001),
		ComparedTopKCount:    128,
		ComparedRankCount:    128,
		MissingSelectedCount: 0,
	}
	verdict, reasons = classifySingleSampleWithThresholds(inconclusiveMetrics, localSingleSampleThresholds())
	if verdict != verdictInconclusive || len(reasons) != 0 {
		t.Fatalf("gray classify = %s reasons=%v, want inconclusive without reject", verdict, reasons)
	}
}

func TestLocalServiceHTTPUnavailableIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "warming up", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	_, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{ModelID: "m", Capability: CapabilityLLMTextV1, Input: []byte("hi")}))
	if err == nil || !IsRetryable(err) {
		t.Fatalf("Infer() error = %v, want retryable error", err)
	}
}

func floatPtr(v float64) *float64 {
	return &v
}

type staticLocalProfileResolver struct {
	profile chainclient.CurrentProfileSnapshot
}

func (r staticLocalProfileResolver) ResolveLocalProfile(context.Context, string, string) (chainclient.CurrentProfileSnapshot, error) {
	return r.profile, nil
}

func resolvedCurrentProfile(modelID string, profileVersion uint32, topK uint32) chainclient.CurrentProfileSnapshot {
	return chainclient.CurrentProfileSnapshot{
		ModelID:        modelID,
		ProfileVersion: chainclient.NewProfileVersion(profileVersion),
		RuntimeClass:   defaultLocalRuntimeClass,
		RequiredTopK:   topK,
		VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
			VerificationProfileID:         2,
			JudgmentFunctionVersion:       defaultLocalJudgmentFunctionVersion,
			TokenScope:                    "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
			IncludeGeneratedSpecialTokens: true,
			RequireOutputTokenIDs:         true,
			RequireFinishReason:           true,
			Metrics: chainclient.CurrentMetricSpecSnapshot{
				CompareLogprobDiff: true,
				CompareRankDelta:   true,
				CompareTopKJaccard: true,
				CompareUnionJS:     true,
				ComparedTopK:       topK,
				NumericScale:       "NUMERIC_SCALE_FP_1E6",
			},
			CanonicalEncodingVersion:    defaultLocalCanonicalEncoding,
			MetricAggregateProofVersion: defaultLocalMetricProofVersion,
		},
		VerificationThresholds: chainclient.CurrentVerificationThresholdsSnapshot{
			PassMinFiniteCount:            9,
			PassMeanAbsLogprobDiffMax:     18000,
			PassAbsLogprobDiffP95Max:      100000,
			PassAbsLogprobDiffP99Max:      200000,
			PassRankDeltaNonzeroRateMax:   25000,
			PassTopKJaccardMeanMin:        935000,
			PassUnionJSP99Max:             12000,
			RejectMeanAbsLogprobDiffMin:   500000,
			RejectAbsLogprobDiffP95Min:    600000,
			RejectAbsLogprobDiffP99Min:    700000,
			RejectRankDeltaNonzeroRateMin: 800000,
			RejectTopKJaccardMeanMax:      100000,
			RejectUnionJSP99Min:           900000,
		},
	}
}

func TestLocalServiceMetadataEndpoints(t *testing.T) {
	srv := newMetadataStub(t, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	ctx := context.Background()
	modelID := testQwenModelID()

	health, err := svc.Health(ctx, HealthRequest{RequestID: "h"})
	if err != nil || !health.Healthy {
		t.Fatalf("Health() = %+v, err = %v", health, err)
	}
	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "c"})
	if err != nil || len(caps.Capabilities) == 0 || caps.Capabilities[0].Capability != CapabilityLLMTextV1 {
		t.Fatalf("ListCapabilities() = %+v, err = %v", caps, err)
	}
	details, err := svc.GetModelDetails(ctx, GetModelDetailsRequest{RequestID: "d", ModelID: "m"})
	if err != nil || details.Error == nil || details.Error.Code != "UNIMPLEMENTED" {
		t.Fatalf("GetModelDetails() = %+v, err = %v, want local unimplemented response", details, err)
	}
	load, err := svc.LoadModel(ctx, LoadModelRequest{RequestID: "l", ModelID: modelID, Capability: CapabilityLLMTextV1})
	if err != nil || !load.Loaded {
		t.Fatalf("LoadModel() = %+v, err = %v", load, err)
	}
	est, err := svc.Estimate(ctx, EstimateRequest{RequestID: "e", Capability: CapabilityLLMTextV1, InputBytes: 10})
	if err != nil || est.EstimatedBytes == 0 {
		t.Fatalf("Estimate() = %+v, err = %v", est, err)
	}
}

// newCapacityStub serves /v1/models and a /metrics response with the given
// occupancy, so ListCapabilities can be exercised against a saturated backend.
func newCapacityStub(t *testing.T, running, waiting float64, omitGauges bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			if omitGauges {
				_, _ = w.Write([]byte("# HELP vllm:cache_config_info Information of the LLMEngine CacheConfig\nvllm:cache_config_info{block_size=\"16\"} 1.0\n"))
				return
			}
			writeVLLMMetrics(w, running, waiting)
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []map[string]any{{"id": "Qwen/Qwen3-8B", "object": "model"}}})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A local service must publish a capacity the handraise path can act on.
// ResourceSnapshot.AvailableSlots() rejects a zero MaxConcurrency, so a service
// that reports only LoadedModels makes every handraise fail with "model service
// capacity is invalid for handraise".
func TestLocalServiceReportsCapacityHandraiseCanUse(t *testing.T) {
	srv := newCapacityStub(t, 1, 2, false)
	svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if resp.ResourceSnapshot.MaxConcurrency != 8 {
		t.Fatalf("MaxConcurrency = %d, want the configured 8", resp.ResourceSnapshot.MaxConcurrency)
	}
	// 1 running + 2 waiting both hold a slot.
	if resp.ResourceSnapshot.QueueDepth != 3 {
		t.Fatalf("QueueDepth = %d, want 3 (running + waiting)", resp.ResourceSnapshot.QueueDepth)
	}
	slots, err := resp.ResourceSnapshot.AvailableSlots()
	if err != nil {
		t.Fatalf("AvailableSlots() error = %v, want a usable handraise capacity", err)
	}
	if slots != 5 {
		t.Fatalf("AvailableSlots() = %d, want 5", slots)
	}
}

// A backlog longer than the batch size is normal for vLLM, not a fault, but it
// must read as saturated rather than underflow into a huge free capacity.
func TestLocalServiceReportsSaturationWhenBacklogExceedsConcurrency(t *testing.T) {
	srv := newCapacityStub(t, 4, 30, false)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	slots, err := resp.ResourceSnapshot.AvailableSlots()
	if err != nil {
		t.Fatalf("AvailableSlots() error = %v", err)
	}
	if slots != 0 {
		t.Fatalf("AvailableSlots() = %d, want 0 while saturated", slots)
	}
}

// An unreadable capacity must fail rather than report an idle service: zero
// occupancy would make a saturated node handraise for work it cannot start.
func TestLocalServiceFailsWhenCapacityIsUnreadable(t *testing.T) {
	for _, testCase := range []struct {
		name string
		srv  *httptest.Server
	}{
		{name: "gauges missing", srv: newCapacityStub(t, 0, 0, true)},
		{name: "metrics unavailable", srv: newModelsStubWithoutMetrics(t)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			svc := NewLocalService(testCase.srv.URL, "local-svc", 4, 0, 0)
			if _, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"}); err == nil {
				t.Fatalf("ListCapabilities() error = nil, want a failure rather than an idle capacity")
			}
		})
	}
}

func TestSumVLLMGaugeValidatesRequestCounts(t *testing.T) {
	const gauge = "vllm:num_requests_running"
	tests := []struct {
		name    string
		metrics string
		want    float64
		wantErr bool
	}{
		{name: "labelled series", metrics: gauge + `{engine="0"} 2` + "\n" + gauge + `{engine="1"} 3`, want: 5},
		{name: "optional timestamp", metrics: gauge + `{engine="0"} 2 1786020000000`, want: 2},
		{name: "nan", metrics: gauge + " NaN", wantErr: true},
		{name: "infinity", metrics: gauge + " +Inf", wantErr: true},
		{name: "negative", metrics: gauge + " -1", wantErr: true},
		{name: "fractional", metrics: gauge + " 1.5", wantErr: true},
		{name: "missing value", metrics: gauge, wantErr: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := sumVLLMGauge(testCase.metrics, gauge)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("sumVLLMGauge() = %v, nil; want an error", got)
				}
				return
			}
			if err != nil || got != testCase.want {
				t.Fatalf("sumVLLMGauge() = %v, %v; want %v, nil", got, err, testCase.want)
			}
		})
	}
}

func newModelsStubWithoutMetrics(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []map[string]any{{"id": "Qwen/Qwen3-8B", "object": "model"}}})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Handraise eligibility matches the chain model id against what the model
// service advertises, but vLLM serves its own name (Qwen/Qwen3-8B). Local maps
// the served name to the registry id and only advertises it when it matches the
// configured support list.
func TestLocalServiceAdvertisesConfiguredModelIDWhenServedModelMatches(t *testing.T) {
	const chainModelID = "hf-ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"
	srv := newCapacityStub(t, 0, 0, false) // serves exactly one model: Qwen/Qwen3-8B
	svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0, chainModelID)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != chainModelID {
		t.Fatalf("Capabilities = %+v, want the chain model id advertised before any load", resp.Capabilities)
	}

	// Inference must still reach the served model behind that id.
	served, err := svc.resolveServedModel(context.Background(), chainModelID)
	if err != nil {
		t.Fatalf("resolveServedModel() error = %v", err)
	}
	if served != "Qwen/Qwen3-8B" {
		t.Fatalf("resolveServedModel() = %q, want the served vLLM model", served)
	}
}

// With several served models the mapping is a guess, and binding a chain id to
// the wrong weights is worse than not being selected.
func TestLocalServiceDoesNotGuessModelIDWhenSeveralAreServed(t *testing.T) {
	srv := newMultiModelStub(t, []string{"Qwen/Qwen3-8B", "meta-llama/Llama-3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0, "hf-somechainid")

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	for _, capability := range resp.Capabilities {
		if capability.ModelID == "hf-somechainid" {
			t.Fatalf("Capabilities = %+v, want no guessed binding while several models are served", resp.Capabilities)
		}
	}
}

func TestLocalServiceDoesNotGuessAmongSeveralConfiguredModelIDs(t *testing.T) {
	srv := newCapacityStub(t, 0, 0, false) // exactly one served model
	svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0, "hf-model-a", "hf-model-b")

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 0 {
		t.Fatalf("Capabilities = %+v, want no advertised models when configured ids do not match served models", resp.Capabilities)
	}
}

func TestLocalServiceDeduplicatesConfiguredModelIDs(t *testing.T) {
	srv := newCapacityStub(t, 0, 0, false)
	modelID := testQwenModelID()
	svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0, " "+modelID+" ", modelID)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != modelID {
		t.Fatalf("Capabilities = %+v, want the single deduplicated configured model", resp.Capabilities)
	}
}

func TestLocalServiceRejectsConfiguredModelIDThatDoesNotMatchServedModel(t *testing.T) {
	srv := newCapacityStub(t, 0, 0, false)
	svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0, "hf-configured")

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 0 {
		t.Fatalf("Capabilities = %+v, want no configured alias for a mismatched served model", resp.Capabilities)
	}
	if _, err := svc.resolveServedModel(context.Background(), "hf-configured"); err == nil ||
		!strings.Contains(err.Error(), "not mapped to a vLLM served model") {
		t.Fatalf("resolveServedModel() error = %v, want mismatched configured id rejected", err)
	}
}

func newMultiModelStub(t *testing.T, models []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			writeVLLMMetrics(w, 0, 0)
		case "/v1/models":
			data := make([]map[string]any, 0, len(models))
			for _, model := range models {
				data = append(data, map[string]any{"id": model, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// countingProfileResolver records how many chain queries a resolution costs.
type countingProfileResolver struct {
	mu       sync.Mutex
	calls    map[string]int
	snapshot func(modelID, profileVersion string) chainclient.CurrentProfileSnapshot
}

func (r *countingProfileResolver) ResolveLocalProfile(_ context.Context, modelID, profileVersion string) (chainclient.CurrentProfileSnapshot, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[modelID+"@"+profileVersion]++
	r.mu.Unlock()
	return r.snapshot(modelID, profileVersion), nil
}

func (r *countingProfileResolver) Calls(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[key]
}

func liveLikeProfileSnapshot(modelID, profileVersion string) chainclient.CurrentProfileSnapshot {
	version, _ := strconv.ParseUint(profileVersion, 10, 32)
	snapshot := chainclient.CurrentProfileSnapshot{
		ModelID:        modelID,
		ProfileVersion: chainclient.NewProfileVersion(uint32(version)),
		RuntimeClass:   defaultLocalRuntimeClass,
		RequiredTopK:   20,
	}
	snapshot.VerificationProfile.Metrics.ComparedTopK = 20
	// Mirror the live devnet profile: all four metrics compared, generated
	// special tokens scored, prompt and padding tokens excluded.
	snapshot.VerificationProfile.Metrics.CompareLogprobDiff = true
	snapshot.VerificationProfile.Metrics.CompareRankDelta = true
	snapshot.VerificationProfile.Metrics.CompareTopKJaccard = true
	snapshot.VerificationProfile.Metrics.CompareUnionJS = true
	snapshot.VerificationProfile.IncludeGeneratedSpecialTokens = true
	snapshot.VerificationProfile.TokenScope = "TOKEN_SCOPE_" + defaultLocalTokenScope
	// The thresholds the node's localnet genesis seed registers for this profile
	// (config/localnet_genesis_seed.json), in FP_1E6.
	snapshot.VerificationThresholds = chainclient.CurrentVerificationThresholdsSnapshot{
		PassMinFiniteCount:            16,
		PassMeanAbsLogprobDiffMax:     50000,
		PassAbsLogprobDiffP95Max:      100000,
		PassAbsLogprobDiffP99Max:      200000,
		PassRankDeltaNonzeroRateMax:   50000,
		PassTopKJaccardMeanMin:        900000,
		PassUnionJSP99Max:             50000,
		RejectMeanAbsLogprobDiffMin:   300000,
		RejectAbsLogprobDiffP95Min:    500000,
		RejectAbsLogprobDiffP99Min:    800000,
		RejectRankDeltaNonzeroRateMin: 300000,
		RejectTopKJaccardMeanMax:      600000,
		RejectUnionJSP99Min:           200000,
	}
	return snapshot
}

// Keeper has no message that edits a registered profile in place -- changing a
// parameter registers a new version -- so a resolved profile never needs
// re-fetching. Querying per Infer/Verify put an avoidable failure point on the
// task hot path: a Keeper blip mid-task lost the task.
func TestLocalServiceCachesResolvedProfilePerVersion(t *testing.T) {
	const servedModel = "Qwen/Qwen3-8B"
	modelID := localHuggingFaceModelID(servedModel)
	srv, _ := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{servedModel})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0, modelID)
	resolver := &countingProfileResolver{snapshot: liveLikeProfileSnapshot}
	svc.SetProfileResolver(resolver)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := svc.resolveLocalProfile(ctx, modelID, "1"); err != nil {
			t.Fatalf("resolveLocalProfile() error = %v", err)
		}
	}
	if got := resolver.Calls(modelID + "@1"); got != 1 {
		t.Fatalf("chain queries for one version = %d, want 1", got)
	}

	// A different version is a different profile and must be fetched.
	if _, err := svc.resolveLocalProfile(ctx, modelID, "2"); err != nil {
		t.Fatalf("resolveLocalProfile() error = %v", err)
	}
	if got := resolver.Calls(modelID + "@2"); got != 1 {
		t.Fatalf("chain queries for the new version = %d, want 1", got)
	}
	if got := resolver.Calls(modelID + "@1"); got != 1 {
		t.Fatalf("first version was re-fetched: %d queries", got)
	}
}

// A resolution that fails must not be cached, or one transient Keeper failure
// would permanently disable the model on this node.
func TestLocalServiceDoesNotCacheFailedProfileResolution(t *testing.T) {
	const servedModel = "Qwen/Qwen3-8B"
	modelID := localHuggingFaceModelID(servedModel)
	srv, _ := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{servedModel})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0, modelID)
	failing := &flakyProfileResolver{}
	svc.SetProfileResolver(failing)
	ctx := context.Background()

	if _, err := svc.resolveLocalProfile(ctx, modelID, "1"); err == nil {
		t.Fatal("resolveLocalProfile() error = nil, want the transient failure")
	}
	profile, err := svc.resolveLocalProfile(ctx, modelID, "1")
	if err != nil {
		t.Fatalf("resolveLocalProfile() error = %v after the resolver recovered", err)
	}
	if profile.RequiredTopK != 20 {
		t.Fatalf("required_top_k = %d, want the chain value once resolvable", profile.RequiredTopK)
	}
}

type flakyProfileResolver struct{ calls int }

func (r *flakyProfileResolver) ResolveLocalProfile(_ context.Context, modelID, profileVersion string) (chainclient.CurrentProfileSnapshot, error) {
	r.calls++
	if r.calls == 1 {
		return chainclient.CurrentProfileSnapshot{}, errors.New("keeper unavailable")
	}
	return liveLikeProfileSnapshot(modelID, profileVersion), nil
}

// supportedVerificationSnapshot is the one combination the local pipeline
// actually executes, and matches the live devnet profile.
func supportedVerificationSnapshot() chainclient.CurrentProfileSnapshot {
	return liveLikeProfileSnapshot("hf-model", "1")
}

// The metric and token-scope fields were copied into the local profile but
// never consumed, so a legal profile selecting a different combination was
// silently executed under the hardcoded rules. Diverging from the profile the
// chain records is worse than refusing it: the verifier recomputes against that
// profile, so a Worker applying different rules produces evidence judged
// inconsistent.
func TestLocalServiceRejectsUnimplementedVerificationRules(t *testing.T) {
	base := defaultQwenSingleSampleProfile("hf-model", "1", "Qwen/Qwen3-8B")
	if _, err := applyCurrentProfileSnapshot(base, supportedVerificationSnapshot()); err != nil {
		t.Fatalf("supported profile rejected: %v", err)
	}

	for _, testCase := range []struct {
		name  string
		want  string
		apply func(*chainclient.CurrentProfileSnapshot)
	}{
		{"logprob diff off", "compare_logprob_diff", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.Metrics.CompareLogprobDiff = false
		}},
		{"rank delta off", "compare_rank_delta", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.Metrics.CompareRankDelta = false
		}},
		{"topk jaccard off", "compare_topk_jaccard", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.Metrics.CompareTopKJaccard = false
		}},
		{"union js off", "compare_union_js", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.Metrics.CompareUnionJS = false
		}},
		{"generated special excluded", "include_generated_special_tokens", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.IncludeGeneratedSpecialTokens = false
		}},
		{"prompt tokens included", "include_prompt_tokens", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.IncludePromptTokens = true
		}},
		{"padding tokens included", "include_padding_tokens", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.IncludePaddingTokens = true
		}},
		{"other token scope", "token_scope", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationProfile.TokenScope = "TOKEN_SCOPE_ALL_PROMPT_TOKENS"
		}},
		{"missing tokens allowed", "pass_max_missing_compared_count", func(s *chainclient.CurrentProfileSnapshot) {
			s.VerificationThresholds.PassMaxMissingComparedCount = 2
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			snapshot := supportedVerificationSnapshot()
			testCase.apply(&snapshot)
			_, err := applyCurrentProfileSnapshot(base, snapshot)
			if err == nil {
				t.Fatalf("applyCurrentProfileSnapshot() error = nil, want %s rejected rather than silently executed under different rules", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to name %s", err, testCase.want)
			}
		})
	}
}

// A profile snapshot without verification thresholds used to keep the built-in
// defaults, a policy the chain never registered, and record it in the
// verification evidence. Node cannot judge such a profile either: its
// JudgeMetricSample refuses pass and reject bounds that overlap, which an
// all-zero set always does. Refusing the profile keeps the node from producing
// evidence under rules that exist only locally.
func TestLocalServiceRejectsProfileWithoutVerificationThresholds(t *testing.T) {
	base := defaultQwenSingleSampleProfile("hf-model", "1", "Qwen/Qwen3-8B")
	snapshot := supportedVerificationSnapshot()
	snapshot.VerificationThresholds = chainclient.CurrentVerificationThresholdsSnapshot{}

	_, err := applyCurrentProfileSnapshot(base, snapshot)
	if err == nil {
		t.Fatal("applyCurrentProfileSnapshot() error = nil, want a profile without thresholds refused rather than judged under built-in defaults")
	}
	if !strings.Contains(err.Error(), "verification_thresholds") {
		t.Fatalf("error = %v, want it to name verification_thresholds", err)
	}
}

// judgmentBoundaryThresholds gives every threshold a distinct value so a test
// can sit a metric exactly on one boundary at a time.
func judgmentBoundaryThresholds() singleSampleThresholds {
	return singleSampleThresholds{
		PassMinFiniteCount:          16,
		PassMeanAbsLogprobDiffMax:   0.018,
		PassAbsLogprobDiffP95Max:    0.100,
		PassAbsLogprobDiffP99Max:    0.200,
		PassRankMismatchRateMax:     0.025,
		PassTopKJaccardMeanMin:      0.935,
		PassUnionJSP99Max:           0.012,
		RejectMeanAbsLogprobDiffMin: 0.023,
		RejectAbsLogprobDiffP95Min:  0.130,
		RejectAbsLogprobDiffP99Min:  0.280,
		RejectRankMismatchRateMin:   0.040,
		RejectTopKJaccardMeanMax:    0.910,
		RejectUnionJSP99Min:         0.025,
	}
}

// passingMetricsAt returns metrics that pass, with finiteCount positions.
func passingMetricsAt(finiteCount int) singleSampleMetrics {
	jaccard, unionJS := 1.0, 0.0
	return singleSampleMetrics{
		FiniteCount:       finiteCount,
		ComparedRankCount: finiteCount,
		ComparedTopKCount: finiteCount,
		TopKJaccardMean:   &jaccard,
		UnionJSP99:        &unionJS,
	}
}

// JudgeMetricSample in x/task/types/metric_judgment.go evaluates reject
// thresholds inclusively. Cortex must match that, because the chain recomputes
// the verdict from the submitted MetricSummary and settlement takes a majority
// over those chain-computed verdicts.
func TestJudgmentBoundariesAreDefined(t *testing.T) {
	thresholds := judgmentBoundaryThresholds()

	// Pass thresholds are inclusive: exactly the minimum finite count passes.
	if verdict, _ := classifySingleSampleWithThresholds(passingMetricsAt(16), thresholds); verdict != verdictPassStrict {
		t.Fatalf("finite_count exactly at pass_min_finite_count = %s, want %s (the minimum that still passes)", verdict, verdictPassStrict)
	}
	if verdict, _ := classifySingleSampleWithThresholds(passingMetricsAt(15), thresholds); verdict == verdictPassStrict {
		t.Fatalf("finite_count below pass_min_finite_count = %s, want it not to pass", verdict)
	}

	// A metric exactly on a pass ceiling still passes.
	onCeiling := passingMetricsAt(16)
	onCeiling.MeanAbsLogprobDiff = thresholds.PassMeanAbsLogprobDiffMax
	if verdict, _ := classifySingleSampleWithThresholds(onCeiling, thresholds); verdict != verdictPassStrict {
		t.Fatalf("mean_abs_logprob_diff exactly at its pass ceiling = %s, want %s", verdict, verdictPassStrict)
	}

	// A metric exactly on a pass floor still passes.
	onFloor := passingMetricsAt(16)
	floor := thresholds.PassTopKJaccardMeanMin
	onFloor.TopKJaccardMean = &floor
	if verdict, _ := classifySingleSampleWithThresholds(onFloor, thresholds); verdict != verdictPassStrict {
		t.Fatalf("topk_jaccard_mean exactly at its pass floor = %s, want %s", verdict, verdictPassStrict)
	}

	// Reject thresholds are inclusive, matching the chain. A metric exactly on
	// the reject boundary rejects; one infinitesimally inside the pass band
	// does not.
	onRejectBoundary := passingMetricsAt(16)
	onRejectBoundary.MeanAbsLogprobDiff = thresholds.RejectMeanAbsLogprobDiffMin
	if verdict, _ := classifySingleSampleWithThresholds(onRejectBoundary, thresholds); verdict != verdictReject {
		t.Fatalf("mean_abs_logprob_diff exactly at its reject boundary = %s, want %s", verdict, verdictReject)
	}
	insidePassBand := passingMetricsAt(16)
	insidePassBand.MeanAbsLogprobDiff = thresholds.RejectMeanAbsLogprobDiffMin * 0.99
	if verdict, _ := classifySingleSampleWithThresholds(insidePassBand, thresholds); verdict != verdictInconclusive {
		t.Fatalf("mean_abs_logprob_diff slightly below its reject boundary = %s, want %s", verdict, verdictInconclusive)
	}
}

func TestFinishReasonV1FromString(t *testing.T) {
	cases := []struct {
		name    string
		reason  string
		want    nodewire.FinishReasonV1
		wantErr bool
	}{
		{"length", "length", nodewire.FinishReasonV1MaxOutputTokens, false},
		{"stop", "stop", nodewire.FinishReasonV1EosToken, false},
		{"STOP", "STOP", nodewire.FinishReasonV1EosToken, false},
		{"eos_token", "eos_token", nodewire.FinishReasonV1EosToken, false},
		{"stop_sequence", "stop_sequence", nodewire.FinishReasonV1StopSequence, false},
		{"max_output_duration", "max_output_duration", nodewire.FinishReasonV1MaxOutputDuration, false},
		{"empty", "", nodewire.FinishReasonV1Unspecified, true},
		{"whitespace", "   ", nodewire.FinishReasonV1Unspecified, true},
		{"unknown", "content_filter", nodewire.FinishReasonV1Unspecified, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := finishReasonV1FromString(tc.reason, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("finishReasonV1FromString(%q) error = %v, wantErr %v", tc.reason, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("finishReasonV1FromString(%q) = %v, want %v", tc.reason, got, tc.want)
			}
		})
	}
}

func TestFinishReasonV1FromStringRejectsAmbiguousStop(t *testing.T) {
	got, err := finishReasonV1FromString("stop", true)
	if err == nil {
		t.Fatalf("ambiguous stop should be rejected, got %v", got)
	}
}
