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
		k := defaultTopK
		if req.Logprobs != nil {
			k = *req.Logprobs
		}
		_ = json.NewEncoder(w).Encode(withTopK(gen, k))
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
		ModelID:    FakeModelID,
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
	var _ Client = newBoundLocalService("", "svc", 4, 0, 0)
}

func TestLocalServiceHealthCallsVLLMHealthEndpoint(t *testing.T) {
	seen := false
	srv := newHealthStub(t, http.StatusOK, "", &seen)
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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

	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 50*time.Millisecond)
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

	svc := newBoundLocalService(srv.URL, "local-svc", 4, 50*time.Millisecond, 0)
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

func TestLocalServiceListCapabilitiesUnavailableIsRetryable(t *testing.T) {
	srv := newModelsStub(t, http.StatusServiceUnavailable, nil, "warming up", nil)
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

	_, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err == nil || !IsRetryable(err) {
		t.Fatalf("ListCapabilities() error = %v, want retryable error", err)
	}
}

func TestLocalServiceListCapabilitiesUsesGeneratedSystemModelIDAfterLoadModel(t *testing.T) {
	srv := newMetadataStub(t, []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

	_, err := svc.LoadModel(context.Background(), LoadModelRequest{RequestID: "load-1", ModelID: "model-random", Capability: CapabilityLLMTextV1})
	if err == nil || !strings.Contains(err.Error(), "is not bound to a repository") {
		t.Fatalf("LoadModel() error = %v, want explicit mapping failure", err)
	}
}

// testQwenModelID is the Hash32 model id, as canonical hex, the local tests
// bind to the served repository Qwen/Qwen3-8B.
func testQwenModelID() string {
	return "ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"
}

func TestLocalServiceHTTPUnavailableIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "warming up", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	_, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi")}))
	if err == nil || !IsRetryable(err) {
		t.Fatalf("Infer() error = %v, want retryable error", err)
	}
}

type staticLocalProfileResolver struct {
	profile chainclient.CurrentProfileSnapshot
}

func (r staticLocalProfileResolver) ResolveLocalProfile(context.Context, string, string) (chainclient.CurrentProfileSnapshot, error) {
	return r.profile, nil
}

func TestLocalServiceMetadataEndpoints(t *testing.T) {
	srv := newMetadataStub(t, []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 8, 0, 0)

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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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
			svc := newBoundLocalService(testCase.srv.URL, "local-svc", 4, 0, 0)
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

// With several served models the mapping is a guess, and binding a chain id to
// the wrong weights is worse than not being selected.
// With several models served, only the chain-bound model id is advertised;
// nothing is derived for the other served model, and an unbound service
// advertises none at all.
func TestLocalServiceDoesNotGuessModelIDWhenSeveralAreServed(t *testing.T) {
	srv := newMultiModelStub(t, []string{"Qwen/Qwen3-8B", "meta-llama/Llama-3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 8, 0, 0)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != testQwenModelID() {
		t.Fatalf("Capabilities = %+v, want only the bound model id", resp.Capabilities)
	}
	unbound := NewLocalService(srv.URL, "local-svc", 8, 0, 0)
	resp, err = unbound.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-2"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 0 {
		t.Fatalf("unbound Capabilities = %+v, want none guessed from the served names", resp.Capabilities)
	}
}

func TestLocalServiceDeduplicatesConfiguredModelIDs(t *testing.T) {
	srv := newCapacityStub(t, 0, 0, false)
	modelID := testQwenModelID()
	svc := newBoundLocalService(srv.URL, "local-svc", 8, 0, 0)

	resp, err := svc.ListCapabilities(context.Background(), ListCapabilitiesRequest{RequestID: "caps-1"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(resp.Capabilities) != 1 || resp.Capabilities[0].ModelID != modelID {
		t.Fatalf("Capabilities = %+v, want the single deduplicated configured model", resp.Capabilities)
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
	manifestHash := testManifestHash()
	snapshot := chainclient.CurrentProfileSnapshot{
		ModelID: modelID,
		// Infer on a chain-resolved profile is refused without an
		// output_decoding from a manifest that hashes to this, so a test that
		// installs a resolver and calls Infer also installs
		// testOutputDecodingSource.
		ManifestHash:   chainclient.ProtoBytes32(manifestHash[:]),
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

// liveLikeProfileSnapshotWithTopK is liveLikeProfileSnapshot with another
// required_top_k.
func liveLikeProfileSnapshotWithTopK(k uint32) func(string, string) chainclient.CurrentProfileSnapshot {
	return func(modelID, profileVersion string) chainclient.CurrentProfileSnapshot {
		snapshot := liveLikeProfileSnapshot(modelID, profileVersion)
		snapshot.RequiredTopK, snapshot.VerificationProfile.Metrics.ComparedTopK = k, k
		return snapshot
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
