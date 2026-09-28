package modelservice

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

func localTestGeneration(model string, profile uint32) *nodewire.GenerationContext {
	return &nodewire.GenerationContext{ModelID: model, ProfileVersion: profile, TaskType: 1, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 128, MaxOutputDuration: 60000,
			DecodingParams: nodewire.DecodingParamsV1{TopPPPM: 1000000, RepetitionPenaltyPPM: 1000000}}}
}

func boundLocalInferFixture(t *testing.T, req InferRequest) InferRequest {
	t.Helper()
	if req.ProfileVersion == "" {
		req.ProfileVersion = "1"
	}
	profile, err := strconv.ParseUint(req.ProfileVersion, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	req.Generation = localTestGeneration(req.ModelID, uint32(profile))
	digest, err := req.Generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.GenerationParamsDigest = digest[:]
	return req
}

func boundLocalVerifyFixture(t *testing.T, req VerifyRequest) VerifyRequest {
	t.Helper()
	bound := boundLocalInferFixture(t, InferRequest{ModelID: req.ModelID, ProfileVersion: req.ProfileVersion})
	req.ProfileVersion, req.Generation, req.GenerationParamsDigest = bound.ProfileVersion, bound.Generation, bound.GenerationParamsDigest
	return req
}

func localGenerationInfer(t *testing.T, g *nodewire.GenerationContext) InferRequest {
	t.Helper()
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return InferRequest{ModelID: g.ModelID, ProfileVersion: fmt.Sprint(g.ProfileVersion), Capability: CapabilityLLMTextV1,
		Input: []byte("hi"), Generation: g, GenerationParamsDigest: digest[:]}
}

func localGenerationServer(t *testing.T, reply map[string]any, captured *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
			return
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		*captured = request
		if request["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			payload, _ := json.Marshal(reply)
			fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", payload)
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func localGenerationReply(count int, finish string, stop any) map[string]any {
	ids, probs, top := make([]int, count), make([]float64, count), make([]TopLogprobRow, count)
	for i := range ids {
		ids[i], probs[i] = 10+i, -0.1
		top[i] = fullTopRow(TopLogprob{Token: fmt.Sprintf("token_id:%d", ids[i]), Logprob: probs[i]})
	}
	return map[string]any{"choices": []map[string]any{{"text": strings.Repeat("x", count), "finish_reason": finish,
		"stop_reason": stop, "prompt_token_ids": []int{1, 2, 3}, "token_ids": ids,
		"logprobs": map[string]any{"token_logprobs": probs, "top_logprobs": top}}}}
}

func TestLocalGenerationRejectsMissingAndMismatchedContext(t *testing.T) {
	for _, mutate := range []func(*InferRequest){func(r *InferRequest) { r.Generation = nil }, func(r *InferRequest) { r.GenerationParamsDigest[0] ^= 1 }, func(r *InferRequest) { r.ModelID = "wrong" }, func(r *InferRequest) { r.ProfileVersion = "2" }} {
		var captured map[string]any
		srv := localGenerationServer(t, localGenerationReply(2, "stop", nil), &captured)
		svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
		req := localGenerationInfer(t, localTestGeneration(testQwenModelID(), 1))
		mutate(&req)
		if _, err := svc.Infer(context.Background(), req); err == nil {
			t.Error("invalid generation context accepted")
		}
		if captured != nil {
			t.Error("invalid generation reached engine")
		}
	}
}

func TestLocalGenerationRejectsBackendOverflow(t *testing.T) {
	for _, mutate := range []func(*nodewire.GenerationContext){
		func(g *nodewire.GenerationContext) { g.Params.MaxOutputTokens = math.MaxUint64 },
		func(g *nodewire.GenerationContext) { g.Params.MaxOutputDuration = math.MaxUint64 },
		func(g *nodewire.GenerationContext) { g.Params.DecodingParams.Seed = math.MaxUint64 },
		func(g *nodewire.GenerationContext) { g.Params.DecodingParams.StopSequences = []string{""} },
		func(g *nodewire.GenerationContext) {
			g.Params.DecodingParams.SamplingEnabled = true
			g.Params.DecodingParams.TemperatureMilli = 1
		},
	} {
		g := localTestGeneration(testQwenModelID(), 1)
		mutate(g)
		var captured map[string]any
		srv := localGenerationServer(t, localGenerationReply(2, "stop", nil), &captured)
		svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
		if _, err := svc.Infer(context.Background(), localGenerationInfer(t, g)); err == nil {
			t.Error("unsupported backend value accepted")
		}
		if captured != nil {
			t.Error("unsupported value reached engine")
		}
	}
}

func TestLocalGenerationPreservesZeroAndGreedy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		g := localTestGeneration(testQwenModelID(), 1)
		g.Params.DecodingParams.SamplingEnabled = enabled
		if !enabled {
			g.Params.DecodingParams.TemperatureMilli = 900
		}
		var captured map[string]any
		srv := localGenerationServer(t, localGenerationReply(2, "stop", nil), &captured)
		_, err := newBoundLocalService(srv.URL, "local", 4, 0, 0).Infer(context.Background(), localGenerationInfer(t, g))
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"temperature", "top_k", "seed", "presence_penalty", "frequency_penalty"} {
			if captured[field] != float64(0) {
				t.Errorf("%s = %v, want explicit 0", field, captured[field])
			}
		}
	}
}

func TestLocalGenerationDeadlineDoesNotPublishPartialOutput(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, bound := range []string{"generation", "rpc", "caller"} {
			t.Run(fmt.Sprintf("%s/stream=%t", bound, streaming), func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/models" {
						_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
						return
					}
					if streaming {
						w.Header().Set("Content-Type", "text/event-stream")
						payload, _ := json.Marshal(localGenerationReply(1, "", nil))
						fmt.Fprintf(w, "data: %s\n\n", payload)
						w.(http.Flusher).Flush()
					}
					select {
					case <-r.Context().Done():
					case <-time.After(100 * time.Millisecond):
					}
				}))
				defer srv.Close()
				g := localTestGeneration(testQwenModelID(), 1)
				if bound == "generation" {
					g.Params.MaxOutputDuration = 20
				}
				req := localGenerationInfer(t, g)
				if bound == "rpc" {
					req.DeadlineMS = time.Now().Add(20 * time.Millisecond).UnixMilli()
				}
				ctx := context.Background()
				if bound == "caller" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
					defer cancel()
				}
				svc := newBoundLocalService(srv.URL, "local", 4, time.Second, 0)
				svc.SetStreamInference(streaming)
				if _, err := svc.Infer(ctx, req); err == nil {
					t.Fatal("partial completion succeeded")
				}
				if len(svc.artifacts) != 0 {
					t.Fatal("partial completion published artifacts")
				}
			})
		}
	}
}

func TestLocalGenerationDoesNotContaminateProfileCache(t *testing.T) {
	srv, seen := newVLLMStub(t, genResponse(), verifyResponse())
	svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
	resolver := &countingProfileResolver{snapshot: liveLikeProfileSnapshot}
	svc.SetManifestSource(testManifestSource())
	svc.SetProfileResolver(resolver)
	for i, limit := range []uint64{8, 1024, 128} {
		g := localTestGeneration(testQwenModelID(), 1)
		g.Params.MaxOutputTokens = limit
		g.Params.DecodingParams.Seed = uint64(i)
		if _, err := svc.Infer(context.Background(), localGenerationInfer(t, g)); err != nil {
			t.Fatal(err)
		}
		if (*seen)[i].MaxTokens != int(limit) || *(*seen)[i].Seed != i {
			t.Fatal("task parameters contaminated a cached profile")
		}
	}
	if resolver.Calls(testQwenModelID()+"@1") != 1 {
		t.Fatal("test did not exercise shared cached profile")
	}
}
