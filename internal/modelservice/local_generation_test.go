package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	ids, probs := make([]int, count), make([]float64, count)
	for i := range ids {
		ids[i], probs[i] = 10+i, -0.1
	}
	return map[string]any{"choices": []map[string]any{{"text": strings.Repeat("x", count), "finish_reason": finish,
		"stop_reason": stop, "prompt_token_ids": []int{1, 2, 3}, "token_ids": ids,
		"logprobs": map[string]any{"token_logprobs": probs}}}}
}

func TestLocalGenerationAppliesTaskParameters(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, limit := range []uint64{8, 128, 1024} {
			t.Run(fmt.Sprintf("stream=%t/max=%d", streaming, limit), func(t *testing.T) {
				g := localTestGeneration(testQwenModelID(), 1)
				g.Params.MaxOutputTokens = limit
				g.Params.DecodingParams = nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 750, TopPPPM: 825000,
					TopK: 23, Seed: 47, PresencePenaltyMilli: -250, FrequencyPenaltyMilli: 500,
					RepetitionPenaltyPPM: 1125000, StopSequences: []string{"END", "STOP"}, StopTokenIDs: []uint32{99, 100}}
				var captured map[string]any
				srv := localGenerationServer(t, localGenerationReply(int(limit), "length", nil), &captured)
				svc := NewLocalService(srv.URL, "local", 4, 0, 0)
				svc.SetStreamInference(streaming)
				req := localGenerationInfer(t, g)
				resp, err := svc.Infer(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				want := map[string]any{"max_tokens": float64(limit), "temperature": .75, "top_p": .825, "top_k": float64(23),
					"seed": float64(47), "presence_penalty": -.25, "frequency_penalty": .5, "repetition_penalty": 1.125,
					"stop": []any{"END", "STOP"}, "stop_token_ids": []any{float64(99), float64(100)}, "stream": streaming}
				for field, value := range want {
					if !reflect.DeepEqual(captured[field], value) {
						t.Errorf("%s = %#v, want %#v", field, captured[field], value)
					}
				}
				if !bytes.Equal(resp.GenerationParamsDigest, req.GenerationParamsDigest) {
					t.Error("applied generation digest missing/mismatched")
				}
				if resp.GeneratedTokenCount != limit {
					t.Fatalf("generated count = %d, want %d", resp.GeneratedTokenCount, limit)
				}
				output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
				if err != nil || string(output.Data) != strings.Repeat("x", int(limit)) {
					t.Fatalf("output truncated or fetch failed: %v", err)
				}
				for _, ref := range []string{resp.TraceRef, resp.CheckpointRef} {
					artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: ref})
					if err != nil {
						t.Fatal(err)
					}
					var envelope struct {
						Generation *nodewire.GenerationContext `json:"generation_context"`
					}
					if err := json.Unmarshal(artifact.Data, &envelope); err != nil || !reflect.DeepEqual(envelope.Generation, g) {
						t.Errorf("evidence lost generation context: %v", err)
					}
				}
			})
		}
	}
}

func TestLocalGenerationRejectsMissingAndMismatchedContext(t *testing.T) {
	for _, mutate := range []func(*InferRequest){func(r *InferRequest) { r.Generation = nil }, func(r *InferRequest) { r.GenerationParamsDigest[0] ^= 1 }, func(r *InferRequest) { r.ModelID = "wrong" }, func(r *InferRequest) { r.ProfileVersion = "2" }} {
		var captured map[string]any
		srv := localGenerationServer(t, localGenerationReply(2, "stop", nil), &captured)
		svc := NewLocalService(srv.URL, "local", 4, 0, 0)
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
		svc := NewLocalService(srv.URL, "local", 4, 0, 0)
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
		_, err := NewLocalService(srv.URL, "local", 4, 0, 0).Infer(context.Background(), localGenerationInfer(t, g))
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

func TestLocalGenerationValidatesCompletion(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, tc := range []struct {
			name, finish string
			count        int
			stop         any
			stops        []string
			stopIDs      []uint32
			omitStop     bool
			want         nodewire.FinishReasonV1
			invalid      bool
		}{
			{name: "overrun", finish: "length", count: 9, invalid: true},
			{name: "premature length", finish: "length", count: 2, invalid: true},
			{name: "missing finish", count: 2, invalid: true},
			{name: "ambiguous stop", finish: "stop", count: 2, stops: []string{"END"}, omitStop: true, invalid: true},
			{name: "null eos with stop sequences", finish: "stop", count: 2, stops: []string{"END"}, want: nodewire.FinishReasonV1EosToken},
			{name: "null eos with stop ids", finish: "stop", count: 2, stopIDs: []uint32{11}, want: nodewire.FinishReasonV1EosToken},
			{name: "unknown stop string", finish: "stop", count: 2, stop: "OTHER", stops: []string{"END"}, invalid: true},
			{name: "sequence", finish: "stop", count: 2, stop: "END", stops: []string{"END"}, want: nodewire.FinishReasonV1StopSequence},
			{name: "unsupported token stop", finish: "stop", count: 2, stop: 11, stopIDs: []uint32{11}, invalid: true},
			{name: "eos", finish: "stop", count: 2, want: nodewire.FinishReasonV1EosToken},
			{name: "explicit eos with stops", finish: "eos_token", count: 2, stops: []string{"END"}, want: nodewire.FinishReasonV1EosToken},
		} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, streaming), func(t *testing.T) {
				g := localTestGeneration(testQwenModelID(), 1)
				g.Params.MaxOutputTokens = 8
				g.Params.DecodingParams.StopSequences, g.Params.DecodingParams.StopTokenIDs = tc.stops, tc.stopIDs
				var captured map[string]any
				reply := localGenerationReply(tc.count, tc.finish, tc.stop)
				if tc.omitStop {
					delete(reply["choices"].([]map[string]any)[0], "stop_reason")
				}
				srv := localGenerationServer(t, reply, &captured)
				svc := NewLocalService(srv.URL, "local", 4, 0, 0)
				svc.SetStreamInference(streaming)
				resp, err := svc.Infer(context.Background(), localGenerationInfer(t, g))
				if tc.invalid {
					if err == nil {
						t.Fatal("invalid completion accepted")
					}
					if len(svc.artifacts) != 0 {
						t.Fatal("invalid completion published artifacts")
					}
					return
				}
				if err != nil || resp.FinishReason != tc.want {
					t.Fatalf("finish = %v, err = %v", resp.FinishReason, err)
				}
				output, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
				trace, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TraceRef})
				checkpoint, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.CheckpointRef})
				count, finish, err := ValidateGenerationEvidence(g, resp.GenerationParamsDigest, output.Data, trace.Data, checkpoint.Data)
				if err != nil || count != uint64(tc.count) || finish != tc.want {
					t.Fatalf("completion evidence = %d/%v, %v", count, finish, err)
				}
			})
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
				svc := NewLocalService(srv.URL, "local", 4, time.Second, 0)
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

func TestLocalGenerationVerifyBindsEvidence(t *testing.T) {
	for _, part := range []string{"valid", "request missing", "request digest", "request deadline", "trace missing", "trace params", "checkpoint missing", "checkpoint params", "checkpoint count", "trace count"} {
		t.Run(part, func(t *testing.T) {
			generated := genResponse()
			generated.Choices[0].FinishReason = "stop"
			srv, seen := newVLLMStub(t, generated, verifyResponse())
			svc := NewLocalService(srv.URL, "local", 4, 0, 0)
			g := localTestGeneration(testQwenModelID(), 1)
			g.Params.DecodingParams.PresencePenaltyMilli = 500
			g.Params.DecodingParams.FrequencyPenaltyMilli = -250
			g.Params.DecodingParams.RepetitionPenaltyPPM = 1250000
			req := localGenerationInfer(t, g)
			infer, err := svc.Infer(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			trace, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: infer.TraceRef})
			checkpoint, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: infer.CheckpointRef})
			verifyReq := VerifyRequest{ModelID: req.ModelID, ProfileVersion: req.ProfileVersion, Capability: req.Capability,
				Generation: req.Generation, GenerationParamsDigest: req.GenerationParamsDigest, Sample: []byte("sample")}
			if part == "request missing" {
				verifyReq.Generation = nil
			}
			if part == "request digest" {
				verifyReq.GenerationParamsDigest = []byte("wrong")
			}
			if part == "request deadline" {
				verifyReq.DeadlineMS = time.Now().Add(-time.Second).UnixMilli()
			}
			if strings.HasPrefix(part, "trace ") || strings.HasPrefix(part, "checkpoint ") {
				data := &trace.Data
				if strings.HasPrefix(part, "checkpoint ") {
					data = &checkpoint.Data
				}
				var env map[string]any
				if err := json.Unmarshal(*data, &env); err != nil {
					t.Fatal(err)
				}
				switch {
				case strings.HasSuffix(part, "missing"):
					delete(env, "generation_context")
				case strings.HasSuffix(part, "params"):
					env["generation_context"].(map[string]any)["generation_params"].(map[string]any)["max_output_tokens"] = 99
				case strings.HasSuffix(part, "count"):
					env["generated_token_count"] = 129
				}
				*data, _ = json.Marshal(env)
			}
			verifyReq.Evidence = map[string]VerifyEvidence{EvidenceKindWorkerValueOpening: {Trace: trace.Data, Checkpoint: checkpoint.Data}}
			resp, err := svc.Verify(context.Background(), verifyReq)
			if part != "valid" {
				if err == nil {
					t.Fatal("tampered generation evidence accepted")
				}
				if len(*seen) != 1 {
					t.Fatal("invalid verification reached engine")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(resp.GenerationParamsDigest, req.GenerationParamsDigest) {
				t.Error("verification digest missing")
			}
			if len(*seen) != 2 || (*seen)[1].MaxTokens != 1 || (*seen)[1].PromptLogprobs == nil {
				t.Fatal("token-ID prefill contract changed")
			}
			if (*seen)[1].RepetitionPenalty != 1 || (*seen)[1].PresencePenalty != 0 || (*seen)[1].FrequencyPenalty != 0 {
				t.Fatal("prefill request changes raw metric semantics")
			}
		})
	}
}

func TestGenerationContextFromTrace(t *testing.T) {
	for _, invalid := range []string{`{}`, `{"generation_context":null}`, `{"generation_context":{}}`, `{"generation_context":"corrupt"}`, `{`} {
		if _, err := GenerationContextFromTrace([]byte(invalid)); err == nil {
			t.Errorf("invalid trace accepted: %s", invalid)
		}
	}
	g := localTestGeneration(testQwenModelID(), 1)
	g.Params.DecodingParams.StopSequences = []string{"STOP"}
	data, _ := json.Marshal(map[string]any{"generation_context": g})
	extracted, err := GenerationContextFromTrace(data)
	if err != nil || !reflect.DeepEqual(g, extracted) {
		t.Fatalf("extract = %+v, %v", extracted, err)
	}
	extracted.Params.DecodingParams.StopSequences[0] = "changed"
	again, err := GenerationContextFromTrace(data)
	if err != nil || again.Params.DecodingParams.StopSequences[0] != "STOP" {
		t.Fatal("extraction aliases retained state")
	}
}

func TestLocalGenerationDoesNotContaminateProfileCache(t *testing.T) {
	srv, seen := newVLLMStub(t, genResponse(), verifyResponse())
	svc := NewLocalService(srv.URL, "local", 4, 0, 0)
	resolver := &countingProfileResolver{snapshot: liveLikeProfileSnapshot}
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

func TestLocalGenerationStreamRetainsTerminalStopMetadata(t *testing.T) {
	for _, extra := range []string{"", "after finish", "conflicting finish"} {
		t.Run(extra, func(t *testing.T) {
			frames := []completionResponse{streamFrame("hello", []int{10}, []float64{-.1}, nil, []int{1, 2, 3}, ""), streamFrame("", nil, nil, nil, nil, "stop")}
			frames[1].Choices[0].StopReason = json.RawMessage(`"END"`)
			if extra == "after finish" {
				frames = append(frames, streamFrame("more", []int{11}, []float64{-.2}, nil, nil, ""))
			}
			if extra == "conflicting finish" {
				frames = append(frames, streamFrame("", nil, nil, nil, nil, "length"))
			}
			srv, _ := newVLLMStreamStub(t, frames, verifyResponse(), []string{"Qwen/Qwen3-8B"})
			svc := NewLocalService(srv.URL, "local", 4, 0, 0)
			g := localTestGeneration(testQwenModelID(), 1)
			g.Params.DecodingParams.StopSequences = []string{"END"}
			req := localGenerationInfer(t, g)
			resp, err := svc.Infer(context.Background(), req)
			if extra != "" {
				if err == nil {
					t.Fatal("invalid terminal stream accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			output, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
			trace, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TraceRef})
			checkpoint, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.CheckpointRef})
			count, finish, err := ValidateGenerationEvidence(g, req.GenerationParamsDigest, output.Data, trace.Data, checkpoint.Data)
			if err != nil || count != 1 || finish != nodewire.FinishReasonV1StopSequence {
				t.Fatalf("stop evidence = %d/%v, %v", count, finish, err)
			}
		})
	}
}

func TestLocalGenerationStreamDistinguishesTerminalNullFromMissingStop(t *testing.T) {
	for _, terminalNull := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal_null=%t", terminalNull), func(t *testing.T) {
			frames := []completionResponse{streamFrame("hello", []int{10}, []float64{-.1}, nil, []int{1, 2, 3}, ""), streamFrame("", nil, nil, nil, nil, "stop")}
			// vLLM can send null before generation terminates. That value alone
			// cannot authenticate how a later terminal frame stopped.
			frames[0].Choices[0].StopReason = json.RawMessage("null")
			if terminalNull {
				frames[1].Choices[0].StopReason = json.RawMessage("null")
			}
			srv, _ := newVLLMStreamStub(t, frames, verifyResponse(), []string{"Qwen/Qwen3-8B"})
			svc := NewLocalService(srv.URL, "local", 4, 0, 0)
			g := localTestGeneration(testQwenModelID(), 1)
			g.Params.DecodingParams.StopSequences = []string{"END"}
			req := localGenerationInfer(t, g)
			resp, err := svc.Infer(context.Background(), req)
			if !terminalNull {
				if err == nil || len(svc.artifacts) != 0 {
					t.Fatalf("missing terminal stop metadata accepted: err=%v", err)
				}
				return
			}
			if err != nil || resp.FinishReason != nodewire.FinishReasonV1EosToken {
				t.Fatalf("explicit terminal null rejected: reason=%v err=%v", resp.FinishReason, err)
			}
			for _, ref := range []string{resp.TraceRef, resp.CheckpointRef} {
				artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: ref})
				if err != nil {
					t.Fatal(err)
				}
				var env traceEnvelope
				if err := json.Unmarshal(artifact.Data, &env); err != nil || !bytes.Equal(env.StopReason, []byte("null")) {
					t.Fatalf("artifact lost explicit null: stop=%q err=%v", env.StopReason, err)
				}
			}
		})
	}
}

func TestValidateGenerationEvidenceRejectsTampering(t *testing.T) {
	srv, _ := newVLLMStub(t, genResponse(), verifyResponse())
	svc := NewLocalService(srv.URL, "local", 4, 0, 0)
	req := localGenerationInfer(t, localTestGeneration(testQwenModelID(), 1))
	resp, err := svc.Infer(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	output, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	trace, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TraceRef})
	checkpoint, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.CheckpointRef})
	for _, field := range []string{"output", "model_id", "profile_version", "input_token_ids_hash", "generated_token_ids_hash", "out_tokens", "finish_reason", "stop_reason"} {
		t.Run(field, func(t *testing.T) {
			var env map[string]any
			_ = json.Unmarshal(trace.Data, &env)
			if field == "out_tokens" {
				env[field] = []any{}
			} else {
				env[field] = "tampered"
			}
			changed, _ := json.Marshal(env)
			if _, _, err := ValidateGenerationEvidence(req.Generation, req.GenerationParamsDigest, output.Data, changed, checkpoint.Data); err == nil {
				t.Fatal("tampered evidence accepted")
			}
		})
	}
	if _, _, err := ValidateGenerationEvidence(req.Generation, req.GenerationParamsDigest, []byte("tampered"), trace.Data, checkpoint.Data); err == nil {
		t.Fatal("tampered output accepted")
	}
}
