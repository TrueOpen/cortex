package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// The task's frozen generation parameters reach vLLM unchanged on both
// transports, and the output and token ids cover the whole generation.
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
				svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
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
				if !bytes.Equal(resp.GenerationParamsDigest, req.GenerationParamsDigest) || resp.GeneratedTokenCount != limit ||
					resp.FinishReason != nodewire.FinishReasonV1MaxOutputTokens {
					t.Fatalf("response = %+v, want the digest, %d tokens and MAX_OUTPUT_TOKENS", resp, limit)
				}
				output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
				if err != nil || string(output.Data) != strings.Repeat("x", int(limit)) {
					t.Fatalf("output truncated or fetch failed: %v", err)
				}
				ids, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TokenIDsRef})
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := DecodeTokenIDsArtifact(ids.Data)
				if err != nil || uint64(len(decoded.Generated)) != limit {
					t.Fatalf("token ids = %d generated, %v", len(decoded.Generated), err)
				}
			})
		}
	}
}

// A streamed generation keeps the terminal frame's stop metadata, and refuses
// frames after the finish or a conflicting second finish.
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
			svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
			g := localTestGeneration(testQwenModelID(), 1)
			g.Params.DecodingParams.StopSequences = []string{"END"}
			resp, err := svc.Infer(context.Background(), localGenerationInfer(t, g))
			if extra != "" {
				if err == nil {
					t.Fatal("invalid terminal stream accepted")
				}
				return
			}
			if err != nil || resp.GeneratedTokenCount != 1 || resp.FinishReason != nodewire.FinishReasonV1StopSequence {
				t.Fatalf("stop response = %+v, %v", resp, err)
			}
		})
	}
}

// A null stop_reason before the end cannot stand for the terminal frame's: a
// missing terminal stop is refused, an explicit terminal null is EOS.
func TestLocalGenerationStreamDistinguishesTerminalNullFromMissingStop(t *testing.T) {
	for _, terminalNull := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal_null=%t", terminalNull), func(t *testing.T) {
			frames := []completionResponse{streamFrame("hello", []int{10}, []float64{-.1}, nil, []int{1, 2, 3}, ""), streamFrame("", nil, nil, nil, nil, "stop")}
			frames[0].Choices[0].StopReason = json.RawMessage("null")
			if terminalNull {
				frames[1].Choices[0].StopReason = json.RawMessage("null")
			}
			srv, _ := newVLLMStreamStub(t, frames, verifyResponse(), []string{"Qwen/Qwen3-8B"})
			svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
			g := localTestGeneration(testQwenModelID(), 1)
			g.Params.DecodingParams.StopSequences = []string{"END"}
			resp, err := svc.Infer(context.Background(), localGenerationInfer(t, g))
			if !terminalNull {
				if err == nil || len(svc.artifacts) != 0 {
					t.Fatalf("missing terminal stop metadata accepted: err=%v", err)
				}
				return
			}
			if err != nil || resp.FinishReason != nodewire.FinishReasonV1EosToken {
				t.Fatalf("explicit terminal null rejected: reason=%v err=%v", resp.FinishReason, err)
			}
		})
	}
}

// localGenerationFinishReason derives the frozen reason from the engine's
// finish, stop_reason and count under the task's parameters.
func TestLocalGenerationFinishReasonMatrix(t *testing.T) {
	g := localTestGeneration(testQwenModelID(), 1)
	g.Params.MaxOutputTokens = 4
	g.Params.DecodingParams.StopSequences = []string{"END"}
	g.Params.DecodingParams.StopTokenIDs = []uint32{7}
	for _, tc := range []struct {
		reason, stop string
		count        uint64
		want         nodewire.FinishReasonV1
		ok           bool
	}{
		{"length", "", 4, nodewire.FinishReasonV1MaxOutputTokens, true},
		{"length", "", 3, 0, false},
		{"length", `"END"`, 4, 0, false},
		{"stop", "null", 2, nodewire.FinishReasonV1EosToken, true},
		{"stop", `"END"`, 2, nodewire.FinishReasonV1StopSequence, true},
		{"stop", `"OTHER"`, 2, 0, false},
		{"stop", "7", 2, nodewire.FinishReasonV1StopToken, true},
		{"stop", "8", 2, 0, false}, // a secondary model EOS id needs output_decoding to say so
		{"stop", `"8"`, 2, 0, false},
		{"eos_token", "7", 2, 0, false},
		{"stop_sequence", "", 2, 0, false},
		{"stop", "null", 5, 0, false},
		{"max_output_duration", "", 2, nodewire.FinishReasonV1MaxOutputDuration, true},
		{"max_output_duration", "", 0, nodewire.FinishReasonV1MaxOutputDuration, true},
		{"max_output_duration", "", 4, 0, false},
		{"max_output_duration", `"END"`, 2, 0, false},
	} {
		got, err := localGenerationFinishReason(g, modelmanifest.OutputDecoding{}, tc.reason, json.RawMessage(tc.stop), tc.count)
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Fatalf("%s/%s/%d = %v, %v; want %v ok=%t", tc.reason, tc.stop, tc.count, got, err, tc.want, tc.ok)
		}
	}
}

// Streaming is a node-local transport detail: the committed output, token ids
// and position values are byte-identical to the non-streamed ones, for the
// completions and the chat paths.
func TestLocalStreamingMatchesNonStreamingMaterial(t *testing.T) {
	material := func(t *testing.T, svc *LocalService, req InferRequest) [3][]byte {
		t.Helper()
		resp, err := svc.Infer(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		var out [3][]byte
		for i, ref := range []string{resp.OutputRef, resp.TokenIDsRef, resp.PositionValuesRef} {
			artifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: ref, AllowEmpty: true})
			if err != nil {
				t.Fatal(err)
			}
			out[i] = artifact.Data
		}
		return out
	}
	t.Run("completions", func(t *testing.T) {
		plainSrv, _ := newVLLMStub(t, genResponse(), verifyResponse())
		plain := newBoundLocalService(plainSrv.URL, "local", 4, 0, 0)
		plain.SetStreamInference(false)
		streamSrv, _ := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
		streamed := newBoundLocalService(streamSrv.URL, "local", 4, 0, 0)
		req := boundLocalInferFixture(t, InferRequest{RequestID: "parity", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi")})
		if a, b := material(t, plain, req), material(t, streamed, req); !reflect.DeepEqual(a, b) {
			t.Fatalf("streamed material differs from non-streamed:\n%x\n%x", a, b)
		}
	})
	t.Run("chat", func(t *testing.T) {
		plainSrv, _ := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
		plain := newBoundLocalService(plainSrv.URL, "local", 4, 0, 0)
		plain.SetStreamInference(false)
		streamSrv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
		streamed := newBoundLocalService(streamSrv.URL, "local", 4, 0, 0)
		if a, b := material(t, plain, chatInferReq(t)), material(t, streamed, chatInferReq(t)); !reflect.DeepEqual(a, b) {
			t.Fatalf("streamed chat material differs from non-streamed:\n%x\n%x", a, b)
		}
	})
}

// A chat stream still generating when max_output_duration expires ends as a
// successful MAX_OUTPUT_DURATION with the tokens that arrived.
func TestLocalServiceChatStopsAtMaxOutputDurationAsSuccess(t *testing.T) {
	chunks := chatContentChunks()[:2]
	chunks[1].Choices[0].FinishReason = ""
	srv := newSlowChatStreamStub(t, chunks, 150*time.Millisecond, []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	req := chatInferReq(t)
	req.Generation.Params.MaxOutputDuration = 200
	digest, err := req.Generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.GenerationParamsDigest = digest[:]
	resp, err := svc.Infer(context.Background(), req)
	if err != nil {
		t.Fatalf("Infer() error = %v, want a successful truncation", err)
	}
	if resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration || resp.GeneratedTokenCount == 0 ||
		resp.GeneratedTokenCount >= req.Generation.Params.MaxOutputTokens {
		t.Fatalf("response = %+v, want a MAX_OUTPUT_DURATION stop below the token ceiling", resp)
	}
	ids, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TokenIDsRef})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTokenIDsArtifact(ids.Data)
	if err != nil || uint64(len(decoded.Generated)) != resp.GeneratedTokenCount {
		t.Fatalf("token ids cover %d tokens, response counts %d (%v)", len(decoded.Generated), resp.GeneratedTokenCount, err)
	}
}

// A failed profile resolution is not cached: the next call resolves again.
func TestLocalServiceDoesNotCacheFailedProfileResolution(t *testing.T) {
	srv, _ := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetOutputDecodingSource(testOutputDecodingSource())
	svc.SetProfileResolver(&flakyProfileResolver{})
	ctx := context.Background()
	if _, err := svc.resolveLocalProfile(ctx, testQwenModelID(), "1"); err == nil {
		t.Fatal("resolveLocalProfile() error = nil, want the transient failure")
	}
	profile, err := svc.resolveLocalProfile(ctx, testQwenModelID(), "1")
	if err != nil || profile.RequiredTopK != 20 {
		t.Fatalf("resolveLocalProfile() = %d, %v after the resolver recovered", profile.RequiredTopK, err)
	}
}

// A budget that expires before the engine emits a token ends as a successful
// zero-token MAX_OUTPUT_DURATION generation, which the protocol allows.
func TestLocalGenerationZeroTokenDurationStop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 2; i++ {
			frame := `{"choices":[{"text":"","prompt_token_ids":[1,2,3],"token_ids":[]}]}`
			if i > 0 {
				frame = `{"choices":[{"text":"","token_ids":[]}]}`
			}
			fmt.Fprintf(w, "data: %s\n\n", frame)
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(150 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()
	svc := newBoundLocalService(srv.URL, "local", 4, 0, 0)
	g := localTestGeneration(testQwenModelID(), 1)
	g.Params.MaxOutputDuration = 50
	resp, err := svc.Infer(context.Background(), localGenerationInfer(t, g))
	if err != nil {
		t.Fatalf("zero-token duration stop = %v, want success", err)
	}
	if resp.GeneratedTokenCount != 0 || resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration {
		t.Fatalf("response = %+v, want zero tokens and MAX_OUTPUT_DURATION", resp)
	}
	if err := ValidateFinishReason(g, nil, resp.FinishReason); err != nil {
		t.Fatalf("the Worker's finish check refuses what the local path produced: %v", err)
	}
}
