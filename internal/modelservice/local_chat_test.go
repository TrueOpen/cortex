package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// newChatVLLMStub emulates vLLM's /v1/chat/completions (plus /v1/models and
// /metrics so model resolution and capacity reads work). It records the requests
// it received so a test can assert the Cortex-pinned fields.
func newChatVLLMStub(t *testing.T, resp chatCompletionResponse, models []string) (*httptest.Server, *[]chatCompletionRequest) {
	t.Helper()
	var seen []chatCompletionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			writeVLLMMetrics(w, 0, 0)
			return
		}
		if r.URL.Path == "/v1/models" {
			data := make([]map[string]any, 0, len(models))
			for _, model := range models {
				data = append(data, map[string]any{"id": model, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		var req chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen = append(seen, req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// helloBytes/worldBytes are the UTF-8 byte values of the two generated tokens,
// carried on each logprob content entry. The delivered output and trace text are
// decoded from these (decodeTokensFromLogprobs), so they -- not Message.Content --
// determine the committed text ("hello world").
var (
	helloBytes = []int{104, 101, 108, 108, 111}     // "hello"
	worldBytes = []int{32, 119, 111, 114, 108, 100} // " world"
)

// chatGenResponse is a two-token chat generation with top-level prompt_token_ids
// and per-choice token_ids + logprobs.content (with bytes), mirroring vLLM's chat
// shape. Message.Content is deliberately left DIFFERENT from the decoded bytes to
// prove the delivered text comes from the token bytes, not message.content.
func chatGenResponse() chatCompletionResponse {
	return chatCompletionResponse{
		ID:             "chatcmpl-test",
		Created:        1700000000,
		Model:          "Qwen/Qwen3-8B",
		Usage:          &chatRespUsage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5},
		PromptTokenIDs: []int{1, 2, 3},
		Choices: []chatResponseChoice{{
			Index:        0,
			Message:      chatRespMessage{Role: "assistant", Content: "ENGINE-DETOKENIZED"},
			FinishReason: "stop",
			TokenIDs:     []int{10, 11},
			Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
				{Token: "token_id:10", Logprob: -0.1, Bytes: helloBytes, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:10", Logprob: -0.1}}},
				{Token: "token_id:11", Logprob: -0.2, Bytes: worldBytes, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:11", Logprob: -0.2}}},
			}},
		}},
	}
}

func TestLocalServiceChatInferProjectsResponse(t *testing.T) {
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetStreamInference(false) // this test pins the non-streaming transport

	resp, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID:  "chat-1",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	// Metering + finish reason (chat "stop" -> EOS).
	if resp.GeneratedTokenCount != 2 || resp.WorkUnit != 2 {
		t.Fatalf("metering = %d/%d, want 2/2", resp.GeneratedTokenCount, resp.WorkUnit)
	}
	if resp.FinishReason != nodewire.FinishReasonV1EosToken {
		t.Fatalf("finish reason = %v, want EOS", resp.FinishReason)
	}

	// Output is the RAW TEXT decoded from the committed token ids (their logprobs
	// bytes), NOT the engine's message.content and NOT a JSON envelope.
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(output.Data) != "hello world" {
		t.Fatalf("output = %q, want decoded token bytes %q", output.Data, "hello world")
	}
	t.Logf("decoded output from token ids %v = %q", []int{10, 11}, string(output.Data))

	// Trace carries the token-level material the Verifier reconstructs from, and its
	// Output is the same decoded text as the delivered output.
	traceArt, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	var trace traceEnvelope
	if err := json.Unmarshal(traceArt.Data, &trace); err != nil {
		t.Fatalf("trace decode error = %v", err)
	}
	if trace.Output != "hello world" {
		t.Fatalf("trace.Output = %q, want decoded token bytes %q", trace.Output, "hello world")
	}
	if len(trace.InputTokenIDs) != 3 || trace.InputTokenIDs[0] != 1 {
		t.Fatalf("trace input token ids = %v, want [1 2 3]", trace.InputTokenIDs)
	}
	if len(trace.OutTokens) != 2 || trace.OutTokens[0].TokenID != 10 || trace.OutTokens[1].TokenID != 11 {
		t.Fatalf("trace out tokens = %+v, want token ids 10,11", trace.OutTokens)
	}
	if trace.OutTokens[0].Logprob != -0.1 || trace.OutTokens[1].Logprob != -0.2 {
		t.Fatalf("trace out token logprobs = %v/%v, want -0.1/-0.2", trace.OutTokens[0].Logprob, trace.OutTokens[1].Logprob)
	}

	// Cortex pins the verification-relevant request fields.
	if len(*seen) == 0 {
		t.Fatalf("chat endpoint was not called")
	}
	got := (*seen)[len(*seen)-1]
	if !got.Logprobs || !got.ReturnTokenIDs || !got.ReturnTokensAsTokenIDs {
		t.Fatalf("request must pin logprobs/return_token_ids/return_tokens_as_token_ids, got %+v", got)
	}
	if got.TopLogprobs != defaultTopK {
		t.Fatalf("top_logprobs = %d, want profile default %d", got.TopLogprobs, defaultTopK)
	}
	// Sampling params come from the chain-bound generation context, not the request:
	// localTestGeneration is greedy (sampling disabled -> temperature 0), top_p 1.0
	// (top_p_ppm 1_000_000) and max_output_tokens 128.
	if got.Temperature != 0 {
		t.Fatalf("temperature = %v, want generation-derived 0", got.Temperature)
	}
	if got.TopP != 1 {
		t.Fatalf("top_p = %v, want generation-derived 1.0", got.TopP)
	}
	if got.MaxCompletionTokens != 128 {
		t.Fatalf("max_completion_tokens = %d, want generation max_output_tokens 128", got.MaxCompletionTokens)
	}
	if got.Stream {
		t.Fatalf("non-streaming svc must send stream:false")
	}
}

func TestLocalServiceChatRejectsForbiddenField(t *testing.T) {
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	_, err := svc.Infer(context.Background(), InferRequest{
		RequestID:  "chat-reject",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}],"logprobs":true}`),
	})
	if err == nil {
		t.Fatalf("Infer() expected error for forbidden field logprobs")
	}
	if !strings.Contains(err.Error(), "logprobs") {
		t.Fatalf("error = %v, want it to name logprobs", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("forbidden request must be rejected before calling vLLM")
	}
}

func TestLocalServiceChatRejectsGenerationParamField(t *testing.T) {
	// The sampling params are owned by the chain-bound generation context, so
	// supplying one in the request is refused rather than silently overridden.
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	for _, field := range []string{"temperature", "top_p", "max_completion_tokens", "max_tokens", "seed", "presence_penalty", "frequency_penalty", "stop"} {
		input := fmt.Sprintf(`{"messages":[{"role":"user","content":"hi"}],%q:%s}`, field, genParamSampleValue(field))
		_, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
			RequestID:  "chat-reject-" + field,
			ModelID:    testQwenModelID(),
			Capability: CapabilityLLMTextV1,
			Input:      []byte(input),
		}))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("field %q: error = %v, want it refused and named", field, err)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("generation-owned request fields must be rejected before calling vLLM")
	}
}

// genParamSampleValue is a syntactically valid JSON value for a rejected
// generation-param field, so the reject is proven to fire on the KEY, not on a
// decode error.
func genParamSampleValue(field string) string {
	switch field {
	case "max_completion_tokens", "max_tokens", "seed":
		return "16"
	case "stop":
		return `["\n"]`
	default:
		return "0.5"
	}
}

// chatBoundMut binds req to a CHAT generation context whose decoding params are
// mutated by mut before the digest is computed, so a test can exercise a context
// that carries a non-OpenAI knob or a stop condition.
func chatBoundMut(t *testing.T, req InferRequest, mut func(*nodewire.DecodingParamsV1)) InferRequest {
	t.Helper()
	g := localTestGeneration(req.ModelID, 1)
	g.TaskType = 2 // CHAT
	mut(&g.Params.DecodingParams)
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.ProfileVersion = "1"
	req.Generation = g
	req.GenerationParamsDigest = digest[:]
	return req
}

func TestLocalServiceChatRejectsNonOpenAIGenerationParams(t *testing.T) {
	// The chat path honours only the OpenAI sampling subset. A generation context
	// that freezes a vLLM-only knob (top_k, repetition_penalty) or ANY stop
	// condition (stop_sequences, stop_token_ids) is refused up front -- fail closed,
	// never silently dropped -- and vLLM is never called.
	cases := []struct {
		name string
		mut  func(*nodewire.DecodingParamsV1)
	}{
		{"top_k", func(d *nodewire.DecodingParamsV1) { d.TopK = 5 }},
		{"repetition_penalty", func(d *nodewire.DecodingParamsV1) { d.RepetitionPenaltyPPM = 1_100_000 }},
		{"stop_sequences", func(d *nodewire.DecodingParamsV1) { d.StopSequences = []string{"END"} }},
		{"stop_token_ids", func(d *nodewire.DecodingParamsV1) { d.StopTokenIDs = []uint32{100} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
			svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
			svc.SetStreamInference(false)

			_, err := svc.Infer(context.Background(), chatBoundMut(t, InferRequest{
				RequestID:  "chat-nonopenai-" + tc.name,
				ModelID:    testQwenModelID(),
				Capability: CapabilityLLMTextV1,
				Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
			}, tc.mut))
			if err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("%s: err = %v, want fail closed naming %q", tc.name, err, tc.name)
			}
			if len(*seen) != 0 {
				t.Fatalf("%s: must be refused before calling vLLM", tc.name)
			}
		})
	}
}

func TestLocalServiceChatRoutesRawTextToInferV0(t *testing.T) {
	// A raw-text input (not a JSON chat body) must fall back to inferV0, which
	// hits /v1/completions. The completions stub serves that path; the chat stub
	// would 404, so success proves the routing.
	srv, _ := newVLLMStub(t, genResponse(), verifyResponse())
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	resp, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "raw-1",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say cat"),
	}))
	if err != nil {
		t.Fatalf("Infer() raw-text error = %v", err)
	}
	if resp.GeneratedTokenCount != 2 {
		t.Fatalf("raw-text metering = %d, want 2 (inferV0 fixture)", resp.GeneratedTokenCount)
	}
}

func TestLocalServiceChatToolCallsMapFinishReasonToEOS(t *testing.T) {
	// A "tool_calls" finish reason still maps to the in-set EOS. The output is just
	// the decoded token text -- tool_calls are no longer parsed into a separate field.
	resp := chatGenResponse()
	resp.Choices[0].FinishReason = "tool_calls"

	srv, _ := newChatVLLMStub(t, resp, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	got, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID:  "chat-tools",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]}`),
	}))
	if err != nil {
		t.Fatalf("Infer() tool_calls error = %v", err)
	}
	if got.FinishReason != nodewire.FinishReasonV1EosToken {
		t.Fatalf("tool_calls finish reason = %v, want EOS", got.FinishReason)
	}
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: got.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(output.Data) != "hello world" {
		t.Fatalf("output = %q, want decoded token bytes %q", output.Data, "hello world")
	}
}

// newChatVLLMStreamStub emulates vLLM's /v1/chat/completions with a
// text/event-stream of the supplied chunks (a leading keepalive comment and a
// trailing [DONE] included), plus /v1/models and /metrics.
func newChatVLLMStreamStub(t *testing.T, chunks []chatCompletionChunk, models []string) (*httptest.Server, *[]chatCompletionRequest) {
	t.Helper()
	var seen []chatCompletionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			writeVLLMMetrics(w, 0, 0)
			return
		case "/v1/models":
			data := make([]map[string]any, 0, len(models))
			for _, m := range models {
				data = append(data, map[string]any{"id": m, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		case "/v1/chat/completions":
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		var req chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen = append(seen, req)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, ": keepalive\n\n")
		for _, chunk := range chunks {
			payload, err := json.Marshal(chunk)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			if flusher != nil {
				flusher.Flush()
			}
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// chatContentChunks is the SSE split of chatGenResponse(): two content deltas plus
// a terminal usage-only chunk that must reassemble to exactly chatGenResponse().
func chatContentChunks() []chatCompletionChunk {
	return []chatCompletionChunk{
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			PromptTokenIDs: []int{1, 2, 3},
			Choices: []chatChunkChoice{{
				Index:    0,
				Delta:    chatChunkDelta{Role: "assistant", Content: "ENGINE"},
				TokenIDs: []int{10},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:10", Logprob: -0.1, Bytes: helloBytes, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:10", Logprob: -0.1}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Choices: []chatChunkChoice{{
				Index:        0,
				Delta:        chatChunkDelta{Content: "DETOK"},
				FinishReason: "stop",
				TokenIDs:     []int{11},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:11", Logprob: -0.2, Bytes: worldBytes, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:11", Logprob: -0.2}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Usage: &chatRespUsage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5},
		},
	}
}

// chatBound binds req to a CHAT (task_type 2) generation context and its digest,
// mirroring boundLocalInferFixture for the raw-text path. The chat path is now
// chain-bound just like inferV0, so every chat Infer needs a valid generation
// context; the sampling parameters the request used to carry come from here.
func chatBound(t *testing.T, req InferRequest) InferRequest {
	t.Helper()
	g := localTestGeneration(req.ModelID, 1)
	g.TaskType = 2 // CHAT
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.ProfileVersion = "1"
	req.Generation = g
	req.GenerationParamsDigest = digest[:]
	return req
}

func chatInferReq(t *testing.T) InferRequest {
	return chatBound(t, InferRequest{
		RequestID:  "chat-stream",
		JobID:      "chat-job",
		TaskID:     "chat-task",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})
}

func TestLocalServiceChatStreamingMatchesNonStreaming(t *testing.T) {
	ctx := context.Background()
	models := []string{"Qwen/Qwen3-8B"}

	streamSrv, seen := newChatVLLMStreamStub(t, chatContentChunks(), models)
	streamSvc := NewLocalService(streamSrv.URL, "local-svc", 4, 0, 0) // streaming default on
	streamOut, streamTrace := chatInferArtifacts(t, ctx, streamSvc, chatInferReq(t))
	if len(*seen) != 1 || !(*seen)[0].Stream {
		t.Fatalf("generation request Stream = %+v, want a single stream:true call", *seen)
	}
	if (*seen)[0].StreamOptions == nil || !(*seen)[0].StreamOptions.IncludeUsage {
		t.Fatalf("streaming request must set stream_options.include_usage")
	}

	jsonSrv, _ := newChatVLLMStub(t, chatGenResponse(), models)
	jsonSvc := NewLocalService(jsonSrv.URL, "local-svc", 4, 0, 0)
	jsonSvc.SetStreamInference(false)
	jsonOut, jsonTrace := chatInferArtifacts(t, ctx, jsonSvc, chatInferReq(t))

	if !bytes.Equal(streamOut, jsonOut) {
		t.Fatalf("streaming output = %s\n non-streaming = %s", streamOut, jsonOut)
	}
	if !bytes.Equal(streamTrace, jsonTrace) {
		t.Fatalf("streaming trace = %s\n non-streaming = %s", streamTrace, jsonTrace)
	}
}

func TestLocalServiceChatStreamObserverReceivesFrames(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), chatInferReq(t))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	if len(obs.frames) != 3 {
		t.Fatalf("observer frames = %d, want 3 (two deltas + done)", len(obs.frames))
	}
	for i, f := range obs.frames {
		if f.RequestID != "chat-stream" || f.JobID != "chat-job" || f.TaskID != "chat-task" || f.ModelID != testQwenModelID() {
			t.Fatalf("frame[%d] identity = %+v, want chat-stream/chat-job/chat-task/%s", i, f, testQwenModelID())
		}
	}
	if f := obs.frames[0]; f.TextDelta != "hello" || !slices.Equal(f.TokenIDs, []int{10}) || f.FinishReason != "" || f.Done {
		t.Fatalf("frame[0] = %+v, want delta hello / [10] / not done", f)
	}
	if f := obs.frames[1]; f.TextDelta != " world" || !slices.Equal(f.TokenIDs, []int{11}) || f.FinishReason != "stop" || f.Done {
		t.Fatalf("frame[1] = %+v, want delta world / [11] / stop", f)
	}
	if f := obs.frames[2]; !f.Done || f.FinishReason != "stop" || f.TextDelta != "" {
		t.Fatalf("frame[2] = %+v, want terminal done frame with finish reason", f)
	}

	// The observed (decoded) deltas reassemble the committed output byte-for-byte.
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(output.Data) != obs.frames[0].TextDelta+obs.frames[1].TextDelta {
		t.Fatalf("output %q != concatenated deltas %q", output.Data, obs.frames[0].TextDelta+obs.frames[1].TextDelta)
	}
	if string(output.Data) != "hello world" {
		t.Fatalf("output = %q, want decoded token bytes %q", output.Data, "hello world")
	}
	for i, f := range obs.frames {
		t.Logf("stream frame[%d]: token_ids=%v decoded piece=%q", i, f.TokenIDs, f.TextDelta)
	}
	t.Logf("concatenated stream output = %q", string(output.Data))
}

// TestLocalServiceChatStreamDeliversToTheRequestScopedObserver pins the observer
// the chat path actually reads in production. Every other streaming test here
// installs the process-wide sink with SetInferStreamObserver, which has no
// production caller at all -- the Worker scopes its output-stream recorder to one
// request with WithInferStreamObserver, exactly so concurrent tasks sharing a
// LocalService cannot replace each other's sink.
//
// Reading the process-wide sink instead left it nil on every real chat task, so no
// frame reached the recorder, outputStreamRecorder.finish took its "no frames
// observed" branch, and the whole generation was committed as a single output
// chunk. The frame boundaries are MMR leaves, so that is a different output_hash,
// not a cosmetic difference in delivery.
func TestLocalServiceChatStreamDeliversToTheRequestScopedObserver(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	obs := &recordingObserver{}
	// Deliberately NOT SetInferStreamObserver: this is how the Worker wires it.
	ctx := WithInferStreamObserver(context.Background(), obs)

	resp, err := svc.Infer(ctx, chatInferReq(t))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if len(obs.frames) == 0 {
		t.Fatal("request-scoped observer received no frames; the chat path is reading the process-wide sink again")
	}

	var streamed string
	for _, f := range obs.frames {
		streamed += f.TextDelta
	}
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	// Byte parity is what lets the Worker commit the streamed frames: its recorder
	// refuses a stream that does not reassemble to the final output.
	if streamed != string(output.Data) {
		t.Fatalf("concatenated deltas %q != committed output %q", streamed, output.Data)
	}
}

func TestLocalServiceChatStreamObserverErrorDoesNotFailInference(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{err: errors.New("downstream gone")}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), chatInferReq(t))
	if err != nil {
		t.Fatalf("Infer() error = %v, want the observer error swallowed", err)
	}
	if resp.OutputRef == "" {
		t.Fatalf("Infer() output ref empty despite a completed generation")
	}
	if len(obs.frames) != 1 {
		t.Fatalf("observer frames after error = %d, want 1 (delivery stops)", len(obs.frames))
	}
}

func TestLocalServiceChatStreamingFallsBackToJSONResponse(t *testing.T) {
	// Streaming is on by default, but a server that answers with a plain JSON body
	// (Content-Type application/json) must be decoded as a whole.
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0) // streaming default on

	resp, err := svc.Infer(context.Background(), chatInferReq(t))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if len(*seen) != 1 || !(*seen)[0].Stream {
		t.Fatalf("request Stream = %+v, want stream:true even though the server replied JSON", *seen)
	}
	if resp.GeneratedTokenCount != 2 {
		t.Fatalf("GeneratedTokenCount = %d, want 2 (fell back to JSON decode)", resp.GeneratedTokenCount)
	}
}

func TestLocalServiceChatRejectsUsageTokenCountMismatch(t *testing.T) {
	// usage.completion_tokens must equal the number of generated token ids the
	// decoded output is built from; a disagreement fails closed.
	resp := chatGenResponse()
	resp.Usage.CompletionTokens = 3 // != len(TokenIDs) == 2

	srv, _ := newChatVLLMStub(t, resp, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetStreamInference(false)

	_, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID:  "chat-usage",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}))
	if err == nil {
		t.Fatalf("Infer() expected error for usage/token id count mismatch")
	}
	if !strings.Contains(err.Error(), "completion_tokens") {
		t.Fatalf("error = %v, want it to name completion_tokens", err)
	}
}

func TestLocalServiceChatRejectsTokenIDLogprobMismatch(t *testing.T) {
	// Each logprobs.content[i] token id must equal token_ids[i], or the bytes being
	// decoded would not provably belong to the committed token ids.
	resp := chatGenResponse()
	resp.Choices[0].Logprobs.Content[1].Token = "token_id:999" // != TokenIDs[1] == 11

	srv, _ := newChatVLLMStub(t, resp, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetStreamInference(false)

	_, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID:  "chat-align",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}))
	if err == nil {
		t.Fatalf("Infer() expected error for token id / logprobs mismatch")
	}
	if !strings.Contains(err.Error(), "token id mismatch") {
		t.Fatalf("error = %v, want it to report a token id mismatch", err)
	}
}

// chatInferArtifacts runs Infer and returns the stored output and trace bytes.
func chatInferArtifacts(t *testing.T, ctx context.Context, svc *LocalService, req InferRequest) (output, trace []byte) {
	t.Helper()
	resp, err := svc.Infer(ctx, req)
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	out, err := svc.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	tr, err := svc.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	return out.Data, tr.Data
}

func TestLastCompleteUTF8Boundary(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{"empty", nil, 0},
		{"ascii", []byte("abc"), 3},
		{"complete 3-byte", []byte{0xE4, 0xBD, 0xA0}, 3},                  // 你
		{"ascii then complete", append([]byte("x"), 0xE4, 0xBD, 0xA0), 4}, // x你
		{"truncated 2of3", []byte{0xE4, 0xBD}, 0},                         // 你 missing last byte
		{"truncated 1of3", []byte{0xE4}, 0},
		{"truncated 1of2", []byte{0xC3}, 0},                        // é lead only
		{"complete then truncated", []byte{0x61, 0xE4, 0xBD}, 1},   // "a" + partial 你
		{"invalid lead left in place", []byte{0x61, 0xFF}, 2},      // 0xFF is not a valid lead
		{"lone continuation left in place", []byte{0x61, 0x80}, 2}, // orphan continuation byte
		{"emoji truncated 3of4", []byte{0xF0, 0x9F, 0x98}, 0},      // 😀 missing last byte
		{"emoji complete", []byte{0xF0, 0x9F, 0x98, 0x80}, 4},      // 😀
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastCompleteUTF8Boundary(tc.in); got != tc.want {
				t.Fatalf("lastCompleteUTF8Boundary(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// chatSplitMultibyteChunks streams "你好" (E4 BD A0 / E5 A5 BD) with the token
// byte boundaries deliberately cutting each character across SSE frames, so the
// per-frame raw bytes are not individually valid UTF-8.
func chatSplitMultibyteChunks() []chatCompletionChunk {
	return []chatCompletionChunk{
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			PromptTokenIDs: []int{1, 2, 3},
			Choices: []chatChunkChoice{{
				Index:    0,
				Delta:    chatChunkDelta{Role: "assistant"},
				TokenIDs: []int{20},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:20", Logprob: -0.1, Bytes: []int{0xE4, 0xBD}, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:20", Logprob: -0.1}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Choices: []chatChunkChoice{{
				Index:    0,
				TokenIDs: []int{21},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:21", Logprob: -0.2, Bytes: []int{0xA0, 0xE5, 0xA5}, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:21", Logprob: -0.2}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Choices: []chatChunkChoice{{
				Index:        0,
				FinishReason: "stop",
				TokenIDs:     []int{22},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:22", Logprob: -0.3, Bytes: []int{0xBD}, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:22", Logprob: -0.3}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Usage: &chatRespUsage{PromptTokens: 3, CompletionTokens: 3, TotalTokens: 6},
		},
	}
}

func TestLocalServiceChatStreamBuffersSplitMultibyte(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatSplitMultibyteChunks(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), chatInferReq(t))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	// Every delivered delta must be valid UTF-8 despite the raw per-token bytes
	// splitting characters across frames.
	var reassembled strings.Builder
	for i, f := range obs.frames {
		if !utf8.ValidString(f.TextDelta) {
			t.Fatalf("frame[%d] TextDelta = %q is not valid UTF-8", i, f.TextDelta)
		}
		reassembled.WriteString(f.TextDelta)
	}

	// The character that completes only on frame 1 / frame 2 is held back until
	// its bytes are whole; frame 0 carries its token id with an empty delta.
	if f := obs.frames[0]; f.TextDelta != "" || !slices.Equal(f.TokenIDs, []int{20}) {
		t.Fatalf("frame[0] = %+v, want empty delta with token [20]", f)
	}
	if f := obs.frames[1]; f.TextDelta != "你" || !slices.Equal(f.TokenIDs, []int{21}) {
		t.Fatalf("frame[1] = %+v, want delta 你 with token [21]", f)
	}
	if f := obs.frames[2]; f.TextDelta != "好" || !slices.Equal(f.TokenIDs, []int{22}) || f.FinishReason != "stop" {
		t.Fatalf("frame[2] = %+v, want delta 好 with token [22] / stop", f)
	}
	if f := obs.frames[len(obs.frames)-1]; !f.Done {
		t.Fatalf("last frame = %+v, want terminal done frame", f)
	}

	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(output.Data) != "你好" {
		t.Fatalf("committed output = %q, want %q", output.Data, "你好")
	}
	// Byte parity: concat(TextDelta) reassembles the committed output exactly.
	if reassembled.String() != string(output.Data) {
		t.Fatalf("concatenated deltas %q != committed output %q", reassembled.String(), output.Data)
	}
}

// newSlowChatStreamStub emits chunks with a delay before each one, so a test can
// place max_output_duration in the middle of the stream. It never sends [DONE],
// which is the real shape: vLLM keeps generating and this node stops listening.
func newSlowChatStreamStub(t *testing.T, chunks []chatCompletionChunk, delay time.Duration, models []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			writeVLLMMetrics(w, 0, 0)
			return
		case "/v1/models":
			data := make([]map[string]any, 0, len(models))
			for _, m := range models {
				data = append(data, map[string]any{"id": m, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		case "/v1/chat/completions":
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, chunk := range chunks {
			time.Sleep(delay)
			payload, err := json.Marshal(chunk)
			if err != nil {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLocalServiceChatStopsAtMaxOutputDurationAsSuccess pins the behaviour
// max_output_duration is in the frozen finish-reason set for.
//
// vLLM has no wall-clock stopping condition, so before this the budget was a
// context deadline: expiry discarded the whole generation and the value could
// never be produced at all. It is a successful termination now -- the tokens
// that arrived before the budget are committed, and this node names the reason
// the engine cannot.
func TestLocalServiceChatStopsAtMaxOutputDurationAsSuccess(t *testing.T) {
	// The engine must still be generating when the budget expires, so both chunks
	// are non-terminal. A stream that already carried finish_reason was ended by
	// the ENGINE and the engine's reason wins: the budget only names a stop that
	// nothing else has named. Clearing it here is what makes this a duration test
	// rather than an EOS one.
	chunks := chatContentChunks()[:2]
	chunks[1].Choices[0].FinishReason = ""
	// 150ms apart against a 200ms budget: the first chunk is folded in under
	// budget, the second crosses it and is the last one committed.
	srv := newSlowChatStreamStub(t, chunks, 150*time.Millisecond, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	req := chatInferReq(t)
	req.Generation.Params.MaxOutputDuration = 200 // ms: the first chunk lands, nothing else arrives
	digest, err := req.Generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.GenerationParamsDigest = digest[:]

	resp, err := svc.Infer(context.Background(), req)
	if err != nil {
		t.Fatalf("Infer() error = %v, want a successful truncation", err)
	}
	if resp.FinishReason != nodewire.FinishReasonV1MaxOutputDuration {
		t.Fatalf("finish reason = %v, want MAX_OUTPUT_DURATION", resp.FinishReason)
	}
	if resp.GeneratedTokenCount == 0 {
		t.Fatal("a budget stop must still commit the tokens that arrived")
	}
	if resp.GeneratedTokenCount >= req.Generation.Params.MaxOutputTokens {
		t.Fatalf("generated %d tokens at the ceiling; that is MAX_OUTPUT_TOKENS, not a duration stop", resp.GeneratedTokenCount)
	}

	// The evidence must describe the truncated run: output, trace and token ids
	// all stop at the same place.
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	traceArt, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	var trace traceEnvelope
	if err := json.Unmarshal(traceArt.Data, &trace); err != nil {
		t.Fatal(err)
	}
	if trace.Output != string(output.Data) {
		t.Fatalf("trace.Output %q != committed output %q", trace.Output, output.Data)
	}
	if len(trace.OutTokens) != int(resp.GeneratedTokenCount) {
		t.Fatalf("trace carries %d tokens, receipt counts %d", len(trace.OutTokens), resp.GeneratedTokenCount)
	}
}
