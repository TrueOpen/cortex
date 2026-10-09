package modelservice

import (
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

	"github.com/TrueOpen/cortex/internal/modelservice/vllmstub"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// newChatVLLMStub emulates vLLM's /v1/chat/completions (plus /v1/models and
// /metrics so model resolution and capacity reads work). It records the requests
// it received so a test can assert the Cortex-pinned fields.
func newChatVLLMStub(t *testing.T, resp chatCompletionResponse, models []string) (*httptest.Server, *[]chatCompletionRequest) {
	t.Helper()
	for i := range resp.Choices {
		resp.Choices[i].Logprobs = chatFullTopK(resp.Choices[i].Logprobs)
	}
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

func TestLocalServiceChatRejectsForbiddenField(t *testing.T) {
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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
			svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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

// Cortex pins the chat request's top_k to the profile's required_top_k (platform
// policy, not a user parameter: the order never sets it, refused upstream), so the
// sampled token always lands inside the reported top_logprobs.
func TestLocalServiceChatPinsTopKToRequiredTopK(t *testing.T) {
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

	if _, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID:  "chat-topk",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})); err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("vLLM calls = %d, want 1", len(*seen))
	}
	if (*seen)[0].TopK != defaultTopK {
		t.Fatalf("chat top_k = %d, want platform-pinned required_top_k %d", (*seen)[0].TopK, defaultTopK)
	}
}

// newChatVLLMStreamStub emulates vLLM's /v1/chat/completions with a
// text/event-stream of the supplied chunks (a leading keepalive comment and a
// trailing [DONE] included), plus /v1/models and /metrics.
func newChatVLLMStreamStub(t *testing.T, chunks []chatCompletionChunk, models []string) (*httptest.Server, *[]chatCompletionRequest) {
	t.Helper()
	chunks = chatChunksFullTopK(chunks)
	frames := make([]any, len(chunks))
	for i, chunk := range chunks {
		frames[i] = chunk
	}
	var seen []chatCompletionRequest
	srv := vllmstub.ChatStream{
		Frames:  frames,
		Models:  models,
		Metrics: func(w http.ResponseWriter) { writeVLLMMetrics(w, 0, 0) },
		OnRequest: func(body []byte) {
			var req chatCompletionRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("decode chat request: %v", err)
			}
			seen = append(seen, req)
		},
	}.Start(t)
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

func TestLocalServiceChatStreamObserverReceivesFrames(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), chatInferReq(t))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	// Each token's text is held back until the next token arrives, because only
	// then is it known not to be a trailing EOS; the last one is released when
	// the stream ends, on a text-only frame before the done frame.
	if len(obs.frames) != 4 {
		t.Fatalf("observer frames = %d, want 4 (two deltas + final text + done)", len(obs.frames))
	}
	for i, f := range obs.frames {
		if f.RequestID != "chat-stream" || f.JobID != "chat-job" || f.TaskID != "chat-task" || f.ModelID != testQwenModelID() {
			t.Fatalf("frame[%d] identity = %+v, want chat-stream/chat-job/chat-task/%s", i, f, testQwenModelID())
		}
	}
	if f := obs.frames[0]; f.TextDelta != "" || !slices.Equal(f.TokenIDs, []int{10}) || f.FinishReason != "" || f.Done {
		t.Fatalf("frame[0] = %+v, want empty delta / [10] / not done", f)
	}
	if f := obs.frames[1]; f.TextDelta != "hello" || !slices.Equal(f.TokenIDs, []int{11}) || f.FinishReason != "stop" || f.Done {
		t.Fatalf("frame[1] = %+v, want delta hello / [11] / stop", f)
	}
	if f := obs.frames[2]; f.TextDelta != " world" || len(f.TokenIDs) != 0 || f.Done {
		t.Fatalf("frame[2] = %+v, want the released last token world", f)
	}
	if f := obs.frames[3]; !f.Done || f.FinishReason != "stop" || f.TextDelta != "" {
		t.Fatalf("frame[3] = %+v, want terminal done frame with finish reason", f)
	}

	// The observed (decoded) deltas reassemble the committed output byte-for-byte.
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if streamed := obs.frames[1].TextDelta + obs.frames[2].TextDelta; string(output.Data) != streamed {
		t.Fatalf("output %q != concatenated deltas %q", output.Data, streamed)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0) // streaming default on

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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
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

	// A token's bytes are released one token late (it might be a trailing
	// EOS), and released bytes are then held until they end a character: U+4F60
	// is whole once token 21 is released, on frame 2, and U+597D once the last
	// token is released at the end of the stream.
	if f := obs.frames[0]; f.TextDelta != "" || !slices.Equal(f.TokenIDs, []int{20}) {
		t.Fatalf("frame[0] = %+v, want empty delta with token [20]", f)
	}
	if f := obs.frames[1]; f.TextDelta != "" || !slices.Equal(f.TokenIDs, []int{21}) {
		t.Fatalf("frame[1] = %+v, want empty delta with token [21]", f)
	}
	if f := obs.frames[2]; f.TextDelta != "\u4f60" || !slices.Equal(f.TokenIDs, []int{22}) || f.FinishReason != "stop" {
		t.Fatalf("frame[2] = %+v, want delta U+4F60 with token [22] / stop", f)
	}
	if f := obs.frames[3]; f.TextDelta != "\u597d" || f.Done {
		t.Fatalf("frame[3] = %+v, want the final delta U+597D", f)
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
	chunks = chatChunksFullTopK(chunks)
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

func chatChunksFullTopK(chunks []chatCompletionChunk) []chatCompletionChunk {
	out := make([]chatCompletionChunk, len(chunks))
	for i, chunk := range chunks {
		chunk.Choices = append([]chatChunkChoice(nil), chunk.Choices...)
		for c := range chunk.Choices {
			chunk.Choices[c].Logprobs = chatFullTopK(chunk.Choices[c].Logprobs)
		}
		out[i] = chunk
	}
	return out
}
