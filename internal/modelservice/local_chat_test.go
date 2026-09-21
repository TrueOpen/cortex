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

	"github.com/SingaXYZ/cortex/internal/nodewire"
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

// chatGenResponse is a two-token chat generation with top-level prompt_token_ids
// and per-choice token_ids + logprobs.content, mirroring vLLM's chat shape.
func chatGenResponse() chatCompletionResponse {
	return chatCompletionResponse{
		ID:             "chatcmpl-test",
		Created:        1700000000,
		Model:          "Qwen/Qwen3-8B",
		Usage:          &chatRespUsage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5},
		PromptTokenIDs: []int{1, 2, 3},
		Choices: []chatResponseChoice{{
			Index:        0,
			Message:      chatRespMessage{Role: "assistant", Content: "hello world"},
			FinishReason: "stop",
			TokenIDs:     []int{10, 11},
			Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
				{Token: "token_id:10", Logprob: -0.1, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:10", Logprob: -0.1}}},
				{Token: "token_id:11", Logprob: -0.2, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:11", Logprob: -0.2}}},
			}},
		}},
	}
}

func TestLocalServiceChatInferProjectsResponse(t *testing.T) {
	srv, seen := newChatVLLMStub(t, chatGenResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetStreamInference(false) // this test pins the non-streaming transport

	resp, err := svc.Infer(context.Background(), InferRequest{
		RequestID:  "chat-1",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}],"temperature":0.7}`),
	})
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

	// Output is a clean OpenAI ChatCompletion object (no vLLM internals).
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	var out chatCompletionOutput
	if err := json.Unmarshal(output.Data, &out); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, output.Data)
	}
	if out.ID != "chatcmpl-test" || out.Object != "chat.completion" || out.Created != 1700000000 {
		t.Fatalf("output envelope = %+v, want id/object/created echoed", out)
	}
	if out.Model != testQwenModelID() {
		t.Fatalf("output model = %q, want chain model_id %q", out.Model, testQwenModelID())
	}
	if len(out.Choices) != 1 || out.Choices[0].Message.Content != "hello world" || out.Choices[0].FinishReason != "stop" {
		t.Fatalf("output choices = %+v, want content=hello world finish_reason=stop", out.Choices)
	}
	if len(out.Choices[0].Message.ToolCalls) != 0 {
		t.Fatalf("output tool_calls = %s, want omitted", out.Choices[0].Message.ToolCalls)
	}
	if out.Usage == nil || out.Usage.TotalTokens != 5 {
		t.Fatalf("output usage = %+v, want total_tokens=5", out.Usage)
	}
	// The evidence trace keeps the model TEXT (not the delivered envelope).
	if strings.Contains(string(output.Data), "prompt_token_ids") || strings.Contains(string(output.Data), "token_ids") {
		t.Fatalf("output must not leak vLLM internal token ids: %s", output.Data)
	}

	// Trace carries the token-level material the Verifier reconstructs from.
	traceArt, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	var trace traceEnvelope
	if err := json.Unmarshal(traceArt.Data, &trace); err != nil {
		t.Fatalf("trace decode error = %v", err)
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
	if got.Temperature != 0.7 {
		t.Fatalf("temperature = %v, want caller-supplied 0.7", got.Temperature)
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
	resp := chatGenResponse()
	resp.Choices[0].Message = chatRespMessage{
		Role:    "assistant",
		Content: "",
		ToolCalls: json.RawMessage(
			`[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Beijing\"}"}}]`),
	}
	resp.Choices[0].FinishReason = "tool_calls"

	srv, _ := newChatVLLMStub(t, resp, []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	got, err := svc.Infer(context.Background(), InferRequest{
		RequestID:  "chat-tools",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}]}`),
	})
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
	var out chatCompletionOutput
	if err := json.Unmarshal(output.Data, &out); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if len(out.Choices) != 1 || len(out.Choices[0].Message.ToolCalls) == 0 {
		t.Fatalf("output must carry tool_calls, got %s", output.Data)
	}
	if out.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("output finish_reason = %q, want faithful tool_calls", out.Choices[0].FinishReason)
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
				Delta:    chatChunkDelta{Role: "assistant", Content: "hello"},
				TokenIDs: []int{10},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:10", Logprob: -0.1, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:10", Logprob: -0.1}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Choices: []chatChunkChoice{{
				Index:        0,
				Delta:        chatChunkDelta{Content: " world"},
				FinishReason: "stop",
				TokenIDs:     []int{11},
				Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{
					{Token: "token_id:11", Logprob: -0.2, TopLogprobs: []chatRespTopLogprob{{Token: "token_id:11", Logprob: -0.2}}},
				}},
			}},
		},
		{
			ID: "chatcmpl-test", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Usage: &chatRespUsage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5},
		},
	}
}

func chatInferReq() InferRequest {
	return InferRequest{
		RequestID:  "chat-stream",
		JobID:      "chat-job",
		TaskID:     "chat-task",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}
}

func TestLocalServiceChatStreamingMatchesNonStreaming(t *testing.T) {
	ctx := context.Background()
	models := []string{"Qwen/Qwen3-8B"}

	streamSrv, seen := newChatVLLMStreamStub(t, chatContentChunks(), models)
	streamSvc := NewLocalService(streamSrv.URL, "local-svc", 4, 0, 0) // streaming default on
	streamOut, streamTrace := chatInferArtifacts(t, ctx, streamSvc, chatInferReq())
	if len(*seen) != 1 || !(*seen)[0].Stream {
		t.Fatalf("generation request Stream = %+v, want a single stream:true call", *seen)
	}
	if (*seen)[0].StreamOptions == nil || !(*seen)[0].StreamOptions.IncludeUsage {
		t.Fatalf("streaming request must set stream_options.include_usage")
	}

	jsonSrv, _ := newChatVLLMStub(t, chatGenResponse(), models)
	jsonSvc := NewLocalService(jsonSrv.URL, "local-svc", 4, 0, 0)
	jsonSvc.SetStreamInference(false)
	jsonOut, jsonTrace := chatInferArtifacts(t, ctx, jsonSvc, chatInferReq())

	if !bytes.Equal(streamOut, jsonOut) {
		t.Fatalf("streaming output = %s\n non-streaming = %s", streamOut, jsonOut)
	}
	if !bytes.Equal(streamTrace, jsonTrace) {
		t.Fatalf("streaming trace = %s\n non-streaming = %s", streamTrace, jsonTrace)
	}
}

func TestLocalServiceChatStreamingToolCallsMatchesNonStreaming(t *testing.T) {
	ctx := context.Background()
	models := []string{"Qwen/Qwen3-8B"}

	// Non-streaming fixture: tool_calls as one block, empty content.
	nonStream := chatGenResponse()
	nonStream.Choices[0].Message = chatRespMessage{
		Role:      "assistant",
		Content:   "",
		ToolCalls: json.RawMessage(`[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Beijing\"}"}}]`),
	}
	nonStream.Choices[0].FinishReason = "tool_calls"

	// Streaming fixture: same generation, tool_calls arriving as index-0 fragments.
	streamChunks := chatContentChunks()
	streamChunks[0].Choices[0].Delta = chatChunkDelta{
		Role: "assistant",
		ToolCalls: []chatToolCallDelta{{
			Index: 0, ID: "call_1", Type: "function",
			Function: &chatToolCallFuncDelta{Name: "get_weather", Arguments: `{"city":`},
		}},
	}
	streamChunks[1].Choices[0].Delta = chatChunkDelta{
		ToolCalls: []chatToolCallDelta{{
			Index:    0,
			Function: &chatToolCallFuncDelta{Arguments: `"Beijing"}`},
		}},
	}
	streamChunks[1].Choices[0].FinishReason = "tool_calls"

	streamSrv, _ := newChatVLLMStreamStub(t, streamChunks, models)
	streamOut, _ := chatInferArtifacts(t, ctx, NewLocalService(streamSrv.URL, "local-svc", 4, 0, 0), chatInferReq())

	jsonSrv, _ := newChatVLLMStub(t, nonStream, models)
	jsonSvc := NewLocalService(jsonSrv.URL, "local-svc", 4, 0, 0)
	jsonSvc.SetStreamInference(false)
	jsonOut, _ := chatInferArtifacts(t, ctx, jsonSvc, chatInferReq())

	if !bytes.Equal(streamOut, jsonOut) {
		t.Fatalf("streaming tool_calls output = %s\n non-streaming = %s", streamOut, jsonOut)
	}
	// Guard that the reassembled arguments really were the concatenation.
	var out chatCompletionOutput
	if err := json.Unmarshal(streamOut, &out); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if !strings.Contains(string(out.Choices[0].Message.ToolCalls), `{\"city\":\"Beijing\"}`) {
		t.Fatalf("tool_calls arguments not reassembled: %s", out.Choices[0].Message.ToolCalls)
	}
}

func TestLocalServiceChatStreamObserverReceivesFrames(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), chatInferReq())
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

	// The observed content deltas reassemble the committed output byte-for-byte.
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	var out chatCompletionOutput
	if err := json.Unmarshal(output.Data, &out); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if out.Choices[0].Message.Content != obs.frames[0].TextDelta+obs.frames[1].TextDelta {
		t.Fatalf("content %q != concatenated deltas", out.Choices[0].Message.Content)
	}
}

func TestLocalServiceChatStreamObserverErrorDoesNotFailInference(t *testing.T) {
	srv, _ := newChatVLLMStreamStub(t, chatContentChunks(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{err: errors.New("downstream gone")}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), chatInferReq())
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

	resp, err := svc.Infer(context.Background(), chatInferReq())
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
