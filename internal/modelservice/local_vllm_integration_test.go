package modelservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const (
	envTestVLLMURL            = "CORTEX_TEST_VLLM_URL"
	envTestVLLMModel          = "CORTEX_TEST_VLLM_MODEL"
	envTestVLLMProfileVersion = "CORTEX_TEST_VLLM_PROFILE_VERSION"
	envTestVLLMPrompt         = "CORTEX_TEST_VLLM_PROMPT"
	envTestVLLMTopK           = "CORTEX_TEST_VLLM_TOP_K"
	// Pointing this at a Keeper RPC resolves the profile from the chain instead
	// of the static fixture, so the run judges its own output under the policy
	// the chain actually published rather than one this test invented.
	envTestVLLMKeeperRPC = "CORTEX_TEST_VLLM_KEEPER_RPC"
	// A full OpenAI chat request body for the chat integration test. When unset the
	// test wraps envTestVLLMPrompt (or its default) in a single user message.
	envTestVLLMChatInput = "CORTEX_TEST_VLLM_CHAT_INPUT"
)

// keeperVLLMProfileResolver mirrors internal/daemon's keeperLocalProfileResolver,
// which is unexported. It is the same two lines: read the current profile and
// hand back the snapshot the local service applies.
type keeperVLLMProfileResolver struct {
	keeper *chainclient.KeeperABCIClient
}

func (r keeperVLLMProfileResolver) ResolveLocalProfile(ctx context.Context, modelID string, profileVersion string) (chainclient.CurrentProfileSnapshot, error) {
	snapshot, err := r.keeper.CurrentModelProfile(ctx, modelID, profileVersion)
	if err != nil {
		return chainclient.CurrentProfileSnapshot{}, err
	}
	return snapshot.Profile, nil
}

// realVLLMChatInput builds the OpenAI chat request body the chat integration test
// sends. envTestVLLMChatInput supplies a full body verbatim; otherwise the prompt
// (envTestVLLMPrompt or its default) is wrapped in a single user message. Either
// way the result must carry a "messages" field so LocalService.Infer routes it to
// /v1/chat/completions rather than the raw-text inferV0 path.
func realVLLMChatInput(t *testing.T) []byte {
	t.Helper()
	if raw := strings.TrimSpace(os.Getenv(envTestVLLMChatInput)); raw != "" {
		if _, isChat, err := parseChatInferInput([]byte(raw)); err != nil || !isChat {
			t.Fatalf("%s is not a valid chat request (isChat=%v err=%v)", envTestVLLMChatInput, isChat, err)
		}
		return []byte(raw)
	}
	prompt := strings.TrimSpace(os.Getenv(envTestVLLMPrompt))
	if prompt == "" {
		prompt = "Write exactly three words about distributed inference."
	}
	body, err := json.Marshal(map[string]any{
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	if err != nil {
		t.Fatalf("marshal chat input: %v", err)
	}
	return body
}

// realVLLMChatMaxTokens bounds generation on the chat path. The chat path is now
// chain-bound like inferV0: MaxOutputTokens comes from the generation context and
// is forwarded to vLLM as max_completion_tokens (localChatGenerationRequest), so a
// modest cap keeps the run bounded and fast while the evidence validates against
// the same ceiling.
const realVLLMChatMaxTokens = 256

// boundRealVLLMChatInfer binds a chat Infer request to a generation context capped
// at maxTokens. Every chat Infer needs one now: the chat path validates
// req.Generation and applies the frozen sampling parameters from it (including the
// max_completion_tokens cap), exactly as inferV0 does. The producing Infer and its
// Verify must bind the SAME context so the trace's generation_params_digest matches.
func boundRealVLLMChatInfer(t *testing.T, req InferRequest, maxTokens uint64) InferRequest {
	t.Helper()
	if req.ProfileVersion == "" {
		req.ProfileVersion = "1"
	}
	req.Generation, req.GenerationParamsDigest = realVLLMChatGeneration(t, req.ModelID, req.ProfileVersion, maxTokens)
	return req
}

// boundRealVLLMChatVerify binds a Verify request to the same generation context
// Infer used, capped at maxTokens. It must match the infer binding exactly: the
// trace carries the infer generation's digest, and ValidateGenerationEvidence
// rejects a verify request whose generation context digests to anything else.
func boundRealVLLMChatVerify(t *testing.T, req VerifyRequest, maxTokens uint64) VerifyRequest {
	t.Helper()
	if req.ProfileVersion == "" {
		req.ProfileVersion = "1"
	}
	req.Generation, req.GenerationParamsDigest = realVLLMChatGeneration(t, req.ModelID, req.ProfileVersion, maxTokens)
	return req
}

// realVLLMChatGeneration builds the generation context (and its digest) both Infer
// and Verify bind on the chat real tests, with MaxOutputTokens set to maxTokens so
// the request cap and the validated ceiling agree.
func realVLLMChatGeneration(t *testing.T, modelID, profileVersion string, maxTokens uint64) (*nodewire.GenerationContext, []byte) {
	t.Helper()
	profile, err := strconv.ParseUint(profileVersion, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	g := localTestGeneration(modelID, uint32(profile))
	g.Params.MaxOutputTokens = maxTokens
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return g, digest[:]
}

func parseRealVLLMUint32(t *testing.T, envName string, raw string) int {
	t.Helper()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value == 0 {
		t.Fatalf("%s=%q must be a positive uint32", envName, raw)
	}
	return int(value)
}

func fetchRealVLLMArtifact(t *testing.T, ctx context.Context, svc *LocalService, ref string, allowEmpty bool) Artifact {
	t.Helper()
	artifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{
		RequestID:  "real-vllm-fetch",
		Ref:        ref,
		AllowEmpty: allowEmpty,
	})
	if err != nil {
		t.Fatalf("FetchArtifact(%q) error = %v", ref, err)
	}
	return artifact
}

// --- streaming Infer transport tests -----------------------------------------
//
// These exercise LocalService.Infer over the vLLM SSE transport. The hermetic
// ones stand up an httptest server that streams server-sent events; the parity
// tests assert the reassembled result is byte-for-byte what the non-streaming
// JSON path yields, which is the contract that keeps output_hash / trace / verify
// unchanged regardless of transport. TestLocalServiceRealVLLMStreamingParity runs
// the same check against a real vLLM (env-gated) to validate that engine's actual
// SSE field placement.

// streamFrame builds a single-choice completion chunk as it appears inside one
// SSE data frame during a streaming generation.
func streamFrame(text string, tokenIDs []int, tokenLogprobs []float64, topLogprobs []TopLogprobRow, promptTokenIDs []int, finishReason string) completionResponse {
	var resp completionResponse
	resp.Choices = append(resp.Choices, completionChoice{
		Text:           text,
		FinishReason:   finishReason,
		PromptTokenIDs: promptTokenIDs,
		TokenIDs:       tokenIDs,
		Logprobs: &completionLogprobs{
			TokenLogprobs: tokenLogprobs,
			TopLogprobs:   topLogprobs,
		},
	})
	return withFullTopK(resp)
}

// twoFrameGeneration is the SSE split of genResponse() used across these tests:
// two frames that must reassemble to exactly genResponse().
func twoFrameGeneration() []completionResponse {
	return []completionResponse{
		streamFrame("hello", []int{10}, []float64{-0.1}, nil, []int{1, 2, 3}, ""),
		streamFrame(" world", []int{11}, []float64{-0.2}, nil, nil, "stop"),
	}
}

// newVLLMStreamStub emulates vLLM's endpoints, answering the generation
// /v1/completions call with a text/event-stream of the supplied frames (a leading
// keepalive comment and a trailing [DONE] included). Verify calls, which carry
// prompt_logprobs, stay non-streaming and get the plain JSON body.
func newVLLMStreamStub(t *testing.T, frames []completionResponse, verify completionResponse, models []string) (*httptest.Server, *[]completionRequest) {
	t.Helper()
	var seen []completionRequest
	var seenMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			writeVLLMMetrics(w, 0, 0)
			return
		case "/v1/models":
			if r.Header.Get("Authorization") != "Bearer EMPTY" {
				http.Error(w, "missing bearer auth", http.StatusUnauthorized)
				return
			}
			data := make([]map[string]any, 0, len(models))
			for _, m := range models {
				data = append(data, map[string]any{"id": m, "object": "model"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
			return
		case "/v1/completions":
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		var req completionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seenMu.Lock()
		seen = append(seen, req)
		seenMu.Unlock()
		if req.PromptLogprobs != nil {
			// Verify path: non-streaming JSON, mirroring newVLLMStub.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(verify)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, ": keepalive\n\n")
		for _, frame := range frames {
			payload, err := json.Marshal(frame)
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

// recordingObserver captures every InferStreamFrame and can inject an error to
// exercise the best-effort delivery contract.
type recordingObserver struct {
	frames []InferStreamFrame
	err    error
}

func (o *recordingObserver) ObserveInferFrame(_ context.Context, frame InferStreamFrame) error {
	o.frames = append(o.frames, frame)
	return o.err
}

func TestLocalServiceInferStreamObserverReceivesFrames(t *testing.T) {
	srv, _ := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	if _, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "obs-req",
		JobID:      "obs-job",
		TaskID:     "obs-task",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	})); err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	if len(obs.frames) != 3 {
		t.Fatalf("observer frames = %d, want 3 (two deltas + done)", len(obs.frames))
	}
	for i, f := range obs.frames {
		if f.RequestID != "obs-req" || f.JobID != "obs-job" || f.TaskID != "obs-task" || f.ModelID != testQwenModelID() {
			t.Fatalf("frame[%d] identity = %+v, want obs-req/obs-job/obs-task/%s", i, f, testQwenModelID())
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
}

func TestLocalServiceInferStreamObserverErrorDoesNotFailInference(t *testing.T) {
	srv, _ := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	obs := &recordingObserver{err: errors.New("downstream gone")}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "obs-err",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v, want the observer error swallowed", err)
	}
	if resp.OutputRef == "" {
		t.Fatalf("Infer() output ref empty despite a completed generation")
	}
	// Delivery stops at the first error, so the second delta and the done frame
	// are never sent.
	if len(obs.frames) != 1 {
		t.Fatalf("observer frames after error = %d, want 1 (delivery stops)", len(obs.frames))
	}
}

func TestLocalServiceInferStreamingFallsBackToJSONResponse(t *testing.T) {
	// Streaming is on by default, but a server that answers /v1/completions with
	// application/json (a stub, or a vLLM that ignored stream:true) must still
	// decode — this is what keeps every non-SSE stub test green.
	srv, seen := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)

	resp, err := svc.Infer(context.Background(), boundLocalInferFixture(t, InferRequest{
		RequestID:  "fallback",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	out, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(out.Data) != "hello world" {
		t.Fatalf("output = %q, want hello world via JSON fallback under streaming", out.Data)
	}
	if len(*seen) == 0 || !(*seen)[0].Stream {
		t.Fatalf("generation request Stream = %+v, want stream:true even though the server replied JSON", *seen)
	}
}
