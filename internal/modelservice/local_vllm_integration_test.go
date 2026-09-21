package modelservice

import (
	"bytes"
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
	"time"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/nodewire"
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
	// A full OpenAI chat request body carrying "tools" that reliably makes the
	// model emit a tool_calls response, gating the tool-call streaming parity test.
	// Left to the operator because whether a call is triggered is model-specific.
	envTestVLLMChatToolInput = "CORTEX_TEST_VLLM_CHAT_TOOL_INPUT"
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

func TestLocalServiceRealVLLM(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM integration test", envTestVLLMURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-test", 4, 5*time.Minute, 5*time.Minute)

	health, err := svc.Health(ctx, HealthRequest{RequestID: "real-vllm-health"})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.Healthy || health.Error != nil {
		t.Fatalf("Health() = %+v, want healthy vLLM service", health)
	}

	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "real-vllm-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}

	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}
	profileVersionNumber := parseRealVLLMUint32(t, envTestVLLMProfileVersion, profileVersion)
	topK := parseRealVLLMUint32(t, envTestVLLMTopK, strings.TrimSpace(os.Getenv(envTestVLLMTopK)))
	if topK == 0 {
		topK = defaultTopK
	}
	chainProfile := false
	if rpc := strings.TrimSpace(os.Getenv(envTestVLLMKeeperRPC)); rpc != "" {
		chainProfile = true
		svc.SetProfileResolver(keeperVLLMProfileResolver{keeper: chainclient.NewKeeperABCIClient(rpc)})
		t.Logf("real vLLM profile source: chain %s (model=%s profile=%d)", rpc, modelID, profileVersionNumber)
	} else {
		svc.SetProfileResolver(staticLocalProfileResolver{profile: resolvedCurrentProfile(modelID, uint32(profileVersionNumber), uint32(topK))})
		t.Logf("real vLLM profile source: static fixture (model=%s profile=%d top_k=%d); set %s to judge under the chain policy",
			modelID, profileVersionNumber, topK, envTestVLLMKeeperRPC)
	}

	prompt := strings.TrimSpace(os.Getenv(envTestVLLMPrompt))
	if prompt == "" {
		prompt = "Write exactly three words about distributed inference."
	}

	load, err := svc.LoadModel(ctx, LoadModelRequest{
		RequestID:  "real-vllm-load",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
	})
	if err != nil {
		t.Fatalf("LoadModel(%q) error = %v", modelID, err)
	}
	if !load.Loaded {
		t.Fatalf("LoadModel(%q) = %+v, want loaded", modelID, load)
	}

	infer, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{
		RequestID:      "real-vllm-infer",
		JobID:          "real-vllm-job",
		TaskID:         "real-vllm-task",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          []byte(prompt),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if infer.OutputRef == "" || infer.TraceRef == "" || infer.CheckpointRef == "" {
		t.Fatalf("Infer() refs = %+v, want output, trace, and checkpoint refs", infer)
	}

	output := fetchRealVLLMArtifact(t, ctx, svc, infer.OutputRef, false)
	if len(output.Data) == 0 {
		t.Fatalf("Infer() output artifact is empty")
	}
	t.Logf("real vLLM output: %q", strings.TrimSpace(string(output.Data)))

	trace := fetchRealVLLMArtifact(t, ctx, svc, infer.TraceRef, false)
	checkpoint := fetchRealVLLMArtifact(t, ctx, svc, infer.CheckpointRef, false)
	t.Logf("infer artifacts: output=%dB trace=%dB checkpoint=%dB finish_reason=%d",
		len(output.Data), len(trace.Data), len(checkpoint.Data), int32(infer.FinishReason))

	var traceEnv traceEnvelope
	if err := json.Unmarshal(trace.Data, &traceEnv); err != nil {
		t.Fatalf("unmarshal trace envelope: %v", err)
	}
	if traceEnv.ModelID != modelID || traceEnv.ProfileVersion != profileVersion {
		t.Fatalf("trace binding = %+v, want %s@%s", traceEnv, modelID, profileVersion)
	}
	if len(traceEnv.InputTokenIDs) == 0 || len(traceEnv.OutTokens) == 0 {
		t.Fatalf("trace token ids = input:%d output:%d, want non-empty token ids", len(traceEnv.InputTokenIDs), len(traceEnv.OutTokens))
	}
	t.Logf("trace: model=%s@%s input_tokens=%d out_tokens=%d generated=%d",
		traceEnv.ModelID, traceEnv.ProfileVersion,
		len(traceEnv.InputTokenIDs), len(traceEnv.OutTokens), traceEnv.GeneratedTokenCount)
	if traceEnv.GeneratedTokenCount != len(traceEnv.OutTokens) {
		t.Fatalf("trace generated count = %d, want %d", traceEnv.GeneratedTokenCount, len(traceEnv.OutTokens))
	}

	verify, err := svc.Verify(ctx, boundLocalVerifyFixture(t, VerifyRequest{
		RequestID:      "real-vllm-verify",
		JobID:          infer.JobID,
		TaskID:         infer.TaskID,
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Sample:         []byte("real-vllm-sample"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: trace.Data, Checkpoint: checkpoint.Data},
		},
	}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.SampleValueSequenceRef == "" || len(verify.SampleDigest) == 0 || len(verify.MaterialDigest) == 0 {
		t.Fatalf("Verify() = %+v, want sample sequence and digests", verify)
	}
	if verify.MainMismatchCount != 0 {
		t.Fatalf("Verify() MainMismatchCount = %d, want non-reject self-verify", verify.MainMismatchCount)
	}

	t.Logf("verify: main_mismatch=%d sample_digest=%x material_digest=%x",
		verify.MainMismatchCount, verify.SampleDigest, verify.MaterialDigest)

	sequence := fetchRealVLLMArtifact(t, ctx, svc, verify.SampleValueSequenceRef, false)
	var envelope verificationEnvelope
	if err := json.Unmarshal(sequence.Data, &envelope); err != nil {
		t.Fatalf("unmarshal verification envelope: %v", err)
	}
	if envelope.Verdict == verdictReject || envelope.RawVerdict == verdictReject {
		t.Fatalf("verification envelope = %+v, want non-reject self-verify", envelope)
	}
	// verdict collapses to PASS unless raw is REJECT, so raw is the informative
	// field: INCONCLUSIVE means no reject threshold tripped but not every strict
	// pass condition was met. Printing the metrics is what tells them apart -
	// otherwise a run that compared nothing looks like a run that compared
	// everything and agreed.
	t.Logf("verification envelope: verdict=%s raw_verdict=%s reject_reasons=%v sequence=%dB",
		envelope.Verdict, envelope.RawVerdict, envelope.RejectReasons, len(sequence.Data))
	t.Logf("verification metrics: %+v", envelope.Metrics)
	t.Logf("verification policy: %+v", envelope.Policy)
	if chainProfile {
		// Under the chain policy the numbers are whatever consensus published, so
		// what is checked is that a policy was resolved at all rather than the
		// service falling back to its built-in defaults. Those defaults differ
		// from the chain's (0.018 vs 0.05 mean-abs-diff, 9 vs 16 min finite), so
		// a fallback would be visible here.
		if envelope.Policy == localSingleSampleThresholds() {
			t.Fatalf("verification policy = %+v, want the chain policy rather than the built-in defaults", envelope.Policy)
		}
	} else if envelope.Policy.PassMinFiniteCount != 9 || envelope.Policy.RejectMeanAbsLogprobDiffMin != 0.5 {
		t.Fatalf("verification policy = %+v, want resolver profile policy", envelope.Policy)
	}
}

// TestLocalServiceRealVLLMChat is the chat-path counterpart of
// TestLocalServiceRealVLLM: it drives LocalService.Infer with an OpenAI Chat
// Completions body so the request is served over /v1/chat/completions rather than
// /v1/completions, and asserts the same end-to-end contract — a committed output,
// a chain-bound trace with generated token ids, and a self-Verify that does not
// reject. The committed output is additionally checked to be a clean OpenAI
// ChatCompletion object (object=chat.completion, protocol model_id, no leaked vLLM
// token-id internals), the shape buildChatCompletionOutput commits.
func TestLocalServiceRealVLLMChat(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM chat integration test", envTestVLLMURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-chat-test", 4, 5*time.Minute, 5*time.Minute)

	health, err := svc.Health(ctx, HealthRequest{RequestID: "real-vllm-chat-health"})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.Healthy || health.Error != nil {
		t.Fatalf("Health() = %+v, want healthy vLLM service", health)
	}

	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "real-vllm-chat-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}

	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}
	profileVersionNumber := parseRealVLLMUint32(t, envTestVLLMProfileVersion, profileVersion)
	topK := parseRealVLLMUint32(t, envTestVLLMTopK, strings.TrimSpace(os.Getenv(envTestVLLMTopK)))
	if topK == 0 {
		topK = defaultTopK
	}
	chainProfile := false
	if rpc := strings.TrimSpace(os.Getenv(envTestVLLMKeeperRPC)); rpc != "" {
		chainProfile = true
		svc.SetProfileResolver(keeperVLLMProfileResolver{keeper: chainclient.NewKeeperABCIClient(rpc)})
		t.Logf("real vLLM chat profile source: chain %s (model=%s profile=%d)", rpc, modelID, profileVersionNumber)
	} else {
		svc.SetProfileResolver(staticLocalProfileResolver{profile: resolvedCurrentProfile(modelID, uint32(profileVersionNumber), uint32(topK))})
		t.Logf("real vLLM chat profile source: static fixture (model=%s profile=%d top_k=%d); set %s to judge under the chain policy",
			modelID, profileVersionNumber, topK, envTestVLLMKeeperRPC)
	}

	// Ensure the chat body carries a generation cap and bind Infer and Verify to
	// the SAME max, so the trace's generation_params_digest matches the verify
	// request's generation context (they differ otherwise, since the chat path
	// enforces the cap only via the request).
	chatInput, chatMaxTokens := ensureChatMaxTokens(t, realVLLMChatInput(t))

	load, err := svc.LoadModel(ctx, LoadModelRequest{
		RequestID:  "real-vllm-chat-load",
		ModelID:    modelID,
		Capability: CapabilityLLMTextV1,
	})
	if err != nil {
		t.Fatalf("LoadModel(%q) error = %v", modelID, err)
	}
	if !load.Loaded {
		t.Fatalf("LoadModel(%q) = %+v, want loaded", modelID, load)
	}

	infer, err := svc.Infer(ctx, boundRealVLLMChatInfer(t, InferRequest{
		RequestID:      "real-vllm-chat-infer",
		JobID:          "real-vllm-chat-job",
		TaskID:         "real-vllm-chat-task",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          chatInput,
	}, chatMaxTokens))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if infer.OutputRef == "" || infer.TraceRef == "" || infer.CheckpointRef == "" {
		t.Fatalf("Infer() refs = %+v, want output, trace, and checkpoint refs", infer)
	}

	// The committed output is a clean OpenAI ChatCompletion object — not the
	// raw-text body inferV0 commits — and must not leak vLLM token-id internals.
	output := fetchRealVLLMArtifact(t, ctx, svc, infer.OutputRef, false)
	if len(output.Data) == 0 {
		t.Fatalf("Infer() output artifact is empty")
	}
	var chatOut chatCompletionOutput
	if err := json.Unmarshal(output.Data, &chatOut); err != nil {
		t.Fatalf("chat output is not JSON: %v (%s)", err, output.Data)
	}
	if chatOut.Object != "chat.completion" {
		t.Fatalf("chat output object = %q, want chat.completion", chatOut.Object)
	}
	if chatOut.Model != modelID {
		t.Fatalf("chat output model = %q, want chain model_id %q", chatOut.Model, modelID)
	}
	if len(chatOut.Choices) == 0 || chatOut.Choices[0].Message.Role != "assistant" {
		t.Fatalf("chat output choices = %+v, want one assistant message", chatOut.Choices)
	}
	if strings.Contains(string(output.Data), "prompt_token_ids") || strings.Contains(string(output.Data), "token_ids") {
		t.Fatalf("chat output must not leak vLLM internal token ids: %s", output.Data)
	}
	t.Logf("real vLLM chat output: content=%q finish=%q",
		strings.TrimSpace(chatOut.Choices[0].Message.Content), chatOut.Choices[0].FinishReason)

	trace := fetchRealVLLMArtifact(t, ctx, svc, infer.TraceRef, false)
	checkpoint := fetchRealVLLMArtifact(t, ctx, svc, infer.CheckpointRef, false)
	t.Logf("chat infer artifacts: output=%dB trace=%dB checkpoint=%dB finish_reason=%d",
		len(output.Data), len(trace.Data), len(checkpoint.Data), int32(infer.FinishReason))

	var traceEnv traceEnvelope
	if err := json.Unmarshal(trace.Data, &traceEnv); err != nil {
		t.Fatalf("unmarshal trace envelope: %v", err)
	}
	if traceEnv.ModelID != modelID || traceEnv.ProfileVersion != profileVersion {
		t.Fatalf("trace binding = %+v, want %s@%s", traceEnv, modelID, profileVersion)
	}
	if len(traceEnv.InputTokenIDs) == 0 || len(traceEnv.OutTokens) == 0 {
		t.Fatalf("trace token ids = input:%d output:%d, want non-empty token ids", len(traceEnv.InputTokenIDs), len(traceEnv.OutTokens))
	}
	if traceEnv.GeneratedTokenCount != len(traceEnv.OutTokens) {
		t.Fatalf("trace generated count = %d, want %d", traceEnv.GeneratedTokenCount, len(traceEnv.OutTokens))
	}
	t.Logf("chat trace: model=%s@%s input_tokens=%d out_tokens=%d generated=%d",
		traceEnv.ModelID, traceEnv.ProfileVersion,
		len(traceEnv.InputTokenIDs), len(traceEnv.OutTokens), traceEnv.GeneratedTokenCount)

	verify, err := svc.Verify(ctx, boundRealVLLMChatVerify(t, VerifyRequest{
		RequestID:      "real-vllm-chat-verify",
		JobID:          infer.JobID,
		TaskID:         infer.TaskID,
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Sample:         []byte("real-vllm-chat-sample"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: trace.Data, Checkpoint: checkpoint.Data},
		},
	}, chatMaxTokens))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.SampleValueSequenceRef == "" || len(verify.SampleDigest) == 0 || len(verify.MaterialDigest) == 0 {
		t.Fatalf("Verify() = %+v, want sample sequence and digests", verify)
	}
	if verify.MainMismatchCount != 0 {
		t.Fatalf("Verify() MainMismatchCount = %d, want non-reject self-verify", verify.MainMismatchCount)
	}
	t.Logf("chat verify: main_mismatch=%d sample_digest=%x material_digest=%x",
		verify.MainMismatchCount, verify.SampleDigest, verify.MaterialDigest)

	sequence := fetchRealVLLMArtifact(t, ctx, svc, verify.SampleValueSequenceRef, false)
	var envelope verificationEnvelope
	if err := json.Unmarshal(sequence.Data, &envelope); err != nil {
		t.Fatalf("unmarshal verification envelope: %v", err)
	}
	if envelope.Verdict == verdictReject || envelope.RawVerdict == verdictReject {
		t.Fatalf("verification envelope = %+v, want non-reject self-verify", envelope)
	}
	t.Logf("chat verification envelope: verdict=%s raw_verdict=%s reject_reasons=%v sequence=%dB",
		envelope.Verdict, envelope.RawVerdict, envelope.RejectReasons, len(sequence.Data))
	t.Logf("chat verification metrics: %+v", envelope.Metrics)
	t.Logf("chat verification policy: %+v", envelope.Policy)
	if chainProfile {
		// Under the chain policy the numbers are whatever consensus published, so
		// what is checked is that a policy was resolved at all rather than the
		// service falling back to its built-in defaults.
		if envelope.Policy == localSingleSampleThresholds() {
			t.Fatalf("verification policy = %+v, want the chain policy rather than the built-in defaults", envelope.Policy)
		}
	} else if envelope.Policy.PassMinFiniteCount != 9 || envelope.Policy.RejectMeanAbsLogprobDiffMin != 0.5 {
		t.Fatalf("verification policy = %+v, want resolver profile policy", envelope.Policy)
	}
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

// realVLLMChatMaxTokens bounds generation on the chat path when the request does
// not otherwise cap it. Unlike inferV0, the chat path forwards no profile-level
// max to vLLM (see buildChatCompletionRequest), so without a request cap the engine
// generates to its context limit — which then exceeds the MaxOutputTokens the
// evidence is validated against. A modest cap keeps the run bounded and fast.
const realVLLMChatMaxTokens = 256

// boundRealVLLMChatInfer binds a chat Infer request to a generation context capped
// at maxTokens. Only the Verify test uses it: Verify requires a generation context
// and re-derives against the one the trace carries, so the producing Infer must
// embed the same one. The streaming/observer/tool tests deliberately do NOT bind a
// generation context — that is the chat path's native mode (buildInferResultFromCompletion
// skips generation validation when req.Generation is nil), where the finish reason,
// including "tool_calls" -> EOS, is resolved by chatFinishResolver rather than the
// stricter localGenerationFinishReason, which has no tool_calls case. Those tests
// still cap generation through the request body (ensureChatMaxTokens) for a bounded
// run; they simply do not validate an on-chain generation contract that chat does
// not carry yet.
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

// ensureChatMaxTokens returns the chat body with a guaranteed generation cap and
// that cap's value: an existing max_completion_tokens / max_tokens is honoured,
// otherwise realVLLMChatMaxTokens is injected.
func ensureChatMaxTokens(t *testing.T, raw []byte) ([]byte, uint64) {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("chat input is not a JSON object: %v (%s)", err, raw)
	}
	if v, ok := body["max_completion_tokens"]; ok {
		return raw, parseChatMaxTokens(t, "max_completion_tokens", v)
	}
	if v, ok := body["max_tokens"]; ok {
		return raw, parseChatMaxTokens(t, "max_tokens", v)
	}
	body["max_completion_tokens"] = json.RawMessage(strconv.Itoa(realVLLMChatMaxTokens))
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal chat input with injected max: %v", err)
	}
	return out, realVLLMChatMaxTokens
}

func parseChatMaxTokens(t *testing.T, field string, raw json.RawMessage) uint64 {
	t.Helper()
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil || n <= 0 {
		t.Fatalf("chat input %s = %s, want a positive number", field, raw)
	}
	return uint64(n)
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
func streamFrame(text string, tokenIDs []int, tokenLogprobs []float64, topLogprobs []map[string]float64, promptTokenIDs []int, finishReason string) completionResponse {
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
	return resp
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

// inferArtifacts runs Infer and returns the stored output and trace bytes.
func inferArtifacts(t *testing.T, ctx context.Context, svc *LocalService, req InferRequest) (output, trace []byte) {
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

func TestLocalServiceInferStreamingMatchesNonStreaming(t *testing.T) {
	models := []string{"Qwen/Qwen3-8B"}
	req := boundLocalInferFixture(t, InferRequest{
		RequestID:  "parity",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	})
	ctx := context.Background()

	streamSrv, seen := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), models)
	streamSvc := NewLocalService(streamSrv.URL, "local-svc", 4, 0, 0) // streaming default on
	streamOut, streamTrace := inferArtifacts(t, ctx, streamSvc, req)
	if len(*seen) != 1 || !(*seen)[0].Stream {
		t.Fatalf("generation request Stream = %+v, want a single stream:true call", *seen)
	}

	jsonSrv, _ := newVLLMStubWithModels(t, genResponse(), verifyResponse(), models)
	jsonSvc := NewLocalService(jsonSrv.URL, "local-svc", 4, 0, 0)
	jsonSvc.SetStreamInference(false)
	jsonOut, jsonTrace := inferArtifacts(t, ctx, jsonSvc, req)

	if !bytes.Equal(streamOut, jsonOut) {
		t.Fatalf("streaming output = %q, non-streaming = %q", streamOut, jsonOut)
	}
	if !bytes.Equal(streamTrace, jsonTrace) {
		t.Fatalf("streaming trace and non-streaming trace differ:\n stream=%s\n json  =%s", streamTrace, jsonTrace)
	}
}

func TestLocalServiceInferStreamObserverReceivesFrames(t *testing.T) {
	srv, _ := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
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
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)
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

// TestLocalServiceInferStreamingYieldsOutputAndChunks shows how one caller gets
// both halves of a streaming Infer at once: the committed full output via the
// returned OutputRef (exactly what a non-streaming caller reads), and the
// incremental chunks via an InferStreamObserver. It pins the contract that the
// observed deltas are a faithful decomposition of that output — concatenating the
// per-frame TextDelta reproduces the stored output byte-for-byte, and the
// per-frame TokenIDs reassemble the trace's generated token ids in order.
func TestLocalServiceInferStreamingYieldsOutputAndChunks(t *testing.T) {
	srv, seen := newVLLMStreamStub(t, twoFrameGeneration(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0) // streaming default on
	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	ctx := context.Background()
	resp, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{
		RequestID:  "stream-out",
		JobID:      "stream-job",
		TaskID:     "stream-task",
		ModelID:    testQwenModelID(),
		Capability: CapabilityLLMTextV1,
		Input:      []byte("say hi"),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if len(*seen) != 1 || !(*seen)[0].Stream {
		t.Fatalf("generation request Stream = %+v, want a single stream:true call", *seen)
	}

	// (1) The committed full output — fetched by the returned ref.
	output, err := svc.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatalf("FetchArtifact(output) error = %v", err)
	}
	if string(output.Data) != "hello world" {
		t.Fatalf("full output = %q, want %q", output.Data, "hello world")
	}
	if resp.GeneratedTokenCount != 2 {
		t.Fatalf("GeneratedTokenCount = %d, want 2", resp.GeneratedTokenCount)
	}

	// (2) The chunks — split the observed frames into content deltas and the
	// single terminal done frame.
	var deltas []InferStreamFrame
	var done *InferStreamFrame
	for i := range obs.frames {
		if obs.frames[i].Done {
			done = &obs.frames[i]
			continue
		}
		deltas = append(deltas, obs.frames[i])
	}
	if done == nil {
		t.Fatalf("observer never delivered a terminal Done frame: %+v", obs.frames)
	}
	if done.FinishReason != "stop" {
		t.Fatalf("done frame finish reason = %q, want stop", done.FinishReason)
	}

	// Contract: the chunks are a faithful decomposition of the full output —
	// text concatenates back, token ids reassemble in order.
	var streamedText strings.Builder
	var streamedTokenIDs []int
	for _, d := range deltas {
		streamedText.WriteString(d.TextDelta)
		streamedTokenIDs = append(streamedTokenIDs, d.TokenIDs...)
	}
	if streamedText.String() != string(output.Data) {
		t.Fatalf("concatenated chunk text = %q, want it to equal the full output %q", streamedText.String(), output.Data)
	}

	trace, err := svc.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.TraceRef})
	if err != nil {
		t.Fatalf("FetchArtifact(trace) error = %v", err)
	}
	if got := outTokenIDs(decodeTraceEnvelope(t, trace.Data)); !slices.Equal(streamedTokenIDs, got) {
		t.Fatalf("reassembled chunk token ids = %v, want trace generated ids %v", streamedTokenIDs, got)
	}
}

func TestLocalServiceInferStreamingFallsBackToJSONResponse(t *testing.T) {
	// Streaming is on by default, but a server that answers /v1/completions with
	// application/json (a stub, or a vLLM that ignored stream:true) must still
	// decode — this is what keeps every non-SSE stub test green.
	srv, seen := newVLLMStubWithModels(t, genResponse(), verifyResponse(), []string{"Qwen/Qwen3-8B"})
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

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

// TestLocalServiceRealVLLMStreamingParity confirms, against a real vLLM, that the
// SSE reassembly recovers the same output and the same input/generated token id
// sequences as the non-streaming path. Greedy decoding (temperature 0, seed 0)
// makes the two runs comparable; token ids are compared rather than raw logprob
// floats, which a real engine may vary in the low bits between runs.
func TestLocalServiceRealVLLMStreamingParity(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM streaming parity test", envTestVLLMURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-stream", 4, 5*time.Minute, 5*time.Minute)
	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "stream-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}
	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}
	prompt := strings.TrimSpace(os.Getenv(envTestVLLMPrompt))
	if prompt == "" {
		prompt = "Write exactly three words about distributed inference."
	}
	req := boundLocalInferFixture(t, InferRequest{
		RequestID:      "stream-parity",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          []byte(prompt),
	})

	svc.SetStreamInference(true)
	streamOut, streamTrace := inferArtifacts(t, ctx, svc, req)
	svc.SetStreamInference(false)
	jsonOut, jsonTrace := inferArtifacts(t, ctx, svc, req)

	if !bytes.Equal(streamOut, jsonOut) {
		t.Fatalf("real vLLM output differs streaming vs non-streaming:\n stream=%q\n json  =%q", streamOut, jsonOut)
	}

	streamEnv := decodeTraceEnvelope(t, streamTrace)
	jsonEnv := decodeTraceEnvelope(t, jsonTrace)
	if !slices.Equal(streamEnv.InputTokenIDs, jsonEnv.InputTokenIDs) {
		t.Fatalf("input token ids differ (prompt_token_ids reassembly):\n stream=%v\n json  =%v", streamEnv.InputTokenIDs, jsonEnv.InputTokenIDs)
	}
	if !slices.Equal(outTokenIDs(streamEnv), outTokenIDs(jsonEnv)) {
		t.Fatalf("generated token ids differ (token_ids reassembly):\n stream=%v\n json  =%v", outTokenIDs(streamEnv), outTokenIDs(jsonEnv))
	}
	if streamEnv.GeneratedTokenCount != jsonEnv.GeneratedTokenCount || streamEnv.FinishReason != jsonEnv.FinishReason {
		t.Fatalf("generated count/finish differ: stream=%d/%q json=%d/%q",
			streamEnv.GeneratedTokenCount, streamEnv.FinishReason, jsonEnv.GeneratedTokenCount, jsonEnv.FinishReason)
	}
	t.Logf("real vLLM streaming parity: output=%dB input_tokens=%d generated=%d finish=%q",
		len(streamOut), len(streamEnv.InputTokenIDs), streamEnv.GeneratedTokenCount, streamEnv.FinishReason)
}

// TestLocalServiceRealVLLMStreamObserver drives a real vLLM over the SSE transport
// and asserts the InferStreamObserver receives that engine's incremental frames,
// and that those frames are a faithful decomposition of the committed output:
// concatenating every delta's TextDelta reproduces the stored output byte-for-byte,
// and the per-frame TokenIDs reassemble the trace's generated token ids in order.
// It is the real-engine counterpart of TestLocalServiceInferStreamingYieldsOutputAndChunks,
// which pins the same contract against an httptest SSE stub. Frame counts are not
// asserted — a real engine may pack several tokens into one SSE frame — so the
// contract is expressed over the reassembly, not the frame boundaries.
func TestLocalServiceRealVLLMStreamObserver(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM streaming observer test", envTestVLLMURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-stream-obs", 4, 5*time.Minute, 5*time.Minute)
	svc.SetStreamInference(true)

	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "stream-obs-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}
	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}
	prompt := strings.TrimSpace(os.Getenv(envTestVLLMPrompt))
	if prompt == "" {
		prompt = "Write exactly three words about distributed inference."
	}

	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	resp, err := svc.Infer(ctx, boundLocalInferFixture(t, InferRequest{
		RequestID:      "real-stream-obs",
		JobID:          "real-stream-obs-job",
		TaskID:         "real-stream-obs-task",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          []byte(prompt),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	// (1) The committed full output — exactly what a non-streaming caller reads.
	output := fetchRealVLLMArtifact(t, ctx, svc, resp.OutputRef, false)
	if len(output.Data) == 0 {
		t.Fatalf("Infer() output artifact is empty")
	}

	// (2) The chunks — every frame carries the request identity, and the frames
	// split into content deltas plus a single terminal done frame.
	var deltas []InferStreamFrame
	var done *InferStreamFrame
	for i := range obs.frames {
		f := obs.frames[i]
		if f.RequestID != "real-stream-obs" || f.JobID != "real-stream-obs-job" ||
			f.TaskID != "real-stream-obs-task" || f.ModelID != modelID {
			t.Fatalf("frame[%d] identity = %+v, want real-stream-obs/real-stream-obs-job/real-stream-obs-task/%s", i, f, modelID)
		}
		if f.Done {
			done = &obs.frames[i]
			continue
		}
		deltas = append(deltas, f)
	}
	if len(deltas) == 0 {
		t.Fatalf("observer received no content delta frames: %+v", obs.frames)
	}
	if done == nil {
		t.Fatalf("observer never delivered a terminal Done frame: %+v", obs.frames)
	}

	// Contract: the chunks are a faithful decomposition of the full output.
	var streamedText strings.Builder
	var streamedTokenIDs []int
	for _, d := range deltas {
		streamedText.WriteString(d.TextDelta)
		streamedTokenIDs = append(streamedTokenIDs, d.TokenIDs...)
	}
	if streamedText.String() != string(output.Data) {
		t.Fatalf("concatenated chunk text = %q, want it to equal the full output %q", streamedText.String(), output.Data)
	}

	trace := fetchRealVLLMArtifact(t, ctx, svc, resp.TraceRef, false)
	traceIDs := outTokenIDs(decodeTraceEnvelope(t, trace.Data))
	if !slices.Equal(streamedTokenIDs, traceIDs) {
		t.Fatalf("reassembled chunk token ids = %v, want trace generated ids %v", streamedTokenIDs, traceIDs)
	}
	if int(resp.GeneratedTokenCount) != len(traceIDs) {
		t.Fatalf("GeneratedTokenCount = %d, want %d", resp.GeneratedTokenCount, len(traceIDs))
	}
	t.Logf("real vLLM stream observer: output=%dB delta_frames=%d generated_tokens=%d finish=%q",
		len(output.Data), len(deltas), resp.GeneratedTokenCount, done.FinishReason)
}

// TestLocalServiceRealVLLMChatStreamingParity is the chat counterpart of
// TestLocalServiceRealVLLMStreamingParity: it runs the same chat request over the
// SSE transport and over the single-JSON-body transport and asserts the two agree.
// Byte parity of the committed output is deliberately NOT asserted — a real chat
// completion embeds a per-request id and created timestamp, so two calls differ in
// those envelope fields even under greedy decoding. Parity is expressed over what
// the protocol actually commits to: the assistant content, the finish reason, and
// the input/generated token id sequences the Verifier reconstructs from.
func TestLocalServiceRealVLLMChatStreamingParity(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM chat streaming parity test", envTestVLLMURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-chat-stream", 4, 5*time.Minute, 5*time.Minute)
	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "chat-stream-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}
	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}
	// Native chat mode: no generation context, generation bounded via the body.
	input, _ := ensureChatMaxTokens(t, realVLLMChatInput(t))
	req := InferRequest{
		RequestID:      "chat-stream-parity",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          input,
	}

	svc.SetStreamInference(true)
	streamOut, streamTrace := chatInferArtifacts(t, ctx, svc, req)
	svc.SetStreamInference(false)
	jsonOut, jsonTrace := chatInferArtifacts(t, ctx, svc, req)

	// Content parity — the delivered assistant message, ignoring the per-request
	// id/created envelope fields a real engine varies between calls.
	streamMsg := decodeChatOutputMessage(t, streamOut)
	jsonMsg := decodeChatOutputMessage(t, jsonOut)
	if streamMsg.Content != jsonMsg.Content {
		t.Fatalf("real vLLM chat content differs streaming vs non-streaming:\n stream=%q\n json  =%q", streamMsg.Content, jsonMsg.Content)
	}
	if streamMsg.FinishReason != jsonMsg.FinishReason {
		t.Fatalf("real vLLM chat finish_reason differs: stream=%q json=%q", streamMsg.FinishReason, jsonMsg.FinishReason)
	}
	if !bytes.Equal(streamMsg.ToolCalls, jsonMsg.ToolCalls) {
		t.Fatalf("real vLLM chat tool_calls differ:\n stream=%s\n json  =%s", streamMsg.ToolCalls, jsonMsg.ToolCalls)
	}

	// Token-id parity — the material the trace/checkpoint bind and the Verifier
	// reconstructs from, compared instead of raw logprob floats the engine may vary
	// in the low bits between runs.
	streamEnv := decodeTraceEnvelope(t, streamTrace)
	jsonEnv := decodeTraceEnvelope(t, jsonTrace)
	if !slices.Equal(streamEnv.InputTokenIDs, jsonEnv.InputTokenIDs) {
		t.Fatalf("input token ids differ (prompt_token_ids reassembly):\n stream=%v\n json  =%v", streamEnv.InputTokenIDs, jsonEnv.InputTokenIDs)
	}
	if !slices.Equal(outTokenIDs(streamEnv), outTokenIDs(jsonEnv)) {
		t.Fatalf("generated token ids differ (token_ids reassembly):\n stream=%v\n json  =%v", outTokenIDs(streamEnv), outTokenIDs(jsonEnv))
	}
	if streamEnv.GeneratedTokenCount != jsonEnv.GeneratedTokenCount || streamEnv.FinishReason != jsonEnv.FinishReason {
		t.Fatalf("generated count/finish differ: stream=%d/%q json=%d/%q",
			streamEnv.GeneratedTokenCount, streamEnv.FinishReason, jsonEnv.GeneratedTokenCount, jsonEnv.FinishReason)
	}
	t.Logf("real vLLM chat streaming parity: content=%dB input_tokens=%d generated=%d finish=%q",
		len(streamMsg.Content), len(streamEnv.InputTokenIDs), streamEnv.GeneratedTokenCount, streamEnv.FinishReason)
}

// TestLocalServiceRealVLLMChatStreamObserver is the chat counterpart of
// TestLocalServiceRealVLLMStreamObserver: it drives a real vLLM chat generation
// over SSE and asserts the InferStreamObserver receives that engine's incremental
// frames, and that those frames are a faithful decomposition of the committed
// output — concatenating every delta's TextDelta reproduces the delivered
// assistant content, and the per-frame TokenIDs reassemble the trace's generated
// token ids in order. Frame counts are not asserted (a real engine may pack several
// tokens into one SSE frame), so the contract is over the reassembly.
func TestLocalServiceRealVLLMChatStreamObserver(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM chat streaming observer test", envTestVLLMURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-chat-stream-obs", 4, 5*time.Minute, 5*time.Minute)
	svc.SetStreamInference(true)

	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "chat-stream-obs-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}
	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}

	obs := &recordingObserver{}
	svc.SetInferStreamObserver(obs)

	// Native chat mode: no generation context, generation bounded via the body.
	input, _ := ensureChatMaxTokens(t, realVLLMChatInput(t))
	resp, err := svc.Infer(ctx, InferRequest{
		RequestID:      "real-chat-stream-obs",
		JobID:          "real-chat-stream-obs-job",
		TaskID:         "real-chat-stream-obs-task",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          input,
	})
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}

	// (1) The committed full output — the delivered assistant content.
	output := fetchRealVLLMArtifact(t, ctx, svc, resp.OutputRef, false)
	msg := decodeChatOutputMessage(t, output.Data)

	// (2) The chunks — every frame carries the request identity, split into content
	// deltas plus a single terminal done frame.
	var deltas []InferStreamFrame
	var done *InferStreamFrame
	for i := range obs.frames {
		f := obs.frames[i]
		if f.RequestID != "real-chat-stream-obs" || f.JobID != "real-chat-stream-obs-job" ||
			f.TaskID != "real-chat-stream-obs-task" || f.ModelID != modelID {
			t.Fatalf("frame[%d] identity = %+v, want real-chat-stream-obs/real-chat-stream-obs-job/real-chat-stream-obs-task/%s", i, f, modelID)
		}
		if f.Done {
			done = &obs.frames[i]
			continue
		}
		deltas = append(deltas, f)
	}
	if len(deltas) == 0 {
		t.Fatalf("observer received no content delta frames: %+v", obs.frames)
	}
	if done == nil {
		t.Fatalf("observer never delivered a terminal Done frame: %+v", obs.frames)
	}

	// Contract: the chunks are a faithful decomposition of the committed output.
	var streamedText strings.Builder
	var streamedTokenIDs []int
	for _, d := range deltas {
		streamedText.WriteString(d.TextDelta)
		streamedTokenIDs = append(streamedTokenIDs, d.TokenIDs...)
	}
	if streamedText.String() != msg.Content {
		t.Fatalf("concatenated chunk text = %q, want it to equal the committed content %q", streamedText.String(), msg.Content)
	}

	trace := fetchRealVLLMArtifact(t, ctx, svc, resp.TraceRef, false)
	traceIDs := outTokenIDs(decodeTraceEnvelope(t, trace.Data))
	if !slices.Equal(streamedTokenIDs, traceIDs) {
		t.Fatalf("reassembled chunk token ids = %v, want trace generated ids %v", streamedTokenIDs, traceIDs)
	}
	if int(resp.GeneratedTokenCount) != len(traceIDs) {
		t.Fatalf("GeneratedTokenCount = %d, want %d", resp.GeneratedTokenCount, len(traceIDs))
	}
	t.Logf("real vLLM chat stream observer: content=%dB delta_frames=%d generated_tokens=%d finish=%q",
		len(msg.Content), len(deltas), resp.GeneratedTokenCount, done.FinishReason)
}

// TestLocalServiceRealVLLMChatToolCallsStreamingParity is the real-engine
// counterpart of TestLocalServiceChatStreamingToolCallsMatchesNonStreaming: it
// drives a tools-bearing chat request against a real vLLM over both transports and
// asserts the committed tool_calls agree byte-for-byte. This is the parity that
// matters for function calls, because the two transports build tool_calls by
// different routes — the non-streaming path re-marshals vLLM's array
// (canonicalToolCalls), the streaming path merges per-index argument fragments
// (toolCallAccumulator) — and their bytes must be identical. The test is gated on
// an operator-supplied tools request (envTestVLLMChatToolInput) because whether a
// given model actually emits a tool_call is model-specific; it fails loudly if the
// supplied input did not trigger one, since equal-but-empty proves nothing.
func TestLocalServiceRealVLLMChatToolCallsStreamingParity(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM chat tool-calls parity test", envTestVLLMURL)
	}
	toolInput := strings.TrimSpace(os.Getenv(envTestVLLMChatToolInput))
	if toolInput == "" {
		t.Skipf("set %s to a tools-bearing chat request to run the tool-calls streaming parity test", envTestVLLMChatToolInput)
	}
	if _, isChat, err := parseChatInferInput([]byte(toolInput)); err != nil || !isChat {
		t.Fatalf("%s is not a valid chat request (isChat=%v err=%v)", envTestVLLMChatToolInput, isChat, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	svc := NewLocalService(endpoint, "real-vllm-chat-tools", 4, 5*time.Minute, 5*time.Minute)
	caps, err := svc.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "chat-tools-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatalf("ListCapabilities() = %+v, want at least one vLLM model", caps)
	}
	modelID := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}
	profileVersion := strings.TrimSpace(os.Getenv(envTestVLLMProfileVersion))
	if profileVersion == "" {
		profileVersion = "1"
	}
	// Native chat mode (no generation context): a "tool_calls" finish resolves to
	// EOS through chatFinishResolver. Binding a generation context would route the
	// finish through localGenerationFinishReason, which has no tool_calls case.
	input, _ := ensureChatMaxTokens(t, []byte(toolInput))
	req := InferRequest{
		RequestID:      "chat-tools-parity",
		ModelID:        modelID,
		ProfileVersion: profileVersion,
		Capability:     CapabilityLLMTextV1,
		Input:          input,
	}

	svc.SetStreamInference(true)
	streamOut, _ := chatInferArtifacts(t, ctx, svc, req)
	svc.SetStreamInference(false)
	jsonOut, _ := chatInferArtifacts(t, ctx, svc, req)

	streamMsg := decodeChatOutputMessage(t, streamOut)
	jsonMsg := decodeChatOutputMessage(t, jsonOut)

	// The supplied input must actually have triggered a tool call — otherwise the
	// byte-equality below holds trivially and covers nothing.
	if !hasToolCalls(jsonMsg.ToolCalls) || !hasToolCalls(streamMsg.ToolCalls) {
		t.Fatalf("%s did not trigger a tool_calls response (stream=%s json=%s); supply an input the model calls a tool for",
			envTestVLLMChatToolInput, streamMsg.ToolCalls, jsonMsg.ToolCalls)
	}
	// Contract: the two transports produce the SAME tool call despite building it by
	// different routes (non-streaming re-marshals vLLM's array; streaming merges
	// per-index argument fragments). The per-call id is excluded because it is a
	// nonce vLLM assigns per request — the two separate calls get different ids, the
	// same way the chat envelope's id/created vary — so parity is expressed over the
	// type, function name, and reassembled arguments.
	streamCalls := toolCallsWithoutIDs(t, streamMsg.ToolCalls)
	jsonCalls := toolCallsWithoutIDs(t, jsonMsg.ToolCalls)
	if !bytes.Equal(streamCalls, jsonCalls) {
		t.Fatalf("real vLLM tool_calls differ streaming vs non-streaming (ignoring id):\n stream=%s\n json  =%s", streamCalls, jsonCalls)
	}
	if streamMsg.FinishReason != jsonMsg.FinishReason {
		t.Fatalf("real vLLM tool_calls finish_reason differs: stream=%q json=%q", streamMsg.FinishReason, jsonMsg.FinishReason)
	}
	t.Logf("real vLLM tool_calls streaming parity: finish=%q tool_calls=%s", streamMsg.FinishReason, streamCalls)
}

// toolCallsWithoutIDs canonicalises committed tool_calls for comparison by zeroing
// each call's id (a per-request nonce) and re-marshalling, so equality reflects the
// type, function name, and arguments — the parts the two transports actually build.
func toolCallsWithoutIDs(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var calls []chatToolCall
	if err := json.Unmarshal(raw, &calls); err != nil {
		t.Fatalf("decode tool_calls: %v (%s)", err, raw)
	}
	for i := range calls {
		calls[i].ID = ""
	}
	out, err := json.Marshal(calls)
	if err != nil {
		t.Fatalf("marshal tool_calls: %v", err)
	}
	return out
}

// hasToolCalls reports whether a committed message's tool_calls field carries at
// least one call (absent / null / empty-array all count as none).
func hasToolCalls(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || string(trimmed) == "[]" {
		return false
	}
	var calls []json.RawMessage
	if err := json.Unmarshal(trimmed, &calls); err != nil {
		return false
	}
	return len(calls) > 0
}

// decodeChatOutputMessage decodes a committed chat output and returns its single
// choice's message plus finish reason, the fields parity is expressed over (the
// id/created envelope a real engine varies between calls are intentionally
// dropped).
func decodeChatOutputMessage(t *testing.T, data []byte) struct {
	Content      string
	FinishReason string
	ToolCalls    json.RawMessage
} {
	t.Helper()
	var out chatCompletionOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("chat output is not JSON: %v (%s)", err, data)
	}
	if len(out.Choices) == 0 {
		t.Fatalf("chat output has no choices: %s", data)
	}
	c := out.Choices[0]
	return struct {
		Content      string
		FinishReason string
		ToolCalls    json.RawMessage
	}{Content: c.Message.Content, FinishReason: c.FinishReason, ToolCalls: c.Message.ToolCalls}
}

func decodeTraceEnvelope(t *testing.T, data []byte) traceEnvelope {
	t.Helper()
	var env traceEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal trace envelope: %v", err)
	}
	return env
}

func outTokenIDs(env traceEnvelope) []int {
	ids := make([]int, 0, len(env.OutTokens))
	for _, tok := range env.OutTokens {
		ids = append(ids, tok.TokenID)
	}
	return ids
}
