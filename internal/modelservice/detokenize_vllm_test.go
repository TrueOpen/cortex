package modelservice

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// envTestVLLMEOSTokenIDs lists the served model's eos_token_ids (the manifest's
// output_decoding set), comma-separated. Defaults to Qwen3-8B's.
const envTestVLLMEOSTokenIDs = "CORTEX_TEST_VLLM_EOS_IDS"

// TestRealVLLMOutputDecodeFullFlow drives the whole issue-#35 flow against a
// real vLLM: the Worker's chat Infer (committed output corroborated against
// the engine's decode before committing), the Verifier's decode comparison
// (DetokenizeCommitted vs the confirmed bytes, both folded by CanonicalUTF8,
// including the tamper case), and the Verifier's teacher-forced prefill over
// the committed token ids. Gated on CORTEX_TEST_VLLM_URL:
//
//	CORTEX_TEST_VLLM_URL=http://127.0.0.1:8000 \
//	CORTEX_TEST_VLLM_MODEL=Qwen/Qwen3-8B \
//	CORTEX_TEST_VLLM_EOS_IDS=151645,151643 \
//	go test ./internal/modelservice -run TestRealVLLMOutputDecodeFullFlow -v
//
// CORTEX_TEST_VLLM_PROMPT or CORTEX_TEST_VLLM_CHAT_INPUT picks the input, and
// CORTEX_TEST_VLLM_TOP_K the required top-k (default 20, vLLM's max_logprobs).
func TestRealVLLMOutputDecodeFullFlow(t *testing.T) {
	url := strings.TrimSpace(os.Getenv(envTestVLLMURL))
	if url == "" {
		t.Skipf("%s not set; export it to run the full decode flow against a real vLLM", envTestVLLMURL)
	}
	served := strings.TrimSpace(os.Getenv(envTestVLLMModel))
	if served == "" {
		served = "Qwen/Qwen3-8B"
	}
	rawEOS := strings.TrimSpace(os.Getenv(envTestVLLMEOSTokenIDs))
	if rawEOS == "" {
		rawEOS = "151645,151643"
	}
	var eosIDs []string
	var eosTokenIDs []uint32
	for field := range strings.SplitSeq(rawEOS, ",") {
		id, err := strconv.ParseUint(strings.TrimSpace(field), 10, 32)
		if err != nil {
			t.Fatalf("%s entry %q: %v", envTestVLLMEOSTokenIDs, field, err)
		}
		eosIDs = append(eosIDs, strconv.FormatUint(id, 10))
		eosTokenIDs = append(eosTokenIDs, uint32(id))
	}
	topK := uint32(20)
	if raw := strings.TrimSpace(os.Getenv(envTestVLLMTopK)); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			t.Fatalf("%s: %v", envTestVLLMTopK, err)
		}
		topK = uint32(parsed)
	}

	// The manifest this run decodes under: the real model's eos_token_ids in
	// the same output_decoding shape the chain-published manifest carries.
	manifest := fmt.Appendf(nil, `{"manifest_version":4,"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[%s],"render_special_tokens":true,"strip_trailing_eos":true}}`,
		strings.Join(eosIDs, ","))
	snapshot := liveLikeProfileSnapshotWithTopK(topK)(testQwenModelID(), "1")
	manifestHash := modelmanifest.Hash(manifest)
	snapshot.ManifestHash = chainclient.ProtoBytes32(manifestHash[:])

	newService := func() *LocalService {
		svc := NewLocalService(url, "real-vllm-decode", 4, 10*time.Minute, time.Minute)
		if err := svc.BindModel(testQwenModelID(), LocalModelProvider, served); err != nil {
			t.Fatal(err)
		}
		svc.SetProfileResolver(staticLocalProfileResolver{profile: snapshot})
		svc.SetOutputDecodingSource(outputDecodingSourceFunc(func(_ context.Context, profile chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
			return modelmanifest.VerifyOutputDecoding(manifest, profile.ManifestHash)
		}))
		svc.SetDetokenizeCorroboration(true)
		return svc
	}
	svc := newService()
	ctx := context.Background()

	// DECODE_VECTORS over the real engine. The expected bytes come from the
	// engine's own round trip (what the offline generator derives from the HF
	// tokenizer directly), so this exercises the gate's plumbing, the
	// trailing-EOS strip and the mid-character truncation against a live
	// tokenizer rather than its independent authorship.
	tokenize := func(text string) []uint32 {
		var resp tokenizeResponse
		if err := svc.post(ctx, "/tokenize", tokenizeRequest{Model: served, Prompt: text}, &resp); err != nil {
			t.Fatalf("tokenize %q: %v", text, err)
		}
		ids := make([]uint32, len(resp.Tokens))
		for i, id := range resp.Tokens {
			ids[i] = uint32(id)
		}
		return ids
	}
	decodeReal := func(ids []uint32) []byte {
		ints := make([]int, len(ids))
		for i, id := range ids {
			ints[i] = int(id)
		}
		decoded, err := svc.detokenizeIDs(ctx, served, ints)
		if err != nil {
			t.Fatalf("detokenize %v: %v", ids, err)
		}
		return decoded
	}
	sentence := tokenize("Hello 世界, decode vectors bind this engine.")
	vectors := []modelmanifest.DecodeVector{
		{TokenIDs: sentence, ExpectedBytes: decodeReal(sentence)},
		// One trailing EOS strips; the expected bytes stay the sentence's.
		{TokenIDs: append(slices.Clone(sentence), eosTokenIDs[0]), ExpectedBytes: decodeReal(sentence)},
		// Nothing but an EOS commits the empty output.
		{TokenIDs: []uint32{eosTokenIDs[0]}, ExpectedBytes: []byte{}},
	}
	if emoji := tokenize("\U0001F30D"); len(emoji) >= 2 {
		truncated := emoji[:len(emoji)-1]
		expected := decodeReal(truncated)
		if !strings.Contains(string(expected), "�") {
			t.Fatalf("mid-character truncation %v decoded to %q without U+FFFD", truncated, expected)
		}
		vectors = append(vectors, modelmanifest.DecodeVector{TokenIDs: truncated, ExpectedBytes: expected})
	}
	svc.SetDecodeVectorsSource(&countingVectorsSource{vectors: vectors})
	t.Logf("gating the flow on %d decode vectors", len(vectors))

	// Worker side: infer and commit. Corroboration runs inside Infer, so a
	// committed output already survived the engine's own decode once.
	resp, err := svc.Infer(ctx, boundRealVLLMChatInfer(t, InferRequest{
		RequestID: "real-decode", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Input: realVLLMChatInput(t),
	}, realVLLMChatMaxTokens))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	output, err := svc.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.OutputRef, AllowEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	idsArtifact, err := svc.FetchArtifact(ctx, FetchArtifactRequest{Ref: resp.TokenIDsRef})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := DecodeTokenIDsArtifact(idsArtifact.Data)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("generated %d tokens, finish %v, committed %d bytes: %.120q",
		len(ids.Generated), resp.FinishReason, len(output.Data), output.Data)

	// Verifier side, rule #35: the confirmed output must be the decode of the
	// committed token ids.
	decoded, err := svc.DetokenizeCommitted(ctx, testQwenModelID(), "1", ids.Generated)
	if err != nil {
		t.Fatalf("DetokenizeCommitted() error = %v", err)
	}
	if string(decoded) != string(CanonicalUTF8(output.Data)) {
		t.Fatalf("decode(T) != committed output:\n decode: %q\n output: %q", decoded, output.Data)
	}
	tampered := append([]byte("TAMPERED:"), output.Data...)
	if string(decoded) == string(CanonicalUTF8(tampered)) {
		t.Fatal("decode(T) matched a tampered output")
	}

	// A node whose engine cannot reproduce a declared vector refuses to decode
	// at all, before any comparison or commitment.
	gated := newService()
	gated.SetDecodeVectorsSource(&countingVectorsSource{vectors: []modelmanifest.DecodeVector{
		{TokenIDs: sentence, ExpectedBytes: append([]byte("NOT THE DECODE "), decodeReal(sentence)...)},
	}})
	if _, err := gated.DetokenizeCommitted(ctx, testQwenModelID(), "1", ids.Generated); err == nil || !strings.Contains(err.Error(), "DECODE_VECTORS[0]") {
		t.Fatalf("DetokenizeCommitted() with a failing vector = %v, want the vector refusal", err)
	}

	// Verifier side, scoring: teacher-force the committed token ids and get a
	// value for every generated position.
	vresp, err := svc.Verify(ctx, boundRealVLLMChatVerify(t, VerifyRequest{
		RequestID: "real-decode-verify", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Sample: []byte("real-decode-seed"), TokenIDs: ids,
	}, realVLLMChatMaxTokens))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(vresp.VerifierValues) != len(ids.Generated) {
		t.Fatalf("verifier values = %d, want one per generated token (%d)", len(vresp.VerifierValues), len(ids.Generated))
	}
	missing := 0
	for _, value := range vresp.VerifierValues {
		if value.Missing {
			missing++
		}
	}
	t.Logf("verify scored %d positions (%d missing): the full infer -> decode-check -> verify flow holds", len(vresp.VerifierValues), missing)
}
