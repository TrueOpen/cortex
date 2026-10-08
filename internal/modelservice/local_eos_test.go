package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// testEOSTokenID is in testManifestBytes' eos_token_ids, and eosBytes is the
// UTF-8 the engine reports for it on the logprob entry. The bytes are
// deliberately non-empty and recognisable: vLLM returns them even though it
// leaves the token out of message.content.
const testEOSTokenID = 151645

var eosBytes = []byte("<|im_end|>")

// genToken is one generated token and the bytes the engine reports for it.
type genToken struct {
	id    int
	bytes []byte
}

func tokenBytesAsInts(raw []byte) []int {
	out := make([]int, len(raw))
	for i, b := range raw {
		out[i] = int(b)
	}
	return out
}

func chatLogprobEntry(token genToken) chatRespLogprobContent {
	key := fmt.Sprintf("token_id:%d", token.id)
	return chatRespLogprobContent{Token: key, Logprob: -0.1, Bytes: tokenBytesAsInts(token.bytes),
		TopLogprobs: []chatRespTopLogprob{{Token: key, Logprob: -0.1}}}
}

// chatGeneration is tokens as a non-streaming chat response.
func chatGeneration(tokens []genToken, finish string) chatCompletionResponse {
	resp := chatCompletionResponse{
		ID: "chatcmpl-eos", Created: 1700000000, Model: "Qwen/Qwen3-8B",
		Usage:          &chatRespUsage{PromptTokens: 3, CompletionTokens: len(tokens), TotalTokens: 3 + len(tokens)},
		PromptTokenIDs: []int{1, 2, 3},
		Choices: []chatResponseChoice{{
			Message: chatRespMessage{Role: "assistant", Content: "ENGINE-DETOKENIZED"}, FinishReason: finish,
			Logprobs: &chatRespLogprobs{},
		}},
	}
	for _, token := range tokens {
		resp.Choices[0].TokenIDs = append(resp.Choices[0].TokenIDs, token.id)
		resp.Choices[0].Logprobs.Content = append(resp.Choices[0].Logprobs.Content, chatLogprobEntry(token))
	}
	return resp
}

// chatGenerationChunks is tokens as an SSE stream, one token per frame, with
// the finish reason on the last token's frame and a usage-only frame after it.
func chatGenerationChunks(tokens []genToken, finish string) []chatCompletionChunk {
	var chunks []chatCompletionChunk
	for i, token := range tokens {
		chunk := chatCompletionChunk{ID: "chatcmpl-eos", Created: 1700000000, Model: "Qwen/Qwen3-8B",
			Choices: []chatChunkChoice{{TokenIDs: []int{token.id}, Logprobs: &chatRespLogprobs{Content: []chatRespLogprobContent{chatLogprobEntry(token)}}}}}
		if i == 0 {
			chunk.PromptTokenIDs = []int{1, 2, 3}
			chunk.Choices[0].Delta.Role = "assistant"
		}
		if i == len(tokens)-1 {
			chunk.Choices[0].FinishReason = finish
		}
		chunks = append(chunks, chunk)
	}
	return append(chunks, chatCompletionChunk{ID: "chatcmpl-eos", Created: 1700000000, Model: "Qwen/Qwen3-8B",
		Usage: &chatRespUsage{PromptTokens: 3, CompletionTokens: len(tokens), TotalTokens: 3 + len(tokens)}})
}

// chatBoundWithLimit is chatBound with the order's max_output_tokens set, so a
// generation can end on a "length" finish.
func chatBoundWithLimit(t *testing.T, req InferRequest, limit uint64) InferRequest {
	t.Helper()
	g := localTestGeneration(req.ModelID, 1)
	g.TaskType = 2 // CHAT
	g.Params.MaxOutputTokens = limit
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.ProfileVersion, req.Generation, req.GenerationParamsDigest = "1", g, digest[:]
	return req
}

// chainBoundLocalService is a local service with a chain-resolved profile and
// the test manifest's output_decoding.
func chainBoundLocalService(url string) *LocalService {
	svc := newBoundLocalService(url, "local-svc", 4, 0, 0)
	svc.SetOutputDecodingSource(testOutputDecodingSource())
	// defaultTopK, not the live profile's 20: the stubs pad top_logprobs to
	// defaultTopK, and required_top_k is checked against what arrives.
	svc.SetProfileResolver(staticLocalProfileResolver{profile: liveLikeProfileSnapshotWithTopK(defaultTopK)(testQwenModelID(), "1")})
	return svc
}

var (
	hello = genToken{10, []byte("hello")}
	world = genToken{11, []byte(" world")}
	eos   = genToken{testEOSTokenID, eosBytes}
	// U+4F60 U+597D is E4 BD A0 / E5 A5 BD, cut so that neither character sits inside
	// one token.
	niHaoA = genToken{20, []byte{0xE4, 0xBD}}
	niHaoB = genToken{21, []byte{0xA0, 0xE5, 0xA5}}
	niHaoC = genToken{22, []byte{0xBD}}
)

var eosRuleCases = []struct {
	name   string
	tokens []genToken
	finish string
	want   string
}{
	// The one trailing EOS is left out of the committed output.
	{"eos ending", []genToken{hello, world, eos}, "stop", "hello world"},
	// Nothing is left out when the generation did not end on an EOS.
	{"max tokens ending", []genToken{hello, world}, "length", "hello world"},
	// An EOS token anywhere else is ordinary output.
	{"eos in the middle", []genToken{hello, eos, world}, "length", "hello<|im_end|> world"},
	// Characters split across tokens, then an EOS.
	{"split multibyte then eos", []genToken{niHaoA, niHaoB, niHaoC, eos}, "stop", "\u4f60\u597d"},
}

// The committed output is the generated tokens' bytes minus one trailing
// token if and only if it is an EOS token, and the streamed frames carry
// exactly those bytes: no more (never an EOS that is then dropped) and no
// less. The generated token ids keep every token, EOS included.
func TestChatCommittedOutputFollowsTheEOSRule(t *testing.T) {
	for _, test := range eosRuleCases {
		t.Run(test.name, func(t *testing.T) {
			for _, streamed := range []bool{false, true} {
				name := "buffered"
				if streamed {
					name = "streamed"
				}
				t.Run(name, func(t *testing.T) {
					var srv *httptest.Server
					if streamed {
						srv, _ = newChatVLLMStreamStub(t, chatGenerationChunks(test.tokens, test.finish), []string{"Qwen/Qwen3-8B"})
					} else {
						srv, _ = newChatVLLMStub(t, chatGeneration(test.tokens, test.finish), []string{"Qwen/Qwen3-8B"})
					}
					svc := chainBoundLocalService(srv.URL)
					svc.SetStreamInference(streamed)
					obs := &recordingObserver{}
					ctx := WithInferStreamObserver(context.Background(), obs)

					resp, err := svc.Infer(ctx, chatBoundWithLimit(t, InferRequest{
						RequestID: "chat-eos", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
						Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
					}, uint64(len(test.tokens))))
					if err != nil {
						t.Fatalf("Infer() error = %v", err)
					}
					output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
					if err != nil {
						t.Fatal(err)
					}
					if string(output.Data) != test.want {
						t.Fatalf("committed output = %q, want %q", output.Data, test.want)
					}
					if resp.GeneratedTokenCount != uint64(len(test.tokens)) {
						t.Fatalf("generated_token_count = %d, want %d: the EOS is still a generated token", resp.GeneratedTokenCount, len(test.tokens))
					}
					if !streamed {
						return
					}
					// The SSE path really ran: the observer only sees frames there.
					if len(obs.frames) == 0 {
						t.Fatal("no stream frames observed; the stub fell back to a unary body")
					}
					var concat strings.Builder
					for _, frame := range obs.frames {
						concat.WriteString(frame.TextDelta)
					}
					if concat.String() != string(output.Data) {
						t.Fatalf("concat(frames) = %q, committed output = %q", concat.String(), output.Data)
					}
				})
			}
		})
	}
}

// Without a chain profile there is no manifest and no EOS set, so nothing is
// stripped: the stripping is driven by the manifest, not by a hardcoded id.
func TestChatWithoutAResolvedProfileKeepsEveryToken(t *testing.T) {
	srv, _ := newChatVLLMStub(t, chatGeneration([]genToken{hello, world, eos}, "stop"), []string{"Qwen/Qwen3-8B"})
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetStreamInference(false)
	resp, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID: "chat-no-profile", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(output.Data); got != "hello world<|im_end|>" {
		t.Fatalf("committed output = %q, want the unstripped text on the no-profile path", got)
	}
}

// A chain-resolved profile whose output_decoding cannot be obtained is refused
// before the engine is called, with an error that says why.
func TestInferRefusesAProfileWithoutItsOutputDecoding(t *testing.T) {
	for name, source := range map[string]OutputDecodingSource{
		"no source": nil,
		"source fails": outputDecodingSourceFunc(func(context.Context, chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
			return modelmanifest.OutputDecoding{}, errors.New("manifest not obtained")
		}),
		"hash mismatch": outputDecodingSourceFunc(func(_ context.Context, profile chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
			return modelmanifest.VerifyOutputDecoding(append([]byte(" "), testManifestBytes...), profile.ManifestHash)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, chat := range []bool{true, false} {
				var calls int
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/models" {
						_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen3-8B"}}})
						return
					}
					calls++
					http.Error(w, "the engine must not be called", http.StatusInternalServerError)
				}))
				defer srv.Close()
				svc := chainBoundLocalService(srv.URL)
				svc.SetOutputDecodingSource(source)
				req := boundLocalInferFixture(t, InferRequest{RequestID: "no-decoding", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi")})
				if chat {
					req = chatBound(t, InferRequest{RequestID: "no-decoding", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`)})
				}
				_, err := svc.Infer(context.Background(), req)
				if err == nil || !strings.Contains(err.Error(), "output_decoding") && !strings.Contains(err.Error(), "manifest") {
					t.Fatalf("chat=%v: Infer() error = %v, want a refusal naming the manifest", chat, err)
				}
				if calls != 0 {
					t.Fatalf("chat=%v: the engine was called %d times without an output_decoding", chat, calls)
				}
			}
		})
	}
}

// Verify does not read the manifest: a Verifier keeps working when the
// output_decoding cannot be obtained.
func TestVerifyDoesNotNeedTheOutputDecoding(t *testing.T) {
	srv, _ := newVLLMStub(t, genResponse(), verifyResponse())
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0)
	svc.SetProfileResolver(&countingProfileResolver{snapshot: liveLikeProfileSnapshotWithTopK(7)})
	if _, err := svc.Verify(context.Background(), boundLocalVerifyFixture(t, VerifyRequest{
		RequestID: "verify-no-manifest", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Sample: []byte("seed"), TokenIDs: TokenIDs{Input: []uint32{1, 2, 3}, Generated: []uint32{10, 11}},
	})); err != nil {
		t.Fatalf("Verify() without an output_decoding source = %v", err)
	}
}

// An EOS finish is only consistent with a generation whose last token is an
// EOS token, since that is the token the committed output leaves out.
func TestChatEOSFinishNeedsATrailingEOSToken(t *testing.T) {
	srv, _ := newChatVLLMStub(t, chatGeneration([]genToken{hello, world}, "stop"), []string{"Qwen/Qwen3-8B"})
	svc := chainBoundLocalService(srv.URL)
	svc.SetStreamInference(false)
	_, err := svc.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID: "chat-eos-finish", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}))
	if err == nil || !strings.Contains(err.Error(), "eos_token_ids") {
		t.Fatalf("Infer() error = %v, want an EOS finish without a trailing EOS token refused", err)
	}
}

// rawGeneration is a /v1/completions response for tokens, with text being the
// engine's own text.
func rawGeneration(text string, finish string, stopReason string, ids ...int) completionResponse {
	resp := completionResponse{Choices: []completionChoice{{
		Text: text, FinishReason: finish, PromptTokenIDs: []int{1, 2, 3}, TokenIDs: ids,
		Logprobs: &completionLogprobs{TokenLogprobs: make([]float64, len(ids))},
	}}}
	if stopReason != "" {
		resp.Choices[0].StopReason = json.RawMessage(stopReason)
	}
	return resp
}

// rawBound binds a raw-text request to a generation with the given limit and
// stop token ids.
func rawBound(t *testing.T, limit uint64, stopTokenIDs ...uint32) InferRequest {
	t.Helper()
	g := localTestGeneration(testQwenModelID(), 1)
	g.Params.MaxOutputTokens = limit
	g.Params.DecodingParams.StopTokenIDs = stopTokenIDs
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return InferRequest{RequestID: "raw-eos", ModelID: testQwenModelID(), ProfileVersion: "1", Capability: CapabilityLLMTextV1,
		Input: []byte("say hello"), Generation: g, GenerationParamsDigest: digest[:]}
}

// /v1/completions returns no per-token bytes, so the raw-text path commits
// the engine's text, and only when the token the engine left out of it is the
// token the EOS rule leaves out. For the same generation the committed bytes
// then equal the chat path's.
func TestRawTextCommittedOutputFollowsTheEOSRule(t *testing.T) {
	for _, test := range []struct {
		name    string
		resp    completionResponse
		limit   uint64
		stops   []uint32
		want    string
		wantErr string
	}{
		{name: "eos ending", resp: rawGeneration("hello world", "stop", "null", 10, 11, testEOSTokenID), limit: 3, want: "hello world"},
		{name: "max tokens ending", resp: rawGeneration("hello world", "length", "", 10, 11), limit: 2, want: "hello world"},
		{name: "eos in the middle", resp: rawGeneration("hello<|im_end|> world", "length", "", 10, testEOSTokenID, 11), limit: 3, want: "hello<|im_end|> world"},
		{name: "stop token that is an eos token", resp: rawGeneration("hello world", "stop", "151645", 10, 11, testEOSTokenID), limit: 3, stops: []uint32{testEOSTokenID}, want: "hello world"},
		// The rule keeps a stop token that is not an EOS token, but the engine
		// left its text out and the response has no bytes to put it back.
		{name: "stop token that is not an eos token", resp: rawGeneration("hello", "stop", "11", 10, 11), limit: 3, stops: []uint32{11}, wantErr: "no per-token bytes"},
		// The engine did not stop on the EOS, so its text is in the response
		// and cannot be cut off.
		{name: "length ending on an eos token", resp: rawGeneration("hello<|im_end|>", "length", "", 10, testEOSTokenID), limit: 2, wantErr: "no per-token bytes"},
		// An EOS finish needs a trailing EOS token.
		{name: "eos finish without an eos token", resp: rawGeneration("hello world", "stop", "null", 10, 11), limit: 3, wantErr: "eos_token_ids"},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv, seen := newVLLMStub(t, test.resp, verifyResponse())
			svc := chainBoundLocalService(srv.URL)
			svc.SetStreamInference(false)
			resp, err := svc.Infer(context.Background(), rawBound(t, test.limit, test.stops...))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Infer() error = %v, want one containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Infer() error = %v", err)
			}
			output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
			if err != nil {
				t.Fatal(err)
			}
			if string(output.Data) != test.want {
				t.Fatalf("committed output = %q, want %q", output.Data, test.want)
			}
			if req := (*seen)[0]; req.SpacesBetweenSpecialTokens == nil || *req.SpacesBetweenSpecialTokens || req.SkipSpecialTokens == nil || *req.SkipSpecialTokens {
				t.Fatalf("generation request must render special tokens without added spaces: %+v", req)
			}
		})
	}
}

// The same generation yields the same committed bytes on both paths.
func TestRawTextAndChatCommitTheSameBytes(t *testing.T) {
	chatSrv, _ := newChatVLLMStub(t, chatGeneration([]genToken{hello, world, eos}, "stop"), []string{"Qwen/Qwen3-8B"})
	chat := chainBoundLocalService(chatSrv.URL)
	chat.SetStreamInference(false)
	chatResp, err := chat.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID: "same-bytes", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	rawSrv, _ := newVLLMStub(t, rawGeneration("hello world", "stop", "null", 10, 11, testEOSTokenID), verifyResponse())
	raw := chainBoundLocalService(rawSrv.URL)
	raw.SetStreamInference(false)
	rawResp, err := raw.Infer(context.Background(), rawBound(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	chatOut, _ := chat.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: chatResp.OutputRef})
	rawOut, _ := raw.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: rawResp.OutputRef})
	if !bytes.Equal(chatOut.Data, rawOut.Data) || chatResp.FinishReason != nodewire.FinishReasonV1EosToken || rawResp.FinishReason != nodewire.FinishReasonV1EosToken {
		t.Fatalf("chat committed %q (%v), raw text committed %q (%v)", chatOut.Data, chatResp.FinishReason, rawOut.Data, rawResp.FinishReason)
	}
}
