package modelservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// detokenizeStub emulates the vLLM endpoints the decode checks touch:
// /v1/chat/completions answers with a fixed chat generation, /tokenize maps
// each prompt byte to the id markerBase+byte, and /detokenize reverses that
// mapping for marker ids (so the calibration probe round-trips byte-exactly)
// and answers decode(ids) for everything else.
type detokenizeStub struct {
	t    *testing.T
	chat chatCompletionResponse
	// decode maps non-marker token ids to their decoded text.
	decode func(ids []int) string
	// cleanup, when true, mangles the calibration round trip the way HF's
	// clean_up_tokenization_spaces does.
	cleanup bool

	mu              sync.Mutex
	tokenizeCalls   int
	detokenizedIDs  [][]int
	detokenizeCalls int
}

const detokenizeMarkerBase = 1 << 20

func (s *detokenizeStub) start() *httptest.Server {
	s.t.Helper()
	for i := range s.chat.Choices {
		s.chat.Choices[i].Logprobs = chatFullTopK(s.chat.Choices[i].Logprobs)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list",
				"data": []map[string]any{{"id": "Qwen/Qwen3-8B", "object": "model"}}})
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.chat)
		case "/tokenize":
			var req struct {
				Prompt           string `json:"prompt"`
				AddSpecialTokens bool   `json:"add_special_tokens"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AddSpecialTokens {
				http.Error(w, "bad tokenize request", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.tokenizeCalls++
			s.mu.Unlock()
			ids := make([]int, len(req.Prompt))
			for i := 0; i < len(req.Prompt); i++ {
				ids[i] = detokenizeMarkerBase + int(req.Prompt[i])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tokens": ids, "count": len(ids)})
		case "/detokenize":
			var req struct {
				Tokens []int `json:"tokens"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Tokens) == 0 {
				http.Error(w, "bad detokenize request", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.detokenizeCalls++
			s.detokenizedIDs = append(s.detokenizedIDs, slices.Clone(req.Tokens))
			s.mu.Unlock()
			if req.Tokens[0] >= detokenizeMarkerBase {
				raw := make([]byte, len(req.Tokens))
				for i, id := range req.Tokens {
					raw[i] = byte(id - detokenizeMarkerBase)
				}
				text := string(raw)
				if s.cleanup {
					for _, p := range []string{",", ".", "?", "'s", "n't"} {
						text = strings.ReplaceAll(text, " "+p, p)
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"prompt": text})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"prompt": s.decode(req.Tokens)})
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	s.t.Cleanup(srv.Close)
	return srv
}

// decodeFromGenTokens is the honest engine decode: the concatenation of each
// token's own bytes, matching what the chat path committed.
func decodeFromGenTokens(tokens []genToken) func(ids []int) string {
	byID := map[int][]byte{}
	for _, token := range tokens {
		byID[token.id] = token.bytes
	}
	return func(ids []int) string {
		var buf []byte
		for _, id := range ids {
			buf = append(buf, byID[id]...)
		}
		return string(buf)
	}
}

// DetokenizeCommitted decodes exactly the committed prefix: everything, minus
// one trailing token if and only if it is in eos_token_ids, with the engine
// not called at all when nothing remains.
func TestDetokenizeCommittedFollowsTheEOSRule(t *testing.T) {
	for _, test := range []struct {
		name      string
		generated []uint32
		wantIDs   []int
		want      string
	}{
		{"eos ending", []uint32{10, 11, testEOSTokenID}, []int{10, 11}, "hello world"},
		{"no eos", []uint32{10, 11}, []int{10, 11}, "hello world"},
		{"eos in the middle", []uint32{10, testEOSTokenID, 11}, []int{10, testEOSTokenID, 11}, "hello<|im_end|> world"},
		{"only an eos", []uint32{testEOSTokenID}, nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &detokenizeStub{t: t, decode: decodeFromGenTokens([]genToken{hello, world, eos})}
			srv := stub.start()
			svc := chainBoundLocalService(srv.URL)
			decoded, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", test.generated)
			if err != nil {
				t.Fatalf("DetokenizeCommitted() error = %v", err)
			}
			if string(decoded) != test.want {
				t.Fatalf("decoded = %q, want %q", decoded, test.want)
			}
			if test.wantIDs == nil {
				if stub.detokenizeCalls != 0 {
					t.Fatalf("detokenize called %d times for an all-EOS generation, want none", stub.detokenizeCalls)
				}
				return
			}
			last := stub.detokenizedIDs[len(stub.detokenizedIDs)-1]
			if !slices.Equal(last, test.wantIDs) {
				t.Fatalf("detokenized ids = %v, want the committed prefix %v", last, test.wantIDs)
			}
		})
	}
}

// Without a declared output_decoding there is nothing to decode under:
// DetokenizeCommitted reports it as ErrNoOutputDecoding so the caller can
// skip, not fault.
func TestDetokenizeCommittedWithoutOutputDecoding(t *testing.T) {
	stub := &detokenizeStub{t: t, decode: decodeFromGenTokens(nil)}
	srv := stub.start()
	svc := newBoundLocalService(srv.URL, "local-svc", 4, 0, 0) // no chain profile
	_, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11})
	if !errors.Is(err, ErrNoOutputDecoding) {
		t.Fatalf("DetokenizeCommitted() error = %v, want ErrNoOutputDecoding", err)
	}
}

// The calibration probe round-trips through /tokenize and /detokenize before
// any decode is trusted. A tokenizer that cleans up spaces fails it loudly,
// and a success is cached per served model.
func TestDetokenizeCalibration(t *testing.T) {
	t.Run("cleanup refused", func(t *testing.T) {
		stub := &detokenizeStub{t: t, cleanup: true, decode: decodeFromGenTokens([]genToken{hello, world})}
		srv := stub.start()
		svc := chainBoundLocalService(srv.URL)
		_, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11})
		if err == nil || !strings.Contains(err.Error(), "clean_up_tokenization_spaces") {
			t.Fatalf("DetokenizeCommitted() error = %v, want the cleanup calibration refusal", err)
		}
	})
	t.Run("success cached", func(t *testing.T) {
		stub := &detokenizeStub{t: t, decode: decodeFromGenTokens([]genToken{hello, world})}
		srv := stub.start()
		svc := chainBoundLocalService(srv.URL)
		for i := range 2 {
			if _, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11}); err != nil {
				t.Fatalf("DetokenizeCommitted() #%d error = %v", i, err)
			}
		}
		if stub.tokenizeCalls != 1 {
			t.Fatalf("tokenize calls = %d, want the calibration probe to run once", stub.tokenizeCalls)
		}
	})
}

// With corroboration on, Infer refuses to commit an output the engine's own
// decode of the committed token ids contradicts, and commits it when the two
// derivations agree. Off (the default), nothing extra is called.
func TestInferCorroboratesTheCommittedOutput(t *testing.T) {
	tokens := []genToken{hello, world, eos}
	infer := func(t *testing.T, stub *detokenizeStub, corroborate bool) (InferResponse, error) {
		t.Helper()
		stub.chat = chatGeneration(tokens, "stop")
		srv := stub.start()
		svc := chainBoundLocalService(srv.URL)
		svc.SetStreamInference(false)
		svc.SetDetokenizeCorroboration(corroborate)
		return svc.Infer(context.Background(), chatBoundWithLimit(t, InferRequest{
			RequestID: "corroborate", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
			Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		}, uint64(len(tokens))))
	}
	t.Run("agreeing decode commits", func(t *testing.T) {
		stub := &detokenizeStub{t: t, decode: decodeFromGenTokens(tokens)}
		if _, err := infer(t, stub, true); err != nil {
			t.Fatalf("Infer() error = %v", err)
		}
		if !slices.Equal(stub.detokenizedIDs[len(stub.detokenizedIDs)-1], []int{10, 11}) {
			t.Fatalf("corroboration decoded %v, want the committed prefix [10 11]", stub.detokenizedIDs)
		}
	})
	t.Run("disagreeing decode refuses", func(t *testing.T) {
		stub := &detokenizeStub{t: t, decode: func([]int) string { return "SOMETHING ELSE" }}
		if _, err := infer(t, stub, true); err == nil || !strings.Contains(err.Error(), "does not decode") {
			t.Fatalf("Infer() error = %v, want the corroboration refusal", err)
		}
	})
	t.Run("off by default", func(t *testing.T) {
		stub := &detokenizeStub{t: t, decode: func([]int) string { return "SOMETHING ELSE" }}
		if _, err := infer(t, stub, false); err != nil {
			t.Fatalf("Infer() error = %v, want no corroboration call at all", err)
		}
		if stub.detokenizeCalls != 0 {
			t.Fatalf("detokenize calls = %d, want none with corroboration off", stub.detokenizeCalls)
		}
	})
}

// The whole #35 flow over one stub: the Worker infers and commits output +
// token ids (corroborating them against the engine), then the Verifier-side
// comparison -- DetokenizeCommitted against the MMR-confirmed bytes, both
// folded by CanonicalUTF8 -- accepts the honest output and refuses a tampered
// one whose token ids still verify.
func TestOutputDecodeCheckBindsTextToTokensEndToEnd(t *testing.T) {
	tokens := []genToken{hello, world, eos}
	stub := &detokenizeStub{t: t, chat: chatGeneration(tokens, "stop"), decode: decodeFromGenTokens(tokens)}
	srv := stub.start()
	svc := chainBoundLocalService(srv.URL)
	svc.SetStreamInference(false)
	svc.SetDetokenizeCorroboration(true)

	// Worker side: infer and commit.
	resp, err := svc.Infer(context.Background(), chatBoundWithLimit(t, InferRequest{
		RequestID: "e2e", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}, uint64(len(tokens))))
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	output, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
	if err != nil {
		t.Fatal(err)
	}
	idsArtifact, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.TokenIDsRef})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := DecodeTokenIDsArtifact(idsArtifact.Data)
	if err != nil {
		t.Fatal(err)
	}

	// Verifier side: the committed text must be the decode of the token ids.
	decoded, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", ids.Generated)
	if err != nil {
		t.Fatalf("DetokenizeCommitted() error = %v", err)
	}
	if string(decoded) != string(CanonicalUTF8(output.Data)) {
		t.Fatalf("decode(T) = %q, confirmed output = %q: the honest flow must agree", decoded, output.Data)
	}

	// A tampered text with intact token ids is exactly what the check exists
	// to catch.
	tampered := append([]byte("TAMPERED:"), output.Data...)
	if string(decoded) == string(CanonicalUTF8(tampered)) {
		t.Fatal("decode(T) matched a tampered output")
	}
}

// CanonicalUTF8 folds ill-formed sequences by maximal subpart: one U+FFFD per
// truncated or broken sequence, never per byte, matching HF tokenizers'
// (Rust's) from_utf8_lossy.
func TestCanonicalUTF8(t *testing.T) {
	for _, test := range []struct {
		name string
		in   string
		want string
	}{
		{"valid ascii", "hello world", "hello world"},
		{"valid multibyte", "你好 \U0001F600", "你好 \U0001F600"},
		{"empty", "", ""},
		{"truncated two-byte tail", "ok\xC3", "ok�"},
		{"truncated three-byte tail", "ok\xE4\xB8", "ok�"},
		{"truncated four-byte tail", "Hello \xF0\x90\x80World", "Hello �World"},
		{"lone continuation", "a\x80b", "a�b"},
		{"invalid lead", "a\xFFb", "a�b"},
		{"lead with bad first continuation", "\xE0\x80", "��"},
		{"overlong-excluded f0", "\xF0\x80a", "��a"},
		{"surrogate range refused", "\xED\xA0\x80", "���"},
		{"broken then valid sequence", "\xE4\xB8你", "�你"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := string(CanonicalUTF8([]byte(test.in))); got != test.want {
				t.Fatalf("CanonicalUTF8(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}
