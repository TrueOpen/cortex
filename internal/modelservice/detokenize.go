package modelservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

// This file is the tokenizer source for issue #35: the committed output must
// be the decode of the committed generated token ids under the profile
// manifest's output_decoding, and until now no node could compute that decode.
//
// The decode is obtained from vLLM's POST /detokenize. Its body carries
// exactly these two fields -- verified against vLLM v0.10.0
// (entrypoints/openai/protocol.py, class DetokenizeRequest) -- and the handler
// calls the HF tokenizer's bare decode(ids) with no keyword arguments
// (entrypoints/openai/serving_engine.py). Of the two settings output_decoding
// fixes:
//
//   - render_special_tokens = true matches: HF's decode defaults to
//     skip_special_tokens=False, so body special tokens render literally.
//   - clean_up_tokenization_spaces = false does NOT by construction. HF falls
//     back to the tokenizer's own clean_up_tokenization_spaces from
//     tokenizer_config.json, which the request cannot override and which
//     varies per model.
//
// The second gap is why calibrateDetokenize exists: before any decode is
// trusted, a cleanup-sensitive probe is round-tripped through /tokenize and
// /detokenize. A tokenizer whose config enables cleanup mangles the probe, and
// every decode-dependent check then refuses loudly instead of comparing
// against bytes the manifest never declared. wire's DECODE_VECTORS artifact
// will settle the same question per profile once published
// (output_decoding.decode_vectors_path is empty on the current testnet
// manifest); the probe is the deployment-local stand-in until then.
type detokenizeRequest struct {
	Model  string `json:"model"`
	Tokens []int  `json:"tokens"`
}

// detokenizeResponse names the decoded text "prompt", which is vLLM's field
// name on this route regardless of what was decoded.
type detokenizeResponse struct {
	Prompt string `json:"prompt"`
}

// tokenizeRequest is vLLM's POST /tokenize body, used only by the calibration
// probe. add_special_tokens is pinned false so the round trip covers exactly
// the probe's bytes and nothing the chat template or a BOS would add.
type tokenizeRequest struct {
	Model            string `json:"model"`
	Prompt           string `json:"prompt"`
	AddSpecialTokens bool   `json:"add_special_tokens"`
}

type tokenizeResponse struct {
	Tokens []int `json:"tokens"`
}

// ErrNoOutputDecoding reports that a profile declares no output_decoding to
// decode under -- the unregistered dev/fake path. Callers running an optional
// consistency check skip it on this error; everything else fails.
var ErrNoOutputDecoding = errors.New("modelservice: profile declares no output_decoding")

// OutputDetokenizer is the optional model-service capability behind the
// Verifier's committed-output decode check (issue #35). LocalService
// implements it against vLLM; the cortex.v1 gRPC boundary has no Detokenize
// RPC yet, so the remote client does not, and the Verifier skips the check
// there until wire grows the RPC.
type OutputDetokenizer interface {
	// DetokenizeCommitted decodes the committed prefix of the generated token
	// ids -- all of them minus one trailing token if and only if it is in the
	// profile's output_decoding.eos_token_ids -- and returns the canonical
	// UTF-8 bytes of that decode. It returns ErrNoOutputDecoding when the
	// profile declares no output_decoding.
	DetokenizeCommitted(ctx context.Context, modelID, profileVersion string, generated []uint32) ([]byte, error)
}

// detokenizeProbe is ASCII built from the patterns HF's
// clean_up_tokenization_spaces rewrites (" .", " ,", " ?", " 's", " n't"): a
// tokenizer that cleans up cannot return it unchanged, and a byte-level BPE
// decode with cleanup off returns exactly it.
const detokenizeProbe = "a , b . c 's d n't e ?"

// calibrateDetokenize proves, once per served model, that this vLLM's
// /detokenize decodes with the semantics output_decoding declares. Success is
// cached (the served tokenizer cannot change under a running engine); failure
// is not, so a transient engine error is retried on the next call.
func (s *LocalService) calibrateDetokenize(ctx context.Context, servedModel string) error {
	s.mu.RLock()
	calibrated := s.detokenizeCalibrated[servedModel]
	s.mu.RUnlock()
	if calibrated {
		return nil
	}
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	var tok tokenizeResponse
	if err := s.post(ctx, "/tokenize", tokenizeRequest{Model: servedModel, Prompt: detokenizeProbe}, &tok); err != nil {
		return fmt.Errorf("modelservice local: tokenize the detokenize calibration probe: %w", err)
	}
	if len(tok.Tokens) == 0 {
		return fmt.Errorf("modelservice local: /tokenize returned no tokens for the calibration probe")
	}
	var detok detokenizeResponse
	if err := s.post(ctx, "/detokenize", detokenizeRequest{Model: servedModel, Tokens: tok.Tokens}, &detok); err != nil {
		return fmt.Errorf("modelservice local: detokenize the calibration probe: %w", err)
	}
	if detok.Prompt != detokenizeProbe {
		return fmt.Errorf("modelservice local: /detokenize for %s is not byte-exact: probe %q decoded to %q; "+
			"the served tokenizer likely enables clean_up_tokenization_spaces, which output_decoding declares false, "+
			"so no decode of this engine can be compared against the committed output",
			servedModel, detokenizeProbe, detok.Prompt)
	}
	s.mu.Lock()
	if s.detokenizeCalibrated == nil {
		s.detokenizeCalibrated = make(map[string]bool)
	}
	s.detokenizeCalibrated[servedModel] = true
	s.mu.Unlock()
	return nil
}

// detokenizeIDs decodes ids through the calibrated /detokenize and returns the
// decoded bytes. The engine's JSON answer is a string, so the result is always
// valid UTF-8: ill-formed sequences in the underlying token bytes arrive as
// U+FFFD, exactly the canonical form CanonicalUTF8 produces.
func (s *LocalService) detokenizeIDs(ctx context.Context, servedModel string, ids []int) ([]byte, error) {
	if err := s.calibrateDetokenize(ctx, servedModel); err != nil {
		return nil, err
	}
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	var resp detokenizeResponse
	if err := s.post(ctx, "/detokenize", detokenizeRequest{Model: servedModel, Tokens: ids}, &resp); err != nil {
		return nil, fmt.Errorf("modelservice local: detokenize %d committed token ids: %w", len(ids), err)
	}
	return []byte(resp.Prompt), nil
}

// DetokenizeCommitted implements OutputDetokenizer against the local vLLM.
func (s *LocalService) DetokenizeCommitted(ctx context.Context, modelID, profileVersion string, generated []uint32) ([]byte, error) {
	profile, err := s.resolveLocalProfile(ctx, modelID, profileVersion)
	if err != nil {
		return nil, err
	}
	profile, err = s.outputDecodingFor(ctx, profile)
	if err != nil {
		return nil, err
	}
	if len(profile.OutputDecoding.EOSTokenIDs) == 0 {
		return nil, fmt.Errorf("%w: profile %s@%s", ErrNoOutputDecoding, modelID, profileVersion)
	}
	ids := make([]int, len(generated))
	for i, id := range generated {
		ids[i] = int(id)
	}
	committed := ids[:profile.OutputDecoding.CommittedTokenCount(ids)]
	if len(committed) == 0 {
		// An output of nothing but an EOS decodes to the empty string, and
		// asking the engine to decode an empty list only invites an edge case.
		return []byte{}, nil
	}
	return s.detokenizeIDs(ctx, profile.ServedModel, committed)
}

// corroborateOutputDecodes refuses to commit an output this node cannot derive
// two independent ways.
//
// The committed output is built from the generated tokens' own bytes (the chat
// path concatenates logprobs.content[i].bytes; the completions path commits
// the engine's text only when checkRawTextCommittedOutput proved it can equal
// that concatenation). The protocol defines it as decode(T minus one trailing
// EOS) under the profile's tokenizer. Those two agree for a byte-level BPE
// with cleanup off, and they are not guaranteed to agree in general. A Worker
// whose two derivations disagree must not publish: the Verifier now runs this
// same comparison (internal/verifier) and faults the Worker on a mismatch, so
// refusing here is what keeps an honest Worker out of that fault.
//
// It costs one extra round trip per generation (plus one calibration round
// trip per served model per process). That is the price of not committing
// bytes this node cannot corroborate. SetDetokenizeCorroboration turns it on;
// the daemon does so for every production worker.
func (s *LocalService) corroborateOutputDecodes(ctx context.Context, profile localModelProfile, tokenIDs []int, output []byte) error {
	s.mu.RLock()
	enabled := s.detokenizeCorroboration
	s.mu.RUnlock()
	if !enabled || len(profile.OutputDecoding.EOSTokenIDs) == 0 {
		// Off, or an unregistered dev profile with no declared decoding.
		return nil
	}
	committed := tokenIDs[:profile.OutputDecoding.CommittedTokenCount(tokenIDs)]
	canonical := CanonicalUTF8(output)
	if len(committed) == 0 {
		if len(canonical) != 0 {
			return fmt.Errorf("modelservice local: committed output is %d bytes but every generated token is an EOS", len(output))
		}
		return nil
	}
	decoded, err := s.detokenizeIDs(ctx, profile.ServedModel, committed)
	if err != nil {
		return err
	}
	if bytes.Equal(decoded, canonical) {
		return nil
	}
	// Both renderings are quoted. The difference is usually whitespace, and an
	// error that only said "mismatch" would leave an operator diffing two
	// strings they cannot see.
	return fmt.Errorf("modelservice local: committed output does not decode from its token ids: "+
		"per-token bytes gave %q (%d bytes), the tokenizer gave %q (%d bytes) over %d committed tokens",
		canonical, len(canonical), decoded, len(decoded), len(committed))
}

// SetDetokenizeCorroboration turns corroborateOutputDecodes on for every
// subsequent Infer. Off by default so the hermetic stubs that only speak
// /v1/completions keep working; the daemon enables it on the production path.
func (s *LocalService) SetDetokenizeCorroboration(enabled bool) {
	s.mu.Lock()
	s.detokenizeCorroboration = enabled
	s.mu.Unlock()
}

// CanonicalUTF8 returns b with every ill-formed UTF-8 sequence replaced by one
// U+FFFD per maximal subpart (Unicode TUS §3.9's substitution of maximal
// subparts, the policy Rust's String::from_utf8_lossy -- and therefore HF
// tokenizers' decode -- applies). A committed output is raw token bytes, so a
// generation cut at the token budget can end mid-character; its decode renders
// that tail as U+FFFD, and this is the transform that makes the two comparable
// byte for byte. Valid input is returned as-is, unconverted and uncopied.
func CanonicalUTF8(b []byte) []byte {
	if utf8.Valid(b) {
		return b
	}
	const replacement = "�"
	out := make([]byte, 0, len(b)+2*utf8.UTFMax)
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			out = append(out, c)
			i++
			continue
		}
		// Expected continuation count and the valid range of the FIRST
		// continuation byte, per the UTF-8 well-formedness table (RFC 3629 /
		// TUS Table 3-7). Later continuations are always 0x80..0xBF.
		var n int
		lo, hi := byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			n = 1
		case c == 0xE0:
			n, lo = 2, 0xA0
		case c >= 0xE1 && c <= 0xEC, c >= 0xEE && c <= 0xEF:
			n = 2
		case c == 0xED:
			n, hi = 2, 0x9F
		case c == 0xF0:
			n, lo = 3, 0x90
		case c >= 0xF1 && c <= 0xF3:
			n = 3
		case c == 0xF4:
			n, hi = 3, 0x8F
		default:
			// 0x80..0xC1 or 0xF5..0xFF: not a lead byte of any sequence.
			out = append(out, replacement...)
			i++
			continue
		}
		j := i + 1
		for k := 0; k < n && j < len(b); k++ {
			if k > 0 {
				lo, hi = 0x80, 0xBF
			}
			if b[j] < lo || b[j] > hi {
				break
			}
			j++
		}
		if j-i == n+1 {
			out = append(out, b[i:j]...)
		} else {
			// The maximal subpart b[i:j] -- the longest prefix that could still
			// have become a valid sequence -- is replaced as one unit.
			out = append(out, replacement...)
		}
		i = j
	}
	return out
}
