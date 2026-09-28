package modelservice

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// detokenizeRequest is vLLM's POST /detokenize body. It carries exactly these
// two fields -- verified against vLLM v0.10.0
// (entrypoints/openai/protocol.py, class DetokenizeRequest) -- and that is the
// whole reason this check exists rather than the §9.1 comparison itself.
//
// The handler calls the HF tokenizer's bare decode(ids) with no keyword
// arguments (entrypoints/openai/serving_engine.py). So of the two settings
// output_decoding fixes:
//
//   - render_special_tokens = true matches by luck: HF's decode defaults to
//     skip_special_tokens=False, so body special tokens render literally.
//   - clean_up_tokenization_spaces = false does NOT. HF falls back to the
//     tokenizer's own clean_up_tokenization_spaces from tokenizer_config.json,
//     which the request cannot override and which varies per model.
//
// A profile whose tokenizer config enables cleanup therefore decodes to
// different bytes than the manifest declares, and nothing in this deployment
// can tell that apart from a correct decode -- settling it is what the
// manifest's DECODE_VECTORS artifact is for, and wire has not published those.
type detokenizeRequest struct {
	Model  string `json:"model"`
	Tokens []int  `json:"tokens"`
}

// detokenizeResponse names the decoded text "prompt", which is vLLM's field
// name on this route regardless of what was decoded.
type detokenizeResponse struct {
	Prompt string `json:"prompt"`
}

// verifyCommittedOutputDecodes refuses to commit an output this node cannot
// derive two independent ways.
//
// The committed output is built by concatenating each generated token's raw
// bytes, which is what makes every text artifact correspond position by
// position to the token ids a Verifier scores. The protocol defines it
// differently though: as decode(T minus one trailing EOS) under the profile's
// tokenizer. Those two agree for byte-level BPE, and they are not guaranteed to
// agree in general -- clean_up_tokenization_spaces operates on the joined
// string, so it can change bytes that no per-token concatenation reproduces.
//
// This is a Worker-local check and deliberately not the §9.1 Verifier
// comparison. It faults nobody: it stops this node from publishing an output
// whose own two derivations disagree, which is the precondition that would make
// a cross-node comparison safe to turn on later. Landing §9.1 without it is how
// honest Workers get judged at fault.
//
// It costs one extra round trip per generation. That is the price of not
// committing bytes this node cannot corroborate.
func (s *LocalService) verifyCommittedOutputDecodes(
	ctx context.Context,
	servedModel string,
	tokenIDs []int,
	committed string,
	decoding modelmanifest.OutputDecodingV1,
) error {
	// No EOS set means no chain-resolved profile, which is the dev and fake
	// path: there is no declared decoding to corroborate against.
	if len(decoding.EOSTokenIDs) == 0 || len(tokenIDs) == 0 {
		return nil
	}
	committedIDs := tokenIDs[:decoding.CommittedTokenCount(tokenIDs)]
	if len(committedIDs) == 0 {
		// An output of nothing but an EOS decodes to the empty string, and
		// asking the engine to decode an empty list only invites an edge case.
		if committed != "" {
			return fmt.Errorf("modelservice local: committed output is %d bytes but every generated token is an EOS", len(committed))
		}
		return nil
	}

	var resp detokenizeResponse
	ctx, cancel := s.withProbeTimeout(ctx)
	defer cancel()
	if err := s.post(ctx, "/detokenize", detokenizeRequest{Model: servedModel, Tokens: committedIDs}, &resp); err != nil {
		return fmt.Errorf("modelservice local: detokenize the committed token ids: %w", err)
	}
	if resp.Prompt == committed {
		return nil
	}
	// Both renderings are quoted. The difference is usually whitespace, and an
	// error that only said "mismatch" would leave an operator diffing two
	// strings they cannot see.
	return fmt.Errorf(
		"modelservice local: committed output does not decode from its token ids: "+
			"per-token bytes gave %q (%d bytes), the tokenizer gave %q (%d bytes) over %d committed tokens; "+
			"check the profile's clean_up_tokenization_spaces",
		committed, len(committed), resp.Prompt, len(resp.Prompt), len(committedIDs))
}
