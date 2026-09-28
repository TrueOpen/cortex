// Package modelmanifest reads the profile manifest blocks Cortex needs at
// runtime out of bytes the chain has already vouched for.
//
// The manifest itself is an off-chain document; only its hash reaches the
// chain, in ProfileState.manifest_hash. That is enough to make any block inside
// it authoritative, because the hash pins the whole document: a Worker and a
// Verifier that both check the bytes against the same on-chain hash are reading
// the same manifest by construction, whatever path the file arrived by. So this
// package takes bytes plus that hash and refuses everything else -- there is no
// "load the manifest and trust it" entry point on purpose.
package modelmanifest

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
)

// ManifestDomainV4 frames the manifest digest the chain stores. The version is
// part of the domain, so a V3 document cannot be presented as a V4 one: the
// digest simply will not match.
const ManifestDomainV4 = "TRUEOPEN_MODEL_MANIFEST_V4"

// ManifestVersionV4 is the manifest_version this package reads. It is checked
// in addition to the domain because a document could carry the wrong version
// field and still hash correctly -- the hash covers whatever the bytes say,
// including a lie about their own version.
const ManifestVersionV4 = 4

// DecoderHFTokenizersV1 is the only decoder V1 admits. Different tokenizer
// libraries decode the same vocabulary to different bytes, so the profile has
// to name one semantic source for Worker and Verifier to agree on.
const DecoderHFTokenizersV1 = "HF_TOKENIZERS_V1"

// OutputDecodingV1 is the manifest block that decides which bytes the committed
// output is made of. Five of its six fields are fixed in V1; they are written
// out rather than assumed so that changing any of them requires a new manifest
// version instead of silently moving every output_hash on the network.
type OutputDecodingV1 struct {
	Decoder                   string   `json:"decoder"`
	EOSTokenIDs               []uint32 `json:"eos_token_ids"`
	StripTrailingEOS          bool     `json:"strip_trailing_eos"`
	RenderSpecialTokens       bool     `json:"render_special_tokens"`
	CleanUpTokenizationSpaces bool     `json:"clean_up_tokenization_spaces"`
	DecodeVectorsPath         string   `json:"decode_vectors_path"`
}

// manifestV4Envelope is the sliver of the manifest this package parses. The
// rest is deliberately left as raw JSON: the digest has already authenticated
// the whole document, so modelling fields nobody here reads would only create a
// second place to keep in step with the manifest schema.
type manifestV4Envelope struct {
	ManifestVersion uint32          `json:"manifest_version"`
	OutputDecoding  json.RawMessage `json:"output_decoding"`
}

// LoadOutputDecoding authenticates raw against the manifest hash the chain
// holds for this profile and returns the output_decoding block carried by those
// exact bytes.
//
// raw must be the manifest file verbatim. It is never re-serialised: canonical
// JSON fixes key order and escaping, so a decode/encode round trip can produce
// different bytes for the same document and a digest that matches nothing. The
// digest is taken over what arrived, and only then is a block parsed out of it.
func LoadOutputDecoding(raw []byte, chainManifestHash codec.Hash) (OutputDecodingV1, error) {
	// A zero hash means the caller never read manifest_hash off the chain. That
	// is not an empty authority to be permissive about -- it is the absence of
	// one, and accepting it would authenticate every manifest against nothing.
	if chainManifestHash.IsZero() {
		return OutputDecodingV1{}, fmt.Errorf("on-chain manifest_hash is unset: cannot authenticate a model manifest without it")
	}
	if len(raw) == 0 {
		return OutputDecodingV1{}, fmt.Errorf("model manifest is empty")
	}
	if digest := codec.HashV1(ManifestDomainV4, raw); digest != chainManifestHash {
		return OutputDecodingV1{}, fmt.Errorf(
			"model manifest does not match the chain: H_V1(%s) over %d bytes is %s, chain holds %s",
			ManifestDomainV4, len(raw), digest, chainManifestHash)
	}

	var envelope manifestV4Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return OutputDecodingV1{}, fmt.Errorf("decode model manifest: %w", err)
	}
	if envelope.ManifestVersion != ManifestVersionV4 {
		return OutputDecodingV1{}, fmt.Errorf("model manifest_version is %d, want %d", envelope.ManifestVersion, ManifestVersionV4)
	}
	if len(envelope.OutputDecoding) == 0 {
		return OutputDecodingV1{}, fmt.Errorf("model manifest carries no output_decoding block")
	}

	decoding, err := decodeOutputDecoding(envelope.OutputDecoding)
	if err != nil {
		return OutputDecodingV1{}, err
	}
	if err := decoding.Validate(); err != nil {
		return OutputDecodingV1{}, err
	}
	return decoding, nil
}

// decodeOutputDecoding rejects unknown keys inside the block. Manifest rule 11
// refuses unknown fields outright, and while this package cannot enforce that
// for the whole document -- it models only one block -- it can for the block it
// does read, so an extension smuggled in beside these six fields is a parse
// error rather than something silently ignored.
func decodeOutputDecoding(raw json.RawMessage) (OutputDecodingV1, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var out OutputDecodingV1
	if err := decoder.Decode(&out); err != nil {
		return OutputDecodingV1{}, fmt.Errorf("decode output_decoding: %w", err)
	}
	return out, nil
}

// Validate enforces the V1 rules from the manifest contract §7.1.
//
// Two of that section's five rules are NOT enforced here, because both need the
// artifact bundle this package is not given: rule 3 (eos_token_ids equals the
// generation_config.json set) and rule 4 (decode_vectors_path resolves to
// exactly one role=DECODE_VECTORS entry). Neither weakens what is checked --
// the bytes are already bound to the chain -- but a caller that has the bundle
// still owes those two.
func (d OutputDecodingV1) Validate() error {
	if d.Decoder != DecoderHFTokenizersV1 {
		return fmt.Errorf("output_decoding.decoder is %q, want %q", d.Decoder, DecoderHFTokenizersV1)
	}
	// The three fixed flags are compared against their V1 values rather than
	// merely read. A manifest that turns one of them off describes a different
	// byte stream for the same tokens, and taking it at face value would have
	// this node commit an output no Verifier reproduces.
	if !d.StripTrailingEOS {
		return fmt.Errorf("output_decoding.strip_trailing_eos is false, V1 fixes it true")
	}
	if !d.RenderSpecialTokens {
		return fmt.Errorf("output_decoding.render_special_tokens is false, V1 fixes it true")
	}
	if d.CleanUpTokenizationSpaces {
		return fmt.Errorf("output_decoding.clean_up_tokenization_spaces is true, V1 fixes it false")
	}
	if len(d.EOSTokenIDs) == 0 {
		return fmt.Errorf("output_decoding.eos_token_ids is empty")
	}
	// Strictly ascending, which also rules out duplicates. The order is part of
	// the canonical bytes, so an unsorted list is a different document that
	// happens to mean the same set - refusing it keeps one encoding per profile.
	for i := 1; i < len(d.EOSTokenIDs); i++ {
		if d.EOSTokenIDs[i] <= d.EOSTokenIDs[i-1] {
			return fmt.Errorf("output_decoding.eos_token_ids is not strictly ascending at index %d: %d then %d", i, d.EOSTokenIDs[i-1], d.EOSTokenIDs[i])
		}
	}
	if d.DecodeVectorsPath == "" {
		return fmt.Errorf("output_decoding.decode_vectors_path is empty")
	}
	return nil
}

// IsEOS reports whether one token id ends generation for this profile.
func (d OutputDecodingV1) IsEOS(tokenID int) bool {
	if tokenID < 0 {
		return false
	}
	for _, id := range d.EOSTokenIDs {
		if uint64(id) == uint64(tokenID) {
			return true
		}
	}
	return false
}

// CommittedTokenCount reports how many of tokenIDs the committed output covers.
//
// That is all of them, or all but the last when the last one is an EOS. Only
// ever one is dropped: a generation that stopped for any other reason -- a
// max_tokens truncation, a user stop -- does not end in EOS and keeps every
// token, and a model that emitted an EOS mid-sequence keeps that one too,
// because only the final position is examined.
//
// The full token sequence, EOS included, stays the generated token IDs the
// Verifier scores. This count governs the committed output alone.
func (d OutputDecodingV1) CommittedTokenCount(tokenIDs []int) int {
	if len(tokenIDs) == 0 {
		return 0
	}
	if !d.IsEOS(tokenIDs[len(tokenIDs)-1]) {
		return len(tokenIDs)
	}
	return len(tokenIDs) - 1
}
