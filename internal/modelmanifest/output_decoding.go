package modelmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// The committed output of a generation is decided by the profile's
// output_decoding block: take the generated token ids T, drop exactly one
// trailing token if and only if it is listed in eos_token_ids, and render the
// rest as UTF-8 with special tokens rendered and no clean-up of tokenization
// spaces. T itself, EOS included, stays in the evidence.
//
// Worker and Verifier must use the same eos_token_ids, so the set is read only
// from manifest bytes that hash to the chain's manifest_hash. Everyone who
// checks the same hash reads the same block, whichever path the bytes took.

// Validate checks the output_decoding rules of a V4 manifest: a known decoder,
// the fixed flags (strip_trailing_eos and render_special_tokens true,
// clean_up_tokenization_spaces false), and a non-empty, strictly ascending
// eos_token_ids. decode_vectors_path is not checked here; see validateFiles.
func (d OutputDecoding) Validate() error { return d.validate() }

// IsEOS reports whether tokenID is one of the profile's EOS tokens.
func (d OutputDecoding) IsEOS(tokenID int) bool {
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

// CommittedTokenCount is how many of tokenIDs the committed output covers:
// all of them, or all but the last when the last one is an EOS token. At most
// one token is ever dropped, and only from the end: an EOS token in the middle
// of a generation stays in the committed output.
func (d OutputDecoding) CommittedTokenCount(tokenIDs []int) int {
	if n := len(tokenIDs); n > 0 && d.IsEOS(tokenIDs[n-1]) {
		return n - 1
	}
	return len(tokenIDs)
}

// VerifyOutputDecoding returns the output_decoding block of the manifest whose
// bytes are body, after checking that body hashes to manifestHash, the chain's
// manifest_hash for the profile.
//
// Only this block is parsed and validated. The hash already authenticates the
// whole document, and the rest of the manifest is not needed to decide the
// committed output, so a manifest whose other fields fail this build's full
// schema (Verify) still yields its output_decoding. The block itself is
// parsed strictly: unknown or duplicate fields, a missing block, and a block
// that breaks the rules in Validate are all refused.
func VerifyOutputDecoding(body []byte, manifestHash chainclient.ProtoBytes32) (OutputDecoding, error) {
	if !manifestHash.IsSet() {
		return OutputDecoding{}, errors.New("chain profile has no manifest_hash")
	}
	if len(body) > MaxManifestBytes {
		return OutputDecoding{}, fmt.Errorf("manifest is %d bytes, above max_manifest_bytes %d", len(body), MaxManifestBytes)
	}
	digest := Hash(body)
	if !bytes.Equal(digest[:], manifestHash) {
		return OutputDecoding{}, fmt.Errorf("%w: got %s, chain has %s", ErrHashMismatch, digest, manifestHash.Hex())
	}
	decoding, err := parseOutputDecoding(body)
	if err != nil {
		return OutputDecoding{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return decoding, nil
}

func parseOutputDecoding(body []byte) (OutputDecoding, error) {
	// Only the top-level object is decoded here, so the other fields are left
	// as raw JSON and never validated.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return OutputDecoding{}, fmt.Errorf("parse manifest: %w", err)
	}
	raw, ok := top["output_decoding"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return OutputDecoding{}, errors.New("manifest has no output_decoding block")
	}
	if err := requireFields(raw, "output_decoding", "clean_up_tokenization_spaces", "decode_vectors_path", "decoder", "eos_token_ids", "render_special_tokens", "strip_trailing_eos"); err != nil {
		return OutputDecoding{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decoding OutputDecoding
	if err := decoder.Decode(&decoding); err != nil {
		return OutputDecoding{}, fmt.Errorf("parse output_decoding: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return OutputDecoding{}, errors.New("parse output_decoding: trailing data")
	}
	if err := decoding.validate(); err != nil {
		return OutputDecoding{}, err
	}
	return decoding, nil
}

// requireFields refuses a block that omits one of the fields, repeats one, or
// sets one to null. encoding/json would otherwise read a missing boolean as
// false and a repeated field as its last value. context names the block in
// error messages.
func requireFields(raw json.RawMessage, context string, names ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("%s must be a JSON object", context)
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("parse %s: %w", context, err)
		}
		key, _ := token.(string)
		if seen[key] {
			return fmt.Errorf("%s.%s is repeated", context, key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("parse %s.%s: %w", context, key, err)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%s.%s must not be null", context, key)
		}
	}
	for _, name := range names {
		if !seen[name] {
			return fmt.Errorf("%s.%s is required", context, name)
		}
	}
	return nil
}
