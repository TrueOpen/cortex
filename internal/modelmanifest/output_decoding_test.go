package modelmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

// wireVector is testdata/model_manifest_v4.json, copied byte for byte from
// TrueOpen/wire main (testdata/v1/hub/model_manifest_v4.json, wire v0.3.0-rc.2).
//
// It is vendored here rather than read through internal/wirevectors because
// that bundle is still pinned at wire v0.2.0, which predates the V4 manifest.
// Point these tests at the bundle once the wire upgrade lands; until then this
// file is the cross-implementation authority and must not be edited to make a
// test pass -- a disagreement with it is a disagreement with the protocol.
type wireVector struct {
	Digest    string `json:"digest_hex"`
	Domain    string `json:"domain"`
	Framing   string `json:"framing"`
	Name      string `json:"name"`
	Payload   string `json:"payload_utf8"`
	Preimage  string `json:"preimage_hex"`
	PreimageN int    `json:"preimage_size_bytes"`
}

func loadWireVector(t *testing.T) wireVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/model_manifest_v4.json")
	if err != nil {
		t.Fatalf("read wire vector: %v", err)
	}
	var file struct {
		Vectors []wireVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode wire vector: %v", err)
	}
	for _, vector := range file.Vectors {
		if vector.Name == "model_manifest_v4" {
			return vector
		}
	}
	t.Fatal("wire vector model_manifest_v4 is absent")
	return wireVector{}
}

func mustHash(t *testing.T, value string) codec.Hash {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("decode hash %q: err=%v len=%d", value, err, len(raw))
	}
	var out codec.Hash
	copy(out[:], raw)
	return out
}

// Everything below rests on this node computing the same manifest digest the
// rest of the network does, so prove that against the published vector before
// anything else reads a field out of a manifest. A test that hashed with the
// same function it was checking would pass just as happily while the whole
// implementation drifted.
func TestManifestFramingReproducesTheWireVectorDigest(t *testing.T) {
	vector := loadWireVector(t)
	if vector.Domain != ManifestDomainV4 || vector.Framing != "H_V1" {
		t.Fatalf("vector domain=%q framing=%q, want %q/H_V1", vector.Domain, vector.Framing, ManifestDomainV4)
	}

	// The vector publishes the framed preimage as well as the digest, so the
	// two halves can be checked separately: that SHA-256 of the published
	// preimage is the published digest, and that codec.HashV1 builds that same
	// preimage out of the domain and the payload.
	preimage, err := hex.DecodeString(vector.Preimage)
	if err != nil {
		t.Fatalf("decode preimage_hex: %v", err)
	}
	if len(preimage) != vector.PreimageN {
		t.Fatalf("preimage is %d bytes, vector says %d", len(preimage), vector.PreimageN)
	}
	if got := hex.EncodeToString(sha256Sum(preimage)); got != vector.Digest {
		t.Fatalf("sha256(published preimage) = %s, vector digest = %s", got, vector.Digest)
	}

	payload := []byte(vector.Payload)
	if got := codec.HashV1(ManifestDomainV4, payload); got.String() != vector.Digest {
		t.Fatalf("codec.HashV1(%s, payload) = %s, want %s", ManifestDomainV4, got, vector.Digest)
	}
}

// The values here are the vector's, not this repository's. If wire republishes
// the fixture with different ones, this test is supposed to fail.
func TestLoadOutputDecodingReadsTheWireVector(t *testing.T) {
	vector := loadWireVector(t)
	decoding, err := LoadOutputDecoding([]byte(vector.Payload), mustHash(t, vector.Digest))
	if err != nil {
		t.Fatalf("LoadOutputDecoding() error = %v", err)
	}

	want := OutputDecodingV1{
		Decoder:                   "HF_TOKENIZERS_V1",
		EOSTokenIDs:               []uint32{151643, 151645},
		StripTrailingEOS:          true,
		RenderSpecialTokens:       true,
		CleanUpTokenizationSpaces: false,
		DecodeVectorsPath:         "trueopen/decode_vectors.json",
	}
	if decoding.Decoder != want.Decoder || decoding.StripTrailingEOS != want.StripTrailingEOS ||
		decoding.RenderSpecialTokens != want.RenderSpecialTokens ||
		decoding.CleanUpTokenizationSpaces != want.CleanUpTokenizationSpaces ||
		decoding.DecodeVectorsPath != want.DecodeVectorsPath ||
		len(decoding.EOSTokenIDs) != len(want.EOSTokenIDs) {
		t.Fatalf("output_decoding = %#v, want %#v", decoding, want)
	}
	for i := range want.EOSTokenIDs {
		if decoding.EOSTokenIDs[i] != want.EOSTokenIDs[i] {
			t.Fatalf("eos_token_ids = %v, want %v", decoding.EOSTokenIDs, want.EOSTokenIDs)
		}
	}
}

// The hash is the whole authority, so the failures that matter are the ones
// where the bytes are fine JSON and still must not be read.
func TestLoadOutputDecodingRefusesUnauthenticatedBytes(t *testing.T) {
	vector := loadWireVector(t)
	payload := []byte(vector.Payload)
	digest := mustHash(t, vector.Digest)

	tampered := append([]byte(nil), payload...)
	// Flip one digit of an eos_token_id. The document stays valid JSON and
	// valid against every rule in Validate; only the digest catches it, which
	// is the point.
	old, want := []byte("151645"), []byte("151646")
	index := bytes.Index(tampered, old)
	if index < 0 {
		t.Fatal("vector payload no longer contains the eos id this test tampers with")
	}
	copy(tampered[index:], want)

	tests := []struct {
		name  string
		raw   []byte
		hash  codec.Hash
		wants string
	}{
		{name: "zero chain hash", raw: payload, hash: codec.Hash{}, wants: "unset"},
		{name: "empty manifest", raw: nil, hash: digest, wants: "empty"},
		{name: "one flipped digit", raw: tampered, hash: digest, wants: "does not match the chain"},
		{name: "hash of a different profile", raw: payload, hash: codec.HashWithDomain("TEST_OTHER", []byte("x")), wants: "does not match the chain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadOutputDecoding(test.raw, test.hash)
			if err == nil {
				t.Fatal("LoadOutputDecoding() accepted bytes the chain does not vouch for")
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("error = %v, want one naming %q", err, test.wants)
			}
		})
	}
}

// Each case here hashes its own bytes, so it reaches the block rules rather
// than stopping at the digest. Every one of them is a manifest the chain
// genuinely vouches for and this node must still refuse.
func TestLoadOutputDecodingEnforcesTheV1BlockRules(t *testing.T) {
	tests := []struct {
		name     string
		version  int
		decoding string
		wants    string
	}{
		{name: "wrong manifest version", version: 3, decoding: goodBlock, wants: "manifest_version"},
		{name: "unknown decoder", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"SENTENCEPIECE_V1","eos_token_ids":[2],"render_special_tokens":true,"strip_trailing_eos":true}`, wants: "decoder"},
		{name: "strip_trailing_eos off", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[2],"render_special_tokens":true,"strip_trailing_eos":false}`, wants: "strip_trailing_eos"},
		{name: "render_special_tokens off", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[2],"render_special_tokens":false,"strip_trailing_eos":true}`, wants: "render_special_tokens"},
		{name: "space cleanup on", version: 4, decoding: `{"clean_up_tokenization_spaces":true,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[2],"render_special_tokens":true,"strip_trailing_eos":true}`, wants: "clean_up_tokenization_spaces"},
		{name: "no eos ids", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[],"render_special_tokens":true,"strip_trailing_eos":true}`, wants: "empty"},
		{name: "eos ids descending", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[9,2],"render_special_tokens":true,"strip_trailing_eos":true}`, wants: "strictly ascending"},
		{name: "eos ids duplicated", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[2,2],"render_special_tokens":true,"strip_trailing_eos":true}`, wants: "strictly ascending"},
		{name: "no decode vectors path", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[2],"render_special_tokens":true,"strip_trailing_eos":true}`, wants: "decode_vectors_path"},
		{name: "unknown field in the block", version: 4, decoding: `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"v.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[2],"render_special_tokens":true,"strip_trailing_eos":true,"strip_leading_bos":true}`, wants: "output_decoding"},
		{name: "no block at all", version: 4, decoding: "", wants: "no output_decoding"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := syntheticManifest(test.version, test.decoding)
			if _, err := LoadOutputDecoding(raw, codec.HashV1(ManifestDomainV4, raw)); err == nil {
				t.Fatal("LoadOutputDecoding() accepted a manifest V1 forbids")
			} else if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("error = %v, want one naming %q", err, test.wants)
			}
		})
	}

	// The same construction with a legal block must pass, or the cases above
	// would prove nothing about the rules and only that the fixture is broken.
	raw := syntheticManifest(4, goodBlock)
	if _, err := LoadOutputDecoding(raw, codec.HashV1(ManifestDomainV4, raw)); err != nil {
		t.Fatalf("LoadOutputDecoding() rejected a legal manifest: %v", err)
	}
}

// Exactly one EOS comes off, and only from the end. The two cases that are easy
// to get wrong are a run of EOS tokens, where a loop would eat all of them, and
// an EOS the model emitted mid-sequence, which is ordinary content.
func TestCommittedTokenCountDropsAtMostTheFinalEOS(t *testing.T) {
	decoding := OutputDecodingV1{EOSTokenIDs: []uint32{151643, 151645}}

	tests := []struct {
		name   string
		tokens []int
		want   int
	}{
		{name: "natural stop", tokens: []int{9, 8, 7, 151645}, want: 3},
		{name: "max tokens truncation keeps everything", tokens: []int{9, 8, 7}, want: 3},
		{name: "two trailing eos drop only one", tokens: []int{9, 151643, 151645}, want: 2},
		{name: "eos mid sequence is content", tokens: []int{9, 151645, 7}, want: 3},
		{name: "the whole output is one eos", tokens: []int{151643}, want: 0},
		{name: "no tokens", tokens: nil, want: 0},
		{name: "a different special token is not an eos", tokens: []int{9, 151644}, want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := decoding.CommittedTokenCount(test.tokens); got != test.want {
				t.Fatalf("CommittedTokenCount(%v) = %d, want %d", test.tokens, got, test.want)
			}
		})
	}
}

const goodBlock = `{"clean_up_tokenization_spaces":false,"decode_vectors_path":"trueopen/decode_vectors.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[151643,151645],"render_special_tokens":true,"strip_trailing_eos":true}`

// syntheticManifest is only ever used for rules the wire vector cannot express
// -- it carries one legal block, so every illegal one has to be built here.
func syntheticManifest(version int, decoding string) []byte {
	if decoding == "" {
		return fmt.Appendf(nil, `{"manifest_version":%d}`, version)
	}
	return fmt.Appendf(nil, `{"manifest_version":%d,"output_decoding":%s}`, version, decoding)
}

func sha256Sum(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}
