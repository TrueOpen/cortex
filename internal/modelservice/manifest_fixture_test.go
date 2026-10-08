package modelservice

import (
	"context"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// testManifestBytes is a V4 manifest carrying the same output_decoding block
// the wire golden vector publishes, trimmed to the two fields this package
// reads. internal/modelmanifest owns the vector-pinned tests; these only need a
// document that hashes to something a profile snapshot can carry.
var testManifestBytes = []byte(`{"manifest_version":4,"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"trueopen/decode_vectors.json","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[151643,151645],"render_special_tokens":true,"strip_trailing_eos":true}}`)

func testManifestHash() codec.Hash {
	return codec.HashV1(modelmanifest.ManifestDomainV4, testManifestBytes)
}

// testManifestSource serves testManifestBytes for every profile. Install it
// alongside any profile resolver: a chain-resolved profile without a manifest
// is refused, which is the point of resolveOutputDecoding.
func testManifestSource() ManifestSource {
	return ManifestSourceFunc(func(context.Context, string, string) ([]byte, error) {
		return testManifestBytes, nil
	})
}
