package modelservice

import (
	"context"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// testManifestBytes stands in for a profile manifest. Only its output_decoding
// block is read on the serving path, so the rest of the document is left out;
// internal/modelmanifest owns the tests against full manifests.
var testManifestBytes = []byte(`{"manifest_version":4,"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[151643,151645],"render_special_tokens":true,"strip_trailing_eos":true}}`)

func testManifestHash() codec.Hash {
	return modelmanifest.Hash(testManifestBytes)
}

// testOutputDecodingSource serves testManifestBytes for every profile and
// checks them against the profile's manifest_hash, as the real fetcher does.
// Install it alongside any profile resolver: Infer on a chain-resolved profile
// is refused without an output_decoding.
func testOutputDecodingSource() OutputDecodingSource {
	return outputDecodingSourceFunc(func(_ context.Context, profile chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
		return modelmanifest.VerifyOutputDecoding(testManifestBytes, profile.ManifestHash)
	})
}

type outputDecodingSourceFunc func(context.Context, chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error)

func (f outputDecodingSourceFunc) OutputDecoding(ctx context.Context, profile chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
	return f(ctx, profile)
}
