package modelmanifest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// testnetManifest is the canonical manifest registered on testnet for
// Qwen/Qwen3.8-27B-FP8 profile 1, copied byte for byte from the public model
// registry (models/testnet/registered/1-Qwen:Qwen3.8-27B-FP8/manifest.canonical.json).
// It has an empty decode_vectors_path, ships no DECODE_VECTORS artifact and
// carries a placeholder evidence_schema_hash, so it is the shape a node meets
// in practice rather than the idealised wire vector.
func testnetManifest(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/testnet_qwen3.8-27b-fp8.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestVerifyOutputDecodingReadsTheTestnetManifest(t *testing.T) {
	body := testnetManifest(t)
	decoding, err := VerifyOutputDecoding(body, hashBytes(body))
	if err != nil {
		t.Fatal(err)
	}
	want := OutputDecoding{
		Decoder: "HF_TOKENIZERS_V1", EOSTokenIDs: []uint32{248044, 248046},
		StripTrailingEOS: true, RenderSpecialTokens: true, CleanUpTokenizationSpaces: false, DecodeVectorsPath: "",
	}
	if !reflect.DeepEqual(decoding, want) {
		t.Fatalf("output_decoding = %+v, want %+v", decoding, want)
	}
	// The strict parser takes the same manifest: an empty decode_vectors_path
	// is accepted.
	if _, err := Parse(body); err != nil {
		t.Fatalf("Parse(testnet manifest) = %v", err)
	}
}

func TestVerifyOutputDecodingReadsTheWireVector(t *testing.T) {
	body, _ := goldenManifest(t)
	manifest, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	decoding, err := VerifyOutputDecoding(body, hashBytes(body))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoding, manifest.OutputDecoding) {
		t.Fatalf("output_decoding = %+v, full parse has %+v", decoding, manifest.OutputDecoding)
	}
}

func TestVerifyOutputDecodingNeedsTheChainHash(t *testing.T) {
	body := testnetManifest(t)
	if _, err := VerifyOutputDecoding(body, nil); err == nil {
		t.Fatal("accepted a manifest without a chain manifest_hash")
	}
	other := hashBytes(append([]byte(nil), body[:len(body)-1]...))
	if _, err := VerifyOutputDecoding(body, other); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch error = %v, want ErrHashMismatch", err)
	}
}

// Every rule of the block is checked on the bytes the chain committed to, and
// a committed block that breaks one is ErrInvalid: no other copy can differ.
func TestVerifyOutputDecodingRefusesAnInvalidBlock(t *testing.T) {
	const block = `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":true,"strip_trailing_eos":true}`
	base := string(testnetManifest(t))
	if !strings.Contains(base, block) {
		t.Fatal("testnet manifest no longer carries the expected output_decoding block")
	}
	for name, replacement := range map[string]string{
		"missing block":        `"output_decoding_removed":{}`,
		"null block":           `"output_decoding":null`,
		"unknown field":        `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"extra":1,"render_special_tokens":true,"strip_trailing_eos":true}`,
		"missing field":        `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":true}`,
		"repeated field":       `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[1],"eos_token_ids":[248044,248046],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"null field":           `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":null,"decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"empty eos":            `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"unsorted eos":         `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248046,248044],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"no stripping":         `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":true,"strip_trailing_eos":false}`,
		"special tokens off":   `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":false,"strip_trailing_eos":true}`,
		"clean-up on":          `"output_decoding":{"clean_up_tokenization_spaces":true,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"unknown decoder":      `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"SENTENCEPIECE","eos_token_ids":[248044,248046],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"negative eos token":   `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[-1,248046],"render_special_tokens":true,"strip_trailing_eos":true}`,
		"block is not object":  `"output_decoding":[1]`,
		"eos is not an array":  `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":248044,"render_special_tokens":true,"strip_trailing_eos":true}`,
		"string boolean field": `"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":"","decoder":"HF_TOKENIZERS_V1","eos_token_ids":[248044,248046],"render_special_tokens":"true","strip_trailing_eos":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := []byte(strings.Replace(base, block, replacement, 1))
			if _, err := VerifyOutputDecoding(body, hashBytes(body)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCommittedTokenCountDropsOnlyOneTrailingEOS(t *testing.T) {
	decoding := OutputDecoding{EOSTokenIDs: []uint32{248044, 248046}}
	for _, test := range []struct {
		name   string
		tokens []int
		want   int
	}{
		{"empty", nil, 0},
		{"eos only", []int{248046}, 0},
		{"trailing eos", []int{1, 2, 248044}, 2},
		{"no eos", []int{1, 2, 3}, 3},
		{"eos in the middle", []int{1, 248044, 3}, 3},
		{"two trailing eos", []int{1, 248044, 248046}, 2},
		{"negative id", []int{1, -1}, 2},
	} {
		if got := decoding.CommittedTokenCount(test.tokens); got != test.want {
			t.Errorf("%s: CommittedTokenCount(%v) = %d, want %d", test.name, test.tokens, got, test.want)
		}
	}
	if (OutputDecoding{}).CommittedTokenCount([]int{1, 248044}) != 2 {
		t.Fatal("an empty EOS set dropped a token")
	}
}

// The testnet manifest fails the full verification the startup gate runs
// (its evidence_schema_hash is a placeholder that does not match its typed
// evidence_schema), yet its output_decoding is authentic: the fetcher must
// still return it, from the same cache, manifest_uri and mirrors.
func TestFetcherOutputDecodingAcceptsAManifestTheFullCheckRefuses(t *testing.T) {
	body := testnetManifest(t)
	manifest, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	chain := chainFor(t, manifest, Hash(body))
	cache := t.TempDir()
	fetcher, server := newTestFetcher(t, map[string][]byte{"/m.json": body}, FetcherConfig{CacheDir: cache})
	chain = withURI(chain, "https://example.com/m.json")

	if _, err := fetcher.Fetch(context.Background(), chain); !errors.Is(err, ErrInvalid) {
		t.Fatalf("full Fetch error = %v, want ErrInvalid for the placeholder evidence_schema_hash", err)
	}
	decoding, err := fetcher.OutputDecoding(context.Background(), chain.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoding.EOSTokenIDs, []uint32{248044, 248046}) {
		t.Fatalf("eos_token_ids = %v", decoding.EOSTokenIDs)
	}
	cached := filepath.Join(cache, chain.Profile.ManifestHash.Hex()+".json")
	if stored, err := os.ReadFile(cached); err != nil || !bytes.Equal(stored, body) {
		t.Fatalf("authentic manifest was not cached: %v", err)
	}
	// A second read comes from the cache without touching the network.
	before := len(server.paths())
	if _, err := fetcher.OutputDecoding(context.Background(), chain.Profile); err != nil {
		t.Fatal(err)
	}
	if len(server.paths()) != before {
		t.Fatalf("cached manifest was fetched again: %v", server.paths())
	}
}

func TestFetcherOutputDecodingFailsClosed(t *testing.T) {
	body := testnetManifest(t)
	profile := chainclient.CurrentProfileSnapshot{ManifestHash: hashBytes(body), ManifestURI: "https://example.com/m.json"}

	t.Run("no source", func(t *testing.T) {
		fetcher, _ := newTestFetcher(t, nil, FetcherConfig{})
		if _, err := fetcher.OutputDecoding(context.Background(), chainclient.CurrentProfileSnapshot{ManifestHash: profile.ManifestHash}); err == nil {
			t.Fatal("returned an output_decoding with no source configured")
		}
	})
	t.Run("wrong bytes", func(t *testing.T) {
		fetcher, _ := newTestFetcher(t, map[string][]byte{"/m.json": []byte(`{"output_decoding":{}}`)}, FetcherConfig{})
		if _, err := fetcher.OutputDecoding(context.Background(), profile); err == nil || !strings.Contains(err.Error(), "not obtained") {
			t.Fatalf("error = %v, want the manifest reported as not obtained", err)
		}
	})
	t.Run("no manifest_hash", func(t *testing.T) {
		fetcher, _ := newTestFetcher(t, map[string][]byte{"/m.json": body}, FetcherConfig{})
		if _, err := fetcher.OutputDecoding(context.Background(), chainclient.CurrentProfileSnapshot{ManifestURI: profile.ManifestURI}); err == nil {
			t.Fatal("returned an output_decoding without a chain manifest_hash")
		}
	})
}
