package modelmanifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// goodDecodeVectors is a well-formed DECODE_VECTORS file: one ordinary case,
// one whose committed output is empty (a T of nothing but an EOS).
const goodDecodeVectors = `[
  {"token_ids": [10, 11, 151645], "expected_bytes_hex": "68656c6c6f20776f726c64"},
  {"token_ids": [151645], "expected_bytes_hex": ""}
]`

func TestParseDecodeVectors(t *testing.T) {
	vectors, err := ParseDecodeVectors([]byte(goodDecodeVectors))
	if err != nil {
		t.Fatal(err)
	}
	want := []DecodeVector{
		{TokenIDs: []uint32{10, 11, 151645}, ExpectedBytes: []byte("hello world")},
		{TokenIDs: []uint32{151645}, ExpectedBytes: []byte{}},
	}
	if !reflect.DeepEqual(vectors, want) {
		t.Fatalf("vectors = %+v, want %+v", vectors, want)
	}
}

func TestParseDecodeVectorsRefusesMalformedFiles(t *testing.T) {
	for name, body := range map[string]string{
		"not an array":       `{"token_ids": [1], "expected_bytes_hex": ""}`,
		"empty array":        `[]`,
		"unknown field":      `[{"token_ids": [1], "expected_bytes_hex": "", "extra": 1}]`,
		"missing token_ids":  `[{"expected_bytes_hex": "61"}]`,
		"missing expected":   `[{"token_ids": [1]}]`,
		"repeated field":     `[{"token_ids": [1], "token_ids": [2], "expected_bytes_hex": "61"}]`,
		"null field":         `[{"token_ids": null, "expected_bytes_hex": "61"}]`,
		"empty token_ids":    `[{"token_ids": [], "expected_bytes_hex": "61"}]`,
		"negative token id":  `[{"token_ids": [-1], "expected_bytes_hex": "61"}]`,
		"fractional id":      `[{"token_ids": [1.5], "expected_bytes_hex": "61"}]`,
		"id above u32":       `[{"token_ids": [4294967296], "expected_bytes_hex": "61"}]`,
		"uppercase hex":      `[{"token_ids": [1], "expected_bytes_hex": "6A"}]`,
		"odd-length hex":     `[{"token_ids": [1], "expected_bytes_hex": "6"}]`,
		"0x prefix":          `[{"token_ids": [1], "expected_bytes_hex": "0x61"}]`,
		"ill-formed UTF-8":   `[{"token_ids": [1], "expected_bytes_hex": "ff"}]`,
		"element not object": `[42]`,
	} {
		if _, err := ParseDecodeVectors([]byte(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	oversize := append([]byte(`[{"token_ids": [1], "expected_bytes_hex": "`), bytes.Repeat([]byte("61"), MaxManifestBytes/2)...)
	oversize = append(oversize, []byte(`"}]`)...)
	if _, err := ParseDecodeVectors(oversize); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("oversize file: %v", err)
	}
}

// manifestWithDecodeVectors builds the two blocks VerifyDecodeVectorsRef reads
// -- output_decoding naming path, and an artifacts.files list -- and hashes
// the result as a committed manifest would be.
func manifestWithDecodeVectors(path string, files string) ([]byte, chainclient.ProtoBytes32) {
	body := fmt.Appendf(nil, `{"artifacts":{"files":[%s]},"output_decoding":{"clean_up_tokenization_spaces":false,"decode_vectors_path":%q,"decoder":"HF_TOKENIZERS_V1","eos_token_ids":[151643,151645],"render_special_tokens":true,"strip_trailing_eos":true}}`,
		files, path)
	return body, hashBytes(body)
}

func decodeVectorsFileEntry(path string, digest [32]byte) string {
	return fmt.Sprintf(`{"digest":"sha256:%s","path":%q,"role":"DECODE_VECTORS","size_bytes":1}`, hex.EncodeToString(digest[:]), path)
}

func TestVerifyDecodeVectorsRef(t *testing.T) {
	digest := sha256.Sum256([]byte(goodDecodeVectors))
	body, hash := manifestWithDecodeVectors("trueopen/decode_vectors.json", decodeVectorsFileEntry("trueopen/decode_vectors.json", digest))
	ref, err := VerifyDecodeVectorsRef(body, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ref.IsDeclared() || ref.Path != "trueopen/decode_vectors.json" || ref.SHA256 != digest {
		t.Fatalf("ref = %+v", ref)
	}
	if _, err := VerifyDecodeVectorsRef(append(body, '\n'), hash); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered manifest: %v", err)
	}

	// The committed testnet manifest declares no vectors: a zero ref, no error.
	testnet := testnetManifest(t)
	ref, err = VerifyDecodeVectorsRef(testnet, hashBytes(testnet))
	if err != nil || ref.IsDeclared() {
		t.Fatalf("testnet manifest: ref %+v, err %v", ref, err)
	}

	// The published wire vector declares them, with the fixture's digest.
	golden, _ := goldenManifest(t)
	ref, err = VerifyDecodeVectorsRef(golden, hashBytes(golden))
	if err != nil || ref.Path != "trueopen/decode_vectors.json" || hex.EncodeToString(ref.SHA256[:]) != strings.Repeat("d", 64) {
		t.Fatalf("golden manifest: ref %+v, err %v", ref, err)
	}
}

func TestVerifyDecodeVectorsRefRefusesABrokenFileList(t *testing.T) {
	digest := sha256.Sum256([]byte(goodDecodeVectors))
	entry := decodeVectorsFileEntry("trueopen/decode_vectors.json", digest)
	for name, files := range map[string]string{
		"no matching entry": `{"digest":"sha256:` + strings.Repeat("a", 64) + `","path":"other.json","role":"DECODE_VECTORS","size_bytes":1}`,
		"wrong role":        strings.Replace(entry, "DECODE_VECTORS", "TOKENIZER", 1),
		"listed twice":      entry + "," + entry,
		"malformed digest":  strings.Replace(entry, "sha256:", "sha512:", 1),
	} {
		body, hash := manifestWithDecodeVectors("trueopen/decode_vectors.json", files)
		if _, err := VerifyDecodeVectorsRef(body, hash); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodeVectorsRefVerify(t *testing.T) {
	ref := DecodeVectorsRef{Path: "trueopen/decode_vectors.json", SHA256: sha256.Sum256([]byte(goodDecodeVectors))}
	vectors, err := ref.Verify([]byte(goodDecodeVectors))
	if err != nil || len(vectors) != 2 {
		t.Fatalf("Verify() = %d vectors, %v", len(vectors), err)
	}
	if _, err := ref.Verify([]byte(goodDecodeVectors + "\n")); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered bytes: %v", err)
	}
	garbage := []byte(`{"not":"an array"}`)
	committed := DecodeVectorsRef{Path: ref.Path, SHA256: sha256.Sum256(garbage)}
	if _, err := committed.Verify(garbage); !errors.Is(err, ErrInvalid) {
		t.Fatalf("committed garbage: %v", err)
	}
}

// decodeVectorsChain returns a chain snapshot registering a manifest that
// commits to the given vectors bytes, with the manifest already in cache so
// only the vectors file's own sources are exercised.
func decodeVectorsChain(t *testing.T, cache string, vectorBytes []byte) (chainclient.CurrentProfileSnapshot, string) {
	t.Helper()
	digest := sha256.Sum256(vectorBytes)
	body, hash := manifestWithDecodeVectors("trueopen/decode_vectors.json", decodeVectorsFileEntry("trueopen/decode_vectors.json", digest))
	if err := os.WriteFile(filepath.Join(cache, hash.Hex()+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	return chainclient.CurrentProfileSnapshot{ManifestHash: hash}, hex.EncodeToString(digest[:])
}

func TestFetcherDecodeVectorsFromTheCache(t *testing.T) {
	cache := t.TempDir()
	chain, digestHex := decodeVectorsChain(t, cache, []byte(goodDecodeVectors))
	if err := os.WriteFile(filepath.Join(cache, digestHex+".decode_vectors.json"), []byte(goodDecodeVectors), 0o644); err != nil {
		t.Fatal(err)
	}
	fetcher, server := newTestFetcher(t, nil, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/mirror"}})
	vectors, err := fetcher.DecodeVectors(context.Background(), chain)
	if err != nil || len(vectors) != 2 {
		t.Fatalf("DecodeVectors() = %d vectors, %v", len(vectors), err)
	}
	if len(server.paths()) != 0 {
		t.Fatalf("cache hit still reached the network: %v", server.paths())
	}
}

func TestFetcherDecodeVectorsFallsThroughToAMirrorAndCaches(t *testing.T) {
	cache := t.TempDir()
	chain, digestHex := decodeVectorsChain(t, cache, []byte(goodDecodeVectors))
	cached := filepath.Join(cache, digestHex+".decode_vectors.json")
	if err := os.WriteFile(cached, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	fetcher, server := newTestFetcher(t, map[string][]byte{
		"/mirror/" + digestHex: []byte(goodDecodeVectors),
	}, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/empty", "https://example.com/mirror"}})
	vectors, err := fetcher.DecodeVectors(context.Background(), chain)
	if err != nil || len(vectors) != 2 {
		t.Fatalf("DecodeVectors() = %d vectors, %v", len(vectors), err)
	}
	want := []string{"/empty/" + digestHex, "/mirror/" + digestHex}
	if got := server.paths(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("requested %v, want %v", got, want)
	}
	if stored, err := os.ReadFile(cached); err != nil || !bytes.Equal(stored, []byte(goodDecodeVectors)) {
		t.Fatalf("verified vectors were not cached: %v", err)
	}
}

func TestFetcherDecodeVectorsHonorsADeclaredAbsence(t *testing.T) {
	cache := t.TempDir()
	testnet := testnetManifest(t)
	if err := os.WriteFile(filepath.Join(cache, hashBytes(testnet).Hex()+".json"), testnet, 0o644); err != nil {
		t.Fatal(err)
	}
	fetcher, server := newTestFetcher(t, nil, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/mirror"}})
	vectors, err := fetcher.DecodeVectors(context.Background(), chainclient.CurrentProfileSnapshot{ManifestHash: hashBytes(testnet)})
	if err != nil || vectors != nil {
		t.Fatalf("DecodeVectors() = %v, %v, want declared absence", vectors, err)
	}
	if len(server.paths()) != 0 {
		t.Fatalf("a declared absence reached the network: %v", server.paths())
	}
}

func TestFetcherDecodeVectorsStopsOnCommittedGarbage(t *testing.T) {
	cache := t.TempDir()
	garbage := []byte(`{"not":"an array"}`)
	chain, digestHex := decodeVectorsChain(t, cache, garbage)
	fetcher, server := newTestFetcher(t, map[string][]byte{
		"/mirror/" + digestHex: garbage,
	}, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/mirror", "https://example.com/second"}})
	if _, err := fetcher.DecodeVectors(context.Background(), chain); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	if got := server.paths(); len(got) != 1 {
		t.Fatalf("requested %v after committed-invalid vectors", got)
	}
}

func TestFetcherDecodeVectorsReportsEverySource(t *testing.T) {
	cache := t.TempDir()
	chain, digestHex := decodeVectorsChain(t, cache, []byte(goodDecodeVectors))
	fetcher, _ := newTestFetcher(t, nil, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/mirror"}})
	_, err := fetcher.DecodeVectors(context.Background(), chain)
	if err == nil || !strings.Contains(err.Error(), "mirror https://example.com/mirror/"+digestHex) {
		t.Fatalf("error does not name the mirror: %v", err)
	}
	unconfigured, _ := newTestFetcher(t, nil, FetcherConfig{CacheDir: cache})
	if _, err := unconfigured.DecodeVectors(context.Background(), chain); err == nil || !strings.Contains(err.Error(), "not obtained") {
		t.Fatalf("cache-only fetch: %v", err)
	}
}
