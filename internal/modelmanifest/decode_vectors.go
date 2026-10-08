package modelmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// DECODE_VECTORS is the manifest's conformance proof for output decoding: a
// JSON array of {token_ids, expected_bytes_hex} pairs, authored against the
// profile's own tokenizer. token_ids is a full generated sequence T (with or
// without a trailing EOS, per case) and expected_bytes_hex is the committed
// output those ids must decode to under output_decoding -- one trailing EOS
// stripped, special tokens rendered, no cleanup, ill-formed tails folded to
// U+FFFD. A node whose decoder reproduces every vector decodes like the
// profile; one that fails any vector must not commit, because its committed
// outputs (Worker) or its decode comparisons (Verifier) would disagree with
// every conforming node.
//
// The file is a model artifact: output_decoding.decode_vectors_path names it,
// artifacts.files lists it with role DECODE_VECTORS, and its sha256 digest --
// not any transport -- is what makes bytes trustworthy.

// DecodeVector is one decoding conformance case.
type DecodeVector struct {
	// TokenIDs is the full generated sequence T of the case, trailing EOS
	// included when the case has one.
	TokenIDs []uint32
	// ExpectedBytes is the committed output T must decode to: the UTF-8 bytes
	// after the one-trailing-EOS strip. Empty for a T of nothing but an EOS.
	ExpectedBytes []byte
}

// ParseDecodeVectors parses a DECODE_VECTORS file strictly: a non-empty JSON
// array whose every element carries exactly token_ids (a non-empty array of
// u32) and expected_bytes_hex (lowercase hex without 0x, decoding to valid
// UTF-8 -- a committed output is canonical UTF-8 by construction, so bytes
// that are not could never be produced and mark an authoring error).
func ParseDecodeVectors(body []byte) ([]DecodeVector, error) {
	if len(body) > MaxManifestBytes {
		return nil, fmt.Errorf("decode vectors are %d bytes, above the %d byte bound", len(body), MaxManifestBytes)
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(body, &elements); err != nil {
		return nil, fmt.Errorf("decode vectors must be a JSON array: %w", err)
	}
	if len(elements) == 0 {
		return nil, errors.New("decode vectors must not be empty")
	}
	vectors := make([]DecodeVector, len(elements))
	for index, element := range elements {
		vector, err := parseDecodeVector(element)
		if err != nil {
			return nil, fmt.Errorf("decode vector %d: %w", index, err)
		}
		vectors[index] = vector
	}
	return vectors, nil
}

func parseDecodeVector(raw json.RawMessage) (DecodeVector, error) {
	if err := requireFields(raw, "decode vector", "expected_bytes_hex", "token_ids"); err != nil {
		return DecodeVector{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var parsed struct {
		TokenIDs         []uint32 `json:"token_ids"`
		ExpectedBytesHex string   `json:"expected_bytes_hex"`
	}
	if err := decoder.Decode(&parsed); err != nil {
		return DecodeVector{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return DecodeVector{}, errors.New("trailing data")
	}
	if len(parsed.TokenIDs) == 0 {
		return DecodeVector{}, errors.New("token_ids must not be empty")
	}
	if !isLowerHex(parsed.ExpectedBytesHex, len(parsed.ExpectedBytesHex)) || len(parsed.ExpectedBytesHex)%2 != 0 {
		return DecodeVector{}, errors.New("expected_bytes_hex must be lowercase hex of even length, without 0x")
	}
	expected, err := hex.DecodeString(parsed.ExpectedBytesHex)
	if err != nil {
		return DecodeVector{}, fmt.Errorf("expected_bytes_hex: %w", err)
	}
	if !utf8.Valid(expected) {
		return DecodeVector{}, errors.New("expected_bytes_hex is not valid UTF-8, which no committed output can be")
	}
	return DecodeVector{TokenIDs: parsed.TokenIDs, ExpectedBytes: expected}, nil
}

// DecodeVectorsRef names a manifest's DECODE_VECTORS artifact: its path inside
// the model directory and the sha256 of its bytes. The zero ref means the
// manifest declares no vectors (decode_vectors_path "").
type DecodeVectorsRef struct {
	Path   string
	SHA256 [32]byte
}

// IsDeclared reports whether the manifest names a DECODE_VECTORS artifact.
func (r DecodeVectorsRef) IsDeclared() bool { return r.Path != "" }

// Verify accepts body only when it hashes to the manifest's digest for the
// artifact, and then parses it. Trust comes from the digest alone, so bytes
// may arrive over any transport.
func (r DecodeVectorsRef) Verify(body []byte) ([]DecodeVector, error) {
	if digest := sha256.Sum256(body); digest != r.SHA256 {
		return nil, fmt.Errorf("%w: decode vectors hash to sha256:%s, the manifest commits sha256:%s",
			ErrHashMismatch, hex.EncodeToString(digest[:]), hex.EncodeToString(r.SHA256[:]))
	}
	vectors, err := ParseDecodeVectors(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return vectors, nil
}

// VerifyDecodeVectorsRef returns the DECODE_VECTORS reference of the manifest
// whose bytes are body, after checking that body hashes to manifestHash. Like
// VerifyOutputDecoding it reads only what it needs from the hash-authenticated
// document: the output_decoding block (strictly) and the artifacts file list.
// A manifest with an empty decode_vectors_path yields the zero ref, which is a
// declared absence, not an error.
func VerifyDecodeVectorsRef(body []byte, manifestHash chainclient.ProtoBytes32) (DecodeVectorsRef, error) {
	if !manifestHash.IsSet() {
		return DecodeVectorsRef{}, errors.New("chain profile has no manifest_hash")
	}
	if len(body) > MaxManifestBytes {
		return DecodeVectorsRef{}, fmt.Errorf("manifest is %d bytes, above max_manifest_bytes %d", len(body), MaxManifestBytes)
	}
	digest := Hash(body)
	if !bytes.Equal(digest[:], manifestHash) {
		return DecodeVectorsRef{}, fmt.Errorf("%w: got %s, chain has %s", ErrHashMismatch, digest, manifestHash.Hex())
	}
	decoding, err := parseOutputDecoding(body)
	if err != nil {
		return DecodeVectorsRef{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if decoding.DecodeVectorsPath == "" {
		return DecodeVectorsRef{}, nil
	}
	ref, err := decodeVectorsFileRef(body, decoding.DecodeVectorsPath)
	if err != nil {
		return DecodeVectorsRef{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return ref, nil
}

// decodeVectorsFileRef finds the one artifacts.files entry that carries the
// declared decode_vectors_path with role DECODE_VECTORS and returns its
// digest. The file list is read loosely: the manifest hash already
// authenticates the document, and validateFiles' full rules are the schema
// check's job, not this reader's.
func decodeVectorsFileRef(body []byte, path string) (DecodeVectorsRef, error) {
	var top struct {
		Artifacts struct {
			Files []ArtifactFile `json:"files"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return DecodeVectorsRef{}, fmt.Errorf("parse manifest artifacts: %w", err)
	}
	var found *ArtifactFile
	for index, file := range top.Artifacts.Files {
		if file.Role != "DECODE_VECTORS" || file.Path != path {
			continue
		}
		if found != nil {
			return DecodeVectorsRef{}, fmt.Errorf("artifacts.files lists %q as DECODE_VECTORS more than once", path)
		}
		found = &top.Artifacts.Files[index]
	}
	if found == nil {
		return DecodeVectorsRef{}, fmt.Errorf("output_decoding.decode_vectors_path %q has no DECODE_VECTORS entry in artifacts.files", path)
	}
	digestHex, ok := strings.CutPrefix(found.Digest, "sha256:")
	if !ok || !isLowerHex(digestHex, 64) {
		return DecodeVectorsRef{}, fmt.Errorf("DECODE_VECTORS digest %q must be sha256: followed by 64 lowercase hex characters", found.Digest)
	}
	ref := DecodeVectorsRef{Path: path}
	if _, err := hex.Decode(ref.SHA256[:], []byte(digestHex)); err != nil {
		return DecodeVectorsRef{}, err
	}
	return ref, nil
}
