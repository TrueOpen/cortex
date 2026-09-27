package modelmanifest

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// ErrHashMismatch means the bytes are not the manifest the chain committed
// to. The source is treated as not having the manifest.
var ErrHashMismatch = errors.New("manifest bytes do not hash to the chain's manifest_hash")

// ErrInvalid means the bytes are the committed manifest but the manifest
// itself is invalid. Every copy of those bytes is equally invalid, so trying
// another source cannot help.
var ErrInvalid = errors.New("committed manifest is invalid")

// Verify runs the fixed verification order on bytes obtained from any
// source:
//
//  1. manifest_hash = H_V1("TRUEOPEN_MODEL_MANIFEST_V4", bytes) must equal
//     the chain's manifest_hash;
//  2. strict parse and schema validation;
//  3. the canonical re-encoding of the parsed manifest must equal the bytes;
//  4. the manifest's projection fields must equal the chain's.
//
// The bytes are never re-encoded before hashing.
func Verify(body []byte, chain chainclient.CurrentModelProfileSnapshot) (*Manifest, error) {
	if len(body) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest is %d bytes, above max_manifest_bytes %d", len(body), MaxManifestBytes)
	}
	digest := Hash(body)
	if !bytes.Equal(digest[:], chain.Profile.ManifestHash) {
		return nil, fmt.Errorf("%w: got %s, chain has %s", ErrHashMismatch, digest, chain.Profile.ManifestHash.Hex())
	}
	manifest, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	canonical, err := Canonical(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical encoding: %v", ErrInvalid, err)
	}
	if !bytes.Equal(canonical, body) {
		return nil, fmt.Errorf("%w: bytes are not the canonical encoding of the manifest (missing, null, duplicate, reordered or non-minimal fields)", ErrInvalid)
	}
	if err := manifest.CompareWithChain(digest, chain); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return manifest, nil
}
