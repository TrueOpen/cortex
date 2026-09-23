package signer

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/TrueOpen/cortex/internal/codec"
)

// Key is one decrypted signing key held in memory.
type Key struct {
	Ref     string
	private *secp256k1.PrivateKey
}

// KeyDescriptor is the public view of a loaded key, safe to log.
type KeyDescriptor struct {
	Ref              string
	CompressedPubkey string
	Address          string
}

type identity struct {
	CompressedPubkeyHex string
	Address             string
}

// signCompact produces the 64-byte [R||S] form Cosmos verifiers expect. The
// decred signer already normalises S to the lower half of the curve order, so
// no separate low-S pass is needed.
func signCompact(private *secp256k1.PrivateKey, digest codec.Hash) ([]byte, error) {
	if private == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if digest == (codec.Hash{}) {
		return nil, fmt.Errorf("digest is required")
	}
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	out := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out, nil
}

// VerifyDigestSignature verifies the canonical 64-byte [R||S] signature used
// by Cortex application material against a compressed secp256k1 public key.
func VerifyDigestSignature(compressedPubkeyHex string, digest codec.Hash, signature []byte) error {
	publicBytes, err := hex.DecodeString(strings.TrimSpace(compressedPubkeyHex))
	if err != nil || len(publicBytes) != 33 {
		return fmt.Errorf("service public key must be 33-byte compressed secp256k1 hex")
	}
	public, err := secp256k1.ParsePubKey(publicBytes)
	if err != nil {
		return fmt.Errorf("parse service public key: %w", err)
	}
	if digest == (codec.Hash{}) {
		return fmt.Errorf("digest is required")
	}
	if len(signature) != 64 {
		return fmt.Errorf("service signature must be 64-byte compact secp256k1")
	}
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[:32]); overflow || r.IsZero() {
		return fmt.Errorf("service signature R scalar is invalid")
	}
	if overflow := s.SetByteSlice(signature[32:]); overflow || s.IsZero() || s.IsOverHalfOrder() {
		return fmt.Errorf("service signature S scalar is invalid")
	}
	if !ecdsa.NewSignature(&r, &s).Verify(digest[:], public) {
		return fmt.Errorf("service signature does not match current service public key")
	}
	return nil
}

// AddressFromCompressedPublicKey derives the Bech32 Ethereum account address
// advertised by a compressed secp256k1 public key.
func AddressFromCompressedPublicKey(hrp string, compressed []byte) (string, error) {
	if len(compressed) != 33 {
		return "", fmt.Errorf("compressed public key must be 33 bytes")
	}
	public, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return "", fmt.Errorf("parse compressed public key: %w", err)
	}
	identity, err := identityFor(public, hrp)
	if err != nil {
		return "", err
	}
	return identity.Address, nil
}

// identityFor derives the compressed public key hex and the bech32 account
// address. Node service identities use the last 20 bytes of Keccak-256 over
// the uncompressed curve coordinates, without the 0x04 prefix.
func identityFor(public *secp256k1.PublicKey, hrp string) (identity, error) {
	if public == nil {
		return identity{}, fmt.Errorf("public key is required")
	}
	compressed := public.SerializeCompressed()
	if len(compressed) != 33 {
		return identity{}, fmt.Errorf("compressed public key must be 33 bytes")
	}
	digest := keccak256(public.SerializeUncompressed()[1:])
	address, err := bech32Encode(hrp, digest[12:])
	if err != nil {
		return identity{}, err
	}
	return identity{CompressedPubkeyHex: hex.EncodeToString(compressed), Address: address}, nil
}

func parsePrivateKeyHex(raw string) (*secp256k1.PrivateKey, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "0x"))
	if len(trimmed) != 64 {
		return nil, fmt.Errorf("private key must be 32-byte hex")
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("private key must be valid hex")
	}
	key := secp256k1.PrivKeyFromBytes(decoded)
	if key.Key.IsZero() {
		return nil, fmt.Errorf("private key must not be zero")
	}
	return key, nil
}
