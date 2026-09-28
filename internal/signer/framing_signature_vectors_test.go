package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

type framingMessage struct {
	Type string `json:"type"`
	Hex  string `json:"hex"`
	UTF8 string `json:"utf8"`
}

func (m framingMessage) bytes(t *testing.T) []byte {
	t.Helper()
	switch m.Type {
	case "string":
		return []byte(m.UTF8)
	case "bytes":
		raw, err := hex.DecodeString(m.Hex)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	t.Fatalf("unknown message type %q", m.Type)
	return nil
}

// TestSignatureFramingVectors checks wire's signature_v1 and
// signature_direct_digest_v1 vectors against this package's signer and
// verifier: the public key derived from the private key, the exact 64-byte
// R||S signature (RFC 6979 makes it deterministic), its signature digest, and
// that a direct-digest signature does not verify against the re-hashed digest.
func TestSignatureFramingVectors(t *testing.T) {
	raw, err := wirevectors.File("shared/framing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Signatures []struct {
			Name               string         `json:"name"`
			PrivateKeyHex      string         `json:"private_key_hex"`
			Message            framingMessage `json:"message"`
			PubkeyHex          string         `json:"pubkey_hex"`
			SignatureHex       string         `json:"signature_hex"`
			SignatureDigestHex string         `json:"signature_digest_hex"`
		} `json:"signature_v1"`
		Direct []struct {
			Name               string         `json:"name"`
			PrivateKeyHex      string         `json:"private_key_hex"`
			DigestMessage      framingMessage `json:"digest_message"`
			DigestHex          string         `json:"digest_hex"`
			PubkeyHex          string         `json:"pubkey_hex"`
			SignatureHex       string         `json:"signature_hex"`
			SignatureDigestHex string         `json:"signature_digest_hex"`
			RehashedDigestHex  string         `json:"rehashed_digest_hex"`
		} `json:"signature_direct_digest_v1"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Signatures) == 0 || len(fixture.Direct) == 0 {
		t.Fatal("framing fixture publishes no signature vectors")
	}
	check := func(name, privateHex, pubkeyHex string, digest codec.Hash, signatureHex, signatureDigestHex string) []byte {
		t.Helper()
		privateBytes, err := hex.DecodeString(privateHex)
		if err != nil {
			t.Fatal(err)
		}
		private := secp256k1.PrivKeyFromBytes(privateBytes)
		id, err := identityFor(private.PubKey(), "trueopen")
		if err != nil || id.CompressedPubkeyHex != pubkeyHex {
			t.Fatalf("%s: public key %s (%v), published %s", name, id.CompressedPubkeyHex, err, pubkeyHex)
		}
		signature, err := signCompact(private, digest)
		if err != nil || hex.EncodeToString(signature) != signatureHex {
			t.Fatalf("%s: signature %x (%v), published %s", name, signature, err, signatureHex)
		}
		if got := codec.HashBytes(signature); got.String() != signatureDigestHex {
			t.Fatalf("%s: signature digest %s, published %s", name, got, signatureDigestHex)
		}
		if err := VerifyDigestSignature(pubkeyHex, digest, signature); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return signature
	}
	for _, vector := range fixture.Signatures {
		// A message signature signs SHA-256 of the message once.
		check(vector.Name, vector.PrivateKeyHex, vector.PubkeyHex, sha256.Sum256(vector.Message.bytes(t)), vector.SignatureHex, vector.SignatureDigestHex)
	}
	for _, vector := range fixture.Direct {
		digest := codec.Hash(sha256.Sum256(vector.DigestMessage.bytes(t)))
		if digest.String() != vector.DigestHex {
			t.Fatalf("%s: digest %s, published %s", vector.Name, digest, vector.DigestHex)
		}
		signature := check(vector.Name, vector.PrivateKeyHex, vector.PubkeyHex, digest, vector.SignatureHex, vector.SignatureDigestHex)
		rehashed := codec.Hash(sha256.Sum256(digest[:]))
		if rehashed.String() != vector.RehashedDigestHex {
			t.Fatalf("%s: rehashed digest %s, published %s", vector.Name, rehashed, vector.RehashedDigestHex)
		}
		if err := VerifyDigestSignature(vector.PubkeyHex, rehashed, signature); err == nil {
			t.Fatalf("%s: a direct-digest signature verified against the re-hashed digest", vector.Name)
		}
	}
}
