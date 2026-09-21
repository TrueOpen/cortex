package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestHashWithDomainUsesLengthPrefixedDeterministicBytes(t *testing.T) {
	got := HashWithDomain("TRUEOPEN_TASK_ID_V1", []byte("session-7"), Uint64Bytes(42))

	var material bytes.Buffer
	writeLenPrefixed(&material, []byte("TRUEOPEN_TASK_ID_V1"))
	writeLenPrefixed(&material, []byte("session-7"))
	writeLenPrefixed(&material, Uint64Bytes(42))
	want := sha256.Sum256(material.Bytes())

	if got != want {
		t.Fatalf("hash mismatch\n got %x\nwant %x", got, want)
	}
}

func TestHashWithDomainUsesLengthPrefixes(t *testing.T) {
	left := HashWithDomain("DOMAIN", []byte("ab"), []byte("c"))
	right := HashWithDomain("DOMAIN", []byte("a"), []byte("bc"))

	if left == right {
		t.Fatalf("hash inputs with same concatenation must differ when length-prefixed: %x", left)
	}
}

func TestHashV1MatchesCanonicalSpecVector(t *testing.T) {
	// github.com/TrueOpen/wire v0.2.0 shared/framing_v1.json, vector
	// "four_byte_payload" under TRUEOPEN_TEST_PAYLOAD_V1. This is wire's own
	// published digest, not a value recorded from what this function returned.
	got := HashV1("TRUEOPEN_TEST_PAYLOAD_V1", []byte{0x00, 0x01, 0x02, 0x03})
	want, err := hex.DecodeString("86a9d92752da8f9211bd31386566570fd28f82f1d57c0be223337879c5f51c1e")
	if err != nil {
		t.Fatalf("decode H_V1 spec digest: %v", err)
	}

	if !bytes.Equal(got[:], want) {
		t.Fatalf("H_V1 hash mismatch\n got %x\nwant %x", got, want)
	}
}

func TestHashV1IsNotHashWithDomain(t *testing.T) {
	domain := "TRUEOPEN_TEST_PAYLOAD_V1"
	payload := []byte{0x00, 0x01, 0x02, 0x03}

	if got, fields := HashV1(domain, payload), HashWithDomain(domain, payload); got == fields {
		t.Fatalf("H_V1 and H_FIELDS_V1 must not be interchangeable: %x", got)
	}
}

func TestProtocolHashRejectsMapSigningInput(t *testing.T) {
	_, err := ProtocolHash("TRUEOPEN_TEST_V1", map[string]string{"b": "2", "a": "1"})
	if err == nil {
		t.Fatal("expected map input to be rejected for protocol signing/hash material")
	}
	if err.Error() != "protocol hash input must not be map/JSON material" {
		t.Fatalf("expected explicit map/JSON rejection, got %v", err)
	}
}

func TestProtocolHashHashesCanonicalBytes(t *testing.T) {
	canonical := []byte("canonical-bytes")
	got, err := ProtocolHash("TRUEOPEN_TEST_V1", canonical)
	if err != nil {
		t.Fatalf("ProtocolHash() error = %v", err)
	}
	want := HashWithDomain("TRUEOPEN_TEST_V1", canonical)
	if got != want {
		t.Fatalf("protocol hash mismatch\n got %x\nwant %x", got, want)
	}
}

func TestProtocolHashRejectsBlankDomain(t *testing.T) {
	_, err := ProtocolHash(" ", []byte("canonical-bytes"))
	if err == nil {
		t.Fatal("expected blank domain to be rejected")
	}
}

func TestHashWithDomainPanicsOnBlankDomain(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected HashWithDomain to panic for blank domain")
		}
	}()

	HashWithDomain("", []byte("canonical-bytes"))
}

func TestOutputHashHashesCanonicalOutputBytes(t *testing.T) {
	canonicalOutput := []byte("visible output bytes")
	got := OutputHash(canonicalOutput)
	want := HashBytes(canonicalOutput)

	if got != want {
		t.Fatalf("output hash mismatch\n got %x\nwant %x", got, want)
	}
}

func TestCanonicalOutputPackageHashHashesPackageBytesAndDiffersFromOutputHash(t *testing.T) {
	canonicalOutput := []byte("answer")
	packageBytes := []byte("package:v1:answer:manifest:signature")

	outputHash := OutputHash(canonicalOutput)
	packageHash := CanonicalOutputPackageHash(packageBytes)

	if packageHash != HashBytes(packageBytes) {
		t.Fatalf("package hash mismatch\n got %x\nwant %x", packageHash, HashBytes(packageBytes))
	}
	if packageHash == outputHash {
		t.Fatalf("package hash must not be interchangeable with output hash: %x", packageHash)
	}
}

// TestHashPrintsAsLowercaseHexUnderEveryVerb pins the reason String exists: a
// digest formatted with %s or %v used to emit the raw 32 bytes, so refusal
// messages that name a hash printed control characters where the value an
// operator has to compare against Keeper belonged.
func TestHashPrintsAsLowercaseHexUnderEveryVerb(t *testing.T) {
	hash := HashBytes([]byte("digest"))
	want := hex.EncodeToString(hash[:])
	if got := hash.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if got := fmt.Sprintf("%s|%v", hash, hash); got != want+"|"+want {
		t.Fatalf("formatted = %q, want the hex digest under both verbs", got)
	}
	if strings.ToLower(want) != want {
		t.Fatalf("hex spelling %q is not lowercase", want)
	}
}

func TestHashIsZeroOnlyForTheUnsetDigest(t *testing.T) {
	if !(Hash{}).IsZero() {
		t.Fatal("the zero hash does not report itself unset")
	}
	if HashBytes(nil).IsZero() {
		t.Fatal("sha256 of no bytes is a real digest and must not report itself unset")
	}
}

func writeLenPrefixed(buf *bytes.Buffer, value []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
	buf.Write(lenBuf[:])
	buf.Write(value)
}
