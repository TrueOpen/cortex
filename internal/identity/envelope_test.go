package identity

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

const testSessionID = "abababababababababababababababababababababababababababababababab"

func TestTaskIDMatchesNodeRawSessionHFieldsVector(t *testing.T) {
	const want = "0891a5c5704d4dff5671daab9b353f31c86f81ac53cf1b3c4ef5171322c19f50"
	if got := TaskIDString(testSessionID, 42); got != want {
		t.Fatalf("TaskIDString() = %s, want Node vector %s", got, want)
	}
}

func TestTaskIDRejectsNonCanonicalSessionID(t *testing.T) {
	for _, sessionID := range []string{
		"",
		"session-7",
		" " + testSessionID,
		testSessionID + " ",
		strings.ToUpper(testSessionID),
		strings.Repeat("g", 64),
		testSessionID[:62],
		testSessionID + "00",
	} {
		if got := TaskIDString(sessionID, 42); got != "" {
			t.Fatalf("TaskIDString(%q) = %s, want empty refusal", sessionID, got)
		}
		if got := TaskID(sessionID, 42); got != (codec.Hash{}) {
			t.Fatalf("TaskID(%q) = %x, want zero refusal", sessionID, got)
		}
	}
}

func TestTaskIDUsesRawSessionAndUint64BigEndian(t *testing.T) {
	const want = "0891a5c5704d4dff5671daab9b353f31c86f81ac53cf1b3c4ef5171322c19f50"
	gotHash := TaskID(testSessionID, 42)
	if got := hex.EncodeToString(gotHash[:]); got != want {
		t.Fatalf("TaskID() = %s, want %s", got, want)
	}
	for _, sequence := range []uint64{0, 1, 10, 43, 1234567890, ^uint64(0)} {
		sequenceHash := TaskID(testSessionID, sequence)
		if got := hex.EncodeToString(sequenceHash[:]); got == want {
			t.Fatalf("TaskID(sequence=%d) reused sequence 42 digest", sequence)
		}
	}
}

func TestChainIDAndOrderDigestDoNotAffectTaskID(t *testing.T) {
	first := NewTaskIdentity("chain-a", testSessionID, 42, codec.HashBytes([]byte("order-a")))
	second := NewTaskIdentity("chain-b", testSessionID, 42, codec.HashBytes([]byte("order-b")))

	if first.TaskID != second.TaskID {
		t.Fatalf("chain_id/order_digest must not affect task_id\n first %x\nsecond %x", first.TaskID, second.TaskID)
	}
}

func TestSignedEnvelopeValidationRequiresOrderDigest(t *testing.T) {
	envelope := validEnvelope()
	envelope.OrderDigest = [32]byte{}

	err := envelope.Validate()
	if err == nil || !strings.Contains(err.Error(), "order_digest") {
		t.Fatalf("expected missing order_digest validation error, got %v", err)
	}
}

func TestSignedEnvelopeValidationRequiresBindingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SignedEnvelope)
		want   string
	}{
		{name: "domain", mutate: func(e *SignedEnvelope) { e.Domain = "" }, want: "domain"},
		{name: "chain id", mutate: func(e *SignedEnvelope) { e.ChainID = "" }, want: "chain_id"},
		{name: "session id", mutate: func(e *SignedEnvelope) { e.SessionID = "" }, want: "session_id"},
		{name: "task id", mutate: func(e *SignedEnvelope) { e.TaskID = [32]byte{} }, want: "task_id"},
		{name: "role", mutate: func(e *SignedEnvelope) { e.Role = "" }, want: "role"},
		{name: "message type", mutate: func(e *SignedEnvelope) { e.MessageType = "" }, want: "message_type"},
		{name: "message version", mutate: func(e *SignedEnvelope) { e.MessageVersion = "" }, want: "message_version"},
		{name: "valid until height", mutate: func(e *SignedEnvelope) { e.ValidUntilHeight = 0 }, want: "valid_until_height"},
		{name: "source snapshot height", mutate: func(e *SignedEnvelope) { e.SourceSnapshotHeight = 0 }, want: "source_snapshot_height"},
		{name: "nonce", mutate: func(e *SignedEnvelope) { e.SignerSequenceOrNonce = "" }, want: "signer_sequence_or_nonce"},
		{name: "canonical message hash", mutate: func(e *SignedEnvelope) { e.CanonicalMessageHash = [32]byte{} }, want: "canonical_message_hash"},
		{name: "signer address", mutate: func(e *SignedEnvelope) { e.SignerAddress = "" }, want: "signer_address"},
		{name: "signature", mutate: func(e *SignedEnvelope) { e.Signature = nil }, want: "signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := validEnvelope()
			tt.mutate(&envelope)

			err := envelope.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q validation error, got %v", tt.want, err)
			}
		})
	}
}

func TestSignedEnvelopeValidationChecksTaskIDMatchesSessionAndOrderSequence(t *testing.T) {
	envelope := validEnvelope()
	envelope.TaskID = TaskID(testSessionID, 43)

	err := envelope.Validate()
	if err == nil || !strings.Contains(err.Error(), "task_id") {
		t.Fatalf("expected task_id mismatch validation error, got %v", err)
	}
}

func TestSignedEnvelopeValidationChecksHeightWindowConsistency(t *testing.T) {
	envelope := validEnvelope()
	envelope.ValidFromHeight = 300
	envelope.ValidUntilHeight = 299

	err := envelope.Validate()
	if err == nil || !strings.Contains(err.Error(), "valid height window") {
		t.Fatalf("expected valid height window validation error, got %v", err)
	}
}

func TestSignedEnvelopeValidationRejectsShortFakeSignature(t *testing.T) {
	envelope := validEnvelope()
	envelope.Signature = []byte("invalid-test-signature")

	if err := envelope.Validate(); err == nil || !strings.Contains(err.Error(), "64 bytes") {
		t.Fatalf("Validate() error = %v, want strict signature length rejection", err)
	}
}

func TestSignedEnvelopeValidationRejectsRecoverableSignatureEncoding(t *testing.T) {
	envelope := validEnvelope()
	envelope.Signature = []byte(strings.Repeat("s", 65))
	if err := envelope.Validate(); err == nil || !strings.Contains(err.Error(), "64 bytes") {
		t.Fatalf("Validate() error = %v, want canonical compact signature rejection", err)
	}
}

func TestSignedEnvelopeSigningHashAllowsUnsignedMaterial(t *testing.T) {
	envelope := validEnvelope()
	envelope.Signature = nil

	if _, err := envelope.SigningHash(); err != nil {
		t.Fatalf("SigningHash() error = %v", err)
	}
}

func TestSignedEnvelopeSigningHashBindsEnvelopeFields(t *testing.T) {
	envelope := validEnvelope()

	first, err := envelope.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash() error = %v", err)
	}

	envelope.ChainID = "trueopen-testnet-2"
	second, err := envelope.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash() after chain mutation error = %v", err)
	}
	if first == second {
		t.Fatalf("SigningHash must change when chain_id changes: %x", first)
	}

	envelope = validEnvelope()
	envelope.OrderDigest = codec.HashBytes([]byte("different order"))
	third, err := envelope.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash() after order mutation error = %v", err)
	}
	if first == third {
		t.Fatalf("SigningHash must change when order_digest changes: %x", first)
	}
}

func TestSignedEnvelopeSigningHashRejectsInvalidMaterial(t *testing.T) {
	envelope := validEnvelope()
	envelope.Signature = nil
	envelope.OrderDigest = codec.Hash{}

	_, err := envelope.SigningHash()
	if err == nil || !strings.Contains(err.Error(), "order_digest") {
		t.Fatalf("SigningHash() error = %v, want order_digest error", err)
	}
}

func TestSignedEnvelopeValidationAcceptsValidEnvelope(t *testing.T) {
	envelope := validEnvelope()

	if err := envelope.Validate(); err != nil {
		t.Fatalf("expected valid envelope, got %v", err)
	}
}

func validEnvelope() SignedEnvelope {
	orderDigest := codec.HashBytes([]byte("canonical order envelope"))
	return SignedEnvelope{
		Domain:                "TRUEOPEN_WORKER_DELIVERY_V1",
		ChainID:               "trueopen-testnet-1",
		SessionID:             testSessionID,
		OrderSequence:         42,
		OrderDigest:           orderDigest,
		TaskID:                TaskID(testSessionID, 42),
		Role:                  "worker",
		MessageType:           "WorkerDelivery",
		MessageVersion:        "v1",
		ValidFromHeight:       100,
		ValidUntilHeight:      120,
		SourceSnapshotHeight:  99,
		SignerSequenceOrNonce: "nonce-1",
		CanonicalMessageHash:  codec.HashBytes([]byte("canonical message")),
		SignerAddress:         "trueopen1worker",
		Signature:             []byte(strings.Repeat("s", 64)),
	}
}
