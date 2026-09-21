package builderclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/wire/bus"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"

	bustaskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
)

// testEnvelopeKey derives a deterministic secp256k1 key for envelope tests.
func testEnvelopeKey(t *testing.T, label string) *secp256k1.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("cortex bus test key " + label))
	return secp256k1.PrivKeyFromBytes(seed[:])
}

// signTestEnvelope mints a signed V2 frame for tests: real payload marshalling,
// real signing projection, real compact low-S signature.
func signTestEnvelope(t *testing.T, key *secp256k1.PrivateKey, input UnsignedEnvelopeInput, payload proto.Message) []byte {
	t.Helper()
	envelope, err := NewUnsignedBusEnvelope(input, payload)
	if err != nil {
		t.Fatalf("NewUnsignedBusEnvelope: %v", err)
	}
	digest, err := BusEnvelopeSignDigest(envelope)
	if err != nil {
		t.Fatalf("BusEnvelopeSignDigest: %v", err)
	}
	envelope.Signature = bus.SignDigest(key, [32]byte(digest))
	frame, err := EncodeBusEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeBusEnvelope: %v", err)
	}
	return frame
}

func testWorkerHandraisePayload(taskID string) *bustaskv1.WorkerHandraiseV1 {
	raw, _ := hex.DecodeString(strings.Repeat("ab", 32))
	return &bustaskv1.WorkerHandraiseV1{
		SchemaVersion: 1, ChainId: "chain-1",
		TaskId: raw, TaskHash: bytes.Repeat([]byte{0xcd}, 32),
		ModelId: "model-a", ProfileVersion: 1,
		Member: &bustaskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: bytes.Repeat([]byte{0x11}, 32),
			Slot:                    1, SlotVersion: 1, OperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
		},
		Duty: 1, ServiceAuthorizationNonce: 23, ExpiryHeight: 100,
		ServiceSignature: bytes.Repeat([]byte{0x22}, 64),
	}
}

// TestEnvelopeRoundTripAndSignature: a signed V2 frame decodes back to the same
// projection, its digest verifies against the signer's key, and one flipped
// payload byte is refused by the digest check.
func TestEnvelopeRoundTripAndSignature(t *testing.T) {
	key := testEnvelopeKey(t, "roundtrip")
	taskID := "task-1"
	input := UnsignedEnvelopeInput{
		Kind: KindWorkerHandraise, ChainID: "chain-1",
		Subject:               NATSWorkerHandraiseSubject(taskID),
		SenderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", SenderParticipantType: ParticipantCortex,
		ServiceAuthorizationNonce: 23,
		IssuedAt:                  time.UnixMilli(1_700_000_000_000).UTC(),
		ExpiresAt:                 time.UnixMilli(1_700_000_030_000).UTC(),
	}
	frame := signTestEnvelope(t, key, input, testWorkerHandraisePayload(taskID))

	envelope, err := DecodeBusEnvelope(frame)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope: %v", err)
	}
	if envelope.Kind != KindWorkerHandraise || envelope.SenderParticipantType != ParticipantCortex {
		t.Fatalf("decoded envelope mismatch: %+v", envelope)
	}
	if err := envelope.ValidateEnvelopeIntrinsics(); err != nil {
		t.Fatalf("intrinsics: %v", err)
	}
	pubHex := hex.EncodeToString(key.PubKey().SerializeCompressed())
	if err := VerifyBusEnvelopeSignature(envelope, pubHex); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tamper with one payload byte after signing: digest recompute must refuse
	// before any signature is considered.
	tampered := envelope
	tampered.Payload = append([]byte(nil), envelope.Payload...)
	tampered.Payload[0] ^= 0x01
	if err := tampered.ValidateEnvelopeIntrinsics(); err == nil {
		t.Fatal("tampered payload passed the digest check")
	}

	var decoded bustaskv1.WorkerHandraiseV1
	if err := envelope.DecodePayload(&decoded); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.GetModelId() != "model-a" {
		t.Fatalf("payload round-trip mismatch: %+v", &decoded)
	}
}

// TestEnvelopeRejectsWrongSubjectKind: a frame whose subject carries another
// kind, or whose placeholder is multi-level, is internally inconsistent.
func TestEnvelopeRejectsWrongSubjectKind(t *testing.T) {
	key := testEnvelopeKey(t, "subject")
	input := UnsignedEnvelopeInput{
		Kind: KindWorkerHandraise, ChainID: "chain-1",
		Subject:               NATSWorkerHandraiseSubject("task-1"),
		SenderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", SenderParticipantType: ParticipantCortex,
		ServiceAuthorizationNonce: 23,
	}
	frame := signTestEnvelope(t, key, input, testWorkerHandraisePayload("task-1"))
	envelope, err := DecodeBusEnvelope(frame)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Subject = NATSVerifyResultSubject("task-1")
	if err := envelope.ValidateEnvelopeIntrinsics(); err == nil {
		t.Fatal("subject carrying another kind was accepted")
	}
	envelope.Subject = NATSWorkerHandraiseSubject("task-1") + ".extra"
	if err := envelope.ValidateEnvelopeIntrinsics(); err == nil {
		t.Fatal("multi-level subject placeholder was accepted")
	}
}

// TestEnvelopeRejectsWrongParticipant: a Builder-domain sender may not sign a
// handraise kind, and an unknown participant enum is refused at decode.
func TestEnvelopeRejectsWrongParticipant(t *testing.T) {
	_, err := NewUnsignedBusEnvelope(UnsignedEnvelopeInput{
		Kind: KindWorkerHandraise, ChainID: "chain-1",
		Subject:               NATSWorkerHandraiseSubject("task-1"),
		SenderOperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", SenderParticipantType: ParticipantBuilder,
		ServiceAuthorizationNonce: 23,
	}, testWorkerHandraisePayload("task-1"))
	if err == nil {
		t.Fatal("BUILDER participant accepted for a handraise kind")
	}
}

// TestEnvelopeRejectsUnknownEnvelopeFields: extra envelope fields mean the peer
// speaks a different field table.
func TestEnvelopeRejectsUnknownEnvelopeFields(t *testing.T) {
	key := testEnvelopeKey(t, "unknown")
	input := UnsignedEnvelopeInput{
		Kind: KindWorkerHandraise, ChainID: "chain-1",
		Subject:               NATSWorkerHandraiseSubject("task-1"),
		SenderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", SenderParticipantType: ParticipantCortex,
		ServiceAuthorizationNonce: 23,
	}
	frame := signTestEnvelope(t, key, input, testWorkerHandraisePayload("task-1"))
	// Append an unknown field (field 99, varint 1) to the frame.
	frame = append(frame, 0x98, 0x06, 0x01)
	if _, err := DecodeBusEnvelope(frame); err == nil {
		t.Fatal("unknown envelope field was accepted")
	}
}
