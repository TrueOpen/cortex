package builderclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	"math"
	"strconv"
	"testing"

	"github.com/TrueOpen/wire/bus"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bussharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

// wirevectors.File verifies the released cross-language signing vectors against
// the pinned manifest, independently of the local module cache.
const busEnvelopeV2VectorsPath = "bus/bus_envelope_v2_vectors.json"

type busEnvelopeV2VectorFile struct {
	Schema              string `json:"schema"`
	Domain              string `json:"domain"`
	PublicKeyCompressed string `json:"public_key_compressed"`
	Cases               []struct {
		Name   string `json:"name"`
		Fields struct {
			SchemaVersion             uint32 `json:"schema_version"`
			ChainID                   string `json:"chain_id"`
			Subject                   string `json:"subject"`
			Kind                      int32  `json:"kind"`
			SenderParticipantType     int32  `json:"sender_participant_type"`
			SenderOperatorAddress     string `json:"sender_operator_address"`
			ServiceAuthorizationNonce string `json:"service_authorization_nonce"`
			MessageID                 string `json:"message_id"`
			Nonce                     string `json:"nonce"`
			IssuedAtUnixMs            string `json:"issued_at_unix_ms"`
			ExpiresAtUnixMs           string `json:"expires_at_unix_ms"`
			PayloadType               int32  `json:"payload_type"`
			PayloadDigest             string `json:"payload_digest"`
		} `json:"fields"`
		PayloadHex string `json:"payload_hex"`
		Expected   struct {
			PayloadDigest string `json:"payload_digest"`
			SigningDigest string `json:"signing_digest"`
			Signature     string `json:"signature"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadBusEnvelopeV2Vectors(t *testing.T) busEnvelopeV2VectorFile {
	t.Helper()
	raw, err := wirevectors.File(busEnvelopeV2VectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", busEnvelopeV2VectorsPath, err)
	}
	var file busEnvelopeV2VectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode %s: %v", busEnvelopeV2VectorsPath, err)
	}
	if file.Schema != "bus-envelope-v2-vectors-v2" {
		t.Fatalf("vector schema = %q, want bus-envelope-v2-vectors-v2", file.Schema)
	}
	if len(file.Cases) == 0 {
		t.Fatal("vector file carries no cases")
	}
	return file
}

func mustHex(t *testing.T, label, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s %q: %v", label, value, err)
	}
	return decoded
}

func mustUint64(t *testing.T, label, value string) uint64 {
	t.Helper()
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatalf("parse %s %q: %v", label, value, err)
	}
	return parsed
}

// TestBusEnvelopeV2SigningAgreesWithWireVectors is the external anchor the V2
// cutover would otherwise not have. Every other envelope test in this package
// checks Cortex against Cortex: it signs with BusEnvelopeSignDigest and then
// verifies with BusEnvelopeSignDigest, which stays green even if the whole
// projection drifts. This one drives the same production functions against
// digests and signatures a different implementation produced, so agreement is
// measured rather than asserted - the same contract the retired
// nexus_bus_envelope_signing_agreement.json fixture used to hold for V1.
func TestBusEnvelopeV2SigningAgreesWithWireVectors(t *testing.T) {
	file := loadBusEnvelopeV2Vectors(t)
	if file.Domain != BusEnvelopeSignDomain {
		t.Fatalf("vector domain = %q, cortex signs under %q", file.Domain, BusEnvelopeSignDomain)
	}
	reachable := 0
	for _, testCase := range file.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			fields := testCase.Fields
			issuedAt := mustUint64(t, "issued_at_unix_ms", fields.IssuedAtUnixMs)
			expiresAt := mustUint64(t, "expires_at_unix_ms", fields.ExpiresAtUnixMs)
			// BusEnvelope carries the two clocks as int64 while the frozen
			// wire types them uint64, so the top half of the range has no
			// Cortex representation at all. That is a refusal, not a silent
			// truncation: DecodeBusEnvelope rejects the frame outright, so a
			// peer sending one gets a closed door rather than a frame whose
			// digest nobody else reproduces. Asserted here so the limit stays
			// visible - if the field type ever widens, this branch stops being
			// taken and the case must derive a digest like any other.
			if issuedAt > math.MaxInt64 || expiresAt > math.MaxInt64 {
				assertCortexRefusesOversizedClocks(t, fields.Kind, issuedAt, expiresAt)
				return
			}
			reachable++

			spec, ok := busSubjectSpecForWireKind(busv1.BusMessageKind(fields.Kind))
			if !ok {
				t.Fatalf("kind %d is not in the cortex subject table", fields.Kind)
			}
			if int32(spec.payloadType) != fields.PayloadType {
				t.Fatalf("cortex maps kind %d to payload_type %d, vector says %d",
					fields.Kind, spec.payloadType, fields.PayloadType)
			}
			participant, err := participantFromWire(bussharedv1.ParticipantType(fields.SenderParticipantType))
			if err != nil {
				t.Fatalf("participant %d: %v", fields.SenderParticipantType, err)
			}

			payload := mustHex(t, "payload_hex", testCase.PayloadHex)
			wantPayloadDigest := mustHex(t, "expected.payload_digest", testCase.Expected.PayloadDigest)
			payloadDigest := bus.PayloadDigest(payload)
			if !bytes.Equal(payloadDigest[:], wantPayloadDigest) {
				t.Fatalf("payload_digest = %x, want %x", payloadDigest[:], wantPayloadDigest)
			}

			envelope := BusEnvelope{
				SchemaVersion:             fields.SchemaVersion,
				ChainID:                   fields.ChainID,
				Subject:                   fields.Subject,
				Kind:                      spec.kind,
				SenderParticipantType:     participant,
				SenderOperatorAddress:     fields.SenderOperatorAddress,
				ServiceAuthorizationNonce: mustUint64(t, "service_authorization_nonce", fields.ServiceAuthorizationNonce),
				MessageID:                 fields.MessageID,
				Nonce:                     mustHex(t, "nonce", fields.Nonce),
				IssuedAtUnixMs:            int64(issuedAt),
				ExpiresAtUnixMs:           int64(expiresAt),
				Payload:                   payload,
				PayloadDigest:             mustHex(t, "payload_digest", fields.PayloadDigest),
				Signature:                 mustHex(t, "expected.signature", testCase.Expected.Signature),
			}

			digest, err := BusEnvelopeSignDigest(envelope)
			if err != nil {
				t.Fatalf("BusEnvelopeSignDigest: %v", err)
			}
			want := mustHex(t, "expected.signing_digest", testCase.Expected.SigningDigest)
			if !bytes.Equal(digest[:], want) {
				t.Fatalf("signing digest = %x, want %x", digest[:], want)
			}
			// The signature is the second, independent half: a digest can
			// agree while the signature encoding (DER vs compact, high-S vs
			// low-S) does not, and only this call exercises the rule Cortex
			// applies to every inbound frame.
			if err := VerifyBusEnvelopeSignature(envelope, file.PublicKeyCompressed); err != nil {
				t.Fatalf("VerifyBusEnvelopeSignature against the wire vector key: %v", err)
			}
		})
	}
	if reachable == 0 {
		t.Fatal("no vector case reached the digest comparison; the anchor asserts nothing")
	}
}

// assertCortexRefusesOversizedClocks proves the int64 narrowing is a closed
// door rather than a truncation. Everything but the two clocks is a valid
// frame, so a failure here means the frame was accepted for the clocks, not
// rejected for some unrelated field.
func assertCortexRefusesOversizedClocks(t *testing.T, kind int32, issuedAt, expiresAt uint64) {
	t.Helper()
	spec, ok := busSubjectSpecForWireKind(busv1.BusMessageKind(kind))
	if !ok {
		t.Fatalf("kind %d is not in the cortex subject table", kind)
	}
	frame, err := proto.Marshal(&busv1.BusEnvelopeV1{
		SchemaVersion:             BusEnvelopeSchemaVersion,
		ChainId:                   "trueopen-localnet-1",
		Subject:                   spec.prefix + "a",
		Kind:                      spec.wireKind,
		SenderParticipantType:     bussharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX,
		SenderOperatorAddress:     "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
		ServiceAuthorizationNonce: 7,
		MessageId:                 "01890000-0000-7000-8000-000000000000",
		Nonce:                     bytes.Repeat([]byte{0x01}, bus.NonceSize),
		IssuedAtUnixMs:            issuedAt,
		ExpiresAtUnixMs:           expiresAt,
		PayloadType:               spec.payloadType,
		Payload:                   []byte{0x0a, 0x01, 0x01},
		PayloadDigest:             bytes.Repeat([]byte{0x02}, 32),
	})
	if err != nil {
		t.Fatalf("marshal oversized-clock frame: %v", err)
	}
	if _, err := DecodeBusEnvelope(frame); err == nil {
		t.Fatal("DecodeBusEnvelope accepted a frame whose clocks overflow int64")
	}
}
