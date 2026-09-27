package revealcontract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// The published payload is decoded field by field into the typed payload and
// re-encoded, so the test checks the field order rather than copying bytes.
func TestVerifierResultPayloadV2ReproducesPublishedVector(t *testing.T) {
	payload, published, digestHex := releasedPayload(t)
	encoded, err := CanonicalVerifierResultPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, published) {
		t.Fatal("canonical V2 payload differs from the published bytes")
	}
	digest := codec.HashV1(nodewire.DomainVerifierResultPayloadV2, encoded)
	if hex.EncodeToString(digest[:]) != digestHex {
		t.Fatalf("result_payload_hash = %x, published %s", digest, digestHex)
	}

	nonZero := payload
	nonZero.VerifierEvidenceKeyCommitment[0] = 1
	if _, err := CanonicalVerifierResultPayload(nonZero); err == nil {
		t.Fatal("CanonicalVerifierResultPayload() accepted a non-zero plaintext key commitment")
	}
	noRoot := payload
	noRoot.VerifierValueRoot = codec.Hash{}
	if _, err := CanonicalVerifierResultPayload(noRoot); err == nil {
		t.Fatal("CanonicalVerifierResultPayload() accepted a zero verifier_value_root")
	}
}

// releasedPayload is wire's verifier_result_payload_v2 vector as a typed payload,
// with its exact bytes and digest.
func releasedPayload(t *testing.T) (VerifierResultPayloadV2, []byte, string) {
	t.Helper()
	data, err := wirevectors.File("task/result_receipt_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name       string `json:"name"`
			Domain     string `json:"domain"`
			PayloadHex string `json:"payload_hex"`
			DigestHex  string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var payloadHex, digestHex string
	for _, vector := range file.Vectors {
		if vector.Name == "verifier_result_payload_v2" && vector.Domain == nodewire.DomainVerifierResultPayloadV2 {
			payloadHex, digestHex = vector.PayloadHex, vector.DigestHex
		}
	}
	published, err := hex.DecodeString(payloadHex)
	if err != nil || len(published) == 0 {
		t.Fatalf("no verifier_result_payload_v2 vector: %v", err)
	}
	fields := splitFrame(t, published)
	if len(fields) != 18 || string(fields[0]) != VerifierResultPayloadVersionV2 {
		t.Fatalf("published payload has %d fields tagged %q, want 18 tagged %s", len(fields), fields[0], VerifierResultPayloadVersionV2)
	}
	verifier, err := nodewire.CanonicalOperatorAddressString("trueopen", fields[6])
	if err != nil {
		t.Fatal(err)
	}
	hash := func(i int) codec.Hash {
		var h codec.Hash
		if len(fields[i]) != len(h) {
			t.Fatalf("payload field %d is %d bytes, want 32", i, len(fields[i]))
		}
		copy(h[:], fields[i])
		return h
	}
	payload := VerifierResultPayloadV2{
		ChainID:                           string(fields[1]),
		TaskID:                            hash(2),
		TaskHash:                          hash(3),
		VerifyRound:                       binary.BigEndian.Uint32(fields[4]),
		SelectedVerifierIndex:             binary.BigEndian.Uint32(fields[5]),
		VerifierOperatorAddress:           verifier,
		InferReceiptHash:                  hash(7),
		ProfileExecutionSnapshotHash:      hash(8),
		GenerationParamsDigest:            hash(9),
		VerifierValueRoot:                 hash(10),
		MetricRoot:                        hash(11),
		MetricLeafCount:                   binary.BigEndian.Uint32(fields[12]),
		MetricSummaryHash:                 hash(13),
		AggregateProofHash:                hash(14),
		VerifierEvidenceBundleHash:        hash(15),
		VerifierEvidenceManifestSizeBytes: binary.BigEndian.Uint64(fields[16]),
		VerifierEvidenceKeyCommitment:     hash(17),
	}
	return payload, published, digestHex
}

func TestCanonicalVerifierPayloadBindsEveryField(t *testing.T) {
	base, want, _ := releasedPayload(t)
	for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
		name := reflect.TypeOf(base).Field(i).Name
		if name == "VerifierEvidenceKeyCommitment" {
			continue // must stay ZERO32 in plaintext; refused above
		}
		t.Run(name, func(t *testing.T) {
			changed := base
			field := reflect.ValueOf(&changed).Elem().Field(i)
			switch field.Kind() {
			case reflect.Uint32, reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			case reflect.Array:
				field.Index(0).SetUint(field.Index(0).Uint() ^ 1)
			case reflect.String:
				if name == "VerifierOperatorAddress" {
					field.SetString("trueopen1kxet8d94k6mm3wd6hw7tm04lcrqu9s7yxckkka")
				} else {
					field.SetString(field.String() + "-changed")
				}
			}
			got, err := CanonicalVerifierResultPayload(changed)
			if err != nil || bytes.Equal(got, want) {
				t.Fatalf("field not bound: %v", err)
			}
		})
	}
}

func splitFrame(t *testing.T, frame []byte) [][]byte {
	t.Helper()
	var fields [][]byte
	for offset := 0; offset < len(frame); {
		if len(frame)-offset < 8 {
			t.Fatal("truncated frame length")
		}
		length := int(binary.BigEndian.Uint64(frame[offset:]))
		offset += 8
		if length > len(frame)-offset {
			t.Fatal("frame field overruns the payload")
		}
		fields = append(fields, frame[offset:offset+length])
		offset += length
	}
	return fields
}
