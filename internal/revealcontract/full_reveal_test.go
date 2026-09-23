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

func releasedPayload(t *testing.T) (VerifierResultPayloadV1, []byte, string) {
	t.Helper()
	raw, err := wirevectors.File("task/result_receipt_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name       string `json:"name"`
			PayloadHex string `json:"payload_hex"`
			DigestHex  string `json:"digest_hex"`
		}
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		if v.Name != "verifier_result_payload_v1" {
			continue
		}
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatal(err)
		}
		var fields [][]byte
		for data := payload; len(data) > 0; {
			if len(data) < 8 {
				t.Fatal("truncated length")
			}
			n := binary.BigEndian.Uint64(data[:8])
			data = data[8:]
			if n > uint64(len(data)) {
				t.Fatal("truncated field")
			}
			fields = append(fields, data[:n])
			data = data[n:]
		}
		if len(fields) != 16 {
			t.Fatalf("payload has %d fields", len(fields))
		}
		h := func(index int) codec.Hash { var result codec.Hash; copy(result[:], fields[index]); return result }
		return VerifierResultPayloadV1{ChainID: string(fields[1]), TaskID: h(2), TaskHash: h(3), VerifyRound: binary.BigEndian.Uint32(fields[4]),
			SelectedVerifierIndex: binary.BigEndian.Uint32(fields[5]), VerifierOperatorAddress: "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
			InferReceiptHash: h(7), ProfileExecutionSnapshotHash: h(8), GenerationParamsDigest: h(9), MetricRoot: h(10), MetricLeafCount: binary.BigEndian.Uint32(fields[11]),
			MetricSummaryHash: h(12), AggregateProofHash: h(13), VerifierEvidenceBundleHash: h(14), VerifierEvidenceManifestSizeBytes: binary.BigEndian.Uint64(fields[15])}, payload, v.DigestHex
	}
	t.Fatal("missing release payload")
	return VerifierResultPayloadV1{}, nil, ""
}

func TestCanonicalVerifierResultPayloadMatchesRelease(t *testing.T) {
	payload, want, digest := releasedPayload(t)
	got, err := CanonicalVerifierResultPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch\n%x\n%x", got, want)
	}
	hash := nodewire.ResultPayloadHash(got)
	if hex.EncodeToString(hash[:]) != digest {
		t.Fatalf("payload digest %x, want %s", hash, digest)
	}
}

func TestCanonicalVerifierPayloadBindsEveryField(t *testing.T) {
	base, want, _ := releasedPayload(t)
	for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
		name := reflect.TypeOf(base).Field(i).Name
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

func TestCanonicalVerifierPayloadRejectsMissingScope(t *testing.T) {
	base, _, _ := releasedPayload(t)
	for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
		name := reflect.TypeOf(base).Field(i).Name
		if name == "SelectedVerifierIndex" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			changed := base
			field := reflect.ValueOf(&changed).Elem().Field(i)
			field.Set(reflect.Zero(field.Type()))
			if _, err := CanonicalVerifierResultPayload(changed); err == nil {
				t.Fatal("missing scope accepted")
			}
		})
	}
}
