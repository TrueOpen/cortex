package nodewire_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// releasedResultReceipt is the published TRUEOPEN_RESULT_V3 vector as a typed
// receipt.
func releasedResultReceipt(t *testing.T) nodewire.ResultReceiptV3 {
	t.Helper()
	v := resultReceiptV3Vectors(t)["result_v3_signing_digest"]
	verifier, err := nodewire.CanonicalOperatorAddressString("trueopen", fieldBytes(t, v, 4, "verifier_operator_address"))
	if err != nil {
		t.Fatal(err)
	}
	return nodewire.ResultReceiptV3{
		SchemaVersion:                     uint32(fieldUint(t, v, 0, "schema_version")),
		ChainID:                           fieldString(t, v, 1, "chain_id"),
		TaskID:                            fieldBytes(t, v, 2, "task_id"),
		VerifyRound:                       uint32(fieldUint(t, v, 3, "verify_round")),
		VerifierOperatorAddress:           verifier,
		ServiceAuthorizationNonce:         fieldUint(t, v, 5, "service_authorization_nonce"),
		GenerationParamsDigest:            fieldBytes(t, v, 6, "generation_params_digest"),
		MetricRoot:                        fieldBytes(t, v, 7, "metric_root"),
		MetricSummary:                     metricSummaryFromFrame(t, field(t, v, 8, "metric_summary")),
		AggregateProofHash:                fieldBytes(t, v, 9, "aggregate_proof_hash"),
		VerifierEvidenceBundleHash:        fieldBytes(t, v, 10, "verifier_evidence_bundle_hash"),
		VerifierEvidenceManifestSizeBytes: fieldUint(t, v, 11, "verifier_evidence_manifest_size_bytes"),
		Salt:                              fieldBytes(t, v, 12, "salt"),
		ExpiryHeight:                      fieldUint(t, v, 13, "expiry_height"),
		VerifierValueRoot:                 fieldBytes(t, v, 14, "verifier_value_root"),
		MetricLeafCount:                   uint32(fieldUint(t, v, 15, "metric_leaf_count")),
		VerifierEvidenceKeyCommitment:     fieldBytes(t, v, 16, "verifier_evidence_key_commitment"),
	}
}

func TestCommitKeyReproducesPublishedVector(t *testing.T) {
	keyVector := requireVector(t, goldenVectorsByName(t), "commit_key_v1")
	key, err := nodewire.VerifyCommitKey(fieldString(t, keyVector, 0, "chain_id"), fieldBytes(t, keyVector, 1, "task_id"), uint32(fieldUint(t, keyVector, 2, "verify_round")), fieldBech32(t, keyVector, 3, "verifier_operator_address"))
	if err != nil || hex.EncodeToString(key[:]) != keyVector.DigestHex {
		t.Fatalf("commit key %x: %v", key, err)
	}
}

func TestResultReceiptBindsEveryFieldAndRejectsLegacySchema(t *testing.T) {
	base := releasedResultReceipt(t)
	digest, err := nodewire.ResultReceiptSigningDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
		name := reflect.TypeOf(base).Field(i).Name
		t.Run(name, func(t *testing.T) {
			changed := base
			field := reflect.ValueOf(&changed).Elem().Field(i)
			switch field.Kind() {
			case reflect.Uint32, reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			case reflect.String:
				field.SetString(field.String() + "-changed")
			case reflect.Slice:
				field.SetBytes(bytes.Repeat([]byte{0x42}, 32))
			case reflect.Struct:
				changed.MetricSummary.FiniteCount++
			}
			got, err := nodewire.ResultReceiptSigningDigest(changed)
			if name == "ServiceSignature" {
				if err != nil || got != digest {
					t.Fatal("service signature entered digest")
				}
				return
			}
			if err == nil && got == digest {
				t.Fatal("field not bound")
			}
		})
	}
	base.SchemaVersion = 2
	if _, err := nodewire.ResultReceiptSigningDigest(base); err == nil {
		t.Fatal("accepted legacy schema")
	}
}

func TestOptionalMetricPresenceAndMembersAreBound(t *testing.T) {
	base := releasedResultReceipt(t).MetricSummary
	digest, _ := nodewire.MetricSummaryHash(base)
	for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
		changed := base
		field := reflect.ValueOf(&changed).Elem().Field(i)
		if field.Kind() == reflect.Struct {
			present := field.FieldByName("Present")
			present.SetBool(!present.Bool())
		} else {
			field.SetUint(field.Uint() + 1)
		}
		got, err := nodewire.MetricSummaryHash(changed)
		if err != nil || got == digest {
			t.Fatalf("summary field %d not bound: %v", i, err)
		}
	}
	absent := nodewire.MetricSummaryV1{}
	present := absent
	present.TopkJaccardMeanFP1e6 = nodewire.PresentUint32(0)
	a, _ := nodewire.MetricSummaryHash(absent)
	b, _ := nodewire.MetricSummaryHash(present)
	if a == b {
		t.Fatal("absent and present zero collide")
	}
}
