package nodewire_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func releasedResultVectors(t *testing.T) map[string]goldenVector {
	t.Helper()
	raw, err := wirevectors.File("task/result_receipt_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	vectors := make(map[string]goldenVector)
	for _, vector := range fixture.Vectors {
		vectors[vector.Name] = vector
	}
	return vectors
}

func releasedResultReceipt(t *testing.T, vector goldenVector) nodewire.ResultReceiptV2 {
	t.Helper()
	summary := goldenVector{Fields: vector.Fields[8].Fields}
	return nodewire.ResultReceiptV2{
		SchemaVersion: uint32(fieldUint(t, vector, 0, "schema_version")),
		ChainID:       fieldString(t, vector, 1, "chain_id"), TaskID: fieldBytes(t, vector, 2, "task_id"),
		VerifyRound:               uint32(fieldUint(t, vector, 3, "verify_round")),
		VerifierOperatorAddress:   fieldBech32(t, vector, 4, "verifier_operator_address"),
		ServiceAuthorizationNonce: fieldUint(t, vector, 5, "service_authorization_nonce"),
		GenerationParamsDigest:    fieldBytes(t, vector, 6, "generation_params_digest"), MetricRoot: fieldBytes(t, vector, 7, "metric_root"),
		MetricSummary: nodewire.MetricSummaryV1{
			FiniteCount: uint32(fieldUint(t, summary, 0, "finite_count")), MissingComparedCount: uint32(fieldUint(t, summary, 1, "missing_compared_count")),
			MeanAbsLogprobDiffFP1e6:   uint32(fieldUint(t, summary, 2, "mean_abs_logprob_diff_fp_1e6")),
			AbsLogprobDiffP95FP1e6:    uint32(fieldUint(t, summary, 3, "abs_logprob_diff_p95_fp_1e6")),
			AbsLogprobDiffP99FP1e6:    uint32(fieldUint(t, summary, 4, "abs_logprob_diff_p99_fp_1e6")),
			RankDeltaNonzeroRateFP1e6: uint32(fieldUint(t, summary, 5, "rank_delta_nonzero_rate_fp_1e6")),
			TopkJaccardMeanFP1e6:      nodewire.PresentUint32(uint32(*summary.Fields[6].Fields[0].Value)),
			UnionJSP99FP1e6:           nodewire.PresentUint32(uint32(*summary.Fields[7].Fields[0].Value)),
			ComparedTopkCount:         uint32(fieldUint(t, summary, 8, "compared_topk_count")), ComparedRankCount: uint32(fieldUint(t, summary, 9, "compared_rank_count")),
		},
		AggregateProofHash:                fieldBytes(t, vector, 9, "aggregate_proof_hash"),
		VerifierEvidenceBundleHash:        fieldBytes(t, vector, 10, "verifier_evidence_bundle_hash"),
		VerifierEvidenceManifestSizeBytes: fieldUint(t, vector, 11, "verifier_evidence_manifest_size_bytes"),
		Salt:                              fieldBytes(t, vector, 12, "salt"), ExpiryHeight: fieldUint(t, vector, 13, "expiry_height"),
	}
}

func TestResultV2PublishedChain(t *testing.T) {
	vectors := releasedResultVectors(t)
	vector := vectors["result_v2_signing_digest"]
	receipt := releasedResultReceipt(t, vector)
	assertPreimageAndDigest(t, vector, func() ([]byte, error) { return nodewire.ResultReceiptSigningPreimage(receipt) })
	summary, err := nodewire.MetricSummaryHash(receipt.MetricSummary)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(summary[:]) != vectors["metric_summary_v1"].DigestHex {
		t.Fatal("summary differs from release")
	}
	v := vectors["result_commitment_v2"]
	commitment := nodewire.ResultCommitmentV2{ChainID: fieldString(t, v, 0, "chain_id"), TaskID: fieldBytes(t, v, 1, "task_id"),
		TaskHash: fieldBytes(t, v, 2, "task_hash"), VerifyRound: uint32(fieldUint(t, v, 3, "verify_round")),
		VerifierOperatorAddress: fieldBech32(t, v, 4, "verifier_operator_address"), ResultPayloadHash: fieldBytes(t, v, 5, "result_payload_hash"), Salt: fieldBytes(t, v, 6, "salt")}
	digest, err := nodewire.ResultCommitmentHash(commitment)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != v.DigestHex {
		t.Fatalf("commitment %x, want %s", digest, v.DigestHex)
	}
	keyVector := requireVector(t, goldenVectorsByName(t), "commit_key_v1")
	key, err := nodewire.VerifyCommitKey(fieldString(t, keyVector, 0, "chain_id"), fieldBytes(t, keyVector, 1, "task_id"), uint32(fieldUint(t, keyVector, 2, "verify_round")), fieldBech32(t, keyVector, 3, "verifier_operator_address"))
	if err != nil || hex.EncodeToString(key[:]) != keyVector.DigestHex {
		t.Fatalf("commit key %x: %v", key, err)
	}
}

func TestResultReceiptBindsEveryFieldAndRejectsLegacySchema(t *testing.T) {
	base := releasedResultReceipt(t, releasedResultVectors(t)["result_v2_signing_digest"])
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
	base.SchemaVersion = 1
	if _, err := nodewire.ResultReceiptSigningDigest(base); err == nil {
		t.Fatal("accepted legacy schema")
	}
}

func TestOptionalMetricPresenceAndMembersAreBound(t *testing.T) {
	base := releasedResultReceipt(t, releasedResultVectors(t)["result_v2_signing_digest"]).MetricSummary
	digest, _ := nodewire.MetricSummaryHash(base)
	for i := 0; i < reflect.TypeOf(base).NumField(); i++ {
		changed := base
		field := reflect.ValueOf(&changed).Elem().Field(i)
		if field.Kind() == reflect.Struct {
			field.FieldByName("Present").SetBool(false)
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
