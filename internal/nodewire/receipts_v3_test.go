package nodewire_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

type inferReceiptV3File struct {
	CommitmentList struct {
		DigestHex   string `json:"digest_hex"`
		PreimageHex string `json:"preimage_hex"`
		Items       []struct {
			EncodedSizeBytes      uint64 `json:"encoded_size_bytes"`
			EvidenceHashOrRootHex string `json:"evidence_hash_or_root_hex"`
			EvidenceKind          int32  `json:"evidence_kind"`
		} `json:"items"`
	} `json:"commitment_list"`
	Vectors []goldenVector `json:"vectors"`
}

func inferReceiptV3Fixture(t *testing.T) (nodewire.InferReceiptV3, inferReceiptV3File) {
	t.Helper()
	data, err := wirevectors.File("task/infer_receipt_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file inferReceiptV3File
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 1 || file.Vectors[0].Domain != nodewire.DomainInferReceiptV3 || len(file.Vectors[0].Fields) != 17 {
		t.Fatal("infer_receipt_v3.json must publish one 17-field TRUEOPEN_INFER_RECEIPT_V3 vector")
	}
	items := make([]nodewire.EvidenceCommitmentV1, 0, len(file.CommitmentList.Items))
	for _, item := range file.CommitmentList.Items {
		hashOrRoot, err := hex.DecodeString(item.EvidenceHashOrRootHex)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, nodewire.EvidenceCommitmentV1{
			EvidenceKind:       nodewire.EvidenceKind(item.EvidenceKind),
			EvidenceHashOrRoot: hashOrRoot,
			EncodedSizeBytes:   item.EncodedSizeBytes,
		})
	}
	v := file.Vectors[0]
	if hex.EncodeToString(fieldBytes(t, v, 9, "evidence_commitments_hash")) != file.CommitmentList.DigestHex {
		t.Fatal("the receipt vector does not carry the published commitment list digest")
	}
	return nodewire.InferReceiptV3{
		SchemaVersion:               uint32(fieldUint(t, v, 0, "schema_version")),
		ChainID:                     fieldString(t, v, 1, "chain_id"),
		TaskID:                      fieldBytes(t, v, 2, "task_id"),
		TaskHash:                    fieldBytes(t, v, 3, "task_hash"),
		WorkerOperatorAddress:       fieldBech32(t, v, 4, "worker_operator_address"),
		ServiceAuthorizationNonce:   fieldUint(t, v, 5, "service_authorization_nonce"),
		GenerationParamsDigest:      fieldBytes(t, v, 6, "generation_params_digest"),
		OutputHash:                  fieldBytes(t, v, 7, "output_hash"),
		OutputSizeBytes:             fieldUint(t, v, 8, "output_size_bytes"),
		RequiredEvidenceCommitments: items,
		ExpiryHeight:                fieldUint(t, v, 10, "expiry_height"),
		GeneratedTokenCount:         fieldUint(t, v, 11, "generated_token_count"),
		OutputLeafCount:             fieldUint(t, v, 12, "output_leaf_count"),
		OutputKeyCommitment:         fieldBytes(t, v, 13, "output_key_commitment"),
		WorkerTokenKeyCommitment:    fieldBytes(t, v, 14, "worker_token_key_commitment"),
		WorkerValueKeyCommitment:    fieldBytes(t, v, 15, "worker_value_key_commitment"),
		CiphertextOutputRoot:        fieldBytes(t, v, 16, "ciphertext_output_root"),
	}, file
}

func TestInferReceiptV3ReproducesPublishedVector(t *testing.T) {
	receipt, file := inferReceiptV3Fixture(t)
	list, err := nodewire.EvidenceCommitmentsHash(receipt.RequiredEvidenceCommitments)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(list[:]) != file.CommitmentList.DigestHex {
		t.Fatalf("evidence_commitments_hash = %x, published %s", list, file.CommitmentList.DigestHex)
	}
	preimage, err := nodewire.InferReceiptSigningPreimage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := nodewire.InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	checkPublished(t, file.Vectors[0], preimage, digest)
	// The service signature is outside the preimage.
	signed := receipt
	signed.ServiceSignature = []byte("signature")
	if again, err := nodewire.InferReceiptSigningDigest(signed); err != nil || again != digest {
		t.Fatal("service_signature changed the receipt digest")
	}
}

// The fixture's rejected_encodings: a V2 domain/schema, one evidence
// commitment, text-encoded Hash32 and a non-zero plaintext encryption slot.
func TestInferReceiptV3RejectsPublishedBadEncodings(t *testing.T) {
	receipt, _ := inferReceiptV3Fixture(t)
	nonZero := make([]byte, 32)
	nonZero[31] = 1
	for name, mutate := range map[string]func(*nodewire.InferReceiptV3){
		"V2 schema version":       func(r *nodewire.InferReceiptV3) { r.SchemaVersion = 2 },
		"one evidence commitment": func(r *nodewire.InferReceiptV3) { r.RequiredEvidenceCommitments = r.RequiredEvidenceCommitments[:1] },
		"commitments out of order": func(r *nodewire.InferReceiptV3) {
			r.RequiredEvidenceCommitments = []nodewire.EvidenceCommitmentV1{r.RequiredEvidenceCommitments[1], r.RequiredEvidenceCommitments[0]}
		},
		"text-encoded Hash32": func(r *nodewire.InferReceiptV3) {
			r.OutputHash = []byte(hex.EncodeToString(r.OutputHash))
		},
		"non-zero plaintext encryption slot": func(r *nodewire.InferReceiptV3) { r.WorkerValueKeyCommitment = nonZero },
		"missing encryption slot":            func(r *nodewire.InferReceiptV3) { r.CiphertextOutputRoot = nil },
	} {
		bad := receipt
		mutate(&bad)
		if _, err := nodewire.InferReceiptSigningDigest(bad); err == nil {
			t.Errorf("%s: InferReceiptSigningDigest() error = nil", name)
		}
	}
}

func resultReceiptV3Vectors(t *testing.T) map[string]goldenVector {
	t.Helper()
	data, err := wirevectors.File("task/result_receipt_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []goldenVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	vectors := make(map[string]goldenVector, len(file.Vectors))
	for _, vector := range file.Vectors {
		vectors[vector.Name] = vector
	}
	return vectors
}

func metricSummaryFromFrame(t *testing.T, frame goldenField) nodewire.MetricSummaryV1 {
	t.Helper()
	inner := goldenVector{Name: frame.Name, Fields: frame.Fields}
	return nodewire.MetricSummaryV1{
		FiniteCount:               uint32(fieldUint(t, inner, 0, "finite_count")),
		MissingComparedCount:      uint32(fieldUint(t, inner, 1, "missing_compared_count")),
		MeanAbsLogprobDiffFP1e6:   uint32(fieldUint(t, inner, 2, "mean_abs_logprob_diff_fp_1e6")),
		AbsLogprobDiffP95FP1e6:    uint32(fieldUint(t, inner, 3, "abs_logprob_diff_p95_fp_1e6")),
		AbsLogprobDiffP99FP1e6:    uint32(fieldUint(t, inner, 4, "abs_logprob_diff_p99_fp_1e6")),
		RankDeltaNonzeroRateFP1e6: uint32(fieldUint(t, inner, 5, "rank_delta_nonzero_rate_fp_1e6")),
		TopkJaccardMeanFP1e6:      fieldOptionalUint32(t, inner, 6, "topk_jaccard_mean_fp_1e6"),
		UnionJSP99FP1e6:           fieldOptionalUint32(t, inner, 7, "union_js_p99_fp_1e6"),
		ComparedTopkCount:         uint32(fieldUint(t, inner, 8, "compared_topk_count")),
		ComparedRankCount:         uint32(fieldUint(t, inner, 9, "compared_rank_count")),
	}
}

func TestResultCommitmentV3ReproducesPublishedVector(t *testing.T) {
	v := resultReceiptV3Vectors(t)["result_commitment_v3"]
	if v.Domain != nodewire.DomainResultCommitmentV3 || len(v.Fields) != 7 {
		t.Fatal("result_commitment_v3 must be a 7-field TRUEOPEN_RESULT_COMMITMENT_V3 vector")
	}
	verifier, err := nodewire.CanonicalOperatorAddressString("trueopen", fieldBytes(t, v, 4, "verifier_operator_address"))
	if err != nil {
		t.Fatal(err)
	}
	commitment := nodewire.ResultCommitmentV3{
		ChainID:                 fieldString(t, v, 0, "chain_id"),
		TaskID:                  fieldBytes(t, v, 1, "task_id"),
		TaskHash:                fieldBytes(t, v, 2, "task_hash"),
		VerifyRound:             uint32(fieldUint(t, v, 3, "verify_round")),
		VerifierOperatorAddress: verifier,
		VerifierValueRoot:       fieldBytes(t, v, 5, "verifier_value_root"),
		Salt:                    fieldBytes(t, v, 6, "salt"),
	}
	digest, err := nodewire.ResultCommitmentHash(commitment)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != v.DigestHex {
		t.Fatalf("commit_hash = %x, published %s", digest, v.DigestHex)
	}
	zeroSalt := commitment
	zeroSalt.Salt = make([]byte, 32)
	if _, err := nodewire.ResultCommitmentHash(zeroSalt); err == nil {
		t.Fatal("ResultCommitmentHash() accepted a ZERO32 salt")
	}
}

func TestResultReceiptV3ReproducesPublishedVector(t *testing.T) {
	vectors := resultReceiptV3Vectors(t)
	summaryVector := vectors["metric_summary_v1"]
	summary := metricSummaryFromFrame(t, field(t, summaryVector, 0, "metric_summary"))
	summaryHash, err := nodewire.MetricSummaryHash(summary)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(summaryHash[:]) != summaryVector.DigestHex {
		t.Fatalf("metric_summary_hash = %x, published %s", summaryHash, summaryVector.DigestHex)
	}

	v := vectors["result_v3_signing_digest"]
	if v.Domain != nodewire.DomainResultV3 || len(v.Fields) != 17 {
		t.Fatal("result_v3_signing_digest must be a 17-field TRUEOPEN_RESULT_V3 vector")
	}
	verifier, err := nodewire.CanonicalOperatorAddressString("trueopen", fieldBytes(t, v, 4, "verifier_operator_address"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := nodewire.ResultReceiptV3{
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
	preimage, err := nodewire.ResultReceiptSigningPreimage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := nodewire.ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	checkPublished(t, v, preimage, digest)

	nonZero := make([]byte, 32)
	nonZero[0] = 1
	for name, mutate := range map[string]func(*nodewire.ResultReceiptV3){
		"V2 schema version":           func(r *nodewire.ResultReceiptV3) { r.SchemaVersion = 2 },
		"leaf count off by one":       func(r *nodewire.ResultReceiptV3) { r.MetricLeafCount++ },
		"non-zero plaintext slot":     func(r *nodewire.ResultReceiptV3) { r.VerifierEvidenceKeyCommitment = nonZero },
		"ZERO32 salt":                 func(r *nodewire.ResultReceiptV3) { r.Salt = make([]byte, 32) },
		"missing verifier value root": func(r *nodewire.ResultReceiptV3) { r.VerifierValueRoot = nil },
	} {
		bad := receipt
		mutate(&bad)
		if _, err := nodewire.ResultReceiptSigningDigest(bad); err == nil {
			t.Errorf("%s: ResultReceiptSigningDigest() error = nil", name)
		}
	}
}
