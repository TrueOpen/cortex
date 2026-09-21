package revealcontract

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

const VerifierResultPayloadVersionV1 = "VERIFIER_RESULT_REVEAL_V1"

// VerifierResultPayloadV1 is the released 16-field result payload. Salt is bound
// by ResultCommitmentV2 and ResultReceiptV2, outside this canonical payload.
type VerifierResultPayloadV1 struct {
	ChainID                           string
	TaskID                            codec.Hash
	TaskHash                          codec.Hash
	VerifyRound                       uint32
	SelectedVerifierIndex             uint32
	VerifierOperatorAddress           string
	InferReceiptHash                  codec.Hash
	ProfileExecutionSnapshotHash      codec.Hash
	GenerationParamsDigest            codec.Hash
	MetricRoot                        codec.Hash
	MetricLeafCount                   uint32
	MetricSummaryHash                 codec.Hash
	AggregateProofHash                codec.Hash
	VerifierEvidenceBundleHash        codec.Hash
	VerifierEvidenceManifestSizeBytes uint64
}

func CanonicalVerifierResultPayload(payload VerifierResultPayloadV1) ([]byte, error) {
	if payload.ChainID == "" || strings.TrimSpace(payload.ChainID) != payload.ChainID || !utf8.ValidString(payload.ChainID) {
		return nil, fmt.Errorf("result payload chain_id must be canonical non-empty UTF-8")
	}
	verifier, err := nodewire.CanonicalOperatorAddressBytes("verifier_operator_address", payload.VerifierOperatorAddress)
	if err != nil {
		return nil, err
	}
	if payload.VerifyRound == 0 {
		return nil, fmt.Errorf("result payload verify_round must be positive")
	}
	if payload.MetricLeafCount == 0 {
		return nil, fmt.Errorf("result payload metric_leaf_count must be positive")
	}
	if payload.VerifierEvidenceManifestSizeBytes == 0 {
		return nil, fmt.Errorf("result payload verifier_evidence_manifest_size_bytes must be positive")
	}
	for _, field := range []struct {
		name  string
		value codec.Hash
	}{
		{"task_id", payload.TaskID}, {"task_hash", payload.TaskHash},
		{"infer_receipt_hash", payload.InferReceiptHash}, {"profile_execution_snapshot_hash", payload.ProfileExecutionSnapshotHash},
		{"generation_params_digest", payload.GenerationParamsDigest}, {"metric_root", payload.MetricRoot},
		{"metric_summary_hash", payload.MetricSummaryHash}, {"aggregate_proof_hash", payload.AggregateProofHash},
		{"verifier_evidence_bundle_hash", payload.VerifierEvidenceBundleHash},
	} {
		if field.value.IsZero() {
			return nil, fmt.Errorf("result payload %s must be non-zero", field.name)
		}
	}
	return hfields.FrameBytes(
		hfields.String(VerifierResultPayloadVersionV1), hfields.String(payload.ChainID),
		hfields.Hash(payload.TaskID), hfields.Hash(payload.TaskHash), hfields.Uint32(payload.VerifyRound),
		hfields.Uint32(payload.SelectedVerifierIndex), hfields.Bytes(verifier), hfields.Hash(payload.InferReceiptHash),
		hfields.Hash(payload.ProfileExecutionSnapshotHash), hfields.Hash(payload.GenerationParamsDigest),
		hfields.Hash(payload.MetricRoot), hfields.Uint32(payload.MetricLeafCount), hfields.Hash(payload.MetricSummaryHash),
		hfields.Hash(payload.AggregateProofHash), hfields.Hash(payload.VerifierEvidenceBundleHash),
		hfields.Uint64(payload.VerifierEvidenceManifestSizeBytes))
}
