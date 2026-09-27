package revealcontract

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const VerifierResultPayloadVersionV2 = "VERIFIER_RESULT_REVEAL_V2"

// VerifierResultPayloadV2 is the wire v0.3.0 18-field reveal payload
// (task/result_receipt_v3.json). It carries the Verifier value root and the
// reserved Verifier evidence key slot. Its hash is the reveal's integrity
// digest and does not enter the commit, which binds verifier_value_root and the
// salt instead.
type VerifierResultPayloadV2 struct {
	ChainID                           string
	TaskID                            codec.Hash
	TaskHash                          codec.Hash
	VerifyRound                       uint32
	SelectedVerifierIndex             uint32
	VerifierOperatorAddress           string
	InferReceiptHash                  codec.Hash
	ProfileExecutionSnapshotHash      codec.Hash
	GenerationParamsDigest            codec.Hash
	VerifierValueRoot                 codec.Hash
	MetricRoot                        codec.Hash
	MetricLeafCount                   uint32
	MetricSummaryHash                 codec.Hash
	AggregateProofHash                codec.Hash
	VerifierEvidenceBundleHash        codec.Hash
	VerifierEvidenceManifestSizeBytes uint64
	VerifierEvidenceKeyCommitment     codec.Hash // ZERO32 in plaintext
}

// CanonicalVerifierResultPayload returns the canonical payload bytes.
func CanonicalVerifierResultPayload(payload VerifierResultPayloadV2) ([]byte, error) {
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
	if payload.VerifierEvidenceManifestSizeBytes == 0 {
		return nil, fmt.Errorf("result payload verifier_evidence_manifest_size_bytes must be positive")
	}
	for _, field := range []struct {
		name  string
		value codec.Hash
	}{
		{"task_id", payload.TaskID}, {"task_hash", payload.TaskHash},
		{"infer_receipt_hash", payload.InferReceiptHash}, {"profile_execution_snapshot_hash", payload.ProfileExecutionSnapshotHash},
		{"generation_params_digest", payload.GenerationParamsDigest}, {"verifier_value_root", payload.VerifierValueRoot},
		{"metric_root", payload.MetricRoot}, {"metric_summary_hash", payload.MetricSummaryHash},
		{"aggregate_proof_hash", payload.AggregateProofHash},
		{"verifier_evidence_bundle_hash", payload.VerifierEvidenceBundleHash},
	} {
		if field.value.IsZero() {
			return nil, fmt.Errorf("result payload %s must be non-zero", field.name)
		}
	}
	if !payload.VerifierEvidenceKeyCommitment.IsZero() {
		return nil, fmt.Errorf("result payload verifier_evidence_key_commitment must be ZERO32 while only PLAINTEXT is accepted")
	}
	return hfields.FrameBytes(
		hfields.String(VerifierResultPayloadVersionV2), hfields.String(payload.ChainID),
		hfields.Hash(payload.TaskID), hfields.Hash(payload.TaskHash), hfields.Uint32(payload.VerifyRound),
		hfields.Uint32(payload.SelectedVerifierIndex), hfields.Bytes(verifier), hfields.Hash(payload.InferReceiptHash),
		hfields.Hash(payload.ProfileExecutionSnapshotHash), hfields.Hash(payload.GenerationParamsDigest),
		hfields.Hash(payload.VerifierValueRoot),
		hfields.Hash(payload.MetricRoot), hfields.Uint32(payload.MetricLeafCount), hfields.Hash(payload.MetricSummaryHash),
		hfields.Hash(payload.AggregateProofHash), hfields.Hash(payload.VerifierEvidenceBundleHash),
		hfields.Uint64(payload.VerifierEvidenceManifestSizeBytes),
		hfields.Hash(payload.VerifierEvidenceKeyCommitment))
}
