package evidence

import (
	"errors"

	"github.com/TrueOpen/cortex/internal/codec"
)

var (
	ErrRawEvidenceMissing = errors.New("raw evidence missing")
	ErrDuplicateFaultID   = errors.New("duplicate fault_id")
)

type ProofKind string

const (
	ProofOutputHashMismatch      ProofKind = "output_hash_mismatch"
	ProofReceiptDeliveryMismatch ProofKind = "receipt_delivery_mismatch"
	ProofCommitRevealMismatch    ProofKind = "commit_reveal_mismatch"
	ProofPayloadMismatch         ProofKind = "payload_mismatch"
	ProofWorkUnitMismatch        ProofKind = "work_unit_mismatch"
	ProofCommitDoubleSign        ProofKind = "commit_double_sign"
	ProofVerdictFraud            ProofKind = "verdict_fraud"
)

type RawEvidence struct {
	FaultID string
	TaskID  string
	Kind    string
	Data    []byte
}

type ProofRequest struct {
	FaultID string
	Kind    ProofKind
	TaskID  string
}

// ProofMaterial is local fault evidence only. The frozen task.v1.Msg
// service registers no fault or fraud proof entry point: MsgOutputHashMismatchProof,
// MsgSubmitFaultProof, MsgSubmitFraudProof and MsgSubmitVerdictFraudProof were
// never registered by any Keeper and do not exist in the frozen tx.proto, so
// this material carries no chain message type at all.
type ProofMaterial struct {
	FaultID         string
	TaskID          string
	Kind            ProofKind
	RawEvidenceRef  string
	EvidenceDigest  codec.Hash
	EvidencePayload []byte
}

type RecordProofEvidenceRequest struct {
	FaultID     string
	Kind        ProofKind
	TaskID      string
	RawKind     string
	RawEvidence []byte
}

type ProofEvidenceRecord struct {
	Material ProofMaterial
}

type ProofEvidenceRecorder struct {
	store *ProofStore
}

type ProofStore struct {
	raw       map[string]RawEvidence
	generated map[string]ProofMaterial
}
