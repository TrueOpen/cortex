package evidence

import (
	"context"
	"errors"
	"fmt"

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

func NewProofStore() *ProofStore {
	return &ProofStore{
		raw:       make(map[string]RawEvidence),
		generated: make(map[string]ProofMaterial),
	}
}

func (s *ProofStore) StoreRawEvidence(ctx context.Context, evidence RawEvidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if evidence.FaultID == "" {
		return fmt.Errorf("fault_id is required")
	}
	if evidence.TaskID == "" {
		return fmt.Errorf("task_id is required")
	}
	if _, ok := s.raw[evidence.FaultID]; ok {
		return ErrDuplicateFaultID
	}
	s.raw[evidence.FaultID] = RawEvidence{
		FaultID: evidence.FaultID,
		TaskID:  evidence.TaskID,
		Kind:    evidence.Kind,
		Data:    append([]byte(nil), evidence.Data...),
	}
	return nil
}

func (s *ProofStore) RawEvidence(faultID string) (RawEvidence, bool) {
	raw, ok := s.raw[faultID]
	if !ok {
		return RawEvidence{}, false
	}
	raw.Data = append([]byte(nil), raw.Data...)
	return raw, true
}

func (s *ProofStore) Generate(ctx context.Context, req ProofRequest) (ProofMaterial, error) {
	if err := ctx.Err(); err != nil {
		return ProofMaterial{}, err
	}
	if _, ok := s.generated[req.FaultID]; ok {
		return ProofMaterial{}, ErrDuplicateFaultID
	}
	raw, ok := s.raw[req.FaultID]
	if !ok || raw.TaskID != req.TaskID {
		return ProofMaterial{}, ErrRawEvidenceMissing
	}
	if !knownProofKind(req.Kind) {
		return ProofMaterial{}, fmt.Errorf("unsupported proof kind %q", req.Kind)
	}
	rawDigest := codec.HashBytes(raw.Data)
	payload := append([]byte(nil), raw.Data...)
	material := ProofMaterial{
		FaultID:         req.FaultID,
		TaskID:          req.TaskID,
		Kind:            req.Kind,
		RawEvidenceRef:  "sha256:" + fmt.Sprintf("%x", rawDigest[:]),
		EvidenceDigest:  codec.HashWithDomain("TRUEOPEN_PROOF_MATERIAL_V1", []byte(req.FaultID), []byte(req.TaskID), []byte(req.Kind), rawDigest[:]),
		EvidencePayload: payload,
	}
	s.generated[req.FaultID] = material
	return material, nil
}

func knownProofKind(kind ProofKind) bool {
	switch kind {
	case ProofOutputHashMismatch, ProofReceiptDeliveryMismatch, ProofCommitRevealMismatch,
		ProofPayloadMismatch, ProofWorkUnitMismatch, ProofCommitDoubleSign, ProofVerdictFraud:
		return true
	default:
		return false
	}
}

func NewProofEvidenceRecorder(store *ProofStore) *ProofEvidenceRecorder {
	return &ProofEvidenceRecorder{store: store}
}

func (r *ProofEvidenceRecorder) Record(ctx context.Context, req RecordProofEvidenceRequest) (ProofEvidenceRecord, error) {
	if r == nil || r.store == nil {
		return ProofEvidenceRecord{}, fmt.Errorf("proof store is required")
	}
	if err := r.store.StoreRawEvidence(ctx, RawEvidence{
		FaultID: req.FaultID,
		TaskID:  req.TaskID,
		Kind:    req.RawKind,
		Data:    append([]byte(nil), req.RawEvidence...),
	}); err != nil {
		return ProofEvidenceRecord{}, err
	}
	material, err := r.store.Generate(ctx, ProofRequest{
		FaultID: req.FaultID,
		Kind:    req.Kind,
		TaskID:  req.TaskID,
	})
	if err != nil {
		return ProofEvidenceRecord{}, err
	}
	return ProofEvidenceRecord{Material: material}, nil
}
