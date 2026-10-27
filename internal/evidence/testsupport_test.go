package evidence

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/TrueOpen/cortex/internal/codec"
)

// Declarations only tests use, kept out of the production binary.

func NewProofStore() *ProofStore {
	return &ProofStore{
		raw:       make(map[string]RawEvidence),
		generated: make(map[string]ProofMaterial),
	}
}

func NewProofEvidenceRecorder(store *ProofStore) *ProofEvidenceRecorder {
	return &ProofEvidenceRecorder{store: store}
}

func BuildTaskEvidenceRoot(input TaskEvidenceInput) (TaskEvidenceRoot, error) {
	if input.TaskID == "" {
		return TaskEvidenceRoot{}, fmt.Errorf("task id is required")
	}
	leaves, err := canonicalEvidenceLeaves(input)
	if err != nil {
		return TaskEvidenceRoot{}, err
	}
	if len(leaves) == 0 {
		return TaskEvidenceRoot{}, fmt.Errorf("task evidence root requires at least one leaf")
	}
	counts := map[string]int{
		LeafWorkerOpening:    len(input.WorkerOpenings),
		LeafVerifierOpening:  len(input.VerifierOpenings),
		LeafFullResultReveal: len(input.FullResultReveals),
	}
	manifest, err := encodeEvidenceManifest(input.TaskID, leaves, counts)
	if err != nil {
		return TaskEvidenceRoot{}, err
	}
	manifestHash := codec.HashWithDomain("TRUEOPEN_TASK_EVIDENCE_MANIFEST_V1", manifest)
	root := codec.HashWithDomain("TRUEOPEN_TASK_EVIDENCE_ROOT_V1", []byte(input.TaskID), manifestHash[:])
	return TaskEvidenceRoot{
		TaskID:          input.TaskID,
		Leaves:          leaves,
		LeafCountByType: counts,
		ManifestHash:    manifestHash,
		RootDigest:      root,
		Manifest:        manifest,
	}, nil
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

func canonicalEvidenceLeaves(input TaskEvidenceInput) ([]EvidenceLeaf, error) {
	groups := []struct {
		typ    string
		leaves []EvidenceLeaf
	}{
		{LeafWorkerOpening, input.WorkerOpenings},
		{LeafVerifierOpening, input.VerifierOpenings},
		{LeafFullResultReveal, input.FullResultReveals},
	}
	var out []EvidenceLeaf
	for _, group := range groups {
		leaves := append([]EvidenceLeaf(nil), group.leaves...)
		sort.Slice(leaves, func(i, j int) bool {
			if leaves[i].Ref != leaves[j].Ref {
				return leaves[i].Ref < leaves[j].Ref
			}
			return bytes.Compare(leaves[i].Digest[:], leaves[j].Digest[:]) < 0
		})
		for _, leaf := range leaves {
			if leaf.Ref == "" || leaf.Digest == (codec.Hash{}) {
				return nil, fmt.Errorf("evidence leaf missing ref or digest")
			}
			leaf.Type = group.typ
			out = append(out, leaf)
		}
	}
	return out, nil
}

func encodeEvidenceManifest(taskID string, leaves []EvidenceLeaf, counts map[string]int) ([]byte, error) {
	type manifestLeaf struct {
		Type   string `json:"type"`
		Ref    string `json:"ref"`
		Digest string `json:"digest"`
	}
	manifestLeaves := make([]manifestLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		manifestLeaves = append(manifestLeaves, manifestLeaf{
			Type:   leaf.Type,
			Ref:    leaf.Ref,
			Digest: fmt.Sprintf("%x", leaf.Digest[:]),
		})
	}
	return codec.CanonicalJSON(struct {
		Version         string         `json:"version"`
		TaskID          string         `json:"task_id"`
		LeafCountByType map[string]int `json:"leaf_count_by_type"`
		Leaves          []manifestLeaf `json:"leaves"`
	}{
		Version:         "task-evidence-root-v1",
		TaskID:          taskID,
		LeafCountByType: counts,
		Leaves:          manifestLeaves,
	})
}
