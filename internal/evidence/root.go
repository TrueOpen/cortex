package evidence

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/TrueOpen/cortex/internal/codec"
)

const (
	LeafWorkerOpening    = "worker_opening"
	LeafVerifierOpening  = "verifier_opening"
	LeafFullResultReveal = "full_result_reveal"
)

type EvidenceLeaf struct {
	Type   string
	Ref    string
	Digest codec.Hash
}

type TaskEvidenceInput struct {
	TaskID            string
	WorkerOpenings    []EvidenceLeaf
	VerifierOpenings  []EvidenceLeaf
	FullResultReveals []EvidenceLeaf
}

type TaskEvidenceRoot struct {
	TaskID          string
	Leaves          []EvidenceLeaf
	LeafCountByType map[string]int
	ManifestHash    codec.Hash
	RootDigest      codec.Hash
	Manifest        []byte
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
