package evidence

import (
	"reflect"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
)

func TestTaskEvidenceRootIsDeterministicAndCountsLeavesByType(t *testing.T) {
	input := TaskEvidenceInput{
		TaskID: "task-1",
		WorkerOpenings: []EvidenceLeaf{
			{Ref: "worker-b", Digest: codec.HashWithDomain("WORKER", []byte("b"))},
			{Ref: "worker-a", Digest: codec.HashWithDomain("WORKER", []byte("a"))},
		},
		VerifierOpenings: []EvidenceLeaf{
			{Ref: "verifier-c", Digest: codec.HashWithDomain("VERIFIER", []byte("c"))},
		},
		FullResultReveals: []EvidenceLeaf{
			{Ref: "full-b", Digest: codec.HashWithDomain("FULL", []byte("b"))},
			{Ref: "full-a", Digest: codec.HashWithDomain("FULL", []byte("a"))},
		},
	}
	first, err := BuildTaskEvidenceRoot(input)
	if err != nil {
		t.Fatalf("build root: %v", err)
	}
	second, err := BuildTaskEvidenceRoot(input)
	if err != nil {
		t.Fatalf("build root again: %v", err)
	}

	if first.RootDigest != second.RootDigest || first.ManifestHash != second.ManifestHash || !reflect.DeepEqual(first.Leaves, second.Leaves) {
		t.Fatalf("root builder is not deterministic: first=%#v second=%#v", first, second)
	}
	wantCounts := map[string]int{
		"worker_opening":     2,
		"verifier_opening":   1,
		"full_result_reveal": 2,
	}
	if !reflect.DeepEqual(first.LeafCountByType, wantCounts) {
		t.Fatalf("leaf counts = %#v, want %#v", first.LeafCountByType, wantCounts)
	}
	wantOrder := []string{
		"worker_opening:worker-a",
		"worker_opening:worker-b",
		"verifier_opening:verifier-c",
		"full_result_reveal:full-a",
		"full_result_reveal:full-b",
	}
	var gotOrder []string
	for _, leaf := range first.Leaves {
		gotOrder = append(gotOrder, leaf.Type+":"+leaf.Ref)
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("leaf order = %#v, want %#v", gotOrder, wantOrder)
	}
	if first.RootDigest == (codec.Hash{}) || first.ManifestHash == (codec.Hash{}) {
		t.Fatalf("root or manifest hash is empty: %#v", first)
	}
}

func TestTaskEvidenceRootRequiresOpeningsAndTaskID(t *testing.T) {
	if _, err := BuildTaskEvidenceRoot(TaskEvidenceInput{}); err == nil {
		t.Fatalf("root builder accepted missing task id")
	}
	if _, err := BuildTaskEvidenceRoot(TaskEvidenceInput{TaskID: "task-1"}); err == nil {
		t.Fatalf("root builder accepted no evidence leaves")
	}
}
