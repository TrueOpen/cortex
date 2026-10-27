package evidence

import (
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
