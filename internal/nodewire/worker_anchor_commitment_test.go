package nodewire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func anchorVectorInput() WorkerAnchorCommitmentV1 {
	return WorkerAnchorCommitmentV1{
		SchemaVersion: WorkerAnchorCommitmentSchemaVersionV1, ChainID: "trueopen-devnet-1",
		TaskID: bytes.Repeat([]byte{0x11}, 32), AcceptedTaskHash: bytes.Repeat([]byte{0x22}, 32),
		WorkerOperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe", EvidenceSchemaHash: bytes.Repeat([]byte{0x33}, 32),
		AnchorCommitHash: bytes.Repeat([]byte{0x44}, 32), AnchorCommitSizeBytes: 1234,
	}
}

// workerAnchorCommitmentVectors is where the shared digest vectors are read
// from. It is this repository's copy until wire publishes the vector; the
// file names its own provenance.
const workerAnchorCommitmentVectors = "testdata/worker_anchor_commitment_v1.json"

type workerAnchorCommitmentVector struct {
	Name                  string `json:"name"`
	Source                string `json:"source"`
	SchemaVersion         uint32 `json:"schema_version"`
	ChainID               string `json:"chain_id"`
	TaskID                string `json:"task_id"`
	AcceptedTaskHash      string `json:"accepted_task_hash"`
	WorkerOperatorAddress string `json:"worker_operator_address"`
	EvidenceSchemaHash    string `json:"evidence_schema_hash"`
	AnchorCommitHash      string `json:"anchor_commit_hash"`
	AnchorCommitSizeBytes uint64 `json:"anchor_commit_size_bytes"`
	Digest                string `json:"digest"`
}

// The digest is the one the Builder computes for the same inputs
// (nexus internal/nodecontract.WorkerAnchorCommitmentV1.Digest), and the one
// the chain stores as the receipt's kind 5 evidence_hash_or_root. Every
// vector was produced outside this package; none is derived from the function
// under test.
func TestWorkerAnchorCommitmentV1DigestVectors(t *testing.T) {
	raw, err := os.ReadFile(workerAnchorCommitmentVectors)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Domain  string                         `json:"domain"`
		Vectors []workerAnchorCommitmentVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Domain != DomainWorkerAnchorCommitmentV1 || len(file.Vectors) < 2 {
		t.Fatalf("%s: domain %q with %d vectors", workerAnchorCommitmentVectors, file.Domain, len(file.Vectors))
	}
	unhex := func(t *testing.T, field, value string) []byte {
		t.Helper()
		out, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		return out
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Source == "" {
				t.Fatal("a vector must name where its digest came from")
			}
			digest, size, err := WorkerAnchorCommitmentV1Digest(WorkerAnchorCommitmentV1{
				SchemaVersion: v.SchemaVersion, ChainID: v.ChainID,
				TaskID: unhex(t, "task_id", v.TaskID), AcceptedTaskHash: unhex(t, "accepted_task_hash", v.AcceptedTaskHash),
				WorkerOperatorAddress: v.WorkerOperatorAddress, EvidenceSchemaHash: unhex(t, "evidence_schema_hash", v.EvidenceSchemaHash),
				AnchorCommitHash: unhex(t, "anchor_commit_hash", v.AnchorCommitHash), AnchorCommitSizeBytes: v.AnchorCommitSizeBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			if digest.String() != v.Digest || size != v.AnchorCommitSizeBytes {
				t.Fatalf("digest %s size %d, want %s %d", digest, size, v.Digest, v.AnchorCommitSizeBytes)
			}
		})
	}
}

func TestWorkerAnchorCommitmentV1DigestRefusesNonCanonicalInput(t *testing.T) {
	for name, mutate := range map[string]func(*WorkerAnchorCommitmentV1){
		"schema":       func(v *WorkerAnchorCommitmentV1) { v.SchemaVersion = 2 },
		"chain":        func(v *WorkerAnchorCommitmentV1) { v.ChainID = "" },
		"worker":       func(v *WorkerAnchorCommitmentV1) { v.WorkerOperatorAddress = "cosmos1xyz" },
		"short hash":   func(v *WorkerAnchorCommitmentV1) { v.AnchorCommitHash = v.AnchorCommitHash[:31] },
		"zero size":    func(v *WorkerAnchorCommitmentV1) { v.AnchorCommitSizeBytes = 0 },
		"over ceiling": func(v *WorkerAnchorCommitmentV1) { v.AnchorCommitSizeBytes = MaxEvidenceEncodedSizeBytesV1 + 1 },
	} {
		v := anchorVectorInput()
		mutate(&v)
		if _, _, err := WorkerAnchorCommitmentV1Digest(v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRequireWorkerEvidenceCommitmentsV3AcceptsTheAnchorThird(t *testing.T) {
	item := func(kind EvidenceKind) EvidenceCommitmentV1 {
		return EvidenceCommitmentV1{EvidenceKind: kind, EvidenceHashOrRoot: bytes.Repeat([]byte{1}, 32), EncodedSizeBytes: 1}
	}
	value, token, anchor := item(EvidenceKindWorkerValueOpening), item(EvidenceKindWorkerTokenOpening), item(EvidenceKindWorkerAnchorOpening)
	if err := RequireWorkerEvidenceCommitmentsV3([]EvidenceCommitmentV1{value, token}); err != nil {
		t.Fatalf("two commitments: %v", err)
	}
	if err := RequireWorkerEvidenceCommitmentsV3([]EvidenceCommitmentV1{value, token, anchor}); err != nil {
		t.Fatalf("three commitments: %v", err)
	}
	for name, items := range map[string][]EvidenceCommitmentV1{
		"anchor first": {anchor, value, token},
		"anchor only":  {anchor},
		"anchor twice": {value, token, anchor, anchor},
		"token third":  {value, anchor, token},
	} {
		if err := RequireWorkerEvidenceCommitmentsV3(items); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
