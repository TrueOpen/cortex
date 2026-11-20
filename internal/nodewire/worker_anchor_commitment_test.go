package nodewire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func anchorVectorInput() WorkerAnchorCommitmentV1 {
	return WorkerAnchorCommitmentV1{
		SchemaVersion: WorkerAnchorCommitmentSchemaVersionV1, ChainID: "trueopen-devnet-1",
		TaskID: bytes.Repeat([]byte{0x11}, 32), AcceptedTaskHash: bytes.Repeat([]byte{0x22}, 32),
		WorkerOperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe", EvidenceSchemaHash: bytes.Repeat([]byte{0x33}, 32),
		AnchorCommitHash: bytes.Repeat([]byte{0x44}, 32), AnchorCommitSizeBytes: 1234,
	}
}

// workerAnchorCommitmentVectors is the shared digest vector wire publishes
// for TRUEOPEN_WORKER_ANCHOR_COMMITMENT_V1, read through wirevectors so its
// bytes are checked against wire's release manifest.
const workerAnchorCommitmentVectors = "task/worker_anchor_commitment_v1.json"

type workerAnchorCommitmentField struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	Value  *uint64 `json:"value"`
	UTF8   string  `json:"utf8"`
	Hex    string  `json:"hex"`
	Bech32 string  `json:"bech32"`
}

type workerAnchorCommitmentVector struct {
	Name                     string                        `json:"name"`
	Domain                   string                        `json:"domain"`
	Framing                  string                        `json:"framing"`
	Fields                   []workerAnchorCommitmentField `json:"fields"`
	ExpectedEncodedSizeBytes uint64                        `json:"expected_encoded_size_bytes"`
	DigestHex                string                        `json:"digest_hex"`
}

// The digest is the one the Builder computes for the same inputs and the one
// the chain stores as the receipt's kind 5 evidence_hash_or_root. The vector is
// wire's; none is derived from the function under test.
func TestWorkerAnchorCommitmentV1DigestVectors(t *testing.T) {
	raw, err := wirevectors.File(workerAnchorCommitmentVectors)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []workerAnchorCommitmentVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatalf("wire %s publishes no %s vector", wirevectors.WireVersion, workerAnchorCommitmentVectors)
	}
	// The eight fields in schema order; the published order is the framing
	// order, so a reordering upstream fails here rather than hashing.
	order := []string{"schema_version", "chain_id", "task_id", "accepted_task_hash",
		"worker_operator_address", "evidence_schema_hash", "anchor_commit_hash", "anchor_commit_size_bytes"}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Domain != DomainWorkerAnchorCommitmentV1 || v.Framing != "H_FIELDS_V1" || len(v.Fields) != len(order) {
				t.Fatalf("domain %q framing %q with %d fields, want an eight-field H_FIELDS_V1 %s vector",
					v.Domain, v.Framing, len(v.Fields), DomainWorkerAnchorCommitmentV1)
			}
			for i, name := range order {
				if v.Fields[i].Name != name {
					t.Fatalf("field %d is %q, want %q", i, v.Fields[i].Name, name)
				}
			}
			unhex := func(i int) []byte {
				t.Helper()
				out, err := hex.DecodeString(v.Fields[i].Hex)
				if err != nil {
					t.Fatalf("%s: %v", order[i], err)
				}
				return out
			}
			u64 := func(i int) uint64 {
				t.Helper()
				if v.Fields[i].Value == nil {
					t.Fatalf("%s publishes no value", order[i])
				}
				return *v.Fields[i].Value
			}
			digest, size, err := WorkerAnchorCommitmentV1Digest(WorkerAnchorCommitmentV1{
				SchemaVersion: uint32(u64(0)), ChainID: v.Fields[1].UTF8,
				TaskID: unhex(2), AcceptedTaskHash: unhex(3),
				WorkerOperatorAddress: v.Fields[4].Bech32, EvidenceSchemaHash: unhex(5),
				AnchorCommitHash: unhex(6), AnchorCommitSizeBytes: u64(7),
			})
			if err != nil {
				t.Fatal(err)
			}
			if digest.String() != v.DigestHex || size != v.ExpectedEncodedSizeBytes {
				t.Fatalf("digest %s size %d, want %s %d", digest, size, v.DigestHex, v.ExpectedEncodedSizeBytes)
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
