package nodewire

import (
	"bytes"
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

// The digest is the one Nexus computes (nodecontract.WorkerAnchorCommitmentV1)
// for the same inputs, and the one the chain stores as the receipt's kind 5
// evidence_hash_or_root.
func TestWorkerAnchorCommitmentV1DigestMatchesNexus(t *testing.T) {
	digest, size, err := WorkerAnchorCommitmentV1Digest(anchorVectorInput())
	if err != nil {
		t.Fatal(err)
	}
	const nexusVector = "55c179b8d51b00fa00e8126d8c4d65a8ead6b99d2ed37ff184395314482d80dc"
	if digest.String() != nexusVector || size != 1234 {
		t.Fatalf("digest %s size %d, want %s 1234", digest, size, nexusVector)
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
