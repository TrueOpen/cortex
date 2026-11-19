package builderclient

import (
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const anchorVectorOperator = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"

func anchorManifestKey() TaskDataKey {
	return EvidenceObjectKey(strings.Repeat("22", 32), strings.Repeat("33", 32), strings.Repeat("11", 32), DataKindEvidenceManifest,
		strings.Repeat("44", 32), EvidenceProducerWorker, 1, anchorVectorOperator, nodewire.EvidenceKindWorkerAnchorOpening)
}

// The task-data body digests of a WORKER_ANCHOR_OPENING object are the ones
// Nexus computes (internal/taskdata) for the same ref; the TypeScript SDK pins
// the same values (test/unit/task-data-signbytes.test.ts).
func TestTaskDataBodyDigestsForTheAnchorKindMatchNexus(t *testing.T) {
	key := anchorManifestKey()
	metadata, err := TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	fetch, err := TaskDataFetchBodyDigest(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	fetchRange, err := TaskDataFetchBodyDigest(key, &TaskDataRange{Offset: 0, Length: 64})
	if err != nil {
		t.Fatal(err)
	}
	upload, err := TaskDataUploadBodyDigest(key, 1234, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := finalizeScope(key.TaskHash, key.SessionID, key.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	var receipt, signature codec.Hash
	for i := range receipt {
		receipt[i], signature[i] = 0x55, 0x66
	}
	finalize, err := taskDataFinalizeResultDigest(scope, receipt, signature, nodewire.EvidenceKindWorkerAnchorOpening)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]codec.Hash{"metadata": metadata, "fetch": fetch, "fetch_range": fetchRange, "upload": upload, "finalize": finalize} {
		want := map[string]string{
			"metadata":    "1f4fc8a0975ab3f34dbc37eccf7a3366c9616197c0a4d6a1c679d2999902d6fa",
			"fetch":       "0c3349e2ea0565f4bc1be24d59f5d36f9231751e657abc9a185c954571a8fd6a",
			"fetch_range": "3c3a86a16e135f66fb2444aaf420bcd55ee6b66e1c5bf29613b44d9cdb38a281",
			"upload":      "6715810e97e4dbd08d2ff8c8b2f9cea5bd775c4f9e53e9b7cdbffb53743cbe62",
			"finalize":    "55a78cec8b1e3e33e8f623669f4bd096dc08b442b274d7359872b4c52c35afdc",
		}[name]
		if got.String() != want {
			t.Errorf("%s body digest %s, want Nexus's %s", name, got, want)
		}
	}
}

func TestTaskDataAnchorKindStaysAWorkerKind(t *testing.T) {
	key := anchorManifestKey()
	key.EvidenceProducerKind = EvidenceProducerVerifier
	if _, err := TaskDataMetadataBodyDigest(key); err == nil {
		t.Fatal("a Verifier object of kind WORKER_ANCHOR_OPENING was framed")
	}
}

func TestWorkerEvidenceRequirementsAdmitTheAnchorThird(t *testing.T) {
	two := WorkerEvidenceRequirementsV3()
	three := append(WorkerEvidenceRequirementsV3(), WorkerAnchorEvidenceRequirementV1())
	if err := ValidateWorkerEvidenceRequirementsV3(two); err != nil || ProfileRequiresAnchorOpening(two) {
		t.Fatalf("two requirements: %v, anchor=%t", err, ProfileRequiresAnchorOpening(two))
	}
	if err := ValidateWorkerEvidenceRequirementsV3(three); err != nil || !ProfileRequiresAnchorOpening(three) {
		t.Fatalf("three requirements: %v, anchor=%t", err, ProfileRequiresAnchorOpening(three))
	}
	reversed := []InferEvidenceRequirement{three[0], three[2], three[1]}
	if err := ValidateWorkerEvidenceRequirementsV3(reversed); err == nil {
		t.Fatal("the anchor requirement before the token requirement was accepted")
	}
}

func TestWorkerAnchorEvidenceConfirmation(t *testing.T) {
	anchor := []byte(`{"request_id":"cmpl-1"}`)
	facts := WorkerEvidenceFacts{
		ChainID: "chain-A", TaskID: strings.Repeat("11", 32), AcceptedTaskHash: strings.Repeat("22", 32),
		WorkerOperatorAddress: anchorVectorOperator, EvidenceSchemaHash: strings.Repeat("33", 32),
		AnchorCommitHash: codec.HashBytes(anchor), AnchorCommitSizeBytes: uint64(len(anchor)),
	}
	committed, err := WorkerAnchorEvidenceCommitment(facts)
	if err != nil {
		t.Fatal(err)
	}
	if committed.EvidenceKind != nodewire.EvidenceKindWorkerAnchorOpening || committed.EncodedSizeBytes != uint64(len(anchor)) {
		t.Fatalf("commitment %+v", committed)
	}
	if err := ConfirmWorkerAnchorEvidence(facts, committed); err != nil {
		t.Fatal(err)
	}
	tampered := facts
	tampered.AnchorCommitHash = codec.HashBytes([]byte("other"))
	if err := ConfirmWorkerAnchorEvidence(tampered, committed); err == nil {
		t.Fatal("other anchor bytes confirmed the commitment")
	}
	unhashed := facts
	unhashed.AnchorCommitHash = codec.Hash{}
	if _, err := WorkerAnchorEvidenceCommitment(unhashed); err == nil {
		t.Fatal("an unhashed anchor artifact was committed")
	}
}
