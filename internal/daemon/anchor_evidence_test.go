package daemon

import (
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// withAnchorCommitment appends an ADR-0040 WORKER_ANCHOR_OPENING commitment to
// the fixture's receipt and re-signs it, as a Worker under a Profile that
// requires kind 5 would.
func withAnchorCommitment(t *testing.T, f *evidenceFixture) {
	t.Helper()
	r := f.Commitments.Receipt
	anchor := []byte(`{"request_id":"cmpl-1","roots":[]}`)
	commitment, err := builderclient.WorkerAnchorEvidenceCommitment(builderclient.WorkerEvidenceFacts{
		ChainID: r.ChainID, TaskID: r.TaskID, AcceptedTaskHash: r.TaskHash, WorkerOperatorAddress: r.WorkerOperatorAddress,
		GenerationParamsDigest: r.GenerationParamsDigest, EvidenceSchemaHash: f.Commitments.EvidenceSchemaHash,
		AnchorCommitHash: codec.HashBytes(anchor), AnchorCommitSizeBytes: uint64(len(anchor)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.RequiredEvidenceCommitments = append(f.Commitments.Receipt.RequiredEvidenceCommitments, commitment)
	f.Commitments.MaxEncodedSizeBytes[nodewire.EvidenceKindWorkerAnchorOpening] = 1 << 20
	f.sign(t)
}

// The Verifier's PREFILL path confirms the token and value bundles of a
// three-commitment receipt without ever asking a Builder for the anchor
// bundle: anchors are judged by chain validators, not by Cortex Verifiers.
func TestNexusEvidenceConfirmerIgnoresAnchorBundle(t *testing.T) {
	f := newEvidenceFixture(t)
	withAnchorCommitment(t, &f)
	// No kind 5 object is served at all: a fetch of it would fail the test.
	client := &evidenceTaskDataClient{objects: f.objects()}
	result, err := confirmBothBundles(newEvidenceConfirmer(t, client), f.Commitments)
	if err != nil {
		t.Fatalf("three-commitment receipt: %v", err)
	}
	if result.FinishReason != f.FinishReason {
		t.Fatalf("finish reason %v, want %v", result.FinishReason, f.FinishReason)
	}
	if len(client.metadataRequests) != 6 || len(client.fetches) != 6 {
		t.Fatalf("manifest/artifact requests=%d/%d, want the 6 of the value and token bundles", len(client.metadataRequests), len(client.fetches))
	}
	for _, request := range client.metadataRequests {
		if request.Key.EvidenceKind == nodewire.EvidenceKindWorkerAnchorOpening {
			t.Fatal("the Verifier asked for the anchor bundle")
		}
	}
}

func TestNexusEvidenceConfirmerRefusesMisplacedThirdCommitment(t *testing.T) {
	f := newEvidenceFixture(t)
	withAnchorCommitment(t, &f)
	// Not re-signed: no canonical receipt can carry this order, so the digest
	// itself refuses it.
	f.Commitments.Receipt.RequiredEvidenceCommitments[2].EvidenceKind = nodewire.EvidenceKindVerifierValueOpening
	client := &evidenceTaskDataClient{objects: f.objects()}
	if _, err := newEvidenceConfirmer(t, client).ConfirmWorkerTokenEvidence(t.Context(), f.Commitments); err == nil {
		t.Fatal("a third commitment other than WORKER_ANCHOR_OPENING was accepted")
	}
	if len(client.metadataRequests) != 0 {
		t.Fatal("a malformed receipt reached the Builder")
	}
}

// A two-commitment receipt is unaffected by the anchor support.
func TestNexusEvidenceConfirmerTwoCommitmentReceiptUnchanged(t *testing.T) {
	f := newEvidenceFixture(t)
	if n := len(f.Commitments.Receipt.RequiredEvidenceCommitments); n != 2 {
		t.Fatalf("fixture receipt has %d commitments", n)
	}
	client := &evidenceTaskDataClient{objects: f.objects()}
	if _, err := confirmBothBundles(newEvidenceConfirmer(t, client), f.Commitments); err != nil {
		t.Fatal(err)
	}
}

func TestInferReceiptRescueCarriesAnchorCommitment(t *testing.T) {
	f := newEvidenceFixture(t)
	withAnchorCommitment(t, &f)
	msg, err := inferReceiptRescueMessage(f.Commitments.Receipt, "trueopen1submitter")
	if err != nil {
		t.Fatal(err)
	}
	got := msg.Receipt.RequiredEvidenceCommitments
	if len(got) != 3 || got[0].EvidenceKind != txclient.EvidenceKindWorkerValueOpening || got[1].EvidenceKind != txclient.EvidenceKindWorkerTokenOpening ||
		got[2].EvidenceKind != txclient.EvidenceKindWorkerAnchorOpening {
		t.Fatalf("rescued commitments %+v", got)
	}
	f2 := newEvidenceFixture(t)
	msg, err = inferReceiptRescueMessage(f2.Commitments.Receipt, "trueopen1submitter")
	if err != nil || len(msg.Receipt.RequiredEvidenceCommitments) != 2 {
		t.Fatalf("two-commitment rescue: %v %d", err, len(msg.Receipt.RequiredEvidenceCommitments))
	}
}
