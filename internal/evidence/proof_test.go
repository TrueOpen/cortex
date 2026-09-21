package evidence

import (
	"context"
	"errors"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
)

func TestProofMaterialRequiresRawEvidenceAndRejectsDuplicateFaultID(t *testing.T) {
	store := NewProofStore()
	if _, err := store.Generate(context.Background(), ProofRequest{
		FaultID: "fault-1",
		Kind:    ProofOutputHashMismatch,
		TaskID:  "task-1",
	}); !errors.Is(err, ErrRawEvidenceMissing) {
		t.Fatalf("generate without raw evidence error = %v, want ErrRawEvidenceMissing", err)
	}

	if err := store.StoreRawEvidence(context.Background(), RawEvidence{
		FaultID: "fault-1",
		TaskID:  "task-1",
		Kind:    "output-package",
		Data:    []byte("raw evidence"),
	}); err != nil {
		t.Fatalf("store raw evidence: %v", err)
	}
	material, err := store.Generate(context.Background(), ProofRequest{
		FaultID: "fault-1",
		Kind:    ProofOutputHashMismatch,
		TaskID:  "task-1",
	})
	if err != nil {
		t.Fatalf("generate proof material: %v", err)
	}
	if len(material.EvidencePayload) == 0 || material.RawEvidenceRef == "" || material.EvidenceDigest == (codec.Hash{}) {
		t.Fatalf("proof material = %#v", material)
	}
	if _, err := store.Generate(context.Background(), ProofRequest{
		FaultID: "fault-1",
		Kind:    ProofOutputHashMismatch,
		TaskID:  "task-1",
	}); !errors.Is(err, ErrDuplicateFaultID) {
		t.Fatalf("duplicate proof error = %v, want ErrDuplicateFaultID", err)
	}
}

func TestRawEvidenceRejectsDuplicateFaultIDBeforeProofGeneration(t *testing.T) {
	store := NewProofStore()
	raw := RawEvidence{
		FaultID: "fault-duplicate",
		TaskID:  "task-1",
		Kind:    "output-package",
		Data:    []byte("first raw evidence"),
	}
	if err := store.StoreRawEvidence(context.Background(), raw); err != nil {
		t.Fatalf("store first raw evidence: %v", err)
	}
	raw.Data = []byte("replacement raw evidence")
	if err := store.StoreRawEvidence(context.Background(), raw); !errors.Is(err, ErrDuplicateFaultID) {
		t.Fatalf("store duplicate raw evidence error = %v, want ErrDuplicateFaultID", err)
	}
}

// TestProofKindsCarryNoChainMessage pins that local fault proof material never
// names a chain message. The frozen task.v1.Msg service registers no fault
// or fraud proof entry point, so an unknown proof kind must be refused and a
// known one must produce evidence with no tx type URL at all.
func TestProofKindsCarryNoChainMessage(t *testing.T) {
	store := NewProofStore()
	kinds := []ProofKind{
		ProofOutputHashMismatch, ProofReceiptDeliveryMismatch, ProofCommitRevealMismatch,
		ProofPayloadMismatch, ProofWorkUnitMismatch, ProofCommitDoubleSign, ProofVerdictFraud,
	}

	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			fault := "fault-" + string(kind)
			if err := store.StoreRawEvidence(context.Background(), RawEvidence{
				FaultID: fault,
				TaskID:  "task-1",
				Kind:    string(kind),
				Data:    []byte("raw-" + fault),
			}); err != nil {
				t.Fatalf("store raw evidence: %v", err)
			}
			material, err := store.Generate(context.Background(), ProofRequest{
				FaultID: fault,
				Kind:    kind,
				TaskID:  "task-1",
			})
			if err != nil {
				t.Fatalf("generate proof: %v", err)
			}
			if material.Kind != kind || material.EvidenceDigest == (codec.Hash{}) {
				t.Fatalf("proof material = %#v", material)
			}
		})
	}

	if err := store.StoreRawEvidence(context.Background(), RawEvidence{
		FaultID: "fault-unknown", TaskID: "task-1", Kind: "unknown", Data: []byte("raw"),
	}); err != nil {
		t.Fatalf("store raw evidence: %v", err)
	}
	if _, err := store.Generate(context.Background(), ProofRequest{
		FaultID: "fault-unknown", Kind: ProofKind("challenge_commit_fraud"), TaskID: "task-1",
	}); err == nil {
		t.Fatal("Generate accepted an unregistered proof kind")
	}
}

func TestProofEvidenceRecorderStoresEvidenceWithoutTxBoundary(t *testing.T) {
	store := NewProofStore()
	recorder := NewProofEvidenceRecorder(store)

	result, err := recorder.Record(context.Background(), RecordProofEvidenceRequest{
		FaultID: "fault-submit", TaskID: "task-1", Kind: ProofPayloadMismatch,
		RawKind: "payload-pair", RawEvidence: []byte("raw payload mismatch evidence"),
	})
	if err != nil {
		t.Fatalf("record proof evidence: %v", err)
	}

	if result.Material.Kind != ProofPayloadMismatch || result.Material.RawEvidenceRef == "" {
		t.Fatalf("proof material = %#v", result.Material)
	}
	if got, ok := store.RawEvidence("fault-submit"); !ok || got.Kind != "payload-pair" || string(got.Data) != "raw payload mismatch evidence" {
		t.Fatalf("raw evidence = %#v ok=%v, want stored before submit", got, ok)
	}
}
