package verifier

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/modelservice"
)

// TestConfirmedWorkerValueEvidenceReplacesTheRefFetch is the real-chain path.
// TraceRef and CheckpointRef are Worker-local model-service addresses no wire
// carries, so a selected Verifier on a real chain gets them empty; the confirmed
// pair is what it verifies against instead, and the model service must not be
// asked for an artifact at all.
func TestConfirmedWorkerValueEvidenceReplacesTheRefFetch(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	// Exactly what NexusOutputConfirmer/NexusEvidenceConfirmer produce on a real
	// chain: bytes, and no refs to address them by.
	state.ConfirmedOutput = []byte("worker output")
	state.ConfirmedTrace = []byte("trace material")
	state.ConfirmedCheckpoint = []byte("checkpoint material")
	state.OutputPackage.OutputRef = ""
	state.OutputPackage.TraceRef = ""
	state.OutputPackage.CheckpointRef = ""
	// FromTaskData is what tells the L2 precheck to judge output_hash alone; the
	// refs and the package hash have no chain source on that path.
	state.OutputPackage.FromTaskData = true

	result := verifyLocally(t, h, state)

	if !result.Started {
		t.Fatal("verification did not run on the confirmed evidence")
	}
	// The model service is asked for the sample value sequence the verification
	// itself produced, and for nothing else: no artifact is fetched under an
	// evidence or worker-output kind, because all three arrived confirmed.
	for _, kind := range h.model.fetchedKinds {
		if kind == modelservice.EvidenceKindWorkerValueOpening || kind == "worker-output" {
			t.Fatalf("model artifact fetch kinds = %v, want no artifact fetched by ref", h.model.fetchedKinds)
		}
	}
}

// TestEmptyArtifactRefsWithoutConfirmedEvidenceIsRefused pins the failure this
// whole change exists to remove -- and pins that it is still a failure rather
// than something silently skipped. Before the evidence data plane existed, a
// real-chain Verifier reached exactly this state and retried "empty ref" every
// 30 seconds until the commit deadline passed.
func TestEmptyArtifactRefsWithoutConfirmedEvidenceIsRefused(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.ConfirmedOutput = []byte("worker output")
	state.OutputPackage.TraceRef = ""
	state.OutputPackage.CheckpointRef = ""

	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err == nil {
		t.Fatal("verification ran with neither confirmed evidence nor resolvable refs")
	}
}

// TestHalfConfirmedWorkerValueEvidenceIsRefused keeps the pair atomic. The
// WORKER_VALUE_OPENING commitment is one digest over BOTH roots, so one
// confirmed artifact beside one fetched by ref would mix a chain-bound value
// with an unbound one under a commitment that covers both.
func TestHalfConfirmedWorkerValueEvidenceIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*TaskState){
		"trace only": func(s *TaskState) {
			s.ConfirmedTrace = []byte("trace material")
		},
		"checkpoint only": func(s *TaskState) {
			s.ConfirmedCheckpoint = []byte("checkpoint material")
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			state := h.validTask()
			state.OpenVerifyAccepted = true
			state.ConfirmedOutput = []byte("worker output")
			mutate(&state)

			_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
			if err == nil {
				t.Fatal("half-confirmed evidence was accepted")
			}
			if !strings.Contains(err.Error(), "confirmed worker value evidence is incomplete") {
				t.Fatalf("error = %v, want the incomplete-pair refusal", err)
			}
		})
	}
}
