package builderclient

import (
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// TestConfirmWorkerValueEvidenceRecoversEveryFinishReason is the point of the
// search: the Verifier has no source for finish_reason, so every value the
// Worker could have committed must be reachable. If one were missing, tasks that
// ended that way would be unverifiable through no fault of the Worker.
func TestConfirmWorkerValueEvidenceRecoversEveryFinishReason(t *testing.T) {
	for _, reason := range nodewire.SuccessfulFinishReasonsV1() {
		facts := completeWorkerValueEvidenceFacts()
		facts.FinishReason = reason
		committed, err := WorkerValueEvidenceCommitment(facts)
		if err != nil {
			t.Fatalf("WorkerValueEvidenceCommitment: %v", err)
		}
		// The confirming side never sets FinishReason: it does not have it.
		verifierView := facts
		verifierView.FinishReason = nodewire.FinishReasonV1Unspecified
		got, err := ConfirmWorkerValueEvidence(verifierView, committed)
		if err != nil {
			t.Fatalf("finish reason %d: %v", reason, err)
		}
		if got != reason {
			t.Fatalf("recovered finish reason = %d, want %d", got, reason)
		}
	}
}

// TestConfirmWorkerValueEvidenceRefusesTamperedArtifacts is the check that makes
// the download worth doing. Every other fact about an evidence object is the
// Builder's own assertion; only reproducing the committed digest binds the bytes
// to something the chain settled on.
func TestConfirmWorkerValueEvidenceRefusesTamperedArtifacts(t *testing.T) {
	facts := completeWorkerValueEvidenceFacts()
	committed, err := WorkerValueEvidenceCommitment(facts)
	if err != nil {
		t.Fatal(err)
	}
	// One flipped byte in the served trace changes its root, and no finish reason
	// recovers the commitment from it.
	tamperedTrace := []byte("trace")
	tamperedTrace[0] ^= 0x01

	refusals := map[string]func(*WorkerValueEvidenceFacts){
		"a single byte flipped in the trace": func(f *WorkerValueEvidenceFacts) {
			f.TraceRoot = codec.HashBytes(tamperedTrace)
		},
		"a different checkpoint": func(f *WorkerValueEvidenceFacts) {
			f.CheckpointRoot = codec.HashBytes([]byte("other checkpoint"))
		},
		"the two artifacts swapped": func(f *WorkerValueEvidenceFacts) {
			f.TraceRoot, f.CheckpointRoot = f.CheckpointRoot, f.TraceRoot
		},
		"the sizes swapped": func(f *WorkerValueEvidenceFacts) {
			f.TraceEncodedSizeBytes, f.CheckpointEncodedSizeBytes =
				f.CheckpointEncodedSizeBytes, f.TraceEncodedSizeBytes
		},
		"a different locked profile evidence schema": func(f *WorkerValueEvidenceFacts) {
			f.EvidenceSchemaHash = strings.Repeat("aa", 32)
		},
		"a different accepted task hash": func(f *WorkerValueEvidenceFacts) {
			f.AcceptedTaskHash = strings.Repeat("bb", 32)
		},
	}
	for name, mutate := range refusals {
		t.Run(name, func(t *testing.T) {
			changed := completeWorkerValueEvidenceFacts()
			changed.FinishReason = nodewire.FinishReasonV1Unspecified
			mutate(&changed)
			if _, err := ConfirmWorkerValueEvidence(changed, committed); err == nil {
				t.Fatalf("%s was confirmed", name)
			}
		})
	}
	// The size sum is not inside the digest, so it is compared separately: a
	// commitment whose encoded_size_bytes disagrees is refused even though the
	// digest reproduces.
	wrongSize := committed
	wrongSize.EncodedSizeBytes++
	verifierView := facts
	verifierView.FinishReason = nodewire.FinishReasonV1Unspecified
	if _, err := ConfirmWorkerValueEvidence(verifierView, wrongSize); err == nil {
		t.Fatal("a commitment with a disagreeing encoded_size_bytes was confirmed")
	}
}

func TestConfirmWorkerValueEvidenceRefusesUnusableCommitments(t *testing.T) {
	facts := completeWorkerValueEvidenceFacts()
	facts.FinishReason = nodewire.FinishReasonV1Unspecified
	good, err := WorkerValueEvidenceCommitment(completeWorkerValueEvidenceFacts())
	if err != nil {
		t.Fatal(err)
	}
	refusals := map[string]EvidenceCommitment{
		"wrong evidence kind": func() EvidenceCommitment {
			v := good
			v.EvidenceKind = nodewire.EvidenceKindVerifierValueOpening
			return v
		}(),
		"unspecified evidence kind": func() EvidenceCommitment {
			v := good
			v.EvidenceKind = nodewire.EvidenceKindUnspecified
			return v
		}(),
		"all-zero committed root": func() EvidenceCommitment {
			v := good
			v.EvidenceHashOrRoot = codec.Hash{}
			return v
		}(),
	}
	for name, committed := range refusals {
		t.Run(name, func(t *testing.T) {
			if _, err := ConfirmWorkerValueEvidence(facts, committed); err == nil {
				t.Fatalf("%s was confirmed", name)
			}
		})
	}
}
