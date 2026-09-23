package daemon

import (
	"context"
	"slices"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// task.v1.EventVerifierAssignmentFinalized is the only event the chain
// emits when the selected Verifier set is decided: it is written in EndBlock
// alongside selection_randomness_height / selection_randomness_beacon, and
// EventVerificationSampleSeedReady is never emitted at all. Classifying it as a
// projection therefore left ReconcilerEffectVerifyReady - the only writer of a
// local verify record - with no producer, so a node the chain had selected did
// nothing, missed commit_deadline and was jailed for it. Measured on
// trueopen-localnet-1: assignment finalized at h=64277 with three selected
// verifiers, zero commits and zero reveals, three EventRoleJailed at h=64302.
func TestReconcilerAdmitsVerifyResponsibilityFromVerifierAssignmentFinalized(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-verifier-assigned"))
	snapshot := verifierAssignedTaskSnapshot("session-1", "task-verifier-assigned", hash, "verifier-1", "verifier-2", "verifier-3")
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})

	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventOpenVerifyAccepted, TaskID: "task-verifier-assigned", SessionID: "session-1",
		Verifier: "verifier-3", Height: 64277,
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 {
		t.Fatalf("effects = %#v, want one verify-ready effect", effects)
	}
	if effects[0].Type != ReconcilerEffectVerifyReady || effects[0].TaskHash != hash {
		t.Fatalf("effect = %#v, want %s keyed by the accepted task hash", effects[0], ReconcilerEffectVerifyReady)
	}
	if !slices.Contains([]string(effects[0].Snapshot.VerifierAssignment.FormalVerifierSet), "verifier-3") {
		t.Fatalf("effect verifier set = %v, want the Keeper selected set", effects[0].Snapshot.VerifierAssignment.FormalVerifierSet)
	}
}

func verifierAssignedTaskSnapshot(sessionID, taskID string, acceptedTaskHash codec.Hash, verifiers ...string) chainclient.TaskSnapshot {
	snapshot := validTaskSnapshot(sessionID, taskID, acceptedTaskHash)
	snapshot.CurrentContract = true
	snapshot.InferReceipt = chainclient.InferReceiptSnapshot{
		SessionID: sessionID, TaskID: taskID, WinnerWorker: snapshot.Assignment.SelectedWorker,
		OutputHash:       chainclient.HexHash(codec.HashWithDomain("TEST_OUTPUT", []byte(taskID))),
		InferReceiptHash: chainclient.HexHash(codec.HashWithDomain("TEST_RECEIPT", []byte(taskID))),
		ReceiptHeight:    chainclient.NewUint64String(64260),
	}
	snapshot.VerifierAssignment = chainclient.VerifierAssignmentSnapshot{VerifyRound: chainclient.NewUint64String(1),
		SessionID: sessionID, TaskID: taskID,
		OpenVerifyHeight:       chainclient.NewUint64String(64265),
		FormalVerifierSet:      chainclient.CSVStrings(verifiers),
		SampleSeedReadyHeight:  chainclient.NewUint64String(64277),
		VerificationSampleSeed: chainclient.HexHash(codec.HashWithDomain("TEST_SEED", []byte(taskID))),
		CommitDeadlineHeight:   chainclient.NewUint64String(64285),
		VerifyDeadlineHeight:   chainclient.NewUint64String(64302),
		SampleSeedStatus:       "READY",
	}
	return snapshot
}
