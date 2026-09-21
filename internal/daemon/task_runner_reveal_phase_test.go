package daemon

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/identity"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
	"github.com/SingaXYZ/cortex/internal/verifier"
)

const revealPhaseTaskID = "task-reveal-phase"

// revealPhaseSnapshot is the Keeper view AFTER StartRevealPhase ran: the
// verifier assignment now carries a reveal_deadline_height, which keeper §10.7
// writes exactly once, in that transition. Before it the same snapshot reports
// zero there, which is why revealPhaseSnapshotBeforeStart exists.
func revealPhaseSnapshot(acceptedTaskHash codec.Hash, revealDeadline uint64) chainclient.TaskSnapshot {
	snapshot := verifierAssignedTaskSnapshot("session-1", revealPhaseTaskID, acceptedTaskHash, "verifier-1")
	snapshot.VerifierAssignment.RevealDeadlineHeight = chainclient.NewUint64String(revealDeadline)
	return snapshot
}

// TestRevealPhaseStartedProducesAnEffectCarryingTheKeeperRevealDeadline is FR1
// and AC1 at the reconciler boundary.
//
// EventRevealPhaseStarted used to be classified projection-only, so it produced
// nothing: the one event that carries the reveal deadline was observed and
// dropped, and internal/verifier's fail-closed refusal of a zero expiry_height
// could never be satisfied. This is the same shape PR #337 gave
// EventVerifierAssignmentFinalized.
func TestRevealPhaseStartedProducesAnEffectCarryingTheKeeperRevealDeadline(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte(revealPhaseTaskID))
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: revealPhaseSnapshot(hash, 64291)}})

	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventRevealPhaseStarted, TaskID: revealPhaseTaskID, SessionID: "session-1",
		Height: 64288, Attributes: map[string]string{"reveal_deadline_height": "64291"},
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 {
		t.Fatalf("effects = %#v, want one reveal-ready effect", effects)
	}
	if effects[0].Type != ReconcilerEffectRevealReady || effects[0].TaskHash != hash {
		t.Fatalf("effect = %#v, want %s keyed by the accepted task hash", effects[0], ReconcilerEffectRevealReady)
	}
	if got := effects[0].Snapshot.VerifierAssignment.RevealDeadlineHeight.Uint64(); got != 64291 {
		t.Fatalf("effect reveal deadline = %d, want the Keeper value 64291", got)
	}
}

// TestRevealPhaseStartedRefusesADeadlineTheKeeperDoesNotConfirm keeps the event
// a carrier rather than an authority. expiry_height is a frozen preimage field
// the Keeper compares, so a reveal signed against an announced height the chain
// state does not hold is a rejected transaction, not a degraded one.
func TestRevealPhaseStartedRefusesADeadlineTheKeeperDoesNotConfirm(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte(revealPhaseTaskID))
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{snapshot: revealPhaseSnapshot(hash, 64291)},
		OnQuarantinedEvent: func(e chainclient.KeeperEvent) { quarantined = append(quarantined, e) },
	})

	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventRevealPhaseStarted, TaskID: revealPhaseTaskID, SessionID: "session-1",
		Height: 64288, Attributes: map[string]string{"reveal_deadline_height": "99999"},
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none: the announced deadline disagrees with Keeper", effects)
	}
	if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, "does not match event reveal deadline") {
		t.Fatalf("quarantined = %#v, want the mismatch reported", quarantined)
	}
}

// TestRevealPhaseStartedWaitsForALaggingSnapshotRatherThanQuarantining is the
// other side of that check. keeper §10.7 writes reveal_deadline_height inside
// the very transition this event announces, so a snapshot still reporting zero
// is a read behind the event -- and quarantining it would throw away the only
// carrier of the value and block the reveal permanently. Retryable is the
// disposition that lets the next poll ask again.
func TestRevealPhaseStartedWaitsForALaggingSnapshotRatherThanQuarantining(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte(revealPhaseTaskID))
	lagging := verifierAssignedTaskSnapshot("session-1", revealPhaseTaskID, hash, "verifier-1")
	if lagging.VerifierAssignment.RevealDeadlineHeight.Uint64() != 0 {
		t.Fatal("the fixture already carries a reveal deadline; this test cannot show the lagging read")
	}
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{snapshot: lagging},
		OnQuarantinedEvent: func(e chainclient.KeeperEvent) { quarantined = append(quarantined, e) },
	})

	_, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventRevealPhaseStarted, TaskID: revealPhaseTaskID, SessionID: "session-1", Height: 64288,
	}})
	if err == nil || !chainclient.IsRetryable(err) {
		t.Fatalf("Apply() error = %v, want a retryable wait for the lagging Keeper read", err)
	}
	if len(quarantined) != 0 {
		t.Fatalf("quarantined = %#v, want the event kept rather than discarded", quarantined)
	}
}

// revealPhaseRunner seeds one verify responsibility for verifier-1 and returns a
// runner over it. stage and revealDeadline are the two values every case below
// varies.
func revealPhaseRunner(t *testing.T, stage layout.RoleStage, revealDeadline uint64, cfg TaskRunnerConfig) (*TaskRunner, *store.Store, codec.Hash) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hash := codec.HashBytes([]byte(revealPhaseTaskID))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: revealPhaseTaskID, SessionID: "session-1", OrderSequence: 1,
		VerifyRound: 1, OpenVerifyHeight: 313,
		CommitDeadlineHeight: 633, RevealDeadlineHeight: revealDeadline, DeadlineHeight: 1033,
		AssignedVerifiers: []string{"verifier-1"},
		Stage:             string(stage),
	})
	cfg.Store = db
	if cfg.MaxConcurrency == 0 {
		cfg.MaxConcurrency = 1
	}
	if cfg.MaxRetryAttempts == 0 {
		cfg.MaxRetryAttempts = 120
	}
	cfg.LocalVerifierAddress = "verifier-1"
	return NewTaskRunner(cfg), db, hash
}

// TestCommittedVerifyWaitsForTheRevealPhaseInsteadOfAttemptingIt is FR3/AC2.
//
// Task-04-Verification-flow.md admits MsgSubmitVerifyResult only after
// EventRevealPhaseStarted. A committed responsibility whose reveal deadline is
// still zero has not reached that point, so the runner must not launch it: the
// attempt could only be refused on chain and retried, which is what burned the
// retry budget of every devnet round.
func TestCommittedVerifyWaitsForTheRevealPhaseInsteadOfAttemptingIt(t *testing.T) {
	ctx := context.Background()
	var ran int
	trace := &collectTrace{}
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 0, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 700},
		Trace:       trace.trace(),
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 0 {
		t.Fatalf("verify executor ran %d times, want 0 before the reveal phase opens", ran)
	}
	// Waiting is not failing. The responsibility stays live, because the event
	// that ends the wait has not arrived yet -- and marking it failed here is how
	// a reveal would be lost the moment the chain finally allowed it.
	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Stage != layout.StageCommitted {
		t.Fatalf("stage = %q, want the committed responsibility left waiting", rec.Stage)
	}
	line := trace.event(t, "verify_reveal_awaiting_phase")
	for _, want := range []string{`task="` + revealPhaseTaskID + `"`, "verify_round=1", "waits=1", "chain_height=700"} {
		if !strings.Contains(line, want) {
			t.Fatalf("verify_reveal_awaiting_phase = %q, want it to carry %s", line, want)
		}
	}
}

// TestRevealPhaseEffectRecordsTheDeadlineAndEndsTheWait is AC1 at the runner
// boundary: after the effect lands, reading the task's state shows a NON-ZERO
// reveal deadline, which is the value internal/verifier's expiry_height gate
// needs and could never see before.
func TestRevealPhaseEffectRecordsTheDeadlineAndEndsTheWait(t *testing.T) {
	ctx := context.Background()
	trace := &collectTrace{}
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 0, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 700},
		Trace:       trace.trace(),
	})
	snapshot := revealPhaseSnapshot(hash, 900)

	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		TaskHash: hash, TaskID: revealPhaseTaskID, Type: ReconcilerEffectRevealReady, Snapshot: snapshot,
		Event: chainclient.KeeperEvent{Type: chainclient.KeeperEventRevealPhaseStarted, Height: 640},
	}}); err != nil {
		t.Fatal(err)
	}
	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.RevealDeadlineHeight != 900 {
		t.Fatalf("reveal deadline = %d, want the Keeper value 900 recorded on the responsibility", rec.RevealDeadlineHeight)
	}
	if rec.Stage != layout.StageCommitted {
		t.Fatalf("stage = %q, want the effect to record the deadline without touching the stage", rec.Stage)
	}
	line := trace.event(t, "keeper_reveal_phase_started")
	for _, want := range []string{
		"reveal_deadline_height=900", "commit_deadline_height=633", `stage="committed"`, "chain_height=640",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("keeper_reveal_phase_started = %q, want it to carry %s", line, want)
		}
	}
}

// TestRevealPhaseEffectDoesNotInventAResponsibility keeps MergeVerify from
// writing a bare verify record for a task this node never verified. Every node
// on the chain sees this event; only the selected Verifiers owe a reveal.
func TestRevealPhaseEffectDoesNotInventAResponsibility(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	hash := codec.HashBytes([]byte("someone-elses-task"))
	runner := NewTaskRunner(TaskRunnerConfig{Store: db, LocalVerifierAddress: "verifier-1"})

	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		TaskHash: hash, TaskID: "someone-elses-task", Type: ReconcilerEffectRevealReady,
		Snapshot: revealPhaseSnapshot(hash, 900),
		Event:    chainclient.KeeperEvent{Type: chainclient.KeeperEventRevealPhaseStarted, Height: 640},
	}}); err != nil {
		t.Fatal(err)
	}
	if rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash)); err == nil && rec.TaskID != "" {
		t.Fatalf("verify record = %#v, want none: this node holds no verify responsibility for that task", rec)
	}
}

// TestRevealRunsOnceTheRevealDeadlineIsKnown closes the loop the two tests above
// open: deadline recorded, responsibility due, executor launched.
func TestRevealRunsOnceTheRevealDeadlineIsKnown(t *testing.T) {
	ctx := context.Background()
	var seen []store.VerifyTask
	runner, _, _ := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 700},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			seen = append(seen, task)
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("verify executor ran %d times, want 1 once the reveal phase is open", len(seen))
	}
	if seen[0].RevealDeadlineHeight != 900 || seen[0].Stage != string(layout.StageCommitted) {
		t.Fatalf("executor saw %#v, want the committed responsibility carrying the reveal deadline", seen[0])
	}
}

// TestCommittedVerifyOutlivesTheCommitDeadline is the scheduling half of the
// split, and it is not cosmetic: the reveal phase opens at or after the commit
// window closes, so a committed responsibility still bounded by
// commit_deadline_height would be stopped by the runner at exactly the moment
// its reveal became legal. Chain height 700 is past commit_deadline 633 and
// inside reveal_deadline 900.
func TestCommittedVerifyOutlivesTheCommitDeadline(t *testing.T) {
	ctx := context.Background()
	var ran int
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 700},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Fatalf("verify executor ran %d times, want 1: the commit deadline does not bound a reveal", ran)
	}
	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Stage != layout.StageSucceeded {
		t.Fatalf("stage = %q, want the reveal to have completed the responsibility", rec.Stage)
	}
}

// TestCommittedVerifyStopsAtTheRevealDeadline is the bound that replaces it. A
// reveal the Keeper will no longer accept is not worth attempting, and the
// deadline that stopped it has to be named as the reveal deadline: an operator
// reading "commit deadline 633" for a task whose commit landed would go looking
// for the wrong fault.
func TestCommittedVerifyStopsAtTheRevealDeadline(t *testing.T) {
	ctx := context.Background()
	var ran int
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 950},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 0 {
		t.Fatalf("verify executor ran %d times, want 0 past the reveal deadline", ran)
	}
	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Stage != layout.StageFailed || !strings.Contains(rec.LastError, "reveal deadline height 900") {
		t.Fatalf("record = %#v, want the stop attributed to the reveal deadline", rec)
	}
}

// TestRevealHalfSkipsOutputConfirmationTheModelAndTheCommitExit pins what the
// reveal half is allowed to touch.
//
// The verification already happened in the commit half and its evidence is on
// disk, so re-confirming the output would re-download it from the Builder once
// per retry for nothing — and the retries are guaranteed until the metric
// pipeline exists. The commit exit is skipped for a different reason: the reveal
// travels the bus as VERIFY_RESULT, so demanding a workload tx client here would
// fail a node closed for a route this half never takes.
func TestRevealHalfSkipsOutputConfirmationTheModelAndTheCommitExit(t *testing.T) {
	sessionID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	taskID := identity.TaskIDString(sessionID, 1)
	receiptHash := codec.HashBytes([]byte("accepted-infer-receipt"))
	confirmer := &recordingOutputConfirmer{pkg: builderclient.OutputPackage{TaskID: taskID}}
	executor := newProductionVerifyExecutor(TaskRunnerConfig{
		OutputConfirmer:      confirmer,
		LocalVerifierAddress: "verifier-1",
		ChainID:              "chain",
		TaskDataAuth:         taskRunnerTaskDataAuth(t),
		SignerAddress:        "service-1",
		// Deliberately no Model and no Tx: the reveal half must need neither.
		VerifierMemberReader: fixedVerifierMemberReader{snapshot: chainclient.VerifierCandidateMemberSnapshot{
			CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
				CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x11}, 32)),
				Slot:                    2, SlotVersion: 1, OperatorAddress: "verifier-1",
			},
			InferReceiptHash: chainclient.ProtoBytes32(receiptHash[:]), ExpiryHeight: 20,
		}},
	})
	task := store.VerifyTask{
		TaskID: taskID, SessionID: sessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("accepted-order")),
		ModelID:     "model-1", ProfileVersion: 1, Capability: "llm-text",
		WorkerAddress: "worker-1", BuilderOperatorAddress: "builder-1",
		InferReceiptDigest: receiptHash,
		VerifyRound:        1, OpenVerifyHeight: 10, CommitDeadlineHeight: 30,
		RevealDeadlineHeight: 60, DeadlineHeight: 80,
		AssignedVerifiers: []string{"verifier-1"},
		Stage:             string(layout.StageCommitted),
	}

	_, terminal, err := executor.RunVerify(context.Background(), codec.HashBytes([]byte("task-hash")), task)
	// The reveal reaches the frozen result body and stops at the one Keeper read
	// this fixture does not wire. Reaching THAT boundary is the assertion: every
	// step before it belongs to the commit half and was not repeated.
	if err == nil || !strings.Contains(err.Error(), "Keeper task facts reader") {
		t.Fatalf("RunVerify() error = %v, want the reveal to reach the frozen result body", err)
	}
	if terminal {
		t.Fatalf("RunVerify() terminal = true, want the responsibility still live")
	}
	if len(confirmer.received) != 0 {
		t.Fatalf("output confirmations on the reveal half = %#v, want none", confirmer.received)
	}
}

// TestRevealHalfRefusesAZeroRevealDeadlineWhereverItIsEnteredFrom is FR4 at the
// executor boundary. The runner's own gate (awaitingRevealPhase) normally keeps
// this case from being scheduled, but the fail-closed reading of a zero reveal
// deadline must not depend on that gate being the only door.
func TestRevealHalfRefusesAZeroRevealDeadlineWhereverItIsEnteredFrom(t *testing.T) {
	executor := newProductionVerifyExecutor(TaskRunnerConfig{
		LocalVerifierAddress: "verifier-1", ChainID: "chain", TaskDataAuth: taskRunnerTaskDataAuth(t),
	})
	task := store.VerifyTask{
		TaskID: revealPhaseTaskID, SessionID: "session-1", VerifyRound: 1,
		RevealDeadlineHeight: 0, Stage: string(layout.StageCommitted),
	}
	if _, _, err := executor.RunVerify(context.Background(), codec.HashBytes([]byte("task-hash")), task); !errors.Is(err, verifier.ErrRevealPhaseNotStarted) {
		t.Fatalf("RunVerify() error = %v, want the reveal phase reported as not started", err)
	}
}

// TestRevealResponsibilitySurvivesProcessRestart is AC6, stated the only way it
// can be stated honestly: a SECOND TaskRunner over the same Pebble store, built
// as a fresh process would build it, still finds the reveal owed.
//
// This is why StageCommitted is not terminal. The old path marked the whole
// responsibility "succeeded" the moment the commit was signed, so a restart
// found nothing at all: loadActiveTasks skips succeeded records, and the reveal
// that was still owed simply ceased to exist. No durable scheduler is involved
// and none is needed (issue #108 stays out of this) -- the reveal is opened by
// an event, and the record the event lands on is the same one the commit wrote.
func TestRevealResponsibilitySurvivesProcessRestart(t *testing.T) {
	ctx := context.Background()
	first, db, hash := revealPhaseRunner(t, layout.StageCommitted, 0, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 700},
	})
	// The phase opens while the first process is alive; then the process ends.
	if err := first.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		TaskHash: hash, TaskID: revealPhaseTaskID, Type: ReconcilerEffectRevealReady,
		Snapshot: revealPhaseSnapshot(hash, 900),
		Event:    chainclient.KeeperEvent{Type: chainclient.KeeperEventRevealPhaseStarted, Height: 640},
	}}); err != nil {
		t.Fatal(err)
	}

	var seen []store.VerifyTask
	restarted := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, MaxRetryAttempts: 120, LocalVerifierAddress: "verifier-1",
		ChainStatus: fixedChainStatus{height: 700},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			seen = append(seen, task)
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("restarted runner ran the reveal %d times, want 1", len(seen))
	}
	if seen[0].Stage != string(layout.StageCommitted) || seen[0].RevealDeadlineHeight != 900 {
		t.Fatalf("restored responsibility = %#v, want the committed stage and the recorded reveal deadline", seen[0])
	}
}
