package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// verifyTerminalEffect is one EventResultAccepted as the reconciler hands it to
// the runner: a reveal that reached the chain, naming the Verifier whose reveal
// it was.
func verifyTerminalEffect(hash codec.Hash, eventType chainclient.KeeperEventType, verifier string) ReconcilerEffect {
	return ReconcilerEffect{
		TaskHash: hash, TaskID: revealPhaseTaskID, Type: ReconcilerEffectVerifyTerminal,
		Event: chainclient.KeeperEvent{Type: eventType, TaskID: revealPhaseTaskID, Verifier: verifier, Height: 22683},
	}
}

// TestAnotherVerifiersRevealLeavesThisResponsibilityAlone is the point of the
// scope check. Every node on the chain sees every EventResultAccepted, and on a
// task with several Verifiers the first reveal to land arrives while the others
// still owe one. Releasing the responsibility on someone else's reveal drops
// this node's own reveal on the floor: the work is done and committed, the
// deadline is still tens of thousands of blocks away, and the record is the
// only thing that keeps the task in the active set.
func TestAnotherVerifiersRevealLeavesThisResponsibilityAlone(t *testing.T) {
	ctx := context.Background()
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{})

	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{
		verifyTerminalEffect(hash, chainclient.KeeperEventResultCredentialAccepted, "verifier-2"),
	}); err != nil {
		t.Fatal(err)
	}

	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatalf("verify record is gone after another Verifier revealed: %v", err)
	}
	if rec.TaskID != revealPhaseTaskID || rec.Stage != layout.StageCommitted {
		t.Fatalf("verify record = %+v, want this node's own reveal still owed", rec)
	}
}

// TestOwnRevealReleasesTheResponsibility keeps the scope check from turning the
// terminal effect into a no-op: this node's own reveal reaching the chain is
// exactly what ends the responsibility, and the release is traced because
// deleting the record is what removes the task from the active set for good.
func TestOwnRevealReleasesTheResponsibility(t *testing.T) {
	ctx := context.Background()
	trace := &collectTrace{}
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{Trace: trace.trace()})

	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{
		verifyTerminalEffect(hash, chainclient.KeeperEventResultCredentialAccepted, "verifier-1"),
	}); err != nil {
		t.Fatal(err)
	}

	if rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash)); err == nil && rec.TaskID != "" {
		t.Fatalf("verify record = %+v, want the responsibility released by this node's own reveal", rec)
	}
	line := trace.event(t, "verify_responsibility_released")
	for _, want := range []string{`verifier="verifier-1"`, "chain_height=22683"} {
		if !strings.Contains(line, want) {
			t.Fatalf("verify_responsibility_released = %q, want it to carry %s", line, want)
		}
	}
}

// TestTaskWideTerminalEventsStillRelease keeps the scope check from reading an
// absent verifier as a foreign one. The reveal deadline closing is the chain
// ending the phase for the whole task, not one Verifier's reveal, so it carries
// no verifier address and must still release a responsibility that can no
// longer be discharged.
func TestTaskWideTerminalEventsStillRelease(t *testing.T) {
	for _, eventType := range []chainclient.KeeperEventType{
		chainclient.KeeperEventRevealDeadlineClosed,
		chainclient.KeeperEventWorkerRevealDeadlineClosed,
	} {
		t.Run(string(eventType), func(t *testing.T) {
			ctx := context.Background()
			runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{})

			if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{
				verifyTerminalEffect(hash, eventType, ""),
			}); err != nil {
				t.Fatal(err)
			}
			if rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash)); err == nil && rec.TaskID != "" {
				t.Fatalf("verify record = %+v, want a task-wide deadline close to release it", rec)
			}
		})
	}
}
