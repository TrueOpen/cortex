package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// I6: a pass snapshots its responsibilities, then an execution that finished
// in between writes its outcome and releases its claim. The pass's claim then
// succeeds against a stale "queued" copy; the live record is re-checked and
// the stale launch is dropped instead of running the work a second time.
func TestDispatchDropsALaunchWhoseRecordMovedAfterTheSnapshot(t *testing.T) {
	ctx := context.Background()
	db := vsStore(t)
	hash := codec.HashBytes([]byte("stale-snapshot-task"))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: "task-stale", SessionID: "session", VerifyRound: 1, CommitDeadlineHeight: 100, Stage: "queued",
	})
	ran := 0
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, ChainStatus: fixedChainStatus{height: 10},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			task.Stage = string(layout.StageCommitted)
			return task, false, nil
		}),
	})
	hooked := 0
	runner.dispatchClaimHook = func(key responsibilityKey) {
		hooked++
		// The earlier execution's outcome lands between the snapshot and here.
		moved := store.VerifyTask{TaskID: "task-stale", Stage: string(layout.StageCommitted)}
		if err := runner.applyOutcome(ctx, taskOutcome{role: key.role, hash: key.hash, verify: moved}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if hooked != 1 || ran != 0 {
		t.Fatalf("hook %d, executor runs %d; want the stale launch dropped", hooked, ran)
	}
	if runner.executing(responsibilityKey{role: "verify", hash: hash}) {
		t.Fatal("the dropped launch kept its inflight claim")
	}
}

// The re-check does not drop a launch whose record did not move.
func TestDispatchLaunchesAnUnchangedRecord(t *testing.T) {
	ctx := context.Background()
	db := vsStore(t)
	hash := codec.HashBytes([]byte("fresh-snapshot-task"))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: "task-fresh", SessionID: "session", VerifyRound: 1, CommitDeadlineHeight: 100, Stage: "queued",
	})
	ran := 0
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, ChainStatus: fixedChainStatus{height: 10},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			return task, false, nil
		}),
	})
	runner.dispatchClaimHook = func(responsibilityKey) {}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Fatalf("executor runs = %d, want 1", ran)
	}
}
