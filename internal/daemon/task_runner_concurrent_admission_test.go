package daemon

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// TestRunStartsNewlyAdmittedTaskWhileAnEarlierTaskIsStillRunning is the
// regression this file exists for, in the shape devnet node3 measured it: the
// node is holding the GPU as a Verifier for the previous task when the chain
// admits it to a new one as a Worker. It used to wait out the rest of the
// verify -- 7.0 seconds on the measured task, with the new task entering the
// model 0.32s after the verify finished -- because the scheduler launched a
// round, blocked on all of it, and only then looked at the wake-up the
// admission had published.
//
// PollInterval is an hour on purpose. The only thing that can start the second
// task within the test's patience is the wake-up being consumed while the first
// execution is still running, which is exactly the property under test; a short
// interval would let a plain timer tick pass for a fix.
func TestRunStartsNewlyAdmittedTaskWhileAnEarlierTaskIsStillRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	verifyHash := codec.HashBytes([]byte("verify-holding-the-node"))
	seedVerifyTask(ctx, t, db, verifyHash, store.VerifyTask{
		TaskID: "task-verify", SessionID: "session-1", Stage: "queued",
		VerifyRound: 1, DeadlineHeight: 100,
	})

	verifyRunning, releaseVerify := make(chan struct{}), make(chan struct{})
	verifyExecutor := verifyExecutorFunc(func(context.Context, codec.Hash, store.VerifyTask) (store.VerifyTask, bool, error) {
		close(verifyRunning)
		<-releaseVerify
		return store.VerifyTask{}, true, nil
	})
	inferStarted := make(chan string, 4)
	inferExecutor := inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
		inferStarted <- task.TaskID
		return task, true, nil
	})

	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, InferExecutor: inferExecutor, VerifyExecutor: verifyExecutor,
		LocalWorkerAddress: "worker-1", MaxConcurrency: 4,
		PollInterval: time.Hour, ChainStatus: fixedChainStatus{height: 10},
	})
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	select {
	case <-verifyRunning:
	case <-time.After(10 * time.Second):
		t.Fatal("the verify responsibility never entered its executor")
	}

	inferHash := codec.HashBytes([]byte("newly-admitted-worker-task"))
	admission := ReconcilerEffect{Type: ReconcilerEffectAssignment, TaskHash: inferHash, TaskID: "task-infer", Snapshot: chainclient.TaskSnapshot{
		Assignment: chainclient.AssignmentSnapshot{
			TaskID: "task-infer", SessionID: "session-2", OrderSequence: chainclient.NewUint64String(1),
			SelectedWorker: "worker-1", ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
			InferDeadlineHeight:      chainclient.NewUint64String(100),
			AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes([]byte("input"))),
		},
	}}
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{admission}); err != nil {
		t.Fatal(err)
	}

	select {
	case taskID := <-inferStarted:
		if taskID != "task-infer" {
			t.Fatalf("started task %q, want the newly admitted task-infer", taskID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the newly admitted task did not start while an earlier execution was in flight")
	}
	// releaseVerify has not been closed, so the verify executor is provably
	// still inside its call: the admitted task started beside it rather than
	// after it.
	close(releaseVerify)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
	record, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(verifyHash))
	if err == nil && record.TaskID != "" {
		t.Fatalf("terminal verify responsibility survived: %#v", record)
	}
}

// TestRunDoesNotStartASecondExecutorForAnExecutingResponsibility pins the
// invariant the round boundary used to provide for free. A running task's
// durable record still reads "queued" until its executor writes the outcome, so
// every pass that overlaps the execution reads a document that looks due. Two
// executors on one Worker responsibility is two signed answers to one question.
func TestRunDoesNotStartASecondExecutorForAnExecutingResponsibility(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	taskHash := codec.HashBytes([]byte("long-running-infer"))
	seedInferTask(ctx, t, db, taskHash, store.InferTask{TaskID: "task-long", SessionID: "session-1", Stage: "queued", DeadlineHeight: 100})

	var starts atomic.Int64
	running, release := make(chan struct{}), make(chan struct{})
	executor := inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
		if starts.Add(1) == 1 {
			close(running)
		}
		<-release
		return task, true, nil
	})
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, InferExecutor: executor, MaxConcurrency: 4,
		PollInterval: 5 * time.Millisecond, ChainStatus: fixedChainStatus{height: 10},
	})
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	select {
	case <-running:
	case <-time.After(10 * time.Second):
		t.Fatal("the infer responsibility never entered its executor")
	}
	// Many poll ticks at this interval, every one of them reading a record the
	// running executor has not changed yet.
	time.Sleep(200 * time.Millisecond)
	if got := starts.Load(); got != 1 {
		t.Fatalf("executor started %d times for one responsibility, want 1", got)
	}
	close(release)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// TestRunStillBoundsConcurrentExecutionsAcrossPasses checks the other half of
// removing the round: the semaphore used to be created inside each pass, which
// bounded the node only because passes could not overlap. Now that a task
// admitted mid-execution starts at once, a per-pass semaphore would bound
// nothing, so MAX_CONCURRENCY has to hold across passes or the node would hand
// the model more work than it was configured for.
func TestRunStillBoundsConcurrentExecutionsAcrossPasses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	firstHash := codec.HashBytes([]byte("first-infer"))
	seedInferTask(ctx, t, db, firstHash, store.InferTask{TaskID: "task-first", SessionID: "session-1", Stage: "queued", DeadlineHeight: 100})

	running, release := make(chan struct{}), make(chan struct{})
	entered := make(chan string, 4)
	executor := inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
		entered <- task.TaskID
		if task.TaskID == "task-first" {
			close(running)
			<-release
		}
		return task, true, nil
	})
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, InferExecutor: executor, LocalWorkerAddress: "worker-1", MaxConcurrency: 1,
		PollInterval: 5 * time.Millisecond, ChainStatus: fixedChainStatus{height: 10},
	})
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	select {
	case id := <-entered:
		if id != "task-first" {
			t.Fatalf("first execution was %q", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first responsibility never entered its executor")
	}
	<-running

	secondHash := codec.HashBytes([]byte("second-infer"))
	admission := ReconcilerEffect{Type: ReconcilerEffectAssignment, TaskHash: secondHash, TaskID: "task-second", Snapshot: chainclient.TaskSnapshot{
		Assignment: chainclient.AssignmentSnapshot{
			TaskID: "task-second", SessionID: "session-2", OrderSequence: chainclient.NewUint64String(1),
			SelectedWorker: "worker-1", ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
			InferDeadlineHeight:      chainclient.NewUint64String(100),
			AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes([]byte("input"))),
		},
	}}
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{admission}); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-entered:
		t.Fatalf("%q entered the model while the single slot was held", id)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case id := <-entered:
		if id != "task-second" {
			t.Fatalf("second execution was %q, want task-second", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admitted task never ran after the slot was released")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// TestRunDrainsInFlightExecutionsBeforeReturning covers the shutdown ordering
// the removed wg.Wait used to give away. cortexd's runner group blocks on Run
// and then tears the node's dependencies down, so Run returning while an
// execution is between its model call and its durable write would pull the store
// out from under a task mid-commit.
func TestRunDrainsInFlightExecutionsBeforeReturning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	taskHash := codec.HashBytes([]byte("draining-infer"))
	seedInferTask(ctx, t, db, taskHash, store.InferTask{TaskID: "task-drain", SessionID: "session-1", Stage: "queued", DeadlineHeight: 100})

	var returned atomic.Bool
	running, release := make(chan struct{}), make(chan struct{})
	executor := inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
		close(running)
		<-release
		returned.Store(true)
		return task, true, nil
	})
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, InferExecutor: executor, MaxConcurrency: 1,
		PollInterval: 5 * time.Millisecond, ChainStatus: fixedChainStatus{height: 10},
	})
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	select {
	case <-running:
	case <-time.After(10 * time.Second):
		t.Fatal("the infer responsibility never entered its executor")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Run returned %v while an execution was still in flight", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want a clean shutdown", err)
		}
		if !returned.Load() {
			t.Fatal("Run returned before the executor had finished")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the execution drained")
	}
}
