package daemon

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
)

var slotWaitMillis = regexp.MustCompile(`waited_ms=(\d+)`)

// TestSlotWaitIsTracedWhenTheModelBudgetIsFull covers the one span between an
// admitted task and its generation that nothing reported. The admission
// milestone and the executor's own first line bracket it, and on a node whose
// model service admits one request at a time it measured 4.4s -- a fifth of
// everything the caller waited for -- with no way to tell waiting for the
// engine budget apart from any other scheduling delay.
func TestSlotWaitIsTracedWhenTheModelBudgetIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// One verify responsibility takes the node's only slot and holds it.
	verifyHash := codec.HashBytes([]byte("verify-holding-the-only-slot"))
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

	trace := &collectTrace{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, InferExecutor: inferExecutor, VerifyExecutor: verifyExecutor,
		LocalWorkerAddress: "worker-1", MaxConcurrency: 1,
		PollInterval: time.Hour, ChainStatus: fixedChainStatus{height: 10},
		Trace: trace.trace(),
	})
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	select {
	case <-verifyRunning:
	case <-time.After(10 * time.Second):
		t.Fatal("the verify responsibility never took the slot")
	}

	inferHash := codec.HashBytes([]byte("worker-task-waiting-for-the-slot"))
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectAssignment, TaskHash: inferHash, TaskID: "task-infer",
		Snapshot: chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
			TaskID: "task-infer", SessionID: "session-2", OrderSequence: chainclient.NewUint64String(1),
			SelectedWorker: "worker-1", ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
			InferDeadlineHeight:      chainclient.NewUint64String(100),
			AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes([]byte("input"))),
		}},
	}}); err != nil {
		t.Fatal(err)
	}

	// The admitted task is now blocked on the budget rather than on anything of
	// its own. Hold it there long enough that a reported wait of zero could only
	// mean the milestone is not measuring the block.
	time.Sleep(250 * time.Millisecond)
	close(releaseVerify)

	select {
	case taskID := <-inferStarted:
		if taskID != "task-infer" {
			t.Fatalf("started %q, want task-infer", taskID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admitted task never reached its executor")
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

	var waits []int
	for _, line := range trace.allLines() {
		if !matchesSlotWaitFor(line, "task-infer") {
			continue
		}
		match := slotWaitMillis.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("task_slot_acquired = %q, want a waited_ms", line)
		}
		waited, _ := strconv.Atoi(match[1])
		waits = append(waits, waited)
	}
	if len(waits) != 1 {
		t.Fatalf("task_slot_acquired lines for task-infer = %d, want exactly one:\n%v", len(waits), trace.allLines())
	}
	if waits[0] < 200 {
		t.Fatalf("waited_ms = %d, want the ~250ms it was held off the budget", waits[0])
	}
}

func matchesSlotWaitFor(line, taskID string) bool {
	return len(line) > 0 &&
		regexp.MustCompile(`event=task_slot_acquired\b`).MatchString(line) &&
		regexp.MustCompile(`task="`+regexp.QuoteMeta(taskID)+`"`).MatchString(line)
}

// TestSlotWaitIsTracedForAnUncontendedTask keeps the milestone unconditional. A
// line that only appeared when the node was busy would leave a reader unable to
// tell a fast acquisition from a milestone that was never reached.
func TestSlotWaitIsTracedForAnUncontendedTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	hash := codec.HashBytes([]byte("uncontended-verify"))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: "task-alone", SessionID: "session-1", Stage: "queued",
		VerifyRound: 1, DeadlineHeight: 100,
	})
	ran := make(chan struct{})
	trace := &collectTrace{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 4, PollInterval: time.Hour,
		ChainStatus: fixedChainStatus{height: 10}, Trace: trace.trace(),
		VerifyExecutor: verifyExecutorFunc(func(context.Context, codec.Hash, store.VerifyTask) (store.VerifyTask, bool, error) {
			close(ran)
			return store.VerifyTask{}, true, nil
		}),
	})
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("the responsibility never ran")
	}
	cancel()
	<-done

	for _, line := range trace.allLines() {
		if matchesSlotWaitFor(line, "task-alone") {
			return
		}
	}
	t.Fatalf("no task_slot_acquired for an uncontended task:\n%v", trace.allLines())
}
