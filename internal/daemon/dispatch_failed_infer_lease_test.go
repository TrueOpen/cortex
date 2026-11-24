package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// leasedInfer drives the harness to a recorded ticket (its lease on the
// task key) and returns a runner holding the infer responsibility for it.
func leasedInfer(t *testing.T, capacity uint32, cfg TaskRunnerConfig) (*dispatchHarness, *TaskRunner, codec.Hash, store.InferTask) {
	t.Helper()
	ctx := context.Background()
	x := newDispatchHarness(t, capacity, nil)
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 100_120)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 100_120)); err != nil {
		t.Fatal(err)
	}
	if n := x.leaseCount(t); n != 1 {
		t.Fatalf("setup: %d leases", n)
	}
	cfg.Store, cfg.ReleaseDispatchLease = x.st, x.d.ReleaseTaskLease
	r := NewTaskRunner(cfg)
	hash := codec.Hash(rec.TaskHash)
	task := store.InferTask{TaskID: hex.EncodeToString(rec.TaskID[:]), DispatchTicketHash: codec.Hash(rec.TicketHash), Stage: "running", DeadlineHeight: 100_120}
	r.infer = map[codec.Hash]store.InferTask{hash: task}
	return x, r, hash, task
}

func freeSlots(t *testing.T, x *dispatchHarness) uint32 {
	t.Helper()
	n, ok := x.d.cfg.Leases.FreeSlots()
	if !ok {
		t.Fatal("free slots unknown")
	}
	return n
}

// The engine refuses an order's output budget (HTTP 400). The refusal is
// deterministic, so the responsibility halts on the first attempt instead of
// retrying until the infer deadline, and the slot it held is free again: the
// node keeps serving while the chain task waits out its window.
func TestRefusedInferHaltsAtOnceAndFreesTheSlot(t *testing.T) {
	ctx := context.Background()
	x, r, hash, task := leasedInfer(t, 1, TaskRunnerConfig{})
	if freeSlots(t, x) != 0 {
		t.Fatal("setup: the recorded task holds the only slot")
	}
	refusal := modelservice.Deterministic(modelservice.FaultCodeRequestRefused,
		errors.New("modelservice local: /v1/chat/completions returned status 400: max_completion_tokens=30744 cannot be greater than max_model_len=4096"))
	out := taskOutcome{role: "infer", hash: hash, ticket: task.DispatchTicketHash, infer: task, err: refusal, finishedAt: time.Now().UTC()}
	for i := 0; i < 2; i++ { // a late duplicate outcome changes nothing
		if err := r.applyOutcome(ctx, out); err != nil {
			t.Fatal(err)
		}
	}
	got := r.infer[hash]
	if got.Stage != "failed" || !got.AutoHalted || got.HaltCode != modelservice.FaultCodeRequestRefused || got.RetryCount != 0 {
		t.Fatalf("task = %+v: halted on the first refusal, no retry spent", got)
	}
	if n := x.leaseCount(t); n != 0 {
		t.Fatalf("%d leases held by a halted inference", n)
	}
	if freeSlots(t, x) != 1 {
		t.Fatal("the slot of a halted inference is not advertised again")
	}
}

func TestInferOutOfRetriesFreesTheSlot(t *testing.T) {
	ctx := context.Background()
	x, r, hash, task := leasedInfer(t, 1, TaskRunnerConfig{MaxRetryAttempts: 2})
	fail := taskOutcome{role: "infer", hash: hash, ticket: task.DispatchTicketHash, infer: task, err: errors.New("boom"), finishedAt: time.Now().UTC()}
	if err := r.applyOutcome(ctx, fail); err != nil {
		t.Fatal(err)
	}
	if r.infer[hash].Stage == "failed" || x.leaseCount(t) != 1 {
		t.Fatal("a failure with retries left keeps the responsibility and its lease")
	}
	if err := r.applyOutcome(ctx, fail); err != nil {
		t.Fatal(err)
	}
	if r.infer[hash].Stage != "failed" || x.leaseCount(t) != 0 {
		t.Fatalf("stage %s, %d leases: the last retry ends the responsibility and returns the lease", r.infer[hash].Stage, x.leaseCount(t))
	}
}

func TestStoppedInferFreesTheSlot(t *testing.T) {
	ctx := context.Background()
	x, r, hash, task := leasedInfer(t, 1, TaskRunnerConfig{})
	if err := r.applyOutcome(ctx, taskOutcome{role: "infer", hash: hash, ticket: task.DispatchTicketHash, infer: task, stopReason: "task deadline height 100120 passed"}); err != nil {
		t.Fatal(err)
	}
	if r.infer[hash].Stage != "failed" || x.leaseCount(t) != 0 {
		t.Fatalf("stage %s, %d leases", r.infer[hash].Stage, x.leaseCount(t))
	}
}

// A record that failed before this process started (or under a build that
// kept the lease until the chain closed the task) still holds its lease in the
// store. The first pass returns it, once.
func TestFailedInferFoundAtStartReturnsItsLease(t *testing.T) {
	ctx := context.Background()
	x, r, hash, task := leasedInfer(t, 1, TaskRunnerConfig{})
	task.Stage = "failed"
	r.infer[hash] = task
	released := 0
	inner := r.cfg.ReleaseDispatchLease
	r.cfg.ReleaseDispatchLease = func(ctx context.Context, id layout.StoredHash) error {
		released++
		return inner(ctx, id)
	}
	for i := 0; i < 3; i++ {
		if err := r.releaseFailedInferLease(ctx, hash, task); err != nil {
			t.Fatal(err)
		}
	}
	if released != 1 || x.leaseCount(t) != 0 {
		t.Fatalf("released %d times, %d leases left", released, x.leaseCount(t))
	}
	running := task
	running.Stage = "running"
	if err := r.releaseFailedInferLease(ctx, codec.Hash{0xee}, running); err != nil || released != 1 {
		t.Fatal("a live responsibility keeps its lease")
	}
}
