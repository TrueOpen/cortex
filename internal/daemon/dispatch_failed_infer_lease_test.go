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

// The state an earlier build leaves behind: an infer record that failed by the
// retry bound, its lease still on the task key. Failed records are not part of
// the active set a pass loads, so the release has to come from the store. A new
// process finds the record on its first pass, returns the lease, and the slot
// is advertised again; later passes do not release it a second time.
func TestFailedInferLeftByAnEarlierBuildReturnsItsLeaseAtStart(t *testing.T) {
	ctx := context.Background()
	x, old, hash, task := leasedInfer(t, 1, TaskRunnerConfig{})
	failed := layout.InferRecord{TaskID: task.TaskID, DispatchTicketHash: layout.StoredHash(task.DispatchTicketHash),
		Stage: layout.StageFailed, RetryCount: 346, LastError: "task retry count 346 reached the bound 120"}
	if err := layout.MergeInfer(ctx, x.st, layout.StoredHash(hash), failed); err != nil {
		t.Fatal(err)
	}
	_ = old // the process that failed the task is gone
	if x.leaseCount(t) != 1 || freeSlots(t, x) != 0 {
		t.Fatal("setup: the failed record still holds the only slot")
	}
	x.open() // restart: the ledger counts the lease from the store again
	if freeSlots(t, x) != 0 {
		t.Fatal("setup: the restarted ledger still counts the lease")
	}
	released := 0
	r := NewTaskRunner(TaskRunnerConfig{Store: x.st, ReleaseDispatchLease: func(ctx context.Context, id layout.StoredHash) error {
		released++
		return x.d.ReleaseTaskLease(ctx, id)
	}})
	for i := 0; i < 3; i++ {
		if err := r.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if released != 1 {
		t.Fatalf("released %d times, want once per process", released)
	}
	if x.leaseCount(t) != 0 || freeSlots(t, x) != 1 {
		t.Fatalf("%d leases, %d free slots after the start: the failed task still holds the slot", x.leaseCount(t), freeSlots(t, x))
	}
}

// A release that fails (the dispatch plane is not bound yet, a store error) is
// not counted as done: the next pass sweeps again.
func TestFailedInferLeaseSweepRetriesAfterAFailedRelease(t *testing.T) {
	ctx := context.Background()
	x, _, hash, task := leasedInfer(t, 1, TaskRunnerConfig{})
	if err := layout.MergeInfer(ctx, x.st, layout.StoredHash(hash), layout.InferRecord{TaskID: task.TaskID,
		DispatchTicketHash: layout.StoredHash(task.DispatchTicketHash), Stage: layout.StageFailed}); err != nil {
		t.Fatal(err)
	}
	fail := true
	r := NewTaskRunner(TaskRunnerConfig{Store: x.st, ReleaseDispatchLease: func(ctx context.Context, id layout.StoredHash) error {
		if fail {
			return errors.New("not bound")
		}
		return x.d.ReleaseTaskLease(ctx, id)
	}})
	var reported []string
	r.cfg.Diagnostic = func(d TaskRunnerDiagnostic) { reported = append(reported, d.Source+": "+d.Error) }
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("a failed release must not fail the pass (that stops the daemon): %v", err)
	}
	if len(reported) != 1 || x.leaseCount(t) != 1 {
		t.Fatalf("reported %v, %d leases: a failed release is reported and leaves the lease", reported, x.leaseCount(t))
	}
	fail = false
	if err := r.RunOnce(ctx); err != nil || x.leaseCount(t) != 0 {
		t.Fatalf("err %v, %d leases: the sweep runs again after a failure", err, x.leaseCount(t))
	}
}
