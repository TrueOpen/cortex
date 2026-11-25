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

// acceptedInfer drives the harness to an accepted ticket whose chain record
// has NOT landed (its lease is still on the ticket key) and returns a runner
// holding the infer responsibility for it, wired as cortexd wires it.
func acceptedInfer(t *testing.T, capacity uint32) (*dispatchHarness, *TaskRunner, layout.DispatchRecord, codec.Hash, store.InferTask) {
	t.Helper()
	x := newDispatchHarness(t, capacity, nil)
	rec := x.committed(t)
	if rec.State != layout.DispatchAccepted {
		t.Fatalf("setup: ticket is %s, want accepted and not yet recorded", rec.State)
	}
	if n := x.leaseCount(t); n != 1 {
		t.Fatalf("setup: %d leases", n)
	}
	r := NewTaskRunner(TaskRunnerConfig{Store: x.st, ReleaseDispatchLease: x.d.ReleaseTaskLease, ReleaseFailedInferLease: x.d.ReleaseFailedInferLease})
	hash := codec.Hash(rec.TaskHash)
	task := store.InferTask{TaskID: hex.EncodeToString(rec.TaskID[:]), DispatchTicketHash: codec.Hash(rec.TicketHash), Stage: "running", DeadlineHeight: 100_120}
	r.infer = map[codec.Hash]store.InferTask{hash: task}
	// The responsibility's record, as the dispatch plane writes it when it
	// admits the inference: the runner persists the failure into it.
	if _, err := layout.GetInferRecord(context.Background(), x.st, rec.TaskHash); err != nil {
		running := layout.InferRecord{TaskID: task.TaskID, DispatchTicketHash: rec.TicketHash, Stage: layout.StageQueued, DeadlineHeight: 100_120}
		if err := layout.MergeInfer(context.Background(), x.st, rec.TaskHash, running); err != nil {
			t.Fatal(err)
		}
	}
	return x, r, rec, hash, task
}

func engineRefuses(t *testing.T, r *TaskRunner, hash codec.Hash, task store.InferTask) {
	t.Helper()
	refusal := modelservice.Deterministic(modelservice.FaultCodeRequestRefused,
		errors.New("modelservice local: /v1/chat/completions returned status 400: this model's maximum context length is 4096 tokens"))
	out := taskOutcome{role: "infer", hash: hash, ticket: task.DispatchTicketHash, infer: task, err: refusal, finishedAt: time.Now().UTC()}
	if err := r.applyOutcome(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	if got := r.infer[hash]; got.Stage != "failed" {
		t.Fatalf("task = %+v, want failed", got)
	}
}

func (x *dispatchHarness) recordLands(t *testing.T) {
	t.Helper()
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 100_120)
	if err := x.d.ObserveDispatchRecorded(context.Background(), x.fact(120, 100_120)); err != nil {
		t.Fatalf("record after the refusal: %v", err)
	}
	if got := x.record(t); got.State != layout.DispatchRecorded {
		t.Fatalf("ticket is %s after its record, want recorded", got.State)
	}
}

// The engine refuses the request in milliseconds, before the Builder's record
// of the ticket is in a block: the lease is still on the ticket key, where the
// task-keyed release finds nothing. The slot must come back at the refusal,
// and the record that lands afterwards must neither fail nor bring a lease
// back; a repeated record changes nothing either.
func TestRefusalBeforeTheRecordFreesTheSlotAndTheRecordDoesNotTakeItBack(t *testing.T) {
	x, r, _, hash, task := acceptedInfer(t, 1)
	if freeSlots(t, x) != 0 {
		t.Fatal("setup: the accepted ticket holds the only slot")
	}
	engineRefuses(t, r, hash, task)
	if x.leaseCount(t) != 0 || freeSlots(t, x) != 1 {
		t.Fatalf("%d leases, %d free slots after a refusal that beat the record", x.leaseCount(t), freeSlots(t, x))
	}
	for i := 0; i < 2; i++ {
		x.recordLands(t)
		if x.leaseCount(t) != 0 || freeSlots(t, x) != 1 {
			t.Fatalf("record %d brought a lease back: %d leases, %d free slots", i+1, x.leaseCount(t), freeSlots(t, x))
		}
	}
	x.open() // a restart counts the leases from the store
	if freeSlots(t, x) != 1 {
		t.Fatal("the restarted ledger counts a lease for the refused task")
	}
}

// The refusal comes after the record moved the lease to the task key: the
// case the first tests cover, here through the same hook cortexd wires.
func TestRefusalAfterTheRecordFreesTheSlot(t *testing.T) {
	x, r, _, hash, task := acceptedInfer(t, 1)
	x.recordLands(t)
	if x.leaseCount(t) != 1 || freeSlots(t, x) != 0 {
		t.Fatal("setup: the recorded task holds the only slot")
	}
	engineRefuses(t, r, hash, task)
	engineRefuses(t, r, hash, task) // a late duplicate outcome
	if x.leaseCount(t) != 0 || freeSlots(t, x) != 1 {
		t.Fatalf("%d leases, %d free slots", x.leaseCount(t), freeSlots(t, x))
	}
}

// The failure and the record cross: the infer record is already failed but
// its release has not run (or ran before the lease was anywhere it looked)
// when the record moves the lease to the task key. The record itself returns
// the lease then, and the release that runs afterwards finds nothing and does
// not push the count below zero.
func TestRecordCrossingAFailedInferReturnsTheLeaseOnce(t *testing.T) {
	ctx := context.Background()
	x, _, rec, hash, task := acceptedInfer(t, 2)
	failed := layout.InferRecord{TaskID: task.TaskID, DispatchTicketHash: rec.TicketHash, Stage: layout.StageFailed, LastError: "refused"}
	if err := layout.MergeInfer(ctx, x.st, layout.StoredHash(hash), failed); err != nil {
		t.Fatal(err)
	}
	x.recordLands(t)
	if x.leaseCount(t) != 0 || freeSlots(t, x) != 2 {
		t.Fatalf("%d leases, %d free slots after the record of a failed inference", x.leaseCount(t), freeSlots(t, x))
	}
	if err := x.d.ReleaseFailedInferLease(ctx, rec.TaskID, rec.TicketHash); err != nil {
		t.Fatal(err)
	}
	if x.leaseCount(t) != 0 || freeSlots(t, x) != 2 {
		t.Fatalf("a second release changed the ledger: %d leases, %d free slots", x.leaseCount(t), freeSlots(t, x))
	}
}

// A record for an inference that is still running moves the lease as before
// and keeps it: only a failed inference gives it back.
func TestRecordOfARunningInferKeepsItsLease(t *testing.T) {
	x, _, _, _, _ := acceptedInfer(t, 1)
	x.recordLands(t)
	if x.leaseCount(t) != 1 || freeSlots(t, x) != 0 {
		t.Fatalf("%d leases, %d free slots: a running inference lost its lease at the record", x.leaseCount(t), freeSlots(t, x))
	}
}

// Restart with a failed infer record whose lease never left the ticket key
// (the process died between the failure and the release, or an earlier build
// wrote the state): the first pass returns it, once.
func TestFailedInferWithATicketKeyedLeaseReturnsItAtStart(t *testing.T) {
	ctx := context.Background()
	x, _, rec, hash, task := acceptedInfer(t, 1)
	failed := layout.InferRecord{TaskID: task.TaskID, DispatchTicketHash: rec.TicketHash, Stage: layout.StageFailed, LastError: "refused"}
	if err := layout.MergeInfer(ctx, x.st, layout.StoredHash(hash), failed); err != nil {
		t.Fatal(err)
	}
	x.open()
	if x.leaseCount(t) != 1 || freeSlots(t, x) != 0 {
		t.Fatal("setup: the restarted ledger counts the ticket-keyed lease")
	}
	released := 0
	r := NewTaskRunner(TaskRunnerConfig{Store: x.st, ReleaseDispatchLease: x.d.ReleaseTaskLease,
		ReleaseFailedInferLease: func(ctx context.Context, id, ticket layout.StoredHash) error {
			released++
			return x.d.ReleaseFailedInferLease(ctx, id, ticket)
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
		t.Fatalf("%d leases, %d free slots after the start", x.leaseCount(t), freeSlots(t, x))
	}
	x.recordLands(t) // the record that arrives after the restart
	if x.leaseCount(t) != 0 || freeSlots(t, x) != 1 {
		t.Fatalf("the late record brought a lease back: %d leases, %d free slots", x.leaseCount(t), freeSlots(t, x))
	}
}
