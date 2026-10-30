package daemon

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func (x *dispatchHarness) leaseCount(t *testing.T) uint32 {
	t.Helper()
	n, err := layout.CountWorkerLeases(context.Background(), x.st)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// I1: a page is applied in order. dispatch_recorded moves the lease to the
// task key; the infer_terminal after it in the same page releases that lease.
func TestRecordedThenTerminalInOnePageLeavesNoLease(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 300)
	r := NewTaskRunner(TaskRunnerConfig{Store: x.st, DispatchRecords: x.d, ReleaseDispatchLease: x.d.ReleaseTaskLease})
	taskID := hex.EncodeToString(rec.TaskID[:])
	page := []ReconcilerEffect{
		{Type: ReconcilerEffectDispatchRecorded, TaskID: taskID, Dispatch: x.fact(120, 300)},
		{Type: ReconcilerEffectInferTerminal, TaskID: taskID, TaskHash: codec.Hash(rec.TaskHash)},
	}
	if err := r.ApplyReconcilerEffects(ctx, page); err != nil {
		t.Fatal(err)
	}
	if got := x.record(t).State; got != layout.DispatchRecorded {
		t.Fatalf("state %s", got)
	}
	if n := x.leaseCount(t); n != 0 {
		t.Fatalf("%d leases left: the terminal effect ran before the record moved the lease", n)
	}
}

// I2: Rebind runs before the Recorded write. A crash between them leaves
// the lease on the task key of a ticket that is still accepted; whatever
// becomes of the ticket next must not leak it.
func TestCrashBetweenRebindAndRecordDoesNotLeakTheLease(t *testing.T) {
	ctx := context.Background()
	t.Run("redelivered record", func(t *testing.T) {
		x := newDispatchHarness(t, 2, nil)
		rec := x.committed(t)
		if _, err := layout.RebindWorkerLease(ctx, x.st, rec.TicketHash, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 300)
		if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 300)); err != nil {
			t.Fatal(err)
		}
		if got := x.record(t).State; got != layout.DispatchRecorded || x.leaseCount(t) != 1 {
			t.Fatalf("state %s, %d leases", got, x.leaseCount(t))
		}
		if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil || x.leaseCount(t) != 0 {
			t.Fatalf("%d leases after success, %v", x.leaseCount(t), err)
		}
	})
	t.Run("released instead", func(t *testing.T) {
		x, _ := claimHarness(t)
		rec := x.committed(t)
		if _, err := layout.RebindWorkerLease(ctx, x.st, rec.TicketHash, rec.TaskID); err != nil {
			t.Fatal(err)
		}
		x.chainRecords(t, [32]byte{0xee}, hrBuilderB, 120, 300) // the chain says another ticket won
		x.atHeight(t, rec.ClaimFromHeight)
		if got := x.record(t).State; got.HoldsDuty() || x.leaseCount(t) != 0 {
			t.Fatalf("state %s, %d leases", got, x.leaseCount(t))
		}
	})
	t.Run("recorded with the lease still on the ticket key", func(t *testing.T) {
		// The order before this fix: Recorded written, then Rebind failed.
		x := newDispatchHarness(t, 2, nil)
		rec := x.committed(t)
		if _, err := layout.UpdateDispatch(ctx, x.st, rec.TicketHash, func(r *layout.DispatchRecord) error {
			r.State, r.WinnerTicketHash, r.RecordedHeight, r.InferDeadlineHeight = layout.DispatchRecorded, r.TicketHash, 120, 300
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil || x.leaseCount(t) != 0 {
			t.Fatalf("%d leases after success, %v", x.leaseCount(t), err)
		}
	})
}

// M1: a recorded ticket whose lease cannot move to its task key (another
// ticket holds it) does not stop the Dispatcher from starting; its ticket
// lease is given back.
func TestRecoverLeasesSurvivesARebindConflict(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 3, nil)
	rec := x.committed(t)
	if _, err := layout.UpdateDispatch(ctx, x.st, rec.TicketHash, func(r *layout.DispatchRecord) error {
		r.State, r.WinnerTicketHash, r.RecordedHeight, r.InferDeadlineHeight = layout.DispatchRecorded, r.TicketHash, 120, 300
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other := layout.StoredHash{0x77}
	if _, _, err := layout.AcquireWorkerLease(ctx, x.st, layout.WorkerLease{TicketHash: other, TaskID: rec.TaskID}, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := layout.RebindWorkerLease(ctx, x.st, other, rec.TaskID); err != nil {
		t.Fatal(err)
	}
	x.open() // fails the test if NewDispatcher fails
	if x.leaseHeld(t) || x.leaseCount(t) != 1 {
		t.Fatalf("ticket lease held %v, %d leases: the conflicting ticket lease is released", x.leaseHeld(t), x.leaseCount(t))
	}
}
