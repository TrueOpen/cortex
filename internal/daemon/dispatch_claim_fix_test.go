package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// sweepAt is atHeight for passes that are allowed to report an error.
func (x *dispatchHarness) sweepAt(height uint64) {
	x.chain.with(func(f *fakeDispatchChain) { f.height = height })
	_ = x.d.Sweep(context.Background())
	_ = x.d.SweepClaims(context.Background())
}

func (x *dispatchHarness) byBuilderCalls() int {
	n := 0
	x.chain.with(func(f *fakeDispatchChain) { n = f.byBuilderCalls })
	return n
}

// I1: a failed recovery never holds a claim's advance back, and is retried
// per Builder until it succeeds; a malformed answer is not retried.
func TestClaimRecoveryFailureDoesNotBlockTheAdvance(t *testing.T) {
	x, tx := claimHarness(t)
	tx.setReject("account sequence mismatch")
	rec := x.committed(t)
	d := rec.ClaimFromHeight
	x.atHeight(t, d) // claimable, one attempt
	x.open()         // a restart: recovery is due
	x.chain.with(func(f *fakeDispatchChain) { f.byBuilderErr = errors.New("node unreachable") })
	x.sweepAt(d + 2)
	if n := len(tx.requests()); n != 2 {
		t.Fatalf("%d claims: the failed recovery stopped the advance", n)
	}
	before := x.byBuilderCalls()
	x.sweepAt(d + 3)
	if x.byBuilderCalls() != before+1 {
		t.Fatal("a transient recovery failure is retried on the next sweep")
	}
	x.chain.with(func(f *fakeDispatchChain) {
		f.byBuilderErr = fmt.Errorf("%w: repeated page token", chainclient.ErrInvalidClaimAnswer)
	})
	x.sweepAt(d + 4)
	before = x.byBuilderCalls()
	x.sweepAt(d + 5)
	if x.byBuilderCalls() != before {
		t.Fatal("a malformed Keeper answer is permanent: not asked again")
	}
}

// Item 10: the record names this ticket, the task view keeps disagreeing.
// It is re-checked per height and fails closed after ConflictGraceBlocks.
func TestWinnerConflictFailsClosedAfterItsGrace(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t) // ClaimRecheckBlocks 3: the grace defaults to it
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 300)
	x.chain.with(func(f *fakeDispatchChain) { f.assignment.WinnerWorker = hrBuilderB })
	d := rec.ClaimFromHeight
	for _, h := range []uint64{d, d + 1, d + 2} {
		x.sweepAt(h)
		if got := x.record(t); got.State != layout.DispatchAccepted || !x.leaseHeld(t) {
			t.Fatalf("height %d: state %s: re-checked inside the grace", h, got.State)
		}
	}
	x.sweepAt(d + 3)
	got := x.record(t)
	if got.State != layout.DispatchConflict || x.leaseHeld(t) || x.leaseCount(t) != 0 || !x.infer.stopped(rec.TicketHash) || len(tx.requests()) != 0 {
		t.Fatalf("state %s, %d leases: fails closed, never claims", got.State, x.leaseCount(t))
	}
	if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); err != nil {
		t.Fatal("the conflict's record is kept")
	}
}

// M4: our ticket recorded under another operator is a conflict, not a claim.
func TestRecordOfOurTicketUnderAnotherOperatorIsNotClaimable(t *testing.T) {
	x, tx := claimHarness(t)
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrBuilderB, 120, 300)
	x.sweepAt(rec.ClaimFromHeight)
	if got := x.record(t); got.State != layout.DispatchAccepted || len(tx.requests()) != 0 {
		t.Fatalf("state %s, %d claims", got.State, len(tx.requests()))
	}
	x.sweepAt(rec.ClaimFromHeight + 3)
	if got := x.record(t); got.State != layout.DispatchConflict || len(tx.requests()) != 0 {
		t.Fatalf("state %s, %d claims", got.State, len(tx.requests()))
	}
}

// I2: nothing outside the store is retired for a ticket that cannot be
// deleted yet, and a conflict's evidence scope is never dropped.
func TestGCChecksDeletabilityBeforeDroppingTheScope(t *testing.T) {
	ctx := context.Background()
	scopeOf := func(x *dispatchHarness, rec layout.DispatchRecord) codec.Hash {
		scope := codec.Hash(layout.DispatchEvidenceScope(rec.TaskHash, rec.TicketHash))
		if _, err := x.ev.Write(ctx, evidence.WriteRequest{TaskHash: scope, TaskID: "t", Kind: "worker-output-fin", Data: []byte("fin")}); err != nil {
			t.Fatal(err)
		}
		return scope
	}
	t.Run("still owning its inference", func(t *testing.T) {
		x, _ := claimHarness(t)
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		rec := x.record(t)
		if err := layout.InferAssignmentBatch(ctx, x.st, rec.TaskHash, layout.TaskRecord{}, layout.InferRecord{TaskID: "t", DispatchTicketHash: rec.TicketHash, Stage: layout.StageQueued}); err != nil {
			t.Fatal(err)
		}
		if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF)); err != nil {
			t.Fatal(err)
		}
		scope := scopeOf(x, rec)
		x.atHeight(t, rec.ClaimFromHeight+75)
		if _, err := x.ev.ReadTaskKind(ctx, scope, "worker-output-fin"); err != nil {
			t.Fatal("the scope of a ticket that still owns its InferRecord is kept")
		}
		if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); err != nil {
			t.Fatal("and so is its record")
		}
	})
	t.Run("conflict", func(t *testing.T) {
		x, _ := claimHarness(t)
		rec := x.committed(t)
		x.chainRecords(t, x.fx.ticketHash(), hrBuilderB, 120, 300)
		x.sweepAt(rec.ClaimFromHeight + 3)
		if x.record(t).State != layout.DispatchConflict {
			t.Fatal("setup: conflict")
		}
		scope := scopeOf(x, rec)
		x.sweepAt(rec.ClaimFromHeight + 75)
		if _, err := x.ev.ReadTaskKind(ctx, scope, "worker-output-fin"); err != nil {
			t.Fatal("a conflict's evidence scope is never dropped")
		}
	})
}

// M8: a recorded ticket is kept until max(D_ticket, infer_deadline) + span.
func TestRecordedTicketRetentionRunsFromItsInferDeadline(t *testing.T) {
	ctx := context.Background()
	x, _ := claimHarness(t)
	rec := x.committed(t)
	deadline := rec.ClaimFromHeight + 100
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, deadline)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, deadline)); err != nil {
		t.Fatal(err)
	}
	if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil {
		t.Fatal(err)
	}
	x.atHeight(t, rec.ClaimFromHeight+75)
	if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); err != nil {
		t.Fatal("kept past D_ticket + span: the infer deadline is later")
	}
	x.atHeight(t, deadline+75)
	if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("collected at infer deadline + span: %v", err)
	}
}

// M1: a revoke gives back a task-key lease its ticket already holds.
func TestRevokeReleasesATaskKeyLease(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	if _, err := layout.RebindWorkerLease(ctx, x.st, rec.TicketHash, rec.TaskID); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF)); err != nil {
		t.Fatal(err)
	}
	if n := x.leaseCount(t); n != 0 {
		t.Fatalf("%d leases after the revoke", n)
	}
}

// M5: a record collected under a claim write is "moved", not an error.
func TestUpdateLockedTreatsAMissingRecordAsMoved(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	_, moved, err := x.d.updateLocked(context.Background(), layout.StoredHash{0x99}, func(*layout.DispatchRecord) error { return nil })
	if err != nil || !moved {
		t.Fatalf("moved %v, %v", moved, err)
	}
}
