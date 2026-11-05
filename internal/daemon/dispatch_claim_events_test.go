package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func TestCompensationEventsSyncTheClaim(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	x.landClaims(tx)
	rec := x.committed(t)
	x.atHeight(t, rec.ClaimFromHeight)
	pending := x.record(t)
	fact := DispatchEventFact{Type: chainclient.KeeperEventDispatchCompensationPaid, Height: pending.RebuttalDeadlineHeight,
		TaskID: rec.TaskID, TicketHash: rec.TicketHash, Builder: hrBuilderA, Worker: hrCortex}
	if err := x.d.ObserveDispatchEvent(ctx, fact); err != nil || x.record(t).State != layout.DispatchClaimPending {
		t.Fatalf("the event is a hint; the query still says pending: %v", err)
	}
	paid := x.chainClaim(pending, claimPaid, rec.ClaimFromHeight+1)
	paid.PaidAmount = "40"
	x.setClaim(paid)
	if err := x.d.ObserveDispatchEvent(ctx, fact); err != nil || x.record(t).State != layout.DispatchClaimPaid {
		t.Fatalf("paid from the query: %v", err)
	}
	other := fact
	other.Worker = hrBuilderB
	if err := x.d.ObserveDispatchEvent(ctx, other); err != nil {
		t.Fatal("another worker's claim is not this node's concern")
	}
	y, _ := claimHarness(t)
	yr := y.committed(t)
	y.atHeight(t, yr.ClaimFromHeight) // claimable, nothing on chain
	f := fact
	f.TicketHash, f.TaskID = yr.TicketHash, yr.TaskID
	f.Type = chainclient.KeeperEventDispatchCompensationClaimed
	if err := y.d.ObserveDispatchEvent(ctx, f); !builderclient.IsRetryable(err) {
		t.Fatalf("a claimed event the query does not show yet retries: %v", err)
	}
}

func TestClaimsRecoverAfterAGap(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	x.landClaims(tx)
	rec := x.committed(t)
	x.atHeight(t, rec.ClaimFromHeight)
	paid := x.chainClaim(x.record(t), claimPaid, rec.ClaimFromHeight+1)
	paid.PaidAmount = "40"
	x.setClaim(paid) // resolved while the process was down; the event is lost
	x.open()
	before := 0
	x.chain.with(func(f *fakeDispatchChain) { before = f.byBuilderCalls })
	if err := x.d.SweepClaims(ctx); err != nil {
		t.Fatal(err)
	}
	after := 0
	x.chain.with(func(f *fakeDispatchChain) { after = f.byBuilderCalls })
	if got := x.record(t); got.State != layout.DispatchClaimPaid || after != before+1 {
		t.Fatalf("state %s, by-builder pages read %d times", got.State, after-before)
	}
	if err := x.d.SweepClaims(ctx); err != nil {
		t.Fatal(err)
	}
	x.chain.with(func(f *fakeDispatchChain) {
		if f.byBuilderCalls != after {
			t.Fatal("recovery runs once per process")
		}
	})
}

// wire b30fba8 keys claims by (session, sequence): a DISMISSED claim may be
// replaced by another ticket's claim, after which this ticket answers
// NotFound for good. A rebutted event read at or past its height must not
// retry the event page forever; the claim is dismissed locally.
func TestRebuttedClaimReplacedAtItsSequenceIsDismissed(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	x.landClaims(tx)
	rec := x.committed(t)
	x.atHeight(t, rec.ClaimFromHeight)
	pending := x.record(t)
	if pending.State != layout.DispatchClaimPending {
		t.Fatalf("state %s, want a pending claim", pending.State)
	}
	x.chain.with(func(f *fakeDispatchChain) { delete(f.claims, [32]byte(rec.TicketHash)) })
	var height uint64
	x.chain.with(func(f *fakeDispatchChain) { height = f.height })
	fact := DispatchEventFact{Type: chainclient.KeeperEventDispatchCompensationRebutted, Height: height + 1,
		TaskID: rec.TaskID, TicketHash: rec.TicketHash, Builder: hrBuilderA, Worker: hrCortex}
	if err := x.d.ObserveDispatchEvent(ctx, fact); !builderclient.IsRetryable(err) {
		t.Fatalf("an event past the served height is a lag and retries: %v", err)
	}
	fact.Height = height
	if err := x.d.ObserveDispatchEvent(ctx, fact); err != nil {
		t.Fatalf("a replaced claim must not hold the event page: %v", err)
	}
	if got := x.record(t); got.State != layout.DispatchClaimDismissed {
		t.Fatalf("state %s, want dismissed", got.State)
	}
}

// A claimed or paid event whose ticket no longer resolves at or past its
// height is not retried either; only a rebuttal changes local state.
func TestClaimEventForAnUnqueryableClaimIsNotRetried(t *testing.T) {
	ctx := context.Background()
	x, tx := claimHarness(t)
	x.landClaims(tx)
	rec := x.committed(t)
	x.atHeight(t, rec.ClaimFromHeight)
	x.chain.with(func(f *fakeDispatchChain) { delete(f.claims, [32]byte(rec.TicketHash)) })
	var height uint64
	x.chain.with(func(f *fakeDispatchChain) { height = f.height })
	fact := DispatchEventFact{Type: chainclient.KeeperEventDispatchCompensationPaid, Height: height,
		TaskID: rec.TaskID, TicketHash: rec.TicketHash, Builder: hrBuilderA, Worker: hrCortex}
	if err := x.d.ObserveDispatchEvent(ctx, fact); err != nil {
		t.Fatal(err)
	}
	if got := x.record(t); got.State != layout.DispatchClaimPending {
		t.Fatalf("state %s, want it left pending", got.State)
	}
}
