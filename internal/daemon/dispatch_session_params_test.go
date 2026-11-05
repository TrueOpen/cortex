package daemon

import (
	"context"
	"fmt"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// freezeSession gives the fake Session its own frozen dispatch policy, apart
// from the current Task params (wire b30fba8, QuerySessionResponse.params).
func freezeSession(x *dispatchHarness, edit func(*chainclient.DispatchParamsSnapshot)) {
	x.chain.with(func(f *fakeDispatchChain) {
		f.session.Dispatch = f.params
		edit(&f.session.Dispatch)
	})
}

// D_ticket is the order anchor plus the Session's frozen record deadline;
// a later governance change of the current params does not move it.
func TestDispatchTicketDeadlineUsesTheSessionsFrozenPolicy(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	freezeSession(x, func(p *chainclient.DispatchParamsSnapshot) { p.RecordDeadlineBlocks = dpRecordDeadline + 7 })
	x.chain.with(func(f *fakeDispatchChain) { f.params.RecordDeadlineBlocks = dpRecordDeadline + 50 })
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	anchor := max(x.fx.order.Order.EarliestSubmitHeight, x.fx.ticket.BoundChangeHeight)
	if got := x.record(t).ClaimFromHeight; got != anchor+dpRecordDeadline+7 {
		t.Fatalf("ClaimFromHeight = %d, want %d from the Session's frozen record deadline", got, anchor+dpRecordDeadline+7)
	}
}

func TestDispatchOfferRefusesAnOrderBeyondTheSessionsLifetime(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	freezeSession(x, func(p *chainclient.DispatchParamsSnapshot) { p.MaxOrderLifetimeBlocks = 100 })
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	msgs := x.a.messages()
	if len(msgs) != 1 {
		t.Fatalf("enqueued %d messages, want one reject", len(msgs))
	}
	rj, ok := msgs[0].(*taskv1.DispatchRejectV1)
	if !ok || rj.GetRejectReason() != taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_INVALID_TICKET {
		t.Fatalf("enqueued %v, want an INVALID_TICKET reject", msgs[0])
	}
	if rec := x.record(t); rec.RejectClass != classOrderInvalid {
		t.Fatalf("record = %+v", rec)
	}
}

// The claim window is the Session's frozen one, and a claim needs the
// retained Session: a compacted Session, or a CLOSED one that closed at or
// before the order's anchor, admits no claim.
func TestClaimabilityReadsTheRetainedSession(t *testing.T) {
	t.Run("frozen claim window", func(t *testing.T) {
		x, tx := claimHarness(t)
		x.landClaims(tx)
		rec := x.committed(t)
		freezeSession(x, func(p *chainclient.DispatchParamsSnapshot) { p.CompensationClaimWindowBlocks = 33 })
		x.atHeight(t, rec.ClaimFromHeight)
		if got := x.record(t); got.ClaimWindowCloseHeight != rec.ClaimFromHeight+33 {
			t.Fatalf("claim window closes at %d, want %d", got.ClaimWindowCloseHeight, rec.ClaimFromHeight+33)
		}
	})
	anchor := func(x *dispatchHarness) uint64 {
		return max(x.fx.order.Order.EarliestSubmitHeight, x.fx.ticket.BoundChangeHeight)
	}
	for name, c := range map[string]struct {
		edit      func(x *dispatchHarness, f *fakeDispatchChain)
		claimable bool
	}{
		"compacted": {func(_ *dispatchHarness, f *fakeDispatchChain) { f.sessionErr = fmt.Errorf("gone: %w", chainclient.ErrNotFound) }, false},
		"closed at the anchor": {func(x *dispatchHarness, f *fakeDispatchChain) {
			f.session.Status, f.session.ClosedHeight = "CLOSED", anchor(x)
		}, false},
		"closed after the anchor": {func(x *dispatchHarness, f *fakeDispatchChain) {
			f.session.Status, f.session.ClosedHeight = "CLOSED", anchor(x)+1
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			x, tx := claimHarness(t)
			x.landClaims(tx)
			rec := x.committed(t)
			x.chain.with(func(f *fakeDispatchChain) { c.edit(x, f) })
			x.atHeight(t, rec.ClaimFromHeight)
			got := x.record(t)
			if c.claimable != (got.State == layout.DispatchClaimPending) || !c.claimable && got.State != layout.DispatchNotClaimable {
				t.Fatalf("state %s (%s), claimable = %v", got.State, got.StateReason, c.claimable)
			}
			if c.claimable != (len(tx.requests()) == 1) {
				t.Fatalf("%d claim requests", len(tx.requests()))
			}
		})
	}
}
