package daemon

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestDispatchOfferAcceptsInWriteOrder(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	th := x.fx.ticketHash()
	msgs := x.a.messages()
	if len(msgs) != 2 {
		t.Fatalf("enqueued %d messages, want accept then input request", len(msgs))
	}
	acc, ok := msgs[0].(*taskv1.DispatchAcceptV1)
	if !ok {
		t.Fatalf("first message is %T, want DispatchAcceptV1", msgs[0])
	}
	req, ok := msgs[1].(*nexusv1.DispatchInputRequestV1)
	if !ok {
		t.Fatalf("second message is %T, want DispatchInputRequestV1", msgs[1])
	}
	cortexSigned(t, acc, acc.GetServiceSignature())
	cortexSigned(t, req, req.GetServiceSignature())
	if !bytes.Equal(acc.GetDispatchTicketHash(), th[:]) || !proto.Equal(acc.GetMember(), x.fx.ticket.GetTarget()) ||
		acc.GetServiceAuthorizationNonce() != 7 || acc.GetChainId() != dpChainID || !bytes.Equal(acc.GetTaskHash(), x.fx.ticket.GetTaskHash()) {
		t.Fatalf("accept = %v", acc)
	}
	ad, err := dispatchwire.Digest(acc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req.GetDispatchAcceptDigest(), ad[:]) || !bytes.Equal(req.GetDispatchTicketHash(), th[:]) {
		t.Fatalf("input request = %v", req)
	}
	deadline := x.now.UnixMilli() + 2_000
	if x.a.outgoing(0).ExpiresAtUnixMilli != deadline || x.a.outgoing(1).ExpiresAtUnixMilli != deadline {
		t.Fatal("accept and first input request both expire at the local accept deadline (C4)")
	}
	rec := x.record(t)
	raw, err := dispatchwire.Raw(acc)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != layout.DispatchAccepted || !bytes.Equal(rec.Accept, raw) || rec.AcceptDigest != layout.StoredHash(ad) ||
		rec.AcceptSeq != 1 || rec.InputRequestSeq != 2 || rec.ClaimFromHeight != 109+dpRecordDeadline || len(rec.SignedOrder) == 0 {
		t.Fatalf("record = %+v", rec)
	}
	if held, err := layout.HasWorkerLease(ctx, x.st, rec.TicketHash); err != nil || !held {
		t.Fatal("the lease is held from before the accept is signed (W3)")
	}
	if free, _ := x.leases.FreeSlots(); free != 1 {
		t.Fatalf("free = %d, want 1", free)
	}
	if x.hr.notifications() == 0 {
		t.Fatal("an accept takes a slot: the standing handraise must be re-evaluated (W4)")
	}
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if len(x.a.messages()) != 2 {
		t.Fatal("a redelivered offer is answered from the record, never re-signed or resent")
	}
}

func TestDispatchOfferCheckOneDropsWithoutSigning(t *testing.T) {
	for _, c := range []struct {
		name    string
		builder string
		mutate  func(*dispatchHarness)
	}{
		{"unconfigured Builder", hrBuilderB, nil},
		{"no standing handraise", hrBuilderA, func(x *dispatchHarness) { x.hr.forget(hrBuilderA) }},
		{"standing handraise expired", hrBuilderA, func(x *dispatchHarness) { x.chain.with(func(f *fakeDispatchChain) { f.height = 201 }) }},
		{"root not held", hrBuilderA, func(x *dispatchHarness) { x.hr.dropRoots() }},
		{"VRF output", hrBuilderA, func(x *dispatchHarness) { x.fx.ticket.VrfOutput[0] ^= 1; x.fx.signTicket(hrBuilderKey) }},
		{"Builder signature", hrBuilderA, func(x *dispatchHarness) { x.fx.signTicket(hrCortexKey) }},
		{"target", hrBuilderA, func(x *dispatchHarness) {
			x.fx.ticket.Target.OperatorAddress = hrBuilderB
			x.fx.signTicket(hrBuilderKey)
		}},
		{"accept deadline", hrBuilderA, func(x *dispatchHarness) { x.fx.ticket.AcceptDeadlineMs = 0; x.fx.signTicket(hrBuilderKey) }},
		{"unverified beacon", hrBuilderA, func(x *dispatchHarness) { x.chain.with(func(f *fakeDispatchChain) { f.epoch.Verified = false }) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			x := newDispatchHarness(t, 2, nil)
			if c.mutate != nil {
				c.mutate(x)
			}
			err := x.d.HandleOffer(ctx, c.builder, x.fx.offer())
			if !errors.Is(err, ErrOfferDropped) {
				t.Fatalf("err = %v, want ErrOfferDropped", err)
			}
			if len(x.a.messages()) != 0 {
				t.Fatal("check 1 failures are dropped: no reject is ever signed")
			}
			if _, err := layout.GetDispatchRecord(ctx, x.st, layout.StoredHash(x.fx.ticketHash())); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a dropped offer leaves no record: %v", err)
			}
			if free, _ := x.leases.FreeSlots(); free != 2 {
				t.Fatal("a dropped offer takes no lease")
			}
		})
	}
}

func TestDispatchOfferRejectsWithTheClosedReasonSet(t *testing.T) {
	const (
		noCapacity = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_NO_CAPACITY
		profile    = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_PROFILE_UNAVAILABLE
		expired    = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_EXPIRED
		invalid    = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_INVALID_TICKET
	)
	stranger := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{4}, 32))
	for _, c := range []struct {
		name        string
		mutate      func(*dispatchHarness)
		reason      taskv1.DispatchRejectReasonV1
		class       string
		builderSide bool
	}{
		{"service key rotation pending (issue #83)", func(x *dispatchHarness) {
			x.chain.with(func(f *fakeDispatchChain) { f.cortexKey.HasPendingRotation = true })
		}, noCapacity, classRotationPending, false},
		{"order does not hash to task_hash", func(x *dispatchHarness) {
			x.fx.order.Order.MaxFee.AtomicUnits = "2000"
			x.fx.signOrder(dpUserKey)
		}, invalid, classOrderInvalid, false},
		{"order expired", func(x *dispatchHarness) { x.fx.order.Order.OrderExpireHeight = 140; x.fx.seal() }, expired, classOrderExpired, false},
		{"user signature", func(x *dispatchHarness) { x.fx.signOrder(stranger) }, invalid, classOrderInvalid, false},
		{"BuilderSet changed", func(x *dispatchHarness) { x.chain.with(func(f *fakeDispatchChain) { f.set.BuilderSetID = "8" }) }, invalid, classOrderInvalid, false},
		{"bound_change_height (2a)", func(x *dispatchHarness) {
			x.chain.with(func(f *fakeDispatchChain) { f.session.BoundChangeHeight = 106 })
		}, invalid, classStaleBoundChange, true},
		{"bond unbonding", func(x *dispatchHarness) { x.chain.with(func(f *fakeDispatchChain) { f.bond.Status = "UNBONDING" }) }, noCapacity, classWinnerIneligible, false},
		{"bond below min_stake", func(x *dispatchHarness) { x.chain.with(func(f *fakeDispatchChain) { f.bond.ActiveBond = 99 }) }, noCapacity, classWinnerIneligible, false},
		{"liability above available bond", func(x *dispatchHarness) {
			x.chain.with(func(f *fakeDispatchChain) { f.liability.MinTaskLiability = 1_001 })
		}, noCapacity, classWinnerIneligible, false},
		{"no support on chain", func(x *dispatchHarness) {
			x.chain.with(func(f *fakeDispatchChain) { delete(f.scopes, config.MinPriceBidKey(hrModelAB, 1)) })
		}, profile, classProfileUnavailable, false},
		{"profile draining", func(x *dispatchHarness) {
			x.local.with(func(l *fakeHandraiseLocal) {
				l.drainProfiles = map[HandraiseProfile]bool{hrProfile(hrModelAB, 1): true}
			})
		}, profile, classProfileUnavailable, false},
		{"price below min_price_bid", func(x *dispatchHarness) {
			x.reconfigure(func(c *DispatcherConfig) { c.MinPriceBid = map[string]uint64{config.MinPriceBidKey(hrModelAB, 1): 11} })
		}, profile, classPriceBelowMin, false},
		{"ticket input_hash", func(x *dispatchHarness) {
			x.fx.ticket.InputHash = bytes.Repeat([]byte{7}, 32)
			x.fx.signTicket(hrBuilderKey)
		}, invalid, classInputMismatch, false},
		{"input above the local limit", func(x *dispatchHarness) {
			x.reconfigure(func(c *DispatcherConfig) { c.MaxInputBytes = 8 })
		}, noCapacity, classInputTooLarge, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			x := newDispatchHarness(t, 2, nil)
			c.mutate(x)
			if err := x.handle(ctx); err != nil {
				t.Fatalf("a reject is an answer, not an error: %v", err)
			}
			msgs := x.a.messages()
			if len(msgs) != 1 {
				t.Fatalf("enqueued %d messages, want one reject", len(msgs))
			}
			rj, ok := msgs[0].(*taskv1.DispatchRejectV1)
			if !ok {
				t.Fatalf("enqueued %T, want a reject", msgs[0])
			}
			cortexSigned(t, rj, rj.GetServiceSignature())
			th := x.fx.ticketHash()
			if rj.GetRejectReason() != c.reason || !bytes.Equal(rj.GetDispatchTicketHash(), th[:]) ||
				!proto.Equal(rj.GetMember(), x.fx.ticket.GetTarget()) || rj.GetServiceAuthorizationNonce() != 7 {
				t.Fatalf("reject = %v", rj)
			}
			if x.a.outgoing(0).ExpiresAtUnixMilli != x.now.UnixMilli()+2_000 {
				t.Fatal("a reject is not sent after the accept deadline")
			}
			rec := x.record(t)
			if rec.State != layout.DispatchRejected || rec.RejectClass != c.class || rec.RejectBuilderSide != c.builderSide || rec.RejectSeq != 1 {
				t.Fatalf("record = %+v", rec)
			}
			if held, err := layout.HasWorkerLease(ctx, x.st, rec.TicketHash); err != nil || held {
				t.Fatal("a rejected ticket holds no lease")
			}
			if err := x.handle(ctx); err != nil {
				t.Fatal(err)
			}
			if len(x.a.messages()) != 1 {
				t.Fatal("a redelivered offer is never answered twice, and never accepted after a reject")
			}
		})
	}
}

func TestDispatchOfferAcceptsALiveSessionKey(t *testing.T) {
	delegate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{5}, 32))
	addr, err := nodewire.EVMAccountAddress("trueopen", delegate.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	raw20, err := nodewire.CanonicalOperatorAddressBytes("session_key", addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		expiry   uint64
		accepted bool
	}{{"live grant", 150, true}, {"grant expired at 149", 149, false}} {
		t.Run(c.name, func(t *testing.T) {
			x := newDispatchHarness(t, 2, nil)
			x.fx.signOrder(delegate)
			x.chain.with(func(f *fakeDispatchChain) {
				f.session.SessionKey, f.session.SessionKeySetHeight, f.session.SessionKeyExpiryHeight = raw20, 50, c.expiry
			})
			if err := x.handle(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, accepted := x.a.messages()[0].(*taskv1.DispatchAcceptV1); accepted != c.accepted {
				t.Fatalf("accepted = %v, want %v", accepted, c.accepted)
			}
		})
	}
}

func TestDispatchOfferResignsTheHandraiseBeforeACapacityReject(t *testing.T) {
	ctx := context.Background()
	occupy := func(x *dispatchHarness) {
		if ok, err := x.leases.Acquire(ctx, layout.WorkerLease{TicketHash: layout.StoredHash{0xee}, TaskID: layout.StoredHash{0xee}, Builder: hrBuilderB, ExpiryHeight: 999}); err != nil || !ok {
			t.Fatalf("occupy: %v %v", ok, err)
		}
	}
	x := newDispatchHarness(t, 1, nil)
	occupy(x)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := x.log.all(), []string{"handraise:refresh", "enqueue:task.v1.DispatchRejectV1"}; !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v: the handraise is re-signed before the reject", got, want)
	}
	if rec := x.record(t); rec.RejectClass != classNoFreeSlot ||
		rec.RejectReason != int32(taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_NO_CAPACITY) {
		t.Fatalf("record = %+v", rec)
	}

	y := newDispatchHarness(t, 1, nil)
	occupy(y)
	y.hr.setFree(hrBuilderA, 0)
	if err := y.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := y.log.all(); !slices.Equal(got, []string{"enqueue:task.v1.DispatchRejectV1"}) {
		t.Fatalf("events %v: a handraise that already offers no slot needs no re-sign", got)
	}

	z := newDispatchHarness(t, 1, nil)
	occupy(z)
	z.hr.setRefreshErr(errors.New("signer down"))
	if err := z.handle(ctx); !builderclient.IsRetryable(err) {
		t.Fatalf("err = %v, want retryable", err)
	}
	if len(z.a.messages()) != 0 {
		t.Fatal("no reject may go out before the handraise is re-signed")
	}
}

func TestDispatchOfferIsNotSignedWithoutTimeToAnswer(t *testing.T) {
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) { c.AcceptSignMargin = 2_500 * time.Millisecond })
	if err := x.handle(context.Background()); !errors.Is(err, ErrOfferDropped) {
		t.Fatalf("err = %v, want dropped", err)
	}
	if len(x.a.messages()) != 0 {
		t.Fatal("nothing is signed past the accept deadline (C4)")
	}
	if free, _ := x.leases.FreeSlots(); free != 2 {
		t.Fatal("no lease is kept")
	}
}

func TestDispatchNewRoundReleasesTheOldLeaseFirst(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 1, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	old := layout.StoredHash(x.fx.ticketHash())
	x.fx.ticket.DispatchRound, x.fx.ticket.Rank = 2, 3
	x.fx.signTicket(hrBuilderKey)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := x.a.messages()
	if len(msgs) != 4 {
		t.Fatalf("enqueued %d messages", len(msgs))
	}
	if _, ok := msgs[2].(*taskv1.DispatchAcceptV1); !ok {
		t.Fatal("capacity 1 still accepts the new round: the old round's lease is released first (W3)")
	}
	prev, err := layout.GetDispatchRecord(ctx, x.st, old)
	if err != nil || prev.State != layout.DispatchSuperseded {
		t.Fatalf("old record = %+v, %v", prev, err)
	}
	if held, _ := layout.HasWorkerLease(ctx, x.st, old); held {
		t.Fatal("the old round's lease is released")
	}
	if !x.infer.stopped(old) {
		t.Fatal("the old round's inference is stopped")
	}
	if rec := x.record(t); rec.State != layout.DispatchAccepted {
		t.Fatalf("new record = %+v", rec)
	}
}

// Q18: every chain read of one offer evaluation is pinned to the one committed
// height it started from.
func TestDispatchOfferReadsAtOneCommittedHeight(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls, heights := x.chain.reads()
	if calls != 1 || len(heights) != 1 || heights[150] == 0 {
		t.Fatalf("CommittedHeight called %d times, reads pinned at %v: want one height for the whole evaluation", calls, heights)
	}
}

// Q9: an accept whose enqueue may have landed (the process stopped before its
// outbox sequence was recorded) may have reached the Builder, so it keeps its
// lease and its accepted state past the deadline.
func TestDispatchAcceptOfUnknownFateKeepsItsLease(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	ctx, cancel := context.WithCancel(context.Background())
	x.a.setDuring(cancel) // the enqueue lands, then the process stops
	if err := x.d.HandleOffer(ctx, hrBuilderA, x.fx.offer()); err == nil {
		t.Fatal("recording the outbox sequence failed")
	}
	x.a.setDuring(nil)
	if rec := x.record(t); rec.State != layout.DispatchAccepted || rec.AcceptSeq != 0 {
		t.Fatalf("record = %+v", rec)
	}
	x.open() // restart
	x.now = x.now.Add(3 * time.Second)
	if err := x.handle(context.Background()); err != nil {
		t.Fatalf("the redelivered offer past the deadline: %v", err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchAccepted {
		t.Fatalf("record = %+v: an accept that may have been sent is never released as unsent", rec)
	}
	if held, _ := layout.HasWorkerLease(context.Background(), x.st, rec.TicketHash); !held {
		t.Fatal("it keeps its lease")
	}
}
