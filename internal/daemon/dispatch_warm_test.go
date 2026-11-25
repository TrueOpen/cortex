package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/store/layout"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// newWarmHarness serves the Dispatcher through a slowDispatchChain so the
// test can count the reads an offer makes and stall the chain.
func newWarmHarness(t *testing.T) (*dispatchHarness, *slowDispatchChain) {
	t.Helper()
	var slow *slowDispatchChain
	x := newDispatchHarness(t, 4, func(cfg *DispatcherConfig) {
		slow = &slowDispatchChain{DispatchChainView: cfg.Chain}
		cfg.Chain = slow
	})
	return x, slow
}

// nextOffer makes the harness offer a new dispatch round of the same order.
func (x *dispatchHarness) nextOffer(round uint32) {
	x.fx.ticket.DispatchRound = round
	x.fx.signTicket(hrBuilderKey)
}

func (x *dispatchHarness) lastIsAccept(t *testing.T) {
	t.Helper()
	msgs := x.a.messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		switch msgs[i].(type) {
		case *taskv1.DispatchAcceptV1:
			return
		case *taskv1.DispatchRejectV1:
			t.Fatalf("the offer was rejected: %v", msgs[i])
		}
	}
	t.Fatal("no accept was enqueued")
}

// #107: once the order-independent facts and the offer's Session are held
// for a height, an offer is answered without a single chain read.
func TestDispatchWarmAnswersAnOfferFromHeldFacts(t *testing.T) {
	ctx := context.Background()
	x, slow := newWarmHarness(t)
	x.d.warmOnce(ctx)
	if got := x.d.chain.WarmHeight(); got != 150 {
		t.Fatalf("held height %d, want 150", got)
	}
	// The first order of a Session reads the Session itself and notes it.
	before := slow.readCount()
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := slow.readCount() - before; got != 1 {
		t.Fatalf("the first offer of a Session made %d chain reads, want 1 (the Session)", got)
	}
	x.lastIsAccept(t)

	x.chain.with(func(f *fakeDispatchChain) { f.height = 151 })
	x.d.warmOnce(ctx)
	heightCalls, _ := x.chain.reads()
	before = slow.readCount()
	x.nextOffer(2)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := slow.readCount() - before; got != 0 {
		t.Fatalf("an offer of a held Session made %d chain reads, want none", got)
	}
	if calls, _ := x.chain.reads(); calls != heightCalls {
		t.Fatal("an offer at the held height must not ask for the committed height")
	}
	x.lastIsAccept(t)
}

// While the chain stalls, the last complete set keeps answering.
func TestDispatchWarmKeepsAnsweringThroughAChainStall(t *testing.T) {
	ctx := context.Background()
	x, slow := newWarmHarness(t)
	x.d.warmOnce(ctx)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.height = 151 })
	x.d.warmOnce(ctx)

	slow.stall(true)
	x.d.warmOnce(ctx) // fails: the held set stays
	if got := x.d.chain.WarmHeight(); got != 151 {
		t.Fatalf("held height %d after a failed refresh, want 151", got)
	}
	x.nextOffer(2)
	if err := x.handle(ctx); err != nil {
		t.Fatalf("an offer during a chain stall: %v", err)
	}
	x.lastIsAccept(t)
}

// Only an accept is decided at the held height: a Session the held height
// predates is read again at the committed height instead of being refused.
func TestDispatchWarmDecidesARejectAtTheCommittedHeight(t *testing.T) {
	ctx := context.Background()
	x, slow := newWarmHarness(t)
	x.d.warmOnce(ctx) // held at 150
	slow.mu.Lock()
	slow.sessionFrom = 151
	slow.mu.Unlock()
	x.chain.with(func(f *fakeDispatchChain) { f.height = 151 })

	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.lastIsAccept(t)
}

// A held set that trails the committed height by more than maxWarmLagBlocks
// is not used: the reads go back to the committed height.
func TestDispatchWarmIsNotUsedWhenItTrails(t *testing.T) {
	ctx := context.Background()
	x, _ := newWarmHarness(t)
	x.d.warmOnce(ctx) // held at 150
	x.chain.with(func(f *fakeDispatchChain) {
		f.height = 150 + maxWarmLagBlocks + 1
		f.nodeErr = errChainStalled // the refresh at the new height fails
	})
	x.d.warmOnce(ctx)
	if got := x.d.warmHeight(); got != 0 {
		t.Fatalf("a set %d blocks behind is still served at %d", maxWarmLagBlocks+1, got)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.nodeErr = nil })
	before, _ := x.chain.reads()
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if after, _ := x.chain.reads(); after != before+1 {
		t.Fatalf("CommittedHeight read %d times for the offer, want 1", after-before)
	}
	x.lastIsAccept(t)
}

// An order above a local limit is refused from the held facts alone: no chain
// read at all, the Session's included, even for the first order of a Session.
// On a slow link that read is what turned a reject the Builder could act on
// into a timeout.
func TestDispatchWarmRefusesAnOrderAboveALocalLimitWithoutAChainRead(t *testing.T) {
	ctx := context.Background()
	x, slow := newWarmHarness(t)
	x.d.cfg.MaxOutputTokens = 127 // the fixture order asks for 128
	x.d.warmOnce(ctx)
	before, sessions := slow.readCount(), x.chain.callCount("SessionAt")
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := slow.readCount() - before; got != 0 {
		t.Fatalf("the refusal made %d chain reads, want none", got)
	}
	if got := x.chain.callCount("SessionAt") - sessions; got != 0 {
		t.Fatalf("the refusal read the Session %d times", got)
	}
	msgs := x.a.messages()
	rj, ok := msgs[len(msgs)-1].(*taskv1.DispatchRejectV1)
	if !ok || rj.GetRejectReason() != reasonNoCapacity || rj.GetServiceAuthorizationNonce() != 7 {
		t.Fatalf("answer = %v, want a signed NO_CAPACITY reject", msgs[len(msgs)-1])
	}
	cortexSigned(t, rj, rj.GetServiceSignature())
	if rec := x.record(t); rec.State != layout.DispatchRejected || rec.RejectClass != classOutputBudgetTooLarge {
		t.Fatalf("record = %+v", rec)
	}
	if held, err := hasWorkerLease(ctx, x.st, layout.StoredHash(x.fx.ticketHash())); err != nil || held {
		t.Fatal("a refused ticket holds no lease")
	}
}

// The early refusal still needs check 1: a ticket that does not pass it at the
// held height is not rejected from there. It goes to the full evaluation at
// the committed height, which drops it without a signature.
func TestDispatchWarmDoesNotRejectAnUnverifiedTicketEarly(t *testing.T) {
	ctx := context.Background()
	x, _ := newWarmHarness(t)
	x.d.cfg.MaxOutputTokens = 127
	x.d.warmOnce(ctx)
	x.fx.ticket.BuilderServiceSignature = bytes.Repeat([]byte{1}, len(x.fx.ticket.BuilderServiceSignature))
	if err := x.handle(ctx); !errors.Is(err, ErrOfferDropped) {
		t.Fatalf("err = %v, want the offer dropped", err)
	}
	for _, m := range x.a.messages() {
		if _, ok := m.(*taskv1.DispatchRejectV1); ok {
			t.Fatal("a reject was signed for a ticket that fails check 1")
		}
	}
}
