package daemon

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestDispatchSweepReleasesAnAcceptThatWasNeverSent(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.a.markUnsent(1) // the accept is enqueued as seq 1 and never reaches a stream
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.now = x.now.Add(time.Second)
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := x.record(t); rec.State != layout.DispatchAccepted {
		t.Fatalf("before the deadline the outbox may still send it: %+v", rec)
	}
	notified := x.hr.notifications()
	x.now = x.now.Add(1_500 * time.Millisecond)
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchAcceptUnsent {
		t.Fatalf("record = %+v, want accept-unsent", rec)
	}
	if held, _ := hasWorkerLease(ctx, x.st, rec.TicketHash); held {
		t.Fatal("an accept never sent before the deadline releases its lease (C4)")
	}
	if x.hr.notifications() <= notified {
		t.Fatal("the freed slot re-evaluates the standing handraise")
	}
	if err := x.handle(ctx); !errors.Is(err, ErrOfferDropped) {
		t.Fatalf("a redelivered offer after the release: err = %v, want dropped", err)
	}
	if len(x.a.messages()) != 2 {
		t.Fatal("nothing is signed or sent again")
	}
}

func TestDispatchSweepReRequestsInputOnlyForSentAccepts(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) {
		c.InputRetryEvery, c.InputRequestTTL = 5*time.Second, 30*time.Second
	})
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.now = x.now.Add(time.Second)
	if err := x.d.Sweep(ctx); err != nil || len(x.a.messages()) != 2 {
		t.Fatalf("no re-request inside the retry interval: %v, %d", err, len(x.a.messages()))
	}
	x.now = x.now.Add(5 * time.Second)
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := x.a.messages()
	if len(msgs) != 3 {
		t.Fatalf("enqueued %d messages, want a re-sent input request", len(msgs))
	}
	if _, ok := msgs[2].(*nexusv1.DispatchInputRequestV1); !ok || x.a.outgoing(2).ExpiresAtUnixMilli != x.now.Add(30*time.Second).UnixMilli() {
		t.Fatalf("third message = %T", msgs[2])
	}
	if rec := x.record(t); rec.State != layout.DispatchAccepted {
		t.Fatal("a sent accept past its deadline stays accepted; S6 settles it at D_ticket")
	}
	x.d.Rebound(hrBuilderA)
	if err := x.d.Sweep(ctx); err != nil || len(x.a.messages()) != 4 {
		t.Fatalf("a new binding re-requests input at once: %v, %d", err, len(x.a.messages()))
	}
}

func TestDispatchRestartResumesTheStoredAcceptAndReleasesOrphanLeases(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.a.setFail(errors.New("outbox down"))
	if err := x.handle(ctx); !builderclient.IsRetryable(err) {
		t.Fatalf("err = %v, want retryable", err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchAccepted || rec.AcceptSeq != 0 {
		t.Fatalf("record = %+v: the accept is durable before it is enqueued", rec)
	}
	orphan := layout.WorkerLease{TicketHash: layout.StoredHash{0xee}, TaskID: layout.StoredHash{0xee}, Builder: hrBuilderA, ExpiryHeight: 1}
	if ok, _, err := layout.AcquireWorkerLease(ctx, x.st, orphan, 9); err != nil || !ok {
		t.Fatal(err)
	}
	x.a.setFail(nil)
	x.open() // restart
	if held, _ := hasWorkerLease(ctx, x.st, orphan.TicketHash); held {
		t.Fatal("a lease with no accepted ticket is released at start")
	}
	if held, _ := hasWorkerLease(ctx, x.st, rec.TicketHash); !held {
		t.Fatal("the accepted ticket keeps its lease")
	}
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	msgs := x.a.messages()
	if len(msgs) != 2 {
		t.Fatalf("enqueued %d messages", len(msgs))
	}
	acc, ok := msgs[0].(*taskv1.DispatchAcceptV1)
	if !ok {
		t.Fatalf("first message = %T", msgs[0])
	}
	raw, err := dispatchwire.Raw(acc)
	if err != nil || !bytes.Equal(raw, rec.Accept) {
		t.Fatal("the stored accept is sent as signed, never re-signed")
	}
}

// Q9: the sweep never releases an accept whose enqueue may have landed; it
// keeps asking for the input instead.
func TestDispatchSweepKeepsAnAcceptOfUnknownFate(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	ctx, cancel := context.WithCancel(context.Background())
	x.a.setDuring(cancel) // the enqueue lands, then the process stops
	if err := x.d.HandleOffer(ctx, hrBuilderA, x.fx.offer()); err == nil {
		t.Fatal("recording the outbox sequence failed")
	}
	x.a.setDuring(nil)
	x.open() // restart
	x.now = x.now.Add(3 * time.Second)
	if err := x.d.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchAccepted {
		t.Fatalf("record = %+v: an accept that may have been sent is never released as unsent", rec)
	}
	if held, _ := hasWorkerLease(context.Background(), x.st, rec.TicketHash); !held {
		t.Fatal("it keeps its lease")
	}
	msgs := x.a.messages()
	if _, ok := msgs[len(msgs)-1].(*nexusv1.DispatchInputRequestV1); !ok {
		t.Fatalf("last message = %T, want an input request", msgs[len(msgs)-1])
	}
}

// The C4 deadlines kept in memory for offers seen by this process are dropped
// once they are long past; persisted records keep their own.
func TestDispatchSweepForgetsLongPastDeadlines(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	x.hr.dropRoots()
	if err := x.handle(context.Background()); !errors.Is(err, ErrOfferDropped) {
		t.Fatalf("err = %v, want dropped", err)
	}
	if n := x.deadlines(); n != 1 {
		t.Fatalf("deadlines = %d, want the dropped offer's", n)
	}
	x.now = x.now.Add(time.Minute)
	if err := x.d.Sweep(context.Background()); err != nil || x.deadlines() != 1 {
		t.Fatalf("a recent deadline is kept: %v, %d", err, x.deadlines())
	}
	x.now = x.now.Add(time.Hour)
	if err := x.d.Sweep(context.Background()); err != nil || x.deadlines() != 0 {
		t.Fatalf("a long-past deadline is forgotten: %v, %d", err, x.deadlines())
	}
}

func (x *dispatchHarness) deadlines() int {
	x.d.mu.Lock()
	defer x.d.mu.Unlock()
	return len(x.d.deadline)
}
