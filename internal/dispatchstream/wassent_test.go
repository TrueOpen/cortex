package dispatchstream

import (
	"bytes"
	"context"
	"testing"
)

func TestWasSentReportsWhatReachedAStream(t *testing.T) {
	ctx := context.Background()
	h := startSession(t, nil)
	s := h.current()
	// Now is fixed at 1_000_000 ms: this one is already expired and is never sent.
	stale, err := s.Enqueue(ctx, Outgoing{Message: reject(1), ExpiresAtUnixMilli: 999_999})
	if err != nil {
		t.Fatal(err)
	}
	live, err := s.Enqueue(ctx, Outgoing{Message: reject(2), ExpiresAtUnixMilli: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := h.bind(t)
	f := c.recvSkippingKeepalive()
	if f.GetReject() == nil || !bytes.Equal(f.GetReject().GetDispatchTicketHash(), h32(4)) {
		t.Fatalf("first business frame = %v, want the live reject", f)
	}
	eventually(t, "the live message marked sent", func() bool { return s.WasSent(live) })
	if s.WasSent(stale) {
		t.Fatal("an expired message was never transmitted")
	}
	h.crash()
	h.waitStopped(t)
	h.run(t)
	s2 := h.current()
	if !s2.WasSent(stale) || !s2.WasSent(live) {
		t.Fatal("after a restart anything enqueued before it may have been sent")
	}
	next, err := s2.Enqueue(ctx, Outgoing{Message: reject(3), ExpiresAtUnixMilli: 999_999})
	if err != nil {
		t.Fatal(err)
	}
	if s2.WasSent(next) {
		t.Fatal("a message enqueued by this Session and never written was not sent")
	}
}
