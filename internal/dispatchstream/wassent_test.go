package dispatchstream

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
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

// A message is marked sent before Send is attempted: a failed Send may still
// have put bytes on the wire, and a false "maybe sent" is safe where a false
// "not sent" is not.
func TestWasSentIsMarkedBeforeASendThatFails(t *testing.T) {
	ctx := context.Background()
	h := startPrepared(t, nil, func(s *Session) {
		s.sendFrame = func(*conn, *rawFrame) error { return errors.New("broken pipe") }
	})
	seq, err := h.current().Enqueue(ctx, Outgoing{Message: reject(2), ExpiresAtUnixMilli: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	h.fake.next(t) // accept the connection; the failing Send ends it
	eventually(t, "the message marked sent despite the failed Send", func() bool { return h.current().WasSent(seq) })
}

// After marking, a message that expired meanwhile is skipped, not sent: a
// caller that saw it unsent at its deadline may already have released it.
func TestSendPendingSkipsWhatExpiredWhileSending(t *testing.T) {
	ctx := context.Background()
	var now atomic.Int64
	now.Store(1_000_000)
	var late uint64
	h := startPrepared(t, func(c *Config) {
		c.Now = func() time.Time { return time.UnixMilli(now.Load()) }
	}, func(s *Session) {
		// Both are in the outbox before Run starts, so one replay picks both.
		if _, err := s.Enqueue(ctx, Outgoing{Message: reject(1), ExpiresAtUnixMilli: 2_000_000}); err != nil {
			t.Fatal(err)
		}
		seq, err := s.Enqueue(ctx, Outgoing{Message: reject(2), ExpiresAtUnixMilli: 1_200_000})
		if err != nil {
			t.Fatal(err)
		}
		late = seq
		s.sendFrame = func(c *conn, f *rawFrame) error {
			err := c.stream.Send(f)
			now.CompareAndSwap(1_000_000, 1_500_000) // the first business send takes long
			return err
		}
	})
	s := h.current()
	c, _ := h.bind(t)
	if f := c.recvSkippingKeepalive(); !bytes.Equal(f.GetReject().GetDispatchTicketHash(), h32(3)) {
		t.Fatalf("first business frame = %v", f)
	}
	if _, err := s.Enqueue(ctx, Outgoing{Message: reject(3), ExpiresAtUnixMilli: 3_000_000}); err != nil {
		t.Fatal(err)
	}
	if f := c.recvSkippingKeepalive(); !bytes.Equal(f.GetReject().GetDispatchTicketHash(), h32(5)) {
		t.Fatalf("next business frame = %v, want the third message: the expired one is skipped", f)
	}
	if !s.WasSent(late) {
		t.Fatal("the skipped message was marked first, so it reads as maybe sent")
	}
}

// Enqueue tells a message that can never be sent (permanent) from a failure
// to persist it (retryable).
func TestEnqueueValidationFailuresAreMarked(t *testing.T) {
	h := startSession(t, nil)
	ctx := context.Background()
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: revoke(t, 1, builderKeyHex), ExpiryHeight: 5}); !errors.Is(err, ErrInvalidOutgoing) {
		t.Fatalf("Builder variant: err = %v, want ErrInvalidOutgoing", err)
	}
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: reject(1)}); !errors.Is(err, ErrInvalidOutgoing) {
		t.Fatalf("missing expiry: err = %v, want ErrInvalidOutgoing", err)
	}
	unsigned := unsignedReject(1)
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: unsigned, ExpiryHeight: 5}); !errors.Is(err, ErrInvalidOutgoing) {
		t.Fatalf("unsigned: err = %v, want ErrInvalidOutgoing", err)
	}
	if err := h.cfg.Store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.current().Enqueue(ctx, Outgoing{Message: reject(1), ExpiryHeight: 5}); err == nil || errors.Is(err, ErrInvalidOutgoing) {
		t.Fatalf("a store failure: err = %v, want an unmarked error", err)
	}
}
