package dispatchstream

import (
	"math"
	"testing"
)

func TestInboundCursorIsContiguousAndAckNeverCrossesGap(t *testing.T) {
	var in inbound
	if got := in.accept(1); got != cursorNew {
		t.Fatalf("cursor 1: %v", got)
	}
	if got := in.accept(1); got != cursorDuplicate {
		t.Fatalf("replayed cursor 1: %v", got)
	}
	if got := in.accept(3); got != cursorGap {
		t.Fatalf("cursor 3 after 1 must be a gap, got %v", got)
	}
	if in.ackable() != 1 {
		t.Fatalf("ack must stop at 1, got %d", in.ackable())
	}
	if got := in.accept(0); got != cursorInvalid {
		t.Fatalf("business cursor 0 must be invalid, got %v", got)
	}
	if got := in.accept(2); got != cursorNew || in.ackable() != 2 {
		t.Fatalf("cursor 2 closes the run: %v ack %d", got, in.ackable())
	}
}

func TestOutboundAckBounds(t *testing.T) {
	var out outbound
	out.assign()
	out.assign()
	if err := out.ack(3); err == nil {
		t.Fatal("ack beyond the last sent cursor must be a protocol violation")
	}
	if err := out.ack(2); err != nil {
		t.Fatal(err)
	}
	if err := out.ack(1); err == nil {
		t.Fatal("a cumulative ack must not go backwards")
	}
	if out.acked != 2 {
		t.Fatalf("acked %d", out.acked)
	}
	if err := out.ack(2); err != nil {
		t.Fatalf("a repeated cumulative ack is not a violation: %v", err)
	}
}

func TestOutboundAssignIsContiguousAndRefusesOverflow(t *testing.T) {
	var out outbound
	for want := uint64(1); want <= 3; want++ {
		got, err := out.assign()
		if err != nil || got != want {
			t.Fatalf("assign: %d %v, want %d", got, err, want)
		}
	}
	out.next = math.MaxUint64
	if _, err := out.assign(); err == nil {
		t.Fatal("cursor overflow must force a reconnect, never wrap")
	}
}
