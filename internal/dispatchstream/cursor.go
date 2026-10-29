// Package dispatchstream runs the Cortex end of one nexus.v1 DispatchStream:
// binding, per-direction business cursors, cumulative acks, keepalive and
// reconnect. Business handling lives behind Handler; this package guarantees
// that each Builder-signed business message reaches it at most once per
// Builder (across reconnects, see dedup.go) and is durably claimed before it
// is acknowledged.
package dispatchstream

import (
	"errors"
	"fmt"
	"math"
)

type cursorVerdict int

const (
	cursorNew cursorVerdict = iota
	cursorDuplicate
	cursorGap
	cursorInvalid
)

func (v cursorVerdict) String() string {
	switch v {
	case cursorNew:
		return "new"
	case cursorDuplicate:
		return "duplicate"
	case cursorGap:
		return "gap"
	default:
		return "invalid"
	}
}

// errCursorExhausted forces a reconnect: cursors never wrap.
var errCursorExhausted = errors.New("dispatchstream: outbound cursor exhausted; reconnect")

// inbound tracks the peer's business cursors within one binding.
type inbound struct{ last uint64 }

func (in *inbound) accept(c uint64) cursorVerdict {
	switch {
	case c == 0:
		return cursorInvalid
	case c <= in.last:
		return cursorDuplicate
	case c != in.last+1:
		return cursorGap
	}
	in.last = c
	return cursorNew
}

// ackable is the cumulative ack to send: everything up to the first gap.
func (in *inbound) ackable() uint64 { return in.last }

// outbound tracks this side's business cursors within one binding.
type outbound struct {
	next  uint64 // last cursor assigned
	acked uint64
}

func (o *outbound) assign() (uint64, error) {
	if o.next == math.MaxUint64 {
		return 0, errCursorExhausted
	}
	o.next++
	return o.next, nil
}

func (o *outbound) sent(c uint64) {
	if c > o.next {
		o.next = c
	}
}

// ack applies a cumulative peer ack. Exceeding what was sent or going
// backwards is a protocol violation; repeating the current value is not.
func (o *outbound) ack(c uint64) error {
	if c > o.next {
		return fmt.Errorf("dispatchstream: peer acked %d beyond last sent %d", c, o.next)
	}
	if c < o.acked {
		return fmt.Errorf("dispatchstream: peer ack went backwards from %d to %d", o.acked, c)
	}
	o.acked = c
	return nil
}
