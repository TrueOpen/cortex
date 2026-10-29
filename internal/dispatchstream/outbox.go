package dispatchstream

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/TrueOpen/cortex/internal/store"
)

// pending is one Cortex business message retained until the Builder acks it
// or it expires. Payload is the inner oneof message exactly as first encoded
// and signed; cursors are reassigned per binding and never stored.
type pending struct {
	Seq     uint64  `json:"-"`
	Variant variant `json:"variant"`
	Payload []byte  `json:"payload"`
	// Exactly one expiry bound. ExpiresAtUnixMilli: expired once the local
	// clock reaches it. ExpiryHeight: expired once the chain height passes it.
	ExpiresAtUnixMilli int64  `json:"expires_at_unix_ms,omitempty"`
	ExpiryHeight       uint64 `json:"expiry_height,omitempty"`
}

func (p pending) expired(nowMs int64, height uint64) bool {
	if p.ExpiresAtUnixMilli != 0 {
		return nowMs >= p.ExpiresAtUnixMilli
	}
	return height > p.ExpiryHeight
}

func (p pending) validate() error {
	if !p.Variant.fromCortex() {
		return fmt.Errorf("dispatchstream: variant %d is not a Cortex business message", p.Variant)
	}
	if (p.ExpiresAtUnixMilli == 0) == (p.ExpiryHeight == 0) {
		return fmt.Errorf("dispatchstream: exactly one of ExpiresAtUnixMilli and ExpiryHeight is required")
	}
	return nil
}

const (
	outboxPrefix    = "dispatch-outbox/"
	outboxSeqPrefix = "dispatch-outbox-seq/"
)

// outbox persists one Builder's outbound business messages, keyed by a local
// sequence that survives reconnects and restarts.
type outbox struct {
	st      *store.Store
	prefix  []byte
	counter []byte
}

func newOutbox(st *store.Store, builder string) *outbox {
	return &outbox{
		st:      st,
		prefix:  []byte(outboxPrefix + builder + "/"),
		counter: []byte(outboxSeqPrefix + builder),
	}
}

func (o *outbox) key(seq uint64) []byte {
	return append(append([]byte(nil), o.prefix...), fmt.Sprintf("%020d", seq)...)
}

// put assigns the next sequence and stores p in one atomic batch.
func (o *outbox) put(ctx context.Context, p pending) (uint64, error) {
	if err := p.validate(); err != nil {
		return 0, err
	}
	value, err := json.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("dispatchstream: encode outbox record: %w", err)
	}
	var seq uint64
	err = o.st.ApplyBatch(ctx, func(b *store.Batch) error {
		cur, err := b.Get(o.counter)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err
		case len(cur) != 8:
			return fmt.Errorf("dispatchstream: outbox counter is %d bytes", len(cur))
		default:
			seq = binary.BigEndian.Uint64(cur)
		}
		seq++
		if err := b.Set(o.counter, binary.BigEndian.AppendUint64(nil, seq)); err != nil {
			return err
		}
		return b.Set(o.key(seq), value)
	})
	if err != nil {
		return 0, fmt.Errorf("dispatchstream: persist outbound message: %w", err)
	}
	return seq, nil
}

// replayable returns every retained unexpired message in sequence order.
// Expired ones are left for prune to drop; they are never resent.
func (o *outbox) replayable(ctx context.Context, nowMs int64, height uint64) ([]pending, error) {
	var out []pending
	err := o.st.ScanPrefix(ctx, o.prefix, func(key, value []byte) error {
		seq, err := strconv.ParseUint(string(key[len(o.prefix):]), 10, 64)
		if err != nil {
			return fmt.Errorf("dispatchstream: outbox key %q: %w", key, err)
		}
		var p pending
		if err := json.Unmarshal(value, &p); err != nil {
			return fmt.Errorf("dispatchstream: outbox record %d: %w", seq, err)
		}
		p.Seq = seq
		if !p.expired(nowMs, height) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// prune deletes expired messages.
func (o *outbox) prune(ctx context.Context, nowMs int64, height uint64) error {
	var dead [][]byte
	err := o.st.ScanPrefix(ctx, o.prefix, func(key, value []byte) error {
		// An unreadable record is left in place: replayable reports it
		// rather than this silently dropping a message.
		var p pending
		if json.Unmarshal(value, &p) == nil && p.expired(nowMs, height) {
			dead = append(dead, key)
		}
		return nil
	})
	if err != nil || len(dead) == 0 {
		return err
	}
	return o.st.ApplyBatch(ctx, func(b *store.Batch) error {
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// done drops an acked message.
func (o *outbox) done(ctx context.Context, seq uint64) error {
	return o.st.DeleteRaw(ctx, o.key(seq))
}
