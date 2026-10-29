package dispatchstream

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	outboxBadPrefix = "dispatch-outbox-bad/"
	outboxSeqPrefix = "dispatch-outbox-seq/"
	// outboxPruneBatch caps the records one prune batch examines.
	outboxPruneBatch = 1024
)

// errBatchFull stops a bounded scan.
var errBatchFull = errors.New("dispatchstream: batch full")

// outbox persists one Builder's outbound business messages, keyed by a local
// sequence that survives reconnects and restarts.
type outbox struct {
	st      *store.Store
	log     *slog.Logger
	builder string
	prefix  []byte
	counter []byte
	batch   int
}

func newOutbox(st *store.Store, builder string, log *slog.Logger) *outbox {
	return &outbox{
		st:      st,
		log:     log,
		builder: builder,
		prefix:  []byte(outboxPrefix + builder + "/"),
		counter: []byte(outboxSeqPrefix + builder),
		batch:   outboxPruneBatch,
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

func (o *outbox) decode(key, value []byte) (pending, error) {
	var p pending
	seq, err := strconv.ParseUint(string(key[len(o.prefix):]), 10, 64)
	if err != nil {
		return p, fmt.Errorf("key: %w", err)
	}
	if err := json.Unmarshal(value, &p); err != nil {
		return p, err
	}
	p.Seq = seq
	return p, p.validate()
}

// replayable returns, in sequence order, every retained unexpired message
// with a sequence above after. Expired ones are left for prune; corrupt ones
// are quarantined so they cannot wedge the session in a reconnect loop.
func (o *outbox) replayable(ctx context.Context, nowMs int64, height, after uint64) ([]pending, error) {
	var out []pending
	var bad [][2][]byte
	err := o.st.ScanPrefixFrom(ctx, o.prefix, o.key(after+1), func(key, value []byte) error {
		p, err := o.decode(key, value)
		if err != nil {
			o.log.Error("quarantining corrupt dispatch outbox record; it will not be sent", "key", string(key), "err", err)
			bad = append(bad, [2][]byte{key, value})
			return nil
		}
		if !p.expired(nowMs, height) {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		err = o.st.ApplyBatch(ctx, func(b *store.Batch) error {
			for _, kv := range bad {
				if err := b.Set(append([]byte(outboxBadPrefix+o.builder+"/"), kv[0][len(o.prefix):]...), kv[1]); err != nil {
					return err
				}
				if err := b.Delete(kv[0]); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("dispatchstream: quarantine outbox records: %w", err)
		}
	}
	return out, nil
}

// prune deletes expired messages, examining o.batch records per store batch
// and checking ctx between batches. Corrupt records are left to replayable's
// quarantine.
func (o *outbox) prune(ctx context.Context, nowMs int64, height uint64) error {
	start := o.prefix
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var dead [][]byte
		var last []byte
		seen := 0
		err := o.st.ScanPrefixFrom(ctx, o.prefix, start, func(key, value []byte) error {
			if seen == o.batch {
				return errBatchFull
			}
			seen++
			last = key
			if p, err := o.decode(key, value); err == nil && p.expired(nowMs, height) {
				dead = append(dead, key)
			}
			return nil
		})
		full := errors.Is(err, errBatchFull)
		if err != nil && !full {
			return err
		}
		if len(dead) > 0 {
			if err := o.st.ApplyBatch(ctx, func(b *store.Batch) error {
				for _, k := range dead {
					if err := b.Delete(k); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if !full {
			return nil
		}
		start = append(last, 0) // the smallest key after last
	}
}

// done drops an acked message.
func (o *outbox) done(ctx context.Context, seq uint64) error {
	return o.st.DeleteRaw(ctx, o.key(seq))
}
