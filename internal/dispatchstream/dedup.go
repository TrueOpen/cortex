package dispatchstream

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
)

// DefaultDedupRetention bounds how long a delivery record is kept. A Builder
// replays only what it has not seen acked, and an ack is lost only with the
// connection it was on, so a replay normally follows within one reconnect
// backoff. A day keeps the record set bounded by one day of inbound traffic
// per Builder. A replay arriving after retention reaches the Handler again,
// which is why Handlers must be idempotent.
const DefaultDedupRetention = 24 * time.Hour

const (
	dedupPrefix       = "dispatch-dedup/"
	dedupExpiryPrefix = "dispatch-dedup-exp/"
	// dedupPruneBatch caps one prune batch so the store lock is not held for
	// a whole backlog; prune loops over batches.
	dedupPruneBatch = 1024
)

// deliveries is the delivery-record store the session uses; an interface
// only so tests can inject write failures.
type deliveries interface {
	key(v variant, digest [32]byte) []byte
	delivered(ctx context.Context, key []byte) (bool, error)
	mark(ctx context.Context, key []byte, state deliveryState) error
	prune(ctx context.Context) error
}

type deliveryState string

const (
	// stateReceived: persisted before the Handler runs. It does not suppress
	// redelivery; it records that a delivery was attempted.
	stateReceived deliveryState = "received"
	// stateDone: the Handler finished (success or non-retryable failure).
	// Only this suppresses a replay.
	stateDone deliveryState = "done"
)

type dedupRecord struct {
	State           deliveryState `json:"state"`
	ExpiresAtUnixMs int64         `json:"expires_at_unix_ms"`
}

// dedup records delivery of Builder business messages so a replay under a new
// cursor (cursors restart on every binding) does not reach the Handler again
// once it has been fully handled. Keys are (builder operator, frame variant,
// message digest). The once store holds a single state with wall-clock
// expiry, so this is a small two-state record with its own per-Builder expiry
// index, on the session's injected clock.
type dedup struct {
	st          *store.Store
	builder     string
	retention   time.Duration
	now         func() time.Time
	log         *slog.Logger
	indexPrefix []byte
	batch       int
}

func newDedup(st *store.Store, builder string, retention time.Duration, now func() time.Time, log *slog.Logger) *dedup {
	if retention <= 0 {
		retention = DefaultDedupRetention
	}
	return &dedup{
		st: st, builder: builder, retention: retention, now: now, log: log,
		indexPrefix: []byte(dedupExpiryPrefix + builder + "/"),
		batch:       dedupPruneBatch,
	}
}

// messageDigest identifies a received inner message from its wire bytes.
// Signed messages use dispatch.SigningDigest over the received bytes, which
// excludes the signature, so a re-signed copy of the same content is the same
// message. Builder containers without their own signature (DispatchOfferV1,
// HandraiseRootNoticeV1) have no signing domain; they are identified by a
// domain-separated hash of the deterministic re-encoding of their decoded
// content -- a normalization of what was decoded, not a wire-defined
// canonical form.
func messageDigest(name string, innerRaw []byte, msg proto.Message) ([32]byte, error) {
	fields := msg.ProtoReflect().Descriptor().Fields()
	if fields.ByName("builder_service_signature") != nil || fields.ByName("service_signature") != nil {
		return dispatch.SigningDigest(name, innerRaw)
	}
	raw, err := dispatchwire.Raw(msg)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte("TRUEOPEN_CORTEX_DISPATCHSTREAM_DEDUP_V1\x00"))
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write(raw)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

func (d *dedup) key(v variant, digest [32]byte) []byte {
	return fmt.Appendf(nil, "%s%s/%d/%s", dedupPrefix, d.builder, v, hex.EncodeToString(digest[:]))
}

// expiryKey orders index entries by expiry: the stamp is offset into unsigned
// space so a negative millisecond value cannot sort after a positive one.
func (d *dedup) expiryKey(expiresAtMs int64, key []byte) []byte {
	out := append(append([]byte(nil), d.indexPrefix...), binary.BigEndian.AppendUint64(nil, uint64(expiresAtMs)+1<<63)...)
	return append(out, key...)
}

func (d *dedup) decode(key, raw []byte) (dedupRecord, bool) {
	var rec dedupRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		d.log.Warn("skipping corrupt dispatch dedup record", "key", string(key), "err", err)
		return rec, false
	}
	return rec, true
}

// delivered reports whether an unexpired done record exists for key. A
// corrupt record counts as not done: redelivery is the at-least-once side.
func (d *dedup) delivered(ctx context.Context, key []byte) (bool, error) {
	raw, err := d.st.GetRaw(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	rec, ok := d.decode(key, raw)
	return ok && rec.State == stateDone && d.now().UnixMilli() < rec.ExpiresAtUnixMs, nil
}

// mark durably writes state for key with a fresh expiry, moving its index.
func (d *dedup) mark(ctx context.Context, key []byte, state deliveryState) error {
	rec := dedupRecord{State: state, ExpiresAtUnixMs: d.now().Add(d.retention).UnixMilli()}
	value, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("dispatchstream: encode dedup record: %w", err)
	}
	return d.st.ApplyBatch(ctx, func(b *store.Batch) error {
		if old, err := b.Get(key); err == nil {
			if prev, ok := d.decode(key, old); ok {
				if err := b.Delete(d.expiryKey(prev.ExpiresAtUnixMs, key)); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := b.Set(key, value); err != nil {
			return err
		}
		return b.Set(d.expiryKey(rec.ExpiresAtUnixMs, key), nil)
	})
}

// prune deletes this Builder's expired records via its expiry index, oldest
// first, in batches of d.batch until a batch comes back short.
func (d *dedup) prune(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := d.pruneBatch(ctx)
		if err != nil || n < d.batch {
			return err
		}
	}
}

// pruneBatch removes up to d.batch expired index entries. A data record is
// deleted when its own expiry equals the index stamp, or when it does not
// decode; otherwise the index entry is stale (the record was re-marked) and
// only the index entry goes.
func (d *dedup) pruneBatch(ctx context.Context) (int, error) {
	nowMs := d.now().UnixMilli()
	head := len(d.indexPrefix) + 8
	n := 0
	err := d.st.ApplyBatch(ctx, func(b *store.Batch) error {
		iter, err := b.NewIter(d.indexPrefix)
		if err != nil {
			return err
		}
		var victims [][]byte
		for ok := iter.First(); ok && len(victims) < d.batch; ok = iter.Next() {
			k := iter.Key()
			if len(k) >= head && int64(binary.BigEndian.Uint64(k[len(d.indexPrefix):])-1<<63) > nowMs {
				break
			}
			victims = append(victims, append([]byte(nil), k...))
		}
		if err := iter.Close(); err != nil {
			return err
		}
		for _, k := range victims {
			if err := b.Delete(k); err != nil {
				return err
			}
			if len(k) < head {
				continue
			}
			stamp := int64(binary.BigEndian.Uint64(k[len(d.indexPrefix):]) - 1<<63)
			dataKey := k[head:]
			raw, err := b.Get(dataKey)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			rec, ok := d.decode(dataKey, raw)
			if !ok || rec.ExpiresAtUnixMs == stamp {
				// A record that does not decode can never be matched to a
				// live index entry; drop it with the expired one (decode has
				// logged it at Warn).
				if err := b.Delete(dataKey); err != nil {
					return err
				}
			}
		}
		n = len(victims)
		return nil
	})
	return n, err
}
