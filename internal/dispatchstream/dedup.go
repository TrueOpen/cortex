package dispatchstream

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	// dedupPruneLimit caps one prune pass so the store lock is not held for
	// a whole backlog; later passes continue.
	dedupPruneLimit = 4096
)

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
// expiry, so this is a small two-state record with its own expiry index, on
// the session's injected clock.
type dedup struct {
	st        *store.Store
	builder   string
	retention time.Duration
	now       func() time.Time
}

func newDedup(st *store.Store, builder string, retention time.Duration, now func() time.Time) *dedup {
	if retention <= 0 {
		retention = DefaultDedupRetention
	}
	return &dedup{st: st, builder: builder, retention: retention, now: now}
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

func expiryKey(expiresAtMs int64, key []byte) []byte {
	out := append([]byte(dedupExpiryPrefix), binary.BigEndian.AppendUint64(nil, uint64(expiresAtMs)+1<<63)...)
	return append(out, key...)
}

// delivered reports whether an unexpired done record exists for key.
func (d *dedup) delivered(ctx context.Context, key []byte) (bool, error) {
	raw, err := d.st.GetRaw(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var rec dedupRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		// Unreadable: treat as not done. At-least-once means redelivery is
		// the safe side.
		return false, nil
	}
	return rec.State == stateDone && d.now().UnixMilli() < rec.ExpiresAtUnixMs, nil
}

// mark durably writes state for key with a fresh expiry, moving its index.
func (d *dedup) mark(ctx context.Context, key []byte, state deliveryState) error {
	rec := dedupRecord{State: state, ExpiresAtUnixMs: d.now().Add(d.retention).UnixMilli()}
	value, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return d.st.ApplyBatch(ctx, func(b *store.Batch) error {
		if old, err := b.Get(key); err == nil {
			var prev dedupRecord
			if json.Unmarshal(old, &prev) == nil {
				if err := b.Delete(expiryKey(prev.ExpiresAtUnixMs, key)); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := b.Set(key, value); err != nil {
			return err
		}
		return b.Set(expiryKey(rec.ExpiresAtUnixMs, key), nil)
	})
}

// prune deletes expired records via the expiry index, oldest first, stopping
// at the first live one.
func (d *dedup) prune(ctx context.Context) error {
	nowMs := d.now().UnixMilli()
	return d.st.ApplyBatch(ctx, func(b *store.Batch) error {
		iter, err := b.NewIter([]byte(dedupExpiryPrefix))
		if err != nil {
			return err
		}
		var victims [][]byte
		for ok := iter.First(); ok && len(victims) < dedupPruneLimit; ok = iter.Next() {
			k := iter.Key()
			if len(k) < len(dedupExpiryPrefix)+8 {
				victims = append(victims, append([]byte(nil), k...))
				continue
			}
			stamp := binary.BigEndian.Uint64(k[len(dedupExpiryPrefix):])
			if int64(stamp-1<<63) > nowMs {
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
			if len(k) >= len(dedupExpiryPrefix)+8 {
				if err := b.Delete(k[len(dedupExpiryPrefix)+8:]); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
