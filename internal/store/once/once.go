// Package once provides a Pebble-backed store for keys that must be accepted at
// most once. It is used for durable replay/dedup claims so that a restarted node
// does not reprocess the same inbound bus frame or duplicate event.
package once

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SingaXYZ/cortex/internal/store"
)

// record is the durable value stored for a claimed key.
type record struct {
	// ExpiresAtUnixMs is the wall-clock time after which the claim may be
	// silently overwritten. It is stored so the store can be pruned without
	// keeping an in-memory mirror of every key.
	ExpiresAtUnixMs int64 `json:"expires_at_unix_ms"`
}

// Store persists once-only keys in a Pebble-backed store.
type Store struct {
	db *store.Store
}

// New wraps the provided Pebble-backed store. The caller must ensure db is not
// nil and outlives the returned Store.
func New(db *store.Store) *Store {
	return &Store{db: db}
}

// keyPrefix keeps once-only keys separate from other store users. expiryPrefix is
// a time-ordered index over the same claims: the key embeds the expiry as
// big-endian bytes, so every expired claim sorts before every live one and pruning
// is a range scan that stops at the first live entry. Without it, pruning had to
// scan hash-ordered claims and could never reach an expired key that happened to
// sort behind live ones.
const (
	keyPrefix    = "once/"
	expiryPrefix = "once-exp/"
)

func claimKey(key string) []byte {
	return []byte(keyPrefix + key)
}

func expiryIndexKey(expiresAtUnixMs int64, key string) []byte {
	// Offset into unsigned space so a negative millisecond value cannot sort
	// after a positive one.
	stamp := uint64(expiresAtUnixMs) + 1<<63
	out := make([]byte, 0, len(expiryPrefix)+8+len(key))
	out = append(out, expiryPrefix...)
	out = binary.BigEndian.AppendUint64(out, stamp)
	return append(out, key...)
}

// Claim records key as claimed until expiresAt. It returns true if this call was
// the first to claim the key (or the previous claim has expired), and false if an
// unexpired claim already exists.
//
// The read and the write share one ApplyBatch closure. Only ApplyBatch holds the
// store lock across the callback, and Authenticate may run concurrently, so a
// GetRaw/PutRaw pair would let two callers both find the key absent, both write,
// and both be told they were first - which is precisely what an at-most-once
// store must not do.
func (s *Store) Claim(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("once store not initialized")
	}
	k := claimKey(key)
	now := time.Now().UTC()
	claimed := false
	err := s.db.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := b.Get(k)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read once key %q: %w", key, err)
		}
		if err == nil {
			var rec record
			if uerr := json.Unmarshal(existing, &rec); uerr != nil {
				// An unreadable claim is a claim. Corruption and a record written
				// by a newer binary are indistinguishable here, and treating it as
				// reclaimable is the one outcome an at-most-once store must never
				// produce: it would let a rolling downgrade accept a replay the
				// newer process had already refused.
				return fmt.Errorf("once key %q holds an unreadable claim: %w", key, uerr)
			}
			if now.Before(time.UnixMilli(rec.ExpiresAtUnixMs)) {
				return nil
			}
		}
		data, err := json.Marshal(record{ExpiresAtUnixMs: expiresAt.UnixMilli()})
		if err != nil {
			return fmt.Errorf("encode once key %q: %w", key, err)
		}
		if err := b.Set(k, data); err != nil {
			return fmt.Errorf("write once key %q: %w", key, err)
		}
		if err := b.Set(expiryIndexKey(expiresAt.UnixMilli(), key), nil); err != nil {
			return fmt.Errorf("index once key %q: %w", key, err)
		}
		claimed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return claimed, nil
}

// Prune deletes claims that have expired, stopping at the first live one.
//
// The expiry index makes this a range scan rather than a search: index keys embed
// the expiry as big-endian bytes, so every expired claim sorts before every live
// one and the walk can stop as soon as it reaches a live entry. The previous
// bounded scan over hash-ordered claims could not do this - it always restarted at
// the same prefix, so an expired claim sorting behind live ones was never reached,
// and cleanup capacity was capped below the rate at which claims arrive.
//
// limit still caps one call so a long backlog is drained over several passes
// rather than holding the store lock for all of it.
func (s *Store) Prune(ctx context.Context, now time.Time, limit int) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("once store not initialized")
	}
	if limit <= 0 {
		return 0, nil
	}
	removed := 0
	err := s.db.ApplyBatch(ctx, func(b *store.Batch) error {
		iter, err := b.NewIter([]byte(expiryPrefix))
		if err != nil {
			return err
		}
		type victim struct{ index, claim []byte }
		victims := make([]victim, 0, limit)
		for ok := iter.First(); ok && len(victims) < limit; ok = iter.Next() {
			indexKey := iter.Key()
			if len(indexKey) < len(expiryPrefix)+8 {
				// Malformed index entry: drop it, the claim itself is untouched
				// and its own expiry still governs.
				victims = append(victims, victim{index: append([]byte(nil), indexKey...)})
				continue
			}
			stamp := binary.BigEndian.Uint64(indexKey[len(expiryPrefix) : len(expiryPrefix)+8])
			expiresAt := time.UnixMilli(int64(stamp - 1<<63))
			if now.Before(expiresAt) {
				// Ordered by expiry, so everything after this is live too.
				break
			}
			key := string(indexKey[len(expiryPrefix)+8:])
			victims = append(victims, victim{
				index: append([]byte(nil), indexKey...),
				claim: claimKey(key),
			})
		}
		if cerr := iter.Close(); cerr != nil {
			return cerr
		}
		for _, v := range victims {
			if err := b.Delete(v.index); err != nil {
				return err
			}
			if v.claim == nil {
				continue
			}
			if err := b.Delete(v.claim); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// Release removes a previously claimed key and its expiry index entry. It is used
// when a frame that was authenticated is later rejected for a retryable
// downstream reason and should be allowed to redeliver.
func (s *Store) Release(ctx context.Context, key string) error {
	if s == nil || s.db == nil {
		return errors.New("once store not initialized")
	}
	return s.db.ApplyBatch(ctx, func(b *store.Batch) error {
		raw, err := b.Get(claimKey(key))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read once key %q: %w", key, err)
		}
		if err == nil {
			var rec record
			// An unreadable record still has to have its claim removed; only its
			// index entry is unrecoverable, and prune tolerates a stale one.
			if json.Unmarshal(raw, &rec) == nil {
				if derr := b.Delete(expiryIndexKey(rec.ExpiresAtUnixMs, key)); derr != nil {
					return fmt.Errorf("delete once index %q: %w", key, derr)
				}
			}
		}
		if err := b.Delete(claimKey(key)); err != nil {
			return fmt.Errorf("delete once key %q: %w", key, err)
		}
		return nil
	})
}
