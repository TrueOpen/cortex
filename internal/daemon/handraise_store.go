package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/store"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// Store layout of the standing handraise (CD §10 "StandingHandraise"):
//
//	handraise-current/<builder>                                  CurrentHandraise
//	handraise-sent/<builder>/<standing digest>                   sentHandraise
//	handraise-root/<builder>/<root digest>                       HeldRoot
//	handraise-root-order/<builder>/<^h>/<^v>/<root digest>       "" (newest first)
//	handraise-exp/<at>/s/<builder>/<standing digest>             "" (prune index)
//	handraise-exp/<at>/r/<builder>/<root digest>/<h>/<v>         "" (prune index)
//
// A root's prune key carries its (root_height, root_version), so its order
// key can be deleted even when the HeldRoot record is unreadable.
const (
	hrCurrentPrefix = "handraise-current/"
	hrSentPrefix    = "handraise-sent/"
	hrRootPrefix    = "handraise-root/"
	hrOrderPrefix   = "handraise-root-order/"
	hrExpiryPrefix  = "handraise-exp/"
	hrPruneBatch    = 512
)

var (
	errHandraiseScanStop = errors.New("handraise store: stop scan")
)

type sentHandraise struct {
	IssuedHeight uint64 `json:"issued_height"`
	ExpiryHeight uint64 `json:"expiry_height"`
	Nonce        uint64 `json:"nonce"`
	Raw          []byte `json:"raw"` // the signed StandingHandraiseV1
	// RetainUntil is the height its prune key names: expiry_height +
	// retention, extended by every root proving it that arrives later.
	RetainUntil uint64 `json:"retain_until"`
}

// HeldRoot is one verified handraise root with this node's inclusion proof,
// retained as dispatch evidence (CD §10, §11.2).
type HeldRoot struct {
	Builder          string                     `json:"builder"`
	RootDigest       [32]byte                   `json:"root_digest"`
	StandingDigest   [32]byte                   `json:"standing_digest"`
	RootHeight       uint64                     `json:"root_height"`
	RootVersion      uint64                     `json:"root_version"`
	Admitted         bool                       `json:"admitted"`
	Reason           taskv1.AdmitRejectReasonV1 `json:"reason"`
	RTTMillis        uint64                     `json:"rtt_ms"`
	ReceivedHeight   uint64                     `json:"received_height"`
	ReceivedAtUnixMs int64                      `json:"received_at_unix_ms"`
	Notice           []byte                     `json:"notice"` // HandraiseRootNoticeV1
	// Equivocal: another digest was already held at the same (root_height,
	// root_version) when this one was stored. Persisted with the root so a
	// redelivery after a crash still raises the alert.
	Equivocal bool `json:"equivocal,omitempty"`
}

type handraiseStore struct {
	st    *store.Store
	batch int // prune index entries per batch; 0 means hrPruneBatch
}

func hrDigestHex(d [32]byte) string { return hex.EncodeToString(d[:]) }

func hrCurrentKey(builder string) []byte { return []byte(hrCurrentPrefix + builder) }
func hrSentKey(builder, digest string) []byte {
	return []byte(hrSentPrefix + builder + "/" + digest)
}
func hrRootKey(builder, digest string) []byte {
	return []byte(hrRootPrefix + builder + "/" + digest)
}
func hrOrderBuilderPrefix(builder string) []byte { return []byte(hrOrderPrefix + builder + "/") }
func hrOrderSlot(builder string, h, v uint64) []byte {
	return fmt.Appendf(nil, "%s%s/%016x/%016x/", hrOrderPrefix, builder, ^h, ^v)
}
func hrOrderKey(builder string, h, v uint64, digest string) []byte {
	return append(hrOrderSlot(builder, h, v), digest...)
}
func hrSentExpiryKey(at uint64, builder, digest string) []byte {
	return fmt.Appendf(nil, "%s%020d/s/%s/%s", hrExpiryPrefix, at, builder, digest)
}
func hrRootExpiryKey(at uint64, builder, digest string, h, v uint64) []byte {
	return fmt.Appendf(nil, "%s%020d/r/%s/%s/%d/%d", hrExpiryPrefix, at, builder, digest, h, v)
}

type hrExpiry struct {
	at                    uint64
	kind, builder, digest string
	rootHeight, rootVer   uint64
}

func parseHRExpiryKey(key []byte) (hrExpiry, error) {
	bad := fmt.Errorf("handraise expiry key %q is malformed", key)
	parts := strings.Split(strings.TrimPrefix(string(key), hrExpiryPrefix), "/")
	if len(parts) < 4 || parts[2] == "" || parts[3] == "" {
		return hrExpiry{}, bad
	}
	e := hrExpiry{kind: parts[1], builder: parts[2], digest: parts[3]}
	var err error
	if e.at, err = strconv.ParseUint(parts[0], 10, 64); err != nil {
		return hrExpiry{}, bad
	}
	switch {
	case e.kind == "s" && len(parts) == 4:
	case e.kind == "r" && len(parts) == 6:
		if e.rootHeight, err = strconv.ParseUint(parts[4], 10, 64); err != nil {
			return hrExpiry{}, bad
		}
		if e.rootVer, err = strconv.ParseUint(parts[5], 10, 64); err != nil {
			return hrExpiry{}, bad
		}
	default:
		return hrExpiry{}, bad
	}
	return e, nil
}

func hrAddSat(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func (s handraiseStore) loadCurrent(ctx context.Context, builder string) (*CurrentHandraise, error) {
	raw, err := s.st.GetRaw(ctx, hrCurrentKey(builder))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c CurrentHandraise
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode current handraise for %s: %w", builder, err)
	}
	return &c, nil
}

// recordSend persists the new current handraise and its send-log entry in one
// batch, before the handraise is enqueued, so a root can only ever prove a
// handraise this log holds (CD §10 写入顺序).
func (s handraiseStore) recordSend(ctx context.Context, builder string, cur CurrentHandraise, sent sentHandraise, retention uint64) error {
	cv, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	sent.RetainUntil = hrAddSat(sent.ExpiryHeight, retention)
	sv, err := json.Marshal(sent)
	if err != nil {
		return err
	}
	d := hrDigestHex(cur.Digest)
	return s.st.ApplyBatch(ctx, func(b *store.Batch) error {
		if err := b.Set(hrCurrentKey(builder), cv); err != nil {
			return err
		}
		if err := b.Set(hrSentKey(builder, d), sv); err != nil {
			return err
		}
		return b.Set(hrSentExpiryKey(sent.RetainUntil, builder, d), []byte{})
	})
}

func (s handraiseStore) exists(ctx context.Context, key []byte) (bool, error) {
	_, err := s.st.GetRaw(ctx, key)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	}
	return false, err
}

func (s handraiseStore) hasSent(ctx context.Context, builder string, digest [32]byte) (bool, error) {
	return s.exists(ctx, hrSentKey(builder, hrDigestHex(digest)))
}

// holdsRoot reports a retained, readable root: an undecodable record is
// not held (a redelivery heals it, see putRoot).
func (s handraiseStore) holdsRoot(ctx context.Context, builder string, digest [32]byte) (bool, error) {
	raw, err := s.st.GetRaw(ctx, hrRootKey(builder, hrDigestHex(digest)))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	var r HeldRoot
	return json.Unmarshal(raw, &r) == nil, nil
}

// putRoot stores r once per digest and returns the record held: r with
// Equivocal set when another digest is already held at the same
// (root_height, root_version), or, on a redelivery (stored=false), the record
// stored before. A stored record that no longer decodes is overwritten with
// the freshly verified r (stored=true): the digest fixes (root_height,
// root_version), so its order key is the same. It also extends the retention
// of the handraise r proves to cover r's own.
func (s handraiseStore) putRoot(ctx context.Context, r HeldRoot, retention uint64) (held HeldRoot, stored bool, err error) {
	d := hrDigestHex(r.RootDigest)
	own := hrOrderKey(r.Builder, r.RootHeight, r.RootVersion, d)
	err = s.st.ApplyBatch(ctx, func(b *store.Batch) error {
		if v, err := b.Get(hrRootKey(r.Builder, d)); err == nil {
			if json.Unmarshal(v, &held) == nil {
				return nil
			}
			held = HeldRoot{} // corrupt: heal it below
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		it, err := b.NewIter(hrOrderSlot(r.Builder, r.RootHeight, r.RootVersion))
		if err != nil {
			return err
		}
		r.Equivocal = false
		for ok := it.First(); ok; ok = it.Next() {
			if string(it.Key()) != string(own) {
				r.Equivocal = true
				break
			}
		}
		if err := it.Close(); err != nil {
			return err
		}
		value, err := json.Marshal(r)
		if err != nil {
			return err
		}
		retainUntil := hrAddSat(r.ReceivedHeight, retention)
		if err := s.extendSent(b, r.Builder, hrDigestHex(r.StandingDigest), retainUntil); err != nil {
			return err
		}
		held, stored = r, true
		if err := b.Set(hrRootKey(r.Builder, d), value); err != nil {
			return err
		}
		if err := b.Set(own, []byte{}); err != nil {
			return err
		}
		return b.Set(hrRootExpiryKey(retainUntil, r.Builder, d, r.RootHeight, r.RootVersion), []byte{})
	})
	if err != nil {
		return HeldRoot{}, false, err
	}
	return held, stored, nil
}

// extendSent re-keys a send-log entry to be retained until at least until.
func (s handraiseStore) extendSent(b *store.Batch, builder, digest string, until uint64) error {
	v, err := b.Get(hrSentKey(builder, digest))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var sent sentHandraise
	if err := json.Unmarshal(v, &sent); err != nil {
		return nil // an unreadable entry keeps its own schedule
	}
	if until <= sent.RetainUntil {
		return nil
	}
	if err := b.Delete(hrSentExpiryKey(sent.RetainUntil, builder, digest)); err != nil {
		return err
	}
	sent.RetainUntil = until
	nv, err := json.Marshal(sent)
	if err != nil {
		return err
	}
	if err := b.Set(hrSentKey(builder, digest), nv); err != nil {
		return err
	}
	return b.Set(hrSentExpiryKey(until, builder, digest), []byte{})
}

// latestRootDigests returns up to n of builder's root digests, newest
// (root_height, root_version) first, decoded from the order keys alone.
func (s handraiseStore) latestRootDigests(ctx context.Context, builder string, n int) ([][32]byte, error) {
	var out [][32]byte
	err := s.st.ScanPrefix(ctx, hrOrderBuilderPrefix(builder), func(key, _ []byte) error {
		if len(out) == n {
			return errHandraiseScanStop
		}
		k := string(key)
		raw, err := hex.DecodeString(k[strings.LastIndexByte(k, '/')+1:])
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("handraise root order key %q is malformed", key)
		}
		var d [32]byte
		copy(d[:], raw)
		out = append(out, d)
		return nil
	})
	if err != nil && !errors.Is(err, errHandraiseScanStop) {
		return nil, err
	}
	return out, nil
}

// latestRoots returns up to n of builder's roots, newest first.
func (s handraiseStore) latestRoots(ctx context.Context, builder string, n int) ([]HeldRoot, error) {
	digests, err := s.latestRootDigests(ctx, builder, n)
	if err != nil {
		return nil, err
	}
	out := make([]HeldRoot, 0, len(digests))
	for _, d := range digests {
		raw, err := s.st.GetRaw(ctx, hrRootKey(builder, hrDigestHex(d)))
		if err != nil {
			return nil, fmt.Errorf("root %x indexed but unreadable: %w", d, err)
		}
		var r HeldRoot
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// pruneBatch deletes one batch of sent records and roots whose retention
// ended before height, scanning the prune index from from (nil: its start).
// It returns where the next batch resumes, or nil once nothing due is left.
// A malformed index key names nothing it could delete; it is dropped on its
// own so it can never wedge the scan.
func (s handraiseStore) pruneBatch(ctx context.Context, height uint64, from []byte) ([]byte, error) {
	limit := s.batch
	if limit <= 0 {
		limit = hrPruneBatch
	}
	prefix := []byte(hrExpiryPrefix)
	if from == nil {
		from = prefix
	}
	var due [][]byte
	var next []byte
	err := s.st.ScanPrefixFrom(ctx, prefix, from, func(key, _ []byte) error {
		if len(due) == limit {
			next = key
			return errHandraiseScanStop
		}
		if e, err := parseHRExpiryKey(key); err == nil && e.at >= height {
			return errHandraiseScanStop
		}
		due = append(due, key)
		return nil
	})
	if err != nil && !errors.Is(err, errHandraiseScanStop) {
		return nil, err
	}
	if len(due) == 0 {
		return nil, nil
	}
	err = s.st.ApplyBatch(ctx, func(b *store.Batch) error {
		for _, k := range due {
			e, err := parseHRExpiryKey(k)
			switch {
			case err != nil:
				// malformed: drop the index key only
			case e.kind == "s":
				if err := b.Delete(hrSentKey(e.builder, e.digest)); err != nil {
					return err
				}
			case e.kind == "r":
				if err := b.Delete(hrOrderKey(e.builder, e.rootHeight, e.rootVer, e.digest)); err != nil {
					return err
				}
				if err := b.Delete(hrRootKey(e.builder, e.digest)); err != nil {
					return err
				}
			}
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return next, nil
}

// rootByDigest reads one retained root; ok=false when absent or unreadable.
func (s handraiseStore) rootByDigest(ctx context.Context, builder string, digest [32]byte) (HeldRoot, bool, error) {
	raw, err := s.st.GetRaw(ctx, hrRootKey(builder, hrDigestHex(digest)))
	if errors.Is(err, store.ErrNotFound) {
		return HeldRoot{}, false, nil
	}
	if err != nil {
		return HeldRoot{}, false, err
	}
	var r HeldRoot
	if json.Unmarshal(raw, &r) != nil {
		return HeldRoot{}, false, nil
	}
	return r, true, nil
}

// rootsUpTo returns up to limit of builder's readable roots with
// root_height <= maxHeight, newest (root_height, root_version) first.
func (s handraiseStore) rootsUpTo(ctx context.Context, builder string, maxHeight uint64, limit int) ([]HeldRoot, error) {
	prefix := hrOrderBuilderPrefix(builder)
	var digests [][32]byte
	err := s.st.ScanPrefix(ctx, prefix, func(key, _ []byte) error {
		if len(digests) == limit {
			return errHandraiseScanStop
		}
		parts := strings.Split(string(key[len(prefix):]), "/")
		if len(parts) != 3 {
			return fmt.Errorf("handraise root order key %q is malformed", key)
		}
		inv, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			return fmt.Errorf("handraise root order key %q is malformed", key)
		}
		if ^inv > maxHeight {
			return nil
		}
		raw, err := hex.DecodeString(parts[2])
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("handraise root order key %q is malformed", key)
		}
		digests = append(digests, [32]byte(raw))
		return nil
	})
	if err != nil && !errors.Is(err, errHandraiseScanStop) {
		return nil, err
	}
	out := make([]HeldRoot, 0, len(digests))
	for _, d := range digests {
		if r, ok, err := s.rootByDigest(ctx, builder, d); err != nil {
			return nil, err
		} else if ok {
			out = append(out, r)
		}
	}
	return out, nil
}
