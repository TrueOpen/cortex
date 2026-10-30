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
//	handraise-current/<builder>                             CurrentHandraise
//	handraise-sent/<builder>/<standing digest>              sentHandraise
//	handraise-root/<builder>/<root digest>                  HeldRoot
//	handraise-root-order/<builder>/<^h>/<^v>/<root digest>  "" (newest first)
//	handraise-exp/<expire height>/<s|r>/<builder>/<digest>  "" (prune index)
const (
	hrCurrentPrefix = "handraise-current/"
	hrSentPrefix    = "handraise-sent/"
	hrRootPrefix    = "handraise-root/"
	hrOrderPrefix   = "handraise-root-order/"
	hrExpiryPrefix  = "handraise-exp/"
	hrPruneBatch    = 512
)

var errHandraiseScanStop = errors.New("handraise store: stop scan")

type sentHandraise struct {
	IssuedHeight uint64 `json:"issued_height"`
	ExpiryHeight uint64 `json:"expiry_height"`
	Nonce        uint64 `json:"nonce"`
	Raw          []byte `json:"raw"` // the signed StandingHandraiseV1
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
}

type handraiseStore struct{ st *store.Store }

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
func hrExpiryKey(at uint64, kind, builder, digest string) []byte {
	return fmt.Appendf(nil, "%s%020d/%s/%s/%s", hrExpiryPrefix, at, kind, builder, digest)
}

func parseHRExpiryKey(key []byte) (at uint64, kind, builder, digest string, err error) {
	parts := strings.Split(strings.TrimPrefix(string(key), hrExpiryPrefix), "/")
	if len(parts) != 4 || (parts[1] != "s" && parts[1] != "r") || parts[2] == "" || parts[3] == "" {
		return 0, "", "", "", fmt.Errorf("handraise expiry key %q is malformed", key)
	}
	at, err = strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, "", "", "", fmt.Errorf("handraise expiry key %q is malformed: %w", key, err)
	}
	return at, parts[1], parts[2], parts[3], nil
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
		return b.Set(hrExpiryKey(hrAddSat(sent.ExpiryHeight, retention), "s", builder, d), []byte{})
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

func (s handraiseStore) holdsRoot(ctx context.Context, builder string, digest [32]byte) (bool, error) {
	return s.exists(ctx, hrRootKey(builder, hrDigestHex(digest)))
}

// putRoot stores r once per digest. equivocal reports another digest already
// held at the same (root_height, root_version).
func (s handraiseStore) putRoot(ctx context.Context, r HeldRoot, retention uint64) (stored, equivocal bool, err error) {
	value, err := json.Marshal(r)
	if err != nil {
		return false, false, err
	}
	d := hrDigestHex(r.RootDigest)
	err = s.st.ApplyBatch(ctx, func(b *store.Batch) error {
		if _, err := b.Get(hrRootKey(r.Builder, d)); err == nil {
			return nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		it, err := b.NewIter(hrOrderSlot(r.Builder, r.RootHeight, r.RootVersion))
		if err != nil {
			return err
		}
		equivocal = it.First()
		if err := it.Close(); err != nil {
			return err
		}
		stored = true
		if err := b.Set(hrRootKey(r.Builder, d), value); err != nil {
			return err
		}
		if err := b.Set(hrOrderKey(r.Builder, r.RootHeight, r.RootVersion, d), []byte{}); err != nil {
			return err
		}
		return b.Set(hrExpiryKey(hrAddSat(r.ReceivedHeight, retention), "r", r.Builder, d), []byte{})
	})
	return stored, equivocal, err
}

// latestRoots returns up to n of builder's roots, newest (root_height,
// root_version) first.
func (s handraiseStore) latestRoots(ctx context.Context, builder string, n int) ([]HeldRoot, error) {
	var digests []string
	err := s.st.ScanPrefix(ctx, hrOrderBuilderPrefix(builder), func(key, _ []byte) error {
		if len(digests) == n {
			return errHandraiseScanStop
		}
		k := string(key)
		digests = append(digests, k[strings.LastIndexByte(k, '/')+1:])
		return nil
	})
	if err != nil && !errors.Is(err, errHandraiseScanStop) {
		return nil, err
	}
	out := make([]HeldRoot, 0, len(digests))
	for _, d := range digests {
		raw, err := s.st.GetRaw(ctx, hrRootKey(builder, d))
		if err != nil {
			return nil, fmt.Errorf("root %s indexed but unreadable: %w", d, err)
		}
		var r HeldRoot
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// prune deletes every sent record and root whose retention ended before
// height, hrPruneBatch index entries per store batch. A malformed index key
// names nothing it could delete; it is dropped on its own so it can never
// wedge the scan.
func (s handraiseStore) prune(ctx context.Context, height uint64) error {
	for {
		var due [][]byte
		err := s.st.ScanPrefix(ctx, []byte(hrExpiryPrefix), func(key, _ []byte) error {
			if len(due) == hrPruneBatch {
				return errHandraiseScanStop
			}
			at, _, _, _, err := parseHRExpiryKey(key)
			if err == nil && at >= height {
				return errHandraiseScanStop
			}
			due = append(due, key)
			return nil
		})
		if err != nil && !errors.Is(err, errHandraiseScanStop) {
			return err
		}
		if len(due) == 0 {
			return nil
		}
		err = s.st.ApplyBatch(ctx, func(b *store.Batch) error {
			for _, k := range due {
				_, kind, builder, digest, err := parseHRExpiryKey(k)
				if err != nil {
					kind = "" // malformed: drop the index key only
				}
				switch kind {
				case "s":
					if err := b.Delete(hrSentKey(builder, digest)); err != nil {
						return err
					}
				case "r":
					rk := hrRootKey(builder, digest)
					v, err := b.Get(rk)
					switch {
					case err == nil:
						var r HeldRoot
						if json.Unmarshal(v, &r) == nil {
							if err := b.Delete(hrOrderKey(builder, r.RootHeight, r.RootVersion, digest)); err != nil {
								return err
							}
						}
					case !errors.Is(err, store.ErrNotFound):
						return err
					}
					if err := b.Delete(rk); err != nil {
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
			return err
		}
		if len(due) < hrPruneBatch {
			return nil
		}
	}
}
