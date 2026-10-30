package daemon

import (
	"bytes"
	"math"
	"slices"
	"time"
)

// HandraiseProfile is one (model_id, profile_version) a standing handraise
// offers. Profiles are listed in ascending (model_id bytes, version) order
// (KC §4.4).
type HandraiseProfile struct {
	ModelID [32]byte
	Version uint32
}

func (p HandraiseProfile) compare(q HandraiseProfile) int {
	if c := bytes.Compare(p.ModelID[:], q.ModelID[:]); c != 0 {
		return c
	}
	switch {
	case p.Version < q.Version:
		return -1
	case p.Version > q.Version:
		return 1
	}
	return 0
}

type memberRef struct {
	SnapshotID  [32]byte `json:"snapshot_id"`
	Slot        uint32   `json:"slot"`
	SlotVersion uint64   `json:"slot_version"`
	Operator    string   `json:"operator"`
}

// handraiseState is what a standing handraise offers, apart from its height,
// nonce and signature.
type handraiseState struct {
	Member    memberRef          `json:"member"`
	AuthNonce uint64             `json:"auth_nonce"`
	Profiles  []HandraiseProfile `json:"profiles"`
	FreeSlots uint32             `json:"free_slots"`
}

func (s handraiseState) equal(o handraiseState) bool {
	return s.Member == o.Member && s.AuthNonce == o.AuthNonce && s.FreeSlots == o.FreeSlots && slices.Equal(s.Profiles, o.Profiles)
}

// shrinks reports whether s offers less than prev: fewer free slots, a dropped
// profile, or a different member or key binding. Those go out at once:
// advertising capacity this node no longer has turns into rejects that count
// against it (CD §5.1 "容量变化先重签常驻举手再拒单"; 参数表: the minimum
// change interval must not delay free-slot reporting).
func (s handraiseState) shrinks(prev handraiseState) bool {
	if s.FreeSlots < prev.FreeSlots || s.Member != prev.Member || s.AuthNonce != prev.AuthNonce {
		return true
	}
	for _, p := range prev.Profiles {
		if !slices.Contains(s.Profiles, p) {
			return true
		}
	}
	return false
}

// CurrentHandraise is the last standing handraise this node signed for one
// Builder, persisted so (issued_height, handraise_nonce) never repeats or goes
// backwards across restarts.
type CurrentHandraise struct {
	IssuedHeight    uint64         `json:"issued_height"`
	Nonce           uint64         `json:"nonce"`
	ExpiryHeight    uint64         `json:"expiry_height"`
	Digest          [32]byte       `json:"digest"`
	State           handraiseState `json:"state"`
	Withdrawn       bool           `json:"withdrawn"`
	SentAtUnixMs    int64          `json:"sent_at_unix_ms"`
	BlockIntervalMs int64          `json:"block_interval_ms"`
}

func (c *CurrentHandraise) sentAt() time.Time { return time.UnixMilli(c.SentAtUnixMs) }

// nextIssue returns the next (issued_height, handraise_nonce): a new height
// restarts the nonce at 0; the same height, or a chain view that went
// backwards, continues after the last pair (KC §4.4: the Builder keeps the
// newest by that pair).
func nextIssue(last *CurrentHandraise, height uint64) (issued, nonce uint64) {
	if last == nil || height > last.IssuedHeight {
		return height, 0
	}
	return last.IssuedHeight, last.Nonce + 1
}

type handraiseAction int

const (
	handraiseNone handraiseAction = iota
	handraiseSend
	handraiseWithdraw
	handraiseDefer
)

type handraiseTiming struct{ Heartbeat, MinChange time.Duration }

// decideHandraise is the CD §4.2.0 trigger rule for one Builder. want is what
// the gates allow (nil: offer nothing). canWithdraw says that refusal rests on
// facts rather than on a failed read. resend is set after a new binding, a
// restart or a failed enqueue.
func decideHandraise(now time.Time, height uint64, last *CurrentHandraise, want *handraiseState, canWithdraw, resend bool, tm handraiseTiming) (handraiseAction, string) {
	if want == nil {
		if canWithdraw && last != nil && !last.Withdrawn && height <= last.ExpiryHeight {
			return handraiseWithdraw, "withdraw"
		}
		return handraiseNone, ""
	}
	if last == nil {
		return handraiseSend, "first"
	}
	since := now.Sub(last.sentAt())
	switch {
	case last.Withdrawn:
		return handraiseSend, "reopen"
	case resend:
		return handraiseSend, "resend"
	case height+1 >= last.ExpiryHeight:
		return handraiseSend, "expiring"
	case since >= tm.Heartbeat:
		return handraiseSend, "heartbeat"
	case want.equal(last.State):
		return handraiseNone, ""
	case want.shrinks(last.State):
		return handraiseSend, "shrink"
	case since >= tm.MinChange:
		return handraiseSend, "change"
	}
	return handraiseDefer, "change held for the minimum interval"
}

const blockClockWindow = 64

type clockSample struct {
	height uint64
	at     time.Time
}

// blockClock estimates the block interval from (committed height, local time)
// observations. It only turns handraise_ttl_ms into an expiry_height; validity
// is judged by height alone (CD §4.2.0), so an estimation error only makes a
// handraise live a little longer or shorter.
type blockClock struct {
	samples []clockSample
	seed    time.Duration // last persisted estimate, used until two heights are seen
}

func (c *blockClock) observe(height uint64, at time.Time) {
	if n := len(c.samples); n > 0 && height <= c.samples[n-1].height {
		return
	}
	c.samples = append(c.samples, clockSample{height, at})
	if len(c.samples) > blockClockWindow {
		c.samples = c.samples[len(c.samples)-blockClockWindow:]
	}
}

func (c *blockClock) interval() (time.Duration, bool) {
	if n := len(c.samples); n >= 2 {
		first, last := c.samples[0], c.samples[n-1]
		if d := last.at.Sub(first.at) / time.Duration(last.height-first.height); d > 0 {
			return d, true
		}
	}
	return c.seed, c.seed > 0
}

// expiryHeight is issued + ceil(ttl / interval), at least one block.
func (c *blockClock) expiryHeight(issued uint64, ttl time.Duration) (uint64, bool) {
	iv, ok := c.interval()
	if !ok {
		return 0, false
	}
	blocks := max(uint64((ttl+iv-1)/iv), 1)
	if issued > math.MaxUint64-blocks {
		return 0, false
	}
	return issued + blocks, true
}
