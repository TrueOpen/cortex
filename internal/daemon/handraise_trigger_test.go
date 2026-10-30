package daemon

import (
	"testing"
	"time"
)

func TestBlockClockExpiryHeight(t *testing.T) {
	var c blockClock
	t0 := time.UnixMilli(1_000_000)
	if _, ok := c.expiryHeight(100, 30*time.Second); ok {
		t.Fatal("no expiry before an interval is known")
	}
	c.observe(100, t0)
	c.observe(100, t0.Add(time.Second))   // same height: ignored
	c.observe(104, t0.Add(8*time.Second)) // 2s per block
	c.observe(103, t0.Add(9*time.Second)) // chain view regressed: ignored
	if got, ok := c.expiryHeight(104, 31*time.Second); !ok || got != 104+16 {
		t.Fatalf("expiry = %d %v, want 120 (ceil(31s/2s) = 16)", got, ok)
	}
	if got, _ := c.expiryHeight(104, time.Millisecond); got != 105 {
		t.Fatalf("a tiny ttl still gives one block, got %d", got)
	}
	seeded := blockClock{seed: 3 * time.Second}
	seeded.observe(50, t0)
	if got, ok := seeded.expiryHeight(50, 30*time.Second); !ok || got != 60 {
		t.Fatalf("the persisted seed stands in until two heights are seen: %d %v", got, ok)
	}
}

func TestNextIssueNeverRepeats(t *testing.T) {
	if i, n := nextIssue(nil, 50); i != 50 || n != 0 {
		t.Fatalf("first = (%d,%d)", i, n)
	}
	last := &CurrentHandraise{IssuedHeight: 50, Nonce: 3}
	if i, n := nextIssue(last, 50); i != 50 || n != 4 {
		t.Fatalf("same height = (%d,%d), want (50,4)", i, n)
	}
	if i, n := nextIssue(last, 49); i != 50 || n != 4 {
		t.Fatalf("a chain view that went backwards must continue from (50,3), got (%d,%d)", i, n)
	}
	if i, n := nextIssue(last, 51); i != 51 || n != 0 {
		t.Fatalf("new height = (%d,%d), want (51,0)", i, n)
	}
}

func TestDecideHandraise(t *testing.T) {
	t0 := time.UnixMilli(1_000_000)
	tm := handraiseTiming{Heartbeat: 10 * time.Second, MinChange: 2 * time.Second}
	base := handraiseState{AuthNonce: 7, FreeSlots: 3, Profiles: []HandraiseProfile{{Version: 1}, {Version: 2}}}
	last := &CurrentHandraise{IssuedHeight: 100, ExpiryHeight: 115, State: base, SentAtUnixMs: t0.UnixMilli()}
	more, fewer, dropped := base, base, base
	more.FreeSlots, fewer.FreeSlots = 4, 2
	dropped.Profiles = base.Profiles[:1]
	withdrawn := *last
	withdrawn.Withdrawn = true
	for _, c := range []struct {
		name        string
		now         time.Time
		height      uint64
		last        *CurrentHandraise
		want        *handraiseState
		canWithdraw bool
		resend      bool
		act         handraiseAction
	}{
		{"first", t0, 100, nil, &base, false, false, handraiseSend},
		{"unchanged", t0.Add(time.Second), 100, last, &base, false, false, handraiseNone},
		{"heartbeat", t0.Add(10 * time.Second), 104, last, &base, false, false, handraiseSend},
		{"expiring", t0.Add(time.Second), 114, last, &base, false, false, handraiseSend},
		{"resend", t0.Add(time.Second), 100, last, &base, false, true, handraiseSend},
		{"growth waits", t0.Add(time.Second), 100, last, &more, false, false, handraiseDefer},
		{"growth after min interval", t0.Add(2 * time.Second), 100, last, &more, false, false, handraiseSend},
		{"fewer slots at once", t0.Add(time.Millisecond), 100, last, &fewer, false, false, handraiseSend},
		{"dropped profile at once", t0.Add(time.Millisecond), 100, last, &dropped, false, false, handraiseSend},
		{"closed by a fact withdraws", t0, 100, last, nil, true, false, handraiseWithdraw},
		{"closed by a failed read stays silent", t0, 100, last, nil, false, false, handraiseNone},
		{"nothing to withdraw once expired", t0, 116, last, nil, true, false, handraiseNone},
		{"withdrawn stays withdrawn", t0, 100, &withdrawn, nil, true, false, handraiseNone},
		{"reopen after withdrawal", t0.Add(time.Millisecond), 100, &withdrawn, &base, false, false, handraiseSend},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, why := decideHandraise(c.now, c.height, c.last, c.want, c.canWithdraw, c.resend, tm); got != c.act {
				t.Fatalf("action %d (%s), want %d", got, why, c.act)
			}
		})
	}
}

func TestBlockClockDropsSamplesAcrossAHalt(t *testing.T) {
	c := blockClock{maxAge: 2 * time.Minute}
	t0 := time.UnixMilli(1_000_000)
	for i := range uint64(10) {
		c.observe(100+i, t0.Add(time.Duration(i)*2*time.Second))
	}
	resume := t0.Add(18*time.Second + 10*time.Minute) // the chain halted for 10 minutes
	c.observe(110, resume)
	if iv, ok := c.interval(); !ok || iv != 2*time.Second {
		t.Fatalf("interval after a halt = %v %v, want the 2s estimate, not the halt", iv, ok)
	}
	c.observe(111, resume.Add(3*time.Second))
	if iv, _ := c.interval(); iv != 3*time.Second {
		t.Fatalf("interval = %v, want 3s from the post-halt samples", iv)
	}
}
