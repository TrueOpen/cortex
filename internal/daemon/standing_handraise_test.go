package daemon

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
)

type hrHarness struct {
	t      *testing.T
	chain  *fakeHandraiseChain
	local  *fakeHandraiseLocal
	a, b   *fakeEnqueuer
	st     *store.Store
	now    time.Time
	alerts []HandraiseAlert
	tweak  func(*StandingHandraiseConfig)
	h      *StandingHandraiser
}

func newHRHarness(t *testing.T, tweak func(*StandingHandraiseConfig)) *hrHarness {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	x := &hrHarness{
		t: t, chain: newFakeHandraiseChain(t), local: &fakeHandraiseLocal{ready: true, free: 3, freeOK: true},
		a: &fakeEnqueuer{}, b: &fakeEnqueuer{}, st: st, now: time.UnixMilli(10_000_000), tweak: tweak,
	}
	x.open()
	return x
}

// open (re)builds the handraiser over the same store, as a restart would.
func (x *hrHarness) open() {
	x.t.Helper()
	cfg := StandingHandraiseConfig{
		ChainID: hrChainID, Operator: hrCortex, Profiles: hrProfileRefs(), MinPriceBid: hrBids(),
		Heartbeat: 10 * time.Second, TTL: 30 * time.Second, MinChange: 2 * time.Second,
		RetentionBlocks: 1_000, RootHistory: 4,
		Chain: x.chain, Local: x.local, Sign: hrSigner(hrCortexKey), Store: x.st,
		Builders: map[string]HandraiseEnqueuer{hrBuilderA: x.a, hrBuilderB: x.b},
		Now:      func() time.Time { return x.now },
		Alert:    func(a HandraiseAlert) { x.alerts = append(x.alerts, a) },
	}
	if x.tweak != nil {
		x.tweak(&cfg)
	}
	h, err := NewStandingHandraiser(context.Background(), cfg)
	if err != nil {
		x.t.Fatal(err)
	}
	x.h = h
}

func (x *hrHarness) try(dt time.Duration, height uint64) error {
	x.now = x.now.Add(dt)
	x.chain.with(func(f *fakeHandraiseChain) { f.height = height })
	return x.h.evaluate(context.Background())
}

func (x *hrHarness) step(dt time.Duration, height uint64) {
	x.t.Helper()
	if err := x.try(dt, height); err != nil {
		x.t.Fatal(err)
	}
}

// warm observes heights 100 and 101 two seconds apart; the second pass sends.
func (x *hrHarness) warm() {
	x.t.Helper()
	x.step(0, 100)
	x.step(2*time.Second, 101)
}

func issueOf(q *fakeEnqueuer) (out [][2]uint64) {
	for _, m := range q.handraises() {
		out = append(out, [2]uint64{m.GetIssuedHeight(), m.GetHandraiseNonce()})
	}
	return out
}

func TestStandingHandraiseFirstSend(t *testing.T) {
	ctx := context.Background()
	x := newHRHarness(t, nil)
	x.step(0, 100)
	if len(x.a.handraises())+len(x.b.handraises()) != 0 {
		t.Fatal("nothing may be sent before the block interval is observed")
	}
	x.step(2*time.Second, 101)
	for _, c := range []struct {
		q       *fakeEnqueuer
		builder string
	}{{x.a, hrBuilderA}, {x.b, hrBuilderB}} {
		hs := c.q.handraises()
		if len(hs) != 1 {
			t.Fatalf("%s got %d handraises", c.builder, len(hs))
		}
		m := hs[0]
		if m.GetSchemaVersion() != 1 || m.GetChainId() != hrChainID || m.GetBuilderAddress() != c.builder || m.GetServiceAuthorizationNonce() != 7 {
			t.Fatalf("identity fields: %v", m)
		}
		if m.GetIssuedHeight() != 101 || m.GetExpiryHeight() != 116 || m.GetHandraiseNonce() != 0 || m.GetFreeSlotCount() != 3 {
			t.Fatalf("heights/nonce/free: %v", m) // 101 + ceil(30s / 2s)
		}
		if c.q.outgoing(0).ExpiryHeight != 116 {
			t.Fatal("Outgoing.ExpiryHeight must be the handraise expiry_height")
		}
		mem := m.GetMember()
		if !bytes.Equal(mem.GetCandidatePoolSnapshotId(), bytes.Repeat([]byte{0x5a}, 32)) || mem.GetSlot() != 4 || mem.GetSlotVersion() != 2 || mem.GetOperatorAddress() != hrCortex {
			t.Fatalf("member: %v", mem)
		}
		var got []HandraiseProfile
		for _, p := range m.GetProfiles() {
			var hp HandraiseProfile
			copy(hp.ModelID[:], p.GetModelId())
			hp.Version = p.GetProfileVersion()
			got = append(got, hp)
		}
		if want := []HandraiseProfile{hrProfile(hrModelAB, 1), hrProfile(hrModelAB, 2), hrProfile(hrModelCD, 1)}; !slices.Equal(got, want) {
			t.Fatalf("profiles must be ascending (model_id, version): %v", got)
		}
		d, err := dispatchwire.Digest(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := dispatch.VerifyDigestSignature(hrPub(t, hrCortexKey), d[:], m.GetServiceSignature()); err != nil {
			t.Fatalf("signature: %v", err)
		}
		if ok, err := x.h.db.hasSent(ctx, c.builder, d); err != nil || !ok {
			t.Fatal("every sent handraise is in the send log")
		}
		if cur, ok := x.h.Current(c.builder); !ok || cur.Digest != d {
			t.Fatal("Current must return the handraise just sent")
		}
	}
}

func TestStandingHandraiseHeartbeatAndMinChangeInterval(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()                          // (101,0) free 3 at t=2s
	x.step(500*time.Millisecond, 101) // unchanged: nothing
	x.local.with(func(l *fakeHandraiseLocal) { l.free = 5 })
	x.step(500*time.Millisecond, 101) // growth 1s after the last send: held
	x.step(time.Second, 101)          // 2s: sent
	x.local.with(func(l *fakeHandraiseLocal) { l.free = 1 })
	x.step(100*time.Millisecond, 101) // shrink: sent at once
	x.step(10*time.Second, 106)       // heartbeat at a new height
	for _, q := range []*fakeEnqueuer{x.a, x.b} {
		var free []uint32
		for _, m := range q.handraises() {
			free = append(free, m.GetFreeSlotCount())
		}
		if got, want := issueOf(q), [][2]uint64{{101, 0}, {101, 1}, {101, 2}, {106, 0}}; !slices.Equal(got, want) {
			t.Fatalf("(issued, nonce) = %v, want %v", got, want)
		}
		if !slices.Equal(free, []uint32{3, 5, 1, 1}) {
			t.Fatalf("free slots = %v", free)
		}
	}
}

func TestStandingHandraiseRestartReboundAndRegression(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	x.open() // restart over the same store
	x.step(100*time.Millisecond, 101)
	if got := issueOf(x.a); !slices.Equal(got, [][2]uint64{{101, 0}, {101, 1}}) {
		t.Fatalf("a restart resends with the next nonce at once (seeded interval): %v", got)
	}
	x.step(100*time.Millisecond, 101)
	if len(x.a.handraises()) != 2 {
		t.Fatal("one resend per restart")
	}
	x.h.Rebound(hrBuilderA)
	x.step(100*time.Millisecond, 99) // the chain view went backwards
	if got := issueOf(x.a); got[len(got)-1] != [2]uint64{101, 2} {
		t.Fatalf("a rebound after a height regression continues from (101,1): %v", got)
	}
	if len(x.b.handraises()) != 2 {
		t.Fatal("Rebound(A) must not resend to B")
	}
}

func TestStandingHandraiseEnqueueFailureResendsWithoutReusingTheNonce(t *testing.T) {
	x := newHRHarness(t, nil)
	x.a.setFail(errors.New("outbox unwritable"))
	x.step(0, 100)
	if err := x.try(2*time.Second, 101); err == nil {
		t.Fatal("a failed enqueue must surface")
	}
	x.a.setFail(nil)
	x.step(100*time.Millisecond, 101)
	if got := issueOf(x.a); !slices.Equal(got, [][2]uint64{{101, 1}}) {
		t.Fatalf("the retry is a fresh handraise with the next nonce, got %v", got)
	}
	if len(x.b.handraises()) != 1 {
		t.Fatal("B is unaffected")
	}
}

func TestStandingHandraiseWithdrawsOnFactsAndStaysSilentOnReadFailures(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	x.chain.with(func(f *fakeHandraiseChain) { f.cortexKey.HasPendingRotation = true })
	x.step(100*time.Millisecond, 101)
	w := x.a.handraises()[1]
	if w.GetFreeSlotCount() != 0 || len(w.GetProfiles()) != 0 || w.GetHandraiseNonce() != 1 || w.GetServiceAuthorizationNonce() != 7 {
		t.Fatalf("withdrawal: %v", w)
	}
	x.step(10*time.Second, 106)
	if len(x.a.handraises()) != 2 {
		t.Fatal("after the withdrawal nothing is sent while the rotation is pending")
	}
	x.chain.with(func(f *fakeHandraiseChain) { f.cortexKey.HasPendingRotation = false })
	x.step(100*time.Millisecond, 106)
	if r := x.a.handraises()[2]; len(r.GetProfiles()) != 3 || r.GetIssuedHeight() != 106 || r.GetHandraiseNonce() != 0 {
		t.Fatalf("reopen: %v", r)
	}
	x.chain.with(func(f *fakeHandraiseChain) { f.nodeErr = errors.New("rpc down") })
	x.step(10*time.Second, 111)
	if len(x.a.handraises()) != 3 {
		t.Fatal("a failed chain read sends nothing, not even a withdrawal; the last handraise expires by height")
	}
}

func TestStandingHandraiseRunResendsOnStartAndRebound(t *testing.T) {
	x := newHRHarness(t, func(c *StandingHandraiseConfig) { c.EvalEvery = time.Hour })
	x.warm()
	x.open()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.h.Run(ctx) }()
	hrEventually(t, "restart resend", func() bool { return len(x.a.handraises()) == 2 && len(x.b.handraises()) == 2 })
	x.h.Rebound(hrBuilderA)
	hrEventually(t, "rebound resend", func() bool { return len(x.a.handraises()) == 3 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	if len(x.b.handraises()) != 2 {
		t.Fatal("Rebound(A) must not touch B")
	}
}

func TestStandingHandraiseRetriesAWithdrawalWhoseEnqueueFailed(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	x.chain.with(func(f *fakeHandraiseChain) { f.cortexKey.HasPendingRotation = true })
	x.a.setFail(errors.New("outbox unwritable"))
	if err := x.try(100*time.Millisecond, 101); err == nil {
		t.Fatal("a failed enqueue must surface")
	}
	x.a.setFail(nil)
	x.step(100*time.Millisecond, 101)
	hs := x.a.handraises()
	if len(hs) != 2 || len(hs[1].GetProfiles()) != 0 || hs[1].GetHandraiseNonce() != 2 {
		t.Fatalf("the withdrawal must be retried with a fresh nonce: %v", issueOf(x.a))
	}
	x.h.Rebound(hrBuilderA)
	x.step(100*time.Millisecond, 101)
	if len(x.a.handraises()) != 2 || len(x.b.handraises()) != 2 {
		t.Fatal("once a withdrawal is enqueued, a rebound sends nothing more (the outbox replays it)")
	}
}
