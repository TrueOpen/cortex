package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// A Builder counts a signed reject against a Worker's reject rate only when
// the Worker's current standing handraise advertises a free slot, and stops
// admitting a Worker whose rate passes its threshold. These tests pin what
// keeps the anchor admission gate out of that rate: the handraise that takes
// the capacity back is enqueued before any reject the gate causes.

// admissionHarness is a standing handraise over a real admission signal,
// read at the harness clock.
type admissionHarness struct {
	*hrHarness
	path string
}

func newAdmissionHarness(t *testing.T, anchorKeys ...string) *admissionHarness {
	t.Helper()
	a := &admissionHarness{path: filepath.Join(t.TempDir(), "admission.json")}
	a.hrHarness = newHRHarness(t, func(c *StandingHandraiseConfig) {
		c.Anchor = &fakeAnchorProbe{}
		c.AnchorAdmission = NewAnchorAdmission(config.AnchorAdmissionConfig{File: a.path}, func() time.Time { return a.now }, nil)
	})
	a.chain.with(func(f *fakeHandraiseChain) {
		for _, key := range anchorKeys {
			f.scopes[key] = requireAnchor(f.scopes[key])
		}
	})
	return a
}

func (a *admissionHarness) signal(accept bool) {
	a.t.Helper()
	writeAdmission(a.t, a.path, fmt.Sprintf(`{"accept":%v,"reason":"backlog","updated":%d}`, accept, a.now.Unix()))
}

// A node whose Profiles all require kind 5 withdraws (zero free slots, no
// Profile) on the first pass after the gate closes, stays silent while it is
// closed, and re-advertises on the first pass after it opens: no chain
// height, Notify or Rebound is needed, and the minimum change interval does
// not hold either send.
func TestStandingHandraiseWithdrawsWhileTheAdmissionGateIsClosed(t *testing.T) {
	x := newAdmissionHarness(t, config.MinPriceBidKey(hrModelAB, 1), config.MinPriceBidKey(hrModelAB, 2), config.MinPriceBidKey(hrModelCD, 1))
	x.signal(true)
	x.warm()
	if hs := x.a.handraises(); len(hs) != 1 || hs[0].GetFreeSlotCount() != 3 || len(hs[0].GetProfiles()) != 3 {
		t.Fatalf("open gate: %v", hs)
	}
	x.signal(false)
	x.step(100*time.Millisecond, 101)
	hs := x.a.handraises()
	if len(hs) != 2 || hs[1].GetFreeSlotCount() != 0 || len(hs[1].GetProfiles()) != 0 {
		t.Fatalf("closed gate: want a withdrawal 100 ms later at the same height, got %v", hs)
	}
	if cur, ok := x.h.Current(hrBuilderA); !ok || !cur.Withdrawn || cur.State.FreeSlots != 0 {
		t.Fatalf("current handraise %+v", cur)
	}
	for range 5 {
		x.signal(false)
		x.step(time.Second, 101)
	}
	if len(x.a.handraises()) != 2 {
		t.Fatalf("%d handraises while the gate stays closed, want the one withdrawal", len(x.a.handraises()))
	}
	x.signal(true)
	x.step(100*time.Millisecond, 101)
	hs = x.a.handraises()
	if len(hs) != 3 || hs[2].GetFreeSlotCount() != 3 || len(hs[2].GetProfiles()) != 3 {
		t.Fatalf("reopened gate: want capacity re-advertised 100 ms later at the same height, got %v", hs)
	}
	if len(x.b.handraises()) != 3 {
		t.Fatalf("the other Builder saw %d handraises, want the same three", len(x.b.handraises()))
	}
}

// A node that also serves Profiles without kind 5 keeps those and its free
// slots: the gated Profile leaves at once (a shrink is never held) and comes
// back as an ordinary change.
func TestStandingHandraiseDropsOnlyGatedProfiles(t *testing.T) {
	ab1, ab2, cd1 := hrProfile(hrModelAB, 1), hrProfile(hrModelAB, 2), hrProfile(hrModelCD, 1)
	x := newAdmissionHarness(t, config.MinPriceBidKey(hrModelCD, 1))
	x.signal(true)
	x.warm()
	x.signal(false)
	x.step(100*time.Millisecond, 101)
	cur, _ := x.h.Current(hrBuilderA)
	if len(x.a.handraises()) != 2 || cur.Withdrawn || cur.State.FreeSlots != 3 || !slices.Equal(cur.State.Profiles, []HandraiseProfile{ab1, ab2}) {
		t.Fatalf("closed gate: %+v after %d handraises", cur, len(x.a.handraises()))
	}
	x.signal(true)
	x.step(100*time.Millisecond, 101)
	if len(x.a.handraises()) != 2 {
		t.Fatal("growth of a live offer is held for the minimum change interval")
	}
	x.signal(true)
	x.step(2*time.Second, 101)
	if cur, _ = x.h.Current(hrBuilderA); len(x.a.handraises()) != 3 || !slices.Equal(cur.State.Profiles, []HandraiseProfile{ab1, ab2, cd1}) {
		t.Fatalf("reopened gate: %+v after %d handraises", cur, len(x.a.handraises()))
	}
}

// gatedHandraise stands in for the StandingHandraiser in Dispatcher tests:
// Refresh does what one evaluation pass does to the current handraise while
// the gate is closed (withdraw, or drop the gated Profile on a node that
// serves others too) and logs it in the order the Builder outbox would see.
type gatedHandraise struct {
	*fakeDispatchHandraise
	gate       *AnchorAdmission
	gated      HandraiseProfile
	keepOthers bool
}

func (h *gatedHandraise) Refresh(ctx context.Context, builder string) error {
	if err := h.fakeDispatchHandraise.Refresh(ctx, builder); err != nil {
		return err
	}
	if h.gate.Refusal() == nil {
		return nil
	}
	h.mu.Lock()
	c := h.current[builder]
	event := "handraise:withdraw"
	if h.keepOthers {
		c.State.Profiles = slices.DeleteFunc(slices.Clone(c.State.Profiles), func(p HandraiseProfile) bool { return p == h.gated })
		event = "handraise:shrink"
	} else {
		c.Withdrawn, c.State.FreeSlots, c.State.Profiles = true, 0, nil
	}
	h.current[builder] = c
	h.mu.Unlock()
	h.log.add(event)
	return nil
}

// gatedOfferHarness offers a kind 5 Profile to a Dispatcher whose last
// handraise still lists it with two free slots.
func gatedOfferHarness(t *testing.T, a *AnchorAdmission, keepOthers bool) (*dispatchHarness, *gatedHandraise) {
	t.Helper()
	x := newDispatchHarness(t, 2, nil)
	x.chain.with(func(f *fakeDispatchChain) {
		key := config.MinPriceBidKey(hrModelAB, 1)
		f.scopes[key] = requireAnchor(f.scopes[key])
	})
	ab1 := hrProfile(hrModelAB, 1)
	x.hr.mu.Lock()
	c := x.hr.current[hrBuilderA]
	c.State.Profiles = []HandraiseProfile{ab1, hrProfile(hrModelAB, 2)}
	x.hr.current[hrBuilderA] = c
	x.hr.mu.Unlock()
	g := &gatedHandraise{fakeDispatchHandraise: x.hr, gate: a, gated: ab1, keepOthers: keepOthers}
	x.reconfigure(func(cfg *DispatcherConfig) {
		cfg.Anchor, cfg.AnchorAdmission, cfg.Handraise = &fakeAnchorProbe{}, a, g
	})
	return x, g
}

// rejectRateSamples replays the outbox order through the Builder's rule: a
// signed reject is a reject-rate sample only while the handraise the Builder
// holds advertises a free slot.
func rejectRateSamples(events []string, free uint32) (rejects, counted int) {
	for _, e := range events {
		switch {
		case e == "handraise:withdraw":
			free = 0
		case strings.HasSuffix(e, "DispatchRejectV1"):
			rejects++
			if free > 0 {
				counted++
			}
		}
	}
	return rejects, counted
}

const rejectEvent = "enqueue:task.v1.DispatchRejectV1"

func TestDispatchOfferClosesTheHandraiseBeforeAnAdmissionReject(t *testing.T) {
	ctx := context.Background()
	t.Run("the withdrawal is enqueued ahead of the reject", func(t *testing.T) {
		a, _, _ := newTestAdmission(t, admissionAbsent)
		x, _ := gatedOfferHarness(t, a, false)
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		if got, want := x.log.all(), []string{"handraise:refresh", "handraise:withdraw", rejectEvent}; !slices.Equal(got, want) {
			t.Fatalf("events %v, want %v", got, want)
		}
		if rec := x.record(t); rec.RejectClass != classAnchorAdmission {
			t.Fatalf("reject class %q", rec.RejectClass)
		}
	})
	t.Run("a handraise that no longer offers the Profile needs no re-sign", func(t *testing.T) {
		for name, edit := range map[string]func(*CurrentHandraise){
			"withdrawn":        func(c *CurrentHandraise) { c.Withdrawn = true },
			"no free slot":     func(c *CurrentHandraise) { c.State.FreeSlots = 0 },
			"profile left out": func(c *CurrentHandraise) { c.State.Profiles = c.State.Profiles[1:] },
		} {
			a, _, _ := newTestAdmission(t, admissionAbsent)
			x, _ := gatedOfferHarness(t, a, false)
			x.hr.mu.Lock()
			c := x.hr.current[hrBuilderA]
			edit(&c)
			x.hr.current[hrBuilderA] = c
			x.hr.mu.Unlock()
			if err := x.handle(ctx); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got := x.log.all(); !slices.Equal(got, []string{rejectEvent}) {
				t.Fatalf("%s: events %v, want the reject alone", name, got)
			}
		}
	})
	t.Run("an open gate re-signs nothing", func(t *testing.T) {
		a, _, _ := newTestAdmission(t, fmt.Sprintf(`{"accept":true,"updated":%d}`, admissionAt.Unix()))
		x, _ := gatedOfferHarness(t, a, false)
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
		if got := x.log.all(); slices.Contains(got, "handraise:refresh") || slices.Contains(got, rejectEvent) {
			t.Fatalf("events %v, want an accept and no re-sign", got)
		}
	})
	t.Run("a handraise that cannot be re-signed sends no reject", func(t *testing.T) {
		a, _, _ := newTestAdmission(t, admissionAbsent)
		x, _ := gatedOfferHarness(t, a, false)
		x.hr.setRefreshErr(errors.New("outbox backing off"))
		err := x.handle(ctx)
		if err == nil || !builderclient.IsRetryable(err) {
			t.Fatalf("err = %v, want a retryable failure", err)
		}
		if got := x.log.all(); slices.Contains(got, rejectEvent) {
			t.Fatalf("events %v: the reject must not overtake the handraise", got)
		}
		if rec := x.record(t); rec.State != layout.DispatchOffered || len(rec.Reject) != 0 {
			t.Fatalf("record %+v, want the offer left unanswered for its redelivery", rec)
		}
	})
}

// Many offers against a closed gate. On a node whose servable Profiles all
// require kind 5 none of the rejects is a reject-rate sample: the first one
// follows the withdrawal in the outbox, and the rest meet a handraise that
// already advertises nothing. The handraise is re-signed once, not per offer.
func TestManyOffersAgainstAClosedGateDoNotFeedTheRejectRate(t *testing.T) {
	const offers = 60
	ctx := context.Background()
	a, _, _ := newTestAdmission(t, admissionAbsent)
	x, _ := gatedOfferHarness(t, a, false)
	for round := uint32(1); round <= offers; round++ {
		x.nextOffer(round)
		if err := x.handle(ctx); err != nil {
			t.Fatalf("offer %d: %v", round, err)
		}
	}
	events := x.log.all()
	rejects, counted := rejectRateSamples(events, 2)
	if rejects != offers || counted != 0 {
		t.Fatalf("%d rejects, %d of them reject-rate samples; want %d and 0", rejects, counted, offers)
	}
	if n := len(events) - rejects; n != 2 || events[0] != "handraise:refresh" || events[1] != "handraise:withdraw" {
		t.Fatalf("events before and between the rejects: %v", events[:min(len(events), 6)])
	}
	if status, _ := a.Status(); status.RefusedOffers != offers {
		t.Fatalf("refused offers %d, want %d", status.RefusedOffers, offers)
	}
	if x.leaseCount(t) != 0 {
		t.Fatalf("%d leases held after %d refused offers", x.leaseCount(t), offers)
	}
}

// The residual. A node that keeps other Profiles on offer still advertises
// free slots after the gated Profile left its handraise, so a reject of an
// offer already in flight is a reject-rate sample. The handraise is still
// re-signed first and only once; what bounds the samples is that a Builder
// which holds the new handraise sends no further offer for the Profile.
func TestInFlightOffersOnAMixedNodeAreTheOnlyRejectRateSamples(t *testing.T) {
	ctx := context.Background()
	a, _, _ := newTestAdmission(t, admissionAbsent)
	x, g := gatedOfferHarness(t, a, true)
	const inFlight = 3
	for round := uint32(1); round <= inFlight; round++ {
		x.nextOffer(round)
		if err := x.handle(ctx); err != nil {
			t.Fatal(err)
		}
	}
	events := x.log.all()
	if rejects, counted := rejectRateSamples(events, 2); rejects != inFlight || counted != inFlight {
		t.Fatalf("%d rejects, %d samples; want %d of each (one per offer in flight)", rejects, counted, inFlight)
	}
	if got, want := events[:3], []string{"handraise:refresh", "handraise:shrink", rejectEvent}; !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v first", events, want)
	}
	if n := strings.Count(strings.Join(events, " "), "handraise:refresh"); n != 1 {
		t.Fatalf("handraise re-signed %d times, want once", n)
	}
	if cur, _ := g.Current(hrBuilderA); cur.Withdrawn || cur.State.FreeSlots != 2 || slices.Contains(cur.State.Profiles, g.gated) {
		t.Fatalf("current handraise %+v, want the other Profile and both slots still on offer", cur)
	}
}
