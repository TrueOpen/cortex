package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStandingHandraiseRefreshSignsAtOnce(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	n := len(x.a.handraises())
	x.local.with(func(l *fakeHandraiseLocal) { l.free = 0 })
	x.now = x.now.Add(time.Millisecond)
	if err := x.h.Refresh(context.Background(), hrBuilderA); err != nil {
		t.Fatal(err)
	}
	hs := x.a.handraises()
	if len(hs) != n+1 || hs[len(hs)-1].GetFreeSlotCount() != 0 {
		t.Fatalf("Refresh must sign and enqueue the shrunk handraise before returning, got %d handraises", len(hs))
	}
}

// A failure toward another Builder does not fail a Refresh for this one, and
// a Builder whose enqueue is backing off cannot be refreshed.
func TestStandingHandraiseRefreshIsScopedToItsBuilder(t *testing.T) {
	ctx := context.Background()
	x := newHRHarness(t, nil)
	x.warm()
	x.b.setFail(errors.New("outbox down"))
	x.local.with(func(l *fakeHandraiseLocal) { l.free = 0 })
	x.now = x.now.Add(time.Millisecond)
	if err := x.h.Refresh(ctx, hrBuilderA); err != nil {
		t.Fatalf("Builder B's failure leaked into A's refresh: %v", err)
	}
	if err := x.h.Refresh(ctx, hrBuilderB); err == nil {
		t.Fatal("B's own refresh fails while its enqueue backs off")
	}
}
