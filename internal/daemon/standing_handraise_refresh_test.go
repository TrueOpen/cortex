package daemon

import (
	"context"
	"testing"
	"time"
)

func TestStandingHandraiseRefreshSignsAtOnce(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	n := len(x.a.handraises())
	x.local.with(func(l *fakeHandraiseLocal) { l.free = 0 })
	x.now = x.now.Add(time.Millisecond)
	if err := x.h.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	hs := x.a.handraises()
	if len(hs) != n+1 || hs[len(hs)-1].GetFreeSlotCount() != 0 {
		t.Fatalf("Refresh must sign and enqueue the shrunk handraise before returning, got %d handraises", len(hs))
	}
}
