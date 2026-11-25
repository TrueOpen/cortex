package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

type fakeQuota struct {
	mu    sync.Mutex
	snap  chainclient.WorkerQuotaSnapshot
	err   error
	reads int
}

func (f *fakeQuota) WorkerQuota(context.Context, string) (chainclient.WorkerQuotaSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.snap, f.err
}

func (f *fakeQuota) set(s chainclient.WorkerQuotaSnapshot, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap, f.err = s, err
}

func pausedSnapshot(bits uint32) chainclient.WorkerQuotaSnapshot {
	return chainclient.WorkerQuotaSnapshot{DispatchPaused: true, PauseReasons: bits}
}

func TestChainPauseNilNeverRefuses(t *testing.T) {
	var p *ChainPause
	if err := p.Refusal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if NewChainPause(nil, "op", 0, nil, nil) != nil {
		t.Fatal("no reader means no gate")
	}
}

func TestChainPauseRefusesWhilePausedAndResumes(t *testing.T) {
	now := time.Unix(1000, 0)
	q := &fakeQuota{}
	p := NewChainPause(q, "op", time.Second, func() time.Time { return now }, nil)
	if err := p.Refusal(context.Background()); err != nil {
		t.Fatalf("not paused: %v", err)
	}
	q.set(pausedSnapshot(chainclient.PauseReasonLateSubmission), nil)
	if err := p.Refusal(context.Background()); err != nil {
		t.Fatal("the cached answer holds inside the refresh interval")
	}
	now = now.Add(2 * time.Second)
	err := p.Refusal(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), ChainPausedReason+":") || !strings.Contains(err.Error(), "late_submission") {
		t.Fatalf("paused refusal = %v", err)
	}
	// A failed read does not end the pause.
	q.set(chainclient.WorkerQuotaSnapshot{}, errors.New("connection refused"))
	now = now.Add(2 * time.Second)
	if p.Refusal(context.Background()) == nil {
		t.Fatal("a failed read must keep the pause")
	}
	q.set(chainclient.WorkerQuotaSnapshot{}, nil)
	now = now.Add(2 * time.Second)
	if err := p.Refusal(context.Background()); err != nil {
		t.Fatalf("cleared pause still refuses: %v", err)
	}
}

func TestChainPauseUnsupportedChainChangesNothing(t *testing.T) {
	now := time.Unix(1000, 0)
	q := &fakeQuota{err: chainclient.ErrQueryUnsupported}
	p := NewChainPause(q, "op", time.Second, func() time.Time { return now }, nil)
	for i := 0; i < 5; i++ {
		if err := p.Refusal(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(10 * time.Second)
	}
	if q.reads != 1 {
		t.Fatalf("an unsupported query is asked again only after a while, got %d reads", q.reads)
	}
	if _, known := p.Snapshot(context.Background()); known {
		t.Fatal("nothing is known on such a chain")
	}
}

func TestChainPauseQuotaExhaustionIsNotAPause(t *testing.T) {
	q := &fakeQuota{snap: chainclient.WorkerQuotaSnapshot{Enforced: true, Quota: 100, ReservedValue: 100}}
	p := NewChainPause(q, "op", time.Second, nil, nil)
	if err := p.Refusal(context.Background()); err != nil {
		t.Fatalf("a used-up quota is enforced by the Builders, not by withdrawing: %v", err)
	}
	if snap, known := p.Snapshot(context.Background()); !known || !snap.Enforced || snap.Remaining != 0 {
		t.Fatalf("snapshot %+v known %v", snap, known)
	}
}

func TestStandingHandraiseWithdrawsWhileTheChainPausesAndResumes(t *testing.T) {
	q := &fakeQuota{}
	x := newHRHarness(t, nil)
	x.warm()
	x.tweak = func(c *StandingHandraiseConfig) {
		c.ChainPause = NewChainPause(q, c.Operator, time.Millisecond, c.Now, nil)
	}
	x.open()
	x.step(100*time.Millisecond, 102)
	before := len(x.a.handraises())
	if before == 0 || x.a.handraises()[before-1].GetFreeSlotCount() == 0 {
		t.Fatal("an unpaused Worker offers")
	}
	q.set(pausedSnapshot(chainclient.PauseReasonLateSubmission), nil)
	x.step(10*time.Second, 106)
	for _, b := range []*fakeEnqueuer{x.a, x.b} {
		hs := b.handraises()
		if last := hs[len(hs)-1]; last.GetFreeSlotCount() != 0 || len(last.GetProfiles()) != 0 {
			t.Fatalf("a paused Worker must withdraw from every Builder, last handraise %v", last)
		}
	}
	if cur, ok := x.h.Current(hrBuilderA); !ok || !cur.Withdrawn {
		t.Fatal("the withdrawal is the current handraise")
	}
	q.set(chainclient.WorkerQuotaSnapshot{}, nil)
	x.step(10*time.Second, 110)
	hs := x.a.handraises()
	if hs[len(hs)-1].GetFreeSlotCount() == 0 {
		t.Fatal("the handraise resumes when the chain clears the pause")
	}
}

func TestDispatcherRefusesOffersWhileTheChainPauses(t *testing.T) {
	q := &fakeQuota{snap: pausedSnapshot(chainclient.PauseReasonJailed)}
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) {
		c.ChainPause = NewChainPause(q, c.Operator, time.Second, nil, nil)
	})
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchRejected || rec.RejectClass != classChainPaused || rec.RejectReason != int32(reasonNoCapacity) {
		t.Fatalf("record = %s %s %d, want a signed NO_CAPACITY reject of class %s", rec.State, rec.RejectClass, rec.RejectReason, classChainPaused)
	}
	if len(x.infer.starts()) != 0 {
		t.Fatal("nothing starts while paused")
	}
}
