package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// slowDispatchChain delays every height-pinned read by one simulated round
// trip and records how many were in flight at once.
type slowDispatchChain struct {
	DispatchChainView
	delay time.Duration

	mu       sync.Mutex
	inflight int
	peak     int
}

func (s *slowDispatchChain) trip() func() {
	s.mu.Lock()
	s.inflight++
	s.peak = max(s.peak, s.inflight)
	s.mu.Unlock()
	time.Sleep(s.delay)
	return func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}
}

func (s *slowDispatchChain) maxInflight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func (s *slowDispatchChain) CortexNodeAt(ctx context.Context, op string, h uint64) (chainclient.CortexNodeSnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.CortexNodeAt(ctx, op, h)
}

func (s *slowDispatchChain) ServiceBondAt(ctx context.Context, op string, h uint64) (chainclient.ServiceBondSnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.ServiceBondAt(ctx, op, h)
}

func (s *slowDispatchChain) CurrentServiceKey(ctx context.Context, pt, op string, h uint64) (chainclient.ServiceKeySnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.CurrentServiceKey(ctx, pt, op, h)
}

func (s *slowDispatchChain) ModelSupportScopeAt(ctx context.Context, op, model, version string, h uint64) (chainclient.CommittedModelSupportScope, error) {
	defer s.trip()()
	return s.DispatchChainView.ModelSupportScopeAt(ctx, op, model, version, h)
}

func (s *slowDispatchChain) BuilderVrfKeyAt(ctx context.Context, op string, h uint64) (chainclient.VrfKeySnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.BuilderVrfKeyAt(ctx, op, h)
}

func (s *slowDispatchChain) BuilderSetAt(ctx context.Context, h uint64) (chainclient.BuilderSetSnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.BuilderSetAt(ctx, h)
}

func (s *slowDispatchChain) DispatchEpochAt(ctx context.Context, esh, h uint64) (chainclient.DispatchEpochSnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.DispatchEpochAt(ctx, esh, h)
}

func (s *slowDispatchChain) SessionAt(ctx context.Context, sid []byte, h uint64) (chainclient.SessionSnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.SessionAt(ctx, sid, h)
}

func (s *slowDispatchChain) WorkerLiabilityParamsAt(ctx context.Context, h uint64) (chainclient.WorkerLiabilityParamsSnapshot, error) {
	defer s.trip()()
	return s.DispatchChainView.WorkerLiabilityParamsAt(ctx, h)
}

// The Builder's accept window is a few hundred ms (nexus default 300 ms for
// the lowest RTT tier), so the offer's chain reads must not cost one round
// trip each: they go out together, and none is read twice.
func TestDispatchOfferReadsTheChainConcurrently(t *testing.T) {
	sequential := newDispatchHarness(t, 2, nil)
	if err := sequential.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, base := sequential.chain.reads()

	var slow *slowDispatchChain
	x := newDispatchHarness(t, 2, func(cfg *DispatcherConfig) {
		slow = &slowDispatchChain{DispatchChainView: cfg.Chain, delay: 40 * time.Millisecond}
		cfg.Chain = slow
	})
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.a.messages()[0].(*taskv1.DispatchAcceptV1); !ok {
		t.Fatalf("first message is %T, want DispatchAcceptV1", x.a.messages()[0])
	}
	if got := slow.maxInflight(); got < 8 {
		t.Fatalf("at most %d chain reads were in flight at once; the offer's reads must go out together", got)
	}
	if _, got := x.chain.reads(); got[150] > base[150] {
		t.Fatalf("%d pinned reads, %d without prefetch: a prefetched read must not be read again", got[150], base[150])
	}
}
