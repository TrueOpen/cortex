package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// slowDispatchChain delays every height-pinned read by one simulated round
// trip and records how many were in flight at once and in all. With stalled
// set, every read and CommittedHeight fail.
type slowDispatchChain struct {
	DispatchChainView
	delay time.Duration

	mu       sync.Mutex
	inflight int
	peak     int
	total    int
	stalled  bool
	// sessionFrom is the first height the Session is on chain at; zero: always.
	sessionFrom uint64
}

func (s *slowDispatchChain) trip() func() {
	s.mu.Lock()
	s.inflight++
	s.total++
	s.peak = max(s.peak, s.inflight)
	s.mu.Unlock()
	time.Sleep(s.delay)
	return func() {
		s.mu.Lock()
		s.inflight--
		s.mu.Unlock()
	}
}

// readCount is how many height-pinned reads were made so far.
func (s *slowDispatchChain) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

func (s *slowDispatchChain) stall(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stalled = on
}

func (s *slowDispatchChain) stallErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stalled {
		return errChainStalled
	}
	return nil
}

var errChainStalled = errors.New("chain stalled")

func (s *slowDispatchChain) CommittedHeight(ctx context.Context) (uint64, error) {
	if err := s.stallErr(); err != nil {
		return 0, err
	}
	return s.DispatchChainView.CommittedHeight(ctx)
}

func (s *slowDispatchChain) maxInflight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func (s *slowDispatchChain) CortexNodeAt(ctx context.Context, op string, h uint64) (chainclient.CortexNodeSnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.CortexNodeSnapshot{}, err
	}
	return s.DispatchChainView.CortexNodeAt(ctx, op, h)
}

func (s *slowDispatchChain) ServiceBondAt(ctx context.Context, op string, h uint64) (chainclient.ServiceBondSnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.ServiceBondSnapshot{}, err
	}
	return s.DispatchChainView.ServiceBondAt(ctx, op, h)
}

func (s *slowDispatchChain) CurrentServiceKey(ctx context.Context, pt, op string, h uint64) (chainclient.ServiceKeySnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.ServiceKeySnapshot{}, err
	}
	return s.DispatchChainView.CurrentServiceKey(ctx, pt, op, h)
}

func (s *slowDispatchChain) ModelSupportScopeAt(ctx context.Context, op, model, version string, h uint64) (chainclient.CommittedModelSupportScope, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.CommittedModelSupportScope{}, err
	}
	return s.DispatchChainView.ModelSupportScopeAt(ctx, op, model, version, h)
}

func (s *slowDispatchChain) BuilderVrfKeyAt(ctx context.Context, op string, h uint64) (chainclient.VrfKeySnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.VrfKeySnapshot{}, err
	}
	return s.DispatchChainView.BuilderVrfKeyAt(ctx, op, h)
}

func (s *slowDispatchChain) BuilderSetAt(ctx context.Context, h uint64) (chainclient.BuilderSetSnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.BuilderSetSnapshot{}, err
	}
	return s.DispatchChainView.BuilderSetAt(ctx, h)
}

func (s *slowDispatchChain) DispatchEpochAt(ctx context.Context, esh, h uint64) (chainclient.DispatchEpochSnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.DispatchEpochSnapshot{}, err
	}
	return s.DispatchChainView.DispatchEpochAt(ctx, esh, h)
}

func (s *slowDispatchChain) SessionAt(ctx context.Context, sid []byte, h uint64) (chainclient.SessionSnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.SessionSnapshot{}, err
	}
	s.mu.Lock()
	from := s.sessionFrom
	s.mu.Unlock()
	if h < from {
		return chainclient.SessionSnapshot{}, chainclient.ErrNotFound
	}
	return s.DispatchChainView.SessionAt(ctx, sid, h)
}

func (s *slowDispatchChain) WorkerLiabilityParamsAt(ctx context.Context, h uint64) (chainclient.WorkerLiabilityParamsSnapshot, error) {
	defer s.trip()()
	if err := s.stallErr(); err != nil {
		return chainclient.WorkerLiabilityParamsSnapshot{}, err
	}
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
