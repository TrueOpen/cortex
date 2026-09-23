package builderdirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// testClock is a hand-advanced clock. Cache expiry is a decision about staleness,
// not about elapsed wall time, so the tests state the passage of time explicitly
// rather than sleeping.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Unix(1_700_000_000, 0).UTC()}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (k *stubKeeper) builderReads() int {
	// Every resolution starts with CommittedBuilder, so counting the heights it
	// recorded counts resolutions that actually reached the chain.
	reads := 0
	for range k.heights {
		reads++
	}
	return reads / 3
}

// The readiness controller re-resolves the configured Builder on every tick
// (default one second), and every Task that fetches input or output resolves its
// receiving Builder. Without a cache each of those is three chain reads.
func TestResolveServesRepeatedCallsFromOneChainRead(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: 30 * time.Second,
		Now:      clock.Now,
	})

	for i := range 5 {
		identity, err := resolver.Resolve(context.Background(), testOperator)
		if err != nil {
			t.Fatalf("Resolve() attempt %d error = %v", i, err)
		}
		if identity.Endpoint != "https://nexus.example.org" || identity.SnapshotHeight != 500 {
			t.Fatalf("identity = %+v", identity)
		}
	}
	if reads := keeper.builderReads(); reads != 1 {
		t.Fatalf("chain resolutions = %d, want 1", reads)
	}
}

func TestResolveRefreshesAfterTheCacheWindow(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: 30 * time.Second,
		Now:      clock.Now,
	})

	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	clock.Advance(31 * time.Second)
	keeper.height = 640
	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if identity.SnapshotHeight != 640 {
		t.Fatalf("SnapshotHeight = %d, want the refreshed height 640", identity.SnapshotHeight)
	}
	if reads := keeper.builderReads(); reads != 2 {
		t.Fatalf("chain resolutions = %d, want 2", reads)
	}
}

// A rotation or a descriptor update must not wait out the cache window: the
// chain event that reports it invalidates the entry.
func TestInvalidateForcesTheNextResolveOntoTheChain(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: time.Hour,
		Now:      clock.Now,
	})

	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	resolver.Invalidate(testOperator)
	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if reads := keeper.builderReads(); reads != 2 {
		t.Fatalf("chain resolutions = %d, want 2", reads)
	}

	resolver.InvalidateAll()
	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("third Resolve() error = %v", err)
	}
	if reads := keeper.builderReads(); reads != 3 {
		t.Fatalf("chain resolutions = %d, want 3", reads)
	}
}

// A node behind a load balancer can be served by a replica that has committed
// fewer blocks. Replacing a newer identity with an older one would silently
// reintroduce a rotated-out endpoint, so the higher height wins.
func TestResolveKeepsTheIdentityFromTheHigherHeight(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: 30 * time.Second,
		Now:      clock.Now,
	})

	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	clock.Advance(31 * time.Second)
	keeper.height = 400
	keeper.descriptor = descriptorWith(t, nexusEndpoint("https://stale.example.org"))
	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if identity.SnapshotHeight != 500 || identity.Endpoint != "https://nexus.example.org" {
		t.Fatalf("identity = %+v, want the height-500 identity retained", identity)
	}
}

// A burst of Tasks for one Builder must not fan out into a burst of chain reads.
func TestConcurrentResolveCollapsesIntoOneChainRead(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: 30 * time.Second,
		Now:      clock.Now,
	})
	keeper.block = make(chan struct{})

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
				errs <- err
			}
		}()
	}
	// Every caller is now either waiting on the shared read or on its result.
	close(keeper.block)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Resolve() error = %v", err)
	}
	if reads := keeper.builderReads(); reads != 1 {
		t.Fatalf("chain resolutions = %d, want 1", reads)
	}
}

// An invalidation that lands while a read is in flight must win. The read began
// before the chain event, so its answer is already known to be superseded, and
// caching it would keep the superseded view alive for a whole window - exactly
// what the explicit invalidation exists to prevent.
func TestInvalidateDuringAnInFlightLoadIsNotOverwritten(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: time.Hour,
		Now:      clock.Now,
	})
	keeper.block = make(chan struct{})
	keeper.entered = make(chan struct{}, 1)

	resolved := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(context.Background(), testOperator)
		resolved <- err
	}()
	// Wait until the resolution is genuinely parked inside its first chain read,
	// so the invalidation lands during the load and not before it starts.
	<-keeper.entered
	resolver.Invalidate(testOperator)
	close(keeper.block)
	if err := <-resolved; err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	keeper.block = nil
	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("Resolve() after invalidate error = %v", err)
	}
	if reads := keeper.builderReads(); reads != 2 {
		t.Fatalf("chain resolutions = %d, want the raced load to have been discarded", reads)
	}
}

// Neither the caller that starts a shared read nor a caller that joins it may be
// held hostage by the other: each leaves on its own deadline, while the read
// itself is detached and still completes and caches. A readiness tick cancelled
// during shutdown must not have to wait out three Keeper requests.
func TestCallersLeaveOnTheirOwnDeadlineWhileTheSharedReadCompletes(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: time.Hour,
		Now:      clock.Now,
	})
	keeper.block = make(chan struct{})
	keeper.entered = make(chan struct{}, 1)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(leaderCtx, testOperator)
		leaderDone <- err
	}()
	// The read is now in flight, so the next caller joins it instead of starting
	// a second one.
	<-keeper.entered

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(waiterCtx, testOperator)
		waiterDone <- err
	}()

	cancelWaiter()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter error = %v, want its own cancellation", err)
	}
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want its own cancellation", err)
	}

	// Both callers are gone; the detached read finishes and is cached, so the
	// next caller is served without touching the chain again.
	close(keeper.block)
	keeper.entered = nil
	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve() after the shared read error = %v", err)
	}
	if identity.Endpoint != "https://nexus.example.org" {
		t.Fatalf("identity = %+v", identity)
	}
	if reads := keeper.builderReads(); reads != 1 {
		t.Fatalf("chain resolutions = %d, want the detached read to have been cached", reads)
	}
}

// The height guard protects against a replica that lags by seconds. A chain that
// persistently serves lower heights - a node repointed at another Keeper, or a
// devnet reset - must not pin the cached identity forever.
func TestPersistentHeightRegressionIsEventuallyAccepted(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: 30 * time.Second,
		Now:      clock.Now,
	})

	if _, err := resolver.Resolve(context.Background(), testOperator); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	// Still a regression from 500, and still above the descriptor's own updated
	// height so the only thing under test is the guard.
	keeper.height = 130
	keeper.descriptor = descriptorWith(t, nexusEndpoint("https://reset.example.org"))

	clock.Advance(31 * time.Second)
	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve() during the guard window error = %v", err)
	}
	if identity.Endpoint != "https://nexus.example.org" {
		t.Fatalf("identity = %+v, want the higher-height identity retained inside the guard window", identity)
	}

	clock.Advance(heightGuardWindow)
	identity, err = resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve() after the guard window error = %v", err)
	}
	if identity.Endpoint != "https://reset.example.org" || identity.SnapshotHeight != 130 {
		t.Fatalf("identity = %+v, want the new chain view accepted after the guard window", identity)
	}
}

// A failed resolution is never cached: the next caller must reach the chain
// again rather than inherit a refusal that may already be stale.
func TestResolveDoesNotCacheFailures(t *testing.T) {
	clock := newTestClock()
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{
		CacheTTL: time.Hour,
		Now:      clock.Now,
	})
	keeper.builderErr = fmt.Errorf("keeper is unavailable")

	for range 3 {
		if _, err := resolver.Resolve(context.Background(), testOperator); err == nil {
			t.Fatal("Resolve() error = nil, want the keeper failure")
		}
	}
	keeper.builderErr = nil
	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve() after recovery error = %v", err)
	}
	if identity.Endpoint != "https://nexus.example.org" {
		t.Fatalf("identity = %+v", identity)
	}
}

type stubMembershipKeeper struct {
	mu     sync.Mutex
	reads  int
	set    chainclient.BuilderSetSnapshot
	height uint64
	err    error
}

func (k *stubMembershipKeeper) CommittedBuilderSet(context.Context) (chainclient.BuilderSetSnapshot, uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reads++
	if k.err != nil {
		return chainclient.BuilderSetSnapshot{}, 0, k.err
	}
	return k.set, k.height, nil
}

func (k *stubMembershipKeeper) observedReads() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.reads
}

func newMembershipFixture(t *testing.T, clock *testClock, ttl time.Duration) (*Membership, *stubMembershipKeeper) {
	t.Helper()
	keeper := &stubMembershipKeeper{
		height: 500,
		set: chainclient.BuilderSetSnapshot{
			BuilderSetVersion: chainclient.Uint64String(7),
			BuilderSetID:      "builder-set-7",
			SetHash:           mustHexHash(t, strings.Repeat("5a", 32)),
			Builders:          []string{testOperator, "trueopen1builderb"},
			SnapshotHeight:    chainclient.Uint64String(500),
		},
	}
	membership, err := NewMembership(keeper, MembershipOptions{CacheTTL: ttl, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewMembership: %v", err)
	}
	return membership, keeper
}

// Membership is consulted once per inbound bus frame, so it must not be one
// chain read per frame.
func TestMembershipServesRepeatedChecksFromOneChainRead(t *testing.T) {
	clock := newTestClock()
	membership, keeper := newMembershipFixture(t, clock, 30*time.Second)

	for range 5 {
		member, err := membership.HasBuilder(context.Background(), testOperator)
		if err != nil || !member {
			t.Fatalf("HasBuilder() = %v, %v", member, err)
		}
	}
	member, err := membership.HasBuilder(context.Background(), "trueopen1stranger")
	if err != nil || member {
		t.Fatalf("HasBuilder(stranger) = %v, %v", member, err)
	}
	if reads := keeper.observedReads(); reads != 1 {
		t.Fatalf("chain reads = %d, want 1", reads)
	}
}

func TestMembershipRefreshesAfterTheWindowAndOnInvalidate(t *testing.T) {
	clock := newTestClock()
	membership, keeper := newMembershipFixture(t, clock, 30*time.Second)

	if _, err := membership.HasBuilder(context.Background(), testOperator); err != nil {
		t.Fatalf("HasBuilder() error = %v", err)
	}
	clock.Advance(31 * time.Second)
	if _, err := membership.HasBuilder(context.Background(), testOperator); err != nil {
		t.Fatalf("HasBuilder() after the window error = %v", err)
	}
	if reads := keeper.observedReads(); reads != 2 {
		t.Fatalf("chain reads = %d, want 2", reads)
	}

	// A BuilderSet update event must take effect immediately, not at the end of
	// the cache window: the set that admitted a sender may no longer contain it.
	membership.Invalidate()
	keeper.height = 620
	keeper.set.Builders = []string{"trueopen1builderb"}
	keeper.set.SnapshotHeight = chainclient.Uint64String(620)
	member, err := membership.HasBuilder(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("HasBuilder() after invalidate error = %v", err)
	}
	if member {
		t.Fatal("HasBuilder() = true, want the removed Builder to stop being a member")
	}
	if reads := keeper.observedReads(); reads != 3 {
		t.Fatalf("chain reads = %d, want 3", reads)
	}
}

// An unreadable chain view is this node's failure, and it must surface as one:
// reporting "not a member" would let a Keeper outage look like an unauthorized
// sender.
func TestMembershipReportsReadFailuresAndDoesNotCacheThem(t *testing.T) {
	clock := newTestClock()
	membership, keeper := newMembershipFixture(t, clock, time.Hour)
	keeper.err = fmt.Errorf("keeper is unavailable")

	for range 3 {
		if _, err := membership.HasBuilder(context.Background(), testOperator); err == nil {
			t.Fatal("HasBuilder() error = nil, want the keeper failure")
		}
	}
	keeper.err = nil
	member, err := membership.HasBuilder(context.Background(), testOperator)
	if err != nil || !member {
		t.Fatalf("HasBuilder() after recovery = %v, %v", member, err)
	}
	if reads := keeper.observedReads(); reads != 4 {
		t.Fatalf("chain reads = %d, want every failed check to have retried", reads)
	}
}

func TestMembershipKeepsTheSetFromTheHigherHeight(t *testing.T) {
	clock := newTestClock()
	membership, keeper := newMembershipFixture(t, clock, 30*time.Second)

	if _, err := membership.HasBuilder(context.Background(), testOperator); err != nil {
		t.Fatalf("HasBuilder() error = %v", err)
	}
	clock.Advance(31 * time.Second)
	keeper.height = 400
	keeper.set.Builders = []string{"trueopen1builderb"}
	keeper.set.SnapshotHeight = chainclient.Uint64String(400)
	member, err := membership.HasBuilder(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("HasBuilder() error = %v", err)
	}
	if !member {
		t.Fatal("HasBuilder() = false, want the height-500 set retained over a height-400 read")
	}
}
