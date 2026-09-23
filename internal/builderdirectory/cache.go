package builderdirectory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// DefaultCacheTTL bounds how long a resolved identity or a membership snapshot
// may be reused without asking the chain again. It is deliberately a constant
// rather than a config key: it is not a policy an operator tunes, it is the
// staleness this build is willing to carry between the events that invalidate
// these entries explicitly.
//
// The window exists because both reads are on hot paths. The readiness
// controller re-resolves the configured Builder every tick (one second by
// default), and membership is consulted once per inbound bus frame. Correctness
// never depends on the window: an entry is dropped the moment the chain reports
// a change, and every value carries the height it was read at.
const DefaultCacheTTL = 30 * time.Second

// heightGuardWindow bounds how long a retained higher-height value may refuse a
// lower-height read. The case the guard is for — a replica behind a load
// balancer that has committed fewer blocks — is transient and measured in
// seconds. A persistent regression is a different situation entirely: a node
// repointed at another Keeper, or a devnet reset that restarts heights low. An
// unbounded guard would pin the cached value forever there, because the retained
// entry is already expired and no expiry can rescue it. After this window the
// lower-height read is accepted.
const heightGuardWindow = 4 * DefaultCacheTTL

// cacheEntry is one cached value plus the facts that decide whether it may be
// served or replaced: when it was read, when it goes stale, and which committed
// height produced it.
type cacheEntry[T any] struct {
	value          T
	readAt         time.Time
	expiresAt      time.Time
	snapshotHeight uint64
}

// cache is a single-value-per-key store with expiry, a bounded monotonic-height
// guard, and single-flight loading. It caches successes only: a failure must not
// be inherited by the next caller, because the condition that caused it may
// already be gone and a cached refusal would outlive it.
type cache[T any] struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry[T]
	loads   map[string]*load[T]
	// generations counts invalidations per key, and epoch counts whole-cache
	// invalidations. A load captures both before reading the chain, so a value
	// whose read began before an invalidation cannot be stored after it: the
	// invalidation exists precisely because that view is known to be superseded,
	// and the height guard cannot catch it because invalidation erased the height
	// it would have compared against. Counting per key keeps invalidating one
	// Builder from also discarding an unrelated in-flight read.
	generations map[string]uint64
	epoch       uint64
}

// load is one in-flight fill. Callers that arrive while a fill is running wait
// on it instead of starting their own: a burst of Tasks for one Builder is one
// chain resolution, not one per Task. The leader publishes the effective value
// before closing done, so waiters never commit anything themselves.
type load[T any] struct {
	done  chan struct{}
	value T
	err   error
}

func newCache[T any](ttl time.Duration, now func() time.Time) *cache[T] {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &cache[T]{
		ttl:         ttl,
		now:         now,
		entries:     make(map[string]cacheEntry[T]),
		loads:       make(map[string]*load[T]),
		generations: make(map[string]uint64),
	}
}

// get returns the cached value for key, filling it through fill when absent or
// stale. fill reports the value and the committed height it was read at.
func (c *cache[T]) get(ctx context.Context, key string, fill func(context.Context) (T, uint64, error)) (T, error) {
	var zero T
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok && c.now().Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.value, nil
	}
	if inflight, ok := c.loads[key]; ok {
		c.mu.Unlock()
		// Waiting on someone else's read must not outlive this caller's own
		// deadline: the leader is a different request with a different budget.
		select {
		case <-inflight.done:
		case <-ctx.Done():
			return zero, ctx.Err()
		}
		return inflight.value, inflight.err
	}
	inflight := &load[T]{done: make(chan struct{})}
	c.loads[key] = inflight
	generation, epoch := c.generations[key], c.epoch
	c.mu.Unlock()

	// The read is shared and outlives the caller that started it: an abandoned
	// Task must not cancel the answer other callers are waiting for. It also runs
	// off this goroutine so the leader can leave on its own deadline exactly like
	// a waiter - a readiness tick that is cancelled during shutdown must not have
	// to wait out three Keeper requests. The Keeper client carries its own
	// per-request timeout, so the detached read still terminates.
	go func() {
		value, height, err := fill(context.WithoutCancel(ctx))
		if err == nil {
			value = c.commit(key, value, height, generation, epoch)
		} else {
			var empty T
			value = empty
		}
		inflight.value, inflight.err = value, err
		close(inflight.done)

		c.mu.Lock()
		delete(c.loads, key)
		c.mu.Unlock()
	}()

	select {
	case <-inflight.done:
		return inflight.value, inflight.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

// commit stores a freshly loaded value and returns what callers should use.
//
// It refuses to store in two cases. An invalidation that happened while the read
// was in flight means this view is already known to be superseded, so the value
// is returned but not cached: it was still read at a real committed height, so
// the one caller waiting on it is answered as of that height, and the next
// caller re-reads. A value read at a lower committed height than the one already
// cached is refused for as long as heightGuardWindow, so a lagging replica
// cannot silently reintroduce a rotated-out endpoint or a membership the chain
// has already changed.
func (c *cache[T]) commit(key string, value T, height uint64, generation uint64, epoch uint64) T {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generations[key] != generation || c.epoch != epoch {
		return value
	}
	now := c.now()
	if entry, ok := c.entries[key]; ok && entry.snapshotHeight > height &&
		now.Sub(entry.readAt) < heightGuardWindow {
		return entry.value
	}
	c.entries[key] = cacheEntry[T]{
		value:          value,
		readAt:         now,
		expiresAt:      now.Add(c.ttl),
		snapshotHeight: height,
	}
	return value
}

func (c *cache[T]) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generations[key]++
	delete(c.entries, key)
}

func (c *cache[T]) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.entries = make(map[string]cacheEntry[T])
	c.generations = make(map[string]uint64)
}

// Invalidate drops the cached identity of one Builder. It is what a service-key
// rotation, a revocation or a descriptor update calls: those must take effect
// immediately rather than at the end of the cache window.
func (r *Resolver) Invalidate(operatorAddress string) {
	if r == nil || r.cache == nil {
		return
	}
	r.cache.invalidate(operatorAddress)
}

// InvalidateAll drops every cached identity.
func (r *Resolver) InvalidateAll() {
	if r == nil || r.cache == nil {
		return
	}
	r.cache.invalidateAll()
}

// MembershipReader is the chain state Membership needs. CommittedBuilderSet both
// answers the question and fixes the height it was answered at, so a membership
// decision is bound to the read that produced it.
type MembershipReader interface {
	CommittedBuilderSet(ctx context.Context) (chainclient.BuilderSetSnapshot, uint64, error)
}

type MembershipOptions struct {
	CacheTTL time.Duration
	// Now is injectable for tests; it defaults to wall clock UTC.
	Now func() time.Time
}

// Membership answers "does the chain currently recognise this Builder" from the
// active BuilderSet.
//
// It is the authority for that question, and configuration is not: a configured
// operator address may narrow what this node accepts but must never widen it,
// because a Builder the chain has removed has to stop being accepted no matter
// what the local file still says.
type Membership struct {
	reader MembershipReader
	cache  *cache[chainclient.BuilderSetSnapshot]
}

func NewMembership(reader MembershipReader, opts MembershipOptions) (*Membership, error) {
	if reader == nil {
		return nil, fmt.Errorf("Builder membership requires a Keeper reader")
	}
	return &Membership{
		reader: reader,
		cache:  newCache[chainclient.BuilderSetSnapshot](opts.CacheTTL, opts.Now),
	}, nil
}

// membershipCacheKey is the single key of the membership cache: there is exactly
// one current BuilderSet, and asking for it by term or by id would be asking a
// different question.
const membershipCacheKey = "current"

// Current returns the active BuilderSet, from cache when fresh.
func (m *Membership) Current(ctx context.Context) (chainclient.BuilderSetSnapshot, error) {
	if m == nil {
		return chainclient.BuilderSetSnapshot{}, fmt.Errorf("Builder membership is unavailable")
	}
	return m.cache.get(ctx, membershipCacheKey, func(ctx context.Context) (chainclient.BuilderSetSnapshot, uint64, error) {
		set, height, err := m.reader.CommittedBuilderSet(ctx)
		if err != nil {
			return chainclient.BuilderSetSnapshot{}, 0, normalizeRetryable(err)
		}
		if height == 0 {
			return chainclient.BuilderSetSnapshot{}, 0, fmt.Errorf("Keeper served no committed height for the current BuilderSet")
		}
		return set, height, nil
	})
}

// HasBuilder reports whether an operator is in the active BuilderSet. An
// unreadable chain view is returned as an error and never as "not a member": a
// Keeper outage must not be indistinguishable from an unauthorized sender.
func (m *Membership) HasBuilder(ctx context.Context, operatorAddress string) (bool, error) {
	set, err := m.Current(ctx)
	if err != nil {
		return false, err
	}
	return set.HasBuilder(operatorAddress), nil
}

// Invalidate drops the cached BuilderSet. A BuilderSet update event calls it, so
// a term change takes effect on the next frame rather than at the end of the
// cache window.
func (m *Membership) Invalidate() {
	if m == nil || m.cache == nil {
		return
	}
	m.cache.invalidate(membershipCacheKey)
}
