package chainclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

// keeperIdleConnsPerHost is how many idle connections the ABCI client keeps to
// the node. Task handling issues Keeper reads from several goroutines at once;
// with http.Transport's default of two, the rest open a fresh TLS connection,
// which costs a full handshake to a remote node on every such read.
const keeperIdleConnsPerHost = 32

// EnableConnectionPool keeps keeperIdleConnsPerHost idle connections to the
// node instead of http.Transport's default of two.
func (c *KeeperABCIClient) EnableConnectionPool() *KeeperABCIClient {
	c.http.Transport = pooledTransport(c.http.Transport, keeperIdleConnsPerHost)
	return c
}

// heightGuardFactor bounds how long, in multiples of the read-cache max age, a
// lower committed height is refused after a higher one was read.
const heightGuardFactor = 4

// EnableParallelReads lets a read that needs several independent queries at one
// committed height issue them together instead of one after another. Errors
// are still reported in the order the queries are listed.
func (c *KeeperABCIClient) EnableParallelReads() *KeeperABCIClient {
	c.parallelReads = true
	return c
}

// runReads runs reads one after another, stopping at the first failure, or all
// together when parallel reads are enabled. Either way the caller checks the
// returned errors in order and reports the first one, so both modes fail the
// same way.
func (c *KeeperABCIClient) runReads(reads ...func() error) []error {
	errs := make([]error, len(reads))
	if !c.parallelReads {
		for i, read := range reads {
			if errs[i] = read(); errs[i] != nil {
				break
			}
		}
		return errs
	}
	var wg sync.WaitGroup
	for i, read := range reads {
		wg.Go(func() { errs[i] = read() })
	}
	wg.Wait()
	return errs
}

func firstError(errs []error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// serviceKeyMemoHeights is how many committed heights of service-key reads the
// memo keeps. Reads are pinned to the newest committed height, so older entries
// stop being asked for within a block or two.
const serviceKeyMemoHeights = 4

// EnableReadCache lets the client reuse two kinds of read:
//
//   - CommittedHeight answers from the last /abci_info result for up to maxAge.
//     The answer is still a height the application has committed and can serve;
//     it is at most maxAge older than a fresh read, the same order as the
//     network delay every read already carries.
//   - A service-key read pinned to a committed height is kept for that height.
//     State at a committed height never changes, so a repeat read cannot differ,
//     and a rotation or revocation is seen as soon as the height moves on.
//
// Only successful reads are kept. A client without EnableReadCache reads the
// node every time.
func (c *KeeperABCIClient) EnableReadCache(maxAge time.Duration) *KeeperABCIClient {
	c.readCache.mu.Lock()
	c.readCache.heightMaxAge = maxAge
	c.readCache.enabled = maxAge > 0
	c.readCache.mu.Unlock()
	return c
}

type keeperReadCache struct {
	mu           sync.Mutex
	enabled      bool
	heightMaxAge time.Duration
	height       uint64
	heightReadAt time.Time
	heightCall   *committedHeightCall

	serviceKeys     map[serviceKeyMemoKey]serviceKeyMemoEntry
	serviceKeyCalls map[serviceKeyMemoKey]*serviceKeyCall

	// pinned and pinnedCalls are the memo for the other reads pinned to a
	// committed height; see memoPinned.
	pinned      map[pinnedReadKey]any
	pinnedCalls map[pinnedReadKey]*pinnedReadCall
	// memoEpoch counts memo clears after a committed-height regression; see
	// clearHeightMemosLocked.
	memoEpoch uint64
}

type serviceKeyCall struct {
	done  chan struct{}
	entry serviceKeyMemoEntry
	err   error
}

type committedHeightCall struct {
	done   chan struct{}
	height uint64
	err    error
}

type serviceKeyMemoKey struct {
	participant sharedv1.ParticipantType
	operator    string
	height      uint64
}

type serviceKeyMemoEntry struct {
	binding ServiceKeySnapshot
	served  uint64
}

type minCommittedHeightKey struct{}

// WithMinCommittedHeight marks reads made under ctx as needing committed state
// at least as new as height. A caller that is checking an event from block h
// against Keeper state sets it to h: a cached height below h would show state
// from before the event and make a valid event look inconsistent. Reads below
// the minimum bypass the cache and ask the node; a node still below the
// minimum is a retryable error, never a stale answer.
func WithMinCommittedHeight(ctx context.Context, height uint64) context.Context {
	if height == 0 {
		return ctx
	}
	return context.WithValue(ctx, minCommittedHeightKey{}, height)
}

func minCommittedHeight(ctx context.Context) uint64 {
	height, _ := ctx.Value(minCommittedHeightKey{}).(uint64)
	return height
}

// committedHeight returns a cached committed height, or reads /abci_info once
// on behalf of every caller that arrives while the read is in flight.
func (c *KeeperABCIClient) committedHeight(ctx context.Context) (uint64, error) {
	cache := &c.readCache
	cache.mu.Lock()
	if !cache.enabled {
		cache.mu.Unlock()
		return c.readCommittedHeight(ctx)
	}
	if minimum := minCommittedHeight(ctx); minimum != 0 && cache.height < minimum {
		// The cached view predates what the caller needs. Read the node
		// directly rather than join a shared read that may have started
		// before the minimum was reached.
		cache.mu.Unlock()
		height, err := c.readCommittedHeight(ctx)
		if err != nil {
			return 0, err
		}
		if height < minimum {
			// The node itself is behind the event (its application has not
			// committed the block yet, or a lagging replica answered). State at
			// this height would be just as stale, so fail retryably and let
			// the caller come back rather than hand it the old view.
			return 0, Retryable(fmt.Errorf("committed height %d is below required height %d", height, minimum))
		}
		cache.mu.Lock()
		if height > cache.height {
			cache.height = height
			cache.heightReadAt = time.Now()
		}
		cache.mu.Unlock()
		return height, nil
	}
	if cache.height != 0 && time.Since(cache.heightReadAt) < cache.heightMaxAge {
		height := cache.height
		cache.mu.Unlock()
		return height, nil
	}
	if call := cache.heightCall; call != nil {
		cache.mu.Unlock()
		select {
		case <-call.done:
			if call.err == nil {
				return call.height, nil
			}
			// The shared read failed, possibly on the other caller's context;
			// this caller reads for itself.
			return c.readCommittedHeight(ctx)
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	call := &committedHeightCall{done: make(chan struct{})}
	cache.heightCall = call
	cache.mu.Unlock()

	startedAt := time.Now()
	height, err := c.readCommittedHeight(ctx)

	cache.mu.Lock()
	if err == nil {
		// Committed heights only grow, so a lower answer comes from a
		// replica that is behind; keep handing out the higher height. The
		// refusal is bounded by heightGuardFactor x heightMaxAge from when
		// the higher height was read: a node repointed at another chain, or
		// a devnet reset, restarts heights low for good, and an unbounded
		// guard would pin every pinned read to a height that no longer
		// exists.
		if height < cache.height && time.Since(cache.heightReadAt) < heightGuardFactor*cache.heightMaxAge {
			height = cache.height
		} else {
			if height < cache.height {
				// The committed height went backwards for good: a reset
				// chain or a node repointed at another one. Reads memoized
				// at the old heights describe that other history, and the
				// new chain will pass through the same heights, so they
				// must not survive.
				cache.clearHeightMemosLocked()
			}
			cache.height = height
			// Age is counted from before the read, so a cached value is
			// never more than heightMaxAge old.
			cache.heightReadAt = startedAt
		}
	}
	cache.heightCall = nil
	cache.mu.Unlock()

	call.height, call.err = height, err
	close(call.done)
	return height, err
}

// memoServiceKey answers a service-key read pinned to a committed height from
// the memo, or makes the read once on behalf of every caller that asks for the
// same key at the same height while it is in flight. As with committedHeight, a
// waiter whose shared read failed reads for itself, a waiter honours its own
// context, and failures are not kept.
func (c *KeeperABCIClient) memoServiceKey(ctx context.Context, key serviceKeyMemoKey, read func(context.Context) (serviceKeyMemoEntry, error)) (serviceKeyMemoEntry, error) {
	cache := &c.readCache
	cache.mu.Lock()
	// A read that started before a chain reset must not store its answer
	// after the memos were cleared.
	epoch := cache.memoEpoch
	if key.height == 0 || !cache.enabled {
		cache.mu.Unlock()
		return read(ctx)
	}
	if entry, ok := cache.serviceKeys[key]; ok {
		cache.mu.Unlock()
		return entry, nil
	}
	if call := cache.serviceKeyCalls[key]; call != nil {
		cache.mu.Unlock()
		select {
		case <-call.done:
			if call.err == nil {
				return call.entry, nil
			}
			entry, err := read(ctx)
			if err == nil {
				c.storeServiceKey(key, entry, epoch)
			}
			return entry, err
		case <-ctx.Done():
			return serviceKeyMemoEntry{}, ctx.Err()
		}
	}
	call := &serviceKeyCall{done: make(chan struct{})}
	if cache.serviceKeyCalls == nil {
		cache.serviceKeyCalls = make(map[serviceKeyMemoKey]*serviceKeyCall)
	}
	cache.serviceKeyCalls[key] = call
	cache.mu.Unlock()

	entry, err := read(ctx)
	if err == nil {
		c.storeServiceKey(key, entry, epoch)
	}
	cache.mu.Lock()
	if cache.serviceKeyCalls[key] == call {
		delete(cache.serviceKeyCalls, key)
	}
	cache.mu.Unlock()
	call.entry, call.err = entry, err
	close(call.done)
	return entry, err
}

func (c *KeeperABCIClient) storeServiceKey(key serviceKeyMemoKey, entry serviceKeyMemoEntry, epoch uint64) {
	if key.height == 0 {
		return
	}
	cache := &c.readCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.enabled || cache.memoEpoch != epoch {
		return
	}
	if cache.serviceKeys == nil {
		cache.serviceKeys = make(map[serviceKeyMemoKey]serviceKeyMemoEntry)
	}
	cache.serviceKeys[key] = entry
	var newest uint64
	for k := range cache.serviceKeys {
		if k.height > newest {
			newest = k.height
		}
	}
	for k := range cache.serviceKeys {
		if k.height+serviceKeyMemoHeights <= newest {
			delete(cache.serviceKeys, k)
		}
	}
}

// pinnedReadKey names one read pinned to a committed height: what was read,
// for which arguments, at which height.
type pinnedReadKey struct {
	kind   string
	args   string
	height uint64
}

type pinnedReadCall struct {
	done  chan struct{}
	value any
	err   error
}

// memoPinned answers a read pinned to a committed height from the memo, or
// makes the read once on behalf of every caller that asks for the same read at
// the same height while it is in flight. It is the service-key memo for any
// pinned read: state at a committed height never changes, so a repeat read at
// that height cannot differ, and a change is seen as soon as the committed
// height moves on -- nothing is reused across heights. A waiter whose shared
// read failed reads for itself, a waiter honours its own context, and failures
// are not kept. Without EnableReadCache, or at height zero, it always reads.
func memoPinned[T any](ctx context.Context, c *KeeperABCIClient, key pinnedReadKey, read func(context.Context) (T, error)) (T, error) {
	cache := &c.readCache
	cache.mu.Lock()
	// A read that started before a chain reset must not store its answer
	// after the memos were cleared.
	epoch := cache.memoEpoch
	if key.height == 0 || !cache.enabled {
		cache.mu.Unlock()
		return read(ctx)
	}
	if value, ok := cache.pinned[key]; ok {
		cache.mu.Unlock()
		return value.(T), nil
	}
	if call := cache.pinnedCalls[key]; call != nil {
		cache.mu.Unlock()
		select {
		case <-call.done:
			if call.err == nil {
				return call.value.(T), nil
			}
			value, err := read(ctx)
			if err == nil {
				c.storePinned(key, value, epoch)
			}
			return value, err
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}
	call := &pinnedReadCall{done: make(chan struct{})}
	if cache.pinnedCalls == nil {
		cache.pinnedCalls = make(map[pinnedReadKey]*pinnedReadCall)
	}
	cache.pinnedCalls[key] = call
	cache.mu.Unlock()

	value, err := read(ctx)
	if err == nil {
		c.storePinned(key, value, epoch)
	}
	cache.mu.Lock()
	if cache.pinnedCalls[key] == call {
		delete(cache.pinnedCalls, key)
	}
	cache.mu.Unlock()
	call.value, call.err = value, err
	close(call.done)
	return value, err
}

// storePinned keeps one successful pinned read and drops entries more than
// serviceKeyMemoHeights below the newest height kept.
func (c *KeeperABCIClient) storePinned(key pinnedReadKey, value any, epoch uint64) {
	cache := &c.readCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.enabled || cache.memoEpoch != epoch {
		return
	}
	if cache.pinned == nil {
		cache.pinned = make(map[pinnedReadKey]any)
	}
	cache.pinned[key] = value
	var newest uint64
	for k := range cache.pinned {
		if k.height > newest {
			newest = k.height
		}
	}
	for k := range cache.pinned {
		if k.height+serviceKeyMemoHeights <= newest {
			delete(cache.pinned, k)
		}
	}
}

// clearHeightMemosLocked drops every read memoized by committed height, and
// the reads in flight from later joiners, and moves memoEpoch on so a read
// still in flight from before does not store its answer afterwards. The
// caller holds mu.
func (cache *keeperReadCache) clearHeightMemosLocked() {
	cache.serviceKeys, cache.serviceKeyCalls = nil, nil
	cache.pinned, cache.pinnedCalls = nil, nil
	cache.memoEpoch++
}
