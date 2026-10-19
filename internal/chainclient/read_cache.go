package chainclient

import (
	"context"
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

	serviceKeys map[serviceKeyMemoKey]serviceKeyMemoEntry
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

// committedHeight returns a cached committed height, or reads /abci_info once
// on behalf of every caller that arrives while the read is in flight.
func (c *KeeperABCIClient) committedHeight(ctx context.Context) (uint64, error) {
	cache := &c.readCache
	cache.mu.Lock()
	if !cache.enabled {
		cache.mu.Unlock()
		return c.readCommittedHeight(ctx)
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

func (c *KeeperABCIClient) lookupServiceKey(key serviceKeyMemoKey) (serviceKeyMemoEntry, bool) {
	if key.height == 0 {
		return serviceKeyMemoEntry{}, false
	}
	cache := &c.readCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.enabled {
		return serviceKeyMemoEntry{}, false
	}
	entry, ok := cache.serviceKeys[key]
	return entry, ok
}

func (c *KeeperABCIClient) storeServiceKey(key serviceKeyMemoKey, entry serviceKeyMemoEntry) {
	if key.height == 0 {
		return
	}
	cache := &c.readCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if !cache.enabled {
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
