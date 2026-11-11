package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// dispatchFacts memoises, for the newest committed height seen, the chain
// facts that do not depend on the order: Task and Hub params, the
// BuilderSet, this node's own node, bond, service key and support scopes,
// and each Builder's service and VRF keys (I3). The session is per order and
// is not memoised, except in a held read-ahead set (Warm), which also keeps
// the sessions of recent offers. Only successful reads are kept; a read at an older
// height goes to the chain uncached. It is safe for concurrent use. Cached
// snapshots (and their slices) are shared: callers must not mutate them.
type dispatchFacts struct {
	DispatchChainView

	mu      sync.Mutex
	height  uint64
	params  *chainclient.DispatchParamsSnapshot
	liab    *chainclient.WorkerLiabilityParamsSnapshot
	set     *chainclient.BuilderSetSnapshot
	nodes   map[string]chainclient.CortexNodeSnapshot
	bonds   map[string]chainclient.ServiceBondSnapshot
	keys    map[[2]string]chainclient.ServiceKeySnapshot
	vrfs    map[string]chainclient.VrfKeySnapshot
	scopes  map[[3]string]chainclient.CommittedModelSupportScope
	epochs  map[uint64]chainclient.DispatchEpochSnapshot // by beacon height
	epochLn uint64                                       // epoch length learned at height
	// sessions is filled only in a held read-ahead set (readSession); the
	// live memo never keeps a Session.
	sessions map[[32]byte]chainclient.SessionSnapshot

	// warm is the last complete set of these facts read ahead at one
	// committed height (Warm), nil before the first. A read at its height is
	// answered from it, so an offer pinned there needs no round trip for them.
	warm atomic.Pointer[warmFacts]
}

// warmFacts is one complete read-ahead set; its memo only ever holds height.
type warmFacts struct {
	height uint64
	facts  *dispatchFacts
}

// warmAt is the held set when it is at height, else nil.
func (f *dispatchFacts) warmAt(height uint64) *dispatchFacts {
	if w := f.warm.Load(); w != nil && w.height == height {
		return w.facts
	}
	return nil
}

// WarmHeight is the height of the held set, zero before the first.
func (f *dispatchFacts) WarmHeight() uint64 {
	if w := f.warm.Load(); w != nil {
		return w.height
	}
	return 0
}

// Warm runs reads concurrently against a fresh memo pinned to height and
// holds the result once every read succeeded or found nothing (ErrNotFound
// is a fact too: the read at height simply goes to the chain again). A set
// with any other failure is dropped and the previous one stays held, so a
// stalled chain leaves the last complete height in place. It never replaces
// a newer set and reports whether it held this one.
func (f *dispatchFacts) Warm(height uint64, reads []func(*dispatchFacts) error) bool {
	if cur := f.warm.Load(); cur != nil && cur.height >= height {
		return false
	}
	g := newDispatchFacts(f.DispatchChainView)
	errs := make([]error, len(reads))
	var wg sync.WaitGroup
	for i, read := range reads {
		wg.Go(func() { errs[i] = read(g) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil && !errors.Is(err, chainclient.ErrNotFound) {
			return false
		}
	}
	next := &warmFacts{height: height, facts: g}
	for {
		cur := f.warm.Load()
		if cur != nil && cur.height >= height {
			return false
		}
		if f.warm.CompareAndSwap(cur, next) {
			return true
		}
	}
}

// SessionAt is not memoised, the Session being per order, except that a held
// read-ahead set answers for the sessions of recent offers (RunWarm).
func (f *dispatchFacts) SessionAt(ctx context.Context, sessionID []byte, height uint64) (chainclient.SessionSnapshot, error) {
	if w := f.warmAt(height); w != nil && len(sessionID) == 32 {
		w.mu.Lock()
		s, ok := w.sessions[[32]byte(sessionID)]
		w.mu.Unlock()
		if ok {
			return s, nil
		}
	}
	return f.DispatchChainView.SessionAt(ctx, sessionID, height)
}

// readSession reads a Session into a read-ahead set. A failure leaves it out:
// the offer then reads the Session itself.
func (f *dispatchFacts) readSession(ctx context.Context, sessionID [32]byte, height uint64) {
	s, err := f.DispatchChainView.SessionAt(ctx, sessionID[:], height)
	if err != nil {
		return
	}
	f.mu.Lock()
	if f.at(height) && f.height == height {
		f.sessions[sessionID] = s
	}
	f.mu.Unlock()
}

func newDispatchFacts(chain DispatchChainView) *dispatchFacts {
	return &dispatchFacts{DispatchChainView: chain}
}

// at prepares the memo for height and reports whether it may be used.
// The caller holds f.mu.
func (f *dispatchFacts) at(height uint64) bool {
	switch {
	case height < f.height:
		return false
	case height > f.height:
		f.height, f.params, f.liab, f.set, f.epochLn = height, nil, nil, nil, 0
		f.nodes, f.bonds = map[string]chainclient.CortexNodeSnapshot{}, map[string]chainclient.ServiceBondSnapshot{}
		f.keys, f.vrfs = map[[2]string]chainclient.ServiceKeySnapshot{}, map[string]chainclient.VrfKeySnapshot{}
		f.scopes, f.epochs = map[[3]string]chainclient.CommittedModelSupportScope{}, map[uint64]chainclient.DispatchEpochSnapshot{}
		f.sessions = map[[32]byte]chainclient.SessionSnapshot{}
	}
	return true
}

// memo reads through the cache: get looks the value up (the caller holds
// f.mu inside get and put), read asks the chain, put stores a success.
func memo[T any](f *dispatchFacts, height uint64, get func() (T, bool), read func() (T, error), put func(T)) (T, error) {
	f.mu.Lock()
	usable := f.at(height)
	if usable {
		if v, ok := get(); ok {
			f.mu.Unlock()
			return v, nil
		}
	}
	f.mu.Unlock()
	v, err := read()
	if err != nil || !usable {
		return v, err
	}
	f.mu.Lock()
	if f.height == height {
		put(v)
	}
	f.mu.Unlock()
	return v, nil
}

func (f *dispatchFacts) DispatchParamsAt(ctx context.Context, height uint64) (chainclient.DispatchParamsSnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.DispatchParamsAt(ctx, height)
	}
	return memo(f, height,
		func() (chainclient.DispatchParamsSnapshot, bool) {
			if f.params == nil {
				return chainclient.DispatchParamsSnapshot{}, false
			}
			return *f.params, true
		},
		func() (chainclient.DispatchParamsSnapshot, error) {
			return f.DispatchChainView.DispatchParamsAt(ctx, height)
		},
		func(v chainclient.DispatchParamsSnapshot) { f.params = &v })
}

func (f *dispatchFacts) WorkerLiabilityParamsAt(ctx context.Context, height uint64) (chainclient.WorkerLiabilityParamsSnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.WorkerLiabilityParamsAt(ctx, height)
	}
	return memo(f, height,
		func() (chainclient.WorkerLiabilityParamsSnapshot, bool) {
			if f.liab == nil {
				return chainclient.WorkerLiabilityParamsSnapshot{}, false
			}
			return *f.liab, true
		},
		func() (chainclient.WorkerLiabilityParamsSnapshot, error) {
			return f.DispatchChainView.WorkerLiabilityParamsAt(ctx, height)
		},
		func(v chainclient.WorkerLiabilityParamsSnapshot) { f.liab = &v })
}

func (f *dispatchFacts) BuilderSetAt(ctx context.Context, height uint64) (chainclient.BuilderSetSnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.BuilderSetAt(ctx, height)
	}
	return memo(f, height,
		func() (chainclient.BuilderSetSnapshot, bool) {
			if f.set == nil {
				return chainclient.BuilderSetSnapshot{}, false
			}
			return *f.set, true
		},
		func() (chainclient.BuilderSetSnapshot, error) { return f.DispatchChainView.BuilderSetAt(ctx, height) },
		func(v chainclient.BuilderSetSnapshot) { f.set = &v })
}

func (f *dispatchFacts) CortexNodeAt(ctx context.Context, operator string, height uint64) (chainclient.CortexNodeSnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.CortexNodeAt(ctx, operator, height)
	}
	return memo(f, height,
		func() (chainclient.CortexNodeSnapshot, bool) { v, ok := f.nodes[operator]; return v, ok },
		func() (chainclient.CortexNodeSnapshot, error) {
			return f.DispatchChainView.CortexNodeAt(ctx, operator, height)
		},
		func(v chainclient.CortexNodeSnapshot) { f.nodes[operator] = v })
}

func (f *dispatchFacts) ServiceBondAt(ctx context.Context, operator string, height uint64) (chainclient.ServiceBondSnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.ServiceBondAt(ctx, operator, height)
	}
	return memo(f, height,
		func() (chainclient.ServiceBondSnapshot, bool) { v, ok := f.bonds[operator]; return v, ok },
		func() (chainclient.ServiceBondSnapshot, error) {
			return f.DispatchChainView.ServiceBondAt(ctx, operator, height)
		},
		func(v chainclient.ServiceBondSnapshot) { f.bonds[operator] = v })
}

func (f *dispatchFacts) CurrentServiceKey(ctx context.Context, participant, operator string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.CurrentServiceKey(ctx, participant, operator, height)
	}
	k := [2]string{participant, operator}
	return memo(f, height,
		func() (chainclient.ServiceKeySnapshot, bool) { v, ok := f.keys[k]; return v, ok },
		func() (chainclient.ServiceKeySnapshot, error) {
			return f.DispatchChainView.CurrentServiceKey(ctx, participant, operator, height)
		},
		func(v chainclient.ServiceKeySnapshot) { f.keys[k] = v })
}

func (f *dispatchFacts) BuilderVrfKeyAt(ctx context.Context, operator string, height uint64) (chainclient.VrfKeySnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.BuilderVrfKeyAt(ctx, operator, height)
	}
	return memo(f, height,
		func() (chainclient.VrfKeySnapshot, bool) { v, ok := f.vrfs[operator]; return v, ok },
		func() (chainclient.VrfKeySnapshot, error) {
			return f.DispatchChainView.BuilderVrfKeyAt(ctx, operator, height)
		},
		func(v chainclient.VrfKeySnapshot) { f.vrfs[operator] = v })
}

func (f *dispatchFacts) ModelSupportScopeAt(ctx context.Context, operator, modelID, version string, height uint64) (chainclient.CommittedModelSupportScope, error) {
	if w := f.warmAt(height); w != nil {
		return w.ModelSupportScopeAt(ctx, operator, modelID, version, height)
	}
	k := [3]string{operator, modelID, version}
	return memo(f, height,
		func() (chainclient.CommittedModelSupportScope, bool) { v, ok := f.scopes[k]; return v, ok },
		func() (chainclient.CommittedModelSupportScope, error) {
			return f.DispatchChainView.ModelSupportScopeAt(ctx, operator, modelID, version, height)
		},
		func(v chainclient.CommittedModelSupportScope) { f.scopes[k] = v })
}

// DispatchEpochAt is memoised by the epoch start the order falls in, once the
// epoch length at height is known.
func (f *dispatchFacts) DispatchEpochAt(ctx context.Context, earliest, height uint64) (chainclient.DispatchEpochSnapshot, error) {
	if w := f.warmAt(height); w != nil {
		return w.DispatchEpochAt(ctx, earliest, height)
	}
	return memo(f, height,
		func() (chainclient.DispatchEpochSnapshot, bool) {
			if f.epochLn == 0 {
				return chainclient.DispatchEpochSnapshot{}, false
			}
			v, ok := f.epochs[earliest/f.epochLn*f.epochLn]
			return v, ok
		},
		func() (chainclient.DispatchEpochSnapshot, error) {
			return f.DispatchChainView.DispatchEpochAt(ctx, earliest, height)
		},
		func(v chainclient.DispatchEpochSnapshot) {
			f.epochLn = v.EpochLengthBlocks
			f.epochs[v.BeaconHeight] = v
		})
}
