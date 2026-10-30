package daemon

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
)

func newTestGates(t *testing.T, chain *fakeHandraiseChain, local *fakeHandraiseLocal, bids map[string]uint64) *handraiseGates {
	t.Helper()
	g, err := newHandraiseGates(hrCortex, chain, local, hrProfileRefs(), bids, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestHandraiseGates(t *testing.T) {
	ctx := context.Background()
	ab1, ab2, cd1 := hrProfile(hrModelAB, 1), hrProfile(hrModelAB, 2), hrProfile(hrModelCD, 1)
	open := func() (*fakeHandraiseChain, *fakeHandraiseLocal) {
		return newFakeHandraiseChain(t), &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}
	}
	offered := func(t *testing.T, r gateResult, want ...HandraiseProfile) {
		t.Helper()
		if r.state == nil || !slices.Equal(r.state.Profiles, want) {
			t.Fatalf("offer %+v (%s), want profiles %v", r.state, r.why, want)
		}
	}
	stopped := func(t *testing.T, r gateResult, factual bool) {
		t.Helper()
		if r.state != nil || r.factual != factual {
			t.Fatalf("result %+v, want stopped with factual=%v", r, factual)
		}
	}

	t.Run("all gates open", func(t *testing.T) {
		chain, local := open()
		r := newTestGates(t, chain, local, hrBids()).evaluate(ctx, true)
		offered(t, r, ab1, ab2, cd1)
		if r.state.FreeSlots != 3 || r.state.AuthNonce != 7 || r.state.Member.Slot != 4 || r.state.Member.SlotVersion != 2 || r.state.Member.Operator != hrCortex {
			t.Fatalf("state %+v", r.state)
		}
	})
	t.Run("H1 workload not ready is not a fact", func(t *testing.T) {
		chain, local := open()
		local.ready = false
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), false)
	})
	t.Run("H1 failed chain read is not a fact", func(t *testing.T) {
		chain, local := open()
		chain.nodeErr = errors.New("rpc down")
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), false)
	})
	t.Run("H1 unbonding bond is a fact", func(t *testing.T) {
		chain, local := open()
		chain.bond.Status = "UNBONDING"
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), true)
	})
	t.Run("H1 Builder VRF key unreadable", func(t *testing.T) {
		chain, local := open()
		chain.vrfErr[hrBuilderB] = errors.New("not registered")
		g := newTestGates(t, chain, local, hrBids())
		if err := g.builder(ctx, hrBuilderA); err != nil {
			t.Fatal(err)
		}
		if err := g.builder(ctx, hrBuilderB); err == nil {
			t.Fatal("a Builder whose VRF key cannot be read gets no handraise")
		}
	})
	t.Run("H2 stale support drops that profile", func(t *testing.T) {
		chain, local := open()
		s := chain.scopes[config.MinPriceBidKey(hrModelCD, 1)]
		s.Support.SupportFreshUntilEpoch = 10 // height 1000 / 100 = epoch 10
		chain.scopes[config.MinPriceBidKey(hrModelCD, 1)] = s
		offered(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), ab1, ab2)
	})
	t.Run("H2 bond below min_stake drops that profile", func(t *testing.T) {
		chain, local := open()
		s := chain.scopes[config.MinPriceBidKey(hrModelAB, 2)]
		s.Profile.Profile.MinStake = 5_000
		chain.scopes[config.MinPriceBidKey(hrModelAB, 2)] = s
		offered(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), ab1, cd1)
	})
	t.Run("H4 missing min_price_bid drops that profile", func(t *testing.T) {
		chain, local := open()
		bids := hrBids()
		delete(bids, config.MinPriceBidKey(hrModelAB, 1))
		offered(t, newTestGates(t, chain, local, bids).evaluate(ctx, true), ab2, cd1)
	})
	t.Run("H3 runtime not ready offers zero slots", func(t *testing.T) {
		chain, local := open()
		local.freeOK, local.free = false, 9
		r := newTestGates(t, chain, local, hrBids()).evaluate(ctx, true)
		offered(t, r, ab1, ab2, cd1)
		if r.state.FreeSlots != 0 {
			t.Fatalf("free = %d, want 0", r.state.FreeSlots)
		}
	})
	t.Run("pending service key rotation stops, as a fact, with the nonce", func(t *testing.T) {
		chain, local := open()
		chain.cortexKey.HasPendingRotation = true
		r := newTestGates(t, chain, local, hrBids()).evaluate(ctx, true)
		stopped(t, r, true)
		if r.authNonce != 7 {
			t.Fatalf("authNonce = %d", r.authNonce)
		}
	})
	t.Run("node drain stops, as a fact", func(t *testing.T) {
		chain, local := open()
		local.drain = true
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), true)
	})
	t.Run("profile drain drops only that profile", func(t *testing.T) {
		chain, local := open()
		local.drainProfiles = map[HandraiseProfile]bool{cd1: true}
		offered(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), ab1, ab2)
	})
	t.Run("no servable profile is a fact", func(t *testing.T) {
		chain, local := open()
		stopped(t, newTestGates(t, chain, local, map[string]uint64{}).evaluate(ctx, true), true)
	})
	t.Run("profiles lost to failed reads are not a fact", func(t *testing.T) {
		chain, local := open()
		chain.scopeErr = errors.New("rpc down")
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), false)
	})
	t.Run("a support scope Keeper does not have is a fact", func(t *testing.T) {
		chain, local := open()
		chain.scopes = map[string]chainclient.CommittedModelSupportScope{}
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, true), true)
	})
	t.Run("unknown block interval is not a fact", func(t *testing.T) {
		chain, local := open()
		stopped(t, newTestGates(t, chain, local, hrBids()).evaluate(ctx, false), false)
	})
}
