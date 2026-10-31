package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

func TestStandingHandraiseWithdrawsOnceFromARetiringBuilder(t *testing.T) {
	x := newHRHarness(t, nil)
	x.warm()
	x.tweak = func(c *StandingHandraiseConfig) { c.Retiring = map[string]bool{hrBuilderB: true} }
	x.open()
	x.step(100*time.Millisecond, 102)
	hs := x.b.handraises()
	if len(hs) != 2 || hs[1].GetFreeSlotCount() != 0 || len(hs[1].GetProfiles()) != 0 {
		t.Fatalf("retiring Builder got %v, want one withdrawal", hs)
	}
	if cur, ok := x.h.Current(hrBuilderB); !ok || !cur.Withdrawn {
		t.Fatal("the withdrawal is the current handraise")
	}
	x.step(10*time.Second, 106)
	if len(x.b.handraises()) != 2 {
		t.Fatal("one withdrawal, then silence (S3 Q3)")
	}
	if a := x.a.handraises(); a[len(a)-1].GetFreeSlotCount() == 0 {
		t.Fatal("the other Builder keeps its offer")
	}
}

func TestDispatcherRefusesOffersFromARetiringBuilder(t *testing.T) {
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) { c.Retiring = map[string]bool{hrBuilderA: true} })
	if err := x.handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	if rec.State != layout.DispatchRejected || rec.RejectClass != classBuilderRetiring || rec.RejectReason != int32(reasonNoCapacity) {
		t.Fatalf("record = %s %s %d, want a signed NO_CAPACITY reject", rec.State, rec.RejectClass, rec.RejectReason)
	}
	if len(x.infer.starts()) != 0 {
		t.Fatal("nothing starts for a retiring Builder")
	}
}

// S6: the claim names as submitter exactly the address that broadcasts it,
// and an inactive workload (no submitter) waits instead of warning.
func TestDispatcherClaimsThroughTheSubmitterPair(t *testing.T) {
	tx := txclienttest.NewFake()
	var addr string
	x := newDispatchHarness(t, 2, func(c *DispatcherConfig) {
		c.Submitter = func() (txclient.Client, string) {
			if addr == "" {
				return nil, ""
			}
			return tx, addr
		}
		c.ReceiptRescueMarginBlocks = 2
	})
	_ = x.committed(t)
	rec := x.record(t)
	x.chain.with(func(f *fakeDispatchChain) {
		f.height = rec.ClaimFromHeight
		f.params.CompensationClaimWindowBlocks = 20
	})
	ctx := context.Background()
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.d.SweepClaims(ctx); err != nil {
		t.Fatal(err)
	}
	if len(tx.Requests()) != 0 {
		t.Fatal("no submitter: nothing is broadcast yet")
	}
	addr = "trueopen1n76x6eelp8s6nx737vnmp29rdme7peaypql50k"
	if err := x.d.SweepClaims(ctx); err != nil {
		t.Fatal(err)
	}
	reqs := tx.Requests()
	if len(reqs) != 1 || reqs[0].Kind != txclient.MsgClaimDispatchCompensation {
		t.Fatalf("requests = %v", reqs)
	}
	if !bytes.Contains(reqs[0].Payload, []byte(addr)) {
		t.Fatalf("submitter_address must be %s: %s", addr, reqs[0].Payload)
	}
}

func TestOmissionWatcherAcceptsASubmitterAndRuns(t *testing.T) {
	cfg := OmissionConfig{ChainID: dpChainID, Operator: hrCortex, Builders: []string{hrBuilderA},
		Chain: nil, Roots: nil, Rosters: nil, Store: nil}
	if _, err := NewOmissionWatcher(cfg); err == nil {
		t.Fatal("an incomplete config is still refused")
	}
}

type rosterResolver struct{ err error }

func (r rosterResolver) ResolveBuilderEndpoint(context.Context, string) (BuilderEndpoint, error) {
	return BuilderEndpoint{}, r.err
}

type failingRosterClient struct{}

func (failingRosterClient) GetDispatchRoster(context.Context, string, *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error) {
	return nil, errors.New("not reached")
}

// A descriptor this node cannot read is its own failure; a Builder without a
// valid descriptor is the Builder's roster miss.
func TestRosterSourceSeparatesLocalFailuresFromBuilderMisses(t *testing.T) {
	ctx := context.Background()
	local := rosterSource{endpoints: rosterResolver{err: builderclient.Retryable(errors.New("rpc down"))}, client: failingRosterClient{}}
	if _, err := local.GetDispatchRoster(ctx, hrBuilderA, nil); !errors.Is(err, ErrRosterSourceLocal) {
		t.Fatalf("unreadable chain = %v, want a local failure", err)
	}
	missing := rosterSource{endpoints: rosterResolver{err: fmt.Errorf("%w: %s", builderdirectory.ErrNoCurrentDescriptor, hrBuilderA)}, client: failingRosterClient{}}
	if _, err := missing.GetDispatchRoster(ctx, hrBuilderA, nil); err == nil || errors.Is(err, ErrRosterSourceLocal) {
		t.Fatalf("no descriptor = %v, want a Builder miss", err)
	}
}

type localFailRosters struct{}

func (localFailRosters) GetDispatchRoster(context.Context, string, *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error) {
	return nil, fmt.Errorf("%w: chain unreadable", ErrRosterSourceLocal)
}

func TestOmissionNeverCountsALocalRosterFailureAsAMiss(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.w.cfg.Rosters = localFailRosters{}
	x.observe()
	for _, h := range []uint64{201, 206} {
		x.chain.mu.Lock()
		x.chain.height = h
		x.chain.mu.Unlock()
		if err := x.w.Sweep(context.Background()); !errors.Is(err, ErrRosterSourceLocal) {
			t.Fatalf("sweep at %d = %v, want the local failure", h, err)
		}
	}
	if len(x.tx.requests()) != 0 || x.state().RosterMissSince != 0 {
		t.Fatalf("a local failure was taken for a roster miss: %+v", x.state())
	}
}
