package daemon

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
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
