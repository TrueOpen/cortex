package daemon

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// fakeAnchorProbe answers AnchorCommitCapable with err and counts the calls.
type fakeAnchorProbe struct {
	err   error
	calls atomic.Int32
}

func (p *fakeAnchorProbe) AnchorCommitCapable(context.Context) error {
	p.calls.Add(1)
	return p.err
}

// requireAnchor makes a support scope's locked Profile require kind 5.
func requireAnchor(scope chainclient.CommittedModelSupportScope) chainclient.CommittedModelSupportScope {
	schema := &scope.Profile.Profile.VerificationProfile.EvidenceSchema
	schema.RequiredInferEvidence = append(slices.Clone(schema.RequiredInferEvidence), chainclient.CurrentInferEvidenceRequirementSnapshot{
		EvidenceKind:            int32(nodewire.EvidenceKindWorkerAnchorOpening),
		CommitmentSchemaVersion: nodewire.WorkerAnchorCommitmentSchemaVersionV1,
		MaxEncodedSizeBytes:     chainclient.Uint64String(1 << 20),
	})
	return scope
}

func TestAnchorProberOf(t *testing.T) {
	local := modelservice.NewLocalService("http://127.0.0.1:1", "local", 1, 0, 0)
	if AnchorProberOf(local) == nil {
		t.Fatal("the local vLLM service must expose its anchor probe")
	}
	if AnchorProberOf(modelservice.NewFakeService()) != nil {
		t.Fatal("the fake model service cannot serve anchors")
	}
}

// The standing handraise leaves a Profile that requires WORKER_ANCHOR_OPENING
// out unless the local engine serves anchor commitments; every other Profile
// is offered as before and never probes.
func TestHandraiseGatesCheckAnchorCapability(t *testing.T) {
	ctx := context.Background()
	ab1, ab2, cd1 := hrProfile(hrModelAB, 1), hrProfile(hrModelAB, 2), hrProfile(hrModelCD, 1)
	for _, c := range []struct {
		name  string
		probe *fakeAnchorProbe // nil: the model service has no probe
		want  []HandraiseProfile
	}{
		{"no probe leaves the anchor profile out", nil, []HandraiseProfile{ab1, ab2}},
		{"engine without the sidecar leaves it out", &fakeAnchorProbe{err: modelservice.ErrAnchorCommitUnsupported}, []HandraiseProfile{ab1, ab2}},
		{"capable engine offers it", &fakeAnchorProbe{}, []HandraiseProfile{ab1, ab2, cd1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			chain := newFakeHandraiseChain(t)
			key := config.MinPriceBidKey(hrModelCD, 1)
			chain.scopes[key] = requireAnchor(chain.scopes[key])
			g := newTestGates(t, chain, &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}, hrBids())
			if c.probe != nil {
				g.anchor = c.probe
			}
			r := g.evaluate(ctx, 100, true)
			if r.state == nil || !slices.Equal(r.state.Profiles, c.want) {
				t.Fatalf("offer %+v (%s), want %v", r.state, r.why, c.want)
			}
			if c.probe != nil && c.probe.calls.Load() != 1 {
				t.Fatalf("probed %d times, want once (only the kind 5 Profile)", c.probe.calls.Load())
			}
			for _, v := range r.profiles {
				if v.HandraiseProfile == cd1 && len(c.want) == 2 && v.class != profileExcluded {
					t.Fatalf("anchor profile class %d, want excluded (a local fact, not a failed read)", v.class)
				}
			}
		})
	}
	t.Run("no anchor profile never probes", func(t *testing.T) {
		probe := &fakeAnchorProbe{err: errors.New("must not be asked")}
		g := newTestGates(t, newFakeHandraiseChain(t), &fakeHandraiseLocal{ready: true, free: 3, freeOK: true}, hrBids())
		g.anchor = probe
		r := g.evaluate(ctx, 100, true)
		if r.state == nil || !slices.Equal(r.state.Profiles, []HandraiseProfile{ab1, ab2, cd1}) || probe.calls.Load() != 0 {
			t.Fatalf("offer %+v after %d probes", r.state, probe.calls.Load())
		}
	})
}

// An offer for a Profile requiring WORKER_ANCHOR_OPENING is refused
// PROFILE_UNAVAILABLE when this node's engine cannot serve anchors, instead of
// being accepted and failing after the GPU work.
func TestDispatchOfferChecksAnchorCapability(t *testing.T) {
	for _, c := range []struct {
		name   string
		probe  *fakeAnchorProbe
		accept bool
	}{
		{"no probe", nil, false},
		{"engine without the sidecar", &fakeAnchorProbe{err: modelservice.ErrAnchorCommitUnsupported}, false},
		{"capable engine", &fakeAnchorProbe{}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			x := newDispatchHarness(t, 2, nil)
			x.chain.with(func(f *fakeDispatchChain) {
				key := config.MinPriceBidKey(hrModelAB, 1)
				f.scopes[key] = requireAnchor(f.scopes[key])
			})
			if c.probe != nil {
				x.reconfigure(func(cfg *DispatcherConfig) { cfg.Anchor = c.probe })
			}
			if err := x.handle(ctx); err != nil {
				t.Fatal(err)
			}
			msgs := x.a.messages()
			if len(msgs) == 0 {
				t.Fatal("no answer to the offer")
			}
			if c.accept {
				if _, ok := msgs[0].(*taskv1.DispatchAcceptV1); !ok {
					t.Fatalf("answered %T, want an accept", msgs[0])
				}
				return
			}
			rj, ok := msgs[0].(*taskv1.DispatchRejectV1)
			if !ok || rj.GetRejectReason() != taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_PROFILE_UNAVAILABLE {
				t.Fatalf("answered %v, want a PROFILE_UNAVAILABLE reject", msgs[0])
			}
			if rec := x.record(t); rec.RejectClass != classProfileUnavailable {
				t.Fatalf("reject class %q", rec.RejectClass)
			}
		})
	}
}
