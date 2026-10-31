package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

func TestDispatchRouterIsRetryableUntilBound(t *testing.T) {
	r := &dispatchRouter{keys: map[string]*builderKeyCache{}}
	for name, f := range map[string]*nexusv1.DispatchStreamFrameV1{
		"root":   {Message: &nexusv1.DispatchStreamFrameV1_HandraiseRoot{HandraiseRoot: &nexusv1.HandraiseRootNoticeV1{}}},
		"offer":  {Message: &nexusv1.DispatchStreamFrameV1_Offer{Offer: &nexusv1.DispatchOfferV1{}}},
		"verify": {Message: &nexusv1.DispatchStreamFrameV1_OpenVerify{OpenVerify: &nexusv1.OpenVerifyV1{}}},
	} {
		if err := r.HandleFrame(context.Background(), hrBuilderA, f); !builderclient.IsRetryable(err) {
			t.Fatalf("%s before binding = %v, want retryable (left unacked)", name, err)
		}
	}
	if err := r.HandleFrame(context.Background(), hrBuilderA, &nexusv1.DispatchStreamFrameV1{}); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("a frame with no handler = %v, want permanent", err)
	}
	r.onBound(hrBuilderA) // unbound owners: no panic
}

func TestDispatchLinkIsRetryableUntilBound(t *testing.T) {
	l := NewDispatchLink()
	err := l.ObserveDispatchRecorded(context.Background(), DispatchRecordedFact{})
	if !chainclient.IsRetryable(err) {
		t.Fatalf("unbound record = %v, want the poller to retry the page", err)
	}
	if err := l.ReleaseTaskLease(context.Background(), [32]byte{}); !builderclient.IsRetryable(err) {
		t.Fatalf("unbound release = %v", err)
	}
}
func TestCheckRootRetentionCoversTheChallengeWindow(t *testing.T) {
	p := chainclient.DispatchParamsSnapshot{RecordDeadlineBlocks: 50, ChallengeWindowBlocks: 1_000, ChallengeResponseBlocks: 100, EvidenceRetentionBlocks: 900}
	if err := checkRootRetention(1_149, p); err == nil || !strings.Contains(err.Error(), "below 1150") {
		t.Fatalf("short retention = %v (S8 Q9)", err)
	}
	if err := checkRootRetention(1_150, p); err != nil {
		t.Fatal(err)
	}
	p.EvidenceRetentionBlocks = 5_000
	if err := checkRootRetention(1_150, p); err == nil {
		t.Fatal("never below the chain's own dispatch evidence retention")
	}
}

func TestDispatchScansFollowTheLedger(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	if busy, err := layout.BuilderHoldsDuty(ctx, x.st, hrBuilderA); err != nil || !busy {
		t.Fatalf("A holds the accepted ticket: %v %v", busy, err)
	}
	if busy, _ := layout.BuilderHoldsDuty(ctx, x.st, hrBuilderB); busy {
		t.Fatal("B holds nothing")
	}
	owner, ok, err := layout.DispatchScopeOwner(ctx, x.st, layout.DispatchEvidenceScope(rec.TaskHash, rec.TicketHash))
	if err != nil || !ok || owner.TaskHash != rec.TaskHash {
		t.Fatalf("scope owner = %v %v %v", owner.TaskHash, ok, err)
	}
	if _, ok, _ := layout.DispatchScopeOwner(ctx, x.st, rec.TaskHash); ok {
		t.Fatal("a task hash is not a scope")
	}
	counts, err := layout.DispatchAnswerCounts(ctx, x.st)
	if err != nil || counts[layout.DispatchAnswer{Builder: hrBuilderA, Answer: "accept"}] != 1 || len(counts) != 1 {
		t.Fatalf("answers = %v, %v", counts, err)
	}
}

func TestDispatchStreamsStatusesNeverGateTheWorkload(t *testing.T) {
	st := vsStore(t)
	s, err := NewDispatchStreams(DispatchStreamsConfig{
		ChainID: dpChainID, Operator: hrCortex, Builders: []string{hrBuilderA}, Retiring: []string{hrBuilderB},
		Stream:    config.DispatchStreamConfig{KeepaliveMS: 15_000, MaxMissed: 3},
		Endpoints: &dialResolver{}, HTTP: builderclient.NewDispatchStreamHTTPClient(),
		Keys: newFakeHandraiseChain(t), Sign: hrSigner(hrCortexKey), Height: func() uint64 { return 0 }, Store: st,
	})
	if err != nil {
		t.Fatal(err)
	}
	rows := s.Statuses()
	if len(rows) != 3 || rows[0].Name != StreamDependencyName(hrBuilderA) || !rows[0].Optional || rows[0].Ready ||
		rows[2].Name != DependencyDispatchStreams || rows[2].Ready {
		t.Fatalf("rows = %+v", rows)
	}
	w := WorkloadReadiness{DependenciesReady: true, Identity: readyStatus(), ModelSupport: readyStatus(), ChainSync: readyStatus(), ServiceAddress: "svc", Streams: rows}
	if !w.Ready() {
		t.Fatal("an unbound stream never holds the workload down (Q4: streams run inside it)")
	}
	if got := w.DependencyStatuses(); got[len(got)-1].Name != DependencyDispatchStreams {
		t.Fatal("stream rows are reported with the rest")
	}
	if len(s.Fanout().builders) != 1 || s.Fanout().builders[0] != hrBuilderA {
		t.Fatal("Verifier messages go to active Builders only")
	}
}

func readyStatus() diagnostics.DependencyStatus { return diagnostics.DependencyStatus{Ready: true} }

func TestWorkloadSubmitterPairsTheTxWithItsAddress(t *testing.T) {
	built := map[string]bool{}
	rt := &Runtime{workloadTxFactory: func(addr string) txclient.Client { built[addr] = true; return txclienttest.NewFake() }}
	if tx, addr := rt.WorkloadSubmitter(); tx != nil || addr != "" {
		t.Fatal("inactive: no submitter")
	}
	if err := rt.ActivateWorkload("trueopen1svc", "02ab"); err != nil {
		t.Fatal(err)
	}
	if tx, addr := rt.WorkloadSubmitter(); tx == nil || addr != "trueopen1svc" || !built[addr] {
		t.Fatalf("submitter = %v %q, want the Tx built for that address", tx, addr)
	}
	rt.DeactivateWorkload()
	if tx, _ := rt.WorkloadSubmitter(); tx != nil {
		t.Fatal("deactivated: no submitter")
	}
	if rt.LastWorkloadReady() {
		t.Fatal("never checked: not ready")
	}
	if _, err := rt.DispatchSigner()(context.Background(), [32]byte{}); !builderclient.IsRetryable(err) {
		t.Fatalf("inactive signer = %v, want retryable", err)
	}
}

// blipChain fails CommittedHeight once, then serves zero dispatch params.
type blipChain struct {
	DispatchChainView
	mu    sync.Mutex
	calls int
}

func (c *blipChain) CommittedHeight(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == 1 {
		return 0, errors.New("chain blip")
	}
	return 100, nil
}

func (c *blipChain) DispatchParamsAt(context.Context, uint64) (chainclient.DispatchParamsSnapshot, error) {
	return chainclient.DispatchParamsSnapshot{}, nil
}

func (c *blipChain) heightCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// S9 Q7: a chain blip at workload start is retried by the readiness
// controller instead of taking the daemon down.
func TestRunStreamsSurvivesAChainBlipAtWorkloadStart(t *testing.T) {
	chain := &blipChain{}
	streams := &DispatchStreams{sessions: map[string]*dispatchstream.Session{}, retired: map[string]bool{}}
	p := &DispatchPlane{cfg: DispatchPlaneConfig{Streams: streams, DispatchChain: chain, Dispatch: config.DispatchConfig{EvidenceRetentionBlocks: 1}}}
	var retried atomic.Int32
	c := NewReadinessController(ReadinessControllerConfig{
		Interval: 5 * time.Millisecond,
		Check: func(context.Context) WorkloadReadiness {
			return WorkloadReadiness{DependenciesReady: true, Identity: readyStatus(), ModelSupport: readyStatus(), ChainSync: readyStatus(), ServiceAddress: "svc"}
		},
		Start: func(ctx context.Context, _ WorkloadReadiness, started func()) error {
			started()
			return p.runStreams(ctx)
		},
		OnRetryableFailure: func(error) { retried.Add(1) },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	hrEventually(t, "the workload restarted after the blip", func() bool { return chain.heightCalls() >= 2 })
	select {
	case err := <-done:
		t.Fatalf("controller returned %v after one chain blip", err)
	case <-time.After(50 * time.Millisecond):
	}
	if retried.Load() != 1 {
		t.Fatalf("retryable failures = %d, want the one blip", retried.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRunStreamsSkipsRetiredBuilders(t *testing.T) {
	st := vsStore(t)
	s, err := NewDispatchStreams(DispatchStreamsConfig{
		ChainID: dpChainID, Operator: hrCortex, Builders: []string{hrBuilderA}, Retiring: []string{hrBuilderB},
		Stream:    config.DispatchStreamConfig{KeepaliveMS: 15_000, MaxMissed: 3},
		Endpoints: &dialResolver{}, HTTP: builderclient.NewDispatchStreamHTTPClient(),
		Keys: newFakeHandraiseChain(t), Sign: hrSigner(hrCortexKey), Height: func() uint64 { return 0 }, Store: st,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.markRetired(hrBuilderB)
	p := &DispatchPlane{cfg: DispatchPlaneConfig{Streams: s, DispatchChain: &blipChain{calls: 1}, Dispatch: config.DispatchConfig{EvidenceRetentionBlocks: 1}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.runStreams(ctx) }()
	hrEventually(t, "the active stream is dialling", func() bool { return s.sessions[hrBuilderA].State().LastError != "" })
	if st := s.sessions[hrBuilderB].State(); !st.Since.IsZero() {
		t.Fatalf("a retired Builder's stream ran again: %+v", st)
	}
	cancel()
	<-done
}
