package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// DispatchPlaneChain is every chain read the plane makes.
type DispatchPlaneChain interface {
	HandraiseChainView
	DispatchChainView
	VerifierStreamChain
	OmissionChainView
}

var _ DispatchPlaneChain = (*chainclient.KeeperABCIClient)(nil)

type DispatchPlaneConfig struct {
	Streams  *DispatchStreams
	Runner   *TaskRunner
	Evidence *evidence.Store
	Store    *store.Store

	ChainID, Operator, FeeDenom string
	Profiles                    []config.ModelProfileRef
	Dispatch                    config.DispatchConfig
	Capacity                    uint32 // model_management.max_concurrency
	Local                       HandraiseLocal
	Sign                        dispatchwire.DigestSigner
	Submitter                   func() (txclient.Client, string)

	HandraiseChain HandraiseChainView
	DispatchChain  DispatchChainView
	VerifierChain  VerifierStreamChain
	OmissionChain  OmissionChainView    // nil: no omission challenges
	Rosters        DispatchRosterSource // nil: no omission challenges

	Now    func() time.Time
	Logger *slog.Logger
	// EvalEvery and SweepEvery pace the loops; zero takes each default.
	EvalEvery, SweepEvery time.Duration
}

// DispatchPlane is the Phase 1 business side over the Builder streams.
type DispatchPlane struct {
	cfg        DispatchPlaneConfig
	handraiser *StandingHandraiser
	dispatcher *Dispatcher
	verifier   *VerifierStream
	omission   *OmissionWatcher
	records    DispatchRecordObservers
	events     DispatchEventObservers
}

func ms(v uint64) time.Duration { return time.Duration(v) * time.Millisecond }

// NewDispatchPlane builds the standing handraiser, the lease ledger, the
// Dispatcher, the Verifier stream handler and the OmissionWatcher, binds
// them to the streams' router and returns the plane. Call it before any
// runner or poller starts.
func NewDispatchPlane(ctx context.Context, cfg DispatchPlaneConfig) (*DispatchPlane, error) {
	s, d := cfg.Streams, cfg.Dispatch
	if s == nil || cfg.Runner == nil || cfg.Evidence == nil || cfg.Store == nil {
		return nil, fmt.Errorf("dispatch plane: incomplete config")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	hEnq, dEnq := map[string]HandraiseEnqueuer{}, map[string]DispatchEnqueuer{}
	for b, sess := range s.sessions {
		hEnq[b], dEnq[b] = sess, sess
	}
	leases, err := NewDispatchLeases(ctx, cfg.Store, cfg.Capacity)
	if err != nil {
		return nil, err
	}
	hr, err := NewStandingHandraiser(ctx, StandingHandraiseConfig{
		ChainID: cfg.ChainID, Operator: cfg.Operator, Profiles: cfg.Profiles, MinPriceBid: d.MinPriceBid,
		Heartbeat: ms(d.Handraise.HeartbeatMS), TTL: ms(d.Handraise.TTLMS), MinChange: ms(d.Handraise.MinChangeIntervalMS),
		RetentionBlocks: d.EvidenceRetentionBlocks, RootHistory: d.Handraise.RootHistory, EvalEvery: cfg.EvalEvery,
		Chain: cfg.HandraiseChain, Local: WithLeaseSlots(cfg.Local, leases), Sign: cfg.Sign, Store: cfg.Store,
		Builders: hEnq, Retiring: s.retiring, Now: cfg.Now, Logger: cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	disp, err := NewDispatcher(ctx, DispatcherConfig{
		ChainID: cfg.ChainID, Operator: cfg.Operator, FeeDenom: cfg.FeeDenom, Profiles: cfg.Profiles, MinPriceBid: d.MinPriceBid,
		SweepEvery: cfg.SweepEvery, Chain: cfg.DispatchChain, Local: cfg.Local, Handraise: hr, Leases: leases,
		Infer: cfg.Runner, Inputs: cfg.Evidence, Evidence: cfg.Evidence, Sign: cfg.Sign, Store: cfg.Store, Builders: dEnq,
		Submitter: cfg.Submitter, ReceiptRescueMarginBlocks: d.ReceiptRescueMarginBlocks, Retiring: s.retiring,
		Now: cfg.Now, Logger: cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	vs, err := NewVerifierStream(VerifierStreamConfig{ChainID: cfg.ChainID, Chain: cfg.VerifierChain, Store: cfg.Store,
		Assignment: cfg.Runner.recordVerifierAssignment, Wake: cfg.Runner.Wake, Logger: cfg.Logger})
	if err != nil {
		return nil, err
	}
	p := &DispatchPlane{cfg: cfg, handraiser: hr, dispatcher: disp, verifier: vs,
		records: DispatchRecordObservers{disp}, events: DispatchEventObservers{disp}}
	if cfg.Submitter != nil && cfg.OmissionChain != nil && cfg.Rosters != nil && d.Omission.RosterGraceBlocks > 0 && d.Omission.ChallengeMarginBlocks > 0 {
		om, err := NewOmissionWatcher(OmissionConfig{ChainID: cfg.ChainID, Operator: cfg.Operator, Builders: s.order,
			Chain: cfg.OmissionChain, Roots: hr, Rosters: cfg.Rosters, Sign: cfg.Sign, Store: cfg.Store, Submitter: cfg.Submitter,
			RosterGraceBlocks: d.Omission.RosterGraceBlocks, ChallengeMarginBlocks: d.Omission.ChallengeMarginBlocks,
			SweepEvery: cfg.SweepEvery, Now: cfg.Now, Logger: cfg.Logger})
		if err != nil {
			return nil, err
		}
		p.omission = om
		p.records = append(p.records, om)
		p.events = append(p.events, om)
	} else {
		cfg.Logger.Warn("omission challenges are off: no submitter (tx.enabled), roster source, chain view or omission pacing")
	}
	s.router.handraise.Store(hr)
	s.router.dispatch.Store(disp)
	s.router.verifier.Store(vs)
	s.plane.Store(p)
	return p, nil
}

// Runners are the plane's workload loops; they stop with the workload, so a
// node that is not ready sends no handraise (CD §4.2.2).
func (p *DispatchPlane) Runners() []func(context.Context) error {
	out := []func(context.Context) error{p.runStreams, p.handraiser.Run, p.dispatcher.Run}
	if p.omission != nil {
		out = append(out, p.omission.Run)
	}
	return out
}

// checkRootRetention refuses a dispatch_evidence_retention_blocks that ends
// before the roots it keeps can still prove an omission (S8 Q9): a root
// received at R backs tickets recorded until R + record_deadline, each
// challengeable for challenge_window + challenge_response after that. It is
// never below the chain's own dispatch evidence retention.
func checkRootRetention(retention uint64, p chainclient.DispatchParamsSnapshot) error {
	need := max(p.EvidenceRetentionBlocks, hrAddSat(hrAddSat(p.RecordDeadlineBlocks, p.ChallengeWindowBlocks), p.ChallengeResponseBlocks))
	if retention < need {
		return fmt.Errorf("dispatch.evidence_retention_blocks %d is below %d: chain dispatch evidence retention %d, or record deadline %d + challenge window %d + response %d (S8 Q9)",
			retention, need, p.EvidenceRetentionBlocks, p.RecordDeadlineBlocks, p.ChallengeWindowBlocks, p.ChallengeResponseBlocks)
	}
	return nil
}

func (p *DispatchPlane) runStreams(ctx context.Context) error {
	// Every failure here is retryable: a chain blip, or a root retention the
	// operator still has to raise, must not take the daemon down; the
	// readiness controller restarts the workload on its next tick (S9 Q7).
	height, err := p.cfg.DispatchChain.CommittedHeight(ctx)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("dispatch plane: committed height: %w", err))
	}
	params, err := p.cfg.DispatchChain.DispatchParamsAt(ctx, height)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("dispatch plane: dispatch params: %w", err))
	}
	if err := checkRootRetention(p.cfg.Dispatch.EvidenceRetentionBlocks, params); err != nil {
		return builderclient.Retryable(err)
	}
	s := p.cfg.Streams
	var wg sync.WaitGroup
	for b, sess := range s.sessions {
		if s.isRetired(b) {
			continue // closed for good; delete it from dispatch.retiring_builders
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sctx, stop := context.WithCancel(ctx)
			defer stop()
			if s.retiring[b] {
				go p.retire(sctx, stop, b)
			}
			_ = sess.Run(sctx)
			if s.retiring[b] && ctx.Err() == nil {
				s.markRetired(b)
			}
		}()
	}
	wg.Wait()
	// Every stream left is retired: stay up with the rest of the workload.
	<-ctx.Done()
	return ctx.Err()
}

// retire closes a retiring Builder's stream once its last handraise is the
// withdrawal (or none was ever sent) and none of its tickets holds a duty,
// one keepalive period later so the outbox can drain (CD §15.3).
func (p *DispatchPlane) retire(ctx context.Context, stop context.CancelFunc, b string) {
	every := max(p.cfg.Streams.cfg.Stream.Keepalive()/4, 100*time.Millisecond)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if cur, ok := p.handraiser.Current(b); ok && !cur.Withdrawn {
			continue
		}
		if busy, err := layout.BuilderHoldsDuty(ctx, p.cfg.Store, b); err != nil || busy {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.cfg.Streams.cfg.Stream.Keepalive()):
		}
		p.cfg.Logger.Info("Builder retired: stream closed; delete it from dispatch.retiring_builders", "builder", b)
		stop()
		return
	}
}
