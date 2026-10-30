package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// standingHandraiseSchemaVersion is StandingHandraiseV1.schema_version, as in
// wire's task_v1_standinghandraisev1 vector.
const standingHandraiseSchemaVersion = 1

// HandraiseEnqueuer is the part of dispatchstream.Session the standing
// handraise uses: one per configured Builder.
type HandraiseEnqueuer interface {
	Enqueue(context.Context, dispatchstream.Outgoing) (uint64, error)
}

// StandingHandraiseConfig configures the standing handraise (CD §4.2.0).
type StandingHandraiseConfig struct {
	ChainID         string
	Operator        string                   // this Cortex operator
	Profiles        []config.ModelProfileRef // local_identity.supported_model_profiles
	MinPriceBid     map[string]uint64        // dispatch.min_price_bid (H4)
	Heartbeat       time.Duration            // dispatch.handraise.heartbeat_ms
	TTL             time.Duration            // dispatch.handraise.ttl_ms
	MinChange       time.Duration            // dispatch.handraise.min_change_interval_ms
	RetentionBlocks uint64                   // dispatch.evidence_retention_blocks
	RootHistory     int                      // dispatch.handraise.root_history; default 64
	EvalEvery       time.Duration            // default 500ms
	PruneEvery      time.Duration            // default 10m
	Chain           HandraiseChainView
	Local           HandraiseLocal
	Sign            dispatchwire.DigestSigner
	Store           *store.Store
	Builders        map[string]HandraiseEnqueuer
	Now             func() time.Time
	Logger          *slog.Logger
	// Alert receives operator alerts in addition to the log line; optional.
	Alert func(HandraiseAlert)
}

// StandingHandraiser keeps one current StandingHandraiseV1 per Builder and
// verifies and retains the handraise roots Builders return.
type StandingHandraiser struct {
	cfg         StandingHandraiseConfig
	gates       *handraiseGates
	db          handraiseStore
	builders    []string // sorted
	wake        chan struct{}
	passTimeout time.Duration
	// clock (and the gates' memo) is touched only under evalMu, by Refresh
	// (from Run or the Dispatcher) or a test calling evaluate; pruneFrom and
	// pruneMore only by Run's goroutine.
	clock     blockClock
	pruneFrom []byte // where the next prune batch resumes
	pruneMore bool   // the last batch was full
	// evalMu runs one evaluation at a time.
	evalMu sync.Mutex

	mu      sync.Mutex
	current map[string]*CurrentHandraise
	// gen counts resend requests (restart, Rebound); sentGen is the gen the
	// last successful enqueue was decided under. A resend is pending while
	// they differ, so a Rebound landing during a send is never lost.
	gen, sentGen map[string]uint64
	// unsent marks a Builder whose last record may not be in its outbox: its
	// enqueue failed, or this process restarted after persisting it. A
	// withdrawal is retried while it is set; a Rebound alone does not set it,
	// because the outbox replays what it holds (Q3: one withdrawal).
	unsent    map[string]bool
	backoff   map[string]*enqueueBackoff
	admission map[string]HeldRoot
}

// enqueueBackoff spaces out retries after failed enqueues: every attempt
// persists a send-log entry and burns a nonce.
type enqueueBackoff struct {
	wait     time.Duration
	retryAt  time.Time
	failures int
	loggedAt time.Time
}

// errHandraiseEnqueue marks an enqueue failure; the backoff logs those itself.
var errHandraiseEnqueue = errors.New("enqueue standing handraise")

// NewStandingHandraiser reloads what was last signed for each Builder, so
// heights and nonces continue, marks every Builder for a resend (restart
// recovery ends with a fresh handraise to each, CD §7.3 step 6), and seeds
// each Builder's admission view from its newest retained root.
//
// S9 wiring: each Session's Config.OnBound must call Rebound, and the
// handraiser needs the Sessions as enqueuers. Build the Sessions first with
// a late-bound OnBound that loads the handraiser from an atomic.Pointer and
// nil-checks it, then pass the Sessions here and store the result:
//
//	var hr atomic.Pointer[StandingHandraiser]
//	OnBound: func(b string) { if h := hr.Load(); h != nil { h.Rebound(b) } }
//	...
//	hr.Store(h)
func NewStandingHandraiser(ctx context.Context, cfg StandingHandraiseConfig) (*StandingHandraiser, error) {
	var missing []string
	for name, absent := range map[string]bool{
		"ChainID": cfg.ChainID == "", "Operator": cfg.Operator == "", "Chain": cfg.Chain == nil,
		"Local": cfg.Local == nil, "Sign": cfg.Sign == nil, "Store": cfg.Store == nil,
		"Builders": len(cfg.Builders) == 0, "Heartbeat": cfg.Heartbeat <= 0, "TTL": cfg.TTL <= 0,
		"MinChange": cfg.MinChange <= 0, "RetentionBlocks": cfg.RetentionBlocks == 0,
	} {
		if absent {
			missing = append(missing, name)
		}
	}
	for b, e := range cfg.Builders {
		if e == nil {
			missing = append(missing, "Builders["+b+"]")
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("standing handraise: config missing %s", strings.Join(missing, ", "))
	}
	if cfg.Heartbeat >= cfg.TTL {
		return nil, fmt.Errorf("standing handraise: heartbeat %v must be below ttl %v", cfg.Heartbeat, cfg.TTL)
	}
	if cfg.RootHistory <= 0 {
		cfg.RootHistory = config.DefaultHandraiseRootHistory
	}
	if cfg.EvalEvery <= 0 {
		cfg.EvalEvery = 500 * time.Millisecond
	}
	if cfg.PruneEvery <= 0 {
		cfg.PruneEvery = 10 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger = cfg.Logger.With("component", "standing_handraise")
	gates, err := newHandraiseGates(cfg.Operator, cfg.Chain, cfg.Local, cfg.Profiles, cfg.MinPriceBid, cfg.Logger)
	if err != nil {
		return nil, err
	}
	h := &StandingHandraiser{
		cfg: cfg, gates: gates, db: handraiseStore{st: cfg.Store},
		builders: slices.Sorted(maps.Keys(cfg.Builders)), wake: make(chan struct{}, 1),
		// A pass must end well inside a handraise's lifetime.
		passTimeout: max(cfg.TTL/4, time.Second),
		clock:       blockClock{maxAge: 4 * cfg.TTL},
		current:     map[string]*CurrentHandraise{}, gen: map[string]uint64{}, sentGen: map[string]uint64{},
		unsent: map[string]bool{}, backoff: map[string]*enqueueBackoff{}, admission: map[string]HeldRoot{},
	}
	var newest *CurrentHandraise
	var notAdmitted []HeldRoot
	for _, b := range h.builders {
		cur, err := h.db.loadCurrent(ctx, b)
		if err != nil {
			return nil, err
		}
		h.current[b], h.gen[b], h.unsent[b] = cur, 1, true
		if cur != nil && (newest == nil || cur.SentAtUnixMs > newest.SentAtUnixMs) {
			newest = cur
		}
		roots, err := h.db.latestRoots(ctx, b, 1)
		if err != nil {
			return nil, err
		}
		if len(roots) == 1 {
			h.admission[b] = roots[0]
			if !roots[0].Admitted {
				notAdmitted = append(notAdmitted, roots[0])
			}
		}
	}
	if newest != nil {
		h.clock.seed = time.Duration(newest.BlockIntervalMs) * time.Millisecond
	}
	// A crash may have come between storing a not-admitted root and its
	// alert; raising it again at start is the cheap way not to lose it.
	for _, r := range notAdmitted {
		h.alert(HandraiseAlert{Kind: AlertHandraiseNotAdmitted, Builder: r.Builder, Root: r})
	}
	return h, nil
}

// Notify wakes an evaluation now; call it when free slots, profiles or drain
// change. It never blocks.
func (h *StandingHandraiser) Notify() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// Rebound requests a fresh handraise to builder. It is the
// dispatchstream.Config.OnBound of that Builder's session (S9 wiring). A new
// binding also ends any enqueue backoff: the next attempt goes out at once.
func (h *StandingHandraiser) Rebound(builder string) {
	h.mu.Lock()
	if _, ok := h.gen[builder]; ok {
		h.gen[builder]++
		if bo := h.backoff[builder]; bo != nil {
			bo.retryAt = time.Time{}
		}
	}
	h.mu.Unlock()
	h.Notify()
}

// Current returns the last handraise this node signed for builder.
func (h *StandingHandraiser) Current(builder string) (CurrentHandraise, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.current[builder]; c != nil {
		return *c, true
	}
	return CurrentHandraise{}, false
}

// Run evaluates every EvalEvery and on Notify/Rebound, and prunes expired
// handraise evidence one batch per PruneEvery tick (and one more per
// evaluation tick while batches come back full), until ctx ends.
func (h *StandingHandraiser) Run(ctx context.Context) error {
	tick := time.NewTicker(h.cfg.EvalEvery)
	defer tick.Stop()
	prune := time.NewTicker(h.cfg.PruneEvery)
	defer prune.Stop()
	for {
		if err := loggable(h.Refresh(ctx)); err != nil && ctx.Err() == nil {
			h.cfg.Logger.Warn("standing handraise pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if h.pruneMore {
				h.pruneStep(ctx)
			}
		case <-h.wake:
		case <-prune.C:
			h.pruneStep(ctx)
		}
	}
}

// Refresh runs one evaluation now and returns once every handraise it
// decided is signed, persisted and enqueued. The Dispatcher calls it before a
// capacity reject (CD §5.1 "容量变化先重签常驻举手再拒单"): the new handraise
// enters the same Builder outbox ahead of the reject.
func (h *StandingHandraiser) Refresh(ctx context.Context) error {
	h.evalMu.Lock()
	defer h.evalMu.Unlock()
	return h.evaluate(ctx)
}

// loggable drops the enqueue failures the backoff already logs.
func loggable(err error) error {
	if err == nil {
		return nil
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		if errors.Is(err, errHandraiseEnqueue) {
			return nil
		}
		return err
	}
	var keep []error
	for _, e := range joined.Unwrap() {
		if !errors.Is(e, errHandraiseEnqueue) {
			keep = append(keep, e)
		}
	}
	return errors.Join(keep...)
}

func (h *StandingHandraiser) pruneStep(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, h.passTimeout)
	defer cancel()
	height, err := h.cfg.Chain.CommittedHeight(ctx)
	if err == nil {
		h.pruneFrom, err = h.db.pruneBatch(ctx, height, h.pruneFrom)
	}
	h.pruneMore = err == nil && h.pruneFrom != nil
	if err != nil {
		h.pruneFrom = nil
		if ctx.Err() == nil {
			h.cfg.Logger.Warn("prune handraise evidence", "err", err)
		}
	}
}

// evaluate is one pass: read the height, run the gates once, decide and send
// per Builder.
func (h *StandingHandraiser) evaluate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, h.passTimeout)
	defer cancel()
	now := h.cfg.Now()
	height, err := h.cfg.Chain.CommittedHeight(ctx)
	if err != nil {
		// Nothing is sent; what was sent expires by height (CD §4.2.0).
		return fmt.Errorf("standing handraise: committed height: %w", err)
	}
	h.clock.observe(height, now)
	_, known := h.clock.interval()
	g := h.gates.evaluate(ctx, height, known)
	tm := handraiseTiming{Heartbeat: h.cfg.Heartbeat, MinChange: h.cfg.MinChange}
	var errs []error
	for _, b := range h.builders {
		h.mu.Lock()
		last, gen, sentGen, unsent, bo := h.current[b], h.gen[b], h.sentGen[b], h.unsent[b], h.backoff[b]
		h.mu.Unlock()
		if bo != nil && now.Before(bo.retryAt) {
			continue
		}
		var prev *handraiseState
		if last != nil && !last.Withdrawn {
			prev = &last.State
		}
		want, canWithdraw, why := g.offer(prev)
		if want != nil {
			if err := h.gates.builder(ctx, height, b); err != nil {
				want, canWithdraw, why = nil, false, err.Error()
			}
		}
		act, reason := decideHandraise(now, height, last, want, canWithdraw, gen != sentGen, tm)
		if act == handraiseNone && want == nil && canWithdraw && unsent && last != nil && last.Withdrawn && height <= last.ExpiryHeight {
			act, reason = handraiseWithdraw, "withdraw again: the last one may not be enqueued"
		}
		var st handraiseState
		switch act {
		case handraiseSend:
			st = *want
		case handraiseWithdraw:
			st = handraiseState{Member: last.State.Member, AuthNonce: last.State.AuthNonce}
			if g.authKnown {
				st.AuthNonce = g.authNonce
			}
			reason += ": " + why
		default:
			if why != "" {
				h.cfg.Logger.Debug("standing handraise held", "builder", b, "why", why)
			}
			continue
		}
		if err := h.send(ctx, b, height, now, st, act == handraiseWithdraw, last, reason, gen); err != nil {
			errs = append(errs, fmt.Errorf("Builder %s: %w", b, err))
		}
	}
	return errors.Join(errs...)
}

// send signs, persists (current record + send log in one batch) and only then
// enqueues. A failed enqueue keeps the resend pending and backs off; the
// persisted nonce is never reused. gen is the resend generation the send was
// decided under.
func (h *StandingHandraiser) send(ctx context.Context, builder string, height uint64, now time.Time, st handraiseState, withdrawn bool, last *CurrentHandraise, reason string, gen uint64) error {
	issued, nonce := nextIssue(last, height)
	expiry, ok := h.clock.expiryHeight(issued, h.cfg.TTL)
	if !ok {
		return errors.New("block interval not observed yet")
	}
	msg := st.message(h.cfg.ChainID, builder, issued, expiry, nonce)
	if err := dispatchwire.SignStandingHandraise(ctx, msg, h.cfg.Sign); err != nil {
		return err
	}
	digest, err := dispatchwire.Digest(msg)
	if err != nil {
		return err
	}
	raw, err := dispatchwire.Raw(msg)
	if err != nil {
		return err
	}
	interval, _ := h.clock.interval()
	cur := CurrentHandraise{
		IssuedHeight: issued, Nonce: nonce, ExpiryHeight: expiry, Digest: digest, State: st,
		Withdrawn: withdrawn, SentAtUnixMs: now.UnixMilli(), BlockIntervalMs: interval.Milliseconds(),
	}
	sent := sentHandraise{IssuedHeight: issued, ExpiryHeight: expiry, Nonce: nonce, Raw: raw}
	if err := h.db.recordSend(ctx, builder, cur, sent, h.cfg.RetentionBlocks); err != nil {
		return fmt.Errorf("persist standing handraise: %w", err)
	}
	h.mu.Lock()
	h.current[builder] = &cur
	h.mu.Unlock()
	if _, err := h.cfg.Builders[builder].Enqueue(ctx, dispatchstream.Outgoing{Message: msg, ExpiryHeight: expiry}); err != nil {
		h.enqueueFailed(builder, now, err)
		return fmt.Errorf("%w: %w", errHandraiseEnqueue, err)
	}
	h.mu.Lock()
	h.sentGen[builder], h.unsent[builder] = gen, false
	bo := h.backoff[builder]
	delete(h.backoff, builder)
	h.mu.Unlock()
	if bo != nil {
		h.cfg.Logger.Info("standing handraise enqueue recovered", "builder", builder, "failures", bo.failures)
	}
	h.cfg.Logger.Debug("standing handraise sent", "builder", builder, "reason", reason, "issued_height", issued,
		"nonce", nonce, "expiry_height", expiry, "free_slots", st.FreeSlots, "profiles", len(st.Profiles), "withdrawn", withdrawn)
	return nil
}

// enqueueFailed backs off 1s, doubling up to the heartbeat. It logs the first
// failure, then at most once per heartbeat.
func (h *StandingHandraiser) enqueueFailed(builder string, now time.Time, err error) {
	h.mu.Lock()
	h.unsent[builder] = true
	bo := h.backoff[builder]
	first := bo == nil
	if first {
		bo = &enqueueBackoff{}
		h.backoff[builder] = bo
	}
	bo.wait = min(max(2*bo.wait, time.Second), h.cfg.Heartbeat)
	bo.retryAt = now.Add(bo.wait)
	bo.failures++
	logIt := first || now.Sub(bo.loggedAt) >= h.cfg.Heartbeat
	if logIt {
		bo.loggedAt = now
	}
	failures, wait := bo.failures, bo.wait
	h.mu.Unlock()
	if logIt {
		h.cfg.Logger.Warn("standing handraise enqueue failed; backing off", "builder", builder,
			"failures", failures, "retry_in", wait, "err", err)
	}
}

func (s handraiseState) message(chainID, builder string, issued, expiry, nonce uint64) *taskv1.StandingHandraiseV1 {
	m := &taskv1.StandingHandraiseV1{
		SchemaVersion: standingHandraiseSchemaVersion, ChainId: chainID, BuilderAddress: builder,
		Member: &taskv1.CandidateMemberRefV1{
			CandidatePoolSnapshotId: append([]byte(nil), s.Member.SnapshotID[:]...),
			Slot:                    s.Member.Slot, SlotVersion: s.Member.SlotVersion, OperatorAddress: s.Member.Operator,
		},
		FreeSlotCount: s.FreeSlots, IssuedHeight: issued, ExpiryHeight: expiry,
		HandraiseNonce: nonce, ServiceAuthorizationNonce: s.AuthNonce,
	}
	for _, p := range s.Profiles {
		m.Profiles = append(m.Profiles, &taskv1.DispatchProfileV1{ModelId: append([]byte(nil), p.ModelID[:]...), ProfileVersion: p.Version})
	}
	return m
}
