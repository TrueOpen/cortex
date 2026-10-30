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
	cfg      StandingHandraiseConfig
	gates    *handraiseGates
	db       handraiseStore
	builders []string // sorted
	wake     chan struct{}
	clock    blockClock // only the evaluating goroutine touches it

	mu      sync.Mutex
	current map[string]*CurrentHandraise
	resend  map[string]bool
	// unsent marks a Builder whose last record may not be in its outbox: its
	// enqueue failed, or this process restarted after persisting it. A
	// withdrawal is retried while it is set; a Rebound alone does not set it,
	// because the outbox replays what it holds (Q3: one withdrawal).
	unsent    map[string]bool
	admission map[string]HeldRoot
}

// NewStandingHandraiser reloads what was last signed for each Builder, so
// heights and nonces continue, and marks every Builder for a resend: restart
// recovery ends with a fresh handraise to each (CD §7.3 step 6).
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
		current: map[string]*CurrentHandraise{}, resend: map[string]bool{}, unsent: map[string]bool{},
		admission: map[string]HeldRoot{},
	}
	var newest *CurrentHandraise
	for _, b := range h.builders {
		cur, err := h.db.loadCurrent(ctx, b)
		if err != nil {
			return nil, err
		}
		h.current[b], h.resend[b], h.unsent[b] = cur, true, true
		if cur != nil && (newest == nil || cur.SentAtUnixMs > newest.SentAtUnixMs) {
			newest = cur
		}
	}
	if newest != nil {
		h.clock.seed = time.Duration(newest.BlockIntervalMs) * time.Millisecond
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
// dispatchstream.Config.OnBound of that Builder's session (S9 wiring).
func (h *StandingHandraiser) Rebound(builder string) {
	h.mu.Lock()
	if _, ok := h.resend[builder]; ok {
		h.resend[builder] = true
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
// handraise evidence every PruneEvery, until ctx ends.
func (h *StandingHandraiser) Run(ctx context.Context) error {
	tick := time.NewTicker(h.cfg.EvalEvery)
	defer tick.Stop()
	prune := time.NewTicker(h.cfg.PruneEvery)
	defer prune.Stop()
	for {
		if err := h.evaluate(ctx); err != nil && ctx.Err() == nil {
			h.cfg.Logger.Warn("standing handraise pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		case <-h.wake:
		case <-prune.C:
			h.prune(ctx)
		}
	}
}

func (h *StandingHandraiser) prune(ctx context.Context) {
	height, err := h.cfg.Chain.CommittedHeight(ctx)
	if err == nil {
		err = h.db.prune(ctx, height)
	}
	if err != nil && ctx.Err() == nil {
		h.cfg.Logger.Warn("prune handraise evidence", "err", err)
	}
}

// evaluate is one pass: read the height, run the gates once, decide and send
// per Builder.
func (h *StandingHandraiser) evaluate(ctx context.Context) error {
	now := h.cfg.Now()
	height, err := h.cfg.Chain.CommittedHeight(ctx)
	if err != nil {
		// Nothing is sent; what was sent expires by height (CD §4.2.0).
		return fmt.Errorf("standing handraise: committed height: %w", err)
	}
	h.clock.observe(height, now)
	_, known := h.clock.interval()
	g := h.gates.evaluate(ctx, known)
	tm := handraiseTiming{Heartbeat: h.cfg.Heartbeat, MinChange: h.cfg.MinChange}
	var errs []error
	for _, b := range h.builders {
		want, canWithdraw, why := g.state, g.factual, g.why
		if want != nil {
			if err := h.gates.builder(ctx, b); err != nil {
				want, canWithdraw, why = nil, false, err.Error()
			}
		}
		h.mu.Lock()
		last, resend, unsent := h.current[b], h.resend[b], h.unsent[b]
		h.mu.Unlock()
		act, reason := decideHandraise(now, height, last, want, canWithdraw, resend, tm)
		if act == handraiseNone && want == nil && canWithdraw && unsent && last != nil && last.Withdrawn && height <= last.ExpiryHeight {
			act, reason = handraiseWithdraw, "withdraw again: the last one may not be enqueued"
		}
		var st handraiseState
		switch act {
		case handraiseSend:
			st = *want
		case handraiseWithdraw:
			st = handraiseState{Member: last.State.Member, AuthNonce: g.authNonce}
			if st.AuthNonce == 0 {
				st.AuthNonce = last.State.AuthNonce
			}
			reason += ": " + why
		default:
			if why != "" {
				h.cfg.Logger.Debug("standing handraise held", "builder", b, "why", why)
			}
			continue
		}
		if err := h.send(ctx, b, height, now, st, act == handraiseWithdraw, last, reason); err != nil {
			errs = append(errs, fmt.Errorf("Builder %s: %w", b, err))
		}
	}
	return errors.Join(errs...)
}

// send signs, persists (current record + send log in one batch) and only then
// enqueues. A failed enqueue leaves the Builder marked for a resend; the
// persisted nonce is never reused.
func (h *StandingHandraiser) send(ctx context.Context, builder string, height uint64, now time.Time, st handraiseState, withdrawn bool, last *CurrentHandraise, reason string) error {
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
		h.mu.Lock()
		h.resend[builder], h.unsent[builder] = true, true
		h.mu.Unlock()
		return fmt.Errorf("enqueue standing handraise: %w", err)
	}
	h.mu.Lock()
	h.resend[builder], h.unsent[builder] = false, false
	h.mu.Unlock()
	h.cfg.Logger.Debug("standing handraise sent", "builder", builder, "reason", reason, "issued_height", issued,
		"nonce", nonce, "expiry_height", expiry, "free_slots", st.FreeSlots, "profiles", len(st.Profiles), "withdrawn", withdrawn)
	return nil
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
