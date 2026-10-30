package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// dispatchMessageSchemaVersion is schema_version of DispatchAcceptV1 and
// DispatchRejectV1, as in wire's dispatch vectors.
const dispatchMessageSchemaVersion = 1

// maxWindowMs keeps accept_deadline_ms inside time.Duration.
const maxWindowMs = uint64(math.MaxInt64 / int64(time.Millisecond))

// ErrOfferDropped marks a DispatchOfferV1 that failed CD §5.1 check 1: it is
// not this node's ticket to answer, so it is logged and dropped and no reject
// is ever signed for it. Permanent for the stream Handler.
var ErrOfferDropped = errors.New("dispatch offer dropped")

// DispatchChainView is the chain authority the Dispatcher reads. Every read of
// one offer evaluation is pinned to the one committed height it started from
// (Q18), so a ticket is never judged on facts from two heights.
// *chainclient.KeeperABCIClient satisfies it.
type DispatchChainView interface {
	CommittedHeight(context.Context) (uint64, error)
	CortexNodeAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.CortexNodeSnapshot, error)
	ServiceBondAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.ServiceBondSnapshot, error)
	CurrentServiceKey(ctx context.Context, participantType, operatorAddress string, height uint64) (chainclient.ServiceKeySnapshot, error)
	ModelSupportScopeAt(ctx context.Context, operatorAddress, modelID, profileVersion string, height uint64) (chainclient.CommittedModelSupportScope, error)
	BuilderVrfKeyAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.VrfKeySnapshot, error)
	BuilderSetAt(ctx context.Context, height uint64) (chainclient.BuilderSetSnapshot, error)
	DispatchEpochAt(ctx context.Context, earliestSubmitHeight, height uint64) (chainclient.DispatchEpochSnapshot, error)
	SessionAt(ctx context.Context, sessionID []byte, height uint64) (chainclient.SessionSnapshot, error)
	DispatchParamsAt(ctx context.Context, height uint64) (chainclient.DispatchParamsSnapshot, error)
	WorkerLiabilityParamsAt(ctx context.Context, height uint64) (chainclient.WorkerLiabilityParamsSnapshot, error)
}

var _ DispatchChainView = (*chainclient.KeeperABCIClient)(nil)

// DispatchHandraise is the part of the StandingHandraiser the Dispatcher uses.
type DispatchHandraise interface {
	Current(builder string) (CurrentHandraise, bool)
	HoldsRoot(ctx context.Context, builder string, digest [32]byte) (bool, error)
	Refresh(context.Context) error
	Notify()
}

var _ DispatchHandraise = (*StandingHandraiser)(nil)

// DispatchEnqueuer is the part of dispatchstream.Session the Dispatcher uses.
type DispatchEnqueuer interface {
	Enqueue(context.Context, dispatchstream.Outgoing) (uint64, error)
	WasSent(seq uint64) bool
}

var _ DispatchEnqueuer = (*dispatchstream.Session)(nil)

// DispatchInputSink publishes verified input under the task hash (TD §2.2,
// §5.1). *evidence.Store satisfies it.
type DispatchInputSink interface {
	Write(context.Context, evidence.WriteRequest) (evidence.Ref, error)
}

var _ DispatchInputSink = (*evidence.Store)(nil)

// DispatcherConfig configures the Worker side of Phase 1 dispatch.
type DispatcherConfig struct {
	ChainID  string
	Operator string // this Cortex operator; tickets must target it
	// FeeDenom is tx.fee_denom: the EIP-712 order domain binds it, so the
	// order's user signature cannot be checked without it.
	FeeDenom    string
	Profiles    []config.ModelProfileRef // local_identity.supported_model_profiles
	MinPriceBid map[string]uint64        // dispatch.min_price_bid (check 6)
	// MaxInputBytes bounds input_size_bytes (check 7); default and ceiling
	// are NexusTaskInputResolver's 64 MiB.
	MaxInputBytes uint64
	// AcceptSignMargin is how much of the accept window must remain to sign
	// (C4). Local, default 0.
	AcceptSignMargin time.Duration
	InputRequestTTL  time.Duration // expiry of a re-sent input request; default 30s
	InputRetryEvery  time.Duration // re-request input this long after the last request; default 5s
	SweepEvery       time.Duration // default 250ms

	Chain     DispatchChainView
	Local     HandraiseLocal // WorkloadReady and Draining; capacity is Leases
	Handraise DispatchHandraise
	Leases    *DispatchLeases
	Infer     DispatchInferStarter
	Inputs    DispatchInputSink
	Sign      dispatchwire.DigestSigner
	Store     *store.Store
	Builders  map[string]DispatchEnqueuer // one Session per configured Builder
	Now       func() time.Time
	Logger    *slog.Logger
}

// Dispatcher answers DispatchOfferV1, DispatchRevokeV1 and
// DispatchInputResponseV1 for every configured Builder (CD §4.2.0, §5.1, §5.2
// W1–W5). Every handler is idempotent per message, as the at-least-once
// stream Handler contract requires.
type Dispatcher struct {
	cfg      DispatcherConfig
	profiles map[HandraiseProfile]bool

	work sync.Mutex // one offer, revoke, input response or sweep at a time

	mu       sync.Mutex
	deadline map[layout.StoredHash]time.Time // C4 accept deadlines seen by this process
	rebound  map[string]bool
	wake     chan struct{}
}

// NewDispatcher validates cfg and fills local defaults.
func NewDispatcher(ctx context.Context, cfg DispatcherConfig) (*Dispatcher, error) {
	var missing []string
	for name, absent := range map[string]bool{
		"ChainID": cfg.ChainID == "", "Operator": cfg.Operator == "", "FeeDenom": cfg.FeeDenom == "",
		"Chain": cfg.Chain == nil, "Local": cfg.Local == nil, "Handraise": cfg.Handraise == nil, "Leases": cfg.Leases == nil,
		"Infer": cfg.Infer == nil, "Inputs": cfg.Inputs == nil, "Sign": cfg.Sign == nil, "Store": cfg.Store == nil,
		"Builders": len(cfg.Builders) == 0,
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
		return nil, fmt.Errorf("dispatcher: config missing %s", strings.Join(missing, ", "))
	}
	if cfg.MaxInputBytes == 0 || cfg.MaxInputBytes > defaultTaskDataMaxBytes {
		cfg.MaxInputBytes = defaultTaskDataMaxBytes
	}
	if cfg.InputRequestTTL <= 0 {
		cfg.InputRequestTTL = 30 * time.Second
	}
	if cfg.InputRetryEvery <= 0 {
		cfg.InputRetryEvery = 5 * time.Second
	}
	if cfg.SweepEvery <= 0 {
		cfg.SweepEvery = 250 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger = cfg.Logger.With("component", "dispatcher")
	profiles := map[HandraiseProfile]bool{}
	for _, r := range cfg.Profiles {
		p, err := profileOf(r.ModelID, r.ProfileVersion)
		if err != nil {
			return nil, fmt.Errorf("dispatcher: %w", err)
		}
		profiles[p] = true
	}
	d := &Dispatcher{
		cfg: cfg, profiles: profiles, deadline: map[layout.StoredHash]time.Time{},
		rebound: map[string]bool{}, wake: make(chan struct{}, 1),
	}
	if err := d.recoverLeases(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// HandleFrame is the stream Handler for the Worker dispatch variants. S9
// routes handraise_root to the StandingHandraiser and the Verifier variants
// elsewhere.
func (d *Dispatcher) HandleFrame(ctx context.Context, from string, f *nexusv1.DispatchStreamFrameV1) error {
	switch {
	case f.GetOffer() != nil:
		return d.HandleOffer(ctx, from, f.GetOffer())
	case f.GetRevoke() != nil:
		return d.HandleRevoke(ctx, from, f.GetRevoke())
	case f.GetInputResponse() != nil:
		return d.HandleInputResponse(ctx, from, f.GetInputResponse())
	}
	return fmt.Errorf("dispatcher: frame variant is not a Worker dispatch message")
}

// noteReceipt fixes the C4 accept deadline at this node's first receipt of
// the offer: monotonic in this process, the persisted wall-clock value after
// a restart. It only ever decides "do not sign or send late".
func (d *Dispatcher) noteReceipt(ticket layout.StoredHash, windowMs uint64, rec layout.DispatchRecord, persisted bool) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.deadline[ticket]; ok {
		return at
	}
	var at time.Time
	if persisted && rec.AcceptDeadlineUnixMs != 0 {
		at = time.UnixMilli(rec.AcceptDeadlineUnixMs)
	} else {
		at = d.cfg.Now().Add(time.Duration(min(windowMs, maxWindowMs)) * time.Millisecond)
	}
	d.deadline[ticket] = at
	return at
}

func (d *Dispatcher) acceptDeadline(rec layout.DispatchRecord) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	if at, ok := d.deadline[rec.TicketHash]; ok {
		return at
	}
	return time.UnixMilli(rec.AcceptDeadlineUnixMs)
}

func (d *Dispatcher) forgetDeadline(ticket layout.StoredHash) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.deadline, ticket)
}

// drop logs a check-1 failure and returns it as ErrOfferDropped.
func (d *Dispatcher) drop(builder string, ticket layout.StoredHash, err error) error {
	d.cfg.Logger.Info("dispatch offer dropped (CD §5.1 check 1; no reject is signed)",
		"builder", builder, "ticket", ticket.String(), "err", err)
	return fmt.Errorf("%w: %w", ErrOfferDropped, err)
}

// release moves rec to state, stops its inference and returns its lease.
func (d *Dispatcher) release(ctx context.Context, rec layout.DispatchRecord, state layout.DispatchState, why string) error {
	if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
		r.State, r.StateReason = state, why
		return nil
	}); err != nil {
		return builderclient.Retryable(fmt.Errorf("record %s: %w", state, err))
	}
	if err := d.cfg.Infer.StopDispatchedInfer(ctx, rec.TaskHash, rec.TicketHash); err != nil {
		return builderclient.Retryable(fmt.Errorf("stop inference: %w", err))
	}
	if err := d.releaseLease(ctx, rec.TicketHash); err != nil {
		return err
	}
	d.forgetDeadline(rec.TicketHash)
	d.cfg.Logger.Info("dispatch ticket released", "builder", rec.Builder, "ticket", rec.TicketHash.String(), "state", state, "why", why)
	return nil
}

func (d *Dispatcher) releaseLease(ctx context.Context, ticket layout.StoredHash) error {
	released, err := d.cfg.Leases.Release(ctx, ticket)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("release lease: %w", err))
	}
	if released {
		d.cfg.Handraise.Notify()
	}
	return nil
}

// supersede releases older rounds of the same task from the same Builder
// before capacity is judged (CD §5.2 W3).
func (d *Dispatcher) supersede(ctx context.Context, builder string, t *taskv1.DispatchTicketV1, self layout.StoredHash) error {
	taskID, ok := hash32(t.GetTaskId())
	if !ok {
		return nil
	}
	recs, err := layout.DispatchRecordsForTask(ctx, d.cfg.Store, taskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("records for task: %w", err))
	}
	for _, r := range recs {
		if r.TicketHash == self || r.Builder != builder || r.DispatchRound >= t.GetDispatchRound() {
			continue
		}
		if r.State != layout.DispatchOffered && r.State != layout.DispatchAccepted {
			continue
		}
		if err := d.release(ctx, r, layout.DispatchSuperseded, fmt.Sprintf("dispatch round %d of the task arrived", t.GetDispatchRound())); err != nil {
			return err
		}
	}
	return nil
}

func profileOf(modelHex string, version uint32) (HandraiseProfile, error) {
	raw, err := hex.DecodeString(modelHex)
	if err != nil || len(raw) != 32 {
		return HandraiseProfile{}, fmt.Errorf("model_id %q is not 32-byte hex", modelHex)
	}
	var p HandraiseProfile
	copy(p.ModelID[:], raw)
	p.Version = version
	return p, nil
}

func hash32(b []byte) (layout.StoredHash, bool) {
	var h layout.StoredHash
	if len(b) != len(h) {
		return h, false
	}
	copy(h[:], b)
	return h, true
}
