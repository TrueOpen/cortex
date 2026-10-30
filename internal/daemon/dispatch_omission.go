package daemon

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// OmissionChainView is the chain authority omission discovery reads.
type OmissionChainView interface {
	CommittedHeight(context.Context) (uint64, error)
	DispatchRecord(ctx context.Context, sessionID []byte, orderSequence uint64) (chainclient.DispatchRecordSnapshot, error)
	TaskProfile(ctx context.Context, taskID []byte) (chainclient.TaskProfileSnapshot, error)
	CandidatePoolMember(ctx context.Context, snapshotID []byte, operator string) (chainclient.CandidateMemberRefSnapshot, error)
	DispatchChallenge(ctx context.Context, challengeID []byte) (chainclient.DispatchChallengeSnapshot, error)
	DispatchParams(ctx context.Context) (chainclient.DispatchParamsSnapshot, error)
}

var _ OmissionChainView = (*chainclient.KeeperABCIClient)(nil)

// OmissionRoots is the retained handraise roots (S3).
type OmissionRoots interface {
	RootByDigest(ctx context.Context, builder string, digest [32]byte) (HeldRoot, bool, error)
	RootsUpTo(ctx context.Context, builder string, maxRootHeight uint64, limit int) ([]HeldRoot, error)
}

var _ OmissionRoots = (*StandingHandraiser)(nil)

// DispatchRosterSource calls GetDispatchRoster on builder's IngressAPI (S9
// adapts builderEndpoints + ConnectTaskDataClient.GetDispatchRoster).
type DispatchRosterSource interface {
	GetDispatchRoster(ctx context.Context, builder string, req *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error)
}

const AlertDispatchOmissionRefused = "dispatch_omission_challenge_refused"

type OmissionConfig struct {
	ChainID        string
	Operator       string   // the victim: this Cortex operator
	ServiceAddress string   // challenger / reporter: the current service key's address (Tx signer)
	Builders       []string // configured Builders: only their records are examined; roster sources
	Chain          OmissionChainView
	Roots          OmissionRoots
	Rosters        DispatchRosterSource
	Sign           dispatchwire.DigestSigner
	Tx             txclient.Client
	Store          *store.Store
	// RosterGraceBlocks: blocks without any valid roster before
	// MsgReportDispatchRosterUnavailable. ChallengeMarginBlocks: no Tx once
	// height + margin reaches the window close. Both required (CD §15.3,
	// S8 Q6): neither has a built-in default.
	RosterGraceBlocks, ChallengeMarginBlocks uint64
	RosterRequestTTLBlocks                   uint64 // default 20
	RecheckBlocks                            uint64 // default 10
	GCEveryBlocks                            uint64 // default 10
	ChecksPerSweep                           int    // default 8
	RootScan                                 int    // roots read per Builder; default 64
	Now                                      func() time.Time
	Logger                                   *slog.Logger
}

// OmissionWatcher finds orders a configured Builder recorded while this
// node held an admitted, free, unexpired leaf for the task's profile, and
// challenges an omission from the roster (CD §8.7, KC §10.17). Only for self.
type OmissionWatcher struct {
	cfg      OmissionConfig
	builders map[string]bool
	mu       sync.Mutex
	nonce    uint64
	gcAt     uint64
}

func NewOmissionWatcher(cfg OmissionConfig) (*OmissionWatcher, error) {
	if cfg.ChainID == "" || cfg.Operator == "" || cfg.ServiceAddress == "" || len(cfg.Builders) == 0 || cfg.Chain == nil || cfg.Roots == nil ||
		cfg.Rosters == nil || cfg.Sign == nil || cfg.Tx == nil || cfg.Store == nil {
		return nil, errors.New("omission watcher: incomplete config")
	}
	if cfg.RosterGraceBlocks == 0 || cfg.ChallengeMarginBlocks == 0 {
		return nil, errors.New("omission watcher: RosterGraceBlocks and ChallengeMarginBlocks are required (no built-in default)")
	}
	for _, d := range []struct {
		p *uint64
		v uint64
	}{{&cfg.RosterRequestTTLBlocks, 20}, {&cfg.RecheckBlocks, 10}, {&cfg.GCEveryBlocks, 10}} {
		if *d.p == 0 {
			*d.p = d.v
		}
	}
	if cfg.ChecksPerSweep <= 0 {
		cfg.ChecksPerSweep = 8
	}
	if cfg.RootScan <= 0 {
		cfg.RootScan = 64
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger = cfg.Logger.With("component", "omission")
	w := &OmissionWatcher{cfg: cfg, builders: map[string]bool{}}
	for _, b := range cfg.Builders {
		w.builders[b] = true
	}
	return w, nil
}

var _ DispatchRecordObserver = (*OmissionWatcher)(nil)

func heldNotice(r HeldRoot) (*nexusv1.HandraiseRootNoticeV1, error) {
	n := &nexusv1.HandraiseRootNoticeV1{}
	if err := proto.Unmarshal(r.Notice, n); err != nil {
		return nil, err
	}
	return n, nil
}

// leafOpen: admitted, free slots, unexpired at recorded (KC §10.17).
func leafOpen(l *taskv1.HandraiseRootLeafV1, recorded uint64) bool {
	return l.GetAdmitted() && l.GetHandraise().GetFreeSlotCount() > 0 && l.GetHandraise().GetExpiryHeight() >= recorded
}

func leafServes(l *taskv1.HandraiseRootLeafV1, p chainclient.TaskProfileSnapshot, recorded uint64) bool {
	return leafOpen(l, recorded) && slices.ContainsFunc(l.GetHandraise().GetProfiles(), func(x *taskv1.DispatchProfileV1) bool {
		return bytes.Equal(x.GetModelId(), p.ModelID) && x.GetProfileVersion() == p.ProfileVersion
	})
}

// ObserveDispatchRecorded opens a case for a record this node may have been
// left out of. Cheap and local: the rest happens in Sweep. Idempotent: a
// redelivered event finds its case and changes nothing.
func (w *OmissionWatcher) ObserveDispatchRecorded(ctx context.Context, f DispatchRecordedFact) error {
	if f.Winner == w.cfg.Operator || !w.builders[f.Builder] {
		return nil
	}
	if local, err := layout.DispatchRecordsForTask(ctx, w.cfg.Store, f.TaskID); err != nil {
		return builderclient.Retryable(err)
	} else if len(local) > 0 {
		return nil // a ticket reached this node in some round: skip the whole task (S8 Q1)
	}
	roots, err := w.cfg.Roots.RootsUpTo(ctx, f.Builder, f.Height, w.cfg.RootScan)
	if err != nil {
		return builderclient.Retryable(err)
	}
	if !slices.ContainsFunc(roots, func(r HeldRoot) bool {
		n, err := heldNotice(r)
		return err == nil && leafOpen(n.GetProof().GetLeaf(), f.Height)
	}) {
		return nil
	}
	created, err := layout.PutOmissionCase(ctx, w.cfg.Store, layout.OmissionCase{TaskID: f.TaskID, SessionID: f.SessionID, OrderSequence: f.OrderSequence,
		Builder: f.Builder, RecordHash: f.RecordHash, RecordedHeight: f.Height})
	if errors.Is(err, layout.ErrConflict) {
		return err
	}
	if err != nil {
		return builderclient.Retryable(err)
	}
	if created {
		w.cfg.Logger.Info("omission candidate", "task", f.TaskID.String(), "builder", f.Builder)
	}
	return nil
}

// Sweep examines open cases (oldest record first, ChecksPerSweep at most),
// re-reads open challenges, and collects closed cases.
func (w *OmissionWatcher) Sweep(ctx context.Context) error {
	height, err := w.cfg.Chain.CommittedHeight(ctx)
	if err != nil {
		return err
	}
	cases, err := layout.OpenOmissionCases(ctx, w.cfg.Store)
	if err != nil {
		return err
	}
	var errs []error
	if len(cases) > 0 {
		p, err := w.cfg.Chain.DispatchParams(ctx)
		if err != nil {
			return err
		}
		slices.SortFunc(cases, func(a, b layout.OmissionCase) int { return cmp.Compare(a.RecordedHeight, b.RecordedHeight) })
		checked := 0
		for _, c := range cases {
			if c.NextCheckHeight > height {
				continue
			}
			var err error
			switch c.State {
			case layout.OmissionChallenged:
				err = w.syncChallenge(ctx, c, c.ChallengeID, height, p)
			default:
				if checked == w.cfg.ChecksPerSweep {
					continue
				}
				checked++
				err = w.examine(ctx, c, height, p)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("task %s: %w", c.TaskID, err))
			}
		}
	}
	if err := w.collect(ctx, height); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

type omissionCandidate struct {
	round uint32
	bound *HeldRoot  // (a) the round's bound root, held, leaf serving
	newer []HeldRoot // (b) roots with root_height <= earliest_submit, leaf serving, newest first
}

func windowClose(c layout.OmissionCase, p chainclient.DispatchParamsSnapshot) uint64 {
	return hrAddSat(c.RecordedHeight, p.ChallengeWindowBlocks)
}

func (w *OmissionWatcher) examine(ctx context.Context, c layout.OmissionCase, height uint64, p chainclient.DispatchParamsSnapshot) error {
	closeAt := windowClose(c, p)
	closing := hrAddSat(height, w.cfg.ChallengeMarginBlocks) >= closeAt
	if c.State == layout.OmissionReported && !c.ReportID.IsZero() {
		if err := w.syncChallenge(ctx, c, c.ReportID, height, p); err != nil {
			return err
		}
		cur, err := layout.GetOmissionCase(ctx, w.cfg.Store, c.TaskID)
		if err != nil || !cur.State.Open() || closing {
			return err // closing: only the report is followed now (syncChallenge)
		}
		c = cur
	}
	if closing {
		return w.close(ctx, c, layout.OmissionAbandoned, fmt.Sprintf("challenge window closes at %d", closeAt), 0, p)
	}
	rec, err := w.cfg.Chain.DispatchRecord(ctx, c.SessionID[:], c.OrderSequence)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("query dispatch record: %w", err)) // NotFound: the query lags the event
	}
	if !bytes.Equal(rec.RecordHash, c.RecordHash[:]) || !bytes.Equal(rec.TaskID, c.TaskID[:]) || rec.Builder != c.Builder || rec.RecordedHeight != c.RecordedHeight {
		return w.close(ctx, c, layout.OmissionAbandoned, "ChainObservationConflict: dispatch_recorded disagrees with QueryDispatchRecord", 0, p)
	}
	if rec.Winner == w.cfg.Operator {
		return w.close(ctx, c, layout.OmissionClear, "this node won the order", 0, p)
	}
	prof, err := w.cfg.Chain.TaskProfile(ctx, c.TaskID[:])
	if err != nil {
		return builderclient.Retryable(err)
	}
	cands, err := w.candidates(ctx, c, rec, prof)
	if err != nil {
		return builderclient.Retryable(err)
	}
	if len(cands) == 0 {
		return w.close(ctx, c, layout.OmissionClear, "no held root with an admitted, free, unexpired leaf for the task's profile", 0, p)
	}
	rounds, err := w.fetchRosters(ctx, c, rec, height)
	if err != nil {
		w.cfg.Logger.Warn("no roster for a candidate omission", "task", c.TaskID.String(), "err", err)
		return w.rosterMissing(ctx, c, cands[0].round, height, closeAt, p)
	}
	for _, cand := range cands { // rounds in record order: the earliest omitted round wins (S8 Q2)
		bound := rounds[cand.round].GetHandraiseRoot()
		evidence := cand.bound
		if evidence == nil {
			for i, r := range cand.newer {
				if r.RootHeight > bound.GetRootHeight() || (r.RootHeight == bound.GetRootHeight() && r.RootVersion > bound.GetRootVersion()) {
					evidence = &cand.newer[i]
					break
				}
			}
		}
		if evidence == nil {
			continue
		}
		notice, err := heldNotice(*evidence)
		if err != nil {
			continue
		}
		roster := rounds[cand.round].GetRoster()
		member := notice.GetProof().GetLeaf().GetHandraise().GetMember()
		slot := member.GetSlot()
		if !bytes.Equal(member.GetCandidatePoolSnapshotId(), roster.GetCandidatePoolSnapshotId()) { // S8 Q4
			m, err := w.cfg.Chain.CandidatePoolMember(ctx, roster.GetCandidatePoolSnapshotId(), w.cfg.Operator)
			if errors.Is(err, chainclient.ErrNotFound) {
				continue // not in the pool the draw used
			}
			if err != nil {
				return builderclient.Retryable(err)
			}
			slot = m.Slot
		}
		proof, err := dispatchwire.NonInclusion(roster, slot)
		if errors.Is(err, dispatchwire.ErrInRoster) {
			continue
		}
		if err != nil {
			return err
		}
		var first *taskv1.DispatchRosterV1
		if cand.round != 0 { // S8 Q3
			first = rounds[rec.Rounds[0].Round].GetRoster()
		}
		return w.challenge(ctx, c, cand.round, &taskv1.MsgChallengeDispatchOmission{TaskId: bytes.Clone(c.TaskID[:]), DispatchRound: cand.round,
			ChallengerAddress: w.cfg.ServiceAddress, Roster: roster, FirstRoundRoster: first, HandraiseRoot: notice.GetRoot(),
			InclusionProof: notice.GetProof(), NonInclusionProof: proof}, height, closeAt, p)
	}
	return w.close(ctx, c, layout.OmissionClear, "present in every examined round's roster", 0, p)
}

func (w *OmissionWatcher) candidates(ctx context.Context, c layout.OmissionCase, rec chainclient.DispatchRecordSnapshot, prof chainclient.TaskProfileSnapshot) ([]omissionCandidate, error) {
	serves := func(r HeldRoot) bool {
		n, err := heldNotice(r)
		return err == nil && leafServes(n.GetProof().GetLeaf(), prof, rec.RecordedHeight)
	}
	pool, err := w.cfg.Roots.RootsUpTo(ctx, c.Builder, rec.EarliestSubmitHeight, w.cfg.RootScan)
	if err != nil {
		return nil, err
	}
	pool = slices.DeleteFunc(pool, func(r HeldRoot) bool { return !serves(r) })
	var out []omissionCandidate
	for _, rd := range rec.Rounds {
		cand := omissionCandidate{round: rd.Round}
		digest := [32]byte(rd.HandraiseRootDigest)
		if r, ok, err := w.cfg.Roots.RootByDigest(ctx, c.Builder, digest); err != nil {
			return nil, err
		} else if ok && serves(r) {
			cand.bound = &r
		}
		for _, r := range pool {
			if r.RootDigest != digest {
				cand.newer = append(cand.newer, r)
			}
		}
		if cand.bound != nil || len(cand.newer) > 0 {
			out = append(out, cand)
		}
	}
	return out, nil
}

// fetchRosters asks the dispatching Builder first, then the other configured
// Builders, and keeps the first answer whose every round hashes to the
// record's roster_hash and handraise_root_digest.
func (w *OmissionWatcher) fetchRosters(ctx context.Context, c layout.OmissionCase, rec chainclient.DispatchRecordSnapshot, height uint64) (map[uint32]*nexusv1.DispatchRosterRoundV1, error) {
	order := append([]string{c.Builder}, slices.DeleteFunc(slices.Clone(w.cfg.Builders), func(b string) bool { return b == c.Builder })...)
	var errs []error
	for _, b := range order {
		req, err := w.rosterRequest(ctx, b, c, height)
		if err != nil {
			return nil, err
		}
		resp, err := w.cfg.Rosters.GetDispatchRoster(ctx, b, req)
		if err == nil {
			var rounds map[uint32]*nexusv1.DispatchRosterRoundV1
			if rounds, err = w.checkRosters(resp, rec); err == nil {
				return rounds, nil
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", b, err))
	}
	return nil, errors.Join(errs...)
}

func (w *OmissionWatcher) checkRosters(resp *nexusv1.GetDispatchRosterResponse, rec chainclient.DispatchRecordSnapshot) (map[uint32]*nexusv1.DispatchRosterRoundV1, error) {
	if len(resp.GetDispatchRecordHash()) != 0 && !bytes.Equal(resp.GetDispatchRecordHash(), rec.RecordHash) {
		return nil, fmt.Errorf("roster answers another record")
	}
	byRound := map[uint32]*nexusv1.DispatchRosterRoundV1{}
	for _, r := range resp.GetRounds() {
		byRound[r.GetDispatchRound()] = r
	}
	for _, want := range rec.Rounds {
		got, ok := byRound[want.Round]
		if !ok {
			return nil, fmt.Errorf("round %d missing", want.Round)
		}
		h, err := dispatchwire.RosterHash(w.cfg.ChainID, got.GetRoster())
		if err != nil || !bytes.Equal(h[:], want.RosterHash) {
			return nil, fmt.Errorf("round %d roster does not hash to roster_hash", want.Round)
		}
		d, err := dispatchwire.Digest(got.GetHandraiseRoot())
		if err != nil || !bytes.Equal(d[:], want.HandraiseRootDigest) {
			return nil, fmt.Errorf("round %d root is not the bound root", want.Round)
		}
	}
	return byRound, nil
}

func (w *OmissionWatcher) rosterRequest(ctx context.Context, builder string, c layout.OmissionCase, height uint64) (*nexusv1.GetDispatchRosterRequest, error) {
	w.mu.Lock()
	w.nonce = max(w.nonce+1, uint64(w.cfg.Now().UnixNano()))
	nonce := w.nonce
	w.mu.Unlock()
	m := &nexusv1.DispatchRosterRequestV1{TaskId: bytes.Clone(c.TaskID[:]), Requester: w.cfg.Operator, Nonce: nonce,
		ExpiryHeight: hrAddSat(height, w.cfg.RosterRequestTTLBlocks), ChainId: w.cfg.ChainID, BuilderOperator: builder}
	if err := dispatchwire.SignRosterRequest(ctx, m, w.cfg.Sign); err != nil {
		return nil, builderclient.Retryable(err)
	}
	return &nexusv1.GetDispatchRosterRequest{SessionId: builderclient.ToIngressHash32(hex.EncodeToString(c.SessionID[:])),
		TaskId:         builderclient.ToIngressHash32(hex.EncodeToString(c.TaskID[:])),
		Authentication: &nexusv1.GetDispatchRosterRequest_RosterRequest{RosterRequest: m}}, nil
}

// challengeRefused: the chain refused the proof itself (S8 Q8); anything
// else is retried.
func challengeRefused(reason string) bool {
	return strings.Contains(reason, "ERR_DISPATCH_CHALLENGE") || strings.Contains(reason, "ERR_CHALLENGE_DUPLICATE")
}

func (w *OmissionWatcher) submit(ctx context.Context, c layout.OmissionCase, kind txclient.Kind, msg proto.Message, deadline uint64, id [32]byte) (txclient.Observation, error) {
	payload, err := txclient.MarshalDispatchMessage(kind, msg)
	if err != nil {
		return txclient.Observation{}, err
	}
	return w.cfg.Tx.Submit(ctx, txclient.Request{TaskID: hex.EncodeToString(c.TaskID[:]), SessionID: hex.EncodeToString(c.SessionID[:]),
		Kind: kind, Payload: payload, DeadlineHeight: deadline, MaterialDigest: codec.Hash(id)})
}

// ownChallenge reports whether the chain already holds challenge id under
// this node's service address: an earlier submission landed (a crash
// between the Tx and the store update, or a duplicate rejection).
func (w *OmissionWatcher) ownChallenge(ctx context.Context, c layout.OmissionCase, id [32]byte) (bool, error) {
	s, err := w.cfg.Chain.DispatchChallenge(ctx, id[:])
	switch {
	case errors.Is(err, chainclient.ErrNotFound):
		return false, nil
	case err != nil:
		return false, builderclient.Retryable(err)
	}
	return s.Challenger == w.cfg.ServiceAddress && bytes.Equal(s.TaskID, c.TaskID[:]), nil
}

func (w *OmissionWatcher) challenge(ctx context.Context, c layout.OmissionCase, round uint32, msg *taskv1.MsgChallengeDispatchOmission, height, closeAt uint64, p chainclient.DispatchParamsSnapshot) error {
	id, err := dispatchwire.OmissionChallengeID(w.cfg.ChainID, c.TaskID, round, w.cfg.Operator, w.cfg.ServiceAddress)
	if err != nil {
		return err
	}
	obs, err := w.submit(ctx, c, txclient.MsgChallengeDispatchOmission, msg, closeAt, id)
	if err != nil {
		return builderclient.Retryable(err)
	}
	if obs.Rejected {
		if own, err := w.ownChallenge(ctx, c, id); err != nil {
			return err
		} else if !own {
			if challengeRefused(obs.RejectReason) {
				w.cfg.Logger.Error("omission challenge refused", "alert", AlertDispatchOmissionRefused, "task", c.TaskID.String(), "reason", obs.RejectReason)
				return w.close(ctx, c, layout.OmissionAbandoned, "the chain refused the omission challenge: "+obs.RejectReason, 0, p)
			}
			w.cfg.Logger.Warn("omission challenge not accepted; retrying", "task", c.TaskID.String(), "reason", obs.RejectReason)
			_, err := layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) { x.NextCheckHeight = height + 1 })
			return err
		}
	}
	c, err = layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) {
		x.State, x.Round, x.ChallengeID, x.ChallengeTx, x.NextCheckHeight = layout.OmissionChallenged, round, layout.StoredHash(id), obs.TxHash, height+w.cfg.RecheckBlocks
	})
	if err != nil {
		return builderclient.Retryable(err)
	}
	return w.syncChallenge(ctx, c, c.ChallengeID, height, p)
}

// rosterMissing waits RosterGraceBlocks after the first miss, then reports
// the roster unavailable once (permissionless, KC §10.17). The roster is
// still sought afterwards; an omission found later is still challenged.
func (w *OmissionWatcher) rosterMissing(ctx context.Context, c layout.OmissionCase, round uint32, height, closeAt uint64, p chainclient.DispatchParamsSnapshot) error {
	if c.RosterMissSince == 0 || c.State == layout.OmissionReported || height < hrAddSat(c.RosterMissSince, w.cfg.RosterGraceBlocks) {
		_, err := layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) {
			if x.RosterMissSince == 0 {
				x.RosterMissSince = height
			}
			x.NextCheckHeight = height + 1
		})
		return err
	}
	id, err := dispatchwire.RosterUnavailableChallengeID(w.cfg.ChainID, c.TaskID, round, w.cfg.ServiceAddress)
	if err != nil {
		return err
	}
	obs, err := w.submit(ctx, c, txclient.MsgReportDispatchRosterUnavailable, &taskv1.MsgReportDispatchRosterUnavailable{
		TaskId: bytes.Clone(c.TaskID[:]), DispatchRound: round, ReporterAddress: w.cfg.ServiceAddress}, closeAt, id)
	if err != nil {
		return builderclient.Retryable(err)
	}
	if obs.Rejected {
		if own, err := w.ownChallenge(ctx, c, id); err != nil {
			return err
		} else if !own {
			w.cfg.Logger.Warn("roster-unavailable report not accepted", "task", c.TaskID.String(), "reason", obs.RejectReason)
			_, err := layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) { x.NextCheckHeight = height + w.cfg.RecheckBlocks })
			return err
		}
	}
	_, err = layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) {
		x.State, x.ReportID, x.ReportRound, x.ReportTx, x.NextCheckHeight = layout.OmissionReported, layout.StoredHash(id), round, obs.TxHash, height+1
	})
	return err
}

var _ DispatchEventObserver = (*OmissionWatcher)(nil)

// ObserveDispatchEvent re-reads a challenge this node opened when the chain
// says it opened or resolved. Idempotent: a closed case ignores it.
func (w *OmissionWatcher) ObserveDispatchEvent(ctx context.Context, f DispatchEventFact) error {
	if f.Type != chainclient.KeeperEventDispatchChallengeOpened && f.Type != chainclient.KeeperEventDispatchChallengeResolved {
		return nil
	}
	c, err := layout.GetOmissionCase(ctx, w.cfg.Store, f.TaskID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return builderclient.Retryable(err)
	}
	if !c.State.Open() || f.ChallengeID.IsZero() || (f.ChallengeID != c.ChallengeID && f.ChallengeID != c.ReportID) {
		return nil
	}
	p, err := w.cfg.Chain.DispatchParams(ctx)
	if err != nil {
		return builderclient.Retryable(err)
	}
	return w.syncChallenge(ctx, c, f.ChallengeID, f.Height, p)
}

// syncChallenge reads QueryDispatchChallenge(id), the authority, and closes
// the case once the challenge it tracks is terminal. A challenge still open
// (or not visible) once the window and the response period have passed is
// given up, so no case stays open forever.
func (w *OmissionWatcher) syncChallenge(ctx context.Context, c layout.OmissionCase, id layout.StoredHash, height uint64, p chainclient.DispatchParamsSnapshot) error {
	s, err := w.cfg.Chain.DispatchChallenge(ctx, id[:])
	switch {
	case errors.Is(err, chainclient.ErrNotFound): // the query lags the Tx
	case err != nil:
		return builderclient.Retryable(err)
	default:
		if s.Challenger != w.cfg.ServiceAddress || !bytes.Equal(s.TaskID, c.TaskID[:]) {
			return fmt.Errorf("ChainObservationConflict: challenge %s names challenger %s, task %x", id, s.Challenger, s.TaskID)
		}
		switch s.Status {
		case taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_UPHELD,
			taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_DISMISSED,
			taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_EXPIRED:
			if id == c.ChallengeID || (id == c.ReportID && c.ChallengeID.IsZero()) {
				return w.close(ctx, c, layout.OmissionResolved, fmt.Sprintf("challenge %s %s at %d", s.Kind, s.Status, s.ResolvedHeight), int32(s.Status), p)
			}
			return nil
		}
	}
	if until := hrAddSat(windowClose(c, p), p.ChallengeResponseBlocks); height >= until {
		return w.close(ctx, c, layout.OmissionAbandoned, fmt.Sprintf("challenge %s not resolved by %d", id, until), 0, p)
	}
	_, err = layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) { x.NextCheckHeight = height + w.cfg.RecheckBlocks })
	return err
}

// close ends a case and keeps it to the challenge window close + response +
// dispatch_evidence_retention_blocks.
func (w *OmissionWatcher) close(ctx context.Context, c layout.OmissionCase, state layout.OmissionState, why string, outcome int32, p chainclient.DispatchParamsSnapshot) error {
	retain := hrAddSat(hrAddSat(windowClose(c, p), p.ChallengeResponseBlocks), p.EvidenceRetentionBlocks)
	_, err := layout.UpdateOmissionCase(ctx, w.cfg.Store, c.TaskID, func(x *layout.OmissionCase) {
		x.State, x.Reason, x.Outcome, x.RetainUntil = state, why, outcome, retain
	})
	if err != nil {
		return builderclient.Retryable(err)
	}
	w.cfg.Logger.Info("omission case closed", "task", c.TaskID.String(), "state", state, "why", why)
	return nil
}

// collect deletes closed cases past RetainUntil, at most every
// GCEveryBlocks.
func (w *OmissionWatcher) collect(ctx context.Context, height uint64) error {
	w.mu.Lock()
	due := w.gcAt == 0 || height >= hrAddSat(w.gcAt, w.cfg.GCEveryBlocks)
	if due {
		w.gcAt = height
	}
	w.mu.Unlock()
	if !due {
		return nil
	}
	tasks, err := layout.DueOmissionGC(ctx, w.cfg.Store, height, 256)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		if err := layout.DeleteOmissionCase(ctx, w.cfg.Store, t); err != nil {
			return err
		}
	}
	return nil
}
