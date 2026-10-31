package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const (
	omService = hrBuilderB // any bech32 address stands in for the service key's address
	omLow     = "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8"
	omHigh    = "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3"
)

var (
	omTask, omSession, omRecordHash = layout.StoredHash(bytes.Repeat([]byte{3}, 32)), layout.StoredHash(bytes.Repeat([]byte{4}, 32)), layout.StoredHash(bytes.Repeat([]byte{0x77}, 32))
	omSnapshot                      = bytes.Repeat([]byte{0x66}, 32)
	omUpheld                        = taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_UPHELD
)

func omModel(name string) []byte { h := codec.HashBytes([]byte(name)); return h[:] }

type omChain struct {
	mu         sync.Mutex
	height     uint64
	record     chainclient.DispatchRecordSnapshot
	records    map[[32]byte]chainclient.DispatchRecordSnapshot // by session; record otherwise
	recordErr  error
	pool       map[string]chainclient.CandidateMemberRefSnapshot // by snapshot hex
	profile    chainclient.TaskProfileSnapshot
	challenges map[[32]byte]chainclient.DispatchChallengeSnapshot
	params     chainclient.DispatchParamsSnapshot
}

func (c *omChain) CommittedHeight(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.height, nil
}
func (c *omChain) DispatchRecord(_ context.Context, session []byte, _ uint64) (chainclient.DispatchRecordSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recordErr != nil {
		return chainclient.DispatchRecordSnapshot{}, c.recordErr
	}
	if r, ok := c.records[[32]byte(session)]; ok {
		return r, nil
	}
	return c.record, nil
}
func (c *omChain) TaskProfile(context.Context, []byte) (chainclient.TaskProfileSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile, nil
}
func (c *omChain) CandidatePoolMember(_ context.Context, snapshot []byte, operator string) (chainclient.CandidateMemberRefSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := c.pool[hex.EncodeToString(snapshot)]; ok && m.OperatorAddress == operator {
		return m, nil
	}
	return chainclient.CandidateMemberRefSnapshot{}, chainclient.ErrNotFound
}
func (c *omChain) DispatchChallenge(_ context.Context, id []byte) (chainclient.DispatchChallengeSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.challenges[[32]byte(id)]
	if !ok {
		return chainclient.DispatchChallengeSnapshot{}, chainclient.ErrNotFound
	}
	return s, nil
}
func (c *omChain) DispatchParams(context.Context) (chainclient.DispatchParamsSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.params, nil
}

type omRoots struct{ roots []HeldRoot } // newest first

func (r *omRoots) RootByDigest(_ context.Context, b string, d [32]byte) (HeldRoot, bool, error) {
	for _, x := range r.roots {
		if x.Builder == b && x.RootDigest == d {
			return x, true, nil
		}
	}
	return HeldRoot{}, false, nil
}

func (r *omRoots) RootsUpTo(_ context.Context, b string, max uint64, limit int) ([]HeldRoot, error) {
	var out []HeldRoot
	for _, x := range r.roots {
		if x.Builder == b && x.RootHeight <= max && len(out) < limit {
			out = append(out, x)
		}
	}
	return out, nil
}

type omRosters struct {
	mu    sync.Mutex
	t     *testing.T
	resp  map[string]*nexusv1.GetDispatchRosterResponse
	asked []string
}

func (s *omRosters) GetDispatchRoster(_ context.Context, builder string, req *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error) {
	m := req.GetRosterRequest()
	d, err := dispatchwire.Digest(m)
	if err != nil || dispatch.VerifyDigestSignature(hrPub(s.t, hrCortexKey), d[:], m.GetServiceSignature()) != nil ||
		m.GetBuilderOperator() != builder || m.GetRequester() != hrCortex || m.GetChainId() != dpChainID ||
		req.GetTaskId() != builderclientIngress(layout.StoredHash(m.GetTaskId())) || len(req.GetSessionId()) != 66 ||
		(bytes.Equal(m.GetTaskId(), omTask[:]) && req.GetSessionId() != builderclientIngress(omSession)) {
		s.t.Errorf("roster request not signed for %s: %v", builder, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, builder)
	if r, ok := s.resp[builder]; ok {
		return r, nil
	}
	return nil, errors.New("DATA_NOT_FOUND")
}

func (s *omRosters) askedBuilders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

func builderclientIngress(h layout.StoredHash) string { return "0x" + h.String() }

// omTx is a txclient.Client: rejects with reject when set, otherwise runs
// land (the chain gains the effect) and reports the Tx confirmed.
type omTx struct {
	mu     sync.Mutex
	reqs   []txclient.Request
	reject string
	land   func(txclient.Request)
	lost   bool // the Tx lands but its result is lost (a crash after broadcast)
}

func (f *omTx) Submit(_ context.Context, r txclient.Request) (txclient.Observation, error) {
	if err := txclient.ValidateRequest(r); err != nil {
		return txclient.Observation{}, err
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	reject, land := f.reject, f.land
	f.mu.Unlock()
	if reject != "" {
		return txclient.Observation{TaskID: r.TaskID, Kind: r.Kind, Rejected: true, RejectReason: reject, Status: txclient.LifecycleRejected}, nil
	}
	if land != nil {
		land(r)
	}
	f.mu.Lock()
	lost := f.lost
	f.mu.Unlock()
	if lost {
		return txclient.Observation{}, errors.New("connection lost after broadcast")
	}
	return txclient.Observation{TaskID: r.TaskID, Kind: r.Kind, Accepted: true, TxHash: "C1A1", Status: txclient.LifecycleKeeperConfirmed}, nil
}

func (f *omTx) requests() []txclient.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]txclient.Request(nil), f.reqs...)
}

func (f *omTx) setReject(s string)                { f.mu.Lock(); f.reject = s; f.mu.Unlock() }
func (f *omTx) setLand(fn func(txclient.Request)) { f.mu.Lock(); f.land = fn; f.mu.Unlock() }

func omLeaf(free uint32, expiry uint64, model string) *taskv1.HandraiseRootLeafV1 {
	return &taskv1.HandraiseRootLeafV1{Admitted: true, Handraise: &taskv1.StandingHandraiseV1{SchemaVersion: 1, ChainId: dpChainID, BuilderAddress: hrBuilderA,
		Member:        &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: omSnapshot, Slot: 4, SlotVersion: 1, OperatorAddress: hrCortex},
		Profiles:      []*taskv1.DispatchProfileV1{{ModelId: omModel(model), ProfileVersion: 1}},
		FreeSlotCount: free, IssuedHeight: 170, ExpiryHeight: expiry, HandraiseNonce: 1, ServiceAuthorizationNonce: 7, ServiceSignature: bytes.Repeat([]byte{1}, 64)}}
}

func omRoot(t *testing.T, height, version uint64, leaf *taskv1.HandraiseRootLeafV1) (HeldRoot, *taskv1.SignedHandraiseRootV1) {
	t.Helper()
	root := &taskv1.SignedHandraiseRootV1{ChainId: dpChainID, BuilderAddress: hrBuilderA, RootHeight: height, RootVersion: version, LeafCount: 1,
		Root: bytes.Repeat([]byte{byte(height + version)}, 32)}
	d, err := dispatchwire.Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	if root.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		t.Fatal(err)
	}
	raw, err := dispatchwire.Raw(&nexusv1.HandraiseRootNoticeV1{Root: root, Proof: &taskv1.HandraiseInclusionProofV1{Leaf: leaf}})
	if err != nil {
		t.Fatal(err)
	}
	return HeldRoot{Builder: hrBuilderA, RootDigest: d, RootHeight: height, RootVersion: version, Admitted: true, Notice: raw}, root
}

type omFixture struct {
	t       *testing.T
	st      *store.Store
	chain   *omChain
	roots   *omRoots
	rosters *omRosters
	tx      *omTx
	w       *OmissionWatcher
	roster  *taskv1.DispatchRosterV1
	bound   *taskv1.SignedHandraiseRootV1
}

// newOmission: Builder A recorded omTask at 200 (window 30, close 230) with one
// round bound to a root at (180, 1) and a roster of slots 1 and 7; this node
// holds that root with leaf for slot 4, model "m" version 1.
func newOmission(t *testing.T, leaf *taskv1.HandraiseRootLeafV1) *omFixture {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	x := &omFixture{t: t, st: st, roots: &omRoots{}, rosters: &omRosters{t: t, resp: map[string]*nexusv1.GetDispatchRosterResponse{}}, tx: &omTx{}}
	held, bound := omRoot(t, 180, 1, leaf)
	x.bound, x.roots.roots = bound, []HeldRoot{held}
	x.roster = &taskv1.DispatchRosterV1{TaskId: omTask[:], ReferenceHeight: 100, CandidatePoolSnapshotId: omSnapshot, Members: []*taskv1.DispatchRosterMemberV1{
		{Slot: 1, SlotVersion: 1, OperatorAddress: omLow, CandidateWeight: 1}, {Slot: 7, SlotVersion: 1, OperatorAddress: omHigh, CandidateWeight: 2}}}
	rh, err := dispatchwire.RosterHash(dpChainID, x.roster)
	if err != nil {
		t.Fatal(err)
	}
	x.chain = &omChain{height: 201, challenges: map[[32]byte]chainclient.DispatchChallengeSnapshot{},
		params:  chainclient.DispatchParamsSnapshot{ChallengeWindowBlocks: 30, ChallengeResponseBlocks: 5, EvidenceRetentionBlocks: 40},
		profile: chainclient.TaskProfileSnapshot{ModelID: omModel("m"), ProfileVersion: 1},
		record: chainclient.DispatchRecordSnapshot{TaskID: omTask[:], RecordHash: omRecordHash[:], Builder: hrBuilderA, Winner: omHigh, RecordedHeight: 200,
			EarliestSubmitHeight: 190, ReferenceHeight: 100, CandidatePoolSnapshotID: omSnapshot,
			Rounds: []chainclient.DispatchRoundSnapshot{{Round: 0, HandraiseRootDigest: held.RootDigest[:], RosterHash: rh[:]}}}}
	x.rosters.resp[hrBuilderA] = &nexusv1.GetDispatchRosterResponse{DispatchRecordHash: omRecordHash[:],
		Rounds: []*nexusv1.DispatchRosterRoundV1{{DispatchRound: 0, Roster: x.roster, HandraiseRoot: bound}}}
	x.tx.setLand(func(r txclient.Request) { // the chain resolves an omission at once (KC §10.17)
		x.chain.mu.Lock()
		defer x.chain.mu.Unlock()
		x.chain.challenges[[32]byte(r.MaterialDigest)] = chainclient.DispatchChallengeSnapshot{ChallengeID: r.MaterialDigest[:], TaskID: omTask[:],
			Challenger: omService, Status: omUpheld, ResolvedHeight: x.chain.height}
	})
	if x.w, err = NewOmissionWatcher(OmissionConfig{ChainID: dpChainID, Operator: hrCortex, ServiceAddress: omService, Builders: []string{hrBuilderA, hrBuilderB},
		Chain: x.chain, Roots: x.roots, Rosters: x.rosters, Sign: hrSigner(hrCortexKey), Tx: x.tx, Store: st,
		RosterGraceBlocks: 4, ChallengeMarginBlocks: 3, GCEveryBlocks: 1}); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *omFixture) fact() DispatchRecordedFact {
	return DispatchRecordedFact{Height: 200, TaskID: omTask, SessionID: omSession, OrderSequence: 7, Builder: hrBuilderA, Winner: omHigh, RecordHash: omRecordHash, InferDeadline: 260}
}

func (x *omFixture) observe() {
	x.t.Helper()
	if err := x.w.ObserveDispatchRecorded(context.Background(), x.fact()); err != nil {
		x.t.Fatal(err)
	}
}

func (x *omFixture) sweepAt(h uint64) {
	x.t.Helper()
	x.chain.mu.Lock()
	x.chain.height = h
	x.chain.mu.Unlock()
	if err := x.w.Sweep(context.Background()); err != nil {
		x.t.Fatal(err)
	}
}

func (x *omFixture) state() layout.OmissionCase {
	x.t.Helper()
	c, err := layout.GetOmissionCase(context.Background(), x.st, omTask)
	if err != nil {
		x.t.Fatal(err)
	}
	return c
}

func omChallenge(t *testing.T, r txclient.Request) *taskv1.MsgChallengeDispatchOmission {
	t.Helper()
	var m taskv1.MsgChallengeDispatchOmission
	if r.Kind != txclient.MsgChallengeDispatchOmission || protojson.Unmarshal(r.Payload, &m) != nil {
		t.Fatalf("not an omission challenge: %+v", r)
	}
	return &m
}

func TestOmissionWatcherNeedsItsMargins(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	cfg := x.w.cfg
	cfg.RosterGraceBlocks = 0
	if _, err := NewOmissionWatcher(cfg); err == nil {
		t.Fatal("RosterGraceBlocks has no built-in default")
	}
	cfg.RosterGraceBlocks, cfg.ChallengeMarginBlocks = 4, 0
	if _, err := NewOmissionWatcher(cfg); err == nil {
		t.Fatal("ChallengeMarginBlocks has no built-in default")
	}
	cfg.ChallengeMarginBlocks = 3
	for _, bad := range []func(*OmissionConfig){
		func(c *OmissionConfig) { c.Operator = "not-bech32" },
		func(c *OmissionConfig) { c.ServiceAddress = "trueopen1nope" },
		func(c *OmissionConfig) { c.Builders = []string{hrBuilderA, "x"} },
	} {
		c := cfg
		bad(&c)
		if _, err := NewOmissionWatcher(c); err == nil {
			t.Fatal("addresses must be bech32")
		}
	}
	if x.w.cfg.RosterRequestTTLBlocks != 20 || x.w.cfg.ChecksPerSweep != 8 {
		t.Fatalf("defaults = %+v", x.w.cfg)
	}
}

func TestOmittedNodeChallengesWithTheBoundRoot(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.observe()
	x.observe() // a redelivered event is a no-op
	x.sweepAt(201)
	reqs := x.tx.requests()
	if len(reqs) != 1 || reqs[0].DeadlineHeight != 230 {
		t.Fatalf("requests = %+v", reqs)
	}
	m := omChallenge(t, reqs[0])
	if m.GetChallengerAddress() != omService || m.GetDispatchRound() != 0 || m.GetFirstRoundRoster() != nil || !proto.Equal(m.GetRoster(), x.roster) ||
		!proto.Equal(m.GetHandraiseRoot(), x.bound) || m.GetInclusionProof().GetLeaf().GetHandraise().GetMember().GetSlot() != 4 ||
		m.GetNonInclusionProof().GetPredecessor().GetSlot() != 1 || m.GetNonInclusionProof().GetSuccessor().GetSlot() != 7 {
		t.Fatalf("challenge = %v", m)
	}
	id, _ := dispatchwire.OmissionChallengeID(dpChainID, omTask, 0, hrCortex, omService)
	if reqs[0].MaterialDigest != codec.Hash(id) {
		t.Fatal("the Tx is keyed by challenge_id")
	}
	if c := x.state(); c.ChallengeID != layout.StoredHash(id) || c.State != layout.OmissionResolved || c.Outcome != int32(omUpheld) || c.RetainUntil != 230+5+40 {
		t.Fatalf("case = %+v", c)
	}
	x.sweepAt(202)
	x.observe()
	if len(x.tx.requests()) != 1 {
		t.Fatal("a resolved case submits nothing again")
	}
}

func TestOmissionOfALaterRoundCarriesTheFirstRoster(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	first := &taskv1.DispatchRosterV1{TaskId: omTask[:], ReferenceHeight: 100, CandidatePoolSnapshotId: omSnapshot, Members: []*taskv1.DispatchRosterMemberV1{
		{Slot: 4, SlotVersion: 1, OperatorAddress: hrCortex, CandidateWeight: 1}}} // round 0 had this node; round 1 left it out
	fh, _ := dispatchwire.RosterHash(dpChainID, first)
	round1 := x.chain.record.Rounds[0]
	round1.Round = 1
	x.chain.record.Rounds = []chainclient.DispatchRoundSnapshot{{Round: 0, HandraiseRootDigest: round1.HandraiseRootDigest, RosterHash: fh[:]}, round1}
	x.rosters.resp[hrBuilderA].Rounds = []*nexusv1.DispatchRosterRoundV1{
		{DispatchRound: 0, Roster: first, HandraiseRoot: x.bound}, {DispatchRound: 1, Roster: x.roster, HandraiseRoot: x.bound}}
	x.observe()
	x.sweepAt(201)
	reqs := x.tx.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %+v", reqs)
	}
	if m := omChallenge(t, reqs[0]); m.GetDispatchRound() != 1 || !proto.Equal(m.GetFirstRoundRoster(), first) || !proto.Equal(m.GetRoster(), x.roster) {
		t.Fatalf("challenge = %v", m)
	}
}

func TestNodeInTheRosterIsClear(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.roster.Members = append(x.roster.Members[:1], &taskv1.DispatchRosterMemberV1{Slot: 4, SlotVersion: 1, OperatorAddress: hrCortex, CandidateWeight: 3}, x.roster.Members[1])
	rh, _ := dispatchwire.RosterHash(dpChainID, x.roster)
	x.chain.record.Rounds[0].RosterHash = rh[:]
	x.observe()
	x.sweepAt(201)
	if c := x.state(); c.State != layout.OmissionClear || len(x.tx.requests()) != 0 {
		t.Fatalf("case = %+v", c)
	}
}

func TestIneligibleLeavesNeverChallenge(t *testing.T) {
	x := newOmission(t, omLeaf(0, 250, "m"))
	x.observe()
	if _, err := layout.GetOmissionCase(context.Background(), x.st, omTask); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("no free slot: not even a case")
	}
	y := newOmission(t, omLeaf(2, 250, "other model"))
	y.observe()
	y.sweepAt(201)
	if c := y.state(); c.State != layout.OmissionClear || len(y.rosters.askedBuilders()) != 0 {
		t.Fatalf("profile mismatch is decided before any roster fetch: %+v", c)
	}
	z := newOmission(t, omLeaf(2, 250, "m"))
	f := z.fact()
	f.Winner = hrCortex
	_ = z.w.ObserveDispatchRecorded(context.Background(), f)
	f.Winner, f.Builder = omHigh, "trueopen1unconfigured"
	_ = z.w.ObserveDispatchRecorded(context.Background(), f)
	if _, err := layout.GetOmissionCase(context.Background(), z.st, omTask); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("only for self, never when self won, only for configured Builders")
	}
	e := newOmission(t, omLeaf(2, 199, "m"))
	e.observe()
	if _, err := layout.GetOmissionCase(context.Background(), e.st, omTask); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a leaf expired before the record is not evidence")
	}
}

func TestNodeThatGotATicketSkipsTheTask(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	rec := layout.DispatchRecord{TicketHash: layout.StoredHash(bytes.Repeat([]byte{0x42}, 32)), TaskID: omTask, TaskHash: layout.StoredHash(bytes.Repeat([]byte{0x43}, 32)),
		Builder: hrBuilderA, Ticket: []byte("ticket"), SignedOrder: []byte("order")}
	if _, _, err := layout.PutDispatchOffer(context.Background(), x.st, rec); err != nil {
		t.Fatal(err)
	}
	x.observe()
	if _, err := layout.GetOmissionCase(context.Background(), x.st, omTask); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a ticket in any round: the whole task is skipped (S8 Q1)")
	}
}

func TestNewerRootBeforeEarliestSubmitIsEvidence(t *testing.T) {
	x := newOmission(t, omLeaf(0, 250, "m")) // the bound root's leaf has no free slot
	newer, newerRoot := omRoot(t, 185, 1, omLeaf(2, 250, "m"))
	late, _ := omRoot(t, 195, 1, omLeaf(2, 250, "m")) // signed after earliest_submit 190: no evidence
	x.roots.roots = append([]HeldRoot{late, newer}, x.roots.roots...)
	x.observe()
	x.sweepAt(201)
	reqs := x.tx.requests()
	if len(reqs) != 1 || !proto.Equal(omChallenge(t, reqs[0]).GetHandraiseRoot(), newerRoot) {
		t.Fatal("source (b): the newer root with root_height <= earliest_submit_height")
	}
}

func TestWindowCloseAbandons(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.observe()
	x.sweepAt(227) // 227 + margin 3 >= close 230
	if c := x.state(); c.State != layout.OmissionAbandoned || len(x.tx.requests()) != 0 {
		t.Fatalf("case = %+v", c)
	}
}

func TestRefusedChallengeIsAbandonedButADuplicateIsOurs(t *testing.T) {
	x := newOmission(t, omLeaf(2, 250, "m"))
	x.tx.setReject("ERR_DISPATCH_CHALLENGE_INVALID_PROOF")
	x.observe()
	x.sweepAt(201)
	if c := x.state(); c.State != layout.OmissionAbandoned {
		t.Fatalf("case = %+v", c)
	}
	y := newOmission(t, omLeaf(2, 250, "m"))
	y.tx.setReject("ERR_CHALLENGE_DUPLICATE")
	id, _ := dispatchwire.OmissionChallengeID(dpChainID, omTask, 0, hrCortex, omService)
	y.chain.challenges[id] = chainclient.DispatchChallengeSnapshot{ChallengeID: id[:], TaskID: omTask[:], Challenger: omService,
		Status: taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF}
	y.observe()
	y.sweepAt(201)
	if c := y.state(); c.State != layout.OmissionChallenged || c.ChallengeID != layout.StoredHash(id) {
		t.Fatalf("our own earlier challenge landed: %+v", c)
	}
	z := newOmission(t, omLeaf(2, 250, "m"))
	z.tx.setReject("out of gas")
	z.observe()
	z.sweepAt(201)
	z.tx.setReject("")
	z.sweepAt(210)
	if len(z.tx.requests()) != 1 {
		t.Fatal("an unclassified refusal backs off RecheckBlocks")
	}
	z.sweepAt(211)
	if c := z.state(); c.State != layout.OmissionResolved || len(z.tx.requests()) != 2 {
		t.Fatalf("any other refusal retries: %+v", c)
	}
}
