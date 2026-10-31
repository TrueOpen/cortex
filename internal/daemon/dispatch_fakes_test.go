package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// dpChainID is the chain of wire's dispatch vectors. The fixture ticket keeps
// their VRF input (chain_id, epoch, seed, session_id, order_sequence), so the
// published VRF proof stays valid while every other field is rewritten and
// re-signed.
const (
	dpChainID        = "trueopen-phase1-vector-1"
	dpOrderChainID   = 777 // EIP-712 domain chain id the fixture user signs under
	dpFeeDenom       = "uusdc"
	dpRecordDeadline = 50
)

var dpUserKey = secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))

func dpHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type dpEpochSection struct {
	Length       uint64 `json:"epoch_length_blocks"`
	Height       uint64 `json:"earliest_submit_height"`
	Epoch        uint64 `json:"epoch"`
	Start        uint64 `json:"epoch_start_height"`
	BeaconHeight uint64 `json:"beacon_height"`
	BeaconHex    string `json:"beacon_randomness_hex"`
	ProofHex     string `json:"vrf_proof_hex"`
}

type dpVRFSection struct {
	PublicKeyHex  string `json:"public_key_hex"`
	RandomnessHex string `json:"randomness_hex"`
}

// dpLog records, in order, what the Dispatcher asked its collaborators to do.
type dpLog struct {
	mu     sync.Mutex
	events []string
}

func (l *dpLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *dpLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// offerFixture is one legitimate offer: wire's ticket vector re-targeted at
// hrCortex from hrBuilderA, bound to a real signed order.
type offerFixture struct {
	t      testing.TB
	ticket *taskv1.DispatchTicketV1
	order  *taskv1.SignedOrderV2
	input  []byte
	root   [32]byte
	vrfPub []byte
	epoch  dpEpochSection
}

func newOfferFixture(t testing.TB) *offerFixture {
	t.Helper()
	var ep dpEpochSection
	if err := wirevectors.DispatchSection("epoch_seed_derivation", &ep); err != nil {
		t.Fatal(err)
	}
	var vrf dpVRFSection
	if err := wirevectors.DispatchSection("vrf", &vrf); err != nil {
		t.Fatal(err)
	}
	row, err := wirevectors.DispatchVectorByName("task_v1_dispatchticketv1")
	if err != nil {
		t.Fatal(err)
	}
	tk := &taskv1.DispatchTicketV1{}
	if err := proto.Unmarshal(dpHex(t, row.ProtobufHex), tk); err != nil {
		t.Fatal(err)
	}
	rootRow, err := wirevectors.DispatchVectorByName("task_v1_signedhandraiserootv1")
	if err != nil {
		t.Fatal(err)
	}
	f := &offerFixture{t: t, ticket: tk, input: []byte("dispatch fixture input: summarise the ledger"), vrfPub: dpHex(t, vrf.PublicKeyHex), epoch: ep}
	copy(f.root[:], dpHex(t, rootRow.DigestHex))
	member := &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: bytes.Repeat([]byte{0x5a}, 32), Slot: 4, SlotVersion: 2, OperatorAddress: hrCortex}
	tk.BuilderAddress = hrBuilderA
	tk.CandidatePoolSnapshotId = bytes.Clone(member.CandidatePoolSnapshotId)
	tk.Target = member
	tk.VrfEpoch, tk.ReferenceHeight = ep.Epoch, ep.Start
	tk.VrfProof, tk.VrfOutput = dpHex(t, ep.ProofHex), dpHex(t, vrf.RandomnessHex)
	tk.HandraiseRootDigest = bytes.Clone(f.root[:])
	tk.AcceptDeadlineMs = 2_000
	tk.BoundChangeHeight = 105
	user, err := evmAccountAddress("trueopen", dpUserKey.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	inputHash := sha256.Sum256(f.input)
	f.order = &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{
		SchemaVersion: 3, ChainId: dpChainID, UserAddress: user,
		SessionId: bytes.Clone(tk.SessionId), OrderSequence: tk.OrderSequence,
		ModelId: dpHex(t, hrModelAB), ProfileVersion: 1, TaskType: sharedv1.TaskType_TASK_TYPE_TEXT_GENERATION,
		InputHash: inputHash[:], InputSizeBytes: uint64(len(f.input)), InputBucket: 2, OutputBudgetBucket: 4,
		GenerationParams: &taskv1.GenerationParamsV1{
			GenerationParamsSchemaVersion: 1, MaxOutputTokens: 128, MaxOutputDuration: 2000,
			DecodingParams: &taskv1.DecodingParamsV1{
				SamplingEnabled: true, TemperatureMilli: 700, TopPPpm: 900_000, TopK: 40, Seed: 17,
				PresencePenaltyMilli: -100, FrequencyPenaltyMilli: 200, RepetitionPenaltyPpm: 1_050_000,
				StopSequences: []string{"END"}, StopTokenIds: []uint32{2},
			},
		},
		PriceBid: &sharedv1.Amount{AtomicUnits: "10"}, MaxFee: &sharedv1.Amount{AtomicUnits: "1000"},
		AssignmentPriorityFee: &sharedv1.Amount{AtomicUnits: "50"}, TxFeeReserve: &sharedv1.Amount{AtomicUnits: "100"},
		EarliestSubmitHeight: ep.Height, OrderExpireHeight: 10_000,
		DeadlinePolicy:       &taskv1.DeadlinePolicyV1{LatencyClass: taskv1.DeadlineLatencyClass_DEADLINE_LATENCY_CLASS_STANDARD},
		TimeoutBucketVersion: 6, SessionAnchorHeight: 50, BuilderSetId: "7", BuilderSetHash: bytes.Repeat([]byte{0x15}, 32),
		PayloadMode: taskv1.PayloadModeV1_PAYLOAD_MODE_V1_PLAINTEXT, InputKeyCommitment: make([]byte, 32),
	}}
	f.seal()
	return f
}

// seal signs the order as its user, binds the ticket to it and re-signs the ticket.
func (f *offerFixture) seal() {
	f.signOrder(dpUserKey)
	f.bindTicket()
	f.signTicket(hrBuilderKey)
}

func (f *offerFixture) signOrder(key *secp256k1.PrivateKey) {
	f.t.Helper()
	digest, err := nodewire.TaskOrderSigningDigest(f.order.Order, dpOrderChainID, dpFeeDenom)
	if err != nil {
		f.t.Fatal(err)
	}
	compact := ecdsa.SignCompact(key, digest[:], false)
	f.order.SignatureScheme = "eip712"
	f.order.UserSignature = append(append([]byte(nil), compact[1:]...), compact[0])
	f.order.SignatureChainId = dpOrderChainID
}

func (f *offerFixture) bindTicket() {
	f.t.Helper()
	raw, err := dispatchwire.Raw(f.order)
	if err != nil {
		f.t.Fatal(err)
	}
	taskHash, facts, err := nodewire.TaskOrderHashAndFactsSignedOrderHex(hex.EncodeToString(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	taskID := identity.TaskID(facts.SessionID, facts.OrderSequence)
	f.ticket.TaskHash, f.ticket.TaskId = bytes.Clone(taskHash[:]), bytes.Clone(taskID[:])
	f.ticket.InputHash = bytes.Clone(f.order.Order.InputHash)
}

func (f *offerFixture) signTicket(keyHex string) {
	f.t.Helper()
	f.ticket.BuilderServiceSignature = nil
	d, err := dispatchwire.Digest(f.ticket)
	if err != nil {
		f.t.Fatal(err)
	}
	if f.ticket.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *offerFixture) offer() *nexusv1.DispatchOfferV1 {
	return &nexusv1.DispatchOfferV1{
		Ticket:      proto.Clone(f.ticket).(*taskv1.DispatchTicketV1),
		SignedOrder: proto.Clone(f.order).(*taskv1.SignedOrderV2),
	}
}

func (f *offerFixture) ticketHash() [32]byte {
	f.t.Helper()
	d, err := dispatchwire.Digest(f.ticket)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *offerFixture) taskHash() [32]byte {
	var h [32]byte
	copy(h[:], f.ticket.TaskHash)
	return h
}

func (f *offerFixture) inputResponse(index, count uint32, chunk []byte) *nexusv1.DispatchInputResponseV1 {
	f.t.Helper()
	th := f.ticketHash()
	m := &nexusv1.DispatchInputResponseV1{
		TaskId: bytes.Clone(f.ticket.TaskId), DispatchTicketHash: th[:], InputHash: bytes.Clone(f.ticket.InputHash),
		InputSizeBytes: uint64(len(f.input)), Input: bytes.Clone(chunk), ChunkIndex: index, ChunkCount: count,
	}
	d, err := dispatchwire.Digest(m)
	if err != nil {
		f.t.Fatal(err)
	}
	if m.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		f.t.Fatal(err)
	}
	return m
}

type fakeDispatchChain struct {
	mu          sync.Mutex
	height      uint64
	node        chainclient.CortexNodeSnapshot
	bond        chainclient.ServiceBondSnapshot
	cortexKey   chainclient.ServiceKeySnapshot
	builderKeys map[string]chainclient.ServiceKeySnapshot
	vrf         chainclient.VrfKeySnapshot
	epoch       chainclient.DispatchEpochSnapshot
	session     chainclient.SessionSnapshot
	set         chainclient.BuilderSetSnapshot
	params      chainclient.DispatchParamsSnapshot
	liability   chainclient.WorkerLiabilityParamsSnapshot
	scopes      map[string]chainclient.CommittedModelSupportScope
	// heightCalls counts CommittedHeight; readHeights counts the pinned reads
	// per height and calls per method.
	heightCalls int
	readHeights map[uint64]int
	calls       map[string]int
	// Injected read failures.
	nodeErr, bondErr, vrfErr error
	// S5 record reads: an unset record or assignment answers ErrNotFound.
	record        chainclient.DispatchRecordSnapshot
	recordErr     error
	recordQueries int
	assignment    chainclient.DispatchAssignmentSnapshot
	assignmentErr error
	// S6 compensation reads: an unset claim or marker answers ErrNotFound.
	claims         map[[32]byte]chainclient.DispatchClaimSnapshot
	ineligible     map[[32]byte]chainclient.DispatchWinnerIneligibleSnapshot
	byBuilderCalls int
	byBuilderErr   error
}

func (f *fakeDispatchChain) DispatchCompensationClaim(_ context.Context, ticket []byte) (chainclient.DispatchClaimSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.claims[[32]byte(ticket)]
	if !ok {
		return chainclient.DispatchClaimSnapshot{}, chainclient.ErrNotFound
	}
	c.Height = f.height
	return c, nil
}

func (f *fakeDispatchChain) DispatchCompensationClaimsByBuilder(_ context.Context, builder string) (uint64, []chainclient.DispatchClaimSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byBuilderCalls++
	if f.byBuilderErr != nil {
		return 0, nil, f.byBuilderErr
	}
	var out []chainclient.DispatchClaimSnapshot
	for _, c := range f.claims {
		if c.Builder == builder && c.Status == taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL {
			c.Height = f.height
			out = append(out, c)
		}
	}
	return f.height, out, nil
}

func (f *fakeDispatchChain) DispatchWinnerIneligible(_ context.Context, ticket []byte) (chainclient.DispatchWinnerIneligibleSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row, ok := f.ineligible[[32]byte(ticket)]
	if !ok {
		return chainclient.DispatchWinnerIneligibleSnapshot{}, chainclient.ErrNotFound
	}
	row.Height = f.height
	return row, nil
}

func newFakeDispatchChain(t testing.TB, f *offerFixture) *fakeDispatchChain {
	var setHash chainclient.HexHash
	copy(setHash[:], bytes.Repeat([]byte{0x15}, 32))
	return &fakeDispatchChain{
		height: 150,
		node:   chainclient.CortexNodeSnapshot{OperatorAddress: hrCortex, Status: "ACTIVE"},
		bond:   chainclient.ServiceBondSnapshot{OperatorAddress: hrCortex, Status: "ACTIVE", ActiveBond: 1_000, BondVersion: 1},
		cortexKey: chainclient.ServiceKeySnapshot{ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: hrCortex,
			ServicePubkey: hex.EncodeToString(hrPub(t, hrCortexKey)), AuthorizationNonce: 7, Status: "ACTIVE"},
		builderKeys: map[string]chainclient.ServiceKeySnapshot{hrBuilderA: {ParticipantType: chainclient.ParticipantTypeBuilder,
			OperatorAddress: hrBuilderA, ServicePubkey: hex.EncodeToString(hrPub(t, hrBuilderKey)), AuthorizationNonce: 1, Status: "ACTIVE"}},
		vrf: chainclient.VrfKeySnapshot{ActivePubkey: bytes.Clone(f.vrfPub)},
		epoch: chainclient.DispatchEpochSnapshot{Height: 150, EpochLengthBlocks: f.epoch.Length, BeaconHeight: f.epoch.BeaconHeight,
			Randomness: dpHex(t, f.epoch.BeaconHex), Verified: true},
		session: chainclient.SessionSnapshot{Height: 150, SessionID: bytes.Clone(f.ticket.SessionId), Status: "ACTIVE",
			OwnerUserAddress: f.order.Order.UserAddress,
			BoundBuilder:     hrBuilderA, BoundChangeHeight: 105},
		set:         chainclient.BuilderSetSnapshot{BuilderSetVersion: 1, BuilderSetID: "7", SetHash: setHash, Builders: []string{hrBuilderA, hrBuilderB}},
		params:      chainclient.DispatchParamsSnapshot{Height: 150, RecordDeadlineBlocks: dpRecordDeadline},
		liability:   chainclient.WorkerLiabilityParamsSnapshot{Height: 150, MinTaskLiability: 10, OrderCoverageBps: 10_000},
		scopes:      map[string]chainclient.CommittedModelSupportScope{config.MinPriceBidKey(hrModelAB, 1): freshScope(hrModelAB, 1)},
		readHeights: map[uint64]int{}, calls: map[string]int{},
	}
}

func (f *fakeDispatchChain) with(fn func(*fakeDispatchChain)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// CommittedHeight is called once per offer evaluation; every other read must
// be pinned to the height it returned (Q18).
func (f *fakeDispatchChain) CommittedHeight(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heightCalls++
	return f.height, nil
}

// pinned records one height-pinned read; the caller holds f.mu.
func (f *fakeDispatchChain) pinned(height uint64) {
	f.readHeights[height]++
	pc, _, _, _ := runtime.Caller(1)
	name := runtime.FuncForPC(pc).Name()
	f.calls[name[strings.LastIndex(name, ".")+1:]]++
}

// callCount reports how often a read method ran.
func (f *fakeDispatchChain) callCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// reads returns the CommittedHeight calls and the heights reads were pinned to.
func (f *fakeDispatchChain) reads() (int, map[uint64]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heightCalls, maps.Clone(f.readHeights)
}

func (f *fakeDispatchChain) CortexNodeAt(_ context.Context, _ string, height uint64) (chainclient.CortexNodeSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.node, f.nodeErr
}

func (f *fakeDispatchChain) ServiceBondAt(_ context.Context, _ string, height uint64) (chainclient.ServiceBondSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.bond, f.bondErr
}

func (f *fakeDispatchChain) CurrentServiceKey(_ context.Context, participant, operator string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	if participant == chainclient.ParticipantTypeCortexNode {
		return f.cortexKey, nil
	}
	k, ok := f.builderKeys[operator]
	if !ok {
		return chainclient.ServiceKeySnapshot{}, chainclient.ErrNotFound
	}
	return k, nil
}

func (f *fakeDispatchChain) ModelSupportScopeAt(_ context.Context, _, modelID, version string, height uint64) (chainclient.CommittedModelSupportScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	if s, ok := f.scopes[modelID+"@"+version]; ok {
		return s, nil
	}
	return chainclient.CommittedModelSupportScope{}, fmt.Errorf("no support scope for %s@%s: %w", modelID, version, chainclient.ErrNotFound)
}

func (f *fakeDispatchChain) BuilderVrfKeyAt(_ context.Context, _ string, height uint64) (chainclient.VrfKeySnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.vrf, f.vrfErr
}

func (f *fakeDispatchChain) BuilderSetAt(_ context.Context, height uint64) (chainclient.BuilderSetSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.set, nil
}

func (f *fakeDispatchChain) DispatchEpochAt(_ context.Context, _, height uint64) (chainclient.DispatchEpochSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.epoch, nil
}

func (f *fakeDispatchChain) SessionAt(_ context.Context, _ []byte, height uint64) (chainclient.SessionSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.session, nil
}

func (f *fakeDispatchChain) DispatchParamsAt(_ context.Context, height uint64) (chainclient.DispatchParamsSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.params, nil
}

func (f *fakeDispatchChain) WorkerLiabilityParamsAt(_ context.Context, height uint64) (chainclient.WorkerLiabilityParamsSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinned(height)
	return f.liability, nil
}

func (f *fakeDispatchChain) DispatchRecord(context.Context, []byte, uint64) (chainclient.DispatchRecordSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordQueries++
	if f.recordErr != nil {
		return chainclient.DispatchRecordSnapshot{}, f.recordErr
	}
	if f.record.TaskID == nil {
		return chainclient.DispatchRecordSnapshot{}, chainclient.ErrNotFound
	}
	return f.record, nil
}

func (f *fakeDispatchChain) DispatchAssignment(context.Context, []byte) (chainclient.DispatchAssignmentSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.assignmentErr != nil {
		return chainclient.DispatchAssignmentSnapshot{}, f.assignmentErr
	}
	if f.assignment.TaskID == nil {
		return chainclient.DispatchAssignmentSnapshot{}, chainclient.ErrNotFound
	}
	return f.assignment, nil
}

type fakeDispatchHandraise struct {
	mu         sync.Mutex
	log        *dpLog
	current    map[string]CurrentHandraise
	roots      map[[32]byte]bool
	refreshErr error
	notified   int
}

func newFakeDispatchHandraise(log *dpLog, root [32]byte) *fakeDispatchHandraise {
	return &fakeDispatchHandraise{
		log:     log,
		current: map[string]CurrentHandraise{hrBuilderA: {IssuedHeight: 140, ExpiryHeight: 200, State: handraiseState{FreeSlots: 2}}},
		roots:   map[[32]byte]bool{root: true},
	}
}

func (h *fakeDispatchHandraise) Current(builder string) (CurrentHandraise, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.current[builder]
	return c, ok
}

func (h *fakeDispatchHandraise) HoldsRoot(_ context.Context, _ string, d [32]byte) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.roots[d], nil
}

func (h *fakeDispatchHandraise) Refresh(context.Context, string) error {
	h.mu.Lock()
	err := h.refreshErr
	h.mu.Unlock()
	h.log.add("handraise:refresh")
	return err
}

func (h *fakeDispatchHandraise) Notify() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notified++
}

func (h *fakeDispatchHandraise) notifications() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.notified
}

func (h *fakeDispatchHandraise) setFree(builder string, free uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.current[builder]
	c.State.FreeSlots = free
	h.current[builder] = c
}

func (h *fakeDispatchHandraise) setRefreshErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refreshErr = err
}

func (h *fakeDispatchHandraise) forget(builder string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.current, builder)
}

func (h *fakeDispatchHandraise) dropRoots() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.roots = map[[32]byte]bool{}
}

// fakeDispatchEnqueuer stands in for dispatchstream.Session: strict decode on
// enqueue, sequences from 1, and WasSent false only for marked sequences.
type fakeDispatchEnqueuer struct {
	mu     sync.Mutex
	log    *dpLog
	sent   []dispatchstream.Outgoing
	unsent map[uint64]bool
	fail   error
	// during runs after a successful enqueue, before Enqueue returns.
	during func()
}

func (q *fakeDispatchEnqueuer) Enqueue(_ context.Context, p dispatchstream.Outgoing) (uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fail != nil {
		return 0, q.fail
	}
	raw, err := dispatchwire.Raw(p.Message)
	if err != nil {
		return 0, err
	}
	name := dispatchwire.Name(p.Message)
	if err := dispatch.ValidateMessage(name, raw); err != nil {
		return 0, fmt.Errorf("%w: %w", dispatchstream.ErrInvalidOutgoing, err)
	}
	q.sent = append(q.sent, p)
	q.log.add("enqueue:" + name)
	if q.during != nil {
		q.during()
	}
	return uint64(len(q.sent)), nil
}

func (q *fakeDispatchEnqueuer) setDuring(fn func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.during = fn
}

func (q *fakeDispatchEnqueuer) WasSent(seq uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.unsent[seq]
}

func (q *fakeDispatchEnqueuer) markUnsent(seq uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.unsent[seq] = true
}

func (q *fakeDispatchEnqueuer) setFail(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.fail = err
}

func (q *fakeDispatchEnqueuer) messages() []proto.Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]proto.Message, 0, len(q.sent))
	for _, p := range q.sent {
		out = append(out, p.Message)
	}
	return out
}

func (q *fakeDispatchEnqueuer) outgoing(i int) dispatchstream.Outgoing {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sent[i]
}

type fakeInferStarter struct {
	mu                sync.Mutex
	started           []DispatchInferEntry
	stops             []layout.StoredHash // ticket hashes
	records           []recordedInfer
	startErr, stopErr error
}

type recordedInfer struct {
	taskHash, ticket              layout.StoredHash
	recordedHeight, inferDeadline uint64
}

func (f *fakeInferStarter) RecordDispatchedInfer(_ context.Context, taskHash, ticket layout.StoredHash, recordedHeight, inferDeadline uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, recordedInfer{taskHash, ticket, recordedHeight, inferDeadline})
	return nil
}

func (f *fakeInferStarter) recorded() []recordedInfer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.records)
}

func (f *fakeInferStarter) StartDispatchedInfer(_ context.Context, e DispatchInferEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.started = append(f.started, e)
	return nil
}

func (f *fakeInferStarter) StopDispatchedInfer(_ context.Context, _, ticket layout.StoredHash) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stops = append(f.stops, ticket)
	return nil
}

func (f *fakeInferStarter) setErrs(start, stop error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startErr, f.stopErr = start, stop
}

func (f *fakeInferStarter) starts() []DispatchInferEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.started)
}

func (f *fakeInferStarter) stopped(ticket layout.StoredHash) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.stops, ticket)
}

type dispatchHarness struct {
	t        *testing.T
	fx       *offerFixture
	chain    *fakeDispatchChain
	local    *fakeHandraiseLocal
	hr       *fakeDispatchHandraise
	a        *fakeDispatchEnqueuer
	infer    *fakeInferStarter
	log      *dpLog
	st       *store.Store
	ev       *evidence.Store
	leases   *DispatchLeases
	now      time.Time
	capacity uint32
	tweak    func(*DispatcherConfig)
	d        *Dispatcher

	signMu  sync.Mutex
	signErr error // every signature fails while set
	// signDuring, when set, runs with signCancel after a signature is made:
	// a test ends the caller's context there so the next store write fails.
	signDuring func(context.CancelFunc)
	signCancel context.CancelFunc
}

func (x *dispatchHarness) setSignErr(err error) {
	x.signMu.Lock()
	defer x.signMu.Unlock()
	x.signErr = err
}

func (x *dispatchHarness) sign(ctx context.Context, d [32]byte) ([]byte, error) {
	x.signMu.Lock()
	err := x.signErr
	x.signMu.Unlock()
	if err != nil {
		return nil, err
	}
	sig, err := hrSigner(hrCortexKey)(ctx, d)
	if x.signDuring != nil && x.signCancel != nil {
		x.signDuring(x.signCancel)
	}
	return sig, err
}

func newDispatchHarness(t *testing.T, capacity uint32, tweak func(*DispatcherConfig)) *dispatchHarness {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ev, err := evidence.NewStore(t.TempDir(), st)
	if err != nil {
		t.Fatal(err)
	}
	fx := newOfferFixture(t)
	log := &dpLog{}
	x := &dispatchHarness{
		t: t, fx: fx, chain: newFakeDispatchChain(t, fx), local: &fakeHandraiseLocal{ready: true, free: 9, freeOK: true},
		hr: newFakeDispatchHandraise(log, fx.root), a: &fakeDispatchEnqueuer{log: log, unsent: map[uint64]bool{}},
		infer: &fakeInferStarter{}, log: log, st: st, ev: ev, now: time.UnixMilli(10_000_000), capacity: capacity, tweak: tweak,
	}
	x.open()
	return x
}

// open builds the Dispatcher over the same store, as a restart would.
func (x *dispatchHarness) open() {
	x.t.Helper()
	leases, err := NewDispatchLeases(context.Background(), x.st, x.capacity)
	if err != nil {
		x.t.Fatal(err)
	}
	x.leases = leases
	cfg := DispatcherConfig{
		ChainID: dpChainID, Operator: hrCortex, FeeDenom: dpFeeDenom, Profiles: hrProfileRefs(), MinPriceBid: hrBids(),
		Chain: x.chain, Local: x.local, Handraise: x.hr, Leases: leases, Infer: x.infer, Inputs: x.ev,
		Sign: x.sign, Store: x.st, Builders: map[string]DispatchEnqueuer{hrBuilderA: x.a},
		Now: func() time.Time { return x.now },
	}
	if x.tweak != nil {
		x.tweak(&cfg)
	}
	d, err := NewDispatcher(context.Background(), cfg)
	if err != nil {
		x.t.Fatal(err)
	}
	x.d = d
}

func (x *dispatchHarness) reconfigure(tweak func(*DispatcherConfig)) {
	x.tweak = tweak
	x.open()
}

func (x *dispatchHarness) handle(ctx context.Context) error {
	return x.d.HandleOffer(ctx, hrBuilderA, x.fx.offer())
}

func (x *dispatchHarness) record(t *testing.T) layout.DispatchRecord {
	t.Helper()
	rec, err := layout.GetDispatchRecord(context.Background(), x.st, layout.StoredHash(x.fx.ticketHash()))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func cortexSigned(t *testing.T, m proto.Message, sig []byte) {
	t.Helper()
	d, err := dispatchwire.Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatch.VerifyDigestSignature(hrPub(t, hrCortexKey), d[:], sig); err != nil {
		t.Fatalf("%s signature: %v", dispatchwire.Name(m), err)
	}
}
