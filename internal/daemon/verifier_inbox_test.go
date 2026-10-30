package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/policy"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// movableChainStatus is a chain whose height advances between polls, which is
// the whole subject here: the state a Verifier candidate waits for appears at a
// block boundary, so a test that cannot move the height cannot tell "asked
// again" from "asked again for the first time".
type movableChainStatus struct {
	mu      sync.Mutex
	height  uint64
	chainID string
}

func (s *movableChainStatus) ChainStatus(context.Context) (uint64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.height, s.chainID, nil
}

func (s *movableChainStatus) advance(blocks uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.height += blocks
}

func (s *movableChainStatus) set(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.height = height
}

// stepVerifierWindow is the verifier candidate window over its whole life: the
// header exists but has no members (SOURCE_FROZEN), then the Beacon lands and it
// is READY with this node in it, then its handraise interval closes.
type stepVerifierWindow struct {
	mu             sync.Mutex
	calls          int
	ready, closed  bool
	receiptHash    codec.Hash
	expiryHeight   uint64
	memberOperator string
}

func (w *stepVerifierWindow) VerifierCandidateMember(ctx context.Context, taskID string, round uint32, operator string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return w.read(ctx, taskID, round, operator, true)
}

// FrozenVerifierWindowMember mirrors the real client: a closed interval is not a
// refusal here, because the frozen member row outlives it.
func (w *stepVerifierWindow) FrozenVerifierWindowMember(ctx context.Context, taskID string, round uint32, operator string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return w.read(ctx, taskID, round, operator, false)
}

func (w *stepVerifierWindow) read(_ context.Context, _ string, round uint32, operator string, requireOpenHandraise bool) (chainclient.VerifierCandidateMemberSnapshot, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	switch {
	case requireOpenHandraise && w.closed:
		return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf(
			"%w: handraise_close_height=%d committed_height=%d", chainclient.ErrVerifierWindowClosed, w.expiryHeight, w.expiryHeight+1)
	case !w.ready:
		return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: status=1", chainclient.ErrVerifierWindowNotReady)
	}
	member := w.memberOperator
	if member == "" {
		member = operator
	}
	snapshotID := codec.HashBytes([]byte("candidate-pool-snapshot"))
	return chainclient.VerifierCandidateMemberSnapshot{
		CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
			CandidatePoolSnapshotID: chainclient.ProtoBytes32(snapshotID[:]),
			Slot:                    3, SlotVersion: uint64(round), OperatorAddress: member,
		},
		InferReceiptHash: chainclient.ProtoBytes32(w.receiptHash[:]),
		ExpiryHeight:     w.expiryHeight,
	}, nil
}

func (w *stepVerifierWindow) queries() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func (w *stepVerifierWindow) becomeReady() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ready = true
}

func (w *stepVerifierWindow) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

// newInboxFixture is the Verifier-side world of the devnet failure: a Builder
// whose OPEN_VERIFY arrives on the stream before the candidate window exists,
// and a chain whose height the test moves by hand.
func newInboxFixture(t *testing.T) (*openVerifyFixture, *movableChainStatus, *stepVerifierWindow, *VerifierStream) {
	t.Helper()
	fixture := newOpenVerifyFixture(t)
	chain := &movableChainStatus{height: 10, chainID: "chain"}
	fixture.runner.cfg.ChainStatus = chain
	window := &stepVerifierWindow{
		receiptHash:  codec.Hash(fixture.snapshot.InferReceipt.InferReceiptHash),
		expiryHeight: 22,
		// The signed member reference carries a real Bech32 operator address:
		// the frozen VerifierHandraise wire refuses anything else.
		memberOperator: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
	}
	fixture.runner.cfg.VerifierMemberReader = window
	stream, err := NewVerifierStream(VerifierStreamConfig{
		ChainID: "chain", Chain: newStubBuilderKeys("builder-1"), Store: fixture.runner.cfg.Store,
		Assignment: fixture.runner.recordVerifierAssignment, Wake: fixture.runner.Wake,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, chain, window, stream
}

func (f *openVerifyFixture) streamOpenVerify(t *testing.T, stream *VerifierStream, mutate func(*nexusv1.OpenVerifyV1)) {
	t.Helper()
	m := f.openVerifyCall()
	m.Binding = &nexusv1.BuilderMessageBindingV1{ChainId: "chain", BuilderAddress: "builder-1", ServiceAuthorizationNonce: 1}
	if mutate != nil {
		mutate(m)
	}
	if err := stream.HandleFrame(context.Background(), "builder-1", openVerifyFrame(m)); err != nil {
		t.Fatalf("OPEN_VERIFY was not recorded and acked: %v", err)
	}
}

func inboxEntry(t *testing.T, f *openVerifyFixture) verifierInboxEntry {
	t.Helper()
	entry, ok, err := (verifierInbox{st: f.runner.cfg.Store}).load(context.Background(), f.taskID, 1)
	if err != nil || !ok {
		t.Fatalf("inbox entry = %v, %v", ok, err)
	}
	return entry
}

// The measured devnet failure (OPEN_VERIFY before the window is READY), now
// from the stream. On trueopen-localnet-1 the Builder sent OPEN_VERIFY four
// times inside h0..h0+4, the window turned READY at h0+5, and nothing asked
// again. The inbox holds the call and the poll loop answers it once the
// window opens, with no new frame.
func TestStreamedOpenVerifyBeforeTheWindowRaisesItsHandFromTheInbox(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	for range 4 {
		fixture.streamOpenVerify(t, stream, nil)
		if err := fixture.runner.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		chain.advance(1)
	}
	if len(fixture.sender.handraises) != 0 {
		t.Fatalf("published = %d, want nothing while the window is not READY", len(fixture.sender.handraises))
	}
	window.becomeReady()
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.assertHandraised(t)
	if entry := inboxEntry(t, fixture); entry.State != inboxDone {
		t.Fatalf("entry = %+v, want done", entry)
	}
	chain.advance(1)
	fixture.streamOpenVerify(t, stream, nil)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fixture.sender.handraises) != 1 {
		t.Fatalf("published = %d, want one handraise per round", len(fixture.sender.handraises))
	}
}

// The inbox is gated on the chain height, not on the poll interval: the window
// materializes at a block boundary.
func TestInboxAsksTheChainOncePerBlock(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	fixture.streamOpenVerify(t, stream, nil)
	if window.queries() != 0 {
		t.Fatal("the stream handler read the chain window; only the poll loop may")
	}
	for range 3 {
		if err := fixture.runner.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if window.queries() != 1 {
		t.Fatalf("window queries in one block = %d, want 1", window.queries())
	}
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if window.queries() != 2 {
		t.Fatalf("window queries after one block = %d, want 2", window.queries())
	}
}

func TestInboxAbandonsTheRoundAtTheGiveUpBound(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	var diagnostics []TaskRunnerDiagnostic
	fixture.runner.cfg.Diagnostic = func(d TaskRunnerDiagnostic) { diagnostics = append(diagnostics, d) }
	fixture.streamOpenVerify(t, stream, nil)
	if err := fixture.runner.RunOnce(ctx); err != nil { // first attempt at h=10: bound 10+40
		t.Fatal(err)
	}
	chain.set(51)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	asked := window.queries()
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if window.queries() != asked {
		t.Fatal("an abandoned round was asked again")
	}
	if got := countTraceEvents(fixture, "verifier_handraise_abandoned"); got != 1 {
		t.Fatalf("verifier_handraise_abandoned lines = %d, want 1", got)
	}
	requireTraceFields(t, fixture.trace.event(t, "verifier_handraise_abandoned"),
		`task="`+fixture.taskID+`"`, "verify_round=1", "attempts=1", "first_height=10", "current_height=51",
		"verify deadline bound height 50 passed at chain height 51")
	requireTraceLevel(t, fixture.trace, "verifier_handraise_abandoned", slog.LevelError)
	if entry := inboxEntry(t, fixture); entry.State != inboxAbandoned {
		t.Fatalf("entry = %+v, want abandoned", entry)
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[len(diagnostics)-1].Error, "Verifier handraise abandoned") {
		t.Fatalf("diagnostics = %#v, want the abandonment reported", diagnostics)
	}
}

// The inbox is durable: a restart inside the window still raises the hand.
func TestInboxSurvivesARestart(t *testing.T) {
	fixture, _, window, stream := newInboxFixture(t)
	fixture.streamOpenVerify(t, stream, nil)
	restarted := NewTaskRunner(fixture.runner.cfg)
	window.becomeReady()
	if err := restarted.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.assertHandraised(t)
}

// Only a retryable refusal keeps the round owed: a call the Keeper contradicts
// is refused once and never asked again.
func TestInboxRefusalIsFinal(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	window.becomeReady()
	fixture.streamOpenVerify(t, stream, func(m *nexusv1.OpenVerifyV1) { m.WorkerOperatorAddress = "worker-2" })
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	entry := inboxEntry(t, fixture)
	if entry.State != inboxRefused || entry.Attempts != 1 || !strings.Contains(entry.LastError, "Keeper winner") {
		t.Fatalf("entry = %+v, want one attempt refused by the Keeper winner check", entry)
	}
	if len(fixture.sender.handraises) != 0 || window.queries() != 0 {
		t.Fatal("a refused call reached the window or the sender")
	}
}

// A closed window is the end of the round: a Permanent refusal, never asked again.
func TestInboxStopsWhenTheWindowCloses(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	fixture.streamOpenVerify(t, stream, nil)
	window.close()
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	requireTraceLevel(t, fixture.trace, "verifier_window_closed", slog.LevelError)
	before := window.queries()
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if window.queries() != before || len(fixture.sender.handraises) != 0 {
		t.Fatalf("queries %d (was %d), published %d: a closed round was asked again", window.queries(), before, len(fixture.sender.handraises))
	}
	if entry := inboxEntry(t, fixture); entry.State != inboxRefused {
		t.Fatalf("entry = %+v, want refused", entry)
	}
}

// A precheck rejection is retryable on purpose (slots, support freshness and
// distance to the deadline move with the height); the inbox makes it true.
func TestInboxRetriesAPrecheckRejection(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	window.becomeReady()
	precheck := func(slots int) staticEligibility {
		return staticEligibility{verifierInput: policy.VerifierPrecheckInput{
			ChainSynced: true, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 0, SupportFreshnessWindow: 20,
			SupportedProfiles: []string{modelservice.CapabilityLLMTextV1}, AvailableSlots: slots,
		}}
	}
	fixture.runner.cfg.HandraiseEligibility = precheck(0)
	fixture.streamOpenVerify(t, stream, nil)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fixture.sender.handraises) != 0 {
		t.Fatal("published from a rejected precheck")
	}
	fixture.runner.cfg.HandraiseEligibility = precheck(1)
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.assertHandraised(t)
}

// Settled entries keep absorbing late duplicates for one span past their
// bound, then are pruned.
func TestInboxPrunesSettledEntries(t *testing.T) {
	fixture, chain, window, stream := newInboxFixture(t)
	ctx := context.Background()
	window.becomeReady()
	fixture.streamOpenVerify(t, stream, nil)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.assertHandraised(t)
	chain.set(10 + 40 + 40)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := (verifierInbox{st: fixture.runner.cfg.Store}).load(ctx, fixture.taskID, 1); !ok {
		t.Fatal("a settled entry was pruned inside its retention span")
	}
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := (verifierInbox{st: fixture.runner.cfg.Store}).load(ctx, fixture.taskID, 1); ok {
		t.Fatal("a settled entry outlived its retention span")
	}
}

// M1: a refusal belongs to the content that earned it. A different Builder
// delivering different (correct) content re-opens the round; the same content
// from another Builder does not.
func TestInboxRefusalReopensForDifferentContentFromAnotherBuilder(t *testing.T) {
	fixture, chain, window, _ := newInboxFixture(t)
	ctx := context.Background()
	stream, err := NewVerifierStream(VerifierStreamConfig{
		ChainID: "chain", Chain: newStubBuilderKeys("builder-1", "builder-2", "builder-3"), Store: fixture.runner.cfg.Store,
		Assignment: fixture.runner.recordVerifierAssignment, Wake: fixture.runner.Wake,
	})
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(builder string, mutate func(*nexusv1.OpenVerifyV1)) {
		t.Helper()
		m := fixture.openVerifyCall()
		m.Binding = &nexusv1.BuilderMessageBindingV1{ChainId: "chain", BuilderAddress: builder, ServiceAuthorizationNonce: 1}
		if mutate != nil {
			mutate(m)
		}
		if err := stream.HandleFrame(ctx, builder, openVerifyFrame(m)); err != nil {
			t.Fatal(err)
		}
	}
	window.becomeReady()
	forged := func(m *nexusv1.OpenVerifyV1) { m.WorkerOperatorAddress = "worker-2" }
	deliver("builder-1", forged)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	deliver("builder-3", forged)
	if entry := inboxEntry(t, fixture); entry.State != inboxRefused {
		t.Fatalf("the same refused content from another Builder re-opened the round: %+v", entry)
	}
	deliver("builder-2", nil)
	if entry := inboxEntry(t, fixture); entry.State != inboxPending || entry.Trigger.Worker != "worker-1" {
		t.Fatalf("entry = %+v, want the round pending on builder-2's content", entry)
	}
	chain.advance(1)
	if err := fixture.runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.assertHandraised(t)
}

// M2: a round settled while the tip was unreadable has no bound yet; it is
// kept one span from the first readable tip rather than pruned at once.
func TestInboxKeepsAnUnboundedSettledEntryForOneSpan(t *testing.T) {
	ctx := context.Background()
	inbox := verifierInbox{st: vsStore(t), span: 40}
	trigger := verifierHandraiseTrigger{Kind: "OpenVerify", TaskID: vsTaskID, VerifyRound: 1}
	if _, err := inbox.admit(ctx, "builder-1", trigger); err != nil {
		t.Fatal(err)
	}
	if err := inbox.settle(ctx, trigger, chainTip{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		height uint64
		kept   bool
	}{{100, true}, {140, true}, {141, false}} {
		if err := inbox.prune(ctx, chainTip{height: step.height, readable: true}); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := inbox.load(ctx, vsTaskID, 1); ok != step.kept {
			t.Fatalf("at height %d kept = %v, want %v", step.height, ok, step.kept)
		}
	}
}
