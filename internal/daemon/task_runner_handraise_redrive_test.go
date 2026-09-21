package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/policy"
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

// newRedriveFixture is the Verifier-side world of the devnet failure: a Builder
// whose OPEN_VERIFY arrives before the candidate window exists, and a chain
// whose height the test moves by hand.
func newRedriveFixture(t *testing.T) (*outputAvailableFixture, *movableChainStatus, *stepVerifierWindow) {
	t.Helper()
	fixture := newOutputAvailableFixture(t)
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
	return fixture, chain, window
}

// This is the measured devnet failure, reproduced.
//
// On trueopen-localnet-1 the Builder sent OPEN_VERIFY four times inside h0..h0+4;
// delta_w was 5, so the verifier candidate window turned READY at h0+5 with
// this node among its three members and stayed open until h0+12. Every frame
// therefore hit "not READY yet" and was dropped -- `trueopen.verify.open.*` is
// Core tier and has no redelivery -- and the eight open blocks went by with
// nobody asking again. Six tasks in a row produced zero handraises and were
// swept for want of verifiers.
//
// So the assertion is not about the refusal, which was already correct. It is
// that the node asks again on its own after the frame is gone, and that the
// handraise goes out from a poll tick with no new frame at all.
func TestOpenVerifyBeforeTheWindowStillRaisesItsHandOnceTheWindowOpens(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)

	for block := range 4 {
		err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())
		if err == nil || !builderclient.IsRetryable(err) {
			t.Fatalf("frame at h0+%d: error = %v, want a retryable wait", block, err)
		}
		chain.advance(1)
	}
	if len(fixture.builder.published) != 0 {
		t.Fatalf("published = %#v, want nothing while the draw does not exist", fixture.builder.published)
	}

	// The Beacon lands. No further frame arrives -- the Builder is done sending.
	window.becomeReady()
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	fixture.assertHandraised(t)

	// And the round is finished with. Neither a later tick nor a late frame
	// raises a second hand: two candidacies from one operator for one round are
	// two answers to one question.
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() after the handraise: %v", err)
	}
	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("a late frame after the re-driven handraise: %v", err)
	}
	if len(fixture.builder.published) != 1 {
		t.Fatalf("published = %d, want the one handraise", len(fixture.builder.published))
	}
}

// The re-drive is gated on the chain height, not on the poll interval. The state
// it is waiting for materializes at a block boundary, so a second query inside
// one height can only return what the first one did -- and a one-second poll
// interval against a five-second block would put five identical Keeper queries
// per block on every waiting task.
func TestVerifierHandraiseRedriveWaitsForTheNextBlockBeforeAskingAgain(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
		t.Fatal("OpenVerify was admitted, want a wait")
	}
	if window.queries() != 1 {
		t.Fatalf("window queries after the frame = %d, want 1", window.queries())
	}
	for range 3 {
		if err := fixture.runner.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce() error = %v", err)
		}
	}
	if window.queries() != 1 {
		t.Fatalf("window queries at an unchanged height = %d, want the one from the frame", window.queries())
	}

	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if window.queries() != 2 {
		t.Fatalf("window queries after the height moved = %d, want 2", window.queries())
	}
}

// A closed window is the end of the round, and the node has to be able to tell
// that from the wait it was in a moment earlier. Keeper does not prune a READY
// window at its close height -- it keeps answering READY -- so "may I still
// raise a hand" is answered by handraise_close_height alone, and past it no
// amount of asking helps.
func TestVerifierHandraiseRedriveStopsWhenTheWindowCloses(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)
	var diagnostics []TaskRunnerDiagnostic
	fixture.runner.cfg.Diagnostic = func(diagnostic TaskRunnerDiagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
		t.Fatal("OpenVerify was admitted, want a wait")
	}
	window.close()
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	requireTraceFields(t, fixture.trace.event(t, "verifier_window_closed"),
		`task="`+fixture.taskID+`"`, "verify_round=1", "waits=1", "current_height=11")
	requireTraceLevel(t, fixture.trace, "verifier_window_closed", slog.LevelError)
	if len(fixture.builder.published) != 0 {
		t.Fatalf("published = %#v, want nothing after the window closed", fixture.builder.published)
	}

	// Nothing is owed any more: the round is not re-driven at the next height.
	before := window.queries()
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() after the close: %v", err)
	}
	if window.queries() != before {
		t.Fatalf("window queries = %d, want no query for a closed round (was %d)", window.queries(), before)
	}
	if len(diagnostics) == 0 {
		t.Fatal("the closed window was never reported")
	}
	last := diagnostics[len(diagnostics)-1]
	if !strings.Contains(last.Error, "closed before this node raised a hand") || last.Waiting {
		t.Fatalf("diagnostic = %#v, want a closed-window refusal that is not a wait", last)
	}
}

// A window that never materializes must not be waited on forever. The heights
// that would bound it -- h_window and h_handraise_close -- are exactly what an
// unmaterialized window does not publish, so the bound is the deployment's own
// verify deadline delta, the same span the handraise expiry falls back to when
// the window cannot be read at all.
func TestVerifierHandraiseRedriveIsAbandonedAtTheVerifyDeadlineBound(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)
	fixture.runner.cfg.VerifyDeadlineDeltaHeight = 30
	var diagnostics []TaskRunnerDiagnostic
	fixture.runner.cfg.Diagnostic = func(diagnostic TaskRunnerDiagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
		t.Fatal("OpenVerify was admitted, want a wait")
	}
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if window.queries() != 2 {
		t.Fatalf("window queries inside the bound = %d, want 2", window.queries())
	}

	// h0 was 10 and the bound is h0+30, so this height is past it.
	chain.set(41)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	requireTraceFields(t, fixture.trace.event(t, "verifier_handraise_abandoned"),
		`task="`+fixture.taskID+`"`, "verify_round=1", "attempts=2", "first_height=10", "current_height=41",
		"verify deadline bound height 40 passed at chain height 41")
	requireTraceLevel(t, fixture.trace, "verifier_handraise_abandoned", slog.LevelError)
	if window.queries() != 2 {
		t.Fatalf("window queries = %d, want the round abandoned without another query", window.queries())
	}
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() after the bound: %v", err)
	}
	if window.queries() != 2 {
		t.Fatalf("window queries = %d, want an abandoned round to stay abandoned", window.queries())
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[len(diagnostics)-1].Error, "Verifier handraise abandoned") {
		t.Fatalf("diagnostics = %#v, want the abandonment reported", diagnostics)
	}
}

// The OUTPUT_AVAILABLE hint arrives on a JetStream subject, which redelivers it
// (inboxWillRedeliver). Arming the local re-drive for it as well would run two
// attempts at one task-round from two schedulers, and the at-most-once claim
// does not suppress a duplicate until the first attempt has completed it.
func TestOutputAvailableHintIsNotRedrivenBecauseItsTransportRedeliversIt(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)

	if err := fixture.deliver(t, fixture.fullHint()); err == nil {
		t.Fatal("the hint was admitted, want a wait")
	}
	if window.queries() != 1 {
		t.Fatalf("window queries after the hint = %d, want 1", window.queries())
	}
	window.becomeReady()
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if window.queries() != 1 || len(fixture.builder.published) != 0 {
		t.Fatalf("queries = %d published = %d, want the hint left to its own transport",
			window.queries(), len(fixture.builder.published))
	}
}

// Only a retryable refusal is owed another attempt. A frame contradicting the
// Keeper snapshot is not a wait at any height, and re-driving it would mean
// re-deciding a question the chain has already answered - on a schedule, with no
// frame in sight.
func TestVerifierHandraiseRedriveIgnoresAFrameTheChainContradicts(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)
	forged := fixture.openVerifyCall()
	other := codec.HashBytes([]byte("some other receipt"))
	forged.InferReceiptHash = append([]byte(nil), other[:]...)

	if err := fixture.deliverOpenVerify(t, forged); err == nil {
		t.Fatal("an OpenVerify naming a receipt Keeper does not hold was accepted")
	}
	window.becomeReady()
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if window.queries() != 0 || len(fixture.builder.published) != 0 {
		t.Fatalf("queries = %d published = %d, want a contradicted frame dropped for good",
			window.queries(), len(fixture.builder.published))
	}
}

// A precheck rejection is retryable on purpose - its reasons (slots, support
// freshness, distance to the deadline) move with the height - and on a Core
// subject that promise had no keeper either. The re-drive is what makes it true.
func TestVerifierHandraiseRedriveRetriesAPrecheckRejection(t *testing.T) {
	fixture, chain, window := newRedriveFixture(t)
	window.becomeReady()
	fixture.runner.cfg.HandraiseEligibility = staticEligibility{verifierInput: policy.VerifierPrecheckInput{
		ChainSynced: true, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 0, SupportFreshnessWindow: 20,
		SupportedProfiles: []string{modelservice.CapabilityLLMTextV1}, AvailableSlots: 0,
	}}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
		t.Fatal("OpenVerify was admitted with no free slot, want the precheck rejection")
	}
	if len(fixture.builder.published) != 0 {
		t.Fatalf("published = %#v, want nothing from a rejected precheck", fixture.builder.published)
	}
	requireTraceLevel(t, fixture.trace, "verifier_handraise", slog.LevelError)

	// A slot frees up. Nothing redelivers the call, so the poll tick is the only
	// thing that can notice.
	fixture.runner.cfg.HandraiseEligibility = staticEligibility{verifierInput: policy.VerifierPrecheckInput{
		ChainSynced: true, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 0, SupportFreshnessWindow: 20,
		SupportedProfiles: []string{modelservice.CapabilityLLMTextV1}, AvailableSlots: 1,
	}}
	chain.advance(1)
	if err := fixture.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	fixture.assertHandraised(t)
}
