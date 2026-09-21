package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
)

// pendingVerifierWindow is the chain between h0 and the Beacon at h_window: the
// window row exists, its members do not yet.
type pendingVerifierWindow struct{ calls int }

func (p *pendingVerifierWindow) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	p.calls++
	return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: status=1", chainclient.ErrVerifierWindowNotReady)
}

// A window with no members yet is not READY for either reading, so the
// frozen-set read answers the same way.
func (p *pendingVerifierWindow) FrozenVerifierWindowMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	p.calls++
	return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("%w: status=1", chainclient.ErrVerifierWindowNotReady)
}

// A Builder may broadcast OPEN_VERIFY as soon as it holds the data
// (04-task-execution-verification-and-settlement.md:285), and the verifier candidate window turns READY only
// after the Beacon at h_window lands, so a candidate that reaches the window
// query early is the normal protocol timeline and its instruction is to wait
// (interface-and-topic-list.md §5.9).
//
// Cortex already waited -- the refusal is retryable and the frame is
// redelivered -- but it said so on the same `task runner failure` line every
// real fault uses, and reading it took a trip through the Keeper contract to
// find out nothing was wrong. The wait now has its own milestone and its own
// diagnostic, so a stalled window is legible as a stalled window.
func TestVerifierWindowStillFrozenIsTracedAsAWaitNotAFailure(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	window := &pendingVerifierWindow{}
	fixture.runner.cfg.VerifierMemberReader = window
	var diagnostics []TaskRunnerDiagnostic
	fixture.runner.cfg.Diagnostic = func(diagnostic TaskRunnerDiagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}

	err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("OpenVerify error = %v, want a retryable wait", err)
	}
	// Waiting is not handraising: nothing is signed or published while the draw
	// this node would be joining does not exist.
	if len(fixture.builder.published) != 0 {
		t.Fatalf("published = %#v, want nothing before the window is READY", fixture.builder.published)
	}
	requireTraceFields(t, fixture.trace.event(t, "verifier_window_pending"),
		`task="`+fixture.taskID+`"`, "verify_round=1", "waits=1", "current_height=10")
	requireTraceLevel(t, fixture.trace, "verifier_window_pending", slog.LevelInfo)
	if len(diagnostics) != 1 || !diagnostics[0].Waiting {
		t.Fatalf("diagnostics = %#v, want exactly one marked as a wait", diagnostics)
	}
	// The word an operator greps for is not "failure", and the chain's own
	// explanation is still in the line.
	if !strings.Contains(diagnostics[0].Error, "verifier candidate window is not READY yet") {
		t.Fatalf("diagnostic error = %q, want the Keeper's own reason", diagnostics[0].Error)
	}
}

// The count is what makes the line worth reading twice: one wait is the
// protocol, forty is a Beacon that never landed.
//
// It counts blocks, not frames. Every source that drives one task-round is
// gated to one attempt per block (repeatedHandraiseBlockWait), so a rising
// count is a rising number of blocks the Beacon has been missing for -- which
// is the quantity that distinguishes the two, and which a redelivery rate that
// depends on JetStream backoff never was.
func TestVerifierWindowWaitCountsTheBlocksItHasBeenWaiting(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	fixture.runner.cfg.VerifierMemberReader = &pendingVerifierWindow{}
	height := &movingChainStatus{height: 10, chainID: "chain"}
	fixture.runner.cfg.ChainStatus = height

	for attempt := 1; attempt <= 3; attempt++ {
		if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
			t.Fatalf("attempt %d was admitted, want a wait", attempt)
		}
		height.advance()
	}
	var waits []string
	for _, line := range fixture.trace.lines {
		if strings.HasPrefix(line, "task trace event=verifier_window_pending ") {
			waits = append(waits, line)
		}
	}
	if len(waits) != 3 {
		t.Fatalf("verifier_window_pending lines = %d, want one per block:\n%s", len(waits), strings.Join(fixture.trace.lines, "\n"))
	}
	for index, line := range waits {
		requireTraceFields(t, line, fmt.Sprintf("waits=%d", index+1))
	}
}

// A window query that fails for any other reason keeps the failure wording: the
// wait is one named chain state, not a blanket for everything this query can
// answer.
func TestVerifierWindowQueryFailureIsStillReportedAsAFailure(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	fixture.runner.cfg.VerifierMemberReader = brokenVerifierWindow{}
	var diagnostics []TaskRunnerDiagnostic
	fixture.runner.cfg.Diagnostic = func(diagnostic TaskRunnerDiagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
		t.Fatal("OpenVerify was admitted, want the query failure surfaced")
	}
	if len(diagnostics) != 1 || diagnostics[0].Waiting {
		t.Fatalf("diagnostics = %#v, want exactly one ordinary failure", diagnostics)
	}
	for _, line := range fixture.trace.lines {
		if strings.HasPrefix(line, "task trace event=verifier_window_pending ") {
			t.Fatalf("a query failure was traced as a wait:\n%s", line)
		}
	}
}

type brokenVerifierWindow struct{}

func (brokenVerifierWindow) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("dial tcp: connection refused")
}

func (brokenVerifierWindow) FrozenVerifierWindowMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf("dial tcp: connection refused")
}
