package daemon

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
)

// The state a waiting handraise is waiting for -- the verifier candidate window
// turning READY -- materializes at a block boundary, so every extra attempt
// inside one block re-asks a question whose answer cannot have changed. The
// re-drive has had that gate since it was written
// (takeVerifierHandraiseRedrives); the inbound path had none, and three
// independent sources drive the same task-round: OPEN_VERIFY is re-broadcast by
// the Builder, the OUTPUT_AVAILABLE hint is NAKed and redelivered by JetStream
// about once a second, and the re-drive fires on the poll interval. Measured on
// trueopen-localnet-1: 28 verifier_window_pending lines and 29 Keeper receipt
// queries across five blocks of one task.
func TestVerifierHandraiseAsksTheChainOncePerBlockForOneTaskRound(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	window := &pendingVerifierWindow{}
	fixture.runner.cfg.VerifierMemberReader = window
	reader := &countingKeeperTaskReader{inner: fixture.runner.cfg.TaskReader}
	fixture.runner.cfg.TaskReader = reader

	for attempt := 1; attempt <= 3; attempt++ {
		err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())
		if err == nil || !builderclient.IsRetryable(err) {
			t.Fatalf("attempt %d error = %v, want the same retryable wait every time", attempt, err)
		}
	}
	if got := reader.calls.Load(); got != 1 {
		t.Fatalf("Keeper task queries = %d, want 1 for three frames inside one block", got)
	}
	if window.calls != 1 {
		t.Fatalf("verifier candidate window queries = %d, want 1 for three frames inside one block", window.calls)
	}
	if got := countTraceEvents(fixture, "verifier_window_pending"); got != 1 {
		t.Fatalf("verifier_window_pending lines = %d, want one per block:\n%s", got, strings.Join(fixture.trace.lines, "\n"))
	}
}

// The operator-facing half of the same gate. A suppressed attempt reports
// nothing: the line it would print is the line the first frame of this block
// already printed, and repeating it once per JetStream redelivery is what made
// a five-block wait look like a node in trouble.
func TestVerifierHandraiseReportsOneWaitPerBlock(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	fixture.runner.cfg.VerifierMemberReader = &pendingVerifierWindow{}
	var diagnostics []TaskRunnerDiagnostic
	fixture.runner.cfg.Diagnostic = func(diagnostic TaskRunnerDiagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
			t.Fatalf("attempt %d was admitted, want a wait", attempt)
		}
	}
	if len(diagnostics) != 1 || !diagnostics[0].Waiting {
		t.Fatalf("diagnostics = %#v, want exactly one wait reported for three frames in one block", diagnostics)
	}
}

// The gate is per block, not per task-round: the next block is exactly when the
// window can have turned READY, so the work is redone there. Without this the
// suppression would be indistinguishable from dropping the wait.
func TestVerifierHandraiseRetriesOnTheNextBlock(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	fixture.runner.cfg.VerifierMemberReader = &pendingVerifierWindow{}
	height := &movingChainStatus{height: 10, chainID: "chain"}
	fixture.runner.cfg.ChainStatus = height
	reader := &countingKeeperTaskReader{inner: fixture.runner.cfg.TaskReader}
	fixture.runner.cfg.TaskReader = reader

	for attempt := 1; attempt <= 3; attempt++ {
		if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
			t.Fatalf("attempt %d was admitted, want a wait", attempt)
		}
		height.advance()
	}
	if got := reader.calls.Load(); got != 3 {
		t.Fatalf("Keeper task queries = %d, want one per block", got)
	}
	if got := countTraceEvents(fixture, "verifier_window_pending"); got != 3 {
		t.Fatalf("verifier_window_pending lines = %d, want one per block:\n%s", got, strings.Join(fixture.trace.lines, "\n"))
	}
}

// Suppressing the work must not suppress the arming. OPEN_VERIFY is the one
// trigger with no transport behind it, so it is the one that arms the local
// re-drive -- and it frequently is not the first frame of its block, because
// the JetStream hint for the same task-round arrives on its own schedule. A
// gate that skipped the re-drive bookkeeping on a suppressed attempt would
// trade a redundant Keeper query for the lost handraise PR #335 exists to
// prevent.
func TestVerifierHandraiseArmsTheRedriveEvenWhenTheBlockIsAlreadyAnswered(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	fixture.runner.cfg.VerifierMemberReader = &pendingVerifierWindow{}

	if err := fixture.deliver(t, fixture.fullHint()); err == nil {
		t.Fatal("the hint was admitted, want a wait")
	}
	if len(fixture.runner.handraiseRedrives) != 0 {
		t.Fatalf("re-drives = %#v, want none armed by the JetStream hint", fixture.runner.handraiseRedrives)
	}
	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err == nil {
		t.Fatal("the call was admitted, want a wait")
	}
	pending, ok := fixture.runner.handraiseRedrives[chainWaitKey(fixture.taskID, 1)]
	if !ok || pending.trigger.Kind != "OpenVerify" {
		t.Fatalf("re-drives = %#v, want the suppressed OPEN_VERIFY still armed", fixture.runner.handraiseRedrives)
	}
}

func countTraceEvents(fixture *outputAvailableFixture, event string) int {
	count := 0
	for _, line := range fixture.trace.lines {
		if strings.HasPrefix(line, "task trace event="+event+" ") {
			count++
		}
	}
	return count
}

type countingKeeperTaskReader struct {
	inner KeeperTaskReader
	calls atomic.Int64
}

func (r *countingKeeperTaskReader) Task(ctx context.Context, sessionID, taskID string) (chainclient.TaskSnapshot, error) {
	r.calls.Add(1)
	return r.inner.Task(ctx, sessionID, taskID)
}

type movingChainStatus struct {
	height  uint64
	chainID string
}

func (s *movingChainStatus) ChainStatus(context.Context) (uint64, string, error) {
	return s.height, s.chainID, nil
}

func (s *movingChainStatus) advance() { s.height++ }
