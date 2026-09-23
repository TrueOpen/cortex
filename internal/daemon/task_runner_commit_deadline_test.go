package daemon

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// A verify responsibility is only worth running while its commit can still be
// accepted. The runner used to charge the whole thing against verify_deadline,
// which on a real chain sits ~700 blocks after commit_deadline: a Verifier that
// could not fetch the output kept re-running the full confirm-and-verify path
// every RetryDelay for the rest of the verify window, long after any commit it
// produced would have been refused. The verifier's own precheck already treats
// the commit window as a precondition of that entire path
// (policy.EvaluateVerifierPrecheck COMMIT_WINDOW_UNSAFE_FOR_BEACON_DELAY), but
// it judges it against the height frozen into the responsibility at admission,
// so it never fires on a retry. This is that judgment made against the live
// tip.
func TestVerifyResponsibilityStopsOnceTheCommitDeadlinePassed(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	hash := codec.HashBytes([]byte("commit-deadline-task"))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: "task-commit-deadline", SessionID: "session", OrderSequence: 1,
		VerifyRound: 1, OpenVerifyHeight: 313,
		CommitDeadlineHeight: 633, RevealDeadlineHeight: 900, DeadlineHeight: 1033,
		Stage: "queued",
	})

	var ran int
	var diagnostics []TaskRunnerDiagnostic
	trace := &collectTrace{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, MaxRetryAttempts: 120,
		// Past commit_deadline_height 633 and well inside verify_deadline 1033 --
		// exactly the window the devnet node spent retrying.
		ChainStatus: fixedChainStatus{height: 654},
		Trace:       trace.trace(),
		Diagnostic:  func(d TaskRunnerDiagnostic) { diagnostics = append(diagnostics, d) },
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 0 {
		t.Fatalf("verify executor ran %d times, want 0: the commit window closed at 633 and the tip is 654", ran)
	}
	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Stage != layout.StageFailed {
		t.Fatalf("stage = %q, want failed", rec.Stage)
	}
	// LastError is the only record an operator gets for a responsibility that
	// stopped without running, so it must name the deadline that stopped it --
	// and name it as the commit deadline, not as "the" deadline, because the
	// verify deadline is still open and an operator reading 1033 would look for
	// a different fault.
	if !strings.Contains(rec.LastError, "commit deadline height 633") {
		t.Fatalf("last error = %q, want the commit deadline named", rec.LastError)
	}
	if !strings.Contains(rec.LastError, "654") {
		t.Fatalf("last error = %q, want the observed chain height named", rec.LastError)
	}
	// A responsibility that stops without running has to say so on the wire,
	// not only in Pebble. The retries an operator was watching simply end, and
	// silence after the last one reads as a hung node rather than a closed
	// window.
	if len(diagnostics) != 1 || diagnostics[0].Source != "verify" ||
		!strings.Contains(diagnostics[0].Error, "commit deadline height 633") {
		t.Fatalf("diagnostics = %#v, want one verify stop naming the commit deadline", diagnostics)
	}
	line := trace.event(t, "responsibility_stopped")
	requireTraceLevel(t, trace, "responsibility_stopped", slog.LevelError)
	for _, want := range []string{
		`role="verify"`, `deadline="commit deadline"`, "deadline_height=633", "chain_height=654",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("responsibility_stopped = %q, want it to carry %s", line, want)
		}
	}
	// Letting the commit deadline pass without a commit is exactly the state
	// 02-data-plane-and-evidence-transfer.md §5 answers with MsgReportDataUnavailable, and Cortex
	// cannot produce one -- the bitmap order it needs has no read on the frozen
	// Query service. Saying nothing here is how that stayed a source comment for
	// as long as it did, so the debt is stated where the window closes.
	if !strings.Contains(rec.LastError, "MsgReportDataUnavailable") {
		t.Fatalf("last error = %q, want the unpaid V7b remedy named", rec.LastError)
	}
	if !strings.Contains(rec.LastError, "selected_task_builders") {
		t.Fatalf("last error = %q, want the missing chain read named", rec.LastError)
	}
}

// The V7b note belongs to the commit deadline and nothing else. A Worker that
// runs out of infer time owes no data-availability report, and an operator
// reading one there would go looking for a Builder fault that is not the fault.
func TestInferResponsibilityDeadlineDoesNotClaimAnUnpaidVerifierRemedy(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	hash := codec.HashBytes([]byte("infer-deadline-task"))
	seedInferTask(ctx, t, db, hash, store.InferTask{
		TaskID: "task-infer-deadline", SessionID: "session", OrderSequence: 1,
		DeadlineHeight: 100, Stage: "queued",
	})
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, MaxRetryAttempts: 120,
		ChainStatus: fixedChainStatus{height: 654},
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			t.Fatal("infer executor ran past its deadline")
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	rec, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Stage != layout.StageFailed {
		t.Fatalf("stage = %q, want failed", rec.Stage)
	}
	if !strings.Contains(rec.LastError, "task deadline height 100") {
		t.Fatalf("last error = %q, want the infer deadline named", rec.LastError)
	}
	if strings.Contains(rec.LastError, "MsgReportDataUnavailable") {
		t.Fatalf("last error = %q, must not claim a Verifier remedy on an infer deadline", rec.LastError)
	}
}

// The commit deadline narrows the window; it never widens it, and it never
// stops a responsibility that is still inside it.
func TestVerifyResponsibilityRunsWhileTheCommitWindowIsOpen(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	hash := codec.HashBytes([]byte("open-window-task"))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: "task-open-window", SessionID: "session", OrderSequence: 1,
		VerifyRound: 1, OpenVerifyHeight: 313,
		CommitDeadlineHeight: 633, DeadlineHeight: 1033,
		Stage: "queued",
	})

	var ran int
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, MaxRetryAttempts: 120,
		ChainStatus: fixedChainStatus{height: 400},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Fatalf("verify executor ran %d times, want 1: the commit window is open until 633", ran)
	}
}

// A responsibility whose commit deadline the chain never published falls back to
// the verify deadline rather than stopping immediately: zero is "not known", not
// "already passed".
func TestVerifyResponsibilityWithoutACommitDeadlineUsesTheVerifyDeadline(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	hash := codec.HashBytes([]byte("no-commit-deadline-task"))
	seedVerifyTask(ctx, t, db, hash, store.VerifyTask{
		TaskID: "task-no-commit-deadline", SessionID: "session", OrderSequence: 1,
		VerifyRound: 1, OpenVerifyHeight: 313,
		CommitDeadlineHeight: 0, DeadlineHeight: 1033,
		Stage: "queued",
	})

	var ran int
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, MaxRetryAttempts: 120,
		ChainStatus: fixedChainStatus{height: 654},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			ran++
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if ran != 1 {
		t.Fatalf("verify executor ran %d times, want 1: no commit deadline is not a closed window", ran)
	}
}
