package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// The last accepted commit emits these events in this order, in one transaction.
func commitCloseEvents(height uint64, missing string) []chainclient.KeeperEvent {
	var events []chainclient.KeeperEvent
	if missing == "0" {
		events = append(events, chainclient.KeeperEvent{
			Type: chainclient.KeeperEventCommitAccepted, Known: true,
			TaskID: revealPhaseTaskID, SessionID: "session-1", Height: height,
			Verifier: "verifier-1",
		})
	}
	return append(events,
		chainclient.KeeperEvent{
			Type: chainclient.KeeperEventRevealPhaseStarted, Known: true,
			TaskID: revealPhaseTaskID, SessionID: "session-1", Height: height,
			Attributes: map[string]string{"reveal_deadline_height": "900"},
		},
		chainclient.KeeperEvent{
			Type: chainclient.KeeperEventCommitDeadlineClosed, Known: true,
			TaskID: revealPhaseTaskID, SessionID: "session-1", Height: height,
			Attributes: map[string]string{"reveal_deadline_height": "900", "missing_verifier_count": missing},
		},
	)
}

func applyCommitCloseEvents(t *testing.T, runner *TaskRunner, hash codec.Hash, events []chainclient.KeeperEvent) {
	t.Helper()
	reconciler := NewReconciler(ReconcilerOptions{
		TaskReader: staticKeeperTaskReader{snapshot: revealPhaseSnapshot(hash, 900)},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) {
			t.Errorf("event %s quarantined: %s", event.Type, event.QuarantineReason)
		},
	})
	effects, err := reconciler.Apply(context.Background(), events)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.ApplyReconcilerEffects(context.Background(), effects); err != nil {
		t.Fatal(err)
	}
}

func TestCommitClosePreservesRevealResponsibility(t *testing.T) {
	for _, test := range []struct {
		name    string
		height  uint64
		missing string
		split   bool
	}{
		{name: "all commits in one transaction", height: 500, missing: "0"},
		{name: "events delivered separately", height: 500, missing: "0", split: true},
		{name: "commit deadline with another verifier missing", height: 634, missing: "1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 0, TaskRunnerConfig{})
			events := commitCloseEvents(test.height, test.missing)
			// Replaying the block must also leave the pending reveal intact.
			for replay := 0; replay < 2; replay++ {
				if test.split {
					for _, event := range events {
						applyCommitCloseEvents(t, runner, hash, []chainclient.KeeperEvent{event})
					}
				} else {
					applyCommitCloseEvents(t, runner, hash, events)
				}
				record, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
				if err != nil {
					t.Fatalf("pending reveal was removed after commit close: %v", err)
				}
				if record.Stage != layout.StageCommitted || record.RevealDeadlineHeight != 900 {
					t.Fatalf("record = %#v, want committed with reveal deadline 900", record)
				}
			}

			var seen []store.VerifyTask
			restarted := NewTaskRunner(TaskRunnerConfig{
				Store: db, LocalVerifierAddress: "verifier-1",
				ChainStatus: fixedChainStatus{height: test.height},
				VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
					seen = append(seen, task)
					task.Stage = string(layout.StageSucceeded)
					return task, false, nil
				}),
			})
			for tick := 0; tick < 2; tick++ {
				if err := restarted.RunOnce(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if len(seen) != 1 || seen[0].Stage != string(layout.StageCommitted) || seen[0].RevealDeadlineHeight != 900 {
				t.Fatalf("executed tasks = %#v, want exactly one reveal after restoring the runner", seen)
			}
		})
	}
}

func TestCommitCloseWhileCommitExecutionIsFinishing(t *testing.T) {
	ctx := context.Background()
	var runner *TaskRunner
	var calls int
	runner, db, hash := revealPhaseRunner(t, layout.StageQueued, 0, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 500},
		VerifyExecutor: verifyExecutorFunc(func(ctx context.Context, hash codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			calls++
			if calls == 1 {
				// The chain may close commits before the relay call returns and
				// before the runner has persisted StageCommitted.
				applyCommitCloseEvents(t, runner, hash, commitCloseEvents(500, "0"))
				task.Stage = string(layout.StageCommitted)
			} else {
				if task.Stage != string(layout.StageCommitted) || task.RevealDeadlineHeight != 900 {
					t.Errorf("next execution = %#v, want the pending reveal", task)
				}
				task.Stage = string(layout.StageSucceeded)
			}
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	record, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatalf("commit completion lost its owning record: %v", err)
	}
	if record.Stage != layout.StageCommitted || record.RevealDeadlineHeight != 900 {
		t.Fatalf("record = %#v, want commit completion to preserve the event's reveal deadline", record)
	}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("executor calls = %d, want commit then reveal", calls)
	}
}

func TestCommitCloseStillStopsUncommittedVerifierAtDeadline(t *testing.T) {
	ctx := context.Background()
	var calls int
	runner, db, hash := revealPhaseRunner(t, layout.StageQueued, 0, TaskRunnerConfig{
		ChainStatus: fixedChainStatus{height: 634},
		VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			calls++
			return task, false, nil
		}),
	})
	applyCommitCloseEvents(t, runner, hash, commitCloseEvents(634, "1"))
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("executor calls = %d, want no commit past its deadline", calls)
	}
	record, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if record.Stage != layout.StageFailed || !strings.Contains(record.LastError, "commit deadline height 633") {
		t.Fatalf("record = %#v, want failed with the commit deadline reason", record)
	}
}

func TestRevealDeadlineClosedStillReleasesVerifyResponsibility(t *testing.T) {
	ctx := context.Background()
	runner, db, hash := revealPhaseRunner(t, layout.StageCommitted, 900, TaskRunnerConfig{})
	applyCommitCloseEvents(t, runner, hash, []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventRevealDeadlineClosed, Known: true,
		TaskID: revealPhaseTaskID, SessionID: "session-1", Height: 901,
	}})
	if _, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetVerifyRecord() error = %v, want cleanup when the reveal window closes", err)
	}
}
