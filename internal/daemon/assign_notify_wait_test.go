package daemon

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/store"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
)

func assignNotifyWaitRunner(t *testing.T, wait time.Duration, wake func(WakeSource)) (*TaskRunner, *store.Store) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: notifyWinner, AssignNotifyScanWait: wait})
	r.SetKeeperPollWake(wake)
	return r, db
}

func assignNotifyMessage(t *testing.T) *busv1.WorkerAssignmentNotifyV1 {
	taskHash := mustHash32(t, notifyAcceptedTaskHashHex)
	return &busv1.WorkerAssignmentNotifyV1{
		TaskId: assignNotifyTaskID(t), TaskHash: taskHash[:],
		WinnerOperatorAddress: notifyWinner, FinalizedHeight: notifyConfirmHeight,
	}
}

// A notification that outruns the Keeper scan is held until the scan it asks
// for records the assignment, and is then accepted -- instead of being
// refused into the one-second redelivery delay.
func TestAssignmentNotifyWaitsForTheScanItAsksFor(t *testing.T) {
	var r *TaskRunner
	var wakes atomic.Int64
	scanned := make(chan error, 1)
	effect := notifyAssignmentEffect(t)
	r, _ = assignNotifyWaitRunner(t, 5*time.Second, func(WakeSource) {
		if wakes.Add(1) == 1 {
			// The poller's scan: it records the assignment a moment later
			// and reports its progress.
			go func() {
				time.Sleep(20 * time.Millisecond)
				err := r.ApplyReconcilerEffects(context.Background(), []ReconcilerEffect{effect})
				r.ObserveKeeperProgress(ChainProgress{CursorHeight: notifyConfirmHeight})
				scanned <- err
			}()
		}
	})
	startedAt := time.Now()
	if err := r.recordAssignNotify(context.Background(), assignNotifyEnvelope(), assignNotifyMessage(t)); err != nil {
		t.Fatalf("recordAssignNotify = %v, want acceptance once the scan landed", err)
	}
	if err := <-scanned; err != nil {
		t.Fatalf("ApplyReconcilerEffects = %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("notification took %s, want it released by the scan", elapsed)
	}
	if wakes.Load() == 0 {
		t.Fatal("the notification did not ask for a scan")
	}
}

// The wait also ends when the cursor passes the announced height without the
// assignment -- the chain disagrees with the frame -- and the frame is then
// judged exactly as before.
func TestAssignmentNotifyWaitEndsAtTheAnnouncedHeight(t *testing.T) {
	r, db := assignNotifyWaitRunner(t, 5*time.Second, func(WakeSource) {})
	if err := db.SetKeeperLastProcessedHeight(context.Background(), notifyConfirmHeight); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	err := r.recordAssignNotify(context.Background(), assignNotifyEnvelope(), assignNotifyMessage(t))
	if !builderclient.IsRetryable(err) {
		t.Fatalf("recordAssignNotify = %v, want the retryable refusal for a record the scan did not write", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("notification waited %s although the cursor was already past its height", elapsed)
	}
}

// The wait is bounded: a chain view that never reaches the announced height
// releases the frame into the usual retryable refusal, after asking for a
// scan more than once.
func TestAssignmentNotifyWaitIsBounded(t *testing.T) {
	var wakes atomic.Int64
	r, _ := assignNotifyWaitRunner(t, 350*time.Millisecond, func(WakeSource) { wakes.Add(1) })
	startedAt := time.Now()
	err := r.recordAssignNotify(context.Background(), assignNotifyEnvelope(), assignNotifyMessage(t))
	if !builderclient.IsRetryable(err) {
		t.Fatalf("recordAssignNotify = %v, want a retryable refusal after the bound", err)
	}
	if elapsed := time.Since(startedAt); elapsed < 300*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("notification waited %s, want about the 350ms bound", elapsed)
	}
	if wakes.Load() < 2 {
		t.Fatalf("scans requested = %d, want a rescan while the chain view lagged", wakes.Load())
	}
}

// Without a poller nothing would advance the cursor, so the frame is refused
// at once, as before; a cancelled handler context ends the wait.
func TestAssignmentNotifyDoesNotWaitWithoutAPoller(t *testing.T) {
	r, _ := assignNotifyWaitRunner(t, 5*time.Second, nil)
	startedAt := time.Now()
	if err := r.recordAssignNotify(context.Background(), assignNotifyEnvelope(), assignNotifyMessage(t)); !builderclient.IsRetryable(err) {
		t.Fatalf("recordAssignNotify = %v, want the retryable refusal", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("notification waited %s without a poller", elapsed)
	}

	r, _ = assignNotifyWaitRunner(t, 5*time.Second, func(WakeSource) {})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	startedAt = time.Now()
	err := r.recordAssignNotify(ctx, assignNotifyEnvelope(), assignNotifyMessage(t))
	if err == nil {
		t.Fatal("recordAssignNotify accepted a frame whose assignment was never recorded")
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("cancelled notification waited %s", elapsed)
	}
}

// A loser's notification never waits: it is acknowledged at once.
func TestAssignmentNotifyForAnotherWinnerDoesNotWait(t *testing.T) {
	var wakes atomic.Int64
	r, _ := assignNotifyWaitRunner(t, 5*time.Second, func(WakeSource) { wakes.Add(1) })
	message := assignNotifyMessage(t)
	message.WinnerOperatorAddress = "trueopen1someoneelse"
	if err := r.recordAssignNotify(context.Background(), assignNotifyEnvelope(), message); err != nil {
		t.Fatalf("recordAssignNotify = %v, want nil for a loser", err)
	}
	if wakes.Load() != 0 {
		t.Fatalf("scans requested = %d, want none for a loser", wakes.Load())
	}
}
