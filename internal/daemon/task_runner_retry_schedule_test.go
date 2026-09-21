package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
)

// The bug with teeth. The retry time was `tickStart + retry_delay`, and
// tickStart is taken before the executor runs -- so an attempt that took longer
// than retry_delay produced a retry time already in the past and the next tick
// re-entered the model with no wait at all.
//
// The devnet numbers make it concrete: infer_timeout_ms is 300000 against a
// one-minute retry_delay, so every failed generation was immediately due again.
// This test reproduces that shape -- one attempt outlasting the delay -- and
// asserts the wait survives it.
func TestARetryIsScheduledFromWhenTheAttemptFinished(t *testing.T) {
	ctx, db := haltTestStore(t)
	hash := codec.HashBytes([]byte("slow-failure"))
	seedInferTask(ctx, t, db, hash, store.InferTask{TaskID: "task-slow", SessionID: "session-1", Stage: "queued"})

	const runtime = 120 * time.Millisecond
	const retryDelay = 40 * time.Millisecond
	runner := NewTaskRunner(TaskRunnerConfig{
		Store:      db,
		RetryDelay: retryDelay,
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			time.Sleep(runtime)
			return task, false, errors.New("transient model outage")
		}),
	})

	before := time.Now().UTC()
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	retryAt := time.UnixMilli(record.RetryAtUnixMilli).UTC()

	// Measured against the moment the tick STARTED plus the attempt's own
	// duration: the old arithmetic put the retry at before+40ms, which is 80ms
	// in the past by the time the attempt returned.
	earliest := before.Add(runtime)
	if retryAt.Before(earliest) {
		t.Fatalf("retry_at %s is before the attempt even finished (%s); the delay was measured from the top of the tick",
			retryAt, earliest)
	}
	if !retryAt.After(time.Now().UTC()) {
		t.Fatalf("retry_at %s is already due; a failed attempt must wait", retryAt)
	}
}

// The backoff is exponential from retry_delay and capped, so a responsibility
// that keeps failing stops asking every minute forever, and one that is merely
// unlucky still retries promptly. Both halves matter: growth without a cap would
// push a retry past the task's own chain deadline.
func TestRetryBackoffGrowsAndIsCapped(t *testing.T) {
	runner := NewTaskRunner(TaskRunnerConfig{
		Store:         nil,
		RetryDelay:    time.Minute,
		MaxRetryDelay: 8 * time.Minute,
	})
	finished := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		attempt uint32
		want    time.Duration
	}{
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 8 * time.Minute},
		{40, 8 * time.Minute},
	} {
		got := runner.retryAt(finished, tc.attempt).Sub(finished)
		if got != tc.want {
			t.Fatalf("attempt %d delay = %s, want %s", tc.attempt, got, tc.want)
		}
	}
}

// A ceiling below the base delay is a configuration mistake, not an instruction
// to retry faster than configured.
func TestRetryCeilingNeverFallsBelowTheBaseDelay(t *testing.T) {
	runner := NewTaskRunner(TaskRunnerConfig{RetryDelay: 5 * time.Minute, MaxRetryDelay: time.Second})
	finished := time.Unix(1_700_000_000, 0).UTC()
	if got := runner.retryAt(finished, 1).Sub(finished); got != 5*time.Minute {
		t.Fatalf("delay = %s, want the configured retry_delay", got)
	}
}

// One bad task must not be able to hold the node. The semaphore slot is
// released on the failing path as well as the succeeding one, so a second task
// runs on the same tick even when the first one fails.
func TestAFailedTaskReleasesItsConcurrencySlot(t *testing.T) {
	ctx, db := haltTestStore(t)
	bad := codec.HashBytes([]byte("bad-task"))
	good := codec.HashBytes([]byte("good-task"))
	seedInferTask(ctx, t, db, bad, store.InferTask{TaskID: "task-bad", SessionID: "session-1", Stage: "queued"})
	seedInferTask(ctx, t, db, good, store.InferTask{TaskID: "task-good", SessionID: "session-1", Stage: "queued"})

	runner := NewTaskRunner(TaskRunnerConfig{
		Store:          db,
		MaxConcurrency: 1,
		RetryDelay:     time.Nanosecond,
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			if task.TaskID == "task-bad" {
				return task, false, errors.New("transient model outage")
			}
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	goodRecord, err := layout.GetInferRecord(ctx, db, layout.StoredHash(good))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if goodRecord.Stage != layout.StageSucceeded {
		t.Fatalf("the healthy task did not run behind the failing one: %#v", goodRecord)
	}
}
