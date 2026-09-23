package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func haltTestStore(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return ctx, db
}

// The production failure this reproduces: a Worker whose vLLM returned evidence
// the frozen order does not admit. The refusal is deterministic, so every retry
// re-ran a multi-minute generation to reach the same verdict -- 120 of them,
// holding the node's only GPU, while every other task waited behind the
// concurrency semaphore.
//
// One attempt is now the whole budget for that class of failure, and the reason
// is durable so a restart does not resume the loop.
func TestADeterministicModelFailureStopsCallingTheModel(t *testing.T) {
	ctx, db := haltTestStore(t)
	hash := codec.HashBytes([]byte("deterministic-failure"))
	seedInferTask(ctx, t, db, hash, store.InferTask{TaskID: "task-bad", SessionID: "session-1", Stage: "queued"})

	var mu sync.Mutex
	calls := 0
	executor := inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return task, false, fmt.Errorf("model generation evidence: %w", modelservice.Deterministic(
			modelservice.FaultCodeTokenBudgetExceeded,
			errors.New("trace generated_token_count exceeds the order's max_output_tokens"),
			modelservice.FaultUint("generated_token_count", 513),
			modelservice.FaultUint("max_output_tokens", 512)))
	})

	runner := NewTaskRunner(TaskRunnerConfig{Store: db, InferExecutor: executor, RetryDelay: time.Nanosecond})
	for range 5 {
		if err := runner.RunOnce(ctx); err != nil {
			t.Fatalf("RunOnce returned error: %v", err)
		}
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("the executor ran %d times across five ticks; a deterministic refusal must stop after the first", got)
	}

	record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if !record.AutoHalted {
		t.Fatalf("the record is not halted: %#v", record)
	}
	if record.HaltCode != modelservice.FaultCodeTokenBudgetExceeded {
		t.Fatalf("halt_code = %q, want the fault's own code", record.HaltCode)
	}
	if record.HaltReason == "" || record.LastError == "" {
		t.Fatalf("the halt carries no reason: %#v", record)
	}
	// The retry count is deliberately untouched: nothing was retried, and
	// "stopped after one attempt because the model contradicted the order" must
	// stay distinguishable from "stopped after 120 attempts".
	if record.RetryCount != 0 {
		t.Fatalf("retry_count = %d, want 0 for a halt", record.RetryCount)
	}
	// A halt is not a task terminal and not a cleanup signal. The responsibility
	// and its evidence manifest must still be there for the chain and for an
	// operator.
	if record.TaskID != "task-bad" {
		t.Fatalf("the halt deleted or renamed the responsibility: %#v", record)
	}
	if _, err := layout.GetTaskRecord(ctx, db, layout.StoredHash(hash)); err != nil {
		t.Fatalf("the halt removed the task record: %v", err)
	}

	// The restart: a fresh runner over the same store must not call the model.
	restarted := NewTaskRunner(TaskRunnerConfig{Store: db, InferExecutor: executor, RetryDelay: time.Nanosecond})
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after restart returned error: %v", err)
	}
	mu.Lock()
	afterRestart := calls
	mu.Unlock()
	if afterRestart != 1 {
		t.Fatalf("the executor ran %d times in total after a restart, want 1", afterRestart)
	}
}

// The other halting class: signed output frames already name this run's bytes,
// so a second generation would sign a different prefix under one task hash.
// Same stop, different code, and the code has to survive to the record because
// it is what tells an operator the remedy is not "run it again".
func TestRegenerationForbiddenAlsoHalts(t *testing.T) {
	ctx, db := haltTestStore(t)
	hash := codec.HashBytes([]byte("frames-already-signed"))
	seedInferTask(ctx, t, db, hash, store.InferTask{TaskID: "task-frames", SessionID: "session-1", Stage: "queued"})

	runner := NewTaskRunner(TaskRunnerConfig{
		Store:      db,
		RetryDelay: time.Nanosecond,
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			return task, false, modelservice.RegenerationForbidden(
				modelservice.FaultCodeOutputFramesAlreadySigned,
				errors.New("inference interrupted after signing output frames"),
				modelservice.FaultInt("signed_frames", 4))
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if !record.AutoHalted || record.HaltCode != modelservice.FaultCodeOutputFramesAlreadySigned {
		t.Fatalf("record = %#v, want a halt carrying the regeneration-forbidden code", record)
	}
}

// The complement, and the more important half of the contract: a transient or
// unclassified failure keeps the old behaviour. Treating either as a halt would
// turn a Nexus blip into a permanently stopped task, which is a worse outage
// than the one being fixed.
func TestTransientAndUnclassifiedFailuresStillRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"transient", modelservice.Transient("MODEL_UNAVAILABLE", errors.New("connection refused"))},
		{"unclassified", errors.New("something went wrong")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db := haltTestStore(t)
			hash := codec.HashBytes([]byte("retryable-" + tc.name))
			seedInferTask(ctx, t, db, hash, store.InferTask{TaskID: "task-" + tc.name, SessionID: "session-1", Stage: "queued"})

			runner := NewTaskRunner(TaskRunnerConfig{
				Store:      db,
				RetryDelay: time.Nanosecond,
				InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
					return task, false, tc.err
				}),
			})
			if err := runner.RunOnce(ctx); err != nil {
				t.Fatalf("RunOnce returned error: %v", err)
			}
			record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
			if err != nil {
				t.Fatalf("GetInferRecord returned error: %v", err)
			}
			if record.AutoHalted {
				t.Fatalf("a %s failure halted the responsibility: %#v", tc.name, record)
			}
			if record.RetryCount != 1 || record.RetryAtUnixMilli == 0 {
				t.Fatalf("a %s failure did not schedule a retry: %#v", tc.name, record)
			}
		})
	}
}

// The requeue is the controlled state update an operator uses to try a halted
// task again, and it is the only thing that clears the halt. Without it the
// halt would need a database edit to release.
func TestRequeueClearsAnAutoHalt(t *testing.T) {
	ctx, db := haltTestStore(t)
	hash := codec.HashBytes([]byte("requeue-halted"))
	seedInferTask(ctx, t, db, hash, store.InferTask{TaskID: "task-requeue", SessionID: "session-1", Stage: "queued"})

	runner := NewTaskRunner(TaskRunnerConfig{
		Store:      db,
		RetryDelay: time.Nanosecond,
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			return task, false, modelservice.Deterministic(modelservice.FaultCodeTokenBudgetExceeded, errors.New("over budget"))
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	rows, err := runner.ListActiveTasks(ctx)
	if err != nil {
		t.Fatalf("ListActiveTasks returned error: %v", err)
	}
	if len(rows) != 1 || !rows[0].AutoHalted || rows[0].HaltCode != modelservice.FaultCodeTokenBudgetExceeded {
		t.Fatalf("the admin listing does not report the halt: %#v", rows)
	}

	queueID := "infer:" + hex.EncodeToString(hash[:])
	if _, err := runner.RequeueActiveTask(ctx, queueID, "operator retried after fixing the profile", time.Now()); err != nil {
		t.Fatalf("RequeueActiveTask returned error: %v", err)
	}
	record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if record.AutoHalted || record.HaltCode != "" || record.HaltReason != "" {
		t.Fatalf("the requeue left the halt in place: %#v", record)
	}
	if record.Stage != layout.StageQueued || record.RetryCount != 0 {
		t.Fatalf("the requeue did not reopen the responsibility: %#v", record)
	}
}
