package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func TestTaskRunnerStartsAndStopsADispatchedInfer(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: st})
	e := DispatchInferEntry{
		TicketHash: layout.StoredHash{1}, TaskHash: layout.StoredHash{2},
		TaskID: strings.Repeat("03", 32), SessionID: strings.Repeat("04", 32), OrderSequence: 1,
		ModelID: hrModelAB, ProfileVersion: 1, InputHash: layout.StoredHash{5}, InputSizeBytes: 10,
		BuilderOperator: hrBuilderA, WorkerAddress: hrCortex, BuilderSetID: "7", BuilderSetHash: bytes.Repeat([]byte{0x15}, 32),
		ClaimFromHeight: 159,
	}
	for i := 0; i < 2; i++ {
		if err := r.StartDispatchedInfer(ctx, e); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	rec, err := layout.GetInferRecord(ctx, st, e.TaskHash)
	if err != nil || rec.TaskID != e.TaskID || rec.DispatchTicketHash != e.TicketHash || rec.Stage != layout.StageQueued || rec.DeadlineHeight != 159 {
		t.Fatalf("infer record = %+v, %v", rec, err)
	}
	task, err := layout.GetTaskRecord(ctx, st, e.TaskHash)
	if err != nil || task.SessionID != e.SessionID || task.OrderSequence != 1 || task.InputDigest != e.InputHash ||
		task.WorkerAddress != hrCortex || task.BuilderOperatorAddress != hrBuilderA || task.TaskBuilderSetID != "7" || task.InputSizeBytes != 10 {
		t.Fatalf("task record = %+v, %v", task, err)
	}
	infer, _, err := r.loadActiveTasks(ctx)
	if err != nil || infer[codec.Hash(e.TaskHash)].DispatchTicketHash != codec.Hash(e.TicketHash) {
		t.Fatalf("the executor sees the ticket it runs for (S5 output seam): %+v, %v", infer, err)
	}
	if err := r.StopDispatchedInfer(ctx, e.TaskHash, layout.StoredHash{9}); err != nil {
		t.Fatal(err)
	}
	if _, err := layout.GetInferRecord(ctx, st, e.TaskHash); err != nil {
		t.Fatal("another round's stop must not touch this responsibility")
	}
	for i := 0; i < 2; i++ {
		if err := r.StopDispatchedInfer(ctx, e.TaskHash, e.TicketHash); err != nil {
			t.Fatalf("stop %d: %v", i, err)
		}
	}
	if _, err := layout.GetInferRecord(ctx, st, e.TaskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after stop: err = %v", err)
	}
	if err := r.StopDispatchedInfer(ctx, layout.StoredHash{}, e.TicketHash); err != nil {
		t.Fatal("a revoke tombstone has no task hash; stopping it is a no-op")
	}
}

// I5: a repeated start for the same ticket never lowers the stage the runner
// reached; a start for another ticket of the same task is a conflict.
func TestStartDispatchedInferNeverRegressesTheStage(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: st})
	e := DispatchInferEntry{
		TicketHash: layout.StoredHash{1}, TaskHash: layout.StoredHash{2},
		TaskID: strings.Repeat("03", 32), SessionID: strings.Repeat("04", 32), OrderSequence: 1,
		ModelID: hrModelAB, ProfileVersion: 1, InputHash: layout.StoredHash{5}, InputSizeBytes: 10,
		BuilderOperator: hrBuilderA, WorkerAddress: hrCortex, BuilderSetID: "7", BuilderSetHash: bytes.Repeat([]byte{0x15}, 32),
		ClaimFromHeight: 159,
	}
	if err := r.StartDispatchedInfer(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := layout.MergeInfer(ctx, st, e.TaskHash, layout.InferRecord{Stage: layout.StageSucceeded, RetryCount: 2}); err != nil {
		t.Fatal(err)
	}
	if err := r.StartDispatchedInfer(ctx, e); err != nil {
		t.Fatal(err)
	}
	if rec, err := layout.GetInferRecord(ctx, st, e.TaskHash); err != nil || rec.Stage != layout.StageSucceeded || rec.RetryCount != 2 {
		t.Fatalf("infer record = %+v, %v: a repeated start must not reset it", rec, err)
	}
	other := e
	other.TicketHash = layout.StoredHash{9}
	if err := r.StartDispatchedInfer(ctx, other); !errors.Is(err, layout.ErrConflict) {
		t.Fatalf("another ticket for the same task: err = %v, want ErrConflict", err)
	}
}
