package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

type blockingInfer struct{ started, cancelled chan struct{} }

func (b *blockingInfer) RunInfer(ctx context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
	close(b.started)
	<-ctx.Done()
	close(b.cancelled)
	task.Stage = "running"
	return task, false, ctx.Err()
}

func TestStopDispatchedInferCancelsTheRunningExecution(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	b := &blockingInfer{started: make(chan struct{}), cancelled: make(chan struct{})}
	r := NewTaskRunner(TaskRunnerConfig{Store: st, InferExecutor: b})
	e := DispatchInferEntry{
		TicketHash: layout.StoredHash{1}, TaskHash: layout.StoredHash{2}, TaskID: strings.Repeat("03", 32), SessionID: strings.Repeat("04", 32),
		OrderSequence: 1, ModelID: hrModelAB, ProfileVersion: 1, InputHash: layout.StoredHash{5}, InputSizeBytes: 10,
		BuilderOperator: hrBuilderA, WorkerAddress: hrCortex, BuilderSetID: "7", BuilderSetHash: bytes.Repeat([]byte{0x15}, 32), ClaimFromHeight: 159,
	}
	if err := r.StartDispatchedInfer(ctx, e); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.RunOnce(ctx) }()
	wait := func(c <-chan struct{}, what string) {
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatal(what)
		}
	}
	wait(b.started, "the executor never started")
	if err := r.StopDispatchedInfer(ctx, e.TaskHash, e.TicketHash); err != nil {
		t.Fatal(err)
	}
	wait(b.cancelled, "StopDispatchedInfer left the execution running")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pass never finished")
	}
	if _, err := layout.GetInferRecord(ctx, st, e.TaskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the cancelled outcome wrote the record back: %v", err)
	}
	e2 := e
	e2.TicketHash = layout.StoredHash{6}
	if err := r.StartDispatchedInfer(ctx, e2); err != nil {
		t.Fatalf("a new round of the task starts cleanly: %v", err)
	}
}
