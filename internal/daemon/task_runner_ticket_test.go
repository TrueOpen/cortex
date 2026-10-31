package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// M2: the stale-outcome guard compares the ticket captured at launch, not the
// one the executor returned.
func TestOutcomeOfAnotherTicketIsDropped(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: st})
	hash, taskID := codec.Hash{2}, strings.Repeat("03", 32)
	r.infer = map[codec.Hash]store.InferTask{hash: {TaskID: taskID, DispatchTicketHash: codec.Hash{6}, Stage: "running"}}
	// The executor launched for ticket 1 echoes the next round's ticket.
	out := taskOutcome{role: "infer", hash: hash, ticket: codec.Hash{1}, infer: store.InferTask{TaskID: taskID, DispatchTicketHash: codec.Hash{6}, Stage: "succeeded"}}
	if err := r.applyOutcome(ctx, out); err != nil {
		t.Fatal(err)
	}
	if got := r.infer[hash].Stage; got != "running" {
		t.Fatalf("stage %s: an outcome of ticket 1 landed on ticket 6's record", got)
	}
}

// M3: a checkpoint of a stopped ticket never merges into the next round.
func TestCheckpointOfAnotherTicketIsOrphaned(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: st})
	hash := codec.Hash{2}
	if err := layout.InferAssignmentBatch(ctx, st, layout.StoredHash(hash), layout.TaskRecord{SessionID: "s"},
		layout.InferRecord{TaskID: "t", DispatchTicketHash: layout.StoredHash{6}, Stage: layout.StageQueued}); err != nil {
		t.Fatal(err)
	}
	err = r.persistInferCheckpoint(ctx, hash, store.InferTask{TaskID: "t", SessionID: "s", DispatchTicketHash: codec.Hash{1}}, layout.Evidence{})
	if !errors.Is(err, errInferCheckpointOrphaned) {
		t.Fatalf("err = %v, want orphaned", err)
	}
}
