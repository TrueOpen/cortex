package worker

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/taskfacts"
)

// countingFactsReader answers from a table and counts what it was asked, so a
// test can tell a retained answer from a repeated chain read.
type countingFactsReader struct {
	facts  map[string]taskfacts.Facts
	err    error
	calls  int
	asked  []string
	failed int
}

func (r *countingFactsReader) TaskFacts(_ context.Context, taskID string) (taskfacts.Facts, error) {
	r.calls++
	r.asked = append(r.asked, taskID)
	if r.err != nil {
		r.failed++
		return taskfacts.Facts{}, r.err
	}
	facts, ok := r.facts[taskID]
	if !ok {
		return taskfacts.Facts{}, errors.New("unknown task")
	}
	return facts, nil
}

func factsFor(taskID string) taskfacts.Facts {
	accepted := codec.HashBytes([]byte("accepted:" + taskID))
	digest := codec.HashBytes([]byte("generation:" + taskID))
	return taskfacts.Facts{
		TaskID: taskID,
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash:       accepted[:],
			GenerationParamsDigest: digest[:],
		},
	}
}

// TestTaskFactsAreReadOncePerTask is why the cache exists. The facts are
// immutable for a task -- the function that reads them says so -- and every
// caller re-read them from the chain, which on a node deployed away from the
// chain was about 630ms a time, three times before the first token.
func TestTaskFactsAreReadOncePerTask(t *testing.T) {
	h := newHarness(t)
	reader := &countingFactsReader{facts: map[string]taskfacts.Facts{"task-a": factsFor("task-a")}}
	h.worker.cfg.TaskFacts = reader

	for range 5 {
		facts, err := h.worker.taskFacts(context.Background(), "task-a")
		if err != nil {
			t.Fatal(err)
		}
		if facts.TaskID != "task-a" {
			t.Fatalf("facts = %+v, want the facts for task-a", facts)
		}
	}
	if reader.calls != 1 {
		t.Fatalf("chain reads = %d, want the one the facts can ever need", reader.calls)
	}
}

// TestTaskFactsAreNotSharedBetweenTasks is the correctness guard the cache has
// to carry. Answering for the wrong task would put another task's accepted hash
// into a signed receipt, which is worse than any number of re-reads.
func TestTaskFactsAreNotSharedBetweenTasks(t *testing.T) {
	h := newHarness(t)
	reader := &countingFactsReader{facts: map[string]taskfacts.Facts{
		"task-a": factsFor("task-a"), "task-b": factsFor("task-b"),
	}}
	h.worker.cfg.TaskFacts = reader

	first, err := h.worker.taskFacts(context.Background(), "task-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.worker.taskFacts(context.Background(), "task-b")
	if err != nil {
		t.Fatal(err)
	}
	if second.TaskID != "task-b" || bytes.Equal(second.AcceptedTaskHash, first.AcceptedTaskHash) {
		t.Fatalf("task-b read %+v, want its own facts rather than task-a's", second)
	}
	if reader.calls != 2 {
		t.Fatalf("chain reads = %d, want one per task", reader.calls)
	}
}

// TestFailedTaskFactsReadsAreNotRetained keeps a chain that was briefly
// unreachable from becoming permanently unreachable for this task. Nothing is
// retained unless it was read.
func TestFailedTaskFactsReadsAreNotRetained(t *testing.T) {
	h := newHarness(t)
	reader := &countingFactsReader{err: errors.New("Keeper RPC is unreachable")}
	h.worker.cfg.TaskFacts = reader

	if _, err := h.worker.taskFacts(context.Background(), "task-a"); err == nil {
		t.Fatal("a failed read was accepted")
	}
	reader.err = nil
	reader.facts = map[string]taskfacts.Facts{"task-a": factsFor("task-a")}
	facts, err := h.worker.taskFacts(context.Background(), "task-a")
	if err != nil {
		t.Fatalf("the failed read was retained instead of retried: %v", err)
	}
	if facts.TaskID != "task-a" {
		t.Fatalf("facts = %+v", facts)
	}
}
