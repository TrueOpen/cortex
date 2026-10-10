package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// countingLimitsReader stands in for the Keeper client, which retains the
// limits itself. The count is what matters: the warm must be the read the
// first task would otherwise have made, not an extra one.
type countingLimitsReader struct {
	reads atomic.Int64
	err   error
}

func (r *countingLimitsReader) OutputStreamLimits(context.Context) (chainclient.OutputStreamLimitsSnapshot, error) {
	r.reads.Add(1)
	if r.err != nil {
		return chainclient.OutputStreamLimitsSnapshot{}, r.err
	}
	return chainclient.OutputStreamLimitsSnapshot{MaxOutputMMRLeaves: 65536, MinOutputStreamFrameBytes: 16, SnapshotHeight: 900}, nil
}

// runWarm starts the runner and reports how it behaved: whether it was still
// running when the warm had finished, and what it returned once cancelled.
func runWarm(t *testing.T, runner runtimeRunner, reader *countingLimitsReader) error {
	t.Helper()
	if runner == nil {
		t.Fatal("no warm runner for a Keeper client that can serve the limits")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner(ctx) }()

	deadline := time.After(5 * time.Second)
	for reader.reads.Load() == 0 {
		select {
		case err := <-done:
			t.Fatalf("the runner returned before reading the limits: %v", err)
		case <-deadline:
			t.Fatal("the limits were never read")
		case <-time.After(time.Millisecond):
		}
	}

	// A runner that returns while the daemon is still up is read by the
	// supervisor as a component that died: once every runner has returned it
	// reports "all runtime runners exited while the daemon was still running"
	// and fails the process. The warm has to outlive its own work.
	select {
	case err := <-done:
		t.Fatalf("the runner exited as soon as it was warm: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the runner ignored cancellation")
		return nil
	}
}

// TestStreamLimitsAreWarmBeforeTheFirstTask is the point of warming: the
// genesis-only read is retained by the Keeper client, so doing it at startup
// means the first task finds it already there instead of paying two chain round
// trips between its admission and its generation.
func TestStreamLimitsAreWarmBeforeTheFirstTask(t *testing.T) {
	reader := &countingLimitsReader{}
	runner := outputStreamLimitsWarmRunner(reader)
	if runner == nil {
		t.Fatal("no warm runner for a Keeper client that can serve the limits")
	}
	if err := runWarm(t, runner, reader); err != nil {
		t.Fatalf("runner error = %v, want a clean exit on cancellation", err)
	}
	if got := reader.reads.Load(); got != 1 {
		t.Fatalf("chain reads = %d, want the single read the first task would have made", got)
	}
}

// TestAChainThatIsDownAtBootDoesNotFailTheDaemon keeps the warm from becoming a
// boot dependency. Returning an error here stops the whole runtime, which would
// turn a chain that is briefly unreachable -- a state this node already
// recovers from through the poller and the readiness gate -- into a node that
// refuses to come up. The limits stay lazily readable, so the cost of a warm
// that did not happen is what the first task pays today and nothing more.
func TestAChainThatIsDownAtBootDoesNotFailTheDaemon(t *testing.T) {
	reader := &countingLimitsReader{err: errors.New("keeper RPC is unreachable")}
	if err := runWarm(t, outputStreamLimitsWarmRunner(reader), reader); err != nil {
		t.Fatalf("runner error = %v, want the failed warm to be survivable", err)
	}
}

// TestNoWarmWithoutAKeeperThatServesTheLimits covers the fake and fixture
// deployments, where the Keeper stand-in does not read task params at all.
func TestNoWarmWithoutAKeeperThatServesTheLimits(t *testing.T) {
	if runner := outputStreamLimitsWarmRunner(nil); runner != nil {
		t.Fatal("a warm runner was built with nothing to read from")
	}
	if runner := outputStreamLimitsWarmRunner(struct{}{}); runner != nil {
		t.Fatal("a warm runner was built for a Keeper that cannot serve the limits")
	}
}
