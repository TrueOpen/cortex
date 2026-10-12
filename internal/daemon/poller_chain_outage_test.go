package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// flakyKeeperEvents is a chain that is unreachable for a while and then comes
// back, which is the ordinary life of a single-validator devnet: a restart, a
// proxy reload, or an upstream that answers 500 for a few seconds.
type flakyKeeperEvents struct {
	failures   int64
	attempts   atomic.Int64
	page       chainclient.KeeperEventsPage
	taskReader KeeperTaskReader
}

func (k *flakyKeeperEvents) FinalizedEvents(_ context.Context, _ chainclient.EventPosition) (chainclient.KeeperEventsPage, error) {
	if k.attempts.Add(1) <= k.failures {
		return chainclient.KeeperEventsPage{}, chainclient.Retryable(errors.New("CometBFT /block_results returned 500 Internal Server Error"))
	}
	return k.page, nil
}

// TestChainOutageDoesNotStopThePoller is the behaviour this exists for. A chain
// that is briefly unreachable used to end the process: the poll returned an
// error after a handful of consecutive failures, the runner supervisor read
// that as the runtime dying, and the node exited. On a host with no supervisor
// that turned a chain blip measured in seconds into an outage measured in
// however long it took somebody to notice.
//
// The node can already express "cannot work right now" without dying -- the
// readiness gate closes and /readyz answers 503 -- so a retryable chain error
// is a reason to wait, not a reason to exit.
func TestChainOutageDoesNotStopThePoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := openPollerTestStore(t)
	hash := codec.HashWithDomain("TEST_TASK", []byte("outage"))
	// Far more consecutive failures than the retry count that used to be fatal.
	keeper := &flakyKeeperEvents{
		failures:   25,
		page:       scanPage(1, 7, "task-outage", hash),
		taskReader: terminalTaskReader(map[string]codec.Hash{"task-outage": hash}),
	}
	scanned := make(chan struct{}, 1)
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{TaskReader: keeper.taskReader}), KeeperPollerConfig{
		Interval:        time.Millisecond,
		RetryBackoff:    time.Millisecond,
		MaxRetryBackoff: 2 * time.Millisecond,
		EffectSink: func(context.Context, []ReconcilerEffect) error {
			select {
			case scanned <- struct{}{}:
			default:
			}
			return nil
		},
	})

	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	select {
	case <-scanned:
	case err := <-done:
		t.Fatalf("the poller gave up on a chain that came back: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("the chain recovered after %d attempts but no scan followed", keeper.attempts.Load())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want a clean exit on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestProtocolFaultsStillStopThePoller keeps the change narrow. Waiting is the
// right answer to a chain that cannot be reached; it is the wrong answer to a
// chain that answered with something this node must not accept, which no amount
// of retrying will turn into a valid reply.
func TestProtocolFaultsStillStopThePoller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := openPollerTestStore(t)
	keeper := &scriptedKeeperEvents{err: errors.New("Keeper QueryTask task_id must be 32-byte hex")}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{
		Interval: time.Millisecond, RetryBackoff: time.Millisecond,
	})

	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run() = nil, want the protocol fault reported rather than retried forever")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the poller retried a fault that retrying cannot fix")
	}
}

// TestRetryBackoffSettlesAtItsCap pins the steady state of a long outage. The
// cap was unreachable while the sixth consecutive failure ended the process:
// the delay only ever climbed 1, 2, 4, 8, 16 before the exit, so the configured
// maximum described a state the poller could never be in. Now it is where a
// poller waiting out a long outage actually sits.
func TestRetryBackoffSettlesAtItsCap(t *testing.T) {
	poller := NewKeeperPoller(openPollerTestStore(t), &scriptedKeeperEvents{}, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{
		RetryBackoff: time.Second, MaxRetryBackoff: 30 * time.Second,
	})
	for _, test := range []struct {
		failures int
		want     time.Duration
	}{
		{1, time.Second}, {2, 2 * time.Second}, {5, 16 * time.Second},
		{6, 30 * time.Second}, {40, 30 * time.Second}, {4000, 30 * time.Second},
	} {
		if got := poller.retryDelay(test.failures); got != test.want {
			t.Fatalf("retryDelay(%d) = %v, want %v", test.failures, got, test.want)
		}
	}
}
