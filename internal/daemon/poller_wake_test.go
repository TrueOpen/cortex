package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// scanPage is one block holding one event, so the scan reaches the effect sink
// and the test can see which wake produced it. rangeStart must continue from
// the cursor the previous page left behind: a scan that starts anywhere else is
// a gap, and the poller refuses it rather than skipping blocks.
func scanPage(rangeStart, height uint64, taskID string, hash codec.Hash) chainclient.KeeperEventsPage {
	return chainclient.KeeperEventsPage{
		ChainHeight: height, FinalizedHeight: height, LastPosition: chainclient.BlockEndPosition(height),
		RangeStartHeight: rangeStart, RangeEndHeight: height, RangeComplete: true,
		Events: []chainclient.KeeperEvent{
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: taskID, SessionID: "session-1", OrderDigest: hash, Height: height},
		},
	}
}

// TestKeeperPollerWakeCutsTheIntervalShort is the point of the wake: a caller
// holding evidence that the chain moved does not have to wait out an interval
// chosen for the idle case. The interval here is long enough that the test
// could only pass by being woken.
func TestKeeperPollerWakeCutsTheIntervalShort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := openPollerTestStore(t)
	hashA := codec.HashWithDomain("TEST_TASK", []byte("wake-a"))
	hashB := codec.HashWithDomain("TEST_TASK", []byte("wake-b"))
	keeper := &scriptedKeeperEvents{
		pages:      []chainclient.KeeperEventsPage{scanPage(1, 12, "task-a", hashA), scanPage(13, 13, "task-b", hashB)},
		taskReader: terminalTaskReader(map[string]codec.Hash{"task-a": hashA, "task-b": hashB}),
	}
	scans := make(chan WakeSource, 8)
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{TaskReader: keeper.taskReader}), KeeperPollerConfig{
		Interval: time.Hour,
		EffectSink: func(ctx context.Context, _ []ReconcilerEffect) error {
			source, _ := WakeSourceFrom(ctx)
			scans <- source
			return nil
		},
	})

	done := make(chan error, 1)
	go func() { done <- poller.Run(ctx) }()

	// Waiting on Run as well, so a poller that stopped reports why instead of
	// looking like a wake that did not arrive.
	nextScan := func(what string) WakeSource {
		t.Helper()
		select {
		case source := <-scans:
			return source
		case err := <-done:
			t.Fatalf("the poller stopped before %s: %v", what, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s never happened", what)
		}
		return ""
	}

	// The first scan runs immediately and says so.
	if source := nextScan("the first scan"); source != WakeStartup {
		t.Fatalf("first scan source = %q, want %q", source, WakeStartup)
	}

	// With an hour to wait, only a wake can produce the second one.
	poller.Wake(WakeNotify)
	if source := nextScan("the woken scan"); source != WakeNotify {
		t.Fatalf("woken scan source = %q, want %q", source, WakeNotify)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestKeeperPollerWakeIsOneSlotAndNeverBlocks keeps a burst of frames from
// turning into a burst of scans: the second request is already covered by the
// pending one. It must also be safe to call with no poller running and on a nil
// poller, because the wiring that supplies it is optional.
func TestKeeperPollerWakeIsOneSlotAndNeverBlocks(t *testing.T) {
	db := openPollerTestStore(t)
	poller := NewKeeperPoller(db, &scriptedKeeperEvents{}, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			poller.Wake(WakeNotify)
		}
		(*KeeperPoller)(nil).Wake(WakeNotify)
		poller.Wake("")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wake blocked")
	}
	if got := len(poller.wake); got != 1 {
		t.Fatalf("pending wakes = %d, want exactly the one slot", got)
	}
}

// TestWakeSourceIsAbsentOutsideThePoller keeps the milestone honest for every
// caller that applies effects directly -- every test, and the fake-bus
// deployment. Those scans have no source, and the field is left off rather than
// defaulted to a lie about how this node learned the fact.
func TestWakeSourceIsAbsentOutsideThePoller(t *testing.T) {
	if source, ok := WakeSourceFrom(context.Background()); ok {
		t.Fatalf("WakeSourceFrom(plain context) = %q, true; want absent", source)
	}
	if source, ok := WakeSourceFrom(withWakeSource(context.Background(), "")); ok {
		t.Fatalf("WakeSourceFrom(empty source) = %q, true; want absent", source)
	}
	source, ok := WakeSourceFrom(withWakeSource(context.Background(), WakeTick))
	if !ok || source != WakeTick {
		t.Fatalf("WakeSourceFrom = %q, %v; want %q, true", source, ok, WakeTick)
	}
}

// TestTaskRunnerWakesThePollerWhenAFrameOutrunsTheCursor pins the one place the
// wake is raised from: a WORKER_ASSIGNMENT_NOTIFY naming a task whose local
// record the scan has not written yet. The frame is still retried -- the wake
// changes when the record appears, not whether this frame may proceed without
// it.
func TestTaskRunnerWakesThePollerWhenAFrameOutrunsTheCursor(t *testing.T) {
	woken := make(chan WakeSource, 4)
	runner := &TaskRunner{cfg: TaskRunnerConfig{
		WakeKeeperPoll: func(source WakeSource) { woken <- source },
	}}
	runner.wakeKeeperPoll()
	select {
	case source := <-woken:
		if source != WakeNotify {
			t.Fatalf("wake source = %q, want %q", source, WakeNotify)
		}
	default:
		t.Fatal("the runner did not ask for a scan")
	}

	// Unwired is the ordinary state in tests and without a poller, and must stay
	// a no-op rather than a panic.
	(&TaskRunner{}).wakeKeeperPoll()
}
