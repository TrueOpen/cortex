package daemon

import (
	"context"
	"errors"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

const (
	// defaultAssignNotifyScanWait bounds how long a WORKER_ASSIGNMENT_NOTIFY
	// waits for the Keeper poller to record the assignment it announces. A
	// Builder sends it as soon as its own node commits the block, so this node
	// is normally at most a block or two behind. Past the bound the frame is
	// refused retryably and redelivered, as before.
	defaultAssignNotifyScanWait = 2 * time.Second
	// assignNotifyRescan is how often a waiting notification asks for another
	// scan when the last one did not reach the announced height: the node this
	// daemon reads has not committed that block yet.
	assignNotifyRescan = 100 * time.Millisecond
)

// ObserveKeeperProgress is the poller's progress callback: every finished
// page lets a waiting assignment notification look again.
func (r *TaskRunner) ObserveKeeperProgress(ChainProgress) {
	r.signalKeeperProgress()
}

func (r *TaskRunner) signalKeeperProgress() {
	if r == nil {
		return
	}
	r.keeperProgressMu.Lock()
	if r.keeperProgress != nil {
		close(r.keeperProgress)
		r.keeperProgress = nil
	}
	r.keeperProgressMu.Unlock()
}

func (r *TaskRunner) keeperProgressSignal() <-chan struct{} {
	r.keeperProgressMu.Lock()
	defer r.keeperProgressMu.Unlock()
	if r.keeperProgress == nil {
		r.keeperProgress = make(chan struct{})
	}
	return r.keeperProgress
}

// awaitAssignmentScan holds a WORKER_ASSIGNMENT_NOTIFY until the Keeper
// poller has scanned up to the height it announces, or has recorded the
// assignment, bounded by AssignNotifyScanWait.
//
// The frame usually arrives before the poller has scanned the block it names.
// Refusing it then costs the JetStream redelivery delay (one second) before
// the frame is looked at again, although the scan it asks for typically lands
// tens of milliseconds later. Waiting for that scan here and then reading the
// record is the same check, made once the record can exist.
//
// It waits only when a poller is wired: without one nothing advances the
// cursor, and the frame is refused at once as before. It holds no runner lock
// while waiting -- the poller's effects take r.mu -- and it changes nothing
// about what the frame is checked against afterwards.
func (r *TaskRunner) awaitAssignmentScan(ctx context.Context, taskID string, taskHash codec.Hash, height uint64) {
	wait := r.cfg.AssignNotifyScanWait
	if r.cfg.WakeKeeperPoll == nil || height == 0 || wait <= 0 || r.cfg.Store == nil {
		return
	}
	startedAt := time.Now()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	rescan := time.NewTicker(assignNotifyRescan)
	defer rescan.Stop()
	scans := 0
	finish := func(cursor uint64, reason string) {
		if scans == 0 {
			// Already recorded on arrival: nothing was waited for.
			return
		}
		r.cfg.Trace.Event("assign_notify_scan_wait",
			tasktrace.Str("task", taskID), tasktrace.Hash("task_hash", taskHash),
			tasktrace.Uint("finalized_height", height), tasktrace.Uint("cursor_height", cursor),
			tasktrace.Int("scans_requested", scans), tasktrace.Str("outcome", reason),
			tasktrace.Millis("wait_ms", time.Since(startedAt)))
	}
	wake := true
	for {
		// Taken before the state is read, so progress landing between the
		// read and the select below is not missed.
		progress := r.keeperProgressSignal()
		cursor, err := r.cfg.Store.KeeperLastProcessedHeight(ctx)
		if err != nil {
			finish(cursor, "store_error")
			return
		}
		// Effects are applied before the cursor moves past their block, so
		// the record can exist before the cursor says so.
		if _, err := layout.GetInferRecord(ctx, r.cfg.Store, layout.StoredHash(taskHash)); err == nil {
			finish(cursor, "recorded")
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			finish(cursor, "store_error")
			return
		}
		if cursor >= height {
			finish(cursor, "scanned")
			return
		}
		if wake {
			r.wakeKeeperPoll()
			scans++
			wake = false
		}
		select {
		case <-ctx.Done():
			finish(cursor, "cancelled")
			return
		case <-deadline.C:
			finish(cursor, "timeout")
			return
		case <-progress:
		case <-rescan.C:
			// The last scan ended below the announced height; ask for
			// another rather than wait for the poll interval.
			wake = true
		}
	}
}
