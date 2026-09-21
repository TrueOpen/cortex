package daemon

import (
	"context"
	"fmt"
	"slices"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/tasktrace"
	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
	"google.golang.org/protobuf/proto"
)

// The Worker order re-drive: the pending-handraise scheduler for a node that
// was busy when the call arrived.
//
// Why it is needed, and why it could not simply be left to redelivery.
// `trueopen.task.open.*` is Core tier (interface-and-topic-list.md §5.1, and the table in
// builderclient/envelope.go says so in code), and Core is fire-and-forget. The
// builderclient.Retryable verdict a busy node now returns is honoured by the
// two layers that can honour it -- the inbox drops its admission entry and the
// authenticator releases the replay claim, so the frame is admissible again --
// but nothing redelivers it. Without something local holding the intent, "busy
// for one task" and "refused this order for good" are the same outcome.
//
// This is the Worker twin of the Verifier re-drive in
// task_runner_handraise_redrive.go and follows it deliberately: same bounded
// map, same height-moved gate, same arming rule (retryable and nothing else),
// same process-local lifetime. The two are not merged because what they replay
// is different -- an OrderBroadcast frame against a chain-expiry height, versus
// a verify round against a candidate window -- and folding them would need one
// of the two bounds to be invented for the other.
//
// What it deliberately is not. It is not durable, for the same reason the
// Verifier one is not: nothing has been signed at the point it is armed, so no
// commitment survives a restart to be honoured, and internal/store holds
// restart obligations only. It is not a second admission path either -- a due
// entry re-enters admitOrder, which re-derives the task hash from the signed
// order, re-reads the chain tip, re-checks the order deadline and re-runs the
// full eligibility precheck. The only thing skipped is envelope authentication,
// which already happened once for these exact bytes; re-running it would refuse
// the entry on the envelope TTL (30 s) long before the capacity it is waiting
// for returns, which is to say a re-drive that re-authenticated could never
// fire.
const (
	// maxTrackedOrderRedrives bounds the pending set. An order normally leaves
	// it within its own expiry window, but a chain whose height cannot be read
	// has no height to expire against, so the map needs a ceiling of its own.
	maxTrackedOrderRedrives = 1024
	// maxOrderRedriveAttempts bounds one order when the tip is unreadable and
	// the height bound cannot be evaluated. With a readable tip the order's own
	// order_expire_height ends the wait.
	maxOrderRedriveAttempts = 32
)

// workerOrderRedrive is one broadcast order still owed a handraise attempt.
type workerOrderRedrive struct {
	subject  string
	envelope builderclient.BusEnvelope
	order    *busv1.OrderBroadcastV1
	taskID   string
	// expireHeight is the order's own order_expire_height, the authoritative
	// bound: past it the order cannot be handraised for by anyone.
	expireHeight            uint64
	firstHeight, lastHeight uint64
	attempts                uint64
}

// abandonedOrderRedrive is one order the re-drive stopped owing an attempt,
// paired with the bound that ended it.
type abandonedOrderRedrive struct {
	pending workerOrderRedrive
	reason  string
}

// updateWorkerOrderRedrive records what one attempt means for the next.
//
// Only a retryable refusal is owed another: an unmarked error is a frame
// contradicting Keeper authority or this node's own configuration, and a
// Permanent one is a closed question. Re-driving either would be re-deciding
// something already decided, on a schedule.
//
// A successful admission also clears the entry, and that includes the case
// where the precheck declined without signing -- admitOrder returns nil there,
// because a precheck rejection with a reject code is a decision and not a
// not-yet.
func (r *TaskRunner) updateWorkerOrderRedrive(subject string, envelope builderclient.BusEnvelope, order *busv1.OrderBroadcastV1, taskID string, expireHeight uint64, tip chainTip, err error) {
	key := subject + "\x00" + taskID
	if err == nil || !builderclient.IsRetryable(err) {
		r.orderRedriveMu.Lock()
		delete(r.orderRedrives, key)
		r.orderRedriveMu.Unlock()
		return
	}
	r.orderRedriveMu.Lock()
	defer r.orderRedriveMu.Unlock()
	if r.orderRedrives == nil {
		r.orderRedrives = make(map[string]*workerOrderRedrive)
	}
	pending, ok := r.orderRedrives[key]
	if !ok {
		if len(r.orderRedrives) >= maxTrackedOrderRedrives {
			r.evictOldestOrderRedriveLocked()
		}
		pending = &workerOrderRedrive{subject: subject, taskID: taskID}
		r.orderRedrives[key] = pending
	}
	// proto.Clone because the decoded payload belongs to the frame the delivery
	// callback owns, and this outlives that callback.
	pending.envelope, pending.order = envelope, proto.Clone(order).(*busv1.OrderBroadcastV1)
	pending.expireHeight = expireHeight
	if pending.firstHeight == 0 && tip.readable {
		pending.firstHeight = tip.height
	}
	pending.attempts++
	pending.lastHeight = tip.height
}

// evictOldestOrderRedriveLocked drops the entry armed earliest, which is the one
// closest to its own order expiring. Refusing the new entry instead would keep
// an order that can no longer be won and discard one that still can.
func (r *TaskRunner) evictOldestOrderRedriveLocked() {
	oldestKey, oldest := "", uint64(0)
	for key, pending := range r.orderRedrives {
		if oldestKey == "" || pending.firstHeight < oldest {
			oldestKey, oldest = key, pending.firstHeight
		}
	}
	delete(r.orderRedrives, oldestKey)
}

// takeWorkerOrderRedrives splits the pending set into the orders whose bound has
// passed - removed here, reported by the caller - and those due for another
// attempt now.
//
// Due is gated on the chain height having moved, for the reason the Verifier
// re-drive gives: capacity frees when a task completes, which is not a
// sub-block event, and without the gate a one-second poll interval would put
// several identical eligibility passes per block on the Keeper for every
// waiting order.
func (r *TaskRunner) takeWorkerOrderRedrives(tip chainTip) (abandoned []abandonedOrderRedrive, due []workerOrderRedrive) {
	r.orderRedriveMu.Lock()
	defer r.orderRedriveMu.Unlock()
	keys := make([]string, 0, len(r.orderRedrives))
	for key := range r.orderRedrives {
		keys = append(keys, key)
	}
	// Deterministic order: the pending set is a map, and a re-drive publishes.
	slices.Sort(keys)
	for _, key := range keys {
		pending := r.orderRedrives[key]
		if reason := orderRedriveExpiry(pending, tip); reason != "" {
			abandoned = append(abandoned, abandonedOrderRedrive{pending: *pending, reason: reason})
			delete(r.orderRedrives, key)
			continue
		}
		if tip.readable && pending.lastHeight >= tip.height {
			continue
		}
		due = append(due, *pending)
	}
	return abandoned, due
}

// orderRedriveExpiry names why an order is abandoned, or "" while it is still
// owed an attempt.
func orderRedriveExpiry(pending *workerOrderRedrive, tip chainTip) string {
	if tip.readable && pending.expireHeight > 0 && tip.height >= pending.expireHeight {
		return fmt.Sprintf("order_expire_height %d reached at chain height %d", pending.expireHeight, tip.height)
	}
	if pending.attempts >= maxOrderRedriveAttempts {
		return fmt.Sprintf("order re-drive attempts reached the bound %d", maxOrderRedriveAttempts)
	}
	return ""
}

// redriveWorkerOrders is the poll loop's half. It never returns an error: it is
// called from RunOnce, whose error stops the daemon, and nothing about one
// order's handraise is worth the node's chain view.
func (r *TaskRunner) redriveWorkerOrders(ctx context.Context, tip chainTip) {
	if r == nil || ctx.Err() != nil || r.cfg.LocalWorkerAddress == "" {
		return
	}
	abandoned, due := r.takeWorkerOrderRedrives(tip)
	for _, expired := range abandoned {
		r.cfg.Trace.ErrorEvent("worker_order_abandoned",
			tasktrace.Str("task", expired.pending.taskID),
			tasktrace.Uint("attempts", expired.pending.attempts),
			tasktrace.Uint("first_height", expired.pending.firstHeight),
			tasktrace.Uint("order_expire_height", expired.pending.expireHeight),
			tasktrace.Uint("chain_height", tip.height),
			tasktrace.Str("reason", expired.reason))
		if r.cfg.Diagnostic != nil {
			r.cfg.Diagnostic(TaskRunnerDiagnostic{
				Source: "worker_order_redrive", Record: expired.pending.taskID,
				Error: "Worker handraise abandoned: " + expired.reason, Count: int64(expired.pending.attempts),
			})
		}
	}
	for _, pending := range due {
		if ctx.Err() != nil {
			return
		}
		// admitOrder re-arms or clears the entry itself, on its own deferred
		// bookkeeping. Doing it again here would count one attempt twice against
		// the cap that ends an unbounded wait.
		err := r.admitOrder(ctx, pending.subject, pending.envelope, pending.order)
		if err == nil || r.cfg.Diagnostic == nil {
			continue
		}
		r.cfg.Diagnostic(TaskRunnerDiagnostic{
			Source: "worker_order_redrive", Record: pending.taskID, Error: err.Error(),
		})
	}
}
