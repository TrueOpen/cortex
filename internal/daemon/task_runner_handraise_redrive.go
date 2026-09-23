package daemon

import (
	"context"
	"fmt"
	"slices"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// The Verifier handraise re-drive: the local scheduler that gives a Core-tier
// handraise trigger a second chance.
//
// Why it has to exist. A Builder may broadcast OPEN_VERIFY as soon as it has
// accepted the infer receipt and holds the data (04-task-execution-verification-and-settlement.md:285),
// while the verifier candidate window a handraise must bind to only
// materializes when the Beacon at h_window = h0 + delta_w lands
// (keeper-interface-contract §4.4). So the ordinary timeline puts the call BEFORE the state
// the call cannot be answered without, and interface-and-topic-list.md §5.9 tells the
// candidate to wait. But `trueopen.verify.open.*` is Core tier (§5.1), and Core is
// fire-and-forget: the handler's builderclient.Retryable verdict promises a
// redelivery that no transport performs (internal/outbox/inbox_runner.go names
// this: "OPEN_VERIFY is Core (§5.1) and has no redelivery"). The wait therefore
// lived on one handler's stack and was lost when the function returned.
//
// Measured on trueopen-localnet-1 at devnet heights 46055-46085: delta_w = 5, the
// Builder re-sent OPEN_VERIFY four times inside h0..h0+4, the window turned
// READY at h0+5 with this node among its three members, and its
// handraise_close_height was h0+12 -- eight open blocks during which nothing
// asked again. Six consecutive tasks produced zero
// MsgSubmitVerifierHandraises; the three that ever succeeded on that chain did
// so only because a frame happened to land after h0+delta_w.
//
// What it deliberately is not. The pending trigger is process-local, not
// durable. Nothing has been signed at the point it is armed -- the signature
// binds the candidate member reference and the expiry height that the window
// this is waiting for has not published yet -- so there is no commitment a
// restart would have to honour, and internal/store holds restart obligations
// only. A restart inside the window loses the trigger exactly as it loses every
// other Core frame in flight, and the node then reaches the task through the
// Keeper snapshot if the chain selects it anyway.
const (
	// maxTrackedHandraiseRedrives bounds the pending set. Entries normally leave
	// it within one window, but a chain whose height cannot be read has no
	// height bound to expire against, so the map needs a ceiling of its own.
	maxTrackedHandraiseRedrives = 4096
	// maxHandraiseRedriveAttempts bounds a single task-round when the chain tip
	// is unreadable and the height bound below cannot be evaluated. It is the
	// fallback, not the primary rule: with a readable tip the window's own clock
	// ends the wait.
	maxHandraiseRedriveAttempts = 64
)

// verifierHandraiseRedrive is one task-round still owed a handraise attempt.
type verifierHandraiseRedrive struct {
	trigger verifierHandraiseTrigger
	// firstHeight is the chain height of the first attempt and giveUpHeight the
	// height past which this round is abandoned. Both are zero when the tip was
	// unreadable at arming time, which is what makes the attempt cap the only
	// bound in that case.
	firstHeight, lastHeight, giveUpHeight uint64
	attempts                              uint64
}

// abandonedHandraiseRedrive is one round the re-drive stopped owing an attempt,
// paired with the bound that ended it.
type abandonedHandraiseRedrive struct {
	pending verifierHandraiseRedrive
	reason  string
}

// updateVerifierHandraiseRedrive records what one attempt means for the next
// one. Only a retryable refusal is owed another attempt: an unmarked error is a
// frame contradicting Keeper authority and a Permanent one is a closed window,
// and re-driving either would be re-deciding a question the chain has answered.
func (r *TaskRunner) updateVerifierHandraiseRedrive(trigger verifierHandraiseTrigger, tip chainTip, err error) {
	key := chainWaitKey(trigger.TaskID, trigger.VerifyRound)
	if err == nil || !builderclient.IsRetryable(err) {
		r.forgetVerifierHandraiseRedrive(key)
		return
	}
	r.redriveMu.Lock()
	defer r.redriveMu.Unlock()
	if r.handraiseRedrives == nil {
		r.handraiseRedrives = make(map[string]*verifierHandraiseRedrive)
	}
	pending, ok := r.handraiseRedrives[key]
	if !ok {
		if len(r.handraiseRedrives) >= maxTrackedHandraiseRedrives {
			r.evictOldestRedriveLocked()
		}
		pending = &verifierHandraiseRedrive{trigger: trigger}
		r.handraiseRedrives[key] = pending
	}
	// The bound is set by the first attempt that had a chain view, not
	// necessarily the first attempt: a node whose chain was unreadable when the
	// call arrived still gets a height bound once it can read one, instead of
	// spending its whole attempt budget unbounded.
	//
	// The span is the deployment's verify deadline delta because the two heights
	// that would bound this exactly -- h_window and h_handraise_close -- are
	// what an unmaterialized window does not publish. It is the same span the
	// handraise expiry falls back to when the window cannot be read at all.
	if pending.firstHeight == 0 && tip.readable {
		pending.firstHeight = tip.height
		pending.giveUpHeight = tip.height + r.cfg.VerifyDeadlineDeltaHeight
	}
	pending.attempts++
	pending.lastHeight = tip.height
	// The sender fields are the frame's; a later frame for the same task-round
	// carries the same Keeper-checked content, so keeping the newest trigger
	// keeps the freshest sender without changing what is attempted.
	pending.trigger = trigger
}

func (r *TaskRunner) forgetVerifierHandraiseRedrive(key string) {
	r.redriveMu.Lock()
	defer r.redriveMu.Unlock()
	delete(r.handraiseRedrives, key)
}

// evictOldestRedriveLocked makes room by dropping the entry armed earliest,
// which is the one closest to its own window closing. Refusing the new entry
// instead would keep a round that can no longer succeed and discard one that
// still can.
func (r *TaskRunner) evictOldestRedriveLocked() {
	oldestKey, oldest := "", uint64(0)
	for key, pending := range r.handraiseRedrives {
		if oldestKey == "" || pending.firstHeight < oldest {
			oldestKey, oldest = key, pending.firstHeight
		}
	}
	delete(r.handraiseRedrives, oldestKey)
}

// takeVerifierHandraiseRedrives splits the pending set into the rounds whose
// bound has passed - removed here, reported by the caller - and the triggers due
// for another attempt now.
//
// Due is gated on the chain height having moved. The state being waited for
// materializes at a block boundary, so a second query inside one height can only
// return the answer the first one did; without the gate a one-second poll
// interval would put five identical queries per block on the Keeper for every
// waiting task.
func (r *TaskRunner) takeVerifierHandraiseRedrives(tip chainTip) (abandoned []abandonedHandraiseRedrive, due []verifierHandraiseTrigger) {
	r.redriveMu.Lock()
	defer r.redriveMu.Unlock()
	keys := make([]string, 0, len(r.handraiseRedrives))
	for key := range r.handraiseRedrives {
		keys = append(keys, key)
	}
	// Deterministic order: the pending set is a map, and a re-drive publishes.
	slices.Sort(keys)
	for _, key := range keys {
		pending := r.handraiseRedrives[key]
		if reason := redriveExpiry(pending, tip); reason != "" {
			abandoned = append(abandoned, abandonedHandraiseRedrive{pending: *pending, reason: reason})
			delete(r.handraiseRedrives, key)
			continue
		}
		if tip.readable && pending.lastHeight >= tip.height {
			continue
		}
		due = append(due, pending.trigger)
	}
	return abandoned, due
}

// redriveExpiry names why a round is abandoned, or "" while it is still owed an
// attempt.
func redriveExpiry(pending *verifierHandraiseRedrive, tip chainTip) string {
	if tip.readable && pending.giveUpHeight > 0 && tip.height > pending.giveUpHeight {
		return fmt.Sprintf("verify deadline bound height %d passed at chain height %d", pending.giveUpHeight, tip.height)
	}
	if pending.attempts >= maxHandraiseRedriveAttempts {
		return fmt.Sprintf("handraise re-drive attempts reached the bound %d", maxHandraiseRedriveAttempts)
	}
	return ""
}

// redriveVerifierHandraises is the poll loop's half of the re-drive. It never
// returns an error: it is called from RunOnce, whose error stops the daemon, and
// nothing about one task's handraise is worth the node's chain view.
func (r *TaskRunner) redriveVerifierHandraises(ctx context.Context, tip chainTip) {
	if r == nil || ctx.Err() != nil {
		return
	}
	abandoned, due := r.takeVerifierHandraiseRedrives(tip)
	for _, expired := range abandoned {
		taskID := expired.pending.trigger.TaskID
		r.cfg.Trace.ErrorEvent("verifier_handraise_abandoned",
			tasktrace.Str("task", taskID),
			tasktrace.Uint("verify_round", uint64(expired.pending.trigger.VerifyRound)),
			tasktrace.Uint("attempts", expired.pending.attempts),
			tasktrace.Uint("first_height", expired.pending.firstHeight),
			tasktrace.Uint("current_height", tip.height),
			tasktrace.Str("reason", expired.reason))
		r.forgetChainWait(chainWaitKey(taskID, expired.pending.trigger.VerifyRound))
		if r.cfg.Diagnostic != nil {
			r.cfg.Diagnostic(TaskRunnerDiagnostic{
				Source: "verifier_handraise_redrive", Record: taskID,
				Error: "Verifier handraise abandoned: " + expired.reason, Count: int64(expired.pending.attempts),
			})
		}
	}
	for _, trigger := range due {
		if ctx.Err() != nil {
			return
		}
		err := r.raiseVerifierHand(ctx, trigger)
		if err == nil || r.cfg.Diagnostic == nil || isRepeatedChainStateWait(err) {
			continue
		}
		r.cfg.Diagnostic(TaskRunnerDiagnostic{
			Source: "verifier_handraise_redrive", Record: trigger.TaskID,
			Error: err.Error(), Waiting: isChainStateWait(err),
		})
	}
}
