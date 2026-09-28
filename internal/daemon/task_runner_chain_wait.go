package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// errChainStateWaiting marks a refusal that is the protocol's own clock rather
// than a fault: a chain state this node must have before it can act is not
// materialized yet, and the contract for that state is to wait for it.
//
// It changes no disposition. A wait was already retryable and already
// redelivered; what it changes is what the node says about itself, because a
// wait reported on the same line as a fault is a wait nobody can tell apart
// from a fault -- and the one that mattered took a trip through the Keeper
// contract to identify.
var errChainStateWaiting = errors.New("waiting for chain state")

// isChainStateWait reports whether a handler refused because it is waiting.
func isChainStateWait(err error) bool { return errors.Is(err, errChainStateWaiting) }

// errRepeatedChainStateWait marks a wait this process has already reported for
// this task-round at this block. The refusal is unchanged in every way that
// decides disposition -- still retryable, still a wait -- and changes one
// thing: it is not reported a second time. A block's first frame prints the
// line; the redeliveries that follow it inside the same block would print a
// copy of it, which is how five blocks of waiting reached the operator as 28
// lines.
var errRepeatedChainStateWait = errors.New("already reported at this height")

// isRepeatedChainStateWait reports whether a refusal is a copy of one this
// process has already reported.
func isRepeatedChainStateWait(err error) bool { return errors.Is(err, errRepeatedChainStateWait) }

// maxTrackedChainWaits bounds the per-task wait counters. A chain that never
// materializes a window keeps every affected frame in redelivery forever, so
// nothing else bounds how many task-rounds are waiting at once.
const maxTrackedChainWaits = 4096

// verifierWindowWait is the answer to a verifier candidate window that exists
// but is still SOURCE_FROZEN.
//
// keeper-interface-contract §4.4 writes the window header in the same transaction that
// accepts the infer receipt and materializes its members only when the Beacon at
// h_window = h0 + delta_w lands; §10.3 keeps the build index pending across
// every block that Beacon is missing. Meanwhile 04-task-execution-verification-and-settlement.md:285 lets a
// Builder broadcast OPEN_VERIFY as soon as it has accepted the receipt and holds
// the data, window or no window. So a candidate arriving here before the draw
// exists is the ordinary timeline, and interface-and-topic-list.md §5.9 says to wait.
//
// The milestone carries the wait count because one wait is that timeline and
// forty is a Beacon that never landed -- the shape that ends with the task's
// verify_open_deadline being swept.
func (r *TaskRunner) verifierWindowWait(taskID string, verifyRound uint32, height uint64, err error) error {
	waits := r.recordChainWait(chainWaitKey(taskID, verifyRound))
	r.cfg.Trace.Event("verifier_window_pending",
		tasktrace.Str("task", taskID),
		tasktrace.Uint("verify_round", uint64(verifyRound)),
		tasktrace.Uint("waits", waits),
		tasktrace.Uint("current_height", height),
		tasktrace.Err("reason", err))
	return builderclient.Retryable(fmt.Errorf("%w: %w", errChainStateWaiting, err))
}

// verifierWindowClosed is the other end of that wait: the window materialized,
// its handraise_close_height is behind the chain tip, and this node did not get
// a hand up in time. It is the terminal answer for the round -- a Permanent
// refusal, because no redelivery and no re-drive can reopen a closed window --
// and it drops the wait counter it is ending.
//
// It is traced as its own milestone rather than folded into the pending line
// because the two say opposite things to an operator. `verifier_window_pending`
// with a rising count is "still waiting, may still succeed"; this is "the
// interval is over, this task-round produced no candidacy", which is the line
// that explains a task later swept for INSUFFICIENT_VERIFIER.
func (r *TaskRunner) verifierWindowClosed(taskID string, verifyRound uint32, height uint64, err error) error {
	waits := r.chainWaitCount(chainWaitKey(taskID, verifyRound))
	r.forgetChainWait(chainWaitKey(taskID, verifyRound))
	r.cfg.Trace.ErrorEvent("verifier_window_closed",
		tasktrace.Str("task", taskID),
		tasktrace.Uint("verify_round", uint64(verifyRound)),
		tasktrace.Uint("waits", waits),
		tasktrace.Uint("current_height", height),
		tasktrace.Err("reason", err))
	return builderclient.Permanent(fmt.Errorf("verifier handraise window for task %s round %d closed before this node raised a hand: %w",
		taskID, verifyRound, err))
}

func chainWaitKey(taskID string, verifyRound uint32) string {
	return fmt.Sprintf("verifier-window:%s:%d", taskID, verifyRound)
}

func revealPhaseWaitKey(taskID string, verifyRound uint64) string {
	return fmt.Sprintf("reveal-phase:%s:%d", taskID, verifyRound)
}

// revealPhaseWaitTraceInterval damps the reveal wait to a periodic reminder.
//
// verifierWindowWait can print on every occurrence because a NATS redelivery is
// what drives it. This wait is driven by the poll loop instead, which asks once
// a PollInterval (one second by default) and gets the same answer until a Keeper
// event lands -- so an unmodulated line would be one per second for the whole
// reveal window. The first wait always prints, because "the commit landed and
// the reveal is now pending" is the state transition an operator is looking for;
// after that the count carries the duration.
const revealPhaseWaitTraceInterval = 300

// revealPhaseWait reports a verify responsibility that is committed and idle
// because the chain has not opened its reveal phase.
//
// This is the state that used to be invisible. A Verifier that had committed
// went on attempting a reveal the Keeper handler must refuse -- Task-04 admits
// MsgSubmitVerifyResult only after EventRevealPhaseStarted -- and the retries
// looked identical to a broken reveal. The wait is now its own milestone, and
// keeper_reveal_phase_started (task_runner_run.go) is the line that ends it.
func (r *TaskRunner) revealPhaseWait(taskID string, verifyRound uint64, tip chainTip) {
	waits := r.recordChainWait(revealPhaseWaitKey(taskID, verifyRound))
	if waits != 1 && waits%revealPhaseWaitTraceInterval != 0 {
		return
	}
	r.cfg.Trace.Event("verify_reveal_awaiting_phase",
		tasktrace.Str("task", taskID),
		tasktrace.Uint("verify_round", verifyRound),
		tasktrace.Uint("waits", waits),
		tasktrace.Uint("chain_height", tip.height))
}

// recordChainWait counts one wait and returns how many this process has counted
// for that key. At the cap the counters restart rather than grow: the count is
// an operator's hint, and bounded memory outranks an exact tally in the one
// situation that reaches the cap.
func (r *TaskRunner) recordChainWait(key string) uint64 {
	r.waitMu.Lock()
	defer r.waitMu.Unlock()
	if r.chainWaits == nil {
		r.chainWaits = make(map[string]uint64)
	}
	if len(r.chainWaits) >= maxTrackedChainWaits {
		clear(r.chainWaits)
	}
	r.chainWaits[key]++
	return r.chainWaits[key]
}

// chainWaitCount reports how many waits this process has counted for a key
// without counting another one.
func (r *TaskRunner) chainWaitCount(key string) uint64 {
	r.waitMu.Lock()
	defer r.waitMu.Unlock()
	return r.chainWaits[key]
}

// forgetChainWait drops a counter once the state it was waiting for arrived, so
// the map holds what is waiting now rather than everything that ever waited.
func (r *TaskRunner) forgetChainWait(key string) {
	r.waitMu.Lock()
	defer r.waitMu.Unlock()
	delete(r.chainWaits, key)
}

// revealDeadlineRecoveryInterval is how many waits pass between two re-reads of
// a parked responsibility's reveal deadline. The first wait always re-reads,
// because a responsibility that is already past its reveal phase has to be
// released now and not in five seconds; after that the interval is what keeps a
// normal wait -- which is most of them, since the reveal phase legitimately
// opens some blocks after the commit -- from turning into one Keeper query per
// second per responsibility.
const revealDeadlineRecoveryInterval = 5

// recoverRevealDeadline re-reads the reveal deadline of a committed verify
// responsibility that has none, and records it.
//
// RevealDeadlineHeight has exactly one writer, ReconcilerEffectRevealReady, and
// the event behind it is consumed once before the poll cursor moves past it for
// good. That made a single missed delivery permanent: the responsibility parks
// on awaitingRevealPhase holding a commit that is already on chain, does
// nothing further, and the round closes INSUFFICIENT_VERIFIER having been told
// exactly once what it needed to know (#44). The chain still holds the answer,
// so a parked responsibility asks for it rather than waiting on a delivery that
// has already happened.
//
// Zero is the ordinary answer here, not a failure: keeper §10.7 writes
// reveal_deadline_height inside the StartRevealPhase transition, so before that
// the assignment carries none. Zero, an unreadable Keeper, a snapshot for
// another round and a refused merge all return 0 and leave the caller waiting,
// because every one of them means this read is not the authority.
func (r *TaskRunner) recoverRevealDeadline(ctx context.Context, hash codec.Hash, task store.VerifyTask) uint64 {
	if r.cfg.TaskReader == nil || r.cfg.Store == nil {
		return 0
	}
	if r.chainWaitCount(revealPhaseWaitKey(task.TaskID, task.VerifyRound))%revealDeadlineRecoveryInterval != 0 {
		return 0
	}
	snapshot, err := r.cfg.TaskReader.Task(ctx, task.SessionID, task.TaskID)
	if err != nil {
		return 0
	}
	assignment := snapshot.VerifierAssignment
	// The round is checked because the deadline is per round: round 2 opening
	// its reveal phase says nothing about a round 1 responsibility, and writing
	// one onto the other would hand internal/verifier an expiry_height that
	// belongs to a different frozen preimage.
	if assignment.VerifyRound.Uint64() != task.VerifyRound {
		return 0
	}
	deadline := assignment.RevealDeadlineHeight.Uint64()
	if deadline == 0 {
		return 0
	}
	record, err := layout.GetVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(hash))
	if err != nil || record.TaskID == "" {
		return 0
	}
	record.RevealDeadlineHeight = deadline
	if err := layout.MergeVerify(ctx, r.cfg.Store, layout.StoredHash(hash), record); err != nil {
		// A conflict means another writer already deposited a different value.
		// That one came from the authoritative effect and this read did not, so
		// the merge losing is the correct outcome, not something to report.
		return 0
	}
	r.forgetChainWait(revealPhaseWaitKey(task.TaskID, task.VerifyRound))
	r.cfg.Trace.Event("verify_reveal_deadline_recovered",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", hash),
		tasktrace.Uint("verify_round", task.VerifyRound),
		tasktrace.Uint("reveal_deadline_height", deadline))
	return deadline
}
