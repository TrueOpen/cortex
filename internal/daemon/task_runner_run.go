package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// responsibilityKey names one role's attempt at one task hash. Both halves are
// needed: the Worker and the Verifier responsibilities for a task live in
// separate documents under the same task_hash, and a node that holds both is
// running two independent executions.
type responsibilityKey struct {
	role string
	hash codec.Hash
}

// taskOutcome is one finished attempt at one responsibility: what the executor
// returned, or the reason it was never called.
type taskOutcome struct {
	role     string
	hash     codec.Hash
	infer    store.InferTask
	verify   store.VerifyTask
	terminal bool
	err      error
	// stopReason fails the responsibility without having run it. It is
	// applied after the execution merge, which by contract carries only the
	// stage and the output/receipt fields across and would otherwise drop
	// the reason - and the reason is the only place an operator learns why
	// the task stopped.
	stopReason string
	// finishedAt is when the executor returned, not when the pass began.
	// The retry clock is measured from it for the reason recordRetrySchedule
	// gives: a run that outlasts the retry delay would otherwise be due the
	// instant it failed.
	finishedAt time.Time
}

// RunOnce is one scheduling pass that waits for every execution it started.
//
// It exists for the callers that need a pass to be observable the moment it
// returns -- seed a record, run a tick, read the durable outcome back. Run does
// NOT use it, and the split is the whole fix: waiting here is what used to make
// a newly admitted task sit out the remaining execution time of the previous
// pass. See dispatch.
func (r *TaskRunner) RunOnce(ctx context.Context) error {
	batch, err := r.dispatch(ctx)
	if err != nil {
		return err
	}
	batch.Wait()
	return r.takeExecutionFailure()
}

// dispatch restores the two independent active-task documents with exactly two
// point reads, then starts an executor for every responsibility that is due and
// does not already have one. Terminal responsibilities never appear because
// their Keeper effects delete them from the owning document.
//
// It returns without waiting for those executors, and that is the fix for a
// measured stall. Scheduling used to be round-based: a pass launched everything
// it had found and then blocked on the entire set before the loop could reach
// the select that consumes r.wakeup. A task the chain admitted mid-pass could
// therefore be started by neither the running pass (it had already read its
// documents) nor the wake-up the admission published (nothing reads that channel
// until the pass returns), so it waited out unrelated work. On devnet a Worker
// admitted at 07:05:22.481 entered the model at 07:05:29.496 -- 0.32s after the
// verify that was holding the round finished at 07:05:29.178, seven seconds of a
// GPU it was queued for.
//
// MAX_CONCURRENCY never addressed this and could not: r.slots bounds how many
// executions run at once, not whether a new responsibility may join a pass
// already in progress. The node that produced the measurement had four slots and
// two executions.
//
// Removing the wait leaves r.slots as the only gate, so an admitted task now
// waits for a free slot and nothing else. Two invariants that the round boundary
// used to supply for free are carried explicitly instead: claimInflight keeps a
// second executor off a responsibility that already has one, and applyOutcome
// writes the one record an outcome belongs to rather than the whole snapshot.
func (r *TaskRunner) dispatch(ctx context.Context) (*sync.WaitGroup, error) {
	batch := &sync.WaitGroup{}
	if r == nil || r.cfg.Store == nil {
		return batch, fmt.Errorf("task runner store is required")
	}
	r.mu.Lock()
	infer, verify, err := r.loadActiveTasks(ctx)
	if err != nil {
		r.mu.Unlock()
		return batch, err
	}
	r.infer, r.verify = infer, verify
	// The pass walks its own copies. r.infer and r.verify are now written by
	// outcomes landing from executions this pass does not own and cannot wait
	// for, so the live maps belong exclusively to r.mu holders; ranging over them
	// outside the lock was the one data race the round boundary had been hiding.
	infer, verify = copyInfer(infer), copyVerify(verify)
	r.mu.Unlock()

	tip := r.currentChainTip(ctx)
	// Before the due responsibilities, because this is the step that decides
	// whether there will BE one: a Verifier candidate that never got its
	// handraise out is never selected, so no verify document ever exists for the
	// loop below to find. It runs outside r.mu on purpose - it publishes and
	// waits on the chain - and it swallows its own errors, because a scheduling
	// pass returning one stops the daemon.
	r.redriveVerifierHandraises(ctx, tip)
	// And the Worker half of the same problem. trueopen.task.open.* is Core tier
	// too, so a busy node's retryable refusal has no transport to honour it;
	// this is where an order held over from a full moment gets its next attempt.
	// Same placement and same reason: it decides whether a responsibility will
	// exist at all, and it swallows its own errors because a scheduling pass
	// returning one stops the daemon.
	r.redriveWorkerOrders(ctx, tip)
	now := time.Now().UTC()
	launch := func(key responsibilityKey, run func() taskOutcome) {
		if !r.claimInflight(key) {
			return
		}
		batch.Add(1)
		r.executions.Add(1)
		go func() {
			defer batch.Done()
			defer r.executions.Done()
			// Released after the outcome is durable, never before: the record of
			// a running task still reads "queued" until this goroutine writes it,
			// so a pass that saw the claim gone would read that stale document
			// and start the same work a second time.
			defer r.releaseInflight(key)
			r.slots <- struct{}{}
			// The slot is returned on every exit -- success, failure, panic
			// unwinding -- because it is the node's whole admission budget for
			// model work. Leaking one against MaxConcurrency=1 is the node.
			//
			// It covers the model call and stops there. Writing the outcome waits
			// on r.mu, which a Nexus control handler can hold across a chain
			// query, and a slot held through that is GPU time nobody is using.
			slot := sync.OnceFunc(func() { <-r.slots })
			defer slot()
			outcome := run()
			slot()
			if err := r.applyOutcome(ctx, outcome); err != nil {
				r.recordExecutionFailure(err)
			}
		}()
	}
	launchInfer := func(hash codec.Hash, task store.InferTask) {
		launch(responsibilityKey{role: "infer", hash: hash}, func() taskOutcome {
			updated, terminal, runErr := r.cfg.InferExecutor.RunInfer(ctx, hash, task)
			return taskOutcome{role: "infer", hash: hash, infer: updated, terminal: terminal, err: runErr, finishedAt: time.Now().UTC()}
		})
	}
	launchVerify := func(hash codec.Hash, task store.VerifyTask) {
		launch(responsibilityKey{role: "verify", hash: hash}, func() taskOutcome {
			updated, terminal, runErr := r.cfg.VerifyExecutor.RunVerify(ctx, hash, task)
			return taskOutcome{role: "verify", hash: hash, verify: updated, terminal: terminal, err: runErr, finishedAt: time.Now().UTC()}
		})
	}
	for hash, task := range infer {
		// A responsibility this process is already executing is not reconsidered
		// at all, not even for the stop checks below. The document this pass read
		// is the one the running executor started from, so every judgment made
		// from it -- due, expired, retry-exhausted -- is about a state that
		// attempt is in the middle of replacing.
		if r.executing(responsibilityKey{role: "infer", hash: hash}) {
			continue
		}
		deadline := inferDeadline(task)
		if reason := r.taskTerminalReason(tip, task.Stage, deadline, task.RetryCount); reason != "" {
			r.reportStoppedResponsibility("infer", task.TaskID, hash, tip, deadline, task.RetryCount, reason)
			if err := r.applyOutcome(ctx, taskOutcome{role: "infer", hash: hash, infer: task, stopReason: reason}); err != nil {
				return batch, err
			}
			continue
		}
		if task.AutoHalted {
			r.reportAutoHalted("infer", task.TaskID, hash, task.HaltCode, task.HaltReason)
			continue
		}
		if r.cfg.InferExecutor == nil || !r.taskDue(now, tip, task.Stage, task.RetryAtUnixMilli, deadline) {
			continue
		}
		reason, undecided := r.localObjectsRecoveryReason(ctx, hash, "infer", task.TaskID)
		if undecided {
			continue
		}
		if reason != "" {
			if err := r.applyOutcome(ctx, taskOutcome{role: "infer", hash: hash, infer: task, stopReason: reason}); err != nil {
				return batch, err
			}
			continue
		}
		launchInfer(hash, task)
	}
	for hash, task := range verify {
		// See the infer loop: an executing responsibility is left alone.
		if r.executing(responsibilityKey{role: "verify", hash: hash}) {
			continue
		}
		// Before any scheduling decision is made about it, because every one of
		// them reads the reveal deadline: verifyDeadline bounds a committed
		// responsibility by it, taskTerminalReason stops the task on it, and
		// awaitingRevealPhase parks on its absence. Recovering afterwards would
		// leave this pass deciding on a zero it has already replaced.
		if awaitingRevealPhase(task) {
			if recovered := r.recoverRevealDeadline(ctx, hash, task); recovered != 0 {
				task.RevealDeadlineHeight = recovered
				r.rememberRecoveredRevealDeadline(hash, task)
			}
		}
		deadline := verifyDeadline(task)
		if reason := r.taskTerminalReason(tip, task.Stage, deadline, task.RetryCount); reason != "" {
			r.reportStoppedResponsibility("verify", task.TaskID, hash, tip, deadline, task.RetryCount, reason)
			if err := r.applyOutcome(ctx, taskOutcome{role: "verify", hash: hash, verify: task, stopReason: reason}); err != nil {
				return batch, err
			}
			continue
		}
		if awaitingRevealPhase(task) {
			// Not due, and not a failure either: the commit is on chain and the
			// chain has not opened the reveal phase yet. Launching the verify
			// here is exactly what used to happen -- a reveal attempted before
			// REVEALING, refused by the Keeper handler, retried until the
			// responsibility burned its retry budget.
			r.revealPhaseWait(task.TaskID, task.VerifyRound, tip)
			continue
		}
		if task.AutoHalted {
			r.reportAutoHalted("verify", task.TaskID, hash, task.HaltCode, task.HaltReason)
			continue
		}
		if r.cfg.VerifyExecutor == nil || !r.taskDue(now, tip, task.Stage, task.RetryAtUnixMilli, deadline) {
			continue
		}
		reason, undecided := r.localObjectsRecoveryReason(ctx, hash, "verify", task.TaskID)
		if undecided {
			continue
		}
		if reason != "" {
			if err := r.applyOutcome(ctx, taskOutcome{role: "verify", hash: hash, verify: task, stopReason: reason}); err != nil {
				return batch, err
			}
			continue
		}
		launchVerify(hash, task)
	}
	return batch, nil
}

// applyOutcome makes one finished attempt durable, on its own, under r.mu.
//
// This used to be a batch: a pass collected every outcome of its round and wrote
// them all once the last executor had returned. Dropping the batch is not a
// mechanical consequence of dropping the round -- it is what makes overlapping
// executions safe to write. The batched path rewrote EVERY active record from
// the snapshot its pass had loaded, so a pass that overlapped a running
// execution would push that execution's pre-run stage back over whatever it had
// committed in the meantime. Writing only the record the outcome belongs to
// removes the whole class.
//
// The merge target is re-read from r.infer/r.verify rather than carried in from
// the pass that launched the attempt, for the same reason: a Keeper effect may
// have advanced the record while the executor ran, and merging into the launch
// snapshot would undo it. A record that is gone is not a failure -- a terminal
// effect deletes it while its executor is still unwinding, and there is then
// nothing left to write.
func (r *TaskRunner) applyOutcome(ctx context.Context, outcome taskOutcome) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if outcome.role == "infer" {
		current, ok := r.infer[outcome.hash]
		if !ok {
			return nil
		}
		updated := mergeInferExecution(current, outcome.infer)
		if outcome.stopReason != "" {
			updated.Stage, updated.LastError = "failed", outcome.stopReason
		}
		if outcome.err != nil {
			r.recordInferRetry(&updated, outcome.err, outcome.finishedAt, outcome.hash)
		}
		if outcome.terminal {
			delete(r.infer, outcome.hash)
			return layout.DeleteInferRecord(ctx, r.cfg.Store, layout.StoredHash(outcome.hash))
		}
		r.infer[outcome.hash] = updated
		return r.persistInferTaskToLayout(ctx, outcome.hash, updated)
	}
	current, ok := r.verify[outcome.hash]
	if !ok {
		return nil
	}
	updated := mergeVerifyExecution(current, outcome.verify)
	if outcome.stopReason != "" {
		updated.Stage, updated.LastError = "failed", outcome.stopReason
	}
	if outcome.err != nil {
		r.recordVerifyRetry(&updated, outcome.err, outcome.finishedAt, outcome.hash)
	}
	if outcome.terminal {
		delete(r.verify, outcome.hash)
		return layout.DeleteVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(outcome.hash))
	}
	r.verify[outcome.hash] = updated
	return r.persistVerifyTaskToLayout(ctx, outcome.hash, updated)
}

// rememberRecoveredRevealDeadline mirrors a reveal deadline just recovered from
// the chain into the live verify view, which is what ActiveTasks and the next
// outcome merge read. recoverRevealDeadline has already made it durable; this is
// only the in-memory copy, and it is skipped when the responsibility has since
// been released, so a terminal effect is not undone by a late mirror.
func (r *TaskRunner) rememberRecoveredRevealDeadline(hash codec.Hash, task store.VerifyTask) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, active := r.verify[hash]; active {
		r.verify[hash] = task
	}
}

// claimInflight marks one responsibility as having an executor goroutine in this
// process, and reports false when it already had one.
//
// The round boundary used to make this impossible to get wrong: no pass started
// until every execution of the previous one had finished, so no pass could see a
// record whose executor was still running. Passes overlap now, and the durable
// record of a running task still says "queued" -- the executor is what changes
// it -- so without this claim the very next poll tick would start a second
// executor for work already in the model. For a Worker that is two signed
// answers to one question; for a Verifier it is a second commit attempt against
// a round the first one is still committing.
func (r *TaskRunner) claimInflight(key responsibilityKey) bool {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	if r.inflight == nil {
		r.inflight = make(map[responsibilityKey]struct{})
	}
	if _, running := r.inflight[key]; running {
		return false
	}
	r.inflight[key] = struct{}{}
	return true
}

func (r *TaskRunner) releaseInflight(key responsibilityKey) {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	delete(r.inflight, key)
}

func (r *TaskRunner) executing(key responsibilityKey) bool {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	_, running := r.inflight[key]
	return running
}

// recordExecutionFailure parks the first durable write an asynchronously applied
// outcome could not complete, and wakes the loop so it is acted on at once
// rather than at the end of the poll interval. Only the first is kept: it is the
// one that explains the others.
func (r *TaskRunner) recordExecutionFailure(err error) {
	if err == nil {
		return
	}
	r.failureMu.Lock()
	if r.execFailure == nil {
		r.execFailure = err
	}
	r.failureMu.Unlock()
	r.Wake()
}

func (r *TaskRunner) takeExecutionFailure() error {
	r.failureMu.Lock()
	defer r.failureMu.Unlock()
	err := r.execFailure
	r.execFailure = nil
	return err
}

// localObjectsRecoveryReason gates one due responsibility on the local task
// objects the evidence index claims are committed. A process that finds them
// gone or corrupt must stop the task rather than redo the work: the signed
// material naming those exact bytes has already been produced, so a rerun
// would sign different bytes for the same task and there would be two answers
// to one question. A task cleanup already moved to trash/ is the same refusal
// for the opposite reason — those objects are retired, not lost — and it is
// reported separately so an operator can tell the two apart.
//
// The audit runs at most once per task per process. It answers a question about
// what a previous process left behind, and re-hashing every committed object of
// every active task on every poll tick would be I/O on the hot path buying
// nothing: corruption that appears mid-process is caught where the bytes are
// actually read.
//
// An error that is neither verdict is not a verdict at all. It leaves the
// document untouched and returns undecided, so the next tick asks again rather
// than failing a task over a transient stat.
func (r *TaskRunner) localObjectsRecoveryReason(ctx context.Context, hash codec.Hash, role, record string) (reason string, undecided bool) {
	if r == nil || r.cfg.Evidence == nil {
		return "", false
	}
	r.recoveryMu.Lock()
	_, checked := r.recoveryChecked[hash]
	r.recoveryMu.Unlock()
	if checked {
		return "", false
	}
	err := r.cfg.Evidence.VerifyTaskObjects(ctx, hash)
	if err == nil {
		r.markRecoveryChecked(hash)
		return "", false
	}
	if r.cfg.Diagnostic != nil {
		r.cfg.Diagnostic(TaskRunnerDiagnostic{Source: role, Record: record, Error: err.Error()})
	}
	if errors.Is(err, evidence.ErrEvidenceUnavailable) || errors.Is(err, evidence.ErrCleanupPending) {
		r.markRecoveryChecked(hash)
		return err.Error(), false
	}
	return "", true
}

func (r *TaskRunner) markRecoveryChecked(hash codec.Hash) {
	r.recoveryMu.Lock()
	defer r.recoveryMu.Unlock()
	if r.recoveryChecked == nil {
		r.recoveryChecked = make(map[codec.Hash]struct{})
	}
	r.recoveryChecked[hash] = struct{}{}
}

// taskDeadline is the chain height past which a responsibility stops being
// worth running, together with the name of the deadline that set it. The name
// is not cosmetic: a verify responsibility has three of them and an operator
// reading "deadline height 1033 passed" while the tip is 654 learns nothing.
//
// note carries what is owed at that deadline and cannot be paid. It reaches
// LastError and the trace, because "the window closed" and "the window closed
// and the protocol's remedy for it has no producer here" are different
// operational facts and only one of them is a reason to escalate upstream.
type taskDeadline struct {
	height uint64
	label  string
	note   string
}

// missingDataUnavailableRemedy is what a Verifier owes the chain when it lets a
// commit deadline pass without a commit, and cannot pay.
//
// 02-data-plane-and-evidence-transfer.md §5 gives the remedy: a selected Verifier that retried the
// fixed Task Builders and still could not obtain complete, commitment-checked
// data submits MsgReportDataUnavailable, marking the Builders that failed it with
// "a bitmap in Task Builder order". §7 makes it the only local failure that enters
// protocol attribution at all -- "local diagnostic information does not enter
// consensus".
//
// Cortex cannot build that bitmap. The order it must be expressed in is
// TaskBuilderSelectionState.selected_task_builders (keeper-data-structure-contract.md §6.5,
// the same frozen order §10.4/§10.5 derive the bitmap from), and the frozen
// task.v1.Query service registers no rpc that returns it: QueryTaskBuilders
// is named in the state's own contract but is not on the service, and no frozen
// task event carries the list either. MsgReportDataUnavailable itself IS
// registered ACTIVE (msg_verification.proto), and it refuses a bitmap with
// out-of-range or trailing bits -- so a guessed order is not a degraded report,
// it is a rejected tx and a Verifier that believes it reported when it did not.
//
// The step without an authoritative read is refused rather than guessed.
// Remove this note when the read lands and wire the producer beside it.
const missingDataUnavailableRemedy = "the V7b remedy (MsgReportDataUnavailable) is owed and cannot be submitted: its Task Builder bitmap must follow TaskBuilderSelectionState.selected_task_builders, and the frozen task.v1.Query service registers no rpc serving that list"

// inferDeadline is the infer deadline and nothing else. A Worker's whole
// responsibility ends at it.
func inferDeadline(task store.InferTask) taskDeadline {
	return taskDeadline{height: task.DeadlineHeight, label: "task deadline"}
}

// verifyDeadline is the height a verify responsibility stops being worth
// running at, and it is the COMMIT deadline whenever the chain published one.
//
// RunVerify is one call: confirm the output, re-run the model, sign the commit,
// submit it, then reveal. Every step after the commit exists to complete a
// commit the chain accepted, so once the commit window is shut the whole call
// can no longer reach a useful end -- and the verifier's own precheck says so,
// refusing the entire path with COMMIT_WINDOW_UNSAFE_FOR_BEACON_DELAY
// (internal/policy/verifier.go). That precheck judges the window against the
// height frozen into the responsibility when the chain admitted it, so on a
// retry it compares 313 with 633 forever and never fires. This is the same
// judgment against the live tip.
//
// verify_deadline stays the bound when the chain published no commit deadline:
// zero means "not known", never "already passed". Where both are known the
// earlier one wins, which today is always the commit deadline (a devnet round
// had 633 against 1033) but is not assumed to be.
//
// Once the commit is on chain the commit deadline stops bounding anything, and
// bounding a committed responsibility by it would be a bug with teeth: the
// reveal phase opens at or after the commit window closes, so a responsibility
// still measured against the commit deadline would be stopped by the runner at
// exactly the moment its reveal became legal.
func verifyDeadline(task store.VerifyTask) taskDeadline {
	if task.Stage == string(layout.StageCommitted) {
		if task.RevealDeadlineHeight > 0 &&
			(task.DeadlineHeight == 0 || task.RevealDeadlineHeight < task.DeadlineHeight) {
			return taskDeadline{height: task.RevealDeadlineHeight, label: "reveal deadline"}
		}
		return taskDeadline{height: task.DeadlineHeight, label: "task deadline"}
	}
	if task.CommitDeadlineHeight > 0 &&
		(task.DeadlineHeight == 0 || task.CommitDeadlineHeight < task.DeadlineHeight) {
		return taskDeadline{
			height: task.CommitDeadlineHeight,
			label:  "commit deadline",
			note:   missingDataUnavailableRemedy,
		}
	}
	return taskDeadline{height: task.DeadlineHeight, label: "task deadline"}
}

// awaitingRevealPhase reports the one state in which a verify responsibility is
// deliberately idle: its commit reached the chain and the chain has not started
// the reveal phase, so reveal_deadline_height is still unknown.
//
// The two conditions are one fact read twice. keeper §10.7 writes
// reveal_deadline_height only inside StartRevealPhase, so a zero here IS "the
// phase has not started" -- there is no second field to consult and no way for
// the two to disagree.
func awaitingRevealPhase(task store.VerifyTask) bool {
	return task.Stage == string(layout.StageCommitted) && task.RevealDeadlineHeight == 0
}

func (r *TaskRunner) taskDue(now time.Time, tip chainTip, stage string, retryAt int64, deadline taskDeadline) bool {
	if stage == "failed" || stage == "succeeded" {
		return false
	}
	if retryAt > 0 && now.Before(time.UnixMilli(retryAt)) {
		return false
	}
	if deadline.height > 0 {
		if tip.configured && !tip.readable {
			return false
		}
		if tip.readable && tip.height > deadline.height {
			return false
		}
	}
	return true
}

func (r *TaskRunner) taskTerminalReason(tip chainTip, stage string, deadline taskDeadline, attempts uint32) string {
	if stage == "failed" || stage == "succeeded" {
		return ""
	}
	if deadline.height > 0 && tip.readable && tip.height > deadline.height {
		reason := fmt.Sprintf("%s height %d passed at chain height %d", deadline.label, deadline.height, tip.height)
		if deadline.note != "" {
			reason += "; " + deadline.note
		}
		return reason
	}
	if int(attempts) >= r.cfg.MaxRetryAttempts {
		return fmt.Sprintf("task retry count %d reached the bound %d", attempts, r.cfg.MaxRetryAttempts)
	}
	return ""
}

// reportStoppedResponsibility makes a responsibility that stopped without
// running say so once, where an operator can see it. Until now a stop reason
// reached nothing but LastError in Pebble: on the wire the node simply went
// quiet after its last retry, which is the hardest shape there is to read --
// silence after 65 retries looks like a hung process, not a closed window.
func (r *TaskRunner) reportStoppedResponsibility(role, taskID string, taskHash codec.Hash, tip chainTip, deadline taskDeadline, attempts uint32, reason string) {
	if r.cfg.Diagnostic != nil {
		r.cfg.Diagnostic(TaskRunnerDiagnostic{Source: role, Record: taskID, Error: reason, Count: int64(attempts)})
	}
	r.cfg.Trace.ErrorEvent("responsibility_stopped",
		tasktrace.Str("role", role), tasktrace.Str("task", taskID),
		tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("deadline", deadline.label),
		tasktrace.Uint("deadline_height", deadline.height),
		tasktrace.Uint("chain_height", tip.height),
		tasktrace.Uint("retry_count", uint64(attempts)),
		tasktrace.Str("reason", reason))
}

// autoHaltReason names the failures that must stop the local scheduler from
// calling the model again for this responsibility, or "" when another attempt is
// legitimate.
//
// Two classes qualify and they qualify for different reasons.
// FaultDeterministic is pointless: the inputs are frozen by the assignment and
// the artifacts are bytes this node already holds, so a second run re-derives
// the same refusal. FaultRegenerationForbidden is worse than pointless: signed
// material naming the previous run's bytes already exists, so a second run
// would produce a second answer to one question.
//
// Everything else keeps the previous behaviour. An unclassified error is not
// evidence that retrying is useless, and treating it as one would turn a Nexus
// blip into a permanently stopped task.
func autoHaltReason(err error) (code, reason string) {
	switch modelservice.ClassOf(err) {
	case modelservice.FaultDeterministic, modelservice.FaultRegenerationForbidden:
	default:
		return "", ""
	}
	code = modelservice.FaultCode(err)
	if code == "" {
		code = strings.ToUpper(strings.ReplaceAll(modelservice.ClassOf(err).String(), "-", "_"))
	}
	return code, err.Error()
}

// retryAt is when a failed attempt becomes due again.
//
// Two things were wrong with what it replaces, and the first one had teeth. The
// delay was added to the timestamp taken at the TOP of RunOnce, before the
// executor ran -- so a generation that took longer than retry_delay produced a
// retry time already in the past, and the next tick re-entered the model
// immediately. With the devnet's 300 s infer timeout against a one-minute
// retry_delay that is not a shortened backoff, it is no backoff at all: 120
// back-to-back generations, each holding the node's only GPU. Measuring from
// the moment the attempt finished is what makes the configured delay mean what
// it says.
//
// The second is that a flat delay treats the tenth failure like the first. The
// growth is exponential and capped by MaxRetryDelay, which is a ceiling and not
// a target: most failures clear on the first or second retry and never reach it.
//
// The chain deadline needs no arithmetic here. A retry scheduled past it is
// never taken -- taskTerminalReason stops the responsibility the moment the tip
// passes the deadline height, ahead of any due check -- so the backoff cannot
// keep a dead responsibility alive, and converting heights to wall-clock to
// pre-empt that would require a block time this node is not told.
func (r *TaskRunner) retryAt(finishedAt time.Time, attempt uint32) time.Time {
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	delay := r.cfg.RetryDelay
	if delay <= 0 {
		delay = time.Minute
	}
	ceiling := r.cfg.MaxRetryDelay
	if ceiling < delay {
		ceiling = delay
	}
	// attempt is the count AFTER the increment, so the first failure shifts by
	// zero and waits exactly retry_delay. The shift is clamped well below the
	// width of a Duration; the ceiling below is what actually bounds it.
	if shift := attempt; shift > 1 {
		if shift > 20 {
			shift = 20
		}
		delay <<= shift - 1
	}
	if delay > ceiling || delay <= 0 {
		delay = ceiling
	}
	return finishedAt.Add(delay)
}

// applyRunFailure is the single place one failed attempt becomes durable state,
// shared by both roles because the decision is identical for them: halt, or
// schedule another attempt.
//
// A halt does NOT increment the retry count. The count exists to bound repeated
// attempts, and there will not be another one; leaving it alone keeps "stopped
// after 3 attempts because the model contradicted the order" distinguishable
// from "stopped after 120 attempts because nothing ever worked".
func (r *TaskRunner) applyRunFailure(role, taskID string, taskHash codec.Hash, err error, finishedAt time.Time,
	stage *string, retryCount *uint32, retryAt *int64, lastError *string, halt *bool, haltCode, haltReason *string) {
	*lastError = err.Error()
	if code, reason := autoHaltReason(err); code != "" {
		*halt, *haltCode, *haltReason = true, code, reason
		*stage = "failed"
		r.cfg.Trace.ErrorEvent("responsibility_auto_halted",
			tasktrace.Str("role", role), tasktrace.Str("task", taskID),
			tasktrace.Hash("task_hash", taskHash),
			tasktrace.Str("class", modelservice.ClassOf(err).String()),
			tasktrace.Str("code", code),
			tasktrace.Uint("retry_count", uint64(*retryCount)),
			tasktrace.Str("reason", reason))
		if r.cfg.Diagnostic != nil {
			r.cfg.Diagnostic(TaskRunnerDiagnostic{Source: role, Record: taskID, Error: "automatic execution halted: " + reason, Count: int64(*retryCount)})
		}
		return
	}
	*retryCount++
	*retryAt = r.retryAt(finishedAt, *retryCount).UnixMilli()
	if int(*retryCount) >= r.cfg.MaxRetryAttempts {
		*stage = "failed"
	}
	if r.cfg.Diagnostic != nil {
		r.cfg.Diagnostic(TaskRunnerDiagnostic{Source: role, Record: taskID, Error: err.Error(), RetryAt: time.UnixMilli(*retryAt), Count: int64(*retryCount)})
	}
}

func (r *TaskRunner) recordInferRetry(task *store.InferTask, err error, finishedAt time.Time, taskHash codec.Hash) {
	r.applyRunFailure("infer", task.TaskID, taskHash, err, finishedAt,
		&task.Stage, &task.RetryCount, &task.RetryAtUnixMilli, &task.LastError,
		&task.AutoHalted, &task.HaltCode, &task.HaltReason)
}

func (r *TaskRunner) recordVerifyRetry(task *store.VerifyTask, err error, finishedAt time.Time, taskHash codec.Hash) {
	r.applyRunFailure("verify", task.TaskID, taskHash, err, finishedAt,
		&task.Stage, &task.RetryCount, &task.RetryAtUnixMilli, &task.LastError,
		&task.AutoHalted, &task.HaltCode, &task.HaltReason)
}

// reportAutoHalted makes a halted responsibility visible on every tick it is
// skipped on, rather than only in the tick that halted it. Silence after a halt
// is indistinguishable from silence after a crash, and an operator looking at a
// node that is doing nothing needs the difference.
//
// It is not rate limited on purpose: a halted record only leaves this state by
// an operator clearing it, so the line is the standing reminder that one is
// owed. loadActiveTasks already skips a failed record, so in the ordinary case
// this fires once -- reaching it at all means something re-queued a halted
// responsibility, which is exactly what deserves a line.
func (r *TaskRunner) reportAutoHalted(role, taskID string, taskHash codec.Hash, code, reason string) {
	r.cfg.Trace.ErrorEvent("responsibility_auto_halt_skipped",
		tasktrace.Str("role", role), tasktrace.Str("task", taskID),
		tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("code", code), tasktrace.Str("reason", reason))
	if r.cfg.Diagnostic != nil {
		r.cfg.Diagnostic(TaskRunnerDiagnostic{Source: role, Record: taskID, Error: "automatic execution halted: " + reason})
	}
}

// ApplyReconcilerEffects serializes Keeper-driven assignment and terminal
// changes through the same infer/verify owner that checkpoints executions.
func (r *TaskRunner) ApplyReconcilerEffects(ctx context.Context, effects []ReconcilerEffect) error {
	if r == nil || r.cfg.Store == nil {
		return fmt.Errorf("task runner store is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, effect := range effects {
		switch effect.Type {
		case ReconcilerEffectAssignment:
			a := effect.Snapshot.Assignment
			if r.cfg.LocalWorkerAddress == "" || a.SelectedWorker != r.cfg.LocalWorkerAddress {
				// Not selected: this node's handraise obligation ends here and the candidate
				// row should go. It was written down so that "a restart in the middle of a
				// handraise can still publish the signed document it promised"; once the
				// winner is final that obligation is discharged, and since this store holds
				// restart obligations only, keeping the row leaves one line of permanent
				// garbage per losing bid.
				//
				// Cleared only on this authoritative path: the chain's final assignment is
				// what settles "not selected", while WORKER_ASSIGNMENT_NOTIFY is an early
				// wake-up that may never arrive at all. A failed cleanup does not affect
				// correctness (the next candidate for the same (session, order) overwrites
				// it), so it must not stop the rest of this batch of effects from landing.
				if r.cfg.LocalWorkerAddress != "" && a.SessionID != "" {
					if err := layout.ReleaseCandidateAdmission(ctx, r.cfg.Store, a.SessionID, a.OrderSequence.Uint64(), layout.StoredHash(effect.TaskHash)); err != nil && r.cfg.Diagnostic != nil {
						r.cfg.Diagnostic(TaskRunnerDiagnostic{
							Source: "assignment_lost", Record: effect.TaskID, Error: err.Error(),
						})
					}
				}
				continue
			}
			inputSizeBytes := uint64(0)
			// Keeper's task snapshot does not currently serve builder_operator_address,
			// and the chain has no field saying which Builder is the receiver. The Builder
			// that broadcast this order must have accepted it and therefore holds the
			// input, so the sender recorded at admission is a reliable fallback source.
			// Once the chain carries the field, the snapshot value wins.
			builderOperator := a.BuilderOperatorAddress
			if candidate, err := layout.GetCandidateAdmission(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash)); err == nil {
				inputSizeBytes = candidate.InputSizeBytes
				if builderOperator == "" {
					builderOperator = candidate.BroadcastingBuilder
				}
			}
			task := layout.TaskRecord{
				SessionID:              a.SessionID,
				OrderSequence:          a.OrderSequence.Uint64(),
				ModelID:                a.ModelID,
				ProfileVersion:         a.ProfileVersion.Uint32(),
				AssignmentOrderDigest:  layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
				AssignmentDigest:       layout.StoredHashFromCodec(effect.AssignmentDigest),
				AcceptedInputHash:      layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
				InputDigest:            layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
				WorkerAddress:          a.SelectedWorker,
				BuilderOperatorAddress: builderOperator,
				InputSizeBytes:         inputSizeBytes,
			}
			infer := layout.InferRecord{
				TaskID:              effect.TaskID,
				WinnerConfirmHeight: a.WinnerConfirmHeight.Uint64(),
				InferDeadlineHeight: a.InferDeadlineHeight.Uint64(),
				Stage:               layout.StageQueued,
				DeadlineHeight:      a.InferDeadlineHeight.Uint64(),
			}
			// woken_by says whether this node waited out its own poll interval or
			// was told to look. It is the measurement that decides whether the
			// interval is worth shortening, or worth replacing with a chain
			// subscription: an assignment admitted on a tick waited up to one
			// interval that a notify would have saved.
			wokenBy := tasktrace.Field{}
			if source, ok := WakeSourceFrom(ctx); ok {
				wokenBy = tasktrace.Str("woken_by", string(source))
			}
			r.cfg.Trace.Event("keeper_assignment_admitted",
				tasktrace.Str("task", effect.TaskID), tasktrace.Hash("task_hash", effect.TaskHash),
				wokenBy,
				tasktrace.Str("session", a.SessionID), tasktrace.Uint("order_sequence", a.OrderSequence.Uint64()),
				tasktrace.Str("model", a.ModelID), tasktrace.Uint("profile_version", uint64(a.ProfileVersion.Uint32())),
				tasktrace.Hash("accepted_order_payload_hash", codec.Hash(a.AcceptedOrderPayloadHash)),
				tasktrace.Hash("assignment_digest", effect.AssignmentDigest),
				tasktrace.Str("worker", a.SelectedWorker), tasktrace.Str("builder", builderOperator),
				tasktrace.Uint("input_size_bytes", inputSizeBytes),
				tasktrace.Uint("winner_confirm_height", a.WinnerConfirmHeight.Uint64()),
				tasktrace.Uint("infer_deadline_height", a.InferDeadlineHeight.Uint64()))
			if err := layout.InferAssignmentBatch(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash), task, infer); err != nil {
				if !r.quarantineEffect(effect, err) {
					return err
				}
			}
		case ReconcilerEffectVerifyReady:
			v := effect.Snapshot.VerifierAssignment
			if r.cfg.LocalVerifierAddress == "" || !slices.Contains([]string(v.FormalVerifierSet), r.cfg.LocalVerifierAddress) {
				continue
			}
			if v.VerifyRound.Uint64() != uint64(supportedVerifyRound) {
				err := fmt.Errorf("unsupported verify_round %d: automatic challenge-round execution is not enabled", v.VerifyRound.Uint64())
				if r.cfg.OnQuarantinedEffect != nil {
					r.cfg.OnQuarantinedEffect(effect, err)
				}
				r.cfg.Trace.ErrorEvent("verify_round_unsupported", tasktrace.Str("task", effect.TaskID), tasktrace.Uint("verify_round", v.VerifyRound.Uint64()), tasktrace.Err("error", err))
				continue
			}
			a := effect.Snapshot.Assignment
			builderOperator := a.BuilderOperatorAddress
			receiptJSON, err := json.Marshal(effect.Snapshot.InferReceipt)
			if err != nil {
				return fmt.Errorf("encode Keeper infer receipt: %w", err)
			}
			task := layout.TaskRecord{
				SessionID:              a.SessionID,
				OrderSequence:          a.OrderSequence.Uint64(),
				ModelID:                a.ModelID,
				ProfileVersion:         a.ProfileVersion.Uint32(),
				AssignmentOrderDigest:  layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
				AssignmentDigest:       layout.StoredHashFromCodec(effect.AssignmentDigest),
				WorkerAddress:          a.SelectedWorker,
				BuilderOperatorAddress: builderOperator,
			}
			verify := layout.VerifyRecord{
				TaskID:                     effect.TaskID,
				VerifyRound:                v.VerifyRound.Uint64(),
				OpenVerifyHeight:           v.OpenVerifyHeight.Uint64(),
				SampleSeedReadyHeight:      v.SampleSeedReadyHeight.Uint64(),
				CommitDeadlineHeight:       v.CommitDeadlineHeight.Uint64(),
				WorkerRevealDeadlineHeight: v.WorkerRevealDeadlineHeight.Uint64(),
				RevealDeadlineHeight:       v.RevealDeadlineHeight.Uint64(),
				VerificationSampleSeed:     layout.StoredHashFromCodec(codec.Hash(v.VerificationSampleSeed)),
				DeadlineHeight:             v.VerifyDeadlineHeight.Uint64(),
				InferReceiptDigest:         layout.StoredHashFromCodec(codec.Hash(effect.Snapshot.InferReceipt.InferReceiptHash)),
				KeeperReceiptJSON:          string(receiptJSON),
				OutputDigest:               layout.StoredHashFromCodec(codec.Hash(effect.Snapshot.InferReceipt.OutputHash)),
				PackageDigest:              layout.StoredHashFromCodec(codec.Hash(effect.Snapshot.InferReceipt.CanonicalOutputPackageHash)),
				AssignedVerifiers:          append([]string(nil), v.FormalVerifierSet...),
				Stage:                      layout.StageQueued,
			}
			if err := layout.VerifyAssignmentBatch(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash), task, verify); err != nil {
				if !r.quarantineEffect(effect, err) {
					return err
				}
				continue
			}
			storedTask, err := layout.GetTaskRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash))
			if err != nil {
				return fmt.Errorf("read admitted Verifier task: %w", err)
			}
			builderOperator = storedTask.BuilderOperatorAddress
			// The verify responsibility carries these two commitments into output
			// confirmation and can be admitted with either of them zero, because
			// the chain is the only source for both. Printing them after the atomic
			// admission makes the selected compatibility Builder visible too.
			r.cfg.Trace.Event("keeper_verify_ready",
				tasktrace.Str("task", effect.TaskID), tasktrace.Hash("task_hash", effect.TaskHash),
				tasktrace.Str("session", a.SessionID), tasktrace.Uint("order_sequence", a.OrderSequence.Uint64()),
				tasktrace.Hash("output_hash", codec.Hash(effect.Snapshot.InferReceipt.OutputHash)),
				tasktrace.Hash("package_hash", codec.Hash(effect.Snapshot.InferReceipt.CanonicalOutputPackageHash)),
				tasktrace.Hash("infer_receipt_hash", codec.Hash(effect.Snapshot.InferReceipt.InferReceiptHash)),
				tasktrace.Str("worker", a.SelectedWorker), tasktrace.Str("builder", builderOperator),
				tasktrace.Int("formal_verifiers", len(v.FormalVerifierSet)),
				tasktrace.Uint("open_verify_height", v.OpenVerifyHeight.Uint64()),
				tasktrace.Uint("commit_deadline_height", v.CommitDeadlineHeight.Uint64()),
				tasktrace.Uint("worker_reveal_deadline_height", v.WorkerRevealDeadlineHeight.Uint64()),
				tasktrace.Uint("reveal_deadline_height", v.RevealDeadlineHeight.Uint64()),
				tasktrace.Uint("verify_deadline_height", v.VerifyDeadlineHeight.Uint64()))
		case ReconcilerEffectRevealReady:
			// The reveal deadline is the whole payload of this effect, and it is
			// merged into a verify responsibility this node already holds rather
			// than creating one. A node that was never a selected Verifier for
			// this task has nothing to reveal, and MergeVerify would happily
			// write a bare record for it.
			v := effect.Snapshot.VerifierAssignment
			revealDeadline := v.RevealDeadlineHeight.Uint64()
			if r.cfg.LocalVerifierAddress == "" || !slices.Contains([]string(v.FormalVerifierSet), r.cfg.LocalVerifierAddress) {
				continue
			}
			record, err := layout.GetVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash))
			if err != nil || record.TaskID == "" {
				// Not an error: the responsibility may already have been
				// released by a terminal effect, and the chain announcing a
				// phase for a task this node no longer owns is normal.
				continue
			}
			record.RevealDeadlineHeight = revealDeadline
			if err := layout.MergeVerify(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash), record); err != nil {
				if !r.quarantineEffect(effect, err) {
					return err
				}
				continue
			}
			r.forgetChainWait(revealPhaseWaitKey(effect.TaskID, record.VerifyRound))
			// The stage is printed beside the deadline because the pair is what
			// says whether anything happens next: "committed" means the reveal
			// runs on the following tick, anything else means this node has not
			// put a commit on chain for the round and never will reveal it.
			r.cfg.Trace.Event("keeper_reveal_phase_started",
				tasktrace.Str("task", effect.TaskID), tasktrace.Hash("task_hash", effect.TaskHash),
				tasktrace.Uint("verify_round", record.VerifyRound),
				tasktrace.Uint("reveal_deadline_height", revealDeadline),
				tasktrace.Uint("commit_deadline_height", record.CommitDeadlineHeight),
				tasktrace.Uint("chain_height", effect.Event.Height),
				tasktrace.Str("stage", string(record.Stage)))
		case ReconcilerEffectInferTerminal:
			if err := layout.DeleteInferRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash)); err != nil {
				return err
			}
		case ReconcilerEffectTaskTerminal:
			ev := layout.Evidence{TaskID: effect.TaskID, TerminalOrSettled: true, RetentionStartHeight: retentionStartHeight(effect)}
			if taskRecord, err := layout.GetTaskRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash)); err == nil {
				ev.SessionID = taskRecord.SessionID
			}
			if err := layout.TaskTerminalBatch(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash), ev); err != nil {
				if !r.quarantineEffect(effect, err) {
					return err
				}
			}
		case ReconcilerEffectVerifyTerminal:
			// Every node on the chain sees every reveal, and on a task with
			// several Verifiers the first one to land arrives while the others
			// still owe theirs. Only a reveal naming this node ends this node's
			// responsibility; a peer's reveal says nothing about it. An empty
			// address is not a foreign one -- a reveal deadline closing is the
			// chain ending the phase for the whole task, and names nobody.
			if effect.Event.Verifier != "" && r.cfg.LocalVerifierAddress != "" && effect.Event.Verifier != r.cfg.LocalVerifierAddress {
				continue
			}
			if err := layout.DeleteVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash)); err != nil {
				return err
			}
			// Traced because this delete is what takes the task out of the
			// active set for good: loadActiveTasks rebuilds that set from the
			// stored records alone, so a responsibility released here never
			// comes back, and an operator reading the log has no other way to
			// see it happen.
			r.cfg.Trace.Event("verify_responsibility_released",
				tasktrace.Str("task", effect.TaskID), tasktrace.Hash("task_hash", effect.TaskHash),
				tasktrace.Str("keeper_event", string(effect.Event.Type)),
				tasktrace.Str("verifier", effect.Event.Verifier),
				tasktrace.Uint("chain_height", effect.Event.Height))
		case ReconcilerEffectEvidenceRetention:
			finality, cleanup := effect.FinalityHeight, effect.CleanupHeight
			switch effect.Event.Type {
			case chainclient.KeeperEventEvidenceCleanupDeferred:
				cleanup = effect.NextCleanupHeight
			}
			// Only a finality height moves the retention clock here. A
			// cleanup-due or cleanup-deferred event carries no finality, and the
			// merge's own rule already advances RetentionStartHeight from
			// FinalityHeight, so passing zero is what keeps a cleanup schedule
			// event from postponing the cleanup it is announcing.
			ev := layout.Evidence{TaskID: effect.TaskID, FinalityHeight: finality, CleanupHeight: cleanup, RetentionStartHeight: finality}
			if taskRecord, err := layout.GetTaskRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash)); err == nil {
				ev.SessionID = taskRecord.SessionID
			}
			if err := layout.MergeEvidence(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash), ev); err != nil {
				if !r.quarantineEffect(effect, err) {
					return err
				}
			}
		case ReconcilerEffectChallengeOpened, ReconcilerEffectChallengeClosed:
			open := effect.Type == ReconcilerEffectChallengeOpened
			if err := layout.UpsertChallenge(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash), effect.Event.ChallengeID, layout.ChallengeLifecycle{
				Open:         open,
				OpenedHeight: effect.Event.Height,
				LastPosition: layout.Position{Height: effect.Event.Height},
			}); err != nil {
				return err
			}
		}
	}
	r.Wake()
	return nil
}

// quarantineEffect decides what one failed effect does to the poll loop, and
// reports true when the caller should skip it rather than abort.
//
// A merge conflict is permanent and belongs to a single task. Returning it would
// reach the effect sink in cmd/cortexd and then poller.Run, which stops on any
// error it cannot retry - so one poisoned task would cost the node its entire
// chain view. Worse, the consumed height is not advanced past the offending
// event, so a restart re-reads it and stops again: the node wedges permanently.
//
// Skipping lets the cursor move. Skipping silently would hide a divergence
// between a durable record and Keeper authority, which is why the callback is
// the price of continuing. This is the same bargain OnQuarantinedEvent makes for
// chain history the node cannot parse.
func (r *TaskRunner) quarantineEffect(effect ReconcilerEffect, err error) bool {
	if !errors.Is(err, layout.ErrConflict) {
		return false
	}
	if r.cfg.OnQuarantinedEffect != nil {
		r.cfg.OnQuarantinedEffect(effect, err)
	}
	return true
}

// retentionStartHeight is the clock the evidence retention window is measured
// from, for the effect that first observes a task terminal: "the authoritative
// finality height when available, otherwise the finalized Keeper cursor that
// carried the effect" (docs/specs/task-storage-layout.md).
//
// The fallback is the whole reason the field is distinct from FinalityHeight. A
// task can reach terminal without ever producing a settlement finality - a
// refusal or a deadline expiry does exactly that - and such a task still has to
// age out. Measuring from the cursor that carried the terminal effect gives it a
// window; leaving the clock at zero would retain its evidence forever.
//
// It is deliberately NOT used for cleanup scheduling events. The spec scopes the
// clock to "when task terminal or settlement is first observed", and
// evidenceRetentionHeights leaves FinalityHeight zero for EvidenceCleanupDue and
// EvidenceCleanupDeferred, which carry only cleanup heights. Falling back to the
// cursor there would set the clock to the height of the very event announcing
// that cleanup is due, and because the merge never regresses, each such event
// would push eligibility out by another full retention window - retaining the
// evidence forever, which is the leak this field exists to close.
func retentionStartHeight(effect ReconcilerEffect) uint64 {
	if effect.FinalityHeight != 0 {
		return effect.FinalityHeight
	}
	return effect.Event.Height
}
