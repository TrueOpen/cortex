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

// RunOnce restores the two independent active-task documents with exactly two
// point reads. Terminal responsibilities never appear because their Keeper
// effects delete them from the owning document.
func (r *TaskRunner) RunOnce(ctx context.Context) error {
	if r == nil || r.cfg.Store == nil {
		return fmt.Errorf("task runner store is required")
	}
	r.mu.Lock()
	infer, verify, err := r.loadActiveTasks(ctx)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	r.infer, r.verify = infer, verify
	r.mu.Unlock()

	tip := r.currentChainTip(ctx)
	// Before the due responsibilities, because this is the step that decides
	// whether there will BE one: a Verifier candidate that never got its
	// handraise out is never selected, so no verify document ever exists for the
	// loop below to find. It runs outside r.mu on purpose - it publishes and
	// waits on the chain - and it swallows its own errors, because RunOnce
	// returning one stops the daemon.
	r.redriveVerifierHandraises(ctx, tip)
	// And the Worker half of the same problem. trueopen.task.open.* is Core tier
	// too, so a busy node's retryable refusal has no transport to honour it;
	// this is where an order held over from a full moment gets its next attempt.
	// Same placement and same reason: it decides whether a responsibility will
	// exist at all, and it swallows its own errors because RunOnce returning one
	// stops the daemon.
	r.redriveWorkerOrders(ctx, tip)
	now := time.Now().UTC()
	type result struct {
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
		// finishedAt is when the executor returned, not when this tick began.
		// The retry clock is measured from it for the reason recordRetrySchedule
		// gives: a run that outlasts the retry delay would otherwise be due the
		// instant it failed.
		finishedAt time.Time
	}
	results := make(chan result, len(infer)+len(verify))
	sem := make(chan struct{}, int(r.cfg.MaxConcurrency))
	var wg sync.WaitGroup
	launchInfer := func(hash codec.Hash, task store.InferTask) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			// The slot is returned on every exit -- success, failure, panic
			// unwinding -- because it is the node's whole admission budget for
			// model work. Leaking one against MaxConcurrency=1 is the node.
			defer func() { <-sem }()
			updated, terminal, runErr := r.cfg.InferExecutor.RunInfer(ctx, hash, task)
			results <- result{role: "infer", hash: hash, infer: updated, terminal: terminal, err: runErr, finishedAt: time.Now().UTC()}
		}()
	}
	launchVerify := func(hash codec.Hash, task store.VerifyTask) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			updated, terminal, runErr := r.cfg.VerifyExecutor.RunVerify(ctx, hash, task)
			results <- result{role: "verify", hash: hash, verify: updated, terminal: terminal, err: runErr, finishedAt: time.Now().UTC()}
		}()
	}
	for hash, task := range infer {
		deadline := inferDeadline(task)
		if reason := r.taskTerminalReason(tip, task.Stage, deadline, task.RetryCount); reason != "" {
			r.reportStoppedResponsibility("infer", task.TaskID, hash, tip, deadline, task.RetryCount, reason)
			results <- result{role: "infer", hash: hash, infer: task, stopReason: reason}
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
			results <- result{role: "infer", hash: hash, infer: task, stopReason: reason}
			continue
		}
		launchInfer(hash, task)
	}
	for hash, task := range verify {
		// Before any scheduling decision is made about it, because every one of
		// them reads the reveal deadline: verifyDeadline bounds a committed
		// responsibility by it, taskTerminalReason stops the task on it, and
		// awaitingRevealPhase parks on its absence. Recovering afterwards would
		// leave this tick deciding on a zero it has already replaced.
		if awaitingRevealPhase(task) {
			if recovered := r.recoverRevealDeadline(ctx, hash, task); recovered != 0 {
				task.RevealDeadlineHeight = recovered
				verify[hash] = task
			}
		}
		deadline := verifyDeadline(task)
		if reason := r.taskTerminalReason(tip, task.Stage, deadline, task.RetryCount); reason != "" {
			r.reportStoppedResponsibility("verify", task.TaskID, hash, tip, deadline, task.RetryCount, reason)
			results <- result{role: "verify", hash: hash, verify: task, stopReason: reason}
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
			results <- result{role: "verify", hash: hash, verify: task, stopReason: reason}
			continue
		}
		launchVerify(hash, task)
	}
	wg.Wait()
	close(results)

	r.mu.Lock()
	defer r.mu.Unlock()
	inferChanged, verifyChanged := false, false
	var terminalInfer, terminalVerify []codec.Hash
	for outcome := range results {
		if outcome.role == "infer" {
			original, ok := infer[outcome.hash]
			if !ok {
				continue
			}
			outcome.infer = mergeInferExecution(original, outcome.infer)
			if outcome.stopReason != "" {
				outcome.infer.Stage, outcome.infer.LastError = "failed", outcome.stopReason
			}
			if outcome.err != nil {
				r.recordInferRetry(&outcome.infer, outcome.err, outcome.finishedAt, outcome.hash)
			}
			if outcome.terminal {
				delete(infer, outcome.hash)
				terminalInfer = append(terminalInfer, outcome.hash)
			} else {
				infer[outcome.hash] = outcome.infer
			}
			inferChanged = true
		} else {
			original, ok := verify[outcome.hash]
			if !ok {
				continue
			}
			outcome.verify = mergeVerifyExecution(original, outcome.verify)
			if outcome.stopReason != "" {
				outcome.verify.Stage, outcome.verify.LastError = "failed", outcome.stopReason
			}
			if outcome.err != nil {
				r.recordVerifyRetry(&outcome.verify, outcome.err, outcome.finishedAt, outcome.hash)
			}
			if outcome.terminal {
				delete(verify, outcome.hash)
				terminalVerify = append(terminalVerify, outcome.hash)
			} else {
				verify[outcome.hash] = outcome.verify
			}
			verifyChanged = true
		}
	}
	if inferChanged {
		if err := r.persistInferChangesToLayout(ctx, infer); err != nil {
			return err
		}
		for _, h := range terminalInfer {
			if err := layout.DeleteInferRecord(ctx, r.cfg.Store, layout.StoredHash(h)); err != nil {
				return err
			}
		}
	}
	if verifyChanged {
		if err := r.persistVerifyChangesToLayout(ctx, verify); err != nil {
			return err
		}
		for _, h := range terminalVerify {
			if err := layout.DeleteVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(h)); err != nil {
				return err
			}
		}
	}
	r.infer, r.verify = infer, verify
	return nil
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
			if err := layout.DeleteVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(effect.TaskHash)); err != nil {
				return err
			}
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
