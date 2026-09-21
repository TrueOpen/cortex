package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/modelregistry"
)

type ReconcilerOptions struct {
	Registry    *modelregistry.Registry
	TaskReader  KeeperTaskReader
	ModelReader KeeperModelRegistryReader
	ChainHeight uint64

	// LocalTaskHash resolves the accepted task hash of a task this node already
	// holds a durable obligation for. It is OPTIONAL and is consulted only when
	// a TERMINAL event's Keeper snapshot cannot be read at all, to key the
	// terminal effect that releases the responsibility and starts the evidence
	// retention clock.
	//
	// It is not a second authority. The local record is keyed by the very
	// accepted_task_hash the snapshot would have supplied, written earlier from
	// a snapshot that was readable, so the fallback can only ever recover an
	// obligation this node already accepted from the chain — never invent one.
	LocalTaskHash func(ctx context.Context, taskID string) (codec.Hash, bool)

	OnQuarantinedEvent func(chainclient.KeeperEvent)
	// OnBuilderSetUpdated reports that a new BuilderSet became effective. The
	// holder of the membership cache uses it to drop the previous set: a Builder
	// the chain has just removed must stop being an admissible bus sender on the
	// next frame, not at the end of a cache window.
	OnBuilderSetUpdated func()
}

type KeeperTaskReader interface {
	Task(context.Context, string, string) (chainclient.TaskSnapshot, error)
}

type KeeperModelRegistryReader interface {
	CurrentModel(context.Context, string) (chainclient.CurrentModelSnapshot, error)
	CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error)
	ModelSupport(context.Context, string, string, string) (chainclient.ModelSupportSnapshot, error)
}

type Reconciler struct {
	registry *modelregistry.Registry
	tasks    KeeperTaskReader
	models   KeeperModelRegistryReader
	opts     ReconcilerOptions
}

type ReconcilerEffectType string

const (
	ReconcilerEffectAssignment  ReconcilerEffectType = "assignment"
	ReconcilerEffectVerifyReady ReconcilerEffectType = "verify_ready"
	// ReconcilerEffectRevealReady opens the reveal responsibility of a verify
	// task whose reveal phase the chain has started. It carries the Keeper
	// snapshot the reveal deadline is read from; see the
	// KeeperEventRevealPhaseStarted case in reconcilerEffectFor.
	ReconcilerEffectRevealReady       ReconcilerEffectType = "reveal_ready"
	ReconcilerEffectInferTerminal     ReconcilerEffectType = "infer_terminal"
	ReconcilerEffectVerifyTerminal    ReconcilerEffectType = "verify_terminal"
	ReconcilerEffectTaskTerminal      ReconcilerEffectType = "task_terminal"
	ReconcilerEffectEvidenceRetention ReconcilerEffectType = "evidence_retention"
	ReconcilerEffectChallengeOpened   ReconcilerEffectType = "challenge_opened"
	ReconcilerEffectChallengeClosed   ReconcilerEffectType = "challenge_closed"
)

// ReconcilerEffect is an ephemeral, replayable instruction to the infer and
// verify manager owners. TaskHash is the Keeper's accepted_task_hash - the
// TRUEOPEN_TASK_ORDER_V1 digest the user signed, read straight off the task
// snapshot below - and is the sole idempotency key; no effect queue or dedup row
// is persisted by the reconciler. It is NOT the accepted order payload digest:
// TaskRecord.AssignmentOrderDigest holds that other field, and conflating the
// two is what made the winner refuse every WORKER_ASSIGNMENT_NOTIFY.
type ReconcilerEffect struct {
	TaskHash         codec.Hash
	TaskID           string
	Type             ReconcilerEffectType
	AssignmentDigest codec.Hash
	// TaskVerdict and SettlementHeight are authoritative Keeper settlement
	// facts. The task owner must use them to retain evidence before deleting the
	// terminal task responsibility.
	TaskVerdict      string
	SettlementHeight uint64
	// Retention heights are authoritative Keeper facts. They are copied out of
	// the event attributes before canonicalisation nils the map, because the
	// attributes are transport noise but the heights are consensus state.
	FinalityHeight    uint64
	CleanupHeight     uint64
	NextCleanupHeight uint64
	Event             chainclient.KeeperEvent
	Snapshot          chainclient.TaskSnapshot
}

// ReconcileFromKeeperQuery rebuilds reconciler effects for a set of events by
// querying Keeper for authoritative task, challenge, and model state. It is
// the recovery entry point used when the poller detects a gap or regression
// and needs to re-establish local task responsibility state from the chain.
func (r *Reconciler) ReconcileFromKeeperQuery(ctx context.Context, events []chainclient.KeeperEvent) ([]ReconcilerEffect, error) {
	return r.Apply(ctx, events)
}

func NewReconciler(opts ReconcilerOptions) *Reconciler {
	return &Reconciler{registry: opts.Registry, tasks: opts.TaskReader, models: opts.ModelReader, opts: opts}
}

func (r *Reconciler) SetRegistry(registry *modelregistry.Registry) {
	if r != nil {
		r.registry = registry
	}
}

func (r *Reconciler) Apply(ctx context.Context, events []chainclient.KeeperEvent) ([]ReconcilerEffect, error) {
	if r == nil {
		return nil, fmt.Errorf("reconciler is required")
	}
	out := make([]ReconcilerEffect, 0, len(events))
	for _, event := range events {
		if event.Quarantined {
			r.reportQuarantine(event)
			continue
		}
		if err := event.Validate(); err != nil {
			r.quarantine(&event, err.Error())
			continue
		}
		if event.Known {
			if _, ok := keeperEventDispositionFor(event.Type); !ok {
				r.quarantine(&event, fmt.Sprintf("recognized Keeper event %s has no explicit disposition", event.Type))
				continue
			}
		}

		authoritative, snapshot, assignmentDigest, err := r.authoritativeTaskEvent(ctx, event)
		if err != nil {
			// The chain view is unreadable or disagrees, so the event is
			// reported and dropped as before. One recovery survives that: a
			// TERMINAL event for a task this node already holds locally still
			// releases the responsibility and starts the evidence retention
			// clock, because a chain that cannot answer for a task it has
			// already failed must not also strand that task's evidence
			// forever. Everything else needs facts only the snapshot carries.
			terminal, recovered := r.terminalEffectFromLocalState(ctx, event)
			if !r.quarantinePermanent(&event, err) {
				return nil, err
			}
			if recovered {
				out = append(out, terminal)
			}
			continue
		}
		event = authoritative
		if authoritative, err = r.authoritativeModelRegistryEvent(ctx, event); err != nil {
			if !r.quarantinePermanent(&event, err) {
				return nil, err
			}
			continue
		}
		event = authoritative
		if err := validateEvidenceRetentionEvent(event); err != nil {
			r.quarantine(&event, err.Error())
			continue
		}
		if err := r.applyModelRegistryEvent(ctx, event); err != nil {
			if !r.quarantinePermanent(&event, err) {
				return nil, err
			}
			continue
		}

		if event.Type == chainclient.KeeperEventBuilderSetUpdated && r.opts.OnBuilderSetUpdated != nil {
			r.opts.OnBuilderSetUpdated()
		}
		effectType, ok := reconcilerEffectFor(event.Type)
		if !ok {
			continue
		}
		// A sweep that names only a session is not a task obligation. task
		// emits it from emitSessionDeadlineSweptEvent with
		// DEADLINE_KIND_V1_SESSION_LIFECYCLE and no task_id, and every durable
		// obligation here is keyed by accepted_task_hash — so there is nothing
		// to key, nothing to terminate, and nothing wrong. Falling through
		// reported it as "missing accepted_task_hash" against an empty task id
		// once per expiring session.
		if event.Type == chainclient.KeeperEventDeadlineSwept && event.TaskID == "" {
			continue
		}
		acceptedTaskHash := snapshot.Assignment.AcceptedTaskHash
		if len(acceptedTaskHash) != 32 {
			r.quarantine(&event, fmt.Sprintf("%s for task %s is missing accepted_task_hash", event.Type, event.TaskID))
			continue
		}
		var taskHash codec.Hash
		copy(taskHash[:], acceptedTaskHash)
		finality, cleanup, nextCleanup := evidenceRetentionHeights(event)
		out = append(out, ReconcilerEffect{
			TaskHash: taskHash, TaskID: event.TaskID, Type: effectType,
			AssignmentDigest: assignmentDigest, Event: canonicalEffectEvent(event), Snapshot: snapshot,
			TaskVerdict: strings.TrimSpace(snapshot.Settlement.TaskVerdict), SettlementHeight: snapshot.Settlement.SettlementHeight.Uint64(),
			FinalityHeight: finality, CleanupHeight: cleanup, NextCleanupHeight: nextCleanup,
		})
	}
	return out, nil
}

// terminalEffectFromLocalState rebuilds the terminal effect of an event whose
// Keeper snapshot could not be read, from the accepted task hash this node
// already has on disk.
//
// It exists for one observed chain state: the deadline sweep writes
// VERIFY_FAILED without a verifier assignment - there was none, which is why
// the task failed - and task's Query/Task requires an assignment for that
// status, so it answers codespace sdk code 6 for that task permanently. The
// snapshot was needed only to key the effect, and the local record is keyed by
// exactly that value.
//
// Deliberately narrow: terminal effects only, only with a resolver wired, and
// only for a task_id the resolver already knows. It supplies no chain facts -
// no verdict, no settlement height, an empty snapshot - so retention starts
// from the event height (retentionStartHeight), which is the correct start for
// a swept task.
func (r *Reconciler) terminalEffectFromLocalState(ctx context.Context, event chainclient.KeeperEvent) (ReconcilerEffect, bool) {
	if r.opts.LocalTaskHash == nil || strings.TrimSpace(event.TaskID) == "" {
		return ReconcilerEffect{}, false
	}
	effectType, ok := reconcilerEffectFor(event.Type)
	if !ok || effectType != ReconcilerEffectTaskTerminal {
		return ReconcilerEffect{}, false
	}
	taskHash, ok := r.opts.LocalTaskHash(ctx, event.TaskID)
	if !ok || taskHash == (codec.Hash{}) {
		return ReconcilerEffect{}, false
	}
	finality, cleanup, nextCleanup := evidenceRetentionHeights(event)
	return ReconcilerEffect{
		TaskHash: taskHash, TaskID: event.TaskID, Type: effectType,
		Event:          canonicalEffectEvent(event),
		FinalityHeight: finality, CleanupHeight: cleanup, NextCleanupHeight: nextCleanup,
	}, true
}

func canonicalEffectEvent(event chainclient.KeeperEvent) chainclient.KeeperEvent {
	event.ContractVersion = ""
	event.RawType = ""
	event.Known = false
	event.Quarantined = false
	event.QuarantineReason = ""
	event.Payload = nil
	event.Attributes = nil
	return event
}

func reconcilerEffectFor(eventType chainclient.KeeperEventType) (ReconcilerEffectType, bool) {
	switch eventType {
	case chainclient.KeeperEventAssignmentFinalized:
		return ReconcilerEffectAssignment, true
	// Both events admit the verify responsibility, and on the live chain only the
	// second one is ever emitted. task writes the selected Verifier set in
	// EndBlock as EventVerifierAssignmentFinalized, carrying
	// selection_randomness_height / selection_randomness_beacon with it -- which
	// is exactly what verifierAssignmentSnapshot maps onto SampleSeedReadyHeight
	// and VerificationSampleSeed -- and emits no EventVerificationSampleSeedReady
	// at all. Treating the finalization as a projection therefore left
	// ReconcilerEffectVerifyReady, the only writer of a local verify record, with
	// no producer: a node the chain had selected wrote nothing, ran nothing, and
	// was jailed at the commit deadline for a duty it never learned it held.
	case chainclient.KeeperEventVerificationSampleSeedReady,
		chainclient.KeeperEventOpenVerifyAccepted:
		return ReconcilerEffectVerifyReady, true
	// The same shape as the finalization above, for the same reason. keeper §10.7
	// writes reveal_deadline_height exactly once, inside StartRevealPhase, so
	// before this event the verifier assignment snapshot carries a zero there --
	// which is the protocol's answer, not a gap. Projecting this event and
	// producing no effect therefore left the reveal with no reachable deadline at
	// all: internal/verifier refuses to sign a result whose expiry_height is zero
	// (correctly, it is a frozen preimage field), so every reveal failed closed
	// forever while the event that carries the answer went nowhere.
	case chainclient.KeeperEventRevealPhaseStarted:
		return ReconcilerEffectRevealReady, true
	// Keeper accepting the infer receipt releases nothing, because the Worker
	// responsibility does not end there. Three steps come after the receipt is
	// relayed: the output upload, the durable Builder storage confirmation, and
	// the OUTPUT_AVAILABLE publication (`ensureOutputAvailable` in
	// internal/worker). The receipt reaches the chain roughly a second before
	// the last of them, so treating this event as ReconcilerEffectInferTerminal
	// deleted the infer record from under the executor still running: the next
	// checkpoint hit store.ErrNotFound, the whole step returned, and
	// OUTPUT_AVAILABLE was never published for that round - permanently, since
	// the deleted record was also the only carrier of a restart obligation.
	// It is now a projection (keeperEventDispositionFor), and nothing leaks:
	// a completed infer record is inert (`loadActiveTasks` skips a succeeded
	// stage) and TaskTerminalBatch deletes both records when the task settles,
	// while an *incomplete* one keeps its retries and finishes the steps the
	// chain has not seen. KeeperEventWorkerTimeout stays terminal - that one
	// really does end the responsibility.
	case chainclient.KeeperEventWorkerTimeout:
		return ReconcilerEffectInferTerminal, true
	case chainclient.KeeperEventResultCredentialAccepted,
		chainclient.KeeperEventWorkerRevealDeadlineClosed,
		chainclient.KeeperEventRevealDeadlineClosed:
		return ReconcilerEffectVerifyTerminal, true
	case chainclient.KeeperEventAssignmentFailed,
		chainclient.KeeperEventSettleAccepted,
		chainclient.KeeperEventDeadlineSwept,
		chainclient.KeeperEventVerifyOpenDeadlineClosed:
		return ReconcilerEffectTaskTerminal, true
	case chainclient.KeeperEventSettlementFinalityUpdated,
		chainclient.KeeperEventEvidenceCleanupDue,
		chainclient.KeeperEventEvidenceCleanupDeferred:
		return ReconcilerEffectEvidenceRetention, true
	case chainclient.KeeperEventChallengeOpened:
		return ReconcilerEffectChallengeOpened, true
	case chainclient.KeeperEventChallengeClosed, chainclient.KeeperEventChallengeOutcomeRecorded:
		return ReconcilerEffectChallengeClosed, true
	default:
		return "", false
	}
}

func (r *Reconciler) authoritativeTaskEvent(ctx context.Context, event chainclient.KeeperEvent) (chainclient.KeeperEvent, chainclient.TaskSnapshot, codec.Hash, error) {

	if event.TaskID == "" {
		return event, chainclient.TaskSnapshot{}, codec.Hash{}, nil
	}
	needSnapshot := eventNeedsTaskHash(event.Type)
	if !needSnapshot {
		return event, chainclient.TaskSnapshot{}, codec.Hash{}, nil
	}
	if r.tasks == nil {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper event %s for task %s requires an authoritative Keeper task reader", event.Type, event.TaskID)
	}

	snapshot, err := r.tasks.Task(ctx, event.SessionID, event.TaskID)
	if err != nil {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("query Keeper task %s: %w", event.TaskID, err)
	}
	if err := snapshot.Validate(); err != nil {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("validate Keeper task %s: %w", event.TaskID, err)
	}
	assignment := snapshot.Assignment
	if assignment.TaskID != event.TaskID || event.SessionID != "" && assignment.SessionID != event.SessionID {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper task identity does not match event %s/%s", event.SessionID, event.TaskID)
	}
	event.SessionID = assignment.SessionID
	if event.Type == chainclient.KeeperEventAssignmentFinalized && event.Worker != "" && assignment.SelectedWorker != event.Worker {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper selected worker %q does not match event worker %q", assignment.SelectedWorker, event.Worker)
	}
	if event.ModelID != "" && event.ModelID != assignment.ModelID {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper model %q does not match event model %q", assignment.ModelID, event.ModelID)
	}
	if event.ProfileVersion != "" && event.ProfileVersion != assignment.ProfileVersion.String() {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper profile %q does not match event profile %q", assignment.ProfileVersion.String(), event.ProfileVersion)
	}
	if event.InferDeadlineHeight != 0 && event.InferDeadlineHeight != assignment.InferDeadlineHeight.Uint64() {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper infer deadline %d does not match event infer deadline %d", assignment.InferDeadlineHeight.Uint64(), event.InferDeadlineHeight)
	}
	if event.Type == chainclient.KeeperEventOpenVerifyAccepted && event.Verifier != "" && !containsString(snapshot.VerifierAssignment.FormalVerifierSet, event.Verifier) {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("event verifier %q is absent from Keeper formal verifier set", event.Verifier)
	}
	if event.Type == chainclient.KeeperEventRevealPhaseStarted {
		if err := bindAuthoritativeRevealDeadline(&event, snapshot.VerifierAssignment); err != nil {
			return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, err
		}
	}
	if event.Type == chainclient.KeeperEventSettleAccepted {
		if snapshot.CurrentContract && snapshot.Settlement.TaskVerdict == "" {
			verdict := strings.TrimSpace(event.Attributes["verdict"])
			heightText := strings.TrimSpace(event.Attributes["settlement_height"])
			height, err := strconv.ParseUint(heightText, 10, 64)
			if verdict == "" || err != nil || height == 0 {
				return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("Keeper settled event authority is incomplete")
			}
			snapshot.Settlement = chainclient.SettlementSnapshot{TaskVerdict: verdict, SettlementHeight: chainclient.NewUint64String(height)}
		}
		if err := bindAuthoritativeSettlement(&event, snapshot.Settlement); err != nil {
			return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, err
		}
	}
	event.SessionID = assignment.SessionID
	event.OrderSequence = assignment.OrderSequence.Uint64()
	event.Worker = assignment.SelectedWorker
	event.WinnerConfirmHeight = assignment.WinnerConfirmHeight.Uint64()
	event.InferDeadlineHeight = assignment.InferDeadlineHeight.Uint64()
	event.ModelID = assignment.ModelID
	event.ProfileVersion = assignment.ProfileVersion.String()
	event.FormalVerifiers = append([]string(nil), snapshot.VerifierAssignment.FormalVerifierSet...)
	material, err := json.Marshal(assignment)
	if err != nil {
		return chainclient.KeeperEvent{}, chainclient.TaskSnapshot{}, codec.Hash{}, fmt.Errorf("encode Keeper assignment %s: %w", event.TaskID, err)
	}
	return event, snapshot, sha256.Sum256(material), nil
}

func eventNeedsTaskHash(eventType chainclient.KeeperEventType) bool {
	_, ok := reconcilerEffectFor(eventType)
	return ok
}

func bindAuthoritativeSettlement(event *chainclient.KeeperEvent, settlement chainclient.SettlementSnapshot) error {
	verdict := strings.TrimSpace(settlement.TaskVerdict)
	height := settlement.SettlementHeight.Uint64()
	if verdict == "" || height == 0 {
		return fmt.Errorf("Keeper settled task snapshot is incomplete")
	}
	if announced := strings.TrimSpace(event.Attributes["verdict"]); announced != "" && announced != verdict {
		return fmt.Errorf("Keeper settlement verdict %q does not match event verdict %q", verdict, announced)
	}
	if announced := strings.TrimSpace(event.Attributes["settlement_height"]); announced != "" {
		announcedHeight, err := strconv.ParseUint(announced, 10, 64)
		if err != nil || announcedHeight == 0 {
			return fmt.Errorf("Keeper settlement event height %q is invalid", announced)
		}
		if announcedHeight != height {
			return fmt.Errorf("Keeper settlement height %d does not match event settlement height %d", height, announcedHeight)
		}
	}
	event.Phase = verdict
	return nil
}

// bindAuthoritativeRevealDeadline checks the reveal deadline an
// EventRevealPhaseStarted announces against the verifier assignment the Keeper
// serves, so a reveal responsibility is never opened on a height nobody can
// vouch for. expiry_height is a frozen preimage field the Keeper compares, so a
// wrong value here is not a degraded reveal, it is a rejected one.
//
// A snapshot still reporting zero is treated as retryable rather than
// quarantined. keeper §10.7 writes reveal_deadline_height exactly once, inside
// the StartRevealPhase transition this very event announces, so zero means the
// query read a node that has not caught up - and quarantining it would discard
// the only carrier of the value and leave the reveal blocked for good.
func bindAuthoritativeRevealDeadline(event *chainclient.KeeperEvent, assignment chainclient.VerifierAssignmentSnapshot) error {
	height := assignment.RevealDeadlineHeight.Uint64()
	if height == 0 {
		return chainclient.Retryable(fmt.Errorf(
			"Keeper verifier assignment for task %s carries no reveal_deadline_height while %s announces the reveal phase started",
			event.TaskID, event.Type))
	}
	announced := strings.TrimSpace(event.Attributes["reveal_deadline_height"])
	if announced == "" {
		return nil
	}
	announcedHeight, err := strconv.ParseUint(announced, 10, 64)
	if err != nil || announcedHeight == 0 {
		return fmt.Errorf("%s reveal_deadline_height %q is invalid", event.Type, announced)
	}
	if announcedHeight != height {
		return fmt.Errorf("Keeper reveal deadline %d does not match event reveal deadline %d", height, announcedHeight)
	}
	return nil
}

type keeperEventDisposition string

const (
	keeperEventFSMTransition keeperEventDisposition = "runtime_effect"
	keeperEventRegistry      keeperEventDisposition = "registry_projection"
	keeperEventRetention     keeperEventDisposition = "retention_projection"
	keeperEventProjection    keeperEventDisposition = "projection_only"
)

func keeperEventDispositionFor(eventType chainclient.KeeperEventType) (keeperEventDisposition, bool) {
	if eventNeedsTaskHash(eventType) {
		return keeperEventFSMTransition, true
	}
	switch eventType {
	case chainclient.KeeperEventProtocolProjection, chainclient.KeeperEventAssignAcceptedPendingRandomness,
		// The two "the chain took your submission" events, and neither one ends
		// the responsibility that produced it: a Worker still has to upload the
		// output and publish OUTPUT_AVAILABLE after the receipt is accepted,
		// exactly as a Verifier still owes a reveal after its commit is.
		chainclient.KeeperEventInferReceiptAccepted,
		chainclient.KeeperEventCommitAccepted,
		// StartRevealPhase emits this after RevealPhaseStarted, including when
		// all commits arrive early. It does not end the reveal responsibility,
		// even if the local commit call has not returned yet. The runner's
		// stage-specific deadlines still stop uncommitted tasks at their bound.
		chainclient.KeeperEventCommitDeadlineClosed,
		chainclient.KeeperEventChallengeOpened,
		chainclient.KeeperEventChallengeSampleSeedReady,
		chainclient.KeeperEventChallengeVerifierAssigned,
		chainclient.KeeperEventChallengeCommitAccepted,
		chainclient.KeeperEventChallengeResultAccepted,
		chainclient.KeeperEventChallengeOutcomeRecorded:
		return keeperEventProjection, true
	case chainclient.KeeperEventModelRegistered,
		chainclient.KeeperEventProfileRegistered,
		chainclient.KeeperEventModelProfileRegistered,
		chainclient.KeeperEventModelProfileStateChanged,
		chainclient.KeeperEventModelSupportUpdated:
		return keeperEventRegistry, true
	case chainclient.KeeperEventSettlementFinalityUpdated,
		chainclient.KeeperEventEvidenceCleanupDue,
		chainclient.KeeperEventEvidenceCleanupDeferred:
		return keeperEventRetention, true
	case chainclient.KeeperEventCommitItemRejected,
		chainclient.KeeperEventFullResultRevealAccepted,
		chainclient.KeeperEventWorkerRevealReceiptAccepted,
		chainclient.KeeperEventTaskEvidenceRootRecorded,
		chainclient.KeeperEventVerdictFraudProofSubmitted,
		chainclient.KeeperEventVerdictFraudProofSucceeded,
		chainclient.KeeperEventFaultRecorded,
		chainclient.KeeperEventChallengeClosed,
		chainclient.KeeperEventChallengeFullResultReveal,
		chainclient.KeeperEventChallengeLivenessIssueRecorded,
		chainclient.KeeperEventChallengeEconomicEffectApplied,
		chainclient.KeeperEventEvidenceRequested,
		chainclient.KeeperEventEvidenceRequestSatisfied,
		chainclient.KeeperEventEvidenceRequestDefaulted,
		chainclient.KeeperEventFreezeSignalSubmitted,
		chainclient.KeeperEventEmergencyFreezeAccepted,
		chainclient.KeeperEventTaskFailureClassUpdated,
		chainclient.KeeperEventRewardMarked,
		chainclient.KeeperEventMarkGateUpdated,
		chainclient.KeeperEventModelSupportBatchAccepted,
		chainclient.KeeperEventBuilderSetUpdated:
		return keeperEventProjection, true
	default:
		return "", false
	}
}

func validateEvidenceRetentionEvent(event chainclient.KeeperEvent) error {
	var key string
	switch event.Type {
	case chainclient.KeeperEventSettlementFinalityUpdated:
		key = "task_finality_height"
	case chainclient.KeeperEventEvidenceCleanupDue:
		key = "cleanup_height"
	case chainclient.KeeperEventEvidenceCleanupDeferred:
		key = "next_cleanup_height"
	default:
		return nil
	}
	height, err := strconv.ParseUint(strings.TrimSpace(event.Attributes[key]), 10, 64)
	if err != nil || height == 0 {
		return fmt.Errorf("%s requires positive %s", event.Type, key)
	}
	return nil
}

// evidenceRetentionHeights extracts the authoritative retention heights from a
// retention event before canonicalisation removes the attribute map. Zero
// values are normal for unrelated event types.
func evidenceRetentionHeights(event chainclient.KeeperEvent) (finality, cleanup, nextCleanup uint64) {
	switch event.Type {
	case chainclient.KeeperEventSettlementFinalityUpdated:
		finality, _ = strconv.ParseUint(strings.TrimSpace(event.Attributes["task_finality_height"]), 10, 64)
	case chainclient.KeeperEventEvidenceCleanupDue:
		cleanup, _ = strconv.ParseUint(strings.TrimSpace(event.Attributes["cleanup_height"]), 10, 64)
	case chainclient.KeeperEventEvidenceCleanupDeferred:
		nextCleanup, _ = strconv.ParseUint(strings.TrimSpace(event.Attributes["next_cleanup_height"]), 10, 64)
	}
	return
}

func (r *Reconciler) authoritativeModelRegistryEvent(ctx context.Context, event chainclient.KeeperEvent) (chainclient.KeeperEvent, error) {
	if r.models == nil {
		return event, nil
	}
	switch event.Type {
	case chainclient.KeeperEventModelRegistered:
		model, err := r.models.CurrentModel(ctx, event.ModelID)
		if err != nil {
			return chainclient.KeeperEvent{}, err
		}
		if err := model.Validate(); err != nil {
			return chainclient.KeeperEvent{}, err
		}
		if model.ModelID != event.ModelID {
			return chainclient.KeeperEvent{}, fmt.Errorf("current Keeper model %q does not match event model %q", model.ModelID, event.ModelID)
		}
		event.Phase = model.Status
	case chainclient.KeeperEventProfileRegistered, chainclient.KeeperEventModelProfileRegistered, chainclient.KeeperEventModelProfileStateChanged:
		profile, err := r.models.CurrentModelProfile(ctx, event.ModelID, event.ProfileVersion)
		if err != nil {
			return chainclient.KeeperEvent{}, err
		}
		if err := profile.Validate(); err != nil {
			return chainclient.KeeperEvent{}, err
		}
		if profile.Model.ModelID != event.ModelID || profile.Profile.ModelID != event.ModelID || profile.Profile.ProfileVersion.String() != event.ProfileVersion {
			return chainclient.KeeperEvent{}, fmt.Errorf("current Keeper model/profile does not match event %s/%s", event.ModelID, event.ProfileVersion)
		}
		event.Phase = profile.Profile.Status
	case chainclient.KeeperEventModelSupportUpdated:
		support, err := r.models.ModelSupport(ctx, event.Worker, event.ModelID, event.ProfileVersion)
		if err != nil {
			return chainclient.KeeperEvent{}, err
		}
		if err := support.Validate(); err != nil {
			return chainclient.KeeperEvent{}, err
		}
		if support.OperatorAddress != event.Worker || support.ModelID != event.ModelID || support.ProfileVersion.String() != event.ProfileVersion {
			return chainclient.KeeperEvent{}, fmt.Errorf("current Keeper model support does not match event worker/model/profile")
		}
		event.DeclaredSupport = support.DeclaredSupport
		event.SupportActive = support.SupportActive
	}
	return event, nil
}

func (r *Reconciler) applyModelRegistryEvent(ctx context.Context, event chainclient.KeeperEvent) error {
	if r.registry == nil {
		return nil
	}
	switch event.Type {
	case chainclient.KeeperEventModelRegistered, chainclient.KeeperEventProfileRegistered,
		chainclient.KeeperEventModelProfileRegistered, chainclient.KeeperEventModelProfileStateChanged:
		r.registry.PutStatus(modelregistry.ModelStatus{
			ModelID: event.ModelID, ProfileVersion: event.ProfileVersion,
			ChainState:        defaultString(event.Phase, modelregistry.ChainStateRegistered),
			DisplayVisibility: modelregistry.DisplayVisible, VerificationLabel: modelregistry.VerificationCommunity,
			RewardState: modelregistry.RewardFeeOnlyNoBlockReward,
		})
	case chainclient.KeeperEventModelSupportUpdated:
		status, err := r.registry.Support(ctx, modelregistry.SupportRequest{ModelID: event.ModelID, Supported: event.DeclaredSupport, DryRun: true})
		if err != nil {
			return err
		}
		r.registry.PutStatus(status)
	}
	return nil
}

func (r *Reconciler) reportQuarantine(event chainclient.KeeperEvent) {
	if r.opts.OnQuarantinedEvent != nil {
		r.opts.OnQuarantinedEvent(event)
	}
}

// quarantinePermanent decides what one failed event does to the poll loop, and
// reports true when the caller should skip it rather than abort.
//
// A retryable failure is a statement about the transport, not about chain
// history: the RPC was unreachable, the node answered 503. Returning it lets
// poller.Run back off and re-read the very same block, which is the only way a
// blip does not cost an event.
//
// Everything else is a permanent fact about a block that is already final -- a
// wire encoding this binary cannot read, a Keeper snapshot that disagrees with
// the event it came from -- and no number of retries changes it. Returning one
// of those reaches poller.Run, which stops on any error it cannot retry, and
// cmd/cortexd turns that into log.Fatal. Worse, the consumed height is never
// advanced past the offending event (poller.applyPage commits a height only
// after its whole block succeeds), so the restart re-reads it and dies again:
// one unreadable attribute wedges the node permanently, and every node reading
// the same chain wedges with it.
//
// Skipping lets the cursor move. Skipping silently would hide a contract
// mismatch with the chain, which is why the OnQuarantinedEvent log line is the
// price of continuing. This is the same bargain TaskRunner.quarantineEffect
// makes for an effect the task owner cannot merge, and the same one
// CometEventClient already makes for an event that fails Validate at parse time.
func (r *Reconciler) quarantinePermanent(event *chainclient.KeeperEvent, err error) bool {
	if chainclient.IsRetryable(err) {
		return false
	}
	r.quarantine(event, err.Error())
	return true
}

func (r *Reconciler) quarantine(event *chainclient.KeeperEvent, reason string) {
	event.Quarantined = true
	if event.QuarantineReason == "" {
		event.QuarantineReason = reason
	}
	r.reportQuarantine(*event)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
