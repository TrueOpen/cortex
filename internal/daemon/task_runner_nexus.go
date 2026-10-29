package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/verifier"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// recordVerifierAssignment consumes VERIFIER_ASSIGNMENT_NOTIFY (§5.9): the
// notice that the chain finalized the selected Verifier set for this task. It
// records nothing the chain did not already say - every field is compared
// against the Keeper snapshot and a disagreement is a refusal - so the message's
// only effect is to wake this node earlier than the poller would have.
//
// It replaced recordVerifierControl, which handled the pre-v1 VERIFY_SELECT_NOTIFY
// and SAMPLE_READY_NOTIFY as one merged case. The merge is gone with the split:
// the "call for handraises" half became OPEN_VERIFY (admitOpenVerify), and
// SAMPLE_READY_NOTIFY has no successor at all, because §5.9 has the selected
// Verifier recompute every committed token rather than sample.
//
// output_cid and canonical_output_package_hash are no longer on this message
// (§4.7), so it no longer supplies the verify record's OutputCID. That was the
// message's one durable side effect; the output package is located through the
// Builder directory and the task-data plane instead.
func (r *TaskRunner) recordVerifierAssignment(ctx context.Context, message *nexusv1.VerifierAssignmentNotifyV1) error {
	return r.builderFrameVerdict("nexus_verifier_assignment_notify", message.GetTaskId(), r.applyVerifierAssignment(ctx, message))
}

func (r *TaskRunner) applyVerifierAssignment(ctx context.Context, message *nexusv1.VerifierAssignmentNotifyV1) error {
	if r.cfg.TaskReader == nil {
		return builderclient.Retryable(fmt.Errorf("authoritative Keeper task reader is required for VerifierAssignmentNotify"))
	}
	taskID, err := taskIDHex(message.GetTaskId())
	if err != nil {
		return fmt.Errorf("VerifierAssignmentNotify: %w", err)
	}
	verifiers := make([]string, 0, len(message.GetVerifiers()))
	for _, selected := range message.GetVerifiers() {
		verifiers = append(verifiers, selected.GetOperatorAddress())
	}
	// Not being selected is not a failure: this notice reaches every candidate
	// (§5.9), this node has nothing to record, so normal terminal state, no error.
	//
	// Judging by the list the message itself asserts is safe: this message's only job is
	// to wake the node early, the obligation of being selected is written by the Keeper
	// effect (the verify_ready branch of ApplyReconcilerEffects), and missing one wake-up
	// misses no obligation. Reporting an error, by contrast, measured 78 redeliveries and
	// 36 seconds of scrolling until the envelope expired.
	if !slices.Contains(verifiers, r.cfg.LocalVerifierAddress) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// This step queries the task_id secondary index in the local Pebble store, not the
	// chain. The wording used to read "Keeper verifier assignment ... is not available",
	// which sent operators off to investigate a chain query that never happened.
	foundHash, foundRec, err := layout.FindVerifyRecordByTaskID(ctx, r.cfg.Store, taskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("local verify record for %s is not available yet: %w", taskID, err))
	}

	tr, err := layout.GetTaskRecord(ctx, r.cfg.Store, foundHash)
	if err != nil {
		return err
	}
	snapshot, err := r.cfg.TaskReader.Task(ctx, tr.SessionID, taskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("query Keeper task %s: %w", taskID, err))
	}
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("validate Keeper task %s: %w", taskID, err)
	}
	// No redelivery of this frame can grow an output hash, so the verdict is
	// asserted permanent rather than left for a retry loop. Two of the three
	// Builders in a proposal
	// group publish this notify without ever having held the Worker's receipt
	// (nexus#67), so on devnet that cost every Verifier 50 refusals over 32
	// seconds -- on top of the real failure they were already reporting.
	// Acknowledging costs nothing: the duty is written by the Keeper effect, and
	// this frame is only an early wake-up (see the unselected-node path above).
	if len(message.GetOutputHash()) != 32 {
		return builderclient.Permanent(fmt.Errorf(
			"VerifierAssignmentNotify output_hash is %d bytes, want 32: the frame cannot be reconciled against Keeper",
			len(message.GetOutputHash())))
	}
	v := snapshot.VerifierAssignment
	// The V2 notify carries no worker-reveal deadline; that height stays a
	// Keeper-snapshot fact the runner reads for itself.
	if !slices.Equal(verifiers, []string(v.FormalVerifierSet)) ||
		!bytes.Equal(message.GetOutputHash(), snapshot.InferReceipt.OutputHash[:]) ||
		message.GetOpenVerifyHeight() != v.OpenVerifyHeight.Uint64() ||
		message.GetCommitDeadlineHeight() != v.CommitDeadlineHeight.Uint64() ||
		(message.GetRevealDeadlineHeight() != 0 && message.GetRevealDeadlineHeight() != v.RevealDeadlineHeight.Uint64()) ||
		message.GetVerifyDeadlineHeight() != v.VerifyDeadlineHeight.Uint64() {
		return fmt.Errorf("VerifierAssignmentNotify control fields do not match Keeper")
	}
	if err := layout.MergeVerify(ctx, r.cfg.Store, foundHash, foundRec); err != nil {
		return err
	}
	r.Wake()
	return nil
}

// admitOpenVerify consumes OPEN_VERIFY (§5.6), the Core-tier call for Verifier
// handraises. It is the Verifier-side counterpart of OPEN_TASK: the Builder
// opens the window, every Verifier candidate that can serve this task sends its
// VerifierHandraise frame back to the Builder over the node frame stream, and the
// selected set is decided on chain afterwards.
//
// Every delivery converges on raiseVerifierHand and shares its at-most-once
// claim, so a task that receives the call more than once still raises its hand
// exactly once.
func (r *TaskRunner) admitOpenVerify(ctx context.Context, builderOperator string, message *nexusv1.OpenVerifyV1) error {
	return r.builderFrameVerdict("nexus_open_verify", message.GetTaskId(), r.openVerify(ctx, builderOperator, message))
}

// builderFrameVerdict settles what a refused Builder frame means. A
// merge-boundary conflict is a permanent per-task refusal: the same frame
// contradicts the same stored field on every redelivery, so retrying it is how
// a redelivery loop starts. Every refusal other than a repeat of this block's
// chain-state wait is reported once.
func (r *TaskRunner) builderFrameVerdict(source string, taskID []byte, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, layout.ErrConflict) {
		err = builderclient.Permanent(err)
	}
	if r.cfg.Diagnostic != nil && !isRepeatedChainStateWait(err) {
		r.cfg.Diagnostic(TaskRunnerDiagnostic{
			Source:  source,
			Record:  hex.EncodeToString(taskID),
			Error:   err.Error(),
			Waiting: isChainStateWait(err),
		})
	}
	return err
}

func (r *TaskRunner) openVerify(ctx context.Context, builderOperator string, message *nexusv1.OpenVerifyV1) error {
	taskID, err := taskIDHex(message.GetTaskId())
	if err != nil {
		return fmt.Errorf("OpenVerify: %w", err)
	}
	if message.GetWorkerOperatorAddress() == "" || message.GetProfileVersion() == 0 || len(message.GetOutputHash()) != 32 {
		return fmt.Errorf("OpenVerify missing required fields")
	}
	if len(message.GetTaskHash()) != 32 {
		return fmt.Errorf("OpenVerify task_hash must be 32 bytes")
	}
	modelID, err := identity.ModelIDHex(message.GetModelId())
	if err != nil {
		return fmt.Errorf("OpenVerify model_id: %w", err)
	}
	if len(message.GetInferReceiptHash()) != 32 {
		return fmt.Errorf("OpenVerify infer_receipt_hash must be 32 bytes")
	}
	if message.GetVerifyRound() != supportedVerifyRound {
		return fmt.Errorf("OpenVerify verify_round = %d, want %d", message.GetVerifyRound(), supportedVerifyRound)
	}
	trigger := verifierHandraiseTrigger{
		Kind: "OpenVerify", TaskID: taskID,
		Worker: message.GetWorkerOperatorAddress(), OutputHash: message.GetOutputHash(), TaskHash: codec.Hash(message.GetTaskHash()),
		ModelID: modelID, ProfileVersion: message.GetProfileVersion(), VerifyRound: message.GetVerifyRound(),
		InferReceiptHash:         codec.Hash(message.GetInferReceiptHash()),
		SenderOperatorAddress:    builderOperator,
		DataReadyBuilderOperator: builderOperator,
		// The call is the one handraise trigger with no transport behind it, so
		// it is the one that arms the local re-drive. See
		// task_runner_handraise_redrive.go.
		Redrivable: true,
	}
	return r.raiseVerifierHand(ctx, trigger)
}

const supportedVerifyRound = uint32(1)

// verifierHandraiseTrigger is the part of an inbound frame that decides whether
// this node should raise a Verifier hand. OPEN_VERIFY reduces to it and is not
// an authority: every field is cross-checked against the Keeper snapshot below.
type verifierHandraiseTrigger struct {
	Kind       string
	TaskID     string
	Worker     string
	OutputHash []byte
	ModelID    string
	// ProfileVersion and VerifyRound are carried by OPEN_VERIFY; a zero round is
	// read as the supported first round.
	ProfileVersion uint32
	VerifyRound    uint32
	// InferReceiptHash is carried by OPEN_VERIFY (§5.6). When present it must
	// equal the Keeper receipt: a
	// Builder calling for verification of a receipt the chain does not hold is
	// calling for verification of nothing.
	InferReceiptHash codec.Hash
	// TaskHash is carried by OPEN_VERIFY (§5.8). When present it must equal the
	// Keeper's accepted task hash: it is a frame-level restatement, never the
	// authority.
	TaskHash codec.Hash
	// SenderOperatorAddress is the frame's already-authenticated sender and is
	// retained for diagnostics.
	SenderOperatorAddress string
	// DataReadyBuilderOperator is the Builder whose OPEN_VERIFY carried the
	// protocol's local data-ready declaration.
	DataReadyBuilderOperator string
	// Redrivable marks a trigger whose transport will not bring it back. Nothing
	// else about the attempt changes; what changes is that a retryable refusal
	// is remembered and tried again from the poll loop instead of being the last
	// thing that ever happens to this task-round.
	Redrivable bool
}

// verifyTaskBinding resolves the local storage key and the session Keeper's query
// needs.
//
// An existing local record wins. With no record it queries the chain by task_id
// directly: Keeper's QueryTask needs only the task_id (which is itself derived from
// the session_id), and the TaskCoreState in the response carries both the session_id
// and the accepted task_hash. A pure Verifier node has had no contact with the Task
// before OPEN_VERIFY arrives, so requiring a local record first would require it to
// be selected first, and being selected requires raising a hand first - a deadlock;
// querying the chain by task_id breaks the cycle without the message having to carry
// a single extra field.
//
// The task_hash OPEN_VERIFY carries must equal the chain's accepted value. A frame
// is always a restatement, and the chain is the authority.
func (r *TaskRunner) verifyTaskBinding(ctx context.Context, message verifierHandraiseTrigger) (layout.StoredHash, string, error) {
	verifyTaskHash, _, findErr := layout.FindVerifyRecordByTaskID(ctx, r.cfg.Store, message.TaskID)
	if findErr == nil {
		record, err := layout.GetTaskRecord(ctx, r.cfg.Store, verifyTaskHash)
		if err != nil {
			return layout.StoredHash{}, "", builderclient.Retryable(
				fmt.Errorf("read verify task record for %s: %w", message.TaskID, err))
		}
		if record.SessionID != "" {
			if message.TaskHash != (codec.Hash{}) && message.TaskHash != codec.Hash(verifyTaskHash) {
				return layout.StoredHash{}, "", fmt.Errorf(
					"%s task_hash does not match Keeper accepted task_hash for %s", message.Kind, message.TaskID)
			}
			return verifyTaskHash, record.SessionID, nil
		}
	}
	snapshot, err := r.cfg.TaskReader.Task(ctx, "", message.TaskID)
	if err != nil {
		return layout.StoredHash{}, "", builderclient.Retryable(
			fmt.Errorf("query Keeper task %s by task_id: %w", message.TaskID, err))
	}
	sessionID := strings.TrimSpace(snapshot.Assignment.SessionID)
	accepted := snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash
	if sessionID == "" || len(accepted) != 32 {
		return layout.StoredHash{}, "", builderclient.Retryable(
			fmt.Errorf("Keeper task %s carries no session_id/accepted_task_hash yet", message.TaskID))
	}
	acceptedHash := codec.Hash(accepted)
	if message.TaskHash != (codec.Hash{}) && message.TaskHash != acceptedHash {
		return layout.StoredHash{}, "", fmt.Errorf(
			"%s task_hash does not match Keeper accepted task_hash for %s", message.Kind, message.TaskID)
	}
	return layout.StoredHashFromCodec(acceptedHash), sessionID, nil
}

// raiseVerifierHand runs one handraise attempt and then decides whether this
// task-round is still owed another one.
//
// The split exists because nothing redelivers OPEN_VERIFY on this node's
// behalf: a handler that returns builderclient.Retryable is asserting a
// redelivery nobody performs, so before this the wait lived on one handler's
// stack and died with it. Measured on
// trueopen-localnet-1: the Builder's four frames all landed in h0..h0+4, the
// candidate window turned READY at h0+5, and the eight blocks it was open for
// went by with no handraise on a node that was in the window -- six tasks in a
// row, zero MsgSubmitVerifierHandraises.
func (r *TaskRunner) raiseVerifierHand(ctx context.Context, message verifierHandraiseTrigger) error {
	if message.VerifyRound == 0 {
		message.VerifyRound = supportedVerifyRound
	}
	r.handraiseMu.Lock()
	defer r.handraiseMu.Unlock()
	// One chain view per attempt, sampled before the Keeper reads so that the
	// wait milestone, the precheck and the re-drive bookkeeping all speak about
	// the same height.
	tip := r.currentChainTip(ctx)
	err, cached := r.repeatedHandraiseBlockWait(message.TaskID, message.VerifyRound, tip)
	if !cached {
		err = r.raiseVerifierHandOnce(ctx, tip, message)
		r.recordHandraiseBlockWait(message.TaskID, message.VerifyRound, tip, err)
	}
	// Bookkeeping runs on a suppressed attempt too. The re-drive is armed by the
	// first redrivable frame that reaches this function for a task-round, and
	// that frame can be the second one this block. Skipping the arming would
	// trade a redundant Keeper query for a lost handraise.
	if message.Redrivable {
		r.updateVerifierHandraiseRedrive(message, tip, err)
	}
	return err
}

// handraiseBlockWait is one task-round's last chain-state wait: the block it was
// refused at, and the refusal itself.
type handraiseBlockWait struct {
	height uint64
	err    error
}

// repeatedHandraiseBlockWait answers an attempt from the previous one when the
// two are in the same block and the previous one ended in a chain-state wait.
//
// Only that verdict is reused, and only inside one block. What the wait is
// waiting for -- the verifier candidate window turning READY at h_window
// (keeper-interface-contract §4.4) -- changes at a block boundary and nowhere else, so a
// second Keeper round trip inside one block can only return the first one's
// answer. Every other verdict is frame-specific: a refusal that a commitment
// disagrees with Keeper belongs to the frame that carried it, and reusing it
// would refuse a different, correct frame that arrived in the same block.
//
// More than one scheduler drives a task-round -- the Builder re-sends
// OPEN_VERIFY and the re-drive fires on the poll interval -- and only the
// re-drive has a gate of its own. Without this, a five-block wait turned into
// dozens of identical `verifier_window_pending` lines and Keeper queries.
func (r *TaskRunner) repeatedHandraiseBlockWait(taskID string, verifyRound uint32, tip chainTip) (error, bool) {
	if !tip.readable {
		return nil, false
	}
	previous, ok := r.handraiseBlockWaits[chainWaitKey(taskID, verifyRound)]
	if !ok || previous.height != tip.height {
		return nil, false
	}
	return fmt.Errorf("%w: %w", errRepeatedChainStateWait, previous.err), true
}

func (r *TaskRunner) recordHandraiseBlockWait(taskID string, verifyRound uint32, tip chainTip, err error) {
	key := chainWaitKey(taskID, verifyRound)
	if !tip.readable || !isChainStateWait(err) {
		delete(r.handraiseBlockWaits, key)
		return
	}
	if r.handraiseBlockWaits == nil {
		r.handraiseBlockWaits = make(map[string]handraiseBlockWait)
	}
	// Bounded by the same ceiling as the wait counters, and for the same reason:
	// a chain that never materializes a window keeps every affected task-round
	// waiting at once, and nothing else limits how many that is.
	if len(r.handraiseBlockWaits) >= maxTrackedChainWaits {
		clear(r.handraiseBlockWaits)
	}
	r.handraiseBlockWaits[key] = handraiseBlockWait{height: tip.height, err: err}
}

func (r *TaskRunner) raiseVerifierHandOnce(ctx context.Context, tip chainTip, message verifierHandraiseTrigger) error {
	if r.cfg.TaskReader == nil {
		return builderclient.Retryable(fmt.Errorf("authoritative Keeper task reader is required for %s", message.Kind))
	}
	// Take the durable verify-candidate claim before the Keeper read and the
	// expensive confirmation / signature work, but note that the claim only
	// suppresses a duplicate once it is marked complete at the end of this
	// function. The local verify record must already exist; if it does not, the
	// message arrived before assignment and should be redelivered.
	verifyTaskHash, sessionID, err := r.verifyTaskBinding(ctx, message)
	if err != nil {
		return err
	}
	// What the frame claimed, before a single value is checked against Keeper.
	// Printed separately from the chain's own view below so a disagreement shows
	// which side carries which digest.
	r.cfg.Trace.Event("verifier_trigger",
		tasktrace.Str("kind", message.Kind), tasktrace.Str("task", message.TaskID),
		tasktrace.Str("session", sessionID), tasktrace.Hash("task_hash", codec.Hash(verifyTaskHash)),
		tasktrace.Str("worker", message.Worker),
		tasktrace.Hash("frame_output_hash", codec.Hash(message.OutputHash)),
		tasktrace.Hash("frame_infer_receipt_hash", message.InferReceiptHash),
		tasktrace.Hash("frame_task_hash", message.TaskHash),
		tasktrace.Str("sender", message.SenderOperatorAddress))
	verifyAdmission := layout.VerifierAdmission{
		SchemaVersion: layout.VerifierAdmissionSchemaVersion,
		OutputHash:    layout.StoredHashFromCodec(codec.Hash(message.OutputHash)),
	}
	verifyRound := uint64(message.VerifyRound)
	alreadyClaimed, err := layout.VerifyAdmissionBatch(ctx, r.cfg.Store, verifyTaskHash, verifyRound, verifyAdmission)
	if err != nil {
		return err
	}
	if alreadyClaimed && message.DataReadyBuilderOperator == "" {
		// A previous delivery already completed this round's confirmation and
		// handraise. An incomplete claim does not land here: that one is redone.
		return nil
	}
	snapshot, err := r.cfg.TaskReader.Task(ctx, sessionID, message.TaskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("query Keeper task %s: %w", message.TaskID, err))
	}
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("validate Keeper task %s: %w", message.TaskID, err)
	}
	assigned := snapshot.Assignment
	if assigned.SessionID != sessionID || assigned.TaskID != message.TaskID || assigned.SelectedWorker != message.Worker {
		return fmt.Errorf("%s worker does not match Keeper winner", message.Kind)
	}
	if message.ModelID != "" && (message.ModelID != assigned.ModelID || message.ProfileVersion != assigned.ProfileVersion.Uint32()) {
		return fmt.Errorf("%s model/profile does not match Keeper assignment", message.Kind)
	}
	// Worker/Verifier mutual exclusion is judged against the Keeper winner before
	// the metadata round trip, candidate-window query and any signature. Every
	// node may receive the call for verification, so the winning Worker
	// receiving its own task is an expected no-op, not a delivery failure, and
	// returning an error here would only make the Builder retry it.
	if r.cfg.LocalVerifierAddress != "" && r.cfg.LocalVerifierAddress == assigned.SelectedWorker {
		r.cfg.Trace.Event("verifier_trigger_skipped",
			tasktrace.Str("kind", message.Kind), tasktrace.Str("task", message.TaskID),
			tasktrace.Str("session", sessionID), tasktrace.Hash("task_hash", codec.Hash(verifyTaskHash)),
			tasktrace.Str("worker", assigned.SelectedWorker), tasktrace.Str("reason", "self_winner"))
		return nil
	}
	// A call or a hint can outrun the chain. Until Keeper has the infer receipt
	// there is no authority to read the commitments from, and that is a "not
	// yet", not a refusal: the same task is admitted later from the snapshot
	// alone.
	if snapshot.InferReceipt.OutputHash.IsZero() {
		return builderclient.Retryable(fmt.Errorf("Keeper infer receipt for %s is not available", message.TaskID))
	}
	// Taken from the on-chain snapshot rather than the local infer record: the local
	// record holds this very value (the assignment effect sets AssignmentOrderDigest =
	// AcceptedOrderPayloadHash), and a pure Verifier node has no infer record at all -
	// that is a Worker-only thing.
	orderDigest := codec.Hash(assigned.AcceptedOrderPayloadHash)
	// output_hash is the commitment, and it is Keeper authority. The package hash
	// is read only so it can be printed: §4.4 removed it from every payload on
	// this bus and the frozen InferReceiptState carries none either, so
	// package_hash=zero below is the normal chain and nothing refuses on it.
	outputHash := codec.Hash(snapshot.InferReceipt.OutputHash)
	packageHash := codec.Hash(snapshot.InferReceipt.CanonicalOutputPackageHash)
	// The chain's own answer, printed before the comparisons that can refuse on
	// it.
	r.cfg.Trace.Event("keeper_infer_receipt",
		tasktrace.Str("kind", message.Kind), tasktrace.Str("task", message.TaskID),
		tasktrace.Hash("output_hash", outputHash), tasktrace.Hash("package_hash", packageHash),
		tasktrace.Hash("infer_receipt_hash", codec.Hash(snapshot.InferReceipt.InferReceiptHash)),
		tasktrace.Hash("order_digest", orderDigest),
		tasktrace.Str("winner_worker", snapshot.InferReceipt.WinnerWorker),
		tasktrace.Str("builder", assigned.BuilderOperatorAddress),
		tasktrace.Str("model", assigned.ModelID), tasktrace.Uint("profile_version", uint64(assigned.ProfileVersion.Uint32())))
	if snapshot.InferReceipt.SessionID != sessionID || snapshot.InferReceipt.TaskID != message.TaskID ||
		snapshot.InferReceipt.WinnerWorker != message.Worker || !bytes.Equal(message.OutputHash, outputHash[:]) {
		return fmt.Errorf("%s commitments do not match Keeper infer receipt", message.Kind)
	}
	if message.InferReceiptHash != (codec.Hash{}) && message.InferReceiptHash != codec.Hash(snapshot.InferReceipt.InferReceiptHash) {
		return fmt.Errorf("%s infer_receipt_hash does not match Keeper infer receipt", message.Kind)
	}
	if r.cfg.VerifierSender == nil {
		return builderclient.Permanent(fmt.Errorf("verifier frame sender is not configured"))
	}
	// V3 is done, and it was done above. data-plane-and-evidence-transfer.md §6 (written
	// when ORDER_BROADCAST was still a NATS subject; its metadata now rides the
	// OpenVerify frame) is the basis for this
	// section, and it nails the reverse direction down too: "the metadata a candidate
	// Worker/Verifier needs is broadcast by the ORDER_BROADCAST / OPEN_VERIFY control
	// messages and is not obtained through the data query interface", while
	// GetTaskDataMetadata "is not a prerequisite step of the normal Task flow". nexus's
	// own interface-and-topic-list.md §4.6 repeats it in the same words and confines FetchTaskData's
	// authorisation to the selected Worker, the selected Verifier and the original User -
	// a candidate is none of them.
	//
	// So the GetTaskDataMetadata call before a handraise was not "one more safeguard": it
	// is a call named and forbidden, and on a real chain it is necessarily refused
	// NEXUS_DATA_UNAUTHORIZED, which is why not one Verifier handraise ever went out.
	// Everything it checked is already here: the envelope's output_hash /
	// infer_receipt_hash / winner_worker / session_id are each reconciled against the
	// Keeper snapshot (the two ifs above), and output_size_bytes comes from the chain's
	// InferReceiptState.
	//
	// "The Builder really holds this output" needs no probe either: interface-and-topic-list.md §5.8
	// states that a Builder "may publish only once the corresponding InferReceipt has been
	// accepted by Keeper and it holds the data the protocol requires locally", acceptance
	// of MsgSubmitVerifierHandraises constitutes that Builder's on-chain data-ready
	// declaration, and the remedy when the data really cannot be fetched is V7b's
	// MsgReportDataUnavailable. The fields the handraise signature binds (§5.9) carry no
	// size and no Builder-local state either.
	//
	// This node cannot produce that remedy, for the reason written in
	// missingDataUnavailableRemedy (task_runner_run.go): the bitmap has to follow the
	// frozen order of TaskBuilderSelectionState.selected_task_builders, and the frozen
	// task.v1.Query service has no rpc that returns that list. So this is not a
	// "write it later", it is one missing chain read; the gap is reported together with
	// LastError and responsibility_stopped when the commit deadline closes the window,
	// instead of living only in a comment.
	//
	// The object itself is downloaded by RunVerify only after the chain has confirmed this
	// node was selected (V7a), and that path is authorised as a selected verifier, which
	// is compliant.
	outputSizeBytes := snapshot.InferReceipt.OutputSizeBytes.Uint64()
	// The on-chain task snapshot does not say which Builder holds the output.
	// interface-and-topic-list.md §5.8's "publishes only when it holds the data the protocol requires
	// locally" guarantees the sender of OPEN_VERIFY holds it, so the sender is used as the
	// fetch target.
	dataReadyBuilder := strings.TrimSpace(message.DataReadyBuilderOperator)
	holdingBuilder := assigned.BuilderOperatorAddress
	if holdingBuilder == "" {
		holdingBuilder = dataReadyBuilder
	}
	completedAdmission := layout.VerifierAdmission{
		SchemaVersion:            layout.VerifierAdmissionSchemaVersion,
		InferReceiptHash:         layout.StoredHashFromCodec(codec.Hash(snapshot.InferReceipt.InferReceiptHash)),
		OutputHash:               layout.StoredHashFromCodec(outputHash),
		DataReadyBuilderOperator: dataReadyBuilder,
	}
	if alreadyClaimed {
		// A handraise already completed for this round. The OPEN_VERIFY still
		// supplies the data-ready Builder, but only after its receipt/output
		// facts matched Keeper.
		return layout.CompleteVerifyAdmission(ctx, r.cfg.Store, verifyTaskHash, verifyRound, completedAdmission)
	}
	r.cfg.Trace.Event("output_metadata_confirmed",
		tasktrace.Str("kind", message.Kind), tasktrace.Str("task", message.TaskID),
		tasktrace.Str("source", "open_verify+keeper"),
		tasktrace.Hash("output_hash", outputHash),
		tasktrace.Uint("output_size_bytes", outputSizeBytes),
		tasktrace.Hash("receipt_hash", codec.Hash(snapshot.InferReceipt.InferReceiptHash)),
		tasktrace.Str("builder", holdingBuilder))
	capability, err := r.capabilityFor(assigned.ModelID, assigned.ProfileVersion.Uint32())
	if err != nil {
		return err
	}
	member := builderclient.CandidateMemberRefMessage{}
	inferReceiptHash := codec.Hash(snapshot.InferReceipt.InferReceiptHash)
	handraiseExpiry := tip.height + r.cfg.VerifyDeadlineDeltaHeight
	if r.cfg.VerifierMemberReader != nil {
		candidate, err := r.cfg.VerifierMemberReader.VerifierCandidateMember(ctx, assigned.TaskID, uint32(verifyRound), r.cfg.LocalVerifierAddress)
		if errors.Is(err, chainclient.ErrVerifierWindowNotReady) {
			return r.verifierWindowWait(assigned.TaskID, uint32(verifyRound), tip.height, err)
		}
		if errors.Is(err, chainclient.ErrVerifierWindowClosed) {
			return r.verifierWindowClosed(assigned.TaskID, uint32(verifyRound), tip.height, err)
		}
		if err != nil {
			return builderclient.Retryable(fmt.Errorf("query verifier candidate window member: %w", err))
		}
		r.forgetChainWait(chainWaitKey(assigned.TaskID, uint32(verifyRound)))
		member = builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: candidate.CandidatePoolSnapshotID.Hex(), Slot: candidate.Slot,
			SlotVersion: candidate.SlotVersion, OperatorAddress: candidate.OperatorAddress,
		}
		if inferReceiptHash == (codec.Hash{}) || inferReceiptHash != codec.Hash(candidate.InferReceiptHash) {
			return fmt.Errorf("verifier candidate window infer_receipt_hash does not match Keeper task snapshot")
		}
		inferReceiptHash = codec.Hash(candidate.InferReceiptHash)
		handraiseExpiry = candidate.ExpiryHeight
	} else {
		return builderclient.Retryable(fmt.Errorf("verifier candidate member reader is required"))
	}
	state := verifier.TaskState{TaskID: assigned.TaskID, SessionID: assigned.SessionID, OrderSequence: assigned.OrderSequence.Uint64(), OrderDigest: orderDigest, VerifyRound: verifyRound, InferReceiptHash: inferReceiptHash, Member: member, ModelID: assigned.ModelID, ProfileVersion: assigned.ProfileVersion.Uint32(), Capability: capability, WorkerAddress: assigned.SelectedWorker, OutputPackage: confirmedOutputSummary(message.TaskID, outputHash), OutputConfirmed: true, OpenVerifyHeight: tip.height, HandraiseExpiryHeight: handraiseExpiry, CurrentHeight: tip.height}
	if r.cfg.HandraiseEligibility != nil {
		precheck, e := r.cfg.HandraiseEligibility.Verifier(ctx, VerifierHandraiseCandidate{TaskID: state.TaskID, SessionID: state.SessionID, ModelID: state.ModelID, ProfileVersion: state.ProfileVersion, Capability: state.Capability, WorkerAddress: state.WorkerAddress, OpenHeight: state.OpenVerifyHeight})
		if e != nil {
			return e
		}
		state.HandraisePrecheck = &precheck
		state.CurrentHeight = precheck.CurrentHeight
	} else if !r.cfg.FakeOutput {
		return fmt.Errorf("production Verifier handraise eligibility resolver is required")
	}
	signerAddress, _ := resolveSigningIdentity(r.cfg, r.cfg.LocalVerifierAddress)
	// service_authorization_nonce from one committed read of this node's own
	// current ServiceKey binding.
	authorizationNonce, _, err := r.cfg.TaskDataAuth.CommittedServiceBinding(ctx)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read current Cortex service binding for the VerifierHandraise: %w", err))
	}
	v := verifier.New(verifier.Config{VerifierAddress: r.cfg.LocalVerifierAddress, ChainID: r.cfg.ChainID, SignerAddress: signerAddress, SignerKeyRef: r.cfg.SignerKeyRef, Signer: r.cfg.Signer, VerifyDeadlineDeltaHeight: r.cfg.VerifyDeadlineDeltaHeight, FakeOutput: r.cfg.FakeOutput, Sender: r.cfg.VerifierSender, ServiceAuthorizationNonce: authorizationNonce, MaxOutputBytes: r.cfg.MaxOutputBytes, Trace: r.cfg.Trace})
	result, err := v.EvaluateAndHandraise(ctx, state)
	if err != nil && (builderclient.IsRetryable(err) || modelservice.IsRetryable(err)) {
		return builderclient.Retryable(err)
	}
	if err != nil {
		return err
	}
	traceVerifierHandraise := r.cfg.Trace.Event
	if !result.Decision.Accepted {
		traceVerifierHandraise = r.cfg.Trace.ErrorEvent
	}
	traceVerifierHandraise("verifier_handraise",
		tasktrace.Str("kind", message.Kind), tasktrace.Str("task", message.TaskID),
		tasktrace.Bool("accepted", result.Decision.Accepted), tasktrace.Str("reject_code", result.Decision.RejectCode),
		tasktrace.Hash("infer_receipt_hash", inferReceiptHash),
		tasktrace.Hash("output_hash", outputHash), tasktrace.Hash("package_hash", packageHash),
		tasktrace.Str("candidate_pool_snapshot_id", member.CandidatePoolSnapshotID),
		tasktrace.Uint("slot", uint64(member.Slot)), tasktrace.Uint("slot_version", uint64(member.SlotVersion)),
		tasktrace.Uint("open_verify_height", state.OpenVerifyHeight), tasktrace.Uint("current_height", state.CurrentHeight),
		tasktrace.Uint("handraise_expiry_height", handraiseExpiry))
	// A precheck refusal is not a success: it has to leave a trace carrying the reject
	// code and keep the redelivery alive. The reasons for a refusal - slots, support
	// freshness, being too close to the deadline - mostly change with height, and marking
	// it complete would send every later redelivery down the dedup path, so this task
	// could never raise a hand again and nothing would appear in the log.
	if !result.Decision.Accepted {
		return builderclient.Retryable(fmt.Errorf("Verifier handraise precheck rejected %s: %s %s",
			message.TaskID, result.Decision.RejectCode, strings.TrimSpace(result.Decision.AuditSummary)))
	}
	completedAdmission.ExpiryHeight = handraiseExpiry
	// Only now does the claim start suppressing duplicates. Marking it here is
	// what makes redelivery safe: every path above can fail retryably - the chain
	// can be behind the hint, Nexus can be down - and a claim marked complete
	// before the work would send the redelivery down the duplicate path, leaving
	// the task with no confirmation and no handraise for good.
	return layout.CompleteVerifyAdmission(ctx, r.cfg.Store, verifyTaskHash, verifyRound, completedAdmission)
}

// taskIDHex projects a payload task_id (raw Hash32) into the canonical
// lowercase hex the task plane keys records by.
func taskIDHex(taskID []byte) (string, error) {
	if len(taskID) != 32 {
		return "", fmt.Errorf("task_id must be 32 bytes, got %d", len(taskID))
	}
	return hex.EncodeToString(taskID), nil
}
