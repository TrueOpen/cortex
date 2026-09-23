package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/verifier"
	"github.com/TrueOpen/cortex/internal/worker"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	"google.golang.org/protobuf/proto"
)

// HandleNexusMessage is the delivery callback: no received Builder bytes are
// persisted. It authenticates and validates first, then admits an eligible
// order, commits the stable signed handraise, and finally publishes it.
func (r *TaskRunner) HandleNexusMessage(ctx context.Context, msg builderclient.NATSMessage) error {
	if r == nil || r.cfg.Store == nil {
		return fmt.Errorf("task runner store is required")
	}
	envelope, kind, payload, err := r.validateNexusMessage(ctx, msg)
	if err != nil {
		r.releaseEnvelopeClaimForRedelivery(msg.Subject, envelope, err)
		return err
	}
	var handleErr error
	switch kind {
	case builderclient.KindOrderBroadcast:
		if r.cfg.LocalWorkerAddress != "" {
			handleErr = r.admitOrder(ctx, strings.TrimSpace(msg.Subject), envelope, payload.(*busv1.OrderBroadcastV1))
		}
	case builderclient.KindOutputAvailable:
		if r.cfg.LocalVerifierAddress != "" {
			handleErr = r.admitOutputAvailable(ctx, envelope, payload.(*busv1.OutputAvailableV1))
		}
	case builderclient.KindWorkerAssignmentNotify:
		if r.cfg.LocalWorkerAddress != "" {
			handleErr = r.recordAssignNotify(ctx, envelope, payload.(*busv1.WorkerAssignmentNotifyV1))
		}
	case builderclient.KindOpenVerify:
		// OPEN_VERIFY is the call for Verifier handraises. It is the
		// Verifier-side counterpart of ORDER_BROADCAST, not a notification:
		// reaching the precheck and publishing on
		// trueopen.handraise.verifier.<task_id> is the whole point of receiving it.
		if r.cfg.LocalVerifierAddress != "" {
			handleErr = r.admitOpenVerify(ctx, envelope, payload.(*busv1.OpenVerifyV1))
		}
	case builderclient.KindVerifierAssignmentNotify:
		if r.cfg.LocalVerifierAddress != "" {
			handleErr = r.recordVerifierAssignment(ctx, envelope, payload.(*busv1.VerifierAssignmentNotifyV1))
		}
	default:
		handleErr = fmt.Errorf("recognized Builder frame %s has no disposition", kind)
	}
	// A merge-boundary conflict is a permanent per-task refusal: the same frame
	// contradicts the same stored field on every redelivery, so retrying it is
	// how a NAK loop starts. Assert the verdict rather than leaving it to the
	// default, because the verifier subjects these frames arrive on are
	// redelivered by subject regardless of what the handler concluded.
	if handleErr != nil && errors.Is(handleErr, layout.ErrConflict) {
		handleErr = builderclient.Permanent(handleErr)
	}
	if handleErr != nil && r.cfg.Diagnostic != nil && !isRepeatedChainStateWait(handleErr) {
		r.cfg.Diagnostic(TaskRunnerDiagnostic{
			Source:  "nexus_" + strings.ToLower(string(kind)),
			Record:  envelope.Subject,
			Error:   handleErr.Error(),
			Waiting: isChainStateWait(handleErr),
		})
	}
	r.releaseEnvelopeClaimForRedelivery(msg.Subject, envelope, handleErr)
	return handleErr
}

func (r *TaskRunner) releaseEnvelopeClaimForRedelivery(subject string, envelope builderclient.BusEnvelope, err error) {
	if err == nil || envelope.MessageID == "" || !inboxWillRedeliver(subject, err) {
		return
	}
	if releaser, ok := r.cfg.NexusEnvelopeAuthenticator.(interface {
		Release(string, builderclient.BusEnvelope)
	}); ok {
		releaser.Release(strings.TrimSpace(subject), envelope)
	}
}

func inboxWillRedeliver(subject string, err error) bool {
	// A permanent verdict is never redelivered, so the envelope claim must stay
	// consumed: releasing it would arm a replay of a frame the inbox is about to
	// acknowledge and refuse.
	if builderclient.IsPermanent(err) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		builderclient.IsRetryable(err) || errors.Is(err, builderclient.ErrBusEnvelopeAuthenticationUnavailable) {
		return true
	}
	// Only the JetStream-tier subjects: a Core subject has no redelivery to
	// arm a replay against, and OPEN_VERIFY is Core exactly like OPEN_TASK.
	kind, _, ok := builderclient.KindForSubject(strings.TrimSpace(subject))
	return ok && (kind == builderclient.KindWorkerAssignmentNotify ||
		kind == builderclient.KindOutputAvailable || kind == builderclient.KindVerifierAssignmentNotify)
}

func (r *TaskRunner) recordAssignNotify(ctx context.Context, envelope builderclient.BusEnvelope, message *busv1.WorkerAssignmentNotifyV1) error {
	taskID, err := busTaskIDHex(message.GetTaskId(), envelope.Subject)
	if err != nil {
		return fmt.Errorf("WorkerAssignmentNotify: %w", err)
	}
	winner := strings.TrimSpace(message.GetWinnerOperatorAddress())
	if winner == "" {
		return fmt.Errorf("WorkerAssignmentNotify winner_operator_address is required")
	}
	if len(message.GetTaskHash()) != 32 {
		return fmt.Errorf("WorkerAssignmentNotify task_hash must be 32 bytes, got %d", len(message.GetTaskHash()))
	}
	// Not being selected is not a failure. By design this notice goes to the winner and
	// the losers alike (payload.proto:26 - "tells the losing workers to stop and the
	// winner to start"), and the Keeper path silently skips the same fact
	// (task_runner_run.go:221). A loser never admitted this task and has nothing to
	// stop, so: normal terminal state, ack, no error.
	//
	// Reporting an error costs more than two extra log lines: JetStream redelivers, the
	// inbox's dedup key is the hash of the whole frame, and every redelivery carries a
	// new message_id - so dedup never takes effect and the failure log scrolls forever.
	if winner != r.cfg.LocalWorkerAddress {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	foundHash, foundRec, err := layout.FindInferRecordByTaskID(ctx, r.cfg.Store, taskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("Keeper assignment for %s is not available: %w", taskID, err))
	}

	tr, err := layout.GetTaskRecord(ctx, r.cfg.Store, foundHash)
	if err != nil {
		return err
	}
	if tr.WorkerAddress != winner || foundRec.WinnerConfirmHeight != message.GetFinalizedHeight() {
		return fmt.Errorf("WorkerAssignmentNotify does not match the authoritative assignment")
	}
	// task_hash is the object §5.2 authorises, H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V1",
	// TaskOrderV1), i.e. Keeper's accepted_task_hash - local storage is keyed by exactly
	// that (reconciler.go:161-167), so foundHash is the value to compare against.
	//
	// What used to be compared was tr.AssignmentOrderDigest, and that field holds
	// accepted_input_hash (task_runner_run.go:241-244 fills all three fields from it),
	// which is a different chain field: by definition the two can never be equal
	// (nodewire.TestAcceptedTaskHashDiffersFromAssignmentOrderDigest pins exactly that),
	// so the winner could never accept this notice.
	if !bytes.Equal(message.GetTaskHash(), foundHash[:]) {
		return fmt.Errorf("WorkerAssignmentNotify task_hash does not match the accepted task hash")
	}

	// The V2 notify carries no payload CID and no BuilderSet reference: input
	// location comes from the Keeper snapshot and the task-data plane, and the
	// envelope no longer has BuilderSet fields to copy. Nothing durable to
	// merge; the message's effect is to wake this node earlier.
	_ = tr
	r.Wake()
	return nil
}

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
func (r *TaskRunner) recordVerifierAssignment(ctx context.Context, envelope builderclient.BusEnvelope, message *busv1.VerifierAssignmentNotifyV1) error {
	if r.cfg.TaskReader == nil {
		return builderclient.Retryable(fmt.Errorf("authoritative Keeper task reader is required for VerifierAssignmentNotify"))
	}
	taskID, err := busTaskIDHex(message.GetTaskId(), envelope.Subject)
	if err != nil {
		return fmt.Errorf("VerifierAssignmentNotify: %w", err)
	}
	verifiers := make([]string, 0, len(message.GetVerifiers()))
	for _, selected := range message.GetVerifiers() {
		verifiers = append(verifiers, selected.GetOperatorAddress())
	}
	// Not being selected is not a failure, exactly as for a WORKER_ASSIGNMENT_NOTIFY
	// loser: this notice goes out on the per-task subject every candidate subscribes to
	// (§5.9), this node has nothing to record, so normal terminal state, ack, no error.
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
	// No redelivery of this frame can grow an output hash, and the subject it
	// arrived on is redelivered by subject rather than by verdict
	// (outbox.verifierFrame), so the verdict has to be asserted or the frame
	// NAKs until the envelope expires. Two of the three Builders in a proposal
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

// admitOutputAvailable treats OUTPUT_AVAILABLE as what the design says it is:
// an auxiliary hint (detailed-design §4.6, interface-and-topic-list §5.8) that a Verifier's output
// metadata is ready, so the scheduler can wake before the chain would have woken
// it. It is never the criterion for verifiability -- OPEN_VERIFY plus the Keeper
// snapshot are, and ApplyReconcilerEffects admits the same task from chain state
// with no hint at all. So the only fields required here are the ones that say
// which task the hint is about plus its semantic core, the committed output
// hash; everything this node then acts on is read from the snapshot.
func (r *TaskRunner) admitOutputAvailable(ctx context.Context, envelope builderclient.BusEnvelope, message *busv1.OutputAvailableV1) error {
	taskID, err := busTaskIDHex(message.GetTaskId(), envelope.Subject)
	if err != nil {
		return fmt.Errorf("OutputAvailable: %w", err)
	}
	if message.GetWorkerOperatorAddress() == "" || len(message.GetOutputHash()) != 32 {
		return fmt.Errorf("OutputAvailable missing required fields")
	}
	// A CORTEX sender must be the Worker it names. The frozen subject table
	// admits this kind from both domains and attaches the condition to the
	// CORTEX row: "the sender must still agree with the on-chain winner, which
	// the consumer checks". The authenticator cannot check it - it proves the
	// sender holds a current ACTIVE CORTEX_NODE key, and there is no chain query
	// for the set of Cortex nodes - so without this any registered node could
	// publish hints about tasks that are not its own. raiseVerifierHand binds
	// the named worker to the Keeper winner below; this binds the signer to the
	// name, and the two together are the whole chain.
	//
	// It is CORTEX-only: the BUILDER row is the receiving Builder relaying the
	// hint, which is legitimately not the Worker.
	if envelope.SenderParticipantType == builderclient.ParticipantCortex {
		sender := strings.TrimSpace(envelope.SenderOperatorAddress)
		if sender != strings.TrimSpace(message.GetWorkerOperatorAddress()) {
			return builderclient.Permanent(fmt.Errorf(
				"OutputAvailable was published by Cortex node %s but names worker %s: a Cortex sender may only announce its own output",
				sender, message.GetWorkerOperatorAddress()))
		}
	}
	return r.raiseVerifierHand(ctx, verifierHandraiseTrigger{
		Kind: "OutputAvailable", TaskID: taskID,
		Worker: message.GetWorkerOperatorAddress(), OutputHash: message.GetOutputHash(),
		SenderOperatorAddress: envelope.SenderOperatorAddress,
		// Deliberately not redrivable: the hint arrives on a JetStream subject
		// (inboxWillRedeliver), so the transport already brings it back. Arming a
		// local re-drive on top of that would run two attempts at the same
		// task-round from two schedulers.
	})
}

// admitOpenVerify consumes OPEN_VERIFY (§5.6), the Core-tier call for Verifier
// handraises. It is the Verifier-side counterpart of OPEN_TASK: the Builder
// opens the window, every Verifier candidate that can serve this task raises its
// hand on trueopen.handraise.verifier.<task_id>, and the selected set is decided on
// chain afterwards.
//
// Before the v1 vocabulary this subject did not exist on Cortex at all. The
// pre-v1 bus merged the call and the selection into one VERIFY_SELECT_NOTIFY,
// which meant the only thing that could start a Verifier handraise here was the
// OUTPUT_AVAILABLE hint - a message §5.8 explicitly says triggers nothing. Both
// paths now converge on raiseVerifierHand and share its at-most-once claim, so a
// task that receives the call and the hint still raises its hand exactly once.
func (r *TaskRunner) admitOpenVerify(ctx context.Context, envelope builderclient.BusEnvelope, message *busv1.OpenVerifyV1) error {
	taskID, err := busTaskIDHex(message.GetTaskId(), envelope.Subject)
	if err != nil {
		return fmt.Errorf("OpenVerify: %w", err)
	}
	if message.GetWorkerOperatorAddress() == "" || message.GetModelId() == "" || message.GetProfileVersion() == 0 || len(message.GetOutputHash()) != 32 {
		return fmt.Errorf("OpenVerify missing required fields")
	}
	if len(message.GetTaskHash()) != 32 {
		return fmt.Errorf("OpenVerify task_hash must be 32 bytes")
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
		ModelID: message.GetModelId(), ProfileVersion: message.GetProfileVersion(), VerifyRound: message.GetVerifyRound(),
		InferReceiptHash:         codec.Hash(message.GetInferReceiptHash()),
		SenderOperatorAddress:    envelope.SenderOperatorAddress,
		DataReadyBuilderOperator: envelope.SenderOperatorAddress,
		// The call is the one handraise trigger with no transport behind it, so
		// it is the one that arms the local re-drive. See
		// task_runner_handraise_redrive.go.
		Redrivable: true,
	}
	return r.raiseVerifierHand(ctx, trigger)
}

const supportedVerifyRound = uint32(1)

// verifierHandraiseTrigger is the part of an inbound frame that decides whether
// this node should raise a Verifier hand. Both OPEN_VERIFY and the
// OUTPUT_AVAILABLE hint reduce to it, and neither is an authority: every field
// is cross-checked against the Keeper snapshot below.
type verifierHandraiseTrigger struct {
	Kind       string
	TaskID     string
	Worker     string
	OutputHash []byte
	ModelID    string
	// ProfileVersion and VerifyRound are carried only by OPEN_VERIFY. The
	// OUTPUT_AVAILABLE compatibility trigger leaves them zero.
	ProfileVersion uint32
	VerifyRound    uint32
	// InferReceiptHash is carried by OPEN_VERIFY (§5.6) and absent on the
	// OUTPUT_AVAILABLE hint. When present it must equal the Keeper receipt: a
	// Builder calling for verification of a receipt the chain does not hold is
	// calling for verification of nothing.
	InferReceiptHash codec.Hash
	// TaskHash is carried by OPEN_VERIFY (§5.8) and absent on the OUTPUT_AVAILABLE
	// hint. When present it must equal the Keeper's accepted task hash: it is a
	// frame-level restatement, never the authority.
	TaskHash codec.Hash
	// SenderOperatorAddress is the frame's already-authenticated sender and is
	// retained for diagnostics.
	SenderOperatorAddress string
	// DataReadyBuilderOperator is set only by OPEN_VERIFY. A Builder may relay
	// OUTPUT_AVAILABLE, but only OPEN_VERIFY carries the protocol's local
	// data-ready declaration.
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
// The task_hash OPEN_VERIFY always carries must equal the chain's accepted value;
// OUTPUT_AVAILABLE does not carry that field. A frame is always a restatement, and
// the chain is the authority.
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
// The split exists because OPEN_VERIFY is Core tier (interface-and-topic-list.md §5.1) and
// Core is fire-and-forget: a handler that returns builderclient.Retryable on
// that subject is asserting a redelivery nobody performs, so before this the
// wait lived on one handler's stack and died with it. Measured on
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
	// first frame that reaches this function for a task-round, and that frame is
	// often the second one this block: OPEN_VERIFY is the only trigger with no
	// transport behind it, and the JetStream hint frequently arrives first.
	// Skipping the arming would trade a redundant Keeper query for a lost
	// handraise.
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
// Three schedulers drive one task-round independently -- the Builder re-sends
// OPEN_VERIFY, JetStream redelivers the OUTPUT_AVAILABLE hint about once a
// second after a NAK, and the re-drive fires on the poll interval -- and only
// the re-drive had a gate of its own. The other two turned a five-block wait
// into 28 identical `verifier_window_pending` lines and 29 Keeper queries.
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
	// node subscribes to the Verifier subjects, so the winning Worker receiving
	// its own task is an expected no-op, not a delivery failure: returning an
	// error here makes the JetStream OUTPUT_AVAILABLE frame NAK forever.
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
	if r.cfg.Builder == nil {
		return builderclient.Retryable(fmt.Errorf("builder client is required for Verifier handraise"))
	}
	// V3 is done, and it was done above. data-plane-and-evidence-transfer.md §6 is the basis for this
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
	// fetch target - the same thing the Worker side does when it fills BroadcastingBuilder
	// from the sender of ORDER_BROADCAST. OUTPUT_AVAILABLE is published by the Worker and
	// does not apply.
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
		// A handraise completed from another valid trigger (normally
		// OUTPUT_AVAILABLE). The authenticated OPEN_VERIFY still supplies the
		// data-ready Builder, but only after its receipt/output facts matched Keeper.
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
	} else if r.cfg.FakeBus {
		member = builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: hex.EncodeToString(outputHash[:]), Slot: 1, SlotVersion: 1,
			OperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		}
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
	// Envelope field 7 from this node's own current ServiceKey binding (§5.2 field 7),
	// the same committed read admitOrder performs for the WorkerHandraise.
	authorizationNonce, _, err := r.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read current Cortex service binding for the VerifierHandraise envelope: %w", err))
	}
	v := verifier.New(verifier.Config{VerifierAddress: r.cfg.LocalVerifierAddress, Builder: r.cfg.Builder, ChainID: r.cfg.ChainID, SignerAddress: signerAddress, SignerKeyRef: r.cfg.SignerKeyRef, Signer: r.cfg.Signer, VerifyDeadlineDeltaHeight: r.cfg.VerifyDeadlineDeltaHeight, FakeOutput: r.cfg.FakeOutput, TrustedNATSDev: r.cfg.TrustedNATSDev || r.cfg.FakeBus, EnvelopeTTL: r.cfg.EnvelopeTTL, NexusEnvelopeSigner: r.cfg.NexusEnvelopeSigner, ServiceAuthorizationNonce: authorizationNonce, MaxOutputBytes: r.cfg.MaxOutputBytes, Trace: r.cfg.Trace})
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

// ValidateNexusMessage remains a read-only validation seam for callers being
// migrated to HandleNexusMessage. It never admits or persists a frame.
func (r *TaskRunner) ValidateNexusMessage(ctx context.Context, msg builderclient.NATSMessage) (string, error) {
	envelope, _, _, err := r.validateNexusMessage(ctx, msg)
	if err != nil {
		return "", err
	}
	return envelope.Subject, nil
}

func (r *TaskRunner) validateNexusMessage(ctx context.Context, msg builderclient.NATSMessage) (builderclient.BusEnvelope, builderclient.BusMessageKind, proto.Message, error) {
	if err := ctx.Err(); err != nil {
		return builderclient.BusEnvelope{}, "", nil, err
	}
	envelope, err := builderclient.DecodeBusEnvelope(msg.Data)
	if err != nil {
		return builderclient.BusEnvelope{}, "", nil, err
	}
	subject := strings.TrimSpace(msg.Subject)
	kind, payload, ok := builderclient.KindForSubject(subject)
	if !ok {
		return builderclient.BusEnvelope{}, "", nil, fmt.Errorf("unsupported Builder subject %q", subject)
	}
	if envelope.Subject != subject || envelope.Kind != kind {
		return builderclient.BusEnvelope{}, "", nil, fmt.Errorf("Builder envelope subject or kind mismatch")
	}
	// Intrinsic validation runs on EVERY inbound frame, including under
	// trusted_nats_dev and the fake bus. What it checks is not a property of the
	// signature: payload_digest committing the canonical payload, payload_codec,
	// and the kind/participant/role/stage/subject agreement are true or false
	// about the frame itself. Gating them behind authentication would mean the
	// devnet mode we actually run today accepts a frame with a false
	// payload_digest or an impossible stage, which is how a body that disagrees
	// with its own commitment would reach a handler.
	//
	// The authenticator repeats this call in strict mode. That is deliberate: it
	// must not depend on a caller having done it first, and the work is a hash
	// over a payload that is about to be decoded anyway.
	if err := envelope.ValidateEnvelopeIntrinsics(); err != nil {
		return envelope, kind, nil, fmt.Errorf("Builder envelope is internally inconsistent: %w", err)
	}
	// Freshness is a validity property, not an authentication one, so it is
	// checked here rather than only inside the authenticator.
	//
	// It used to live only in the authenticator (envelope_auth.go:474,477), which
	// trusted_nats_dev skips wholesale. ValidateEnvelopeIntrinsics above requires
	// the two stamps to be present and ordered but never compares them against
	// now, so under that posture an inbound frame had no expiry at all. Combined
	// with a Retryable handler failure and the durable's unlimited delivery
	// budget, that turned a bounded refusal into a permanent ~1/s redelivery
	// loop: measured at 23KB/min per node against an ASSIGN_NOTIFY whose
	// assignment Keeper does not have. Under strict the same frame died at
	// TTL+skew.
	//
	// The refusal is permanent on purpose. An envelope past its own expiry can
	// never become valid, so redelivering it is pure cost; acking it is what
	// ends the loop.
	if err := r.checkEnvelopeFreshness(envelope, time.Now().UTC()); err != nil {
		return envelope, kind, nil, builderclient.Permanent(err)
	}
	if !r.cfg.TrustedNATSDev && !r.cfg.FakeBus {
		if r.cfg.NexusEnvelopeAuthenticator == nil {
			return envelope, kind, nil, builderclient.ErrBusEnvelopeAuthenticationUnavailable
		}
		if err := r.cfg.NexusEnvelopeAuthenticator.Authenticate(ctx, subject, envelope); err != nil {
			return envelope, kind, nil, fmt.Errorf("authenticate Nexus BusEnvelope: %w", err)
		}
	}
	if err := envelope.DecodePayload(payload); err != nil {
		return envelope, kind, nil, err
	}
	return envelope, kind, payload, nil
}

func (r *TaskRunner) admitOrder(ctx context.Context, subject string, envelope builderclient.BusEnvelope, order *busv1.OrderBroadcastV1) (err error) {
	taskHash, orderFacts, signedOrderBytes, err := validateNexusOrderBroadcast(order, envelope, !r.cfg.FakeBus)
	if err != nil {
		return err
	}
	orderTaskID := identity.TaskIDString(orderFacts.SessionID, orderFacts.OrderSequence)
	// From here on, every exit updates the Worker order re-drive. This is the
	// first point at which the two things that bound a pending entry are known:
	// the order's identity and its own order_expire_height. The bookkeeping is a
	// defer rather than a call at each return because a retryable refusal can
	// leave this function from a dozen places and the one that matters most --
	// "no free slot" out of the eligibility precheck -- is in the middle.
	//
	// redriveTip is whatever chain view this attempt actually used; it stays
	// unreadable when the attempt short-circuits on a stored admission before
	// reading one, which costs nothing but the height-moved gate for that entry.
	redriveTip := chainTip{}
	defer func() {
		r.updateWorkerOrderRedrive(subject, envelope, order, orderTaskID, orderFacts.OrderExpireHeight, redriveTip, err)
	}()
	r.cfg.Trace.Event("order_broadcast",
		tasktrace.Str("task", orderTaskID), tasktrace.Str("session", orderFacts.SessionID),
		tasktrace.Uint("order_sequence", orderFacts.OrderSequence), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("model", orderFacts.ModelID), tasktrace.Uint("profile_version", uint64(orderFacts.ProfileVersion)),
		tasktrace.Str("input_hash", orderFacts.InputHash), tasktrace.Uint("input_size_bytes", orderFacts.InputSizeBytes),
		tasktrace.Uint("order_expire_height", orderFacts.OrderExpireHeight),
		tasktrace.Str("broadcasting_builder", envelope.SenderOperatorAddress))
	if subject != builderclient.NATSTaskOpenSubject(orderFacts.ModelID) {
		return fmt.Errorf("OrderBroadcast subject does not match the signed order's model")
	}
	if r.cfg.TaskFacts != nil {
		facts, factsErr := r.cfg.TaskFacts.TaskFacts(ctx, orderTaskID)
		switch {
		case factsErr == nil:
			if err := facts.Validate(orderTaskID); err != nil {
				return fmt.Errorf("validate accepted task hash: %w", err)
			}
			if codec.Hash(facts.AcceptedTaskHash) != taskHash {
				return fmt.Errorf("OrderBroadcast conflicts with Keeper accepted_task_hash")
			}
		case errors.Is(factsErr, chainclient.ErrNotFound):
			// Pre-acceptance order: legal RBF remains open.
		default:
			return builderclient.Retryable(fmt.Errorf("query accepted task hash: %w", factsErr))
		}
	}
	r.admitMu.Lock()
	defer r.admitMu.Unlock()
	if existing, err := layout.GetCandidateAdmission(ctx, r.cfg.Store, layout.StoredHash(taskHash)); err == nil {
		if codec.Hash(existing.HandraiseDigest[:]) != codec.HashBytes(existing.HandraisePayload) {
			return fmt.Errorf("candidate handraise digest is corrupt")
		}
		switch {
		case existing.SchemaVersion > layout.CandidateAdmissionSchemaVersion:
			return fmt.Errorf("candidate admission schema_version %d is newer than supported %d", existing.SchemaVersion, layout.CandidateAdmissionSchemaVersion)
		case existing.SchemaVersion == layout.CandidateAdmissionSchemaVersion:
			if orderFacts.InputSizeBytes > 0 {
				existing.InputSizeBytes = orderFacts.InputSizeBytes
			}
			if err := layout.AdmissionBatch(ctx, r.cfg.Store, orderFacts.SessionID, orderFacts.OrderSequence, layout.StoredHash(taskHash), existing); err != nil {
				return err
			}
			r.recordSessionAdmission(orderFacts.SessionID, orderFacts.OrderSequence, taskHash)
			return r.publishCandidate(ctx, orderTaskID, existing.HandraisePayload, existing.DedupID)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	tip := r.currentChainTip(ctx)
	redriveTip = tip
	if tip.readable && orderFacts.OrderExpireHeight <= tip.height {
		return fmt.Errorf("OrderBroadcast order_expire_height %d is not above current chain height %d", orderFacts.OrderExpireHeight, tip.height)
	}
	if !tip.readable && r.cfg.HandraiseEligibility == nil {
		return builderclient.Retryable(fmt.Errorf("OrderBroadcast deadline cannot be judged without a chain view"))
	}
	capability, err := r.capabilityFor(orderFacts.ModelID, orderFacts.ProfileVersion)
	if err != nil {
		return err
	}
	precheck, expiry, err := r.workerEligibility(ctx, WorkerHandraiseCandidate{TaskID: orderTaskID, SessionID: orderFacts.SessionID, OrderSequence: orderFacts.OrderSequence, ModelID: orderFacts.ModelID, ProfileVersion: orderFacts.ProfileVersion, Capability: capability, DeadlineHeight: orderFacts.OrderExpireHeight})
	if err != nil {
		return err
	}
	if expiry == 0 || expiry > orderFacts.OrderExpireHeight {
		return fmt.Errorf("WorkerHandraise expiry_height is outside the order deadline")
	}
	// TRUEOPEN_BUS_ENVELOPE_V1 field 7 comes from this node's own current ServiceKey
	// binding (interface-and-topic-list.md §5.2 field 7) - one committed read, the same
	// read the frozen Task wires use, so the handraise cannot be published against
	// a binding this node has not confirmed it still holds.
	//
	// The committed height that read returns is deliberately discarded: field 14
	// is "the sender's chain view" (§5.2 field 14) and for a handraise that view is the
	// precheck height the decision was taken at, which is also what the Worker's
	// own SignedEnvelope stamps as its source snapshot. Two different heights on
	// one message would be two different claims about the same thing.
	member := builderclient.CandidateMemberRefMessage{}
	if r.cfg.CandidateMemberReader != nil {
		candidateMember, err := r.cfg.CandidateMemberReader.CurrentCandidateMember(ctx, r.cfg.LocalWorkerAddress)
		if err != nil {
			return builderclient.Retryable(fmt.Errorf("query current CandidatePool member: %w", err))
		}
		member = builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: candidateMember.CandidatePoolSnapshotID.Hex(),
			Slot:                    candidateMember.Slot, SlotVersion: candidateMember.SlotVersion, OperatorAddress: candidateMember.OperatorAddress,
		}
	} else if r.cfg.FakeBus {
		member = builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: hex.EncodeToString(taskHash[:]), Slot: 1, SlotVersion: 1,
			OperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		}
	} else {
		return builderclient.Retryable(fmt.Errorf("CandidatePool member reader is required"))
	}
	authorizationNonce, _, err := r.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read current Cortex service binding for the WorkerHandraise envelope: %w", err))
	}
	signerAddress, _ := resolveSigningIdentity(r.cfg, r.cfg.LocalWorkerAddress)
	result, err := worker.New(worker.Config{WorkerAddress: r.cfg.LocalWorkerAddress, ChainID: r.cfg.ChainID, SignerAddress: signerAddress, SignerKeyRef: r.cfg.SignerKeyRef, Signer: r.cfg.Signer, FakeOutput: r.cfg.FakeOutput, TrustedNATSDev: r.cfg.TrustedNATSDev || r.cfg.FakeBus, EnvelopeTTL: r.cfg.EnvelopeTTL, NexusEnvelopeSigner: r.cfg.NexusEnvelopeSigner, Trace: r.cfg.Trace}).EvaluateAndHandraise(ctx, worker.WorkerHandraiseRequest{
		TaskID: orderTaskID, SessionID: orderFacts.SessionID, OrderSequence: orderFacts.OrderSequence,
		TaskHash: taskHash, ModelID: orderFacts.ModelID, ProfileVersion: orderFacts.ProfileVersion, Member: member,
		CurrentHeight: precheck.CurrentHeight, HandraiseExpireHeight: expiry,
		ServiceAuthorizationNonce: authorizationNonce,
		Precheck:                  precheck,
	})
	if err != nil {
		return err
	}
	traceWorkerHandraise := r.cfg.Trace.Event
	if !result.Decision.Accepted {
		traceWorkerHandraise = r.cfg.Trace.ErrorEvent
	}
	traceWorkerHandraise("worker_handraise",
		tasktrace.Str("task", orderTaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Bool("signed", result.Signed), tasktrace.Bool("accepted", result.Decision.Accepted),
		tasktrace.Str("reject_code", result.Decision.RejectCode),
		tasktrace.Hash("handraise_digest", codec.HashBytes(result.Payload)),
		tasktrace.Str("dedup_id", result.DedupID),
		tasktrace.Uint("current_height", precheck.CurrentHeight), tasktrace.Uint("expiry_height", expiry),
		tasktrace.Str("candidate_pool_snapshot_id", member.CandidatePoolSnapshotID), tasktrace.Uint("slot", uint64(member.Slot)))
	if !result.Signed {
		if r.cfg.Diagnostic != nil {
			reason := result.Decision.RejectCode
			if strings.TrimSpace(reason) == "" {
				reason = "unsigned"
			}
			r.cfg.Diagnostic(TaskRunnerDiagnostic{
				Source: "nexus_order_broadcast",
				Record: orderTaskID,
				Error:  "WorkerHandraise not admitted: " + reason,
			})
		}
		return nil
	}

	admission := layout.CandidateAdmission{
		SchemaVersion:    layout.CandidateAdmissionSchemaVersion,
		SignedOrder:      append([]byte(nil), signedOrderBytes...),
		HandraisePayload: append([]byte(nil), result.Payload...),
		HandraiseDigest:  layout.StoredHashFromCodec(codec.HashBytes(result.Payload)),
		PublishTS:        envelope.IssuedAtUnixMs,
		DedupID:          result.DedupID,
		InputSizeBytes:   orderFacts.InputSizeBytes,
		// The sender comes from a verified envelope field: the signature covers
		// sender_operator_address, so an impostor cannot pass verification and this value
		// is as trustworthy as the on-chain identity.
		BroadcastingBuilder: envelope.SenderOperatorAddress,
	}
	if err := layout.AdmissionBatch(ctx, r.cfg.Store, orderFacts.SessionID, orderFacts.OrderSequence, layout.StoredHash(taskHash), admission); err != nil {
		return err
	}
	if codec.Hash(admission.HandraiseDigest[:]) != codec.HashBytes(admission.HandraisePayload) {
		return fmt.Errorf("candidate handraise digest is corrupt")
	}
	r.recordSessionAdmission(orderFacts.SessionID, orderFacts.OrderSequence, taskHash)
	return r.publishCandidate(ctx, orderTaskID, admission.HandraisePayload, admission.DedupID)
}

// busTaskIDHex projects a payload task_id (raw Hash32) into the canonical
// lowercase hex the task plane keys records by, and binds it to the delivered
// subject's placeholder so a frame cannot smuggle one task under another's
// subject.
func busTaskIDHex(taskID []byte, subject string) (string, error) {
	if len(taskID) != 32 {
		return "", fmt.Errorf("task_id must be 32 bytes, got %d", len(taskID))
	}
	value := hex.EncodeToString(taskID)
	trimmed := strings.TrimSpace(subject)
	if index := strings.LastIndex(trimmed, "."); index >= 0 {
		if placeholder := trimmed[index+1:]; placeholder != value {
			return "", fmt.Errorf("payload task_id %s does not match subject %s", value, trimmed)
		}
	}
	return value, nil
}

func (r *TaskRunner) recordSessionAdmission(sessionID string, sequence uint64, taskHash codec.Hash) {
	current, ok := r.sessions[sessionID]
	if !ok || sequence >= current.sequence {
		if !ok {
			if len(r.sessions) >= r.cfg.MaxSessionAdmissions {
				oldest := r.sessionOrder[0]
				r.sessionOrder = r.sessionOrder[1:]
				delete(r.sessions, oldest)
			}
			r.sessionOrder = append(r.sessionOrder, sessionID)
		}
		r.sessions[sessionID] = sessionAdmission{sequence: sequence, taskHash: taskHash}
	}
}

// checkEnvelopeFreshness bounds an inbound envelope against the wall clock, with
// the same two rules the strict authenticator applies: a lifetime longer than the
// deployment's accepted TTL is refused outright, and an expiry already past is
// refused with the configured clock skew as tolerance.
//
// A zero TTL means the deployment stated none, so only the expiry rule applies.
// The skew is a tolerance for comparing a remote stamp against the local clock,
// never a licence to extend the sender's own lifetime, which is why the TTL
// comparison does not add it.
func (r *TaskRunner) checkEnvelopeFreshness(envelope builderclient.BusEnvelope, now time.Time) error {
	issuedAt := time.UnixMilli(envelope.IssuedAtUnixMs).UTC()
	expiresAt := time.UnixMilli(envelope.ExpiresAtUnixMs).UTC()
	if ttl := r.cfg.EnvelopeTTL; ttl > 0 {
		if lifetime := expiresAt.Sub(issuedAt); lifetime > ttl {
			return fmt.Errorf("Nexus envelope lifetime %s exceeds the accepted TTL %s", lifetime, ttl)
		}
	}
	if now.After(expiresAt.Add(r.cfg.EnvelopeClockSkew)) {
		return fmt.Errorf("Nexus envelope expired at %s", expiresAt.Format(time.RFC3339))
	}
	return nil
}
