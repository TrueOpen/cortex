package verifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type DeadlineRiskType string

const (
	CommitDeadlineRisk       DeadlineRiskType = "commit_deadline"
	WorkerRevealDeadlineRisk DeadlineRiskType = "worker_reveal_deadline"
	ResultRevealDeadlineRisk DeadlineRiskType = "result_reveal_deadline"
)

type SettlementConfig struct {
	VerifierAddress  string
	WorkerAddress    string
	SubmitterAddress string
	Tx               txclient.Client
	GasPayer         string
	FeeCap           txclient.Coin
	// CommitFeeCap bounds the commit exit specifically. The exit runs on every
	// verify round of a real-mode node, so it is the one path whose per-tx cost
	// an operator may want held below the general tx ceiling; deployment wiring
	// narrows it with self_rescue.max_fee_amount. Zero falls back to FeeCap,
	// which the broadcaster then checks against tx.max_fee_amount, so there is
	// no configuration in which the exit submits with no cap at all.
	CommitFeeCap  txclient.Coin
	FeeGrant      string
	Memo          string
	ContextReader chainclient.SettlementContextReader
}

type SettlementManager struct {
	cfg SettlementConfig
}

type DeadlineRisk struct {
	SessionID      string
	TaskID         string
	Type           DeadlineRiskType
	CurrentHeight  uint64
	DeadlineHeight uint64
	Margin         uint64
	Message        any
	WorkerReveal   ReceiptOnlyWorkerReveal
}

type ReceiptOnlyWorkerReveal struct {
	SessionID                        string
	VerifyRound                      uint64
	WorkerAddress                    string
	SampledValueSetHash              codec.Hash
	EvidenceSchemaVersion            string
	ReceiptSignature                 []byte
	EvidenceAvailabilityEndpointHash codec.Hash
	FullResultPlaintext              []byte
}

type SettlementObservation struct {
	Submitted               bool
	Tx                      txclient.Observation
	MechanicalSlashExpected bool
	Closed                  bool
	ChainVerdict            string
	FailureClass            string
}

type SettlementInput struct {
	Message         txclient.SettleTaskMessage
	LocalRoot       codec.Hash
	OpeningsValid   bool
	PlaintextValues [][]byte
}

type SettlementEnvelope struct {
	TaskID       string
	EvidenceRoot codec.Hash
	Payload      []byte
}

type VerifyDeadlineInput struct {
	SessionID        string
	TaskID           string
	CurrentHeight    uint64
	DeadlineHeight   uint64
	HasValidSettleTx bool
	ChainVerdict     string
	FailureClass     string
	SweepKind        string
}

func NewSettlementManager(cfg SettlementConfig) *SettlementManager {
	return &SettlementManager{cfg: cfg}
}

func (m *SettlementManager) HandleDeadlineRisk(ctx context.Context, risk DeadlineRisk) (SettlementObservation, error) {
	if risk.CurrentHeight+risk.Margin < risk.DeadlineHeight {
		return SettlementObservation{}, nil
	}
	if risk.Type == WorkerRevealDeadlineRisk {
		if risk.WorkerReveal.WorkerAddress != m.cfg.WorkerAddress {
			return SettlementObservation{}, fmt.Errorf("worker reveal operator %q does not match configured operator %q", risk.WorkerReveal.WorkerAddress, m.cfg.WorkerAddress)
		}
		return SettlementObservation{}, m.rejectWorkerRevealSelfRescue(risk.TaskID, risk.WorkerReveal)
	}
	kind, ok := deadlineRiskTxKind(risk.Type)
	if !ok {
		return SettlementObservation{}, fmt.Errorf("unsupported deadline risk %q", risk.Type)
	}
	if err := m.validateCortexOperator(kind, risk.Message); err != nil {
		return SettlementObservation{}, err
	}
	payload, err := txclient.MarshalMessage(kind, risk.Message)
	if err != nil {
		return SettlementObservation{}, err
	}
	tx, err := m.submit(ctx, txclient.Request{
		TaskID:         risk.TaskID,
		SessionID:      risk.SessionID,
		Kind:           kind,
		Payload:        payload,
		DeadlineHeight: risk.DeadlineHeight,
		MaterialDigest: codec.HashWithDomain("TRUEOPEN_VERIFIER_SELF_RESCUE_MATERIAL_V1", []byte(risk.TaskID), []byte(kind), payload),
	})
	if err != nil {
		return SettlementObservation{}, err
	}
	return SettlementObservation{Submitted: true, Tx: tx}, nil
}

// SubmitVerifyCommitDirect puts a signed frozen verify commit on chain because
// the relay cannot carry it. It is the A trigger of the commit exit and shares
// nothing with HandleDeadlineRisk's B trigger but this manager's guardrails:
// there is no margin check and no deadline scheduling here, because relay
// unavailability is known synchronously (see commit_exit.go).
//
// The identity rule is keeper-interface-contract.md §10.6 validation rule 6: the outer
// Cosmos Tx signer of a self-submitted MsgSubmitVerifyCommit must be the current
// Cortex service address of the same verifier_operator_address, and neither the
// operator key nor a relayer key is legal. validateCortexOperator checks the
// body's own two addresses against this manager's configured pair; the signer
// itself is bound one layer down, where txclient.CosmosSigner names the address
// its key must resolve to and the signer refuses a mismatch. Both halves fail
// closed, so a node configured with the wrong identity refuses before paying
// gas for a transaction the chain would reject.
func (m *SettlementManager) SubmitVerifyCommitDirect(ctx context.Context, in DirectCommitInput) (SettlementObservation, error) {
	if strings.TrimSpace(in.TaskID) == "" {
		return SettlementObservation{}, fmt.Errorf("verify commit self-submission requires a task id")
	}
	// expiry_height is inside the signed body, so a zero here means the body
	// itself was assembled without the Keeper commit deadline. It also becomes
	// the tx timeout_height, and a tx with no timeout can be included after the
	// commit window shut and rejected at this node's expense.
	if in.DeadlineHeight == 0 {
		return SettlementObservation{}, fmt.Errorf("verify commit self-submission for task %s requires the commit deadline height", in.TaskID)
	}
	if err := m.validateCortexOperator(txclient.MsgSubmitVerifyCommit, in.Message); err != nil {
		return SettlementObservation{}, err
	}
	payload, err := txclient.MarshalMessage(txclient.MsgSubmitVerifyCommit, in.Message)
	if err != nil {
		return SettlementObservation{}, err
	}
	tx, err := m.submit(ctx, txclient.Request{
		TaskID:         in.TaskID,
		SessionID:      in.SessionID,
		Kind:           txclient.MsgSubmitVerifyCommit,
		Payload:        payload,
		DeadlineHeight: in.DeadlineHeight,
		// A domain of its own rather than the self-rescue one: this material is
		// produced by a different trigger, and a shared domain would make the
		// two indistinguishable in the tx lifecycle records an operator reads
		// to answer "which exit sent this".
		MaterialDigest: codec.HashWithDomain("TRUEOPEN_VERIFIER_COMMIT_SELF_SUBMIT_MATERIAL_V1", []byte(in.TaskID), payload),
		FeeCap:         m.cfg.CommitFeeCap,
	})
	if err != nil {
		return SettlementObservation{}, err
	}
	return SettlementObservation{Submitted: true, Tx: tx}, nil
}

// validateCortexOperator enforces the two address facts every verifier-signed
// item carries: the body names this node's verifier operator, and the outer
// Cosmos Tx submitter is this node's current Cortex service address. It is
// shared by the deadline-risk self-rescue and by the commit exit because
// keeper-interface-contract.md §10.6 rule 6 states the requirement once for both.
func (m *SettlementManager) validateCortexOperator(kind txclient.Kind, message any) error {
	var operator, submitter string
	switch value := message.(type) {
	case txclient.SubmitVerifyCommitMessage:
		operator = value.Commit.VerifierOperatorAddress
		submitter = value.SubmitterAddress
	case txclient.SubmitVerifyResultMessage:
		operator = value.Receipt.VerifierOperatorAddress
		submitter = value.SubmitterAddress
	default:
		return fmt.Errorf("verifier-submitted message type %T is invalid for %s", message, kind)
	}
	if operator == "" || operator != m.cfg.VerifierAddress {
		return fmt.Errorf("%s verifier_operator_address %q does not match this node's configured operator %q", kind, operator, m.cfg.VerifierAddress)
	}
	if submitter == "" || submitter != m.cfg.SubmitterAddress {
		return fmt.Errorf("%s submitter_address %q is not this operator's current Cortex service address %q; keeper §10.6 rule 6 forbids the operator key and any relayer key here", kind, submitter, m.cfg.SubmitterAddress)
	}
	return nil
}

// rejectWorkerRevealSelfRescue validates the receipt-only material Cortex holds
// and then fails closed, because the frozen contract has no Worker reveal
// message to send it on.
//
// Evidence that the responsibility moved rather than being renamed:
//   - tx.proto de-registration note: "MsgWorkerReveal -> deleted; §9.6a
//     registers no separate worker reveal Msg", and the SubmitFullResultReveal
//     rpc comment: "The deleted MsgWorkerReveal had no separate contract entry".
//   - The reveal message that note points at was itself verifier-scoped
//     (FullResultRevealV1 carried verifier_operator_address and commit_key), so
//     it was never a worker wire — and §10.9a has since removed it too.
//   - The worker's opening is now a commitment inside MsgSubmitInferReceipt:
//     evidence.proto EVIDENCE_KIND_WORKER_VALUE_OPENING is the "Worker
//     input/generated token and worker metric leaf/aggregate opening" carried by
//     InferReceiptV1.required_evidence_commitments, and TaskEvidenceLeafTypeV1
//     has no worker-reveal leaf.
//   - DeadlineKindV1 registers WORKER_ASSIGNMENT and WORKER_INFER but no worker
//     reveal deadline, so the phase itself is gone.
//
// Cortex cannot re-express this material as required_evidence_commitments: the
// list must exactly equal the locked Profile's
// evidence_schema.required_infer_evidence, which hub.v1.Query/Profile
// serves and Cortex has no reader for.
func (m *SettlementManager) rejectWorkerRevealSelfRescue(taskID string, reveal ReceiptOnlyWorkerReveal) error {
	if reveal.VerifyRound == 0 || reveal.WorkerAddress == "" || reveal.SampledValueSetHash == (codec.Hash{}) || reveal.EvidenceSchemaVersion == "" || len(reveal.ReceiptSignature) == 0 {
		return fmt.Errorf("worker reveal self-rescue requires receipt-only material")
	}
	if len(reveal.FullResultPlaintext) > 0 {
		return fmt.Errorf("worker reveal self-rescue must not include full result plaintext")
	}
	return fmt.Errorf("task %s worker reveal self-rescue cannot be submitted: the frozen contract registers no worker reveal Msg and the replacement carrier, "+
		"MsgSubmitInferReceipt.receipt.required_evidence_commitments, needs the locked Profile's "+
		"evidence_schema.required_infer_evidence from hub.v1.Query/Profile, which Cortex does not read", taskID)
}

func (m *SettlementManager) HandleStage3BuilderFailure(ctx context.Context, input SettlementInput) (SettlementObservation, error) {
	envelope, err := BuildSettlementEnvelope(input)
	if err != nil {
		return SettlementObservation{}, err
	}
	if m == nil || m.cfg.ContextReader == nil {
		return SettlementObservation{}, fmt.Errorf("settlement requires authoritative Keeper task and Builder window reads")
	}
	if m.cfg.SubmitterAddress == "" || input.Message.SubmitterAddress != m.cfg.SubmitterAddress {
		return SettlementObservation{}, fmt.Errorf("settlement submitter_address must match the current Cosmos service signer")
	}
	state, err := m.cfg.ContextReader.SettlementContext(ctx, envelope.TaskID)
	if err != nil {
		return SettlementObservation{}, fmt.Errorf("read settlement context: %w", err)
	}
	if state.TaskID != envelope.TaskID || state.SessionID == "" || state.ObservedHeight == 0 || state.UpdatedHeight == 0 || state.UpdatedHeight > state.ObservedHeight {
		return SettlementObservation{}, fmt.Errorf("settlement context has invalid task scope or committed height")
	}
	if state.Terminal() {
		return SettlementObservation{Closed: true}, nil
	}
	if !state.CanSubmit() {
		return SettlementObservation{}, fmt.Errorf("settlement is not permissionless: task phase=%d height=%d first_height=%d deadline=%d", state.Phase, state.ObservedHeight, state.PermissionlessHeight, state.DeadlineHeight)
	}
	// Like Nexus SubmitSettle, submit only the task and the actual Cosmos signer.
	// The Node owns verdicts, proof validation and all accounting fields.
	obs, err := m.submit(ctx, txclient.Request{
		TaskID: envelope.TaskID, SessionID: state.SessionID,
		Kind: txclient.MsgSettleTask, Payload: envelope.Payload, DeadlineHeight: state.DeadlineHeight,
	})
	if err != nil {
		return SettlementObservation{
			Tx: obs, Submitted: obs.TxHash != "",
			Closed: obs.Accepted && !obs.Rejected && obs.Status == txclient.LifecycleKeeperConfirmed,
		}, err
	}
	return SettlementObservation{
		Submitted: true, Tx: obs,
		Closed: obs.Accepted && !obs.Rejected && obs.Status == txclient.LifecycleKeeperConfirmed,
	}, nil
}

func (m *SettlementManager) HandleVerifyDeadline(ctx context.Context, input VerifyDeadlineInput) (SettlementObservation, error) {
	if input.HasValidSettleTx || input.CurrentHeight < input.DeadlineHeight {
		return SettlementObservation{}, nil
	}
	deadlineKind, err := frozenDeadlineKind(input.SweepKind)
	if err != nil {
		return SettlementObservation{}, err
	}
	payload, err := txclient.MarshalMessage(txclient.MsgSweepDeadline, txclient.SweepDeadlineMessage{
		Locator: txclient.DeadlineLocatorMessage{
			Task: &txclient.TaskDeadlineLocatorMessage{
				TaskID:       txclient.ProtoBytes32(input.TaskID),
				DeadlineKind: deadlineKind,
			},
		},
		SubmitterAddress: m.cfg.SubmitterAddress,
	})
	if err != nil {
		return SettlementObservation{}, err
	}
	tx, err := m.submit(ctx, txclient.Request{TaskID: input.TaskID, SessionID: input.SessionID, Kind: txclient.MsgSweepDeadline, Payload: payload})
	if err != nil {
		return SettlementObservation{}, err
	}
	return SettlementObservation{
		Submitted:    true,
		Tx:           tx,
		Closed:       tx.Accepted,
		ChainVerdict: input.ChainVerdict,
		FailureClass: input.FailureClass,
	}, nil
}

// frozenDeadlineKind maps a local sweep label onto the DeadlineKindV1 value the
// frozen public MsgSweepDeadline can actually route through a
// TaskDeadlineLocator.
//
// The frozen sweep handler accepts exactly WORKER_ASSIGNMENT and WORKER_INFER
// from a TaskDeadlineLocator; every other task-scoped kind is refused with
// "<KIND> cannot be targeted from the frozen V1 locator" because
// TaskDeadlineLocator freezes neither the verify round nor the deadline height
// (node x/task/keeper/msg_server_sweep_deadline.go). The verify and
// finality deadlines are therefore swept by EndBlock only, and the four
// K-BLOCK-03/04 challenge and evidence kinds have no ACTIVE writer at all. Each
// unroutable label fails closed with the reason rather than paying gas for a
// transaction the Keeper always rejects.
func frozenDeadlineKind(value string) (string, error) {
	switch value {
	case "INFER_DEADLINE":
		return txclient.DeadlineKindWorkerInfer, nil
	case "ASSIGNMENT_DEADLINE":
		return txclient.DeadlineKindWorkerAssignment, nil
	case "VERIFY_OPEN_DEADLINE", "COMMIT_DEADLINE", "REVEAL_DEADLINE", "VERIFY_DEADLINE":
		return "", fmt.Errorf("local sweep kind %q cannot be targeted from the frozen V1 TaskDeadlineLocator, which carries neither verify round nor deadline height; EndBlock is the only sweeper for it", value)
	case "WORKER_REVEAL_DEADLINE":
		return "", fmt.Errorf("local sweep kind %q has no frozen DeadlineKindV1 value: the worker reveal phase is not part of the frozen contract", value)
	case "CHALLENGE_CLOSE", "CHALLENGE_RESOLVE_DEADLINE", "EVIDENCE_REQUEST_DEADLINE":
		return "", fmt.Errorf("local sweep kind %q is K-BLOCK-03/04 gated: no ACTIVE writer may emit the matching DeadlineKindV1 value and the sweep executor rejects it", value)
	default:
		return "", fmt.Errorf("unsupported local sweep kind %q", value)
	}
}

func (m *SettlementManager) submit(ctx context.Context, req txclient.Request) (txclient.Observation, error) {
	if m.cfg.Tx == nil {
		return txclient.Observation{}, fmt.Errorf("tx client is required")
	}
	if req.GasPayer == "" {
		req.GasPayer = m.cfg.GasPayer
	}
	if req.FeeCap == (txclient.Coin{}) {
		req.FeeCap = m.cfg.FeeCap
	}
	if req.FeeGrant == "" {
		req.FeeGrant = m.cfg.FeeGrant
	}
	if req.Memo == "" {
		req.Memo = m.cfg.Memo
	}
	return m.cfg.Tx.Submit(ctx, req)
}

// BuildSettlementEnvelope encodes the frozen MsgSettleTask. The message asserts
// no evidence root: task_evidence_root, the verdict, the payout plan and the
// facts hash are all derived by the Keeper's BuildSettlementFacts, so the
// locally computed root travels beside the payload as an audit fact instead of
// being claimed on chain.
func BuildSettlementEnvelope(input SettlementInput) (SettlementEnvelope, error) {
	if len(input.PlaintextValues) > 0 {
		return SettlementEnvelope{}, fmt.Errorf("settlement envelope must not include plaintext verifier/worker values")
	}
	payload, err := txclient.MarshalMessage(txclient.MsgSettleTask, input.Message)
	if err != nil {
		return SettlementEnvelope{}, err
	}
	return SettlementEnvelope{
		TaskID: input.Message.TaskID.Hex(), EvidenceRoot: input.LocalRoot, Payload: payload,
	}, nil
}

// deadlineRiskTxKind maps a self-rescue deadline risk onto the frozen Msg that
// carries it. Two risks are deliberately absent, each because the frozen
// contract registers no Msg they could travel in:
//
//   - WorkerRevealDeadlineRisk — the worker reveal phase is gone; the material
//     is handled by rejectWorkerRevealSelfRescue instead.
//   - a full-result availability risk — keeper-interface-contract.md §10.9a removed
//     MsgSubmitFullResultReveal and reserved msg number 18, and
//     04-task-execution-verification-and-settlement.md states the target protocol no longer defines it. The
//     bounded compact reveal it used to register is now carried only inside the
//     VERIFY_RESULT credential the Builder relays, so there is no second,
//     self-submitted registration for a Verifier to fall back to.
func deadlineRiskTxKind(risk DeadlineRiskType) (txclient.Kind, bool) {
	switch risk {
	case CommitDeadlineRisk:
		return txclient.MsgSubmitVerifyCommit, true
	case ResultRevealDeadlineRisk:
		return txclient.MsgSubmitVerifyResult, true
	default:
		return "", false
	}
}
