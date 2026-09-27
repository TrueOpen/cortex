package verifier

// The commit exit: what happens to a signed VerifyCommitV1 once it exists.
//
// A Verifier that has signed one has three conceivable ways onto the chain, and
// one of them is shut for good:
//
//   - The bus registers no VERIFY_COMMIT kind at all. interface-and-topic-list.md §5.3
//     lists eight kinds and VERIFY_RESULT is the only verifier one, so there is
//     no subject to publish a commit on -- see builderclient.NATSVerifyResultSubject
//     for the one that does exist.
//
// The other two are the relay and self-submission, in that order. The relay is
// nexus's unary ingress rpc SubmitVerifyCommit: it validates the whole request
// and the duty signature and then has the receiving Builder submit the batch
// (nexus#70, phase-one trusted Builder). It spent a period refusing every perfectly legal
// request with FailedPrecondition + NEXUS_INGRESS_RELAY_NOT_OFFERED, and that
// refusal is still the contract's way of saying "take the other road" for a
// round it will not carry -- which is why the classifier below survives the
// relay being open.
//
// Self-submission is the second, and the contract makes it a first-class route
// rather than a degradation. nexus docs/nexus-cortex-contract-migration.md §4-B
// states it outright -- "self-submit is not a degradation, it is a first-class path
// in the contract" -- and keeper-interface-contract.md §10.6 validation rule 6 writes both
// routes into one rule: a relayed MsgBatchSubmitVerifyCommit carries the Builder
// service address as its outer Cosmos Tx signer, a self-submitted
// MsgSubmitVerifyCommit carries "the current Cortex service address of the same
// verifier_operator_address". Both write the same CommitState and both trigger the
// same StartRevealPhase; the chain has no "unconfirmed" intermediate state for one
// of them.
//
// FailedPrecondition rather than Unimplemented is the relay saying "do not
// retry, take the other road", so this exit is taken the moment the commit is
// signed. That is what keeps it separate from the deadline-risk self-rescue in
// SettlementManager.HandleDeadlineRisk: that one fires only near a deadline,
// which needs the durable deadline scheduling of issue #108, and stays disabled
// in real mode. This one needs no scheduler at all -- relay unavailability is
// known synchronously, at the instant the signature exists.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// CommitRelay hands a signed frozen verify commit to a Task Builder relay.
//
// daemon.NexusVerifyCommitRelay supplies one in real mode whenever the task-data
// plane is configured. A nil relay is still a legal configuration rather than a
// gap -- it means this round structurally has no relay channel, which is one of
// the two ways the self-submission exit is reached -- and so is a nil
// CommitSubmitter beside a live relay: a file:// keystore node cannot assemble a
// Cosmos transaction at all. What is refused is having neither.
type CommitRelay interface {
	RelayVerifyCommit(context.Context, CommitRelayRequest) error
}

// CommitRelayRequest is the signed body plus the routing context a relay needs.
// The body is the exact nodewire value whose TRUEOPEN_COMMIT_V1 digest was signed,
// for the same reason commitMessage projects from it: a second read of Config or
// TaskState would be a second chance for the sent body to differ from the
// signed one.
type CommitRelayRequest struct {
	SessionID   string
	TaskID      string
	VerifyRound uint64
	Commit      nodewire.VerifyCommitV1
}

// ErrCommitRelayNotOffered is the relay's deterministic refusal: this Builder
// does not relay verify submissions in this round. A relay adapter raises it to
// say "stop asking me, self-submit" rather than "try again later".
var ErrCommitRelayNotOffered = errors.New("verify commit relay is not offered for this round")

// ErrCommitExitUnavailable marks a commit that was signed and has nowhere to go.
// It is a wiring failure, not a protocol gap: without it the signed commit would
// stay a local evidence file while the chain records no CommitState at all,
// which is exactly the silence this exit was built to end.
var ErrCommitExitUnavailable = errors.New("no verify commit exit is available")

// nexusRelayNotOfferedCode is the contract-frozen code nexus's ingress returns
// with FailedPrecondition (nexus internal/ingress/workerverifier.go). A relay
// adapter is expected to wrap ErrCommitRelayNotOffered, but the code is matched
// too so that an adapter returning the connect error unchanged is still
// classified correctly: the code IS the contract, and nexus emits it under no
// other status.
const nexusRelayNotOfferedCode = "NEXUS_INGRESS_RELAY_NOT_OFFERED"

// CommitRelayNotOffered reports whether a relay error is the deterministic
// refusal. Every other error is treated as transient on purpose: a relay that
// may still accept this commit must not be raced by a self-submission for the
// same commit_key.
func CommitRelayNotOffered(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrCommitRelayNotOffered) || strings.Contains(err.Error(), nexusRelayNotOfferedCode)
}

// CommitSubmitter submits the signed frozen commit directly on chain.
// *SettlementManager implements it: the fee cap, the gas payer and the
// operator/submitter identity rules all already live there, and rule 6's
// "current Cortex service address" requirement is one of them.
type CommitSubmitter interface {
	SubmitVerifyCommitDirect(context.Context, DirectCommitInput) (SettlementObservation, error)
}

var _ CommitSubmitter = (*SettlementManager)(nil)

// The trigger reasons, spelled once. They reach the trace and the returned
// delivery, because "there was no relay to try" and "the relay refused" are
// different operational facts even though both end in a self-submission.
const (
	CommitExitRelayChannelAbsent = "relay_channel_absent"
	CommitExitRelayNotOffered    = "relay_not_offered"
	CommitExitRelayed            = "relayed"
)

// CommitDelivery is what actually happened to the signed commit. It keeps
// broadcast and inclusion apart deliberately: nexus's contract §7 forbids
// describing any ack or relay acceptance as chain acceptance, and the same rule
// applies to this node's own broadcast. ChainAccepted is Keeper confirmation and
// nothing weaker.
type CommitDelivery struct {
	Reason        string
	Relayed       bool
	SelfSubmitted bool
	// Duplicate says this process had already landed a commit for this
	// commit_key, so nothing was sent. The Keeper would have answered a second
	// submission with a duplicate noop (§10.6 rule 5) and charged gas for it.
	Duplicate      bool
	TxHash         string
	IncludedHeight uint64
	ChainAccepted  bool
}

// DirectCommitInput is one self-submission. DeadlineHeight becomes the tx
// timeout_height, so a commit that misses commit_deadline_height cannot be
// included late and rejected on chain at this node's expense.
type DirectCommitInput struct {
	SessionID string
	TaskID    string
	// Reason is the trigger that opened this exit, carried for the log only. It
	// is not a wire field: MsgSubmitVerifyCommit has no provenance member, and
	// §10.6 defines no second wire for a self-submitted item.
	Reason         string
	DeadlineHeight uint64
	Message        txclient.SubmitVerifyCommitMessage
}

// commitExitLabel names the route in one word for the trace. A delivery that
// took no route at all is "none" rather than an empty field, because "the exit
// was not reached" and "the exit was reached and failed" read identically once a
// field goes blank.
func commitExitLabel(delivery CommitDelivery) string {
	switch {
	case delivery.Relayed:
		return "relay"
	case delivery.SelfSubmitted && delivery.Duplicate:
		return "self_submit_duplicate"
	case delivery.SelfSubmitted:
		return "self_submit"
	default:
		return "none"
	}
}

// commitKeyScope is the local spelling of the Keeper's commit_key scope,
// H_FIELDS_V1("TRUEOPEN_COMMIT_KEY_V1", chain_id, task_id, verify_round,
// verifier_operator_address) (keeper-interface-contract.md §10.9).
//
// It deliberately excludes commit_hash. The Keeper keys CommitState by this
// scope alone, so a second submission for the same scope is a duplicate noop
// whatever hash it carries -- a retry that re-derived a different seed included.
// Paying gas to learn that is precisely what remembering the scope avoids.
func commitKeyScope(cfg Config, state TaskState) string {
	return fmt.Sprintf("%s/%s/%d/%s", cfg.ChainID, state.TaskID, state.VerifyRound, cfg.VerifierAddress)
}

// deliverCommit takes the commit exit for a commit that is signed and persisted.
//
// Order matters: the relay is asked first whenever one is wired, so a restored
// relay wins and the same commit_key is never both relayed and self-submitted.
func (v *Verifier) deliverCommit(ctx context.Context, state TaskState, result VerifyResult) (CommitDelivery, error) {
	scope := commitKeyScope(v.cfg, state)
	if previous, ok := v.commits[scope]; ok {
		previous.Duplicate = true
		return previous, nil
	}
	if previous, ok, err := v.persistedDelivery(ctx, scope); err != nil {
		return CommitDelivery{}, err
	} else if ok {
		v.commits[scope] = previous
		return previous, nil
	}
	reason := CommitExitRelayChannelAbsent
	if v.cfg.CommitRelay != nil {
		relayErr := v.cfg.CommitRelay.RelayVerifyCommit(ctx, CommitRelayRequest{
			SessionID: state.SessionID, TaskID: state.TaskID,
			VerifyRound: state.VerifyRound, Commit: result.CommitWire,
		})
		switch {
		case relayErr == nil:
			// Not memoised. Relay acceptance is not chain acceptance (nexus
			// contract §7), so a later retry of this responsibility must stay
			// free to deliver the commit again rather than assume a batch it
			// never saw land did.
			return CommitDelivery{Reason: CommitExitRelayed, Relayed: true}, nil
		case !CommitRelayNotOffered(relayErr):
			return CommitDelivery{}, fmt.Errorf("relay verify commit for task %s: %w", state.TaskID, relayErr)
		}
		reason = CommitExitRelayNotOffered
	}
	if v.cfg.CommitSubmitter == nil {
		return CommitDelivery{}, fmt.Errorf(
			"%w: the relay cannot carry this commit (%s) and no direct commit submitter is wired, so the signed "+
				"commit for task %s would stay a local evidence file while the chain records no CommitState",
			ErrCommitExitUnavailable, reason, state.TaskID)
	}
	message, err := commitMessage(v.cfg, result)
	if err != nil {
		return CommitDelivery{}, err
	}
	observation, err := v.cfg.CommitSubmitter.SubmitVerifyCommitDirect(ctx, DirectCommitInput{
		SessionID: state.SessionID, TaskID: state.TaskID, Reason: reason,
		DeadlineHeight: uint64(message.Commit.ExpiryHeight), Message: message,
	})
	if err != nil {
		return CommitDelivery{}, err
	}
	delivery := CommitDelivery{
		Reason: reason, SelfSubmitted: true,
		TxHash:         observation.Tx.TxHash,
		IncludedHeight: observation.Tx.IncludedHeight,
		ChainAccepted:  observation.Tx.Accepted,
	}
	switch {
	case observation.Tx.Rejected:
		return delivery, fmt.Errorf(
			"verify commit self-submission for task %s was rejected on chain (tx %s, height %d): %s",
			state.TaskID, observation.Tx.TxHash, observation.Tx.IncludedHeight, observation.Tx.RejectReason)
	case !observation.Tx.Accepted:
		// Broadcast is not inclusion and inclusion is not Keeper confirmation.
		// Returning the delivery beside the refusal keeps the tx hash in the
		// operator's hands, which is the only way to tell a lost tx from one
		// still in the mempool.
		return delivery, fmt.Errorf(
			"verify commit self-submission for task %s reached %q but not Keeper confirmation (tx %s, height %d)",
			state.TaskID, observation.Tx.Status, observation.Tx.TxHash, observation.Tx.IncludedHeight)
	}
	if err := v.recordDelivery(ctx, state, scope, result, delivery); err != nil {
		return delivery, fmt.Errorf("record confirmed verify commit for task %s: %w", state.TaskID, err)
	}
	v.commits[scope] = delivery
	return delivery, nil
}
