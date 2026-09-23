package txclient

import (
	"context"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

type Kind string

const (
	MsgRegisterModelProfile     Kind = "/hub.v1.MsgRegisterModelProfile"
	MsgDeclareModelSupport      Kind = "/hub.v1.MsgDeclareModelSupport"
	MsgBatchConfirmModelSupport Kind = "/hub.v1.MsgBatchConfirmModelSupport"
	// Task-domain type URLs are exactly the rpc request names the frozen
	// task.v1.Msg service registers ACTIVE (node
	// proto/task/v1/tx.proto). Cortex emits only these five; the two batch
	// relay entries MsgBatchSubmitVerifyCommit / MsgBatchSubmitVerifyResult are
	// Task Builder messages and have no Cortex producer.
	//
	// MsgSubmitFullResultReveal is deliberately absent. keeper-interface-contract.md §10.9a
	// removed it and msg number 18 is now RESERVED / "must not be reused"; Phase 0
	// registers neither the Msg nor FullResultRevealState/Event/Query, and
	// 04-task-execution-verification-and-settlement.md states that the target protocol "no longer defines the
	// semantically duplicated MsgSubmitFullResultReveal". A Kind here would be a
	// type URL no chain route accepts, so the reveal travels only as the
	// VERIFY_RESULT bus credential the Builder relays.
	MsgSubmitInferReceipt Kind = "/task.v1.MsgSubmitInferReceipt"
	MsgSubmitVerifyCommit Kind = "/task.v1.MsgSubmitVerifyCommit"
	MsgSubmitVerifyResult Kind = "/task.v1.MsgSubmitVerifyResult"
	MsgSettleTask         Kind = "/task.v1.MsgSettleTask"
	MsgSweepDeadline      Kind = "/task.v1.MsgSweepDeadline"
)

type Client interface {
	Submit(context.Context, Request) (Observation, error)
}

type Request struct {
	TaskID string
	// SessionID is local routing context and never a field of any frozen Msg.
	// The frozen Task messages locate a task by task_id alone, while the
	// vendored Keeper Query surface still keys by (session_id, task_id), so the
	// confirmation reader takes the session from the request envelope.
	SessionID       string
	Kind            Kind
	Payload         []byte
	GasPayer        string
	FeeCap          Coin
	FeeGrant        string
	Memo            string
	AccountSequence uint64
	DeadlineHeight  uint64
	MaterialDigest  codec.Hash
}

type Observation struct {
	TaskID          string
	Kind            Kind
	Accepted        bool
	Rejected        bool
	TxHash          string
	RejectReason    string
	PayloadDigest   codec.Hash
	AccountSequence uint64
	Fee             Coin
	GasPayer        string
	DeadlineHeight  uint64
	MaterialDigest  codec.Hash
	Status          LifecycleState
	IncludedHeight  uint64
}

type Coin struct {
	Amount uint64
	Denom  string
}

func (k Kind) String() string {
	return string(k)
}

func (k Kind) Valid() bool {
	switch k {
	case MsgRegisterModelProfile,
		MsgDeclareModelSupport,
		MsgBatchConfirmModelSupport,
		MsgSubmitInferReceipt,
		MsgSubmitVerifyCommit,
		MsgSubmitVerifyResult,
		MsgSettleTask,
		MsgSweepDeadline:
		return true
	default:
		return false
	}
}

func ValidateRequest(req Request) error {
	if strings.TrimSpace(req.TaskID) == "" {
		return fmt.Errorf("task id is required")
	}
	if !req.Kind.Valid() {
		return fmt.Errorf("unsupported tx kind %q", req.Kind)
	}
	return ValidateMessagePayload(req.Kind, req.Payload)
}
