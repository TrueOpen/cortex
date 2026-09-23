package daemon

import (
	"connectrpc.com/connect"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/TrueOpen/cortex/internal/verifier"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// VerifyCommitRelay hands a Verifier-signed commit to the receiving Builder to submit
// on chain (phase-one trusted Builder, nexus#70). A return only means the Builder
// broadcast it, never that the chain accepted it.
type VerifyCommitRelay interface {
	RelayVerifyCommit(context.Context, store.VerifyTask, nodewire.VerifyCommitV1) (builderclient.VerifyRelayAck, error)
}

// taskCommitRelay binds a VerifyCommitRelay to one concrete verify responsibility, to
// satisfy the verifier's commit exit (verifier.CommitRelay): the exit passes only
// session / task / commit, and the receiving Builder's address lives in the
// responsibility record.
//
// The error classification decides where the exit goes (verifier.deliverCommit):
//   - a deterministic refusal from nexus (InvalidArgument / PermissionDenied /
//     Unauthenticated / FailedPrecondition / NotFound / Unimplemented) and a permanent
//     transport failure -> wrapped as ErrCommitRelayNotOffered, and the exit
//     self-submits at once;
//   - anything else (the chain briefly unreachable, the Builder undialable) ->
//     returned as is, and the exit reports an error and retries without
//     self-submitting: the relay may still accept it, and self-submitting would race
//     an in-flight batch for the same commit_key.
type taskCommitRelay struct {
	relay VerifyCommitRelay
	task  store.VerifyTask
}

// taskCommitRelayFor returns nil when no relay is configured: the exit treats that as
// "there is no relay route".
func taskCommitRelayFor(relay VerifyCommitRelay, task store.VerifyTask) verifier.CommitRelay {
	if relay == nil {
		return nil
	}
	return taskCommitRelay{relay: relay, task: task}
}

func (r taskCommitRelay) RelayVerifyCommit(ctx context.Context, req verifier.CommitRelayRequest) error {
	task := r.task
	if req.SessionID != "" {
		task.SessionID = req.SessionID
	}
	if req.TaskID != "" {
		task.TaskID = req.TaskID
	}
	_, err := r.relay.RelayVerifyCommit(ctx, task, req.Commit)
	if err == nil {
		return nil
	}
	if commitRelayRefusedDeterministically(err) {
		return fmt.Errorf("%w: %v", verifier.ErrCommitRelayNotOffered, err)
	}
	return err
}

func commitRelayRefusedDeterministically(err error) bool {
	if builderclient.IsPermanent(err) {
		return true
	}
	switch connect.CodeOf(err) {
	case connect.CodeInvalidArgument, connect.CodePermissionDenied, connect.CodeUnauthenticated,
		connect.CodeFailedPrecondition, connect.CodeNotFound, connect.CodeUnimplemented:
		return true
	}
	return false
}

type NexusVerifyCommitRelayConfig struct {
	TaskData  builderclient.TaskDataClient
	Endpoints BuilderEndpointResolver
	Auth      *taskdataauth.Authenticator
	ChainID   string
	// Trace reports the Builder's answer, transaction hash included. Nil is silent.
	Trace *tasktrace.Trace
}

// NexusVerifyCommitRelay relays over IngressAPI SubmitVerifyCommit: the receiving
// Builder is resolved from the on-chain descriptor, over the same dialBuilder path as
// output confirmation (check the certificate against the fingerprint, retry once after
// a certificate change).
type NexusVerifyCommitRelay struct {
	cfg NexusVerifyCommitRelayConfig
}

func NewNexusVerifyCommitRelay(cfg NexusVerifyCommitRelayConfig) (*NexusVerifyCommitRelay, error) {
	switch {
	case cfg.TaskData == nil:
		return nil, fmt.Errorf("Nexus verify commit relay requires a task-data client")
	case cfg.Endpoints == nil:
		return nil, fmt.Errorf("Nexus verify commit relay requires a Builder endpoint resolver")
	case cfg.Auth == nil:
		return nil, fmt.Errorf("Nexus verify commit relay requires a task-data authenticator")
	case strings.TrimSpace(cfg.ChainID) == "":
		return nil, fmt.Errorf("Nexus verify commit relay requires a chain id")
	}
	return &NexusVerifyCommitRelay{cfg: cfg}, nil
}

func (r *NexusVerifyCommitRelay) RelayVerifyCommit(ctx context.Context, task store.VerifyTask, commit nodewire.VerifyCommitV1) (builderclient.VerifyRelayAck, error) {
	if err := ctx.Err(); err != nil {
		return builderclient.VerifyRelayAck{}, err
	}
	if strings.TrimSpace(task.BuilderOperatorAddress) == "" {
		return builderclient.VerifyRelayAck{}, fmt.Errorf("verify commit relay requires the receiving Builder operator address")
	}
	if err := builderclient.ValidateSignedVerifyCommit(commit); err != nil {
		return builderclient.VerifyRelayAck{}, err
	}
	var ack builderclient.VerifyRelayAck
	err := dialBuilder(ctx, r.cfg.Endpoints, task.BuilderOperatorAddress, func(ctx context.Context, endpoint BuilderEndpoint) error {
		got, err := r.relayTo(ctx, task, commit, endpoint)
		ack = got
		return err
	})
	return ack, err
}

func (r *NexusVerifyCommitRelay) relayTo(ctx context.Context, task store.VerifyTask, commit nodewire.VerifyCommitV1, endpoint BuilderEndpoint) (builderclient.VerifyRelayAck, error) {
	ack, err := r.cfg.TaskData.SubmitVerifyCommit(ctx, endpoint.Endpoint, builderclient.SubmitVerifyCommitRequest{
		Commit: commit,
	})
	if err != nil {
		return builderclient.VerifyRelayAck{}, err
	}
	r.cfg.Trace.Event("verify_commit_relayed",
		tasktrace.Str("task", task.TaskID), tasktrace.Str("session", task.SessionID),
		tasktrace.Str("builder", endpoint.OperatorAddress), tasktrace.Str("endpoint", endpoint.Endpoint),
		tasktrace.Hex("commit_hash", hex.EncodeToString(commit.CommitHash)),
		tasktrace.Bool("idempotent", ack.Idempotent), tasktrace.Hash("commit_key", ack.CommitKey))
	return ack, nil
}
