package worker

import (
	"context"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// ReceivingBuilderRef identifies the task whose receiving Builder must be
// resolved. It deliberately carries the task identity beside the current
// single-Builder compatibility source. The frozen contract carries the
// authoritative per-task list in TaskBuilderSelectionState.selected_task_builders;
// until that Query is serveable, Worker input uses an authenticated ORDER_BROADCAST
// sender and Verifier output uses an authenticated data-ready OPEN_VERIFY sender.
// When the read path lands, only the provider implementation changes and
// AssignedBuilderOperator goes away; nothing in the relay path has to change.
type ReceivingBuilderRef struct {
	SessionID string
	TaskID    string
	// AssignedBuilderOperator is the one compatibility Builder persisted for the
	// task while the authoritative Task Builder list cannot be queried.
	AssignedBuilderOperator string
}

func receivingBuilderRef(event chainclient.AssignmentFinalized) ReceivingBuilderRef {
	return ReceivingBuilderRef{SessionID: event.SessionID, TaskID: event.TaskID, AssignedBuilderOperator: event.BuilderOperatorAddress}
}

// ReceivingBuilderProvider yields the receiving Builder's operator address,
// Nexus endpoint, current service pubkey and the chain height those were pinned
// at. It is the single switch point for where per-task Builder authority is
// read from; see ReceivingBuilderRef and TrueOpen/node#92.
type ReceivingBuilderProvider interface {
	ResolveReceivingBuilder(ctx context.Context, task ReceivingBuilderRef) (BuilderEndpoint, error)
}

// ReceivingBuilderRefresher is an optional capability: re-read the descriptor once,
// past the cache (ADR-0015: after a Builder changes certificates the fingerprint
// mismatches -> re-read the descriptor and retry once).
type ReceivingBuilderRefresher interface {
	RefreshReceivingBuilder(ctx context.Context, task ReceivingBuilderRef) (BuilderEndpoint, error)
}

// ReceivingBuilderFunc adapts a plain function to ReceivingBuilderProvider, so a
// caller with nothing to hold onto does not need a named type.
type ReceivingBuilderFunc func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error)

func (f ReceivingBuilderFunc) ResolveReceivingBuilder(
	ctx context.Context,
	task ReceivingBuilderRef,
) (BuilderEndpoint, error) {
	return f(ctx, task)
}

// BuilderEndpoint is the resolved receiving-Builder identity a Worker needs to
// relay task material and authenticate the storage confirmation.
type BuilderEndpoint struct {
	AuthorizationNonce uint64
	OperatorAddress    string
	Endpoint           string
	ServicePubkey      string
	// TLSPubkeyHash is the descriptor's tls_pubkey_hash (64 lowercase hex) or ""
	// when none was published; the relay/upload calls carry it in their context
	// so the dial verifies the Builder's certificate key.
	TLSPubkeyHash string
	CurrentHeight uint64
}

// receivingBuilder resolves the receiving Builder for one task and fails
// closed on anything the relay path cannot safely use: a Builder identity is
// only usable with a canonical operator address, a reachable endpoint, the
// service key that signs its material, and the height that key was read at.
func (w *Worker) receivingBuilder(ctx context.Context, ref ReceivingBuilderRef) (BuilderEndpoint, error) {
	if w.cfg.ReceivingBuilder == nil {
		return BuilderEndpoint{}, fmt.Errorf("receiving Builder provider is required")
	}
	return w.checkReceivingBuilder(w.cfg.ReceivingBuilder.ResolveReceivingBuilder(ctx, ref))
}

// refreshReceivingBuilder re-reads past the cache; a provider without refresh support
// returns an error and the caller handles the original one.
func (w *Worker) refreshReceivingBuilder(ctx context.Context, ref ReceivingBuilderRef) (BuilderEndpoint, error) {
	refresher, ok := w.cfg.ReceivingBuilder.(ReceivingBuilderRefresher)
	if !ok {
		return BuilderEndpoint{}, fmt.Errorf("receiving Builder provider cannot re-read the descriptor")
	}
	return w.checkReceivingBuilder(refresher.RefreshReceivingBuilder(ctx, ref))
}

func (w *Worker) checkReceivingBuilder(builder BuilderEndpoint, err error) (BuilderEndpoint, error) {
	if err != nil {
		return BuilderEndpoint{}, err
	}
	if strings.TrimSpace(builder.OperatorAddress) == "" ||
		strings.TrimSpace(builder.OperatorAddress) != builder.OperatorAddress ||
		strings.TrimSpace(builder.Endpoint) == "" ||
		strings.TrimSpace(builder.ServicePubkey) == "" || builder.CurrentHeight == 0 || builder.AuthorizationNonce == 0 {
		return BuilderEndpoint{}, fmt.Errorf("resolved receiving Builder identity is incomplete or mismatched")
	}
	return builder, nil
}
