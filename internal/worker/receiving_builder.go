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
// read from; see ReceivingBuilderRef.
//
// Two methods because the two questions genuinely differ, not because one is a
// leftover. Everything the task's material consists of -- output frames
// (04-任务/02 §9.2: 逐帧向全部 Task Builders 推送), the evidence bundles and their
// FinalizeTaskResult (§230, §257) -- goes to every Task Builder, so a Builder
// that is down cannot strand the task and a Verifier can obtain data from any of
// them. The single Builder remains for the one thing that is genuinely
// once-per-task: relaying the signed receipt onward to the chain.
type ReceivingBuilderProvider interface {
	ResolveReceivingBuilder(ctx context.Context, task ReceivingBuilderRef) (BuilderEndpoint, error)
	// ResolveReceivingBuilders returns every Task Builder of this task in the
	// order the chain froze, which is also the order
	// MsgReportDataUnavailable's bitmap is defined against. Callers must not
	// reorder it.
	ResolveReceivingBuilders(ctx context.Context, task ReceivingBuilderRef) ([]BuilderEndpoint, error)
}

// ReceivingBuilderRefresher is an optional capability: re-read the descriptor once,
// past the cache (ADR-0015: after a Builder changes certificates the fingerprint
// mismatches -> re-read the descriptor and retry once).
type ReceivingBuilderRefresher interface {
	RefreshReceivingBuilder(ctx context.Context, task ReceivingBuilderRef) (BuilderEndpoint, error)
}

// ReceivingBuildersRefresher is the list form of ReceivingBuilderRefresher, for
// the same ADR-0015 reason. The single-Builder refresh can only name the
// assigned Builder, and the evidence path now talks to Builders it cannot name;
// without this, a certificate rotation on any of the others would be
// unrecoverable for that Builder within the task.
type ReceivingBuildersRefresher interface {
	RefreshReceivingBuilders(ctx context.Context, task ReceivingBuilderRef) ([]BuilderEndpoint, error)
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

// ResolveReceivingBuilders answers with the one Builder the function knows. A
// caller that has only a function has no task-to-Builder-list read to offer, so
// the honest answer is the single-element list rather than an error: the frame
// path then behaves exactly as it did before, which is what a test fixture or a
// fake wants. Production wires daemon.receivingBuilders, which reads the frozen
// selection from the chain.
func (f ReceivingBuilderFunc) ResolveReceivingBuilders(
	ctx context.Context,
	task ReceivingBuilderRef,
) ([]BuilderEndpoint, error) {
	endpoint, err := f(ctx, task)
	if err != nil {
		return nil, err
	}
	return []BuilderEndpoint{endpoint}, nil
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

// receivingBuilders resolves every Task Builder for one task. Each is checked
// the same way the single receiving Builder is, and an unusable member fails the
// whole resolution rather than being skipped: relaying to a subset while
// believing it is the whole set is the failure this read exists to remove.
func (w *Worker) receivingBuilders(ctx context.Context, ref ReceivingBuilderRef) ([]BuilderEndpoint, error) {
	if w.cfg.ReceivingBuilder == nil {
		return nil, fmt.Errorf("receiving Builder provider is required")
	}
	builders, err := w.cfg.ReceivingBuilder.ResolveReceivingBuilders(ctx, ref)
	if err != nil {
		return nil, err
	}
	if len(builders) == 0 {
		return nil, fmt.Errorf("task has no resolved Task Builders")
	}
	checked := make([]BuilderEndpoint, 0, len(builders))
	for _, builder := range builders {
		endpoint, err := w.checkReceivingBuilder(builder, nil)
		if err != nil {
			return nil, err
		}
		checked = append(checked, endpoint)
	}
	return checked, nil
}

// currentReceivingBuilder re-reads one Task Builder's identity so a storage
// confirmation is verified against the service key and authorization nonce the
// Builder holds now, not the ones cached when the upload began.
func (w *Worker) currentReceivingBuilder(ctx context.Context, ref ReceivingBuilderRef, operator string) (BuilderEndpoint, error) {
	builders, err := w.receivingBuilders(ctx, ref)
	if err != nil {
		return BuilderEndpoint{}, err
	}
	return builderByOperator(builders, operator)
}

// refreshReceivingBuilderFor re-reads one Task Builder's descriptor past the
// cache. The single-Builder refresher is preferred when the wanted Builder is
// the assigned one, because a provider may support that and nothing else.
func (w *Worker) refreshReceivingBuilderFor(ctx context.Context, ref ReceivingBuilderRef, operator string) (BuilderEndpoint, error) {
	if operator == ref.AssignedBuilderOperator {
		if endpoint, err := w.refreshReceivingBuilder(ctx, ref); err == nil {
			return endpoint, nil
		}
	}
	refresher, ok := w.cfg.ReceivingBuilder.(ReceivingBuildersRefresher)
	if !ok {
		return BuilderEndpoint{}, fmt.Errorf("receiving Builder provider cannot re-read Task Builder descriptors")
	}
	builders, err := refresher.RefreshReceivingBuilders(ctx, ref)
	if err != nil {
		return BuilderEndpoint{}, err
	}
	endpoint, err := builderByOperator(builders, operator)
	if err != nil {
		return BuilderEndpoint{}, err
	}
	return w.checkReceivingBuilder(endpoint, nil)
}

// builderByOperator picks one member out of a resolved Task Builder list. A
// miss is an error rather than a fallback: the list is the chain's frozen
// selection, and an operator that is not in it is not a Builder this task's
// material may be sent to.
func builderByOperator(builders []BuilderEndpoint, operator string) (BuilderEndpoint, error) {
	for _, builder := range builders {
		if builder.OperatorAddress == operator {
			return builder, nil
		}
	}
	return BuilderEndpoint{}, fmt.Errorf("Task Builder %s is not in this task's frozen selection", operator)
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
