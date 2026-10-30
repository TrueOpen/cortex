package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// HandleRevoke applies one DispatchRevokeV1 from builder. The session already
// verified builder_service_signature on the received bytes against builder's
// current key (dispatchstream.Handler contract, Q10). CD §4.2.0 撤回: stop at
// once, release the lease, never claim (S6 reads State), keep ticket and
// revoke. Staged input is dropped with the state change (I7).
func (d *Dispatcher) HandleRevoke(ctx context.Context, builder string, rv *nexusv1.DispatchRevokeV1) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	if rv.GetReason() != nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF {
		return fmt.Errorf("dispatch revoke from %s: reason %v is outside the closed set (RBF only)", builder, rv.GetReason())
	}
	ticket, ok1 := hash32(rv.GetDispatchTicketHash())
	taskID, ok2 := hash32(rv.GetTaskId())
	if !ok1 || !ok2 {
		return fmt.Errorf("dispatch revoke from %s: task_id and dispatch_ticket_hash must be 32 bytes", builder)
	}
	raw, err := dispatchwire.Raw(rv)
	if err != nil {
		return err
	}
	rec, err := layout.PutDispatchRevoke(ctx, d.cfg.Store, ticket, taskID, builder, raw)
	if errors.Is(err, layout.ErrConflict) {
		return fmt.Errorf("dispatch revoke from %s for ticket %s: %w", builder, ticket, err)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("persist revoke: %w", err))
	}
	// TODO(S6): a stop that fails here is retried only by a redelivered
	// revoke; S6's sweep must retry StopDispatchedInfer for revoked tickets
	// whose inference may still run (M-e).
	if err := d.cfg.Infer.StopDispatchedInfer(ctx, rec.TaskHash, rec.TicketHash); err != nil {
		return builderclient.Retryable(fmt.Errorf("stop inference: %w", err))
	}
	if err := d.releaseLease(ctx, ticket); err != nil {
		return err
	}
	d.forgetDeadline(ticket)
	d.cfg.Logger.Info("dispatch ticket revoked (RBF)", "builder", builder, "ticket", ticket.String(), "state", rec.State)
	return nil
}
