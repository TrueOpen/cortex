package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// gcBatch bounds the tickets one GC pass looks at.
const gcBatch = 256

// retentionSpan is how long past D_ticket a settled ticket is kept: every
// window its signed material can still be asked for (claim + rebuttal;
// challenge + response, which also covers recorded_height + challenge window
// since recorded_height <= D_ticket), plus dispatch_evidence_retention_blocks
// (S6 Q9, read at GC time).
func retentionSpan(p chainclient.DispatchParamsSnapshot) uint64 {
	return hrAddSat(max(hrAddSat(p.CompensationClaimWindowBlocks, p.CompensationRebuttalBlocks),
		hrAddSat(p.ChallengeWindowBlocks, p.ChallengeResponseBlocks)), p.EvidenceRetentionBlocks)
}

// collectGarbage deletes settled tickets whose retention ended, gcBatch per
// pass every GCEveryBlocks, resuming from a cursor. The caller holds the
// work lock.
func (d *Dispatcher) collectGarbage(ctx context.Context, height uint64) error {
	d.mu.Lock()
	due := d.gcAt == 0 || height >= hrAddSat(d.gcAt, d.cfg.GCEveryBlocks)
	cursor := d.gcCursor
	d.mu.Unlock()
	if !due {
		return nil
	}
	tickets, err := layout.CollectableDispatchTickets(ctx, d.cfg.Store, cursor, gcBatch)
	if err != nil {
		return fmt.Errorf("dispatcher gc: %w", err)
	}
	var span uint64
	if len(tickets) > 0 {
		p, err := d.cfg.Chain.DispatchParamsAt(ctx, height)
		if err != nil {
			return fmt.Errorf("dispatcher gc: params: %w", err)
		}
		if span = retentionSpan(p); span == 0 {
			// Zero windows and zero retention are not a chain this node can
			// keep evidence for; deleting at D_ticket would be worse than
			// keeping everything.
			d.cfg.Logger.Warn("dispatch GC skipped: the chain's claim, challenge and retention windows are all zero")
			tickets = nil
		}
	}
	var errs []error
	for _, t := range tickets {
		if err := d.collectTicket(ctx, t, height, span); err != nil {
			errs = append(errs, fmt.Errorf("gc ticket %s: %w", t, err))
		}
	}
	d.mu.Lock()
	d.gcAt = height
	d.gcCursor = layout.StoredHash{}
	if len(tickets) == gcBatch {
		d.gcCursor = tickets[len(tickets)-1]
	}
	d.mu.Unlock()
	return errors.Join(errs...)
}

func (d *Dispatcher) collectTicket(ctx context.Context, ticket layout.StoredHash, height, span uint64) error {
	rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rec.State == layout.DispatchRevoked {
		// HandleRevoke stores the revoke before it stops the inference and
		// releases the leases; a failure there is finished here (all three
		// are idempotent).
		if err := d.cfg.Infer.StopDispatchedInfer(ctx, rec.TaskHash, rec.TicketHash); err != nil {
			return builderclient.Retryable(fmt.Errorf("stop inference: %w", err))
		}
		if err := d.releaseLease(ctx, rec.TicketHash); err != nil {
			return err
		}
		if err := d.releaseTaskLeaseOf(ctx, rec); err != nil {
			return err
		}
	}
	// Retention runs from D_ticket; a recorded ticket's material is asked
	// for until its infer deadline at least (M8); a tombstone has neither
	// and is anchored at the first GC pass that saw it.
	base := max(rec.ClaimFromHeight, rec.InferDeadlineHeight)
	if base == 0 {
		if rec.GCFromHeight == 0 {
			_, err := layout.UpdateDispatch(ctx, d.cfg.Store, ticket, func(r *layout.DispatchRecord) error { r.GCFromHeight = height; return nil })
			return err
		}
		base = rec.GCFromHeight
	}
	if height < hrAddSat(base, span) {
		return nil
	}
	// Deletable first: nothing outside the store is retired for a ticket
	// that still holds a lease or owns its inference.
	if err := layout.CanDeleteDispatchRecord(ctx, d.cfg.Store, ticket); errors.Is(err, layout.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		return nil // a later pass takes it
	} else if err != nil {
		return err
	}
	// A recorded ticket's scope follows the task's operator-confirmed
	// cleanup (S6 Q9), and a conflict's is kept as the evidence of the
	// disagreement; every other one was never referenced by the chain.
	if rec.State != layout.DispatchRecorded && rec.State != layout.DispatchConflict && d.cfg.Evidence != nil && !rec.TaskHash.IsZero() {
		if err := d.cfg.Evidence.DropNamespace(ctx, codec.Hash(layout.DispatchEvidenceScope(rec.TaskHash, rec.TicketHash))); err != nil {
			return err
		}
	}
	if err := layout.DeleteDispatchRecord(ctx, d.cfg.Store, ticket); errors.Is(err, layout.ErrConflict) {
		return nil // took a lease or an inference since the check: a later pass takes it
	} else if err != nil {
		return err
	}
	return nil
}
