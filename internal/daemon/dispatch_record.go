package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const (
	recordedNotice = int32(taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED)
	rejectedNotice = int32(taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED)
)

// DispatchRecordedFact is one EventDispatchRecorded as the reconciler read it.
type DispatchRecordedFact struct {
	Height        uint64 // block of the event = recorded_height
	TaskID        layout.StoredHash
	SessionID     layout.StoredHash
	OrderSequence uint64
	Builder       string
	Winner        string
	TicketHash    layout.StoredHash
	RecordHash    layout.StoredHash
	InferDeadline uint64
}

// DispatchRecordObserver consumes the authoritative record events (S9 wires
// the Dispatcher as TaskRunnerConfig.DispatchRecords).
type DispatchRecordObserver interface {
	ObserveDispatchRecorded(context.Context, DispatchRecordedFact) error
}

var _ DispatchRecordObserver = (*Dispatcher)(nil)

// HandleRecordResult applies one RecordResultNoticeV1 from the dispatching
// Builder. It is a hint (CD §5.2 W6): REJECTED pauses delivery and nothing
// else (§8.6); RECORDED makes this node ask the chain, now and on the next
// sweeps, and only the chain's answer moves the ticket. The notice is stored
// and acknowledged even when the chain does not show the record yet (S5 Q4).
// The session verified builder_service_signature before this call (S4 Q10).
func (d *Dispatcher) HandleRecordResult(ctx context.Context, builder string, n *nexusv1.RecordResultNoticeV1) error {
	ticket, ok := hash32(n.GetDispatchTicketHash())
	if !ok {
		return errors.New("record notice: dispatch_ticket_hash is not 32 bytes")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("record notice for unknown ticket %s", ticket)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}
	if rec.Builder != builder {
		return fmt.Errorf("record notice for ticket %s from %s, which did not dispatch it", ticket, builder)
	}
	if rec.State != layout.DispatchAccepted && rec.State != layout.DispatchPendingClaim {
		d.cfg.Logger.Info("record notice ignored", "ticket", ticket.String(), "state", rec.State, "status", n.GetStatus().String())
		return nil
	}
	raw, err := dispatchwire.Raw(n)
	if err != nil {
		return err
	}
	rejected := n.GetStatus() == taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED
	rec, err = layout.UpdateDispatch(ctx, d.cfg.Store, ticket, func(r *layout.DispatchRecord) error {
		if len(r.RecordNotice) == 0 {
			r.RecordNotice, r.NoticeStatus = raw, int32(n.GetStatus())
		}
		if rejected && r.State == layout.DispatchAccepted {
			r.State = layout.DispatchPendingClaim
			r.StateReason = fmt.Sprintf("Builder notice REJECTED (%s): delivery paused, inference continues (CD §8.6)", n.GetRejectCode())
		}
		return nil
	})
	if errors.Is(err, layout.ErrConflict) {
		return fmt.Errorf("record notice for ticket %s: %w", ticket, err)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("record notice: %w", err))
	}
	if n.GetStatus() == taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED {
		if err := d.confirmRecord(ctx, rec); err != nil && !builderclient.IsRetryable(err) {
			return err
		}
	}
	return nil
}

// ObserveDispatchRecorded applies one committed dispatch_recorded event, the
// authoritative source (CD §4.1a, W6). The event is re-read through
// QueryDispatchRecord; a disagreement is a ChainObservationConflict and a
// permanent refusal that changes nothing locally. A task this node holds no
// ticket for is not its concern here (S5 Q15; S8 reads it).
func (d *Dispatcher) ObserveDispatchRecorded(ctx context.Context, f DispatchRecordedFact) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	recs, err := layout.DispatchRecordsForTask(ctx, d.cfg.Store, f.TaskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("records for task %s: %w", f.TaskID, err))
	}
	if len(recs) == 0 {
		return nil
	}
	snap, err := d.cfg.Chain.DispatchRecord(ctx, f.SessionID[:], f.OrderSequence)
	if err != nil {
		// NotFound included: the event is committed and the query lags.
		return builderclient.Retryable(fmt.Errorf("confirm dispatch_recorded for task %s: %w", f.TaskID, err))
	}
	if !bytes.Equal(snap.TaskID, f.TaskID[:]) || !bytes.Equal(snap.TicketHash, f.TicketHash[:]) || !bytes.Equal(snap.RecordHash, f.RecordHash[:]) ||
		snap.RecordedHeight != f.Height || snap.Builder != f.Builder || snap.Winner != f.Winner {
		d.cfg.Logger.Error("dispatch chain observation conflict", "alert", "dispatch_chain_observation_conflict",
			"task", f.TaskID.String(), "why", "dispatch_recorded event disagrees with QueryDispatchRecord")
		return fmt.Errorf("ChainObservationConflict: dispatch_recorded for task %s disagrees with QueryDispatchRecord", f.TaskID)
	}
	var errs []error
	for _, rec := range recs {
		if err := d.applyRecord(ctx, rec, snap, f.InferDeadline); err != nil {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
		}
	}
	return joinDispatchErrs(errs)
}

// joinDispatchErrs joins errs, staying retryable when any of them is: a
// handler that must still repeat work for one ticket asks for redelivery.
func joinDispatchErrs(errs []error) error {
	err := errors.Join(errs...)
	for _, e := range errs {
		if builderclient.IsRetryable(e) {
			return builderclient.Retryable(err)
		}
	}
	return err
}

// confirmRecord asks the chain whether rec's order is recorded. NotFound is
// "not yet": retryable, nothing changes.
func (d *Dispatcher) confirmRecord(ctx context.Context, rec layout.DispatchRecord) error {
	snap, err := d.cfg.Chain.DispatchRecord(ctx, rec.SessionID[:], rec.OrderSequence)
	if errors.Is(err, chainclient.ErrNotFound) {
		return builderclient.Retryable(fmt.Errorf("order %s/%d is not recorded yet", rec.SessionID, rec.OrderSequence))
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("query dispatch record: %w", err))
	}
	return d.applyRecord(ctx, rec, snap, 0)
}

// applyRecord merges one chain record into rec (CD §5.2 W6, §8.6).
// wantDeadline is the event's infer_deadline, zero when the record came from
// a query. The caller holds the work lock.
func (d *Dispatcher) applyRecord(ctx context.Context, rec layout.DispatchRecord, snap chainclient.DispatchRecordSnapshot, wantDeadline uint64) error {
	if !bytes.Equal(snap.TaskID, rec.TaskID[:]) {
		return fmt.Errorf("ChainObservationConflict: the record of order %d names task %x, ticket %s is for %s", rec.OrderSequence, snap.TaskID, rec.TicketHash, rec.TaskID)
	}
	alreadyRecorded := rec.State == layout.DispatchRecorded
	winner, _ := hash32(snap.TicketHash)
	if winner != rec.TicketHash || snap.Winner != d.cfg.Operator {
		// Another ticket won the order (S5 Q6): pause, keep the lease and the
		// inference; settleDeadlines decides the claim at D_ticket.
		if rec.State != layout.DispatchAccepted {
			return nil
		}
		if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
			r.State, r.StateReason = layout.DispatchPendingClaim, fmt.Sprintf("order recorded with ticket %s for %s", winner, snap.Winner)
			return nil
		}); err != nil {
			return builderclient.Retryable(fmt.Errorf("pause a losing ticket: %w", err))
		}
		d.cfg.Logger.Info("dispatch order recorded for another ticket; delivery paused", "ticket", rec.TicketHash.String(), "winner", winner.String())
		return nil
	}
	if rec.State != layout.DispatchRecorded {
		if rec.State != layout.DispatchAccepted && rec.State != layout.DispatchPendingClaim {
			d.cfg.Logger.Error("dispatch chain observation conflict", "alert", "dispatch_chain_observation_conflict",
				"ticket", rec.TicketHash.String(), "state", rec.State, "why", "recorded on chain as the winner")
			return fmt.Errorf("ChainObservationConflict: ticket %s is recorded on chain but locally %s", rec.TicketHash, rec.State)
		}
		a, err := d.cfg.Chain.DispatchAssignment(ctx, rec.TaskID[:])
		if err != nil {
			return builderclient.Retryable(fmt.Errorf("query recorded task: %w", err))
		}
		if !bytes.Equal(a.DispatchTicketHash, rec.TicketHash[:]) || a.WinnerWorker != d.cfg.Operator || a.RecordHeight != snap.RecordedHeight ||
			(wantDeadline != 0 && a.InferDeadlineHeight != wantDeadline) {
			if a.Height < snap.Height {
				return builderclient.Retryable(fmt.Errorf("task views of %s at %d lag the record read at %d", rec.TaskID, a.Height, snap.Height))
			}
			// The chain disagrees with itself or with the event (S5 Q2): refuse
			// it, change nothing, and leave the ticket to the next observation.
			d.cfg.Logger.Error("dispatch chain observation conflict", "alert", "dispatch_chain_observation_conflict",
				"ticket", rec.TicketHash.String(), "why", "task assignment view disagrees with the dispatch record")
			return fmt.Errorf("ChainObservationConflict: task view of %s (ticket %x, winner %s, record_height %d, infer_deadline_height %d) disagrees with the record (ticket %s, record_height %d, infer_deadline %d)",
				rec.TaskID, a.DispatchTicketHash, a.WinnerWorker, a.RecordHeight, a.InferDeadlineHeight, rec.TicketHash, snap.RecordedHeight, wantDeadline)
		}
		digest, err := orderGenerationDigest(rec.SignedOrder)
		if err != nil {
			return err
		}
		if !bytes.Equal(a.AcceptedTaskHash, rec.TaskHash[:]) || !bytes.Equal(a.GenerationParamsDigest, digest[:]) {
			return d.conflict(ctx, rec, fmt.Sprintf("recorded task %s carries accepted_task_hash %x / generation_params_digest %x; the ticket and order promised %s / %s",
				rec.TaskID, a.AcceptedTaskHash, a.GenerationParamsDigest, rec.TaskHash, digest))
		}
		// The lease moves first: a crash or a retryable failure after it
		// leaves an accepted ticket whose lease is on the task key, which a
		// redelivery finishes and a release gives back (releaseTaskLeaseOf).
		// The reverse order left a recorded ticket with nothing to retry the
		// move.
		if err := d.rebindLease(ctx, rec, false); err != nil {
			return err
		}
		recordHash, _ := hash32(snap.RecordHash)
		if rec, err = layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(r *layout.DispatchRecord) error {
			r.State, r.StateReason = layout.DispatchRecorded, "recorded on chain with this ticket as the winner"
			r.WinnerTicketHash, r.RecordHash, r.RecordedHeight, r.InferDeadlineHeight = r.TicketHash, recordHash, snap.RecordedHeight, a.InferDeadlineHeight
			r.FalseNotice = r.NoticeStatus == rejectedNotice
			return nil
		}); err != nil {
			return builderclient.Retryable(fmt.Errorf("record ticket %s: %w", rec.TicketHash, err))
		}
		d.cfg.Logger.Info("dispatch recorded", "ticket", rec.TicketHash.String(), "recorded_height", rec.RecordedHeight, "infer_deadline_height", rec.InferDeadlineHeight)
		if rec.FalseNotice {
			d.cfg.Logger.Warn("REJECTED notice for a ticket the chain recorded", "alert", AlertDispatchFalseNotice,
				"ticket", rec.TicketHash.String(), "builder", rec.Builder)
		}
	}
	// Idempotent tail: a redelivery after a crash past the state write
	// resumes here.
	if alreadyRecorded {
		if err := d.rebindLease(ctx, rec, true); err != nil {
			return err
		}
	}
	if err := d.cfg.Infer.RecordDispatchedInfer(ctx, rec.TaskHash, rec.TicketHash, rec.RecordedHeight, rec.InferDeadlineHeight); err != nil {
		return builderclient.Retryable(fmt.Errorf("record the infer deadline: %w", err))
	}
	return nil
}

// rebindLease moves rec's lease to (task_id, WORKER); idempotent.
func (d *Dispatcher) rebindLease(ctx context.Context, rec layout.DispatchRecord, alreadyRecorded bool) error {
	_, err := d.cfg.Leases.Rebind(ctx, rec.TicketHash, rec.TaskID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, layout.ErrConflict) && alreadyRecorded:
		// The lease moved earlier and has been given back since (the infer
		// succeeded or ended): nothing left to move.
		return nil
	case errors.Is(err, layout.ErrConflict):
		return fmt.Errorf("rebind lease of ticket %s: %w", rec.TicketHash, err)
	default:
		return builderclient.Retryable(fmt.Errorf("rebind lease: %w", err))
	}
}

// conflict fails a ticket closed whose record contradicts what the ticket and
// order promised: its receipt could never be valid. Stop, release, then the
// state (the S4 release order); every step is idempotent.
func (d *Dispatcher) conflict(ctx context.Context, rec layout.DispatchRecord, why string) error {
	if err := d.release(ctx, rec, layout.DispatchConflict, why); err != nil {
		return err
	}
	d.cfg.Logger.Error("dispatch chain observation conflict", "alert", "dispatch_chain_observation_conflict", "ticket", rec.TicketHash.String(), "why", why)
	return fmt.Errorf("ChainObservationConflict: %s", why)
}

// sweepRecords re-asks the chain for tickets whose Builder said RECORDED,
// once per committed height. The caller holds the work lock.
func (d *Dispatcher) sweepRecords(ctx context.Context, height uint64) error {
	recs, err := layout.AwaitingRecordDispatches(ctx, d.cfg.Store)
	if err != nil {
		return fmt.Errorf("dispatcher: awaiting record: %w", err)
	}
	var pending []layout.DispatchRecord
	for _, rec := range recs {
		if rec.NoticeStatus == recordedNotice {
			pending = append(pending, rec)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	d.mu.Lock()
	fresh := height > d.recordCheckedAt
	if fresh {
		d.recordCheckedAt = height
	}
	d.mu.Unlock()
	if !fresh {
		return nil
	}
	var errs []error
	for _, rec := range pending {
		if err := d.confirmRecord(ctx, rec); err != nil && !builderclient.IsRetryable(err) {
			errs = append(errs, fmt.Errorf("ticket %s: %w", rec.TicketHash, err))
		}
	}
	return errors.Join(errs...)
}

// orderGenerationDigest is generation_params_digest of a SignedOrderV2
// (08-TaskOrderHash §4.3), the value the chain freezes at record time.
func orderGenerationDigest(signedOrder []byte) (codec.Hash, error) {
	_, facts, err := nodewire.TaskOrderHashAndFactsSignedOrderHex(hex.EncodeToString(signedOrder))
	if err != nil {
		return codec.Hash{}, fmt.Errorf("stored signed order: %w", err)
	}
	if facts.Generation == nil {
		return codec.Hash{}, errors.New("stored signed order carries no generation params")
	}
	return facts.Generation.Digest()
}
