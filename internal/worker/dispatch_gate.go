package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// DeliveryState is what this ticket's dispatch record says now.
type DeliveryState struct {
	// Paused: anything but accepted-unrecorded or recorded -- a REJECTED
	// notice, another ticket recorded, a conflict, a revoke. Frames, Fin and
	// the receipt stay local (CD §5.2 W6, §8.6); generation is not stopped
	// here.
	Paused bool
	Reason string
	// Set once the chain recorded this ticket as the winner (W6); zero before.
	RecordedHeight      uint64
	InferDeadlineHeight uint64
}

// DispatchGate is the Worker's view of its ticket's DispatchRecord.
type DispatchGate interface {
	DeliveryState(ctx context.Context, ticket codec.Hash) (DeliveryState, error)
	// ReceiptSigned hands the signed receipt to the record before any relay,
	// so self-rescue (CD W13) has it even when the Builder is unreachable.
	ReceiptSigned(ctx context.Context, ticket codec.Hash, receipt builderclient.SignedInferReceipt) error
}

var (
	// ErrDeliveryPaused: the ticket's delivery is paused; nothing more leaves.
	ErrDeliveryPaused = errors.New("dispatch delivery is paused")
	// ErrAwaitingDispatchRecord: frames and Fin are out; the receipt waits for
	// the record, whose infer_deadline_height it signs as expiry_height (S5 Q1).
	ErrAwaitingDispatchRecord = errors.New("waiting for the dispatch record")
)

// deliveryState reads the gate. Without one the caller vouches the ticket is
// recorded with event's heights (tools and package tests); production always
// wires a gate.
func (w *Worker) deliveryState(ctx context.Context, event chainclient.AssignmentFinalized) (DeliveryState, error) {
	if w.cfg.Dispatch == nil {
		return DeliveryState{RecordedHeight: event.WinnerConfirmHeight, InferDeadlineHeight: event.InferDeadlineHeight}, nil
	}
	return w.cfg.Dispatch.DeliveryState(ctx, w.cfg.DispatchTicketHash)
}

// deliveryPaused is the per-frame check. An unreadable gate counts as paused:
// the frame stays journaled and is replayed when delivery resumes.
func (w *Worker) deliveryPaused(ctx context.Context) bool {
	if w.cfg.Dispatch == nil {
		return false
	}
	s, err := w.cfg.Dispatch.DeliveryState(ctx, w.cfg.DispatchTicketHash)
	return err != nil || s.Paused
}

// evidenceRedundancyTarget is ceil(2n/3) of the Task Builder group (CD W11).
func evidenceRedundancyTarget(n int) int { return (2*n + 2) / 3 }

// evidenceFloorReached reports whether finalized of total Task Builders meet
// the ceil(2/3) floor. Below it the relay is retried (the Builders already
// confirmed are skipped next time), unless every failure is permanent: then
// no retry can reach the floor and the error stays permanent. An empty group
// is never success: a target of zero would otherwise pass with nothing
// delivered.
func evidenceFloorReached(finalized, total int, failures []error) error {
	if total == 0 {
		return errors.New("the task has no Task Builder group to finalize the evidence on")
	}
	target := evidenceRedundancyTarget(total)
	if finalized >= target {
		return nil
	}
	err := fmt.Errorf("evidence finalized on %d of %d Task Builders, below the ceil(2/3) target %d: %w",
		finalized, total, target, errors.Join(failures...))
	for _, f := range failures {
		if builderclient.IsRetryable(f) {
			return builderclient.Retryable(err)
		}
	}
	if len(failures) == 0 {
		return builderclient.Retryable(err)
	}
	return err
}
