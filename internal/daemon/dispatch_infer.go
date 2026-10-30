package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// DispatchInferEntry is the ticket-side entry into the existing inference
// executor. It replaces the AssignmentFinalized that S0 retired as the way a
// Worker responsibility is created: every fact comes from the accepted ticket
// and its signed order, none from a Keeper assignment.
type DispatchInferEntry struct {
	TicketHash      layout.StoredHash
	TaskHash        layout.StoredHash
	TaskID          string // lowercase hex
	SessionID       string // lowercase hex
	OrderSequence   uint64
	ModelID         string
	ProfileVersion  uint32
	InputHash       layout.StoredHash
	InputSizeBytes  uint64
	BuilderOperator string
	WorkerAddress   string
	BuilderSetID    string
	BuilderSetHash  []byte
	// ClaimFromHeight is D_ticket. Until S5 sets the record-based
	// infer_deadline_height it is the responsibility's provisional deadline.
	ClaimFromHeight uint64
}

// DispatchInferStarter starts and stops the inference of an accepted ticket.
// Both are idempotent.
type DispatchInferStarter interface {
	StartDispatchedInfer(context.Context, DispatchInferEntry) error
	StopDispatchedInfer(ctx context.Context, taskHash, ticketHash layout.StoredHash) error
}

var _ DispatchInferStarter = (*TaskRunner)(nil)

// StartDispatchedInfer admits the responsibility (task/ + infer/ in one
// batch) and wakes the runner. The input is already committed to the evidence
// store under the task hash (TD §5.1), so productionInferExecutor reads it
// locally instead of fetching.
func (r *TaskRunner) StartDispatchedInfer(ctx context.Context, e DispatchInferEntry) error {
	if r == nil || r.cfg.Store == nil {
		return fmt.Errorf("task runner store is required")
	}
	task := layout.TaskRecord{
		SessionID: e.SessionID, OrderSequence: e.OrderSequence, ModelID: e.ModelID, ProfileVersion: e.ProfileVersion,
		InputDigest: e.InputHash, AcceptedInputHash: e.InputHash, InputSizeBytes: e.InputSizeBytes,
		WorkerAddress: e.WorkerAddress, BuilderOperatorAddress: e.BuilderOperator,
		TaskBuilderSetID: e.BuilderSetID, TaskBuilderSetHash: e.BuilderSetHash,
	}
	infer := layout.InferRecord{
		TaskID: e.TaskID, DispatchTicketHash: e.TicketHash, Stage: layout.StageQueued, DeadlineHeight: e.ClaimFromHeight,
	}
	if err := layout.InferAssignmentBatch(ctx, r.cfg.Store, e.TaskHash, task, infer); err != nil {
		return fmt.Errorf("admit dispatched infer: %w", err)
	}
	r.Wake()
	return nil
}

// StopDispatchedInfer removes the responsibility if ticketHash still owns it,
// so the runner never re-enters it. Cancelling an execution already in
// flight is S6's (CLAIMABLE stops inference).
func (r *TaskRunner) StopDispatchedInfer(ctx context.Context, taskHash, ticketHash layout.StoredHash) error {
	if taskHash.IsZero() {
		return nil
	}
	rec, err := layout.GetInferRecord(ctx, r.cfg.Store, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rec.DispatchTicketHash != ticketHash {
		return nil
	}
	if err := layout.DeleteInferRecord(ctx, r.cfg.Store, taskHash); err != nil {
		return err
	}
	r.Wake()
	return nil
}
