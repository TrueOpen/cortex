package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
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
	// ClaimFromHeight is D_ticket: the responsibility's deadline until the
	// record lands (RecordDispatchedInfer moves it to infer_deadline_height).
	ClaimFromHeight uint64
	// RecordedHeight and InferDeadlineHeight are set when the record landed
	// before the input was committed; zero otherwise.
	RecordedHeight      uint64
	InferDeadlineHeight uint64
}

// DispatchInferStarter starts and stops the inference of an accepted ticket,
// and hands it the record once the chain has it. All are idempotent.
type DispatchInferStarter interface {
	StartDispatchedInfer(context.Context, DispatchInferEntry) error
	StopDispatchedInfer(ctx context.Context, taskHash, ticketHash layout.StoredHash) error
	RecordDispatchedInfer(ctx context.Context, taskHash, ticketHash layout.StoredHash, recordedHeight, inferDeadline uint64) error
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
	// A repeated start (a redelivered last chunk after a crash) must not
	// re-admit the record: that would reset the stage the runner reached
	// (I5). Another ticket's responsibility for the task is a conflict.
	switch cur, err := layout.GetInferRecord(ctx, r.cfg.Store, e.TaskHash); {
	case err == nil && cur.DispatchTicketHash == e.TicketHash:
		r.Wake()
		return nil
	case err == nil:
		return fmt.Errorf("%w: task %s already runs for ticket %s", layout.ErrConflict, e.TaskHash, cur.DispatchTicketHash)
	case !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("read infer record: %w", err)
	}
	task := layout.TaskRecord{
		SessionID: e.SessionID, OrderSequence: e.OrderSequence, ModelID: e.ModelID, ProfileVersion: e.ProfileVersion,
		InputDigest: e.InputHash, AcceptedInputHash: e.InputHash, InputSizeBytes: e.InputSizeBytes,
		WorkerAddress: e.WorkerAddress, BuilderOperatorAddress: e.BuilderOperator,
		TaskBuilderSetID: e.BuilderSetID, TaskBuilderSetHash: e.BuilderSetHash,
	}
	deadline := e.ClaimFromHeight
	if e.InferDeadlineHeight != 0 {
		deadline = e.InferDeadlineHeight
	}
	infer := layout.InferRecord{
		TaskID: e.TaskID, DispatchTicketHash: e.TicketHash, Stage: layout.StageQueued, DeadlineHeight: deadline,
		WinnerConfirmHeight: e.RecordedHeight, InferDeadlineHeight: e.InferDeadlineHeight,
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

// RecordDispatchedInfer merges the record into the responsibility ticket owns:
// record height, infer_deadline_height and the runner's stop bound, which moves
// from D_ticket to the infer deadline. A responsibility not admitted yet (input
// still being fetched) gets them through DispatchInferEntry instead. It takes
// the runner lock, so the runner's in-memory copy cannot write the old bound
// back; callers must not hold it (the Dispatcher never does).
func (r *TaskRunner) RecordDispatchedInfer(ctx context.Context, taskHash, ticket layout.StoredHash, recordedHeight, inferDeadline uint64) error {
	if r == nil || r.cfg.Store == nil {
		return fmt.Errorf("task runner store is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, err := layout.GetInferRecord(ctx, r.cfg.Store, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rec.DispatchTicketHash != ticket {
		return nil
	}
	if err := layout.MergeInfer(ctx, r.cfg.Store, taskHash, layout.InferRecord{
		TaskID: rec.TaskID, DispatchTicketHash: ticket, Stage: rec.Stage, WinnerConfirmHeight: recordedHeight,
		InferDeadlineHeight: inferDeadline, DeadlineHeight: inferDeadline,
	}); err != nil {
		return err
	}
	if t, ok := r.infer[codec.Hash(taskHash)]; ok {
		t.DeadlineHeight, t.WinnerConfirmHeight = inferDeadline, recordedHeight
		r.infer[codec.Hash(taskHash)] = t
	}
	r.Wake()
	return nil
}
