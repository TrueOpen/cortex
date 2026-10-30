package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// maxInputChunks bounds chunk_count independently of input_size_bytes.
const maxInputChunks = 1 << 16

// HandleInputResponse stages one DispatchInputResponseV1 chunk, deduplicated
// by (ticket, chunk) (CD §7.2 I1a). Staging is bounded by input_size_bytes and
// per chunk, and counted in the same batch as the chunk (C1). When the count
// says every chunk is in, the input is assembled once, checked against
// input_hash, published under the task hash and the inference is started
// (W5, TD §5.1).
func (d *Dispatcher) HandleInputResponse(ctx context.Context, builder string, r *nexusv1.DispatchInputResponseV1) error {
	ticket, ok := hash32(r.GetDispatchTicketHash())
	if !ok {
		return errors.New("dispatch input: dispatch_ticket_hash is not 32 bytes")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	rec, err := layout.GetDispatchRecord(ctx, d.cfg.Store, ticket)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("dispatch input for unknown ticket %s", ticket)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read dispatch record: %w", err))
	}
	if rec.Builder != builder {
		return fmt.Errorf("dispatch input for ticket %s from %s, which did not dispatch it", ticket, builder)
	}
	if rec.State != layout.DispatchAccepted || rec.InputCommitted {
		d.cfg.Logger.Debug("dispatch input ignored", "ticket", ticket.String(), "state", rec.State, "committed", rec.InputCommitted)
		return nil
	}
	count, index, chunk := r.GetChunkCount(), r.GetChunkIndex(), r.GetInput()
	switch {
	case !bytes.Equal(r.GetTaskId(), rec.TaskID[:]) || !bytes.Equal(r.GetInputHash(), rec.InputHash[:]) || r.GetInputSizeBytes() != rec.InputSizeBytes:
		return fmt.Errorf("dispatch input does not match ticket %s", ticket)
	case count == 0 || index >= count || count > maxInputChunks || uint64(count) > rec.InputSizeBytes:
		return fmt.Errorf("dispatch input chunk %d of %d is out of range", index, count)
	case len(chunk) == 0:
		return fmt.Errorf("dispatch input chunk %d is empty", index)
	}
	rec, _, err = layout.StageDispatchInputChunk(ctx, d.cfg.Store, ticket, index, count, chunk)
	if errors.Is(err, layout.ErrConflict) || errors.Is(err, layout.ErrInputBound) {
		return fmt.Errorf("dispatch input chunk %d of ticket %s refused: %w", index, ticket, err)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("stage input chunk: %w", err))
	}
	if rec.InputChunksReceived < rec.InputChunkCount {
		return nil
	}
	return d.commitInput(ctx, rec)
}

// commitInput assembles, verifies, publishes and starts. Every step is
// idempotent, so a crash anywhere is repaired by a redelivered chunk or the
// sweep's re-request.
func (d *Dispatcher) commitInput(ctx context.Context, rec layout.DispatchRecord) error {
	var input []byte
	var err error
	if rec.InputStagedBytes == rec.InputSizeBytes {
		input, err = layout.AssembleDispatchInput(ctx, d.cfg.Store, rec.TicketHash, rec.InputChunkCount, rec.InputSizeBytes)
		if err != nil {
			return builderclient.Retryable(fmt.Errorf("assemble input: %w", err))
		}
	}
	if input == nil || codec.HashBytes(input) != codec.Hash(rec.InputHash) {
		// TD §5.1: unverified bytes never reach the model. Forget them and
		// let the sweep ask again.
		if _, err := layout.ResetDispatchInput(ctx, d.cfg.Store, rec.TicketHash); err != nil {
			return builderclient.Retryable(fmt.Errorf("reset input: %w", err))
		}
		return fmt.Errorf("input for ticket %s does not match input_hash/input_size_bytes; discarded", rec.TicketHash)
	}
	so := &taskv1.SignedOrderV2{}
	if err := proto.Unmarshal(rec.SignedOrder, so); err != nil {
		return fmt.Errorf("stored order: %w", err)
	}
	sessionID, taskID := hex.EncodeToString(rec.SessionID[:]), hex.EncodeToString(rec.TaskID[:])
	if _, err := d.cfg.Inputs.Write(ctx, evidence.WriteRequest{
		TaskHash: codec.Hash(rec.TaskHash), SessionID: sessionID, TaskID: taskID,
		Kind: string(layout.ArtifactTaskInput), Data: input,
	}); err != nil {
		return builderclient.Retryable(fmt.Errorf("publish input: %w", err))
	}
	o := so.GetOrder()
	if err := d.cfg.Infer.StartDispatchedInfer(ctx, DispatchInferEntry{
		TicketHash: rec.TicketHash, TaskHash: rec.TaskHash, TaskID: taskID, SessionID: sessionID,
		OrderSequence: rec.OrderSequence, ModelID: rec.ModelID, ProfileVersion: rec.ProfileVersion,
		InputHash: rec.InputHash, InputSizeBytes: rec.InputSizeBytes, BuilderOperator: rec.Builder,
		WorkerAddress: d.cfg.Operator, BuilderSetID: o.GetBuilderSetId(), BuilderSetHash: bytes.Clone(o.GetBuilderSetHash()),
		ClaimFromHeight: rec.ClaimFromHeight,
	}); err != nil {
		if errors.Is(err, layout.ErrConflict) {
			// Another ticket owns this task's responsibility; no redelivery
			// changes that (I6).
			return fmt.Errorf("start inference for ticket %s: %w", rec.TicketHash, err)
		}
		return builderclient.Retryable(fmt.Errorf("start inference: %w", err))
	}
	if _, err := layout.UpdateDispatchDroppingInput(ctx, d.cfg.Store, rec.TicketHash, func(x *layout.DispatchRecord) error {
		x.InputCommitted = true
		return nil
	}); err != nil {
		return builderclient.Retryable(fmt.Errorf("record input committed: %w", err))
	}
	d.forgetDeadline(rec.TicketHash)
	d.cfg.Logger.Info("dispatch input committed; inference started", "ticket", rec.TicketHash.String(), "task_hash", rec.TaskHash.String())
	return nil
}
