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

// HandleInputResponse stores one DispatchInputResponseV1 chunk, deduplicated
// by (ticket, chunk) (CD §7.2 I1a). When every chunk is present the input is
// checked against input_hash and input_size_bytes, published under the task
// hash and the inference is started (W5, TD §5.1).
func (d *Dispatcher) HandleInputResponse(ctx context.Context, builder string, r *nexusv1.DispatchInputResponseV1) error {
	d.work.Lock()
	defer d.work.Unlock()
	ticket, ok := hash32(r.GetDispatchTicketHash())
	if !ok {
		return errors.New("dispatch input: dispatch_ticket_hash is not 32 bytes")
	}
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
	case len(chunk) == 0 || uint64(len(chunk)) > rec.InputSizeBytes:
		return fmt.Errorf("dispatch input chunk %d has %d bytes", index, len(chunk))
	case rec.InputChunkCount != 0 && rec.InputChunkCount != count:
		return fmt.Errorf("dispatch input chunk_count changed from %d to %d", rec.InputChunkCount, count)
	}
	if _, err := layout.PutDispatchInputChunk(ctx, d.cfg.Store, ticket, index, chunk); err != nil {
		if errors.Is(err, layout.ErrConflict) {
			return fmt.Errorf("dispatch input chunk %d of ticket %s arrived again with different bytes: %w", index, ticket, err)
		}
		return builderclient.Retryable(fmt.Errorf("store input chunk: %w", err))
	}
	if rec.InputChunkCount == 0 {
		if rec, err = layout.UpdateDispatch(ctx, d.cfg.Store, ticket, func(x *layout.DispatchRecord) error {
			x.InputChunkCount = count
			return nil
		}); err != nil {
			return builderclient.Retryable(fmt.Errorf("record chunk count: %w", err))
		}
	}
	chunks, err := layout.DispatchInputChunks(ctx, d.cfg.Store, ticket)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read input chunks: %w", err))
	}
	if uint32(len(chunks)) < rec.InputChunkCount {
		return nil
	}
	return d.commitInput(ctx, rec, chunks)
}

// commitInput assembles, verifies, publishes and starts. Every step is
// idempotent, so a crash anywhere is repaired by the redelivered last chunk.
func (d *Dispatcher) commitInput(ctx context.Context, rec layout.DispatchRecord, chunks map[uint32][]byte) error {
	input := make([]byte, 0, rec.InputSizeBytes)
	for i := uint32(0); i < rec.InputChunkCount; i++ {
		c, ok := chunks[i]
		if !ok {
			return nil
		}
		input = append(input, c...)
	}
	if uint64(len(input)) != rec.InputSizeBytes || codec.HashBytes(input) != codec.Hash(rec.InputHash) {
		// TD §5.1: unverified bytes never reach the model. Forget them and
		// let the sweep ask again.
		if err := layout.DeleteDispatchInputChunks(ctx, d.cfg.Store, rec.TicketHash); err != nil {
			return builderclient.Retryable(fmt.Errorf("discard input chunks: %w", err))
		}
		if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(x *layout.DispatchRecord) error {
			x.InputChunkCount, x.InputRequestedAtUnixMs = 0, 0
			return nil
		}); err != nil {
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
		return builderclient.Retryable(fmt.Errorf("start inference: %w", err))
	}
	if _, err := layout.UpdateDispatch(ctx, d.cfg.Store, rec.TicketHash, func(x *layout.DispatchRecord) error {
		x.InputCommitted = true
		return nil
	}); err != nil {
		return builderclient.Retryable(fmt.Errorf("record input committed: %w", err))
	}
	if err := layout.DeleteDispatchInputChunks(ctx, d.cfg.Store, rec.TicketHash); err != nil {
		d.cfg.Logger.Warn("drop committed input chunks", "ticket", rec.TicketHash.String(), "err", err)
	}
	d.forgetDeadline(rec.TicketHash)
	d.cfg.Logger.Info("dispatch input committed; inference started", "ticket", rec.TicketHash.String(), "task_hash", rec.TaskHash.String())
	return nil
}
