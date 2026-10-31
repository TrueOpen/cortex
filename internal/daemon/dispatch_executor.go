package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/worker"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// dispatchedInfer is the dispatch side of one Worker responsibility: the
// accepted ticket's record, the source of every pre-record fact (S4 Q12). The
// chain cross-check of the same facts happens once, when the record lands
// (Dispatcher.applyRecord).
type dispatchedInfer struct {
	rec              layout.DispatchRecord
	worker           string
	referenceHeight  uint64
	generationDigest codec.Hash
}

func loadDispatchedInfer(ctx context.Context, st *store.Store, task store.InferTask) (dispatchedInfer, error) {
	if task.DispatchTicketHash == (codec.Hash{}) {
		return dispatchedInfer{}, fmt.Errorf("infer responsibility %s carries no dispatch ticket; a Phase 1 Worker duty only comes from an accepted ticket", task.TaskID)
	}
	rec, err := layout.GetDispatchRecord(ctx, st, layout.StoredHash(task.DispatchTicketHash))
	if err != nil {
		return dispatchedInfer{}, fmt.Errorf("dispatch record %s: %w", task.DispatchTicketHash, err)
	}
	if hex.EncodeToString(rec.TaskID[:]) != task.TaskID {
		return dispatchedInfer{}, fmt.Errorf("dispatch record %s is for task %s, not %s", task.DispatchTicketHash, rec.TaskID, task.TaskID)
	}
	var ticket taskv1.DispatchTicketV1
	if err := proto.Unmarshal(rec.Ticket, &ticket); err != nil {
		return dispatchedInfer{}, fmt.Errorf("stored ticket: %w", err)
	}
	digest, err := orderGenerationDigest(rec.SignedOrder)
	if err != nil {
		return dispatchedInfer{}, err
	}
	return dispatchedInfer{rec: rec, worker: ticket.GetTarget().GetOperatorAddress(), referenceHeight: ticket.GetReferenceHeight(), generationDigest: digest}, nil
}

func (d dispatchedInfer) taskID() string { return hex.EncodeToString(d.rec.TaskID[:]) }

// TaskFacts serves accepted_task_hash and generation_params_digest from the
// ticket (whose task_hash S4 checked against the order) and the order.
func (d dispatchedInfer) TaskFacts(_ context.Context, taskID string) (taskfacts.Facts, error) {
	if taskID != d.taskID() {
		return taskfacts.Facts{}, fmt.Errorf("ticket %s answers for task %s, not %s", d.rec.TicketHash, d.taskID(), taskID)
	}
	return taskfacts.Facts{TaskID: d.taskID(), TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
		AcceptedTaskHash:       chainclient.ProtoBytes32(bytes.Clone(d.rec.TaskHash[:])),
		GenerationParamsDigest: chainclient.ProtoBytes32(bytes.Clone(d.generationDigest[:])),
	}}, nil
}

// TaskSnapshot answers the Worker's assignment re-read from the ticket: before
// the record there is no chain Task to read.
func (d dispatchedInfer) TaskSnapshot(_ context.Context, taskID string) (chainclient.TaskSnapshot, error) {
	if taskID != d.taskID() {
		return chainclient.TaskSnapshot{}, fmt.Errorf("ticket %s answers for task %s, not %s", d.rec.TicketHash, d.taskID(), taskID)
	}
	return chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
		TaskID: d.taskID(), SessionID: hex.EncodeToString(d.rec.SessionID[:]), SelectedWorker: d.worker,
		AcceptedOrderPayloadHash: chainclient.HexHash(d.rec.InputHash),
	}}, nil
}

// localHeights are the heights the Worker's local legacy envelope is bounded
// by: the record's once it landed, before it the ticket's reference height and
// the runner's current bound (D_ticket). They never reach the chain; the
// receipt takes the record's heights from the dispatch gate (S5 Q1).
func (d dispatchedInfer) localHeights(task store.InferTask) (from, until uint64) {
	from, until = d.rec.RecordedHeight, d.rec.InferDeadlineHeight
	if from == 0 {
		from = d.referenceHeight
	}
	if until == 0 {
		until = task.DeadlineHeight
	}
	return from, until
}

// dispatchGate is worker.DispatchGate over the store's DispatchRecord.
type dispatchGate struct{ st *store.Store }

var _ worker.DispatchGate = dispatchGate{}

func (g dispatchGate) DeliveryState(ctx context.Context, ticket codec.Hash) (worker.DeliveryState, error) {
	rec, err := layout.GetDispatchRecord(ctx, g.st, layout.StoredHash(ticket))
	if err != nil {
		return worker.DeliveryState{}, err
	}
	switch rec.State {
	case layout.DispatchAccepted:
		return worker.DeliveryState{}, nil
	case layout.DispatchRecorded:
		return worker.DeliveryState{RecordedHeight: rec.RecordedHeight, InferDeadlineHeight: rec.InferDeadlineHeight}, nil
	}
	return worker.DeliveryState{Paused: true, Reason: fmt.Sprintf("ticket is %s: %s", rec.State, rec.StateReason)}, nil
}

// ReceiptSigned stores the signed receipt on the record, write-once; the
// record refuses it unless the ticket is recorded (S5 Q1).
func (g dispatchGate) ReceiptSigned(ctx context.Context, ticket codec.Hash, receipt builderclient.SignedInferReceipt) error {
	if receipt.DispatchTicketHash != ticket.String() {
		return fmt.Errorf("receipt binds ticket %s, not %s", receipt.DispatchTicketHash, ticket)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = layout.UpdateDispatch(ctx, g.st, layout.StoredHash(ticket), func(r *layout.DispatchRecord) error {
		r.Receipt = raw
		return nil
	})
	return err
}
