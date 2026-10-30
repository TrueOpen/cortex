package chainclient

import (
	"bytes"
	"context"
	"fmt"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// DispatchRecordSnapshot is task.v1 DispatchRecordState at one committed
// height: the record entry the chain accepted for one order (CD §5.2 W6).
type DispatchRecordSnapshot struct {
	Height                 uint64
	TaskID                 []byte
	RecordHash             []byte
	TicketHash             []byte // the winner ticket
	Builder                string
	Winner                 string // winner.operator_address
	WinnerRound            uint32
	RecordedHeight         uint64
	ClaimWindowCloseHeight uint64
}

// DispatchRecord reads the record of order (sessionID, orderSequence) through
// the by_order selector at the latest committed height; the Query has no
// task_id selector. ErrNotFound: not recorded (yet, or ever).
func (c *KeeperABCIClient) DispatchRecord(ctx context.Context, sessionID []byte, orderSequence uint64) (DispatchRecordSnapshot, error) {
	if len(sessionID) != 32 {
		return DispatchRecordSnapshot{}, fmt.Errorf("session_id is %d bytes, want 32", len(sessionID))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return DispatchRecordSnapshot{}, err
	}
	var response taskv1.QueryDispatchRecordResponse
	req := &taskv1.QueryDispatchRecordRequest{Selector: &taskv1.QueryDispatchRecordRequest_ByOrder{
		ByOrder: &taskv1.DispatchRecordByOrderV1{SessionId: sessionID, OrderSequence: orderSequence},
	}}
	if err := c.query(ctx, taskQuery+"DispatchRecord", height, req, &response); err != nil {
		return DispatchRecordSnapshot{}, err
	}
	r := response.GetRecord()
	for _, f := range []struct {
		name  string
		value []byte
	}{{"task_id", r.GetTaskId()}, {"dispatch_record_hash", r.GetDispatchRecordHash()}, {"dispatch_ticket_hash", r.GetDispatchTicketHash()}} {
		if len(f.value) != 32 {
			return DispatchRecordSnapshot{}, fmt.Errorf("Keeper dispatch record %s is %d bytes, want 32", f.name, len(f.value))
		}
	}
	if r.GetWinner().GetOperatorAddress() == "" || r.GetBuilderAddress() == "" || r.GetRecordedHeight() == 0 || r.GetRecordedHeight() > height {
		return DispatchRecordSnapshot{}, fmt.Errorf("Keeper dispatch record for order %d is incomplete", orderSequence)
	}
	return DispatchRecordSnapshot{
		Height: height, TaskID: bytes.Clone(r.GetTaskId()), RecordHash: bytes.Clone(r.GetDispatchRecordHash()),
		TicketHash: bytes.Clone(r.GetDispatchTicketHash()), Builder: r.GetBuilderAddress(), Winner: r.GetWinner().GetOperatorAddress(),
		WinnerRound: r.GetWinnerRound(), RecordedHeight: r.GetRecordedHeight(), ClaimWindowCloseHeight: r.GetClaimWindowCloseHeight(),
	}, nil
}

// DispatchAssignmentSnapshot is the recorded Task as the Worker needs it, read
// at one committed height from Query/Task (core) and Query/TaskAssignment.
type DispatchAssignmentSnapshot struct {
	Height                 uint64
	TaskID                 []byte
	AcceptedTaskHash       []byte
	GenerationParamsDigest []byte
	RecordHeight           uint64
	// InferDeadlineHeight is record_height + the Task's timeout bucket, as the
	// Keeper wrote it (KC §10.1). Cortex never recomputes the bucket (S5 Q2).
	InferDeadlineHeight uint64
	DispatchTicketHash  []byte
	WinnerWorker        string
	ReceiptAccepted     bool
}

// DispatchAssignment reads the facts a recorded Worker duty is checked
// against: the accepted task hash and generation digest the ticket and order
// promised, the record height and the infer deadline. Both views are read at
// the same committed height.
func (c *KeeperABCIClient) DispatchAssignment(ctx context.Context, taskID []byte) (DispatchAssignmentSnapshot, error) {
	if len(taskID) != 32 {
		return DispatchAssignmentSnapshot{}, fmt.Errorf("task_id is %d bytes, want 32", len(taskID))
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return DispatchAssignmentSnapshot{}, err
	}
	var task taskv1.QueryTaskResponse
	var assignment taskv1.QueryTaskAssignmentResponse
	if err := firstError(c.runReads(
		func() error {
			return c.query(ctx, taskQuery+"Task", height, &taskv1.QueryTaskRequest{TaskId: taskID}, &task)
		},
		func() error {
			return c.query(ctx, taskQuery+"TaskAssignment", height, &taskv1.QueryTaskAssignmentRequest{TaskId: taskID}, &assignment)
		},
	)); err != nil {
		return DispatchAssignmentSnapshot{}, err
	}
	core, view := task.GetTask().GetActive().GetCore(), assignment.GetAssignment()
	if !bytes.Equal(core.GetTaskId(), taskID) || !bytes.Equal(view.GetTaskId(), taskID) {
		return DispatchAssignmentSnapshot{}, fmt.Errorf("Keeper task views of %x answered for another task", taskID)
	}
	out := DispatchAssignmentSnapshot{
		Height: height, TaskID: bytes.Clone(taskID), AcceptedTaskHash: bytes.Clone(core.GetAcceptedTaskHash()),
		GenerationParamsDigest: bytes.Clone(view.GetGenerationParamsDigest()), RecordHeight: view.GetRecordHeight(),
		InferDeadlineHeight: view.GetInferDeadlineHeight(), DispatchTicketHash: bytes.Clone(view.GetDispatchTicketHash()),
		WinnerWorker: view.GetWinnerWorker(), ReceiptAccepted: core.GetReceiptStatus() == taskv1.ReceiptStatus_RECEIPT_STATUS_RECEIPT_ACCEPTED,
	}
	if len(out.AcceptedTaskHash) != 32 || len(out.GenerationParamsDigest) != 32 || len(out.DispatchTicketHash) != 32 ||
		out.RecordHeight == 0 || out.InferDeadlineHeight <= out.RecordHeight || out.WinnerWorker == "" {
		return DispatchAssignmentSnapshot{}, fmt.Errorf("Keeper task %x is not a recorded dispatch", taskID)
	}
	return out, nil
}
