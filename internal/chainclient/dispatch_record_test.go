package chainclient

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cosmos/gogoproto/proto"
	gproto "google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestDispatchRecordReadsTheWinnerByOrder(t *testing.T) {
	sid, tid := bytes.Repeat([]byte{0x5c}, 32), bytes.Repeat([]byte{0x03}, 32)
	ticket, record := bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x77}, 32)
	state := &taskv1.DispatchRecordState{
		TaskId: tid, DispatchRecordHash: record, DispatchTicketHash: ticket, BuilderAddress: "trueopen1builder",
		Winner: &taskv1.CandidateMemberRefV1{OperatorAddress: "trueopen1worker"}, WinnerRound: 1, RecordedHeight: 120, ClaimWindowCloseHeight: 400,
	}
	answer := func(s *taskv1.DispatchRecordState) *KeeperABCIClient {
		server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
			if path != taskQuery+"DispatchRecord" || height != "900" {
				t.Errorf("ABCI %s at %s", path, height)
			}
			var req taskv1.QueryDispatchRecordRequest
			if err := unmarshalTestProto(data, &req); err != nil {
				t.Error(err)
			}
			if !bytes.Equal(req.GetByOrder().GetSessionId(), sid) || req.GetByOrder().GetOrderSequence() != 7 {
				t.Errorf("selector = %v", req.GetSelector())
			}
			if s == nil {
				return nil, 5, "rpc error: code = NotFound desc = no record"
			}
			return &taskv1.QueryDispatchRecordResponse{Record: s}, 0, ""
		})
		t.Cleanup(server.Close)
		return NewKeeperABCIClient(server.URL)
	}
	got, err := answer(state).DispatchRecord(context.Background(), sid, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.TaskID, tid) || !bytes.Equal(got.TicketHash, ticket) || !bytes.Equal(got.RecordHash, record) ||
		got.Builder != "trueopen1builder" || got.Winner != "trueopen1worker" || got.RecordedHeight != 120 || got.Height != 900 ||
		got.WinnerRound != 1 || got.ClaimWindowCloseHeight != 400 {
		t.Fatalf("snapshot = %+v", got)
	}
	if _, err := answer(nil).DispatchRecord(context.Background(), sid, 7); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no record: err = %v", err)
	}
	bad := gproto.Clone(state).(*taskv1.DispatchRecordState)
	bad.Winner = nil
	if _, err := answer(bad).DispatchRecord(context.Background(), sid, 7); err == nil {
		t.Fatal("a record without a winner is refused")
	}
	future := gproto.Clone(state).(*taskv1.DispatchRecordState)
	future.RecordedHeight = 901
	if _, err := answer(future).DispatchRecord(context.Background(), sid, 7); err == nil {
		t.Fatal("a record above the committed height it was read at is refused")
	}
	if _, err := answer(state).DispatchRecord(context.Background(), []byte{1}, 7); err == nil {
		t.Fatal("a session_id that is not 32 bytes is refused before any query")
	}
}

func TestDispatchAssignmentReadsTheRecordedTask(t *testing.T) {
	tid := bytes.Repeat([]byte{0x03}, 32)
	hash, digest, ticket := bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x42}, 32)
	deadline, winner := uint64(150), "trueopen1worker"
	view := &taskv1.TaskAssignmentViewV1{TaskId: tid, GenerationParamsDigest: digest, RecordHeight: 120,
		InferDeadlineHeight: &deadline, DispatchTicketHash: ticket, WinnerWorker: &winner}
	core := &taskv1.TaskCoreState{TaskId: tid, AcceptedTaskHash: hash, ReceiptStatus: taskv1.ReceiptStatus_RECEIPT_STATUS_RECEIPT_ACCEPTED}
	serve := func(v *taskv1.TaskAssignmentViewV1) *KeeperABCIClient {
		server := newABCITestServer(t, func(path, height string, _ []byte) (proto.Message, uint32, string) {
			if height != "900" {
				t.Errorf("height = %s", height)
			}
			switch path {
			case taskQuery + "Task":
				return &taskv1.QueryTaskResponse{Task: &taskv1.TaskViewV1{Value: &taskv1.TaskViewV1_Active{Active: &taskv1.TaskActiveBundleV1{Core: core}}}}, 0, ""
			case taskQuery + "TaskAssignment":
				return &taskv1.QueryTaskAssignmentResponse{Assignment: v}, 0, ""
			}
			t.Errorf("ABCI path = %q", path)
			return nil, 0, ""
		})
		t.Cleanup(server.Close)
		return NewKeeperABCIClient(server.URL)
	}
	got, err := serve(view).DispatchAssignment(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.AcceptedTaskHash, hash) || !bytes.Equal(got.GenerationParamsDigest, digest) || !bytes.Equal(got.DispatchTicketHash, ticket) ||
		got.RecordHeight != 120 || got.InferDeadlineHeight != 150 || got.WinnerWorker != winner || !got.ReceiptAccepted || got.Height != 900 {
		t.Fatalf("snapshot = %+v", got)
	}
	early := gproto.Clone(view).(*taskv1.TaskAssignmentViewV1)
	early.InferDeadlineHeight = nil
	if _, err := serve(early).DispatchAssignment(context.Background(), tid); err == nil {
		t.Fatal("a task without infer_deadline_height is not a recorded dispatch")
	}
	stale := gproto.Clone(view).(*taskv1.TaskAssignmentViewV1)
	at := uint64(120)
	stale.InferDeadlineHeight = &at
	if _, err := serve(stale).DispatchAssignment(context.Background(), tid); err == nil {
		t.Fatal("infer_deadline_height must lie after record_height (record_height + timeout bucket)")
	}
	if _, err := serve(view).DispatchAssignment(context.Background(), []byte{3}); err == nil {
		t.Fatal("a task_id that is not 32 bytes is refused before any query")
	}
}
