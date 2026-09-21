package chainclient

import "testing"

// TaskSnapshot.Validate must not read order_sequence 0 as a missing field.
//
// Keeper creates a session's StreamState without assigning
// NextExpectedSequence, so the first order of every session is sequence 0 and
// the Keeper answers Query/Task with exactly that. Treating it as incomplete
// authority fails the read the Worker leg depends on - which would have turned
// the bus-side refusal into a chain-side one the moment the bus stopped
// refusing.
//
// A sequence carries no completeness signal of its own: what makes the
// assignment identifiable is task_id, and task_id already commits to the
// sequence through H_FIELDS_V1(TRUEOPEN_TASK_ID_V1, session_id, order_sequence).
func TestTaskSnapshotValidateAcceptsSessionFirstOrderSequenceZero(t *testing.T) {
	current := TaskSnapshot{
		Status:          "ASSIGNED",
		CurrentContract: true,
		Assignment: AssignmentSnapshot{
			SessionID:                "session-1",
			TaskID:                   "task-1",
			OrderSequence:            NewUint64String(0),
			SelectedWorker:           "trueopen1node",
			InferDeadlineHeight:      NewUint64String(120),
			ModelID:                  "model-1",
			ProfileVersion:           NewProfileVersion(1),
			AcceptedOrderPayloadHash: HexHash{2},
			TaskReceiptFactsSnapshot: TaskReceiptFactsSnapshot{AcceptedTaskHash: ProtoBytes32(make([]byte, 32))},
		},
	}
	if err := current.Validate(); err != nil {
		t.Fatalf("TaskSnapshot.Validate() error = %v, want the session's first order accepted", err)
	}

	terminal := current
	terminal.Status = "TERMINAL"
	terminal.Settlement = SettlementSnapshot{TaskVerdict: "PASS"}
	if err := terminal.Validate(); err != nil {
		t.Fatalf("terminal TaskSnapshot.Validate() error = %v, want the session's first order accepted", err)
	}

	// The completeness checks the sequence sat beside must still hold.
	incomplete := current
	incomplete.Assignment.TaskID = ""
	if err := incomplete.Validate(); err == nil {
		t.Fatal("TaskSnapshot.Validate() error = nil, want incomplete authority without a task_id")
	}
}
