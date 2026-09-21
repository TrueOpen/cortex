package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store"
	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
)

// The two chain facts this notify path has to keep apart, with the values the
// devnet actually carried for task e1795ec8…: accepted_task_hash is the store
// key and the frame's task_hash, accepted_input_hash is what
// TaskRecord.AssignmentOrderDigest holds.
const (
	notifyAcceptedTaskHashHex  = "4f37cad771d3dbe04a85ee0b709c53537a6f8978da39a30797de057db800ee1e"
	notifyAcceptedInputHashHex = "848e23cda8c1ac64128e2dca7e5f50c2fec3f468b0203a075e894560b5fd83ee"
	notifyTaskIDHex            = "e1795ec8b243a142af40564dd6ad66dd4d88f9cc1e3ed52907254a2ee057370c"
	notifyWinner               = "trueopen127sthpcvplyvumztjcn036utdwnqx22y8ywtlr"
	notifyConfirmHeight        = uint64(12601)
)

func mustHash32Bytes(t *testing.T, value string) []byte {
	t.Helper()
	hash := mustHash32(t, value)
	return hash[:]
}

func mustHash32(t *testing.T, value string) codec.Hash {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("decode %q: %v (%d bytes)", value, err, len(raw))
	}
	var hash codec.Hash
	copy(hash[:], raw)
	return hash
}

// seedAssignedInferTask puts the winner in the state the Keeper poller leaves
// it in: the store keyed by accepted_task_hash, with AssignmentOrderDigest
// carrying accepted_input_hash exactly as ApplyReconcilerEffects writes it.
func seedAssignedInferTask(t *testing.T, ctx context.Context, r *TaskRunner) codec.Hash {
	t.Helper()
	taskHash := mustHash32(t, notifyAcceptedTaskHashHex)
	snapshot := chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
		TaskID: notifyTaskIDHex, SessionID: "session-1", OrderSequence: chainclient.NewUint64String(0),
		SelectedWorker: notifyWinner, ModelID: "model-1", ProfileVersion: chainclient.NewProfileVersion(1),
		WinnerConfirmHeight:      chainclient.NewUint64String(notifyConfirmHeight),
		InferDeadlineHeight:      chainclient.NewUint64String(112601),
		AcceptedOrderPayloadHash: chainclient.HexHash(mustHash32(t, notifyAcceptedInputHashHex)),
	}}
	effect := ReconcilerEffect{
		Type: ReconcilerEffectAssignment, TaskHash: taskHash, TaskID: notifyTaskIDHex, Snapshot: snapshot,
	}
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{effect}); err != nil {
		t.Fatalf("ApplyReconcilerEffects returned error: %v", err)
	}
	return taskHash
}

func assignNotifyEnvelope() builderclient.BusEnvelope {
	return builderclient.BusEnvelope{
		Subject: builderclient.NATSWorkerAssignmentSubject(notifyTaskIDHex),
		Kind:    builderclient.KindWorkerAssignmentNotify,
	}
}

func assignNotifyTaskID(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(notifyTaskIDHex)
	if err != nil {
		t.Fatalf("decode task id: %v", err)
	}
	return raw
}

// WORKER_ASSIGNMENT_NOTIFY carries task_hash, the §5.2 authorization object
// H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V1", TaskOrderV1) - the Keeper's
// accepted_task_hash. The record's AssignmentOrderDigest is a DIFFERENT chain
// field, accepted_input_hash. Comparing the frame against that one refused
// every notify the winner ever received, deterministically, because
// nodewire.TestAcceptedTaskHashDiffersFromAssignmentOrderDigest pins that the
// two values can never be equal. The constants here are the real devnet values
// for task e1795ec8…, so this test fails if the comparison moves back.
func TestWinnerAcceptsAssignmentNotifyBoundToTheAcceptedTaskHash(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	r := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: notifyWinner})
	taskHash := seedAssignedInferTask(t, ctx, r)

	message := &busv1.WorkerAssignmentNotifyV1{
		TaskId:                assignNotifyTaskID(t),
		TaskHash:              taskHash[:],
		WinnerOperatorAddress: notifyWinner,
		FinalizedHeight:       notifyConfirmHeight,
	}
	if err := r.recordAssignNotify(ctx, assignNotifyEnvelope(), message); err != nil {
		t.Fatalf("recordAssignNotify with the accepted task hash returned error: %v", err)
	}

	// The old comparison target must still be refused: it is a real 32-byte
	// chain value, so this is the case that used to pass validation and fail.
	inputHash := mustHash32(t, notifyAcceptedInputHashHex)
	if bytes.Equal(taskHash[:], inputHash[:]) {
		t.Fatal("fixture broken: accepted_task_hash equals accepted_input_hash")
	}
	message.TaskHash = inputHash[:]
	err = r.recordAssignNotify(ctx, assignNotifyEnvelope(), message)
	if err == nil || !strings.Contains(err.Error(), "task_hash does not match the accepted task hash") {
		t.Fatalf("recordAssignNotify with accepted_input_hash error = %v, want a task_hash refusal", err)
	}
}

// Losing the assignment is a normal terminal state, not a failure: the frame is
// addressed to the losing workers by design, and the Keeper path skips the same
// fact silently (task_runner_run.go:221). Reporting an error here also arms
// JetStream redelivery, and the inbox dedup key changes with each message_id,
// so the failure log never stops.
func TestLosingTheAssignmentIsNotAFailure(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// No local record at all - the losing node never admitted this task.
	r := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: "trueopen1loser"})
	message := &busv1.WorkerAssignmentNotifyV1{
		TaskId:                assignNotifyTaskID(t),
		TaskHash:              mustHash32Bytes(t, notifyAcceptedTaskHashHex),
		WinnerOperatorAddress: notifyWinner,
		FinalizedHeight:       notifyConfirmHeight,
	}
	if err := r.recordAssignNotify(ctx, assignNotifyEnvelope(), message); err != nil {
		t.Fatalf("recordAssignNotify for a lost assignment returned error = %v, want a silent ack", err)
	}
}

// The message the losing node used to log said "missing or conflicting required
// fields" while the only condition it tested was the winner address. A frame
// that really is missing a required field has to be the thing that says so.
func TestAssignmentNotifyNamesTheFieldItRefuses(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: notifyWinner})

	for name, testCase := range map[string]struct {
		message *busv1.WorkerAssignmentNotifyV1
		want    string
	}{
		"no winner": {
			message: &busv1.WorkerAssignmentNotifyV1{
				TaskId:   assignNotifyTaskID(t),
				TaskHash: mustHash32Bytes(t, notifyAcceptedTaskHashHex),
			},
			want: "winner_operator_address is required",
		},
		"short task hash": {
			message: &busv1.WorkerAssignmentNotifyV1{
				TaskId:                assignNotifyTaskID(t),
				TaskHash:              []byte{1, 2, 3},
				WinnerOperatorAddress: notifyWinner,
			},
			want: "task_hash must be 32 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := r.recordAssignNotify(ctx, assignNotifyEnvelope(), testCase.message)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("recordAssignNotify error = %v, want it to name %q", err, testCase.want)
			}
		})
	}
}
