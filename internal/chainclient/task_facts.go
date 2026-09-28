package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// TaskReceiptFactsSnapshot carries the immutable Keeper commitments signed by
// InferReceiptV2. Absent and all-zero values remain distinct: IsSet reports
// presence, while consumers decide whether a present zero commitment is usable.
type TaskReceiptFactsSnapshot struct {
	AcceptedTaskHash             ProtoBytes32 `json:"accepted_task_hash,omitempty"`
	GenerationParamsDigest       ProtoBytes32 `json:"generation_params_digest,omitempty"`
	ProfileExecutionSnapshotHash ProtoBytes32 `json:"profile_execution_snapshot_hash,omitempty"`
}

// Validate requires every receipt commitment to contain exactly 32 bytes.
func (s TaskReceiptFactsSnapshot) Validate() error {
	for _, field := range []struct {
		name  string
		value ProtoBytes32
	}{
		{"accepted_task_hash", s.AcceptedTaskHash},
		{"generation_params_digest", s.GenerationParamsDigest},
		{"profile_execution_snapshot_hash", s.ProfileExecutionSnapshotHash},
	} {
		if len(field.value) == 0 {
			return fmt.Errorf("Keeper task %s is required", field.name)
		}
		if len(field.value) != 32 {
			return fmt.Errorf("Keeper task %s must contain exactly 32 bytes", field.name)
		}
	}
	return nil
}

// TaskReceiptFactsAnswer states which task the Keeper answered for, so adapters
// and injected readers cannot silently relabel another task's commitments.
type TaskReceiptFactsAnswer struct {
	TaskID string
	TaskReceiptFactsSnapshot
}

// TaskReceiptFacts reads the authoritative core and assignment commitments at
// one committed height using the wire QueryTask and QueryTaskAssignment.
func (c *KeeperABCIClient) TaskReceiptFacts(ctx context.Context, taskID string) (TaskReceiptFactsAnswer, error) {
	canonical, key, err := canonicalTaskKey(taskID)
	if err != nil {
		return TaskReceiptFactsAnswer{}, err
	}
	height, err := c.CommittedHeight(ctx)
	if err != nil {
		return TaskReceiptFactsAnswer{}, err
	}
	var task taskv1.QueryTaskResponse
	if err := c.query(ctx, taskQuery+"Task", height, &taskv1.QueryTaskRequest{TaskId: key}, &task); err != nil {
		return TaskReceiptFactsAnswer{}, fmt.Errorf("read Keeper task %s accepted_task_hash: %w", taskID, err)
	}
	core := task.GetTask().GetActive().GetCore()
	if core == nil {
		return TaskReceiptFactsAnswer{}, fmt.Errorf("Keeper task %s response carries no active bundle", taskID)
	}
	if !bytes.Equal(core.TaskId, key) {
		return TaskReceiptFactsAnswer{}, fmt.Errorf("Keeper task core identity does not match queried task %s", taskID)
	}

	var assignment taskv1.QueryTaskAssignmentResponse
	if err := c.query(ctx, taskQuery+"TaskAssignment", height, &taskv1.QueryTaskAssignmentRequest{TaskId: key}, &assignment); err != nil {
		return TaskReceiptFactsAnswer{}, fmt.Errorf("read Keeper task %s assignment commitments: %w", taskID, err)
	}
	view := assignment.GetAssignment()
	if !bytes.Equal(view.GetTaskId(), key) {
		return TaskReceiptFactsAnswer{}, fmt.Errorf("Keeper task assignment identity %x does not match queried task %s", view.GetTaskId(), taskID)
	}
	answer := TaskReceiptFactsAnswer{
		TaskID: canonical,
		TaskReceiptFactsSnapshot: TaskReceiptFactsSnapshot{
			AcceptedTaskHash:             ProtoBytes32(core.AcceptedTaskHash),
			GenerationParamsDigest:       ProtoBytes32(view.GenerationParamsDigest),
			ProfileExecutionSnapshotHash: ProtoBytes32(view.ProfileExecutionSnapshotHash),
		},
	}
	if err := answer.Validate(); err != nil {
		return TaskReceiptFactsAnswer{}, fmt.Errorf("Keeper task %s: %w", taskID, err)
	}
	return answer, nil
}

// canonicalTaskKey converts the lowercase Hash32 task key to protobuf bytes.
func canonicalTaskKey(taskID string) (string, []byte, error) {
	trimmed := strings.TrimSpace(taskID)
	if !isCanonicalSHA256Hex(trimmed) {
		return "", nil, fmt.Errorf("Keeper task id must be canonical lowercase 64-hex, got %q", taskID)
	}
	key, err := hex.DecodeString(trimmed)
	if err != nil {
		return "", nil, err
	}
	return trimmed, key, nil
}

func isCanonicalSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
