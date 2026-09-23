package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// seedInferTask writes a TaskRecord and InferRecord into the store so that
// RunOnce sees the task via the new layout. Missing fields are zero-valued;
// callers should override what the test cares about.
func seedInferTask(ctx context.Context, t *testing.T, s *store.Store, h codec.Hash, task store.InferTask) {
	t.Helper()
	orderDigest := task.OrderDigest
	if orderDigest == (codec.Hash{}) {
		orderDigest = task.AssignmentDigest
	}
	inputDigest := task.InputDigest
	if inputDigest == (codec.Hash{}) {
		inputDigest = codec.HashBytes([]byte(task.TaskID + ":input"))
	}
	tr := layout.TaskRecord{
		SessionID:              task.SessionID,
		OrderSequence:          task.OrderSequence,
		ModelID:                task.ModelID,
		ProfileVersion:         task.ProfileVersion,
		AssignmentOrderDigest:  layout.StoredHash(orderDigest),
		AssignmentDigest:       layout.StoredHash(task.AssignmentDigest),
		AcceptedInputHash:      layout.StoredHash(inputDigest),
		WorkerAddress:          task.WorkerAddress,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		TaskBuilderSetID:       task.BuilderSetID,
		TaskBuilderSetHash:     task.BuilderSetHash,
		InputSizeBytes:         task.InputSizeBytes,
		InputCID:               task.InputCID,
		InputDigest:            layout.StoredHash(inputDigest),
	}
	stage := layout.RoleStage(task.Stage)
	if stage == "" {
		stage = layout.StageQueued
	}
	rec := layout.InferRecord{
		TaskID:              task.TaskID,
		WinnerConfirmHeight: task.WinnerConfirmHeight,
		InferDeadlineHeight: task.DeadlineHeight,
		Stage:               stage,
		RetryCount:          task.RetryCount,
		RetryAtUnixMilli:    task.RetryAtUnixMilli,
		RetryAtHeight:       task.RetryAtHeight,
		DeadlineHeight:      task.DeadlineHeight,
		LastError:           task.LastError,
		OutputCID:           task.OutputCID,
		OutputDigest:        layout.StoredHash(task.OutputDigest),
		ReceiptCID:          task.ReceiptCID,
		ReceiptDigest:       layout.StoredHash(task.ReceiptDigest),
	}
	if err := layout.MergeTask(ctx, s, layout.StoredHash(h), tr); err != nil {
		t.Fatal(err)
	}
	if err := layout.MergeInfer(ctx, s, layout.StoredHash(h), rec); err != nil {
		t.Fatal(err)
	}
}

// seedVerifyTask writes a TaskRecord and VerifyRecord into the store so that
// RunOnce sees the task via the new layout.
func seedVerifyTask(ctx context.Context, t *testing.T, s *store.Store, h codec.Hash, task store.VerifyTask) {
	t.Helper()
	orderDigest := task.OrderDigest
	if orderDigest == (codec.Hash{}) {
		orderDigest = task.AssignmentDigest
	}
	tr := layout.TaskRecord{
		SessionID:              task.SessionID,
		OrderSequence:          task.OrderSequence,
		ModelID:                task.ModelID,
		ProfileVersion:         task.ProfileVersion,
		AssignmentOrderDigest:  layout.StoredHash(orderDigest),
		AssignmentDigest:       layout.StoredHash(task.AssignmentDigest),
		AcceptedInputHash:      layout.StoredHash(orderDigest),
		WorkerAddress:          task.WorkerAddress,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		TaskBuilderSetID:       task.BuilderSetID,
		TaskBuilderSetHash:     task.BuilderSetHash,
	}
	stage := layout.RoleStage(task.Stage)
	if stage == "" {
		stage = layout.StageQueued
	}
	rec := layout.VerifyRecord{
		TaskID:                     task.TaskID,
		VerifyRound:                task.VerifyRound,
		OpenVerifyHeight:           task.OpenVerifyHeight,
		SampleSeedReadyHeight:      task.CurrentHeight,
		CommitDeadlineHeight:       task.CommitDeadlineHeight,
		WorkerRevealDeadlineHeight: task.WorkerRevealDeadlineHeight,
		RevealDeadlineHeight:       task.RevealDeadlineHeight,
		VerificationSampleSeed:     layout.StoredHash(task.VerificationSampleSeed),
		AssignedVerifiers:          task.AssignedVerifiers,
		InferReceiptDigest:         layout.StoredHash(task.InferReceiptDigest),
		OutputDigest:               layout.StoredHash(task.OutputDigest),
		PackageDigest:              layout.StoredHash(task.PackageDigest),
		Stage:                      stage,
		RetryCount:                 task.RetryCount,
		RetryAtUnixMilli:           task.RetryAtUnixMilli,
		RetryAtHeight:              task.RetryAtHeight,
		DeadlineHeight:             task.DeadlineHeight,
		LastError:                  task.LastError,
		ReceiptCID:                 task.ReceiptCID,
		ReceiptDigest:              layout.StoredHash(task.ReceiptDigest),
	}
	if err := layout.MergeTask(ctx, s, layout.StoredHash(h), tr); err != nil {
		t.Fatal(err)
	}
	if err := layout.MergeVerify(ctx, s, layout.StoredHash(h), rec); err != nil {
		t.Fatal(err)
	}
}
