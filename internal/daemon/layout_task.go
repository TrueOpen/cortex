package daemon

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// inferTaskFromRecords materialises an execution DTO from the task and infer
// role records. The returned task is only as current as the supplied records.
//
// capability is supplied rather than stored. It is a local label the deployment
// config gives to a chain-committed (model_id, profile_version) pair, so two
// admissions of one task can legitimately disagree about it - which is why it must
// not live in a chain-immutable record field. Derive it at use, from the two fields
// the chain does commit.
func inferTaskFromRecords(task layout.TaskRecord, role layout.InferRecord, capability string) store.InferTask {
	return store.InferTask{
		TaskID:                 role.TaskID,
		SessionID:              task.SessionID,
		OrderSequence:          task.OrderSequence,
		AssignmentDigest:       codec.Hash(task.AssignmentDigest),
		OrderDigest:            codec.Hash(task.AssignmentOrderDigest),
		ModelID:                task.ModelID,
		ProfileVersion:         task.ProfileVersion,
		Capability:             capability,
		DeadlineHeight:         role.DeadlineHeight,
		InputCID:               task.InputCID,
		InputDigest:            codec.Hash(task.InputDigest),
		Stage:                  string(role.Stage),
		RetryCount:             role.RetryCount,
		RetryAtHeight:          role.RetryAtHeight,
		RetryAtUnixMilli:       role.RetryAtUnixMilli,
		LastError:              role.LastError,
		AutoHalted:             role.AutoHalted,
		HaltCode:               role.HaltCode,
		HaltReason:             role.HaltReason,
		OutputCID:              role.OutputCID,
		OutputDigest:           codec.Hash(role.OutputDigest),
		ReceiptCID:             role.ReceiptCID,
		ReceiptDigest:          codec.Hash(role.ReceiptDigest),
		WorkerAddress:          task.WorkerAddress,
		WinnerConfirmHeight:    role.WinnerConfirmHeight,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		InputSizeBytes:         task.InputSizeBytes,
		BuilderSetID:           task.TaskBuilderSetID,
		BuilderSetHash:         task.TaskBuilderSetHash,
	}
}

// inferRecordFromTask extracts the infer-role fields from an execution DTO.
// It merges executor outputs into an existing record so that stable fields
// (e.g. TaskID, WinnerConfirmHeight) are not lost.
func inferRecordFromTask(t store.InferTask, rec layout.InferRecord) layout.InferRecord {
	return layout.InferRecord{
		TaskID:                 t.TaskID,
		GenerationParamsDigest: layout.StoredHash(t.AssignmentDigest), // legacy mapping
		WinnerConfirmHeight:    t.WinnerConfirmHeight,
		InferDeadlineHeight:    rec.InferDeadlineHeight,
		FinishReason:           rec.FinishReason,
		Stage:                  layout.RoleStage(t.Stage),
		RetryCount:             t.RetryCount,
		RetryAtUnixMilli:       t.RetryAtUnixMilli,
		RetryAtHeight:          t.RetryAtHeight,
		DeadlineHeight:         t.DeadlineHeight,
		LastError:              t.LastError,
		// AutoHalt only ever travels record-ward as "set it": mergeAutoHalt
		// refuses to clear, and a checkpoint that happens to carry the zero value
		// must not look like a request to.
		AutoHalt:      layout.AutoHalt{AutoHalted: t.AutoHalted, HaltCode: t.HaltCode, HaltReason: t.HaltReason},
		OutputCID:     t.OutputCID,
		OutputDigest:  layout.StoredHash(t.OutputDigest),
		ReceiptCID:    t.ReceiptCID,
		ReceiptDigest: layout.StoredHash(t.ReceiptDigest),
	}
}

// verifyTaskFromRecords materialises an execution DTO from the task and verify
// role records. capability is supplied for the reason given on
// inferTaskFromRecords.
func verifyTaskFromRecords(task layout.TaskRecord, role layout.VerifyRecord, capability string) store.VerifyTask {
	return store.VerifyTask{
		TaskID:           role.TaskID,
		SessionID:        task.SessionID,
		OrderSequence:    task.OrderSequence,
		AssignmentDigest: codec.Hash(task.AssignmentDigest),
		// The same mapping inferTaskFromRecords makes, and for the same reason:
		// TaskRecord.AssignmentOrderDigest is the accepted order payload hash, and
		// it is the value verifier.validateCanonicalTaskState requires a verify
		// responsibility to carry. Leaving it unmapped made every restored verify
		// task refuse itself with L2_TASK_IDENTITY_MISSING before the frozen
		// commit or result body was ever assembled.
		OrderDigest:                codec.Hash(task.AssignmentOrderDigest),
		ModelID:                    task.ModelID,
		ProfileVersion:             task.ProfileVersion,
		Capability:                 capability,
		DeadlineHeight:             role.DeadlineHeight,
		Stage:                      string(role.Stage),
		RetryCount:                 role.RetryCount,
		RetryAtHeight:              role.RetryAtHeight,
		RetryAtUnixMilli:           role.RetryAtUnixMilli,
		LastError:                  role.LastError,
		AutoHalted:                 role.AutoHalted,
		HaltCode:                   role.HaltCode,
		HaltReason:                 role.HaltReason,
		ReceiptCID:                 role.ReceiptCID,
		ReceiptDigest:              codec.Hash(role.ReceiptDigest),
		WorkerAddress:              task.WorkerAddress,
		BuilderOperatorAddress:     task.BuilderOperatorAddress,
		VerifyRound:                role.VerifyRound,
		OpenVerifyHeight:           role.OpenVerifyHeight,
		CommitDeadlineHeight:       role.CommitDeadlineHeight,
		WorkerRevealDeadlineHeight: role.WorkerRevealDeadlineHeight,
		RevealDeadlineHeight:       role.RevealDeadlineHeight,
		VerificationSampleSeed:     codec.Hash(role.VerificationSampleSeed),
		AssignedVerifiers:          role.AssignedVerifiers,
		InferReceiptDigest:         codec.Hash(role.InferReceiptDigest),
		KeeperReceiptJSON:          []byte(role.KeeperReceiptJSON),
		OutputDigest:               codec.Hash(role.OutputDigest),
		PackageDigest:              codec.Hash(role.PackageDigest),
		BuilderSetID:               task.TaskBuilderSetID,
		BuilderSetHash:             task.TaskBuilderSetHash,
	}
}

// verifyRecordFromTask extracts the verify-role fields from an execution DTO,
// merging executor outputs into the supplied record.
func verifyRecordFromTask(t store.VerifyTask, rec layout.VerifyRecord) layout.VerifyRecord {
	return layout.VerifyRecord{
		TaskID:                     t.TaskID,
		VerifyRound:                rec.VerifyRound,
		KeeperReceiptJSON:          string(t.KeeperReceiptJSON),
		OpenVerifyHeight:           rec.OpenVerifyHeight,
		SampleSeedReadyHeight:      rec.SampleSeedReadyHeight,
		CommitDeadlineHeight:       rec.CommitDeadlineHeight,
		WorkerRevealDeadlineHeight: rec.WorkerRevealDeadlineHeight,
		RevealDeadlineHeight:       rec.RevealDeadlineHeight,
		VerificationSampleSeed:     rec.VerificationSampleSeed,
		AssignedVerifiers:          rec.AssignedVerifiers,
		InferReceiptDigest:         rec.InferReceiptDigest,
		OutputDigest:               rec.OutputDigest,
		PackageDigest:              rec.PackageDigest,
		Stage:                      layout.RoleStage(t.Stage),
		RetryCount:                 t.RetryCount,
		RetryAtUnixMilli:           t.RetryAtUnixMilli,
		RetryAtHeight:              t.RetryAtHeight,
		DeadlineHeight:             t.DeadlineHeight,
		LastError:                  t.LastError,
		// See inferRecordFromTask.
		AutoHalt:      layout.AutoHalt{AutoHalted: t.AutoHalted, HaltCode: t.HaltCode, HaltReason: t.HaltReason},
		ReceiptCID:    t.ReceiptCID,
		ReceiptDigest: layout.StoredHash(t.ReceiptDigest),
	}
}
