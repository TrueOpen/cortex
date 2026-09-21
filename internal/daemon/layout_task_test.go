package daemon

import (
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store/layout"
)

func TestInferTaskRoundTrip(t *testing.T) {
	task := layout.TaskRecord{
		SessionID:              "session-1",
		OrderSequence:          7,
		ModelID:                "model-a",
		ProfileVersion:         1,
		AssignmentOrderDigest:  layout.StoredHash{1},
		AssignmentDigest:       layout.StoredHash{2},
		WorkerAddress:          "worker-1",
		BuilderOperatorAddress: "builder-1",
	}
	rec := layout.InferRecord{
		TaskID:              "task-1",
		WinnerConfirmHeight: 10,
		InferDeadlineHeight: 20,
		FinishReason:        layout.FinishReasonEOS,
		Stage:               layout.StageQueued,
		RetryCount:          3,
		RetryAtUnixMilli:    1234,
		RetryAtHeight:       5,
		DeadlineHeight:      30,
		LastError:           "boom",
		OutputCID:           "cid://output",
		OutputDigest:        layout.StoredHash{3},
		ReceiptCID:          "cid://receipt",
		ReceiptDigest:       layout.StoredHash{4},
	}
	dto := inferTaskFromRecords(task, rec, "llm_text_v1")
	if dto.TaskID != rec.TaskID || dto.SessionID != task.SessionID || dto.OrderSequence != task.OrderSequence {
		t.Fatalf("basic fields mismatch: %#v", dto)
	}
	if dto.AssignmentDigest != codec.Hash(task.AssignmentDigest) || dto.OrderDigest != codec.Hash(task.AssignmentOrderDigest) {
		t.Fatalf("digest mismatch: %#v", dto)
	}
	updated := inferRecordFromTask(dto, rec)
	if updated.OutputCID != dto.OutputCID {
		t.Fatalf("record from task mismatch: %#v", updated)
	}
}

func TestVerifyTaskRoundTrip(t *testing.T) {
	task := layout.TaskRecord{
		SessionID:              "session-2",
		OrderSequence:          8,
		ModelID:                "model-b",
		ProfileVersion:         2,
		AssignmentOrderDigest:  layout.StoredHash{5},
		AssignmentDigest:       layout.StoredHash{6},
		WorkerAddress:          "worker-2",
		BuilderOperatorAddress: "builder-2",
		TaskBuilderSetID:       "bsid",
		TaskBuilderSetHash:     []byte("hash"),
	}
	rec := layout.VerifyRecord{
		TaskID:                     "task-2",
		VerifyRound:                1,
		OpenVerifyHeight:           11,
		SampleSeedReadyHeight:      12,
		CommitDeadlineHeight:       13,
		WorkerRevealDeadlineHeight: 14,
		RevealDeadlineHeight:       15,
		VerificationSampleSeed:     layout.StoredHash{7},
		AssignedVerifiers:          []string{"v1"},
		InferReceiptDigest:         layout.StoredHash{8},
		KeeperReceiptJSON:          "{}",
		OutputCID:                  "cid://out",
		OutputDigest:               layout.StoredHash{9},
		PackageDigest:              layout.StoredHash{10},
		Stage:                      layout.StageQueued,
		RetryCount:                 1,
		RetryAtUnixMilli:           5678,
		RetryAtHeight:              6,
		DeadlineHeight:             40,
		LastError:                  "oops",
		ReceiptCID:                 "cid://receipt2",
		ReceiptDigest:              layout.StoredHash{11},
	}
	dto := verifyTaskFromRecords(task, rec, "llm_text_v1")
	if dto.TaskID != rec.TaskID || dto.SessionID != task.SessionID || string(dto.KeeperReceiptJSON) != "{}" {
		t.Fatalf("basic fields mismatch: %#v", dto)
	}
	updated := verifyRecordFromTask(dto, rec)
	if updated.KeeperReceiptJSON != string(dto.KeeperReceiptJSON) {
		t.Fatalf("keeper receipt mismatch: got %q", updated.KeeperReceiptJSON)
	}
}

func TestStageFromRoleString(t *testing.T) {
	if inferTaskFromRecords(layout.TaskRecord{}, layout.InferRecord{Stage: layout.StageSucceeded}, "").Stage != "succeeded" {
		t.Fatal("stage mapping failed")
	}
}
