package layout

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
)

func autoHaltStore(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return ctx, s
}

// The failure mode this closes: a Keeper assignment event that arrives twice --
// which is normal, the poller replays a block after a restart -- is merged with
// Stage StageQueued and a zero AutoHalt. Under last-writer-wins that merge
// silently cleared the halt and handed the task straight back to the model,
// which is the loop the halt exists to stop.
func TestReplayedAssignmentDoesNotClearAnAutoHalt(t *testing.T) {
	ctx, s := autoHaltStore(t)
	hash := StoredHash{1}

	if err := InferAssignmentBatch(ctx, s, hash,
		TaskRecord{SessionID: "session-1", ModelID: "model-a", ProfileVersion: 1},
		InferRecord{TaskID: "task-1", Stage: StageQueued, InferDeadlineHeight: 900, DeadlineHeight: 900}); err != nil {
		t.Fatalf("InferAssignmentBatch returned error: %v", err)
	}
	if err := MergeInfer(ctx, s, hash, InferRecord{
		TaskID: "task-1", Stage: StageFailed,
		AutoHalt: AutoHalt{AutoHalted: true, HaltCode: "GENERATION_TOKEN_BUDGET_EXCEEDED", HaltReason: "the model outgrew the order"},
	}); err != nil {
		t.Fatalf("MergeInfer returned error: %v", err)
	}

	// The same assignment again, exactly as the reconciler would replay it.
	if err := InferAssignmentBatch(ctx, s, hash,
		TaskRecord{SessionID: "session-1", ModelID: "model-a", ProfileVersion: 1},
		InferRecord{TaskID: "task-1", Stage: StageQueued, InferDeadlineHeight: 900, DeadlineHeight: 900}); err != nil {
		t.Fatalf("replayed InferAssignmentBatch returned error: %v", err)
	}

	record, err := GetInferRecord(ctx, s, hash)
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if !record.AutoHalted {
		t.Fatalf("a replayed assignment cleared the auto-halt; record = %#v", record)
	}
	if record.HaltCode != "GENERATION_TOKEN_BUDGET_EXCEEDED" || record.HaltReason == "" {
		t.Fatalf("the halt lost its code or reason: %#v", record)
	}
	// The replay is still allowed to move the stage; the halt is what the guard
	// in RunOnce then reads, which is why both are checked here.
	if record.Stage != StageQueued {
		t.Fatalf("stage = %q, want the replayed assignment's own stage", record.Stage)
	}
}

// Clearing is an operator act on its own path, and it is the only thing that
// clears. A merge carrying the zero value must not.
func TestOnlyTheExplicitClearReleasesAnAutoHalt(t *testing.T) {
	ctx, s := autoHaltStore(t)
	hash := StoredHash{2}

	if err := MergeInfer(ctx, s, hash, InferRecord{
		TaskID:   "task-2",
		Stage:    StageFailed,
		AutoHalt: AutoHalt{AutoHalted: true, HaltCode: "OUTPUT_FRAMES_ALREADY_SIGNED", HaltReason: "signed frames exist"},
	}); err != nil {
		t.Fatalf("MergeInfer returned error: %v", err)
	}
	if err := MergeInfer(ctx, s, hash, InferRecord{TaskID: "task-2", Stage: StageQueued}); err != nil {
		t.Fatalf("MergeInfer returned error: %v", err)
	}
	record, err := GetInferRecord(ctx, s, hash)
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if !record.AutoHalted {
		t.Fatalf("a zero-valued merge cleared the halt: %#v", record)
	}

	if err := ClearInferAutoHalt(ctx, s, hash); err != nil {
		t.Fatalf("ClearInferAutoHalt returned error: %v", err)
	}
	record, err = GetInferRecord(ctx, s, hash)
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if record.AutoHalted || record.HaltCode != "" || record.HaltReason != "" {
		t.Fatalf("the explicit clear left halt state behind: %#v", record)
	}
	if record.TaskID != "task-2" {
		t.Fatalf("the clear rewrote more than the halt: %#v", record)
	}
}

// The same rule on the verify record, because a Verifier holds the second
// half of a task's model work and a VerifyAssignmentBatch replays the same way.
func TestVerifyAutoHaltIsStickyAndClearable(t *testing.T) {
	ctx, s := autoHaltStore(t)
	hash := StoredHash{3}

	if err := MergeVerify(ctx, s, hash, VerifyRecord{
		TaskID: "task-3", VerifyRound: 1, Stage: StageFailed,
		AutoHalt: AutoHalt{AutoHalted: true, HaltCode: "GENERATION_CHECKPOINT_MISMATCH", HaltReason: "checkpoint contradicts trace"},
	}); err != nil {
		t.Fatalf("MergeVerify returned error: %v", err)
	}
	if err := MergeVerify(ctx, s, hash, VerifyRecord{TaskID: "task-3", VerifyRound: 1, Stage: StageQueued}); err != nil {
		t.Fatalf("MergeVerify returned error: %v", err)
	}
	record, err := GetVerifyRecord(ctx, s, hash)
	if err != nil {
		t.Fatalf("GetVerifyRecord returned error: %v", err)
	}
	if !record.AutoHalted {
		t.Fatalf("a zero-valued merge cleared the verify halt: %#v", record)
	}
	if err := ClearVerifyAutoHalt(ctx, s, hash); err != nil {
		t.Fatalf("ClearVerifyAutoHalt returned error: %v", err)
	}
	if record, err = GetVerifyRecord(ctx, s, hash); err != nil || record.AutoHalted {
		t.Fatalf("verify halt survived the explicit clear: %#v, %v", record, err)
	}
}

// The old-record read strategy, asserted rather than asserted-in-a-comment: the
// three fields are absent from every record written before this landed, and
// absent must decode to "not halted" so an upgrade changes no behaviour. Nothing
// migrates.
func TestRecordsWrittenBeforeTheHaltFieldsExistedDecodeAsNotHalted(t *testing.T) {
	const legacyInfer = `{"schema_version":1,"task_id":"task-legacy","stage":"queued","retry_count":3,"last_error":"transient"}`
	var infer InferRecord
	if err := json.Unmarshal([]byte(legacyInfer), &infer); err != nil {
		t.Fatalf("decoding a pre-upgrade infer record returned error: %v", err)
	}
	if infer.AutoHalted || infer.HaltCode != "" || infer.HaltReason != "" {
		t.Fatalf("a pre-upgrade infer record decoded as halted: %#v", infer)
	}
	if infer.TaskID != "task-legacy" || infer.RetryCount != 3 || infer.Stage != StageQueued {
		t.Fatalf("a pre-upgrade infer record lost a field it did carry: %#v", infer)
	}

	const legacyVerify = `{"schema_version":1,"task_id":"task-legacy","verify_round":1,"stage":"committed"}`
	var verify VerifyRecord
	if err := json.Unmarshal([]byte(legacyVerify), &verify); err != nil {
		t.Fatalf("decoding a pre-upgrade verify record returned error: %v", err)
	}
	if verify.AutoHalted || verify.Stage != StageCommitted {
		t.Fatalf("a pre-upgrade verify record decoded wrongly: %#v", verify)
	}

	// And the forward direction: a record that is not halted must not start
	// writing the three keys, so a downgrade reads exactly what it wrote.
	encoded, err := json.Marshal(InferRecord{TaskID: "task-plain", Stage: StageQueued})
	if err != nil {
		t.Fatalf("marshal returned error: %v", err)
	}
	for _, key := range []string{"auto_halted", "halt_code", "halt_reason"} {
		if strings.Contains(string(encoded), key) {
			t.Fatalf("an unhalted record wrote %s: %s", key, encoded)
		}
	}
}
