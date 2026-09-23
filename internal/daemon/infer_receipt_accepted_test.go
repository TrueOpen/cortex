package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/worker"
)

// TestInferReceiptAcceptedKeepsTheInferResponsibility covers the race that cost
// a devnet Worker its OUTPUT_AVAILABLE message on a round it had otherwise
// completed.
//
// The chain accepts the infer receipt about a second before the Worker finishes
// uploading the output, so EventInferReceiptAccepted lands while the executor
// is still inside ensureOutputAvailable. When that event mapped to
// ReconcilerEffectInferTerminal, the infer record was deleted underneath the
// running step, the next checkpoint returned store.ErrNotFound, and the step
// returned before publishing OUTPUT_AVAILABLE -- with no retry left, since the
// deleted record was also the only carrier of the restart obligation.
//
// The event is now a projection: it emits no effect, is not quarantined, and
// leaves the local record alone.
func TestInferReceiptAcceptedKeepsTheInferResponsibility(t *testing.T) {
	ctx := context.Background()
	taskHash := codec.HashWithDomain("TEST_ACCEPTED", []byte("task-receipt-accepted"))
	snapshot := validTaskSnapshot("session-1", "task-receipt-accepted", taskHash)
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{snapshot: snapshot},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
	})
	// Known is what a real decoded chain event carries, and it is the flag that
	// sends the event through the disposition table. Without it this test would
	// pass even if the projection were missing there.
	effects, err := r.Apply(ctx, []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventInferReceiptAccepted, Known: true,
		TaskID: "task-receipt-accepted", SessionID: "session-1", OrderDigest: taskHash, Height: 20,
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none: accepting the receipt releases no responsibility", effects)
	}
	if len(quarantined) != 0 {
		t.Fatalf("quarantined = %#v, want none: the event has an explicit projection disposition", quarantined)
	}

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	task := store.InferTask{TaskID: "task-receipt-accepted", SessionID: "session-1", Stage: "queued"}
	seedInferTask(ctx, t, db, taskHash, task)
	runner := NewTaskRunner(TaskRunnerConfig{Store: db})
	if err := runner.ApplyReconcilerEffects(ctx, effects); err != nil {
		t.Fatalf("ApplyReconcilerEffects() error = %v", err)
	}
	rec, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("infer record missing after the receipt was accepted on chain: %v", err)
	}
	if rec.TaskID != task.TaskID {
		t.Fatalf("infer record = %#v, want the responsibility for %s intact", rec, task.TaskID)
	}
}

// TestOrphanedInferCheckpointIsNotAFailure pins the second half of the same
// fix, for the terminal events that legitimately do delete the record
// (WorkerTimeout, and the task-terminal batch).
//
// CheckpointStorageConfirmation is the exact call that failed on devnet, and it
// sits between the output upload and the OUTPUT_AVAILABLE publication inside
// ensureOutputAvailable. Its bytes are already durable in the evidence store
// before any merge is attempted, so a missing merge target means "nobody will
// read this again", not "the round failed" -- and reporting it aborted the rest
// of the step.
func TestOrphanedInferCheckpointIsNotAFailure(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	evidenceStore, err := evidence.NewStore(t.TempDir(), db)
	if err != nil {
		t.Fatal(err)
	}
	taskHash := codec.HashBytes([]byte("orphaned-checkpoint"))
	task := store.InferTask{TaskID: "task-orphan", SessionID: "session-orphan", Stage: "queued"}
	seedInferTask(ctx, t, db, taskHash, task)
	runner := NewTaskRunner(TaskRunnerConfig{Store: db})
	persistence := &evidenceWorkerPersistence{
		taskHash: taskHash, task: &task, evidence: evidenceStore, store: db,
		persist: runner.persistInferCheckpoint,
	}
	confirmation := worker.StorageConfirmationCheckpoint{
		TaskID: task.TaskID, DataKind: "OUTPUT", BuilderOperator: "trueopen1builder",
		MaterialDigest: "abcd", SemanticHash: "ef01", SizeBytes: 7,
		RetentionUntilHeight: 500, Signature: []byte("signature"),
		VerifiedAt: time.Unix(1, 0).UTC(),
	}
	if err := persistence.CheckpointStorageConfirmation(ctx, confirmation); err != nil {
		t.Fatalf("CheckpointStorageConfirmation() with the record present error = %v", err)
	}

	// A terminal Keeper event now releases the responsibility while the same
	// step is in flight.
	if err := layout.DeleteInferRecord(ctx, db, layout.StoredHash(taskHash)); err != nil {
		t.Fatal(err)
	}
	confirmation.MaterialDigest = "beef"
	if err := persistence.CheckpointStorageConfirmation(ctx, confirmation); err != nil {
		t.Fatalf("CheckpointStorageConfirmation() after the record was released error = %v, want nil", err)
	}
	// The bytes still landed: an orphaned checkpoint is skipped at the merge, not
	// at the write.
	payload, err := evidenceStore.ReadTaskKind(ctx, taskHash, "worker-confirmation-meta:OUTPUT:trueopen1builder:beef")
	if err != nil {
		t.Fatalf("storage confirmation bytes missing: %v", err)
	}
	var saved storageConfirmationMeta
	if err := json.Unmarshal(payload, &saved); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved.Signature, confirmation.Signature) {
		t.Fatal("atomic confirmation lost its signature")
	}

	// A session mismatch is a different animal and must stay loud: the record
	// exists and disagrees with the checkpoint.
	seedInferTask(ctx, t, db, taskHash, task)
	mismatch := task
	mismatch.SessionID = "session-other"
	err = runner.persistInferCheckpoint(ctx, taskHash, mismatch, layout.Evidence{TaskID: task.TaskID})
	if err == nil || errors.Is(err, errInferCheckpointOrphaned) {
		t.Fatalf("persistInferCheckpoint() session mismatch error = %v, want a reported divergence", err)
	}
}
