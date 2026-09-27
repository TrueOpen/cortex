package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// A capability label is the deployment config's local name for a chain-committed
// (model_id, profile_version) pair. The chain commits neither the label nor
// anything that fixes it, so it is not part of accepted_task_hash and two
// admissions of one task can legitimately disagree about it.
//
// It used to be stored in a write-once TaskRecord field, which made that
// disagreement a consensus conflict. This is the sequence that turned a config
// edit into a lost responsibility, and it must stay a non-event: DeleteInferRecord
// leaves the task row behind, so a redelivered admission met a conflicting task row
// with no infer row, was quarantined, and created nothing - leaving the node
// selected on chain with nothing to run.
func TestCapabilityConfigChangeDoesNotLoseTheResponsibility(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	taskHash := codec.HashBytes([]byte("capability-conflict"))
	key := testModelID + "\x001"
	snapshot := chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
		TaskID: "task-1", SessionID: "session-1", OrderSequence: chainclient.NewUint64String(1),
		SelectedWorker: "worker-1", ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
		InferDeadlineHeight:      chainclient.NewUint64String(100),
		AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes([]byte("input"))),
	}}
	assignment := ReconcilerEffect{Type: ReconcilerEffectAssignment, TaskHash: taskHash, TaskID: "task-1", Snapshot: snapshot}

	var quarantined []string
	runner := NewTaskRunner(TaskRunnerConfig{
		Store:               db,
		LocalWorkerAddress:  "worker-1",
		ProfileCapabilities: map[string]string{key: "llm_text_v1"},
		OnQuarantinedEffect: func(_ ReconcilerEffect, err error) { quarantined = append(quarantined, err.Error()) },
	})

	// 1. Admission.
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{assignment}); err != nil {
		t.Fatalf("step 1 admission: %v", err)
	}
	task, err := layout.GetTaskRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("step 1: admitted, infer row exists (ModelID=%q ProfileVersion=%d)", task.ModelID, task.ProfileVersion)

	// 2. Infer terminal. DeleteInferRecord removes only the infer row.
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{
		{Type: ReconcilerEffectInferTerminal, TaskHash: taskHash, TaskID: "task-1"},
	}); err != nil {
		t.Fatalf("step 2 infer terminal: %v", err)
	}
	if _, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("step 2: infer row should be gone, got %v", err)
	}
	survived, err := layout.GetTaskRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("step 2: the task row should survive: %v", err)
	}
	t.Logf("step 2: infer row deleted, task row survives (ModelID=%q)", survived.ModelID)

	// 3. An operator edits the capability label for that (model, profile) and
	//    restarts. Same chain facts, different local naming.
	runner.cfg.ProfileCapabilities = map[string]string{key: "llm_text_v2"}
	t.Logf("step 3: config now maps %q -> %q", "model-1/1", "llm_text_v2")

	// 4. The assignment event is redelivered — reachable today because
	//    recoverCursorAhead rewinds the cursor on a reorg, and gap recovery
	//    replays a page.
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{assignment}); err != nil {
		t.Fatalf("step 4 redelivery returned an error instead of quarantining: %v", err)
	}

	// 5. What happened?
	if len(quarantined) != 0 {
		t.Errorf("step 5: still quarantined: %s", quarantined[0])
	} else {
		t.Log("step 5: no conflict — the config edit no longer collides")
	}

	if _, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash)); err != nil {
		t.Errorf("step 6: the responsibility is still lost: %v", err)
	} else {
		t.Log("step 6: the redelivered admission re-created the infer row")
	}
}
