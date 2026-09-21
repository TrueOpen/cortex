package daemon

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/evidence"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
)

// The crash-recovery half of the task-scoped local layout: an index row that
// names committed bytes which are no longer on disk means a previous process
// already signed responsibility material for those exact bytes. Rerunning the
// responsibility would sign different bytes for the same task, so the task must
// stop instead. A task whose objects are intact is unaffected — the gate must
// not become a blanket refusal to make progress after any restart.
func TestRunOnceStopsATaskWhoseCommittedLocalObjectsAreGoneAndRunsOneThatIsIntact(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	evidenceStore, err := evidence.NewStore(root, db)
	if err != nil {
		t.Fatalf("evidence.NewStore returned error: %v", err)
	}

	lostHash := codec.HashBytes([]byte("task-with-lost-objects"))
	intactHash := codec.HashBytes([]byte("task-with-intact-objects"))
	lostTrace := []byte("worker trace whose bytes go missing")
	for hash, data := range map[codec.Hash][]byte{
		lostHash:   lostTrace,
		intactHash: []byte("worker trace that survives the restart"),
	} {
		if _, err := evidenceStore.Write(ctx, evidence.WriteRequest{
			TaskHash: hash, Kind: string(layout.ArtifactWorkerTrace), Data: data,
		}); err != nil {
			t.Fatalf("evidence Write returned error: %v", err)
		}
	}
	lostHex := hex.EncodeToString(lostHash[:])
	traceDigest := codec.HashBytes(lostTrace)
	if err := os.Remove(filepath.Join(root, "tasks", lostHex[:2], lostHex,
		"evidence", "artifacts", hex.EncodeToString(traceDigest[:]))); err != nil {
		t.Fatalf("removing the committed object returned error: %v", err)
	}

	seedInferTask(ctx, t, db, lostHash, store.InferTask{TaskID: "lost", Stage: "queued"})
	seedInferTask(ctx, t, db, intactHash, store.InferTask{TaskID: "intact", Stage: "queued"})

	var ranMu sync.Mutex
	ran := map[string]int{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store:    db,
		Evidence: evidenceStore,
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			ranMu.Lock()
			ran[task.TaskID]++
			ranMu.Unlock()
			task.Stage = "succeeded"
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	ranMu.Lock()
	lostRuns, intactRuns := ran["lost"], ran["intact"]
	ranMu.Unlock()
	if lostRuns != 0 {
		t.Fatalf("the task with missing committed objects ran %d time(s); its already-signed material named bytes that are gone", lostRuns)
	}
	if intactRuns != 1 {
		t.Fatalf("the intact task ran %d time(s), want 1", intactRuns)
	}

	lostRecord, err := layout.GetInferRecord(ctx, db, layout.StoredHash(lostHash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if lostRecord.Stage != layout.StageFailed {
		t.Fatalf("stopped task stage = %q, want %q", lostRecord.Stage, layout.StageFailed)
	}
	if !strings.Contains(lostRecord.LastError, evidence.ErrEvidenceUnavailable.Error()) {
		t.Fatalf("stopped task LastError = %q, want it to name why the task cannot be redone", lostRecord.LastError)
	}
	intactRecord, err := layout.GetInferRecord(ctx, db, layout.StoredHash(intactHash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if intactRecord.Stage != layout.StageSucceeded {
		t.Fatalf("intact task stage = %q, want %q", intactRecord.Stage, layout.StageSucceeded)
	}
}

// The gate answers a question about what a previous process left behind, so it
// runs at most once per task per process. Hashing every committed object of
// every active task on every poll tick would be pointless I/O on the hot path.
func TestRunOnceVerifiesLocalObjectsAtMostOncePerTask(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	evidenceStore, err := evidence.NewStore(root, db)
	if err != nil {
		t.Fatalf("evidence.NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("repeatedly-polled-task"))
	trace := []byte("worker trace")
	if _, err := evidenceStore.Write(ctx, evidence.WriteRequest{
		TaskHash: taskHash, Kind: string(layout.ArtifactWorkerTrace), Data: trace,
	}); err != nil {
		t.Fatalf("evidence Write returned error: %v", err)
	}
	seedInferTask(ctx, t, db, taskHash, store.InferTask{TaskID: "polled", Stage: "queued"})

	runner := NewTaskRunner(TaskRunnerConfig{
		Store:    db,
		Evidence: evidenceStore,
		InferExecutor: inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
			return task, false, nil
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("first RunOnce returned error: %v", err)
	}
	// Corrupt the bytes after the first pass. A gate that re-hashed on every
	// tick would now stop a task it already cleared, which is not what this
	// check is for: mid-process corruption is caught where the bytes are read,
	// not by re-auditing the whole task on a timer.
	hexHash := hex.EncodeToString(taskHash[:])
	traceDigest := codec.HashBytes(trace)
	object := filepath.Join(root, "tasks", hexHash[:2], hexHash,
		"evidence", "artifacts", hex.EncodeToString(traceDigest[:]))
	if err := os.Remove(object); err != nil {
		t.Fatalf("removing the committed object returned error: %v", err)
	}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce returned error: %v", err)
	}
	record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetInferRecord returned error: %v", err)
	}
	if record.Stage == layout.StageFailed {
		t.Fatalf("the already-cleared task was re-audited on a later tick: %#v", record)
	}
}
