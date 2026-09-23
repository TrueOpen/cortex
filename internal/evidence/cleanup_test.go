package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func TestPlanCleanupDiscoversEvidenceWhenTaskHashesAreNotSupplied(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	ready := writePackage(t, ctx, root, index, "ready", 80, 100)
	writePackage(t, ctx, root, index, "future", 80, 101)

	plan, err := PlanCleanup(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 100, TaskStatus: cleanupAllowed,
	})
	if err != nil {
		t.Fatalf("PlanCleanup returned error: %v", err)
	}
	if len(plan.Items) != 1 || plan.Items[0].TaskHash != hexDigest(ready[:]) {
		t.Fatalf("plan items = %#v, want ready task hash only", plan.Items)
	}
	if plan.Digest == "" {
		t.Fatal("plan digest is empty")
	}
	if got, err := index.Evidence(ctx, ready); err != nil || got.TerminalOrSettled != false {
		t.Fatalf("planning changed metadata: %#v, %v", got, err)
	}
}

func TestCleanupRequiresTerminalOrSettledTaskWithNoOpenChallenge(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	nonterminal := writePackage(t, ctx, root, index, "nonterminal", 20, 20)
	challenged := writePackage(t, ctx, root, index, "challenged", 20, 20)
	allowed := writePackage(t, ctx, root, index, "allowed", 20, 20)

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 20,
		TaskStatus: func(_ context.Context, taskHash codec.Hash) (TaskCleanupStatus, error) {
			switch taskHash {
			case nonterminal:
				return TaskCleanupStatus{}, nil
			case challenged:
				return TaskCleanupStatus{TerminalOrSettled: true, OpenChallenge: true}, nil
			default:
				return TaskCleanupStatus{TerminalOrSettled: true}, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 1 || len(result.Records) != 1 || result.Records[0].TaskHash != hexDigest(allowed[:]) {
		t.Fatalf("cleanup result = %#v, want only allowed task", result)
	}
	for _, retained := range []codec.Hash{nonterminal, challenged} {
		metadata, err := index.Evidence(ctx, retained)
		if err != nil || metadata.TerminalOrSettled != false {
			t.Fatalf("retained evidence %x = (%#v, %v), want active", retained, metadata, err)
		}
		if _, err := os.Stat(taskDirPath(t, root, retained)); err != nil {
			t.Fatalf("retained task %x lost its directory: %v", retained, err)
		}
	}
}

func TestRetentionHeightAdvancementDefersCleanupByTaskHash(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "advanced-retention", 20, 20)
	advanced, err := index.AdvanceEvidenceRetention(ctx, taskHash, 20, 40)
	if err != nil || !advanced {
		t.Fatalf("AdvanceEvidenceRetention = (%t, %v)", advanced, err)
	}

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 20, TaskStatus: cleanupAllowed,
	})
	if err != nil || result.Cleaned != 0 {
		t.Fatalf("Cleanup before advanced height = (%#v, %v)", result, err)
	}
	if _, err := index.Evidence(ctx, taskHash); err != nil {
		t.Fatalf("evidence was removed before advanced height: %v", err)
	}

	result, err = cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 40, TaskStatus: cleanupAllowed,
	})
	if err != nil || result.Cleaned != 1 {
		t.Fatalf("Cleanup at advanced height = (%#v, %v)", result, err)
	}
}

func cleanupAllowed(context.Context, codec.Hash) (TaskCleanupStatus, error) {
	return TaskCleanupStatus{TerminalOrSettled: true}, nil
}

// cleanupConfirmed computes a plan for the supplied config and executes cleanup
// using the deterministic plan digest as the operator confirmation.
func cleanupConfirmed(ctx context.Context, cfg CleanupConfig) (CleanupResult, error) {
	plan, err := PlanCleanup(ctx, cfg)
	if err != nil {
		return CleanupResult{}, err
	}
	cfg.ConfirmDigest = plan.Digest
	return Cleanup(ctx, cfg)
}

func newEvidenceFixture(t *testing.T) (string, *LayoutStoreIndex) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "evidence")
	index, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = index.Close() })
	return root, &LayoutStoreIndex{Store: index}
}

func writePackage(t *testing.T, ctx context.Context, root string, index *LayoutStoreIndex, name string, finality, cleanup uint64) codec.Hash {
	t.Helper()
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	taskHash := codec.HashBytes([]byte("task-" + name))
	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: "output-package", Data: []byte("package-" + name),
		FinalityHeight: finality, CleanupHeight: cleanup,
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	return taskHash
}

// taskDirPath and trashDirPath are the live and condemned locations of one
// task's whole local footprint. Cleanup moves the first onto the second.
func taskDirPath(t *testing.T, root string, taskHash codec.Hash) string {
	t.Helper()
	return filepath.Join(resolvedRoot(t, root), taskRelDir(taskHash))
}

func trashDirPath(t *testing.T, root string, taskHash codec.Hash) string {
	t.Helper()
	return filepath.Join(resolvedRoot(t, root), trashRelDir(taskHash))
}

func resolvedRoot(t *testing.T, root string) string {
	t.Helper()
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) returned error: %v", root, err)
	}
	return realRoot
}

// Cleanup retires a task by moving its whole directory out of the live tree and
// then dropping its index rows. The renamed directory is itself the durable
// cleanup-pending marker, which is why the move happens first and the deletion
// of the bytes is left to the sweep.
func TestCleanupMovesTheWholeTaskDirectoryToTrashAndDropsTheIndexRows(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "cleanup", 20, 20)

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20,
		TaskStatus: cleanupAllowed, SweepGracePeriod: time.Hour,
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 1 || result.Trashed != 1 {
		t.Fatalf("cleanup result = %#v, want one task cleaned and trashed", result)
	}
	if _, err := index.Evidence(ctx, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("metadata lookup error = %v, want ErrNotFound", err)
	}
	if _, err := os.Lstat(taskDirPath(t, root, taskHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live task directory still exists: %v", err)
	}
	info, err := os.Lstat(trashDirPath(t, root, taskHash))
	if err != nil {
		t.Fatalf("trashed task directory is missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("trash entry mode = %v, want a directory", info.Mode())
	}
}

// The grace period covers the window in which a retired directory is still on
// disk, so an operator who moved too early can still recover the bytes.
func TestSweepRespectsTheGracePeriodBeforeDrainingTrash(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "grace", 20, 20)
	if _, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20,
		TaskStatus: cleanupAllowed, SweepGracePeriod: time.Hour,
	}); err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}

	result, err := Sweep(ctx, CleanupConfig{Root: root, Index: index, CurrentHeight: 30, SweepGracePeriod: time.Hour})
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if result.Scanned != 1 || result.Pending != 1 || result.Removed != 0 {
		t.Fatalf("sweep result = %#v, want the trashed task held by the grace period", result)
	}
	if _, err := os.Lstat(trashDirPath(t, root, taskHash)); err != nil {
		t.Fatalf("trashed directory was removed inside the grace period: %v", err)
	}

	result, err = Sweep(ctx, CleanupConfig{Root: root, Index: index, CurrentHeight: 30, SweepGracePeriod: 0})
	if err != nil {
		t.Fatalf("second Sweep returned error: %v", err)
	}
	if result.Removed != 1 {
		t.Fatalf("sweep result = %#v, want the expired trash removed", result)
	}
	if _, err := os.Lstat(trashDirPath(t, root, taskHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trashed directory still exists after the grace period: %v", err)
	}
}

// Cleanup finishes the job in the same call rather than leaving the bytes to an
// unscheduled runner: with no grace period the retired directory is gone by the
// time Cleanup returns.
func TestCleanupDrainsTrashInTheSameCall(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "drain", 20, 20)

	if _, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20,
		TaskStatus: cleanupAllowed, SweepGracePeriod: 0,
	}); err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	for _, path := range []string{taskDirPath(t, root, taskHash), trashDirPath(t, root, taskHash)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%q still exists after cleanup: %v", path, err)
		}
	}
}

// Deletion follows the authoritative cleanup path and nothing else. A live task
// directory is never swept, even with no index row at all - which is precisely
// the case the retired global sweep treated as a reclaimable orphan, and the
// case a write in progress looks like.
func TestSweepNeverTouchesTheLiveTaskTree(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	referenced := writePackage(t, ctx, root, index, "referenced", 20, 20)
	unreferenced := writePackage(t, ctx, root, index, "unreferenced", 20, 20)
	if err := index.DeleteEvidence(ctx, unreferenced); err != nil {
		t.Fatalf("DeleteEvidence returned error: %v", err)
	}

	result, err := Sweep(ctx, CleanupConfig{Root: root, Index: index, CurrentHeight: 30, SweepGracePeriod: 0})
	if err != nil {
		t.Fatalf("Sweep returned error: %v", err)
	}
	if result.Scanned != 0 || result.Removed != 0 {
		t.Fatalf("sweep result = %#v, want the live tree untouched", result)
	}
	for _, taskHash := range []codec.Hash{referenced, unreferenced} {
		if _, err := os.Stat(taskDirPath(t, root, taskHash)); err != nil {
			t.Fatalf("live task %x was swept: %v", taskHash, err)
		}
	}
}

// A crash between the directory rename and the index delete leaves a row that
// still says "eligible" and a directory that is already gone. The next cleanup
// must finish the index delete rather than fail on the missing directory - and
// it reports that it moved nothing, because there was nothing left to move.
func TestCleanupCompletesAfterACrashBetweenTrashAndIndexDelete(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "interrupted", 20, 20)
	if moved, err := trashTaskDirectory(root, taskHash); err != nil || !moved {
		t.Fatalf("trashTaskDirectory = (%t, %v), want the directory moved", moved, err)
	}

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20,
		TaskStatus: cleanupAllowed, SweepGracePeriod: 0,
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 1 || result.Trashed != 0 {
		t.Fatalf("cleanup result = %#v, want the index delete completed and nothing moved", result)
	}
	if _, err := index.Evidence(ctx, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("metadata lookup error = %v, want ErrNotFound", err)
	}
}

// A condemned directory left by an interrupted earlier cleanup holds bytes that
// were already authorized for deletion, so retiring the same task again drops
// it rather than merging it with the live directory.
func TestCleanupReplacesATrashEntryLeftByAnEarlierAttempt(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := codec.HashBytes([]byte("task-retried"))
	evidenceStore, err := NewStore(root, index)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	trashed := trashDirPath(t, root, taskHash)
	if err := os.MkdirAll(trashed, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	stale := filepath.Join(trashed, "stale-marker")
	if err := os.WriteFile(stale, []byte("condemned"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	if _, err := evidenceStore.Write(ctx, WriteRequest{
		TaskHash: taskHash, Kind: "output-package", Data: []byte("fresh"),
		FinalityHeight: 20, CleanupHeight: 20,
	}); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	if _, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20,
		TaskStatus: cleanupAllowed, SweepGracePeriod: time.Hour,
	}); err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale trash entry survived: %v", err)
	}
	fresh := codec.HashBytes([]byte("fresh"))
	condemned := filepath.Join(trashed, evidenceName, artifactsName, hexDigest(fresh[:]))
	if _, err := os.Lstat(condemned); err != nil {
		t.Fatalf("the retired task's own bytes are not in trash: %v", err)
	}
}

// TestCleanupRechecksChallengeBeforeDeleting verifies that Cleanup refuses to
// delete metadata while a challenge is open, even if heights are eligible.
func TestCleanupRechecksChallengeBeforeDeleting(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "challenge", 20, 20)
	cleanupBlocked := func(context.Context, codec.Hash) (TaskCleanupStatus, error) {
		return TaskCleanupStatus{TerminalOrSettled: true, OpenChallenge: true}, nil
	}
	result, err := cleanupConfirmed(ctx, CleanupConfig{Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20, TaskStatus: cleanupBlocked})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 0 {
		t.Fatalf("cleaned = %d, want 0", result.Cleaned)
	}
	if _, err := index.Evidence(ctx, taskHash); err != nil {
		t.Fatalf("metadata was deleted: %v", err)
	}
	if _, err := os.Stat(taskDirPath(t, root, taskHash)); err != nil {
		t.Fatalf("task directory was moved while a challenge is open: %v", err)
	}
}

// TestCleanupDeletesChallenges verifies that Cleanup deletes evidence metadata
// and every challenge/<taskHash>/* row for a task.
func TestCleanupDeletesChallenges(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "challenges", 20, 20)
	if err := index.SetEvidenceChallenge(ctx, taskHash, "ch-1", true); err != nil {
		t.Fatalf("SetEvidenceChallenge: %v", err)
	}
	if err := index.SetEvidenceChallenge(ctx, taskHash, "ch-2", true); err != nil {
		t.Fatalf("SetEvidenceChallenge: %v", err)
	}
	cleanupOK := func(context.Context, codec.Hash) (TaskCleanupStatus, error) {
		return TaskCleanupStatus{TerminalOrSettled: true, OpenChallenge: false}, nil
	}
	result, err := cleanupConfirmed(ctx, CleanupConfig{Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20, TaskStatus: cleanupOK})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", result.Cleaned)
	}
	if _, err := index.Evidence(ctx, taskHash); err == nil {
		t.Fatalf("metadata still exists")
	}
	challenges, err := index.ListEvidenceChallenges(ctx, taskHash)
	if err != nil {
		t.Fatalf("ListEvidenceChallenges returned error: %v", err)
	}
	if len(challenges) != 0 {
		t.Fatalf("challenge rows = %v, want none", challenges)
	}
}

// TestCleanupRequiresConfirmedDigest verifies that Cleanup refuses to delete
// anything until the operator supplies the exact deterministic plan digest.
func TestCleanupRequiresConfirmedDigest(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "confirm", 20, 20)

	_, err := Cleanup(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20, TaskStatus: cleanupAllowed,
	})
	if !errors.Is(err, ErrCleanupDigestRequired) {
		t.Fatalf("Cleanup without digest error = %v, want ErrCleanupDigestRequired", err)
	}

	plan, err := PlanCleanup(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20, TaskStatus: cleanupAllowed,
	})
	if err != nil {
		t.Fatalf("PlanCleanup returned error: %v", err)
	}

	_, err = Cleanup(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20, TaskStatus: cleanupAllowed,
		ConfirmDigest: "not-the-digest",
	})
	if !errors.Is(err, ErrCleanupDigestMismatch) {
		t.Fatalf("Cleanup with wrong digest error = %v, want ErrCleanupDigestMismatch", err)
	}
	if _, err := os.Stat(taskDirPath(t, root, taskHash)); err != nil {
		t.Fatalf("task directory was moved without a confirmed digest: %v", err)
	}

	result, err := Cleanup(ctx, CleanupConfig{
		Root: root, Index: index, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 20, TaskStatus: cleanupAllowed,
		ConfirmDigest: plan.Digest,
	})
	if err != nil {
		t.Fatalf("Cleanup with matching digest returned error: %v", err)
	}
	if result.Cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", result.Cleaned)
	}
}

// TestCleanupRefusesStalePlan verifies that a plan digest computed before a
// new evidence record appears is rejected when Cleanup is later called with it.
func TestCleanupRefusesStalePlan(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	_ = writePackage(t, ctx, root, index, "stale", 20, 20)

	plan, err := PlanCleanup(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 20, TaskStatus: cleanupAllowed,
	})
	if err != nil {
		t.Fatalf("PlanCleanup returned error: %v", err)
	}

	// A new record is added after the operator already accepted the plan.
	writePackage(t, ctx, root, index, "new", 20, 20)

	_, err = Cleanup(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 20, TaskStatus: cleanupAllowed,
		ConfirmDigest: plan.Digest,
	})
	if !errors.Is(err, ErrCleanupDigestMismatch) {
		t.Fatalf("stale plan error = %v, want ErrCleanupDigestMismatch", err)
	}
}

// TestCleanupDiagnostics reports retained bytes, open challenge age, cleanup age
// and sweep outcome.
func TestCleanupDiagnostics(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "diagnostic", 20, 20)
	if err := index.SetEvidenceChallenge(ctx, taskHash, "ch-1", true); err != nil {
		t.Fatalf("SetEvidenceChallenge: %v", err)
	}

	diag, err := CleanupDiagnostics(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 25, SweepGracePeriod: 0,
	})
	if err != nil {
		t.Fatalf("CleanupDiagnostics returned error: %v", err)
	}
	if diag.CurrentHeight != 25 {
		t.Fatalf("current height = %d, want 25", diag.CurrentHeight)
	}
	if diag.RetainedBytes == 0 {
		t.Fatalf("retained bytes = 0, want > 0")
	}
	if diag.CleanupAgeBlocks != 5 {
		t.Fatalf("cleanup age = %d, want 5", diag.CleanupAgeBlocks)
	}
	if len(diag.OpenChallenges) != 1 || len(diag.OpenChallenges[0].ChallengeIDs) != 1 {
		t.Fatalf("open challenges = %#v, want one challenge", diag.OpenChallenges)
	}
}

// TestCleanupRequiresPositiveCleanupHeight verifies that a terminal task whose
// evidence record has a finality but no cleanup height is not eligible for
// cleanup. Without this guard, CleanupHeight==0 would be treated as due.
func TestCleanupRequiresPositiveCleanupHeight(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "no-cleanup", 20, 0)

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 100, TaskStatus: cleanupAllowed,
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 0 {
		t.Fatalf("cleaned = %d, want 0 when CleanupHeight is zero", result.Cleaned)
	}
	if _, err := index.Evidence(ctx, taskHash); err != nil {
		t.Fatalf("evidence was removed with zero CleanupHeight: %v", err)
	}
}

func TestSweepRejectsASymlinkedTrashRoot(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "symlinked-trash-root", 20, 20)
	if moved, err := trashTaskDirectory(root, taskHash); err != nil || !moved {
		t.Fatalf("trashTaskDirectory = (%t, %v)", moved, err)
	}

	trashPath := filepath.Join(resolvedRoot(t, root), trashRoot)
	if err := os.RemoveAll(trashPath); err != nil {
		t.Fatalf("RemoveAll trash returned error: %v", err)
	}
	if err := os.Symlink(t.TempDir(), trashPath); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	_, err := Sweep(ctx, CleanupConfig{Root: root, Index: index, CurrentHeight: 30, SweepGracePeriod: 0})
	if !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("Sweep error = %v, want %v", err, ErrEvidenceEscape)
	}
}

func TestSweepRejectsASymlinkedTrashShard(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "symlinked-trash-shard", 20, 20)
	if moved, err := trashTaskDirectory(root, taskHash); err != nil || !moved {
		t.Fatalf("trashTaskDirectory = (%t, %v)", moved, err)
	}

	shard := filepath.Dir(trashDirPath(t, root, taskHash))
	if err := os.RemoveAll(shard); err != nil {
		t.Fatalf("RemoveAll shard returned error: %v", err)
	}
	if err := os.Symlink(t.TempDir(), shard); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	_, err := Sweep(ctx, CleanupConfig{Root: root, Index: index, CurrentHeight: 30, SweepGracePeriod: 0})
	if !errors.Is(err, ErrEvidenceEscape) {
		t.Fatalf("Sweep error = %v, want %v", err, ErrEvidenceEscape)
	}
}

// TestCleanupRequiresPositiveRetentionStartHeight verifies that a terminal task
// with no retention clock at all is not eligible. FinalityHeight is not the gate
// - RetentionStartHeight is - but a row carrying neither is still refused.
func TestCleanupRequiresPositiveRetentionStartHeight(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "no-finality", 0, 20)

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 20, TaskStatus: cleanupAllowed,
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 0 {
		t.Fatalf("cleaned = %d, want 0 when there is no retention clock", result.Cleaned)
	}
	if _, err := index.Evidence(ctx, taskHash); err != nil {
		t.Fatalf("evidence was removed with zero RetentionStartHeight: %v", err)
	}
}

// A task can reach terminal without ever producing a settlement finality - a
// refusal or a deadline expiry does exactly that. Such a task has no
// FinalityHeight, so gating eligibility on that field retained its evidence
// forever. The retention clock the spec defines for this case is the finalized
// Keeper cursor that carried the terminal effect, recorded as
// RetentionStartHeight.
func TestCleanupUsesRetentionStartHeightWithoutAnyFinality(t *testing.T) {
	ctx := context.Background()
	root, index := newEvidenceFixture(t)
	taskHash := writePackage(t, ctx, root, index, "terminal-no-finality", 0, 20)
	// What the task-terminal effect records: terminal, a cursor height, and no
	// finality height, because no settlement ever happened.
	if err := layout.MergeEvidence(ctx, index.Store, layout.StoredHash(taskHash), layout.Evidence{
		TerminalOrSettled: true, RetentionStartHeight: 20,
	}); err != nil {
		t.Fatalf("MergeEvidence returned error: %v", err)
	}
	metadata, err := index.Evidence(ctx, taskHash)
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if metadata.FinalityHeight != 0 {
		t.Fatalf("FinalityHeight = %d, want the case under test to have none", metadata.FinalityHeight)
	}

	result, err := cleanupConfirmed(ctx, CleanupConfig{
		Root: root, Index: index, CurrentHeight: 100, TaskStatus: cleanupAllowed,
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if result.Cleaned != 1 {
		t.Fatalf("cleaned = %d, want the retention window measured from RetentionStartHeight", result.Cleaned)
	}
	if _, err := index.Evidence(ctx, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("evidence error = %v, want ErrNotFound", err)
	}
}
