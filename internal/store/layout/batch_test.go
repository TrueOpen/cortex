package layout

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/SingaXYZ/cortex/internal/store"
)

func openTestLayout(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func hash(label string) StoredHash {
	h := StoredHash{}
	copy(h[:], label)
	return h
}

func TestMergeTaskCreatesAndMerges(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task1")

	record := TaskRecord{
		SessionID:         "session-1",
		OrderSequence:     42,
		ModelID:           "model-a",
		ProfileVersion:    1,
		AcceptedInputHash: hash("input"),
	}
	if err := MergeTask(ctx, s, taskHash, record); err != nil {
		t.Fatalf("MergeTask: %v", err)
	}

	second := record
	second.SessionID = "other"
	if err := MergeTask(ctx, s, taskHash, second); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict err = %v, want ErrConflict", err)
	}

	// Identical replay is allowed.
	if err := MergeTask(ctx, s, taskHash, record); err != nil {
		t.Fatalf("identical replay: %v", err)
	}

	// Late field first-write wins.
	late := TaskRecord{TaskBuilderSetID: "builder-set-1", TaskBuilderSetHash: []byte("hash-1")}
	if err := MergeTask(ctx, s, taskHash, late); err != nil {
		t.Fatalf("late field write: %v", err)
	}
	stored, err := GetTaskRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if stored.TaskBuilderSetID != "builder-set-1" {
		t.Fatalf("builder set id = %q", stored.TaskBuilderSetID)
	}

	// Conflicting late field fails.
	late2 := TaskRecord{TaskBuilderSetID: "builder-set-2"}
	if err := MergeTask(ctx, s, taskHash, late2); !errors.Is(err, ErrConflict) {
		t.Fatalf("late conflict err = %v, want ErrConflict", err)
	}
}

func TestMergeTaskConcurrentCreationConverges(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")

	var wg sync.WaitGroup
	errors := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		record := TaskRecord{SessionID: "session", OrderSequence: 1, ModelID: "m1"}
		if err := MergeTask(ctx, s, taskHash, record); err != nil {
			errors <- err
		}
	}()
	go func() {
		defer wg.Done()
		record := TaskRecord{SessionID: "session", OrderSequence: 1, ModelID: "m1"}
		if err := MergeTask(ctx, s, taskHash, record); err != nil {
			errors <- err
		}
	}()
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent merge: %v", err)
	}

	stored, err := GetTaskRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if stored.ModelID != "m1" {
		t.Fatalf("model id = %q", stored.ModelID)
	}
}

func TestMergeInferRejectsInvalidStage(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	infer := InferRecord{Stage: "quued"}
	if err := MergeInfer(ctx, s, hash("task"), infer); !errors.Is(err, ErrInvalidStage) {
		t.Fatalf("invalid stage err = %v, want ErrInvalidStage", err)
	}
}

func TestMergeInferOneShotFinishReason(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")
	if err := MergeInfer(ctx, s, taskHash, InferRecord{Stage: StageQueued}); err != nil {
		t.Fatalf("create infer: %v", err)
	}
	if err := MergeInfer(ctx, s, taskHash, InferRecord{Stage: StageQueued, FinishReason: FinishReasonEOS}); err != nil {
		t.Fatalf("set finish reason: %v", err)
	}
	if err := MergeInfer(ctx, s, taskHash, InferRecord{Stage: StageQueued, FinishReason: FinishReasonUnknown}); !errors.Is(err, ErrConflict) {
		t.Fatalf("finish reason conflict err = %v, want ErrConflict", err)
	}
	stored, err := GetInferRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("get infer: %v", err)
	}
	if stored.FinishReason != FinishReasonEOS {
		t.Fatalf("finish reason = %q", stored.FinishReason)
	}
}

func TestMergeEvidenceArtifacts(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")
	e1 := Evidence{
		SessionID: "session",
		TaskID:    "task-1",
		Artifacts: []EvidenceArtifact{
			{Kind: ArtifactWorkerOutput, Digest: hash("output1"), Size: 10},
		},
	}
	if err := MergeEvidence(ctx, s, taskHash, e1); err != nil {
		t.Fatalf("merge evidence: %v", err)
	}

	e2 := Evidence{
		Artifacts: []EvidenceArtifact{
			{Kind: ArtifactWorkerTrace, Digest: hash("trace1"), Size: 5},
		},
	}
	if err := MergeEvidence(ctx, s, taskHash, e2); err != nil {
		t.Fatalf("merge more artifacts: %v", err)
	}

	// Singleton conflict: a second worker-output digest is rejected.
	e3 := Evidence{
		Artifacts: []EvidenceArtifact{
			{Kind: ArtifactWorkerOutput, Digest: hash("output2"), Size: 20},
		},
	}
	if err := MergeEvidence(ctx, s, taskHash, e3); !errors.Is(err, ErrConflict) {
		t.Fatalf("singleton conflict err = %v, want ErrConflict", err)
	}

	stored, err := GetEvidenceRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	if len(stored.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(stored.Artifacts))
	}
	for _, a := range stored.Artifacts {
		if a.Kind == ArtifactWorkerOutput && a.Digest != hash("output1") {
			t.Fatalf("output digest was replaced: %s", a.Digest)
		}
	}
}

// "A later finality advances both FinalityHeight and RetentionStartHeight;
// heights never regress" (docs/specs/task-storage-layout.md). The authoritative
// finality height is by definition a valid retention start, so a finality that
// arrives without an explicit one still has to carry the clock - otherwise a row
// whose only height is a finality never becomes eligible for cleanup.
func TestEvidenceFinalityAdvancesTheRetentionClock(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("retention-clock")

	if err := MergeEvidence(ctx, s, taskHash, Evidence{TaskID: "task-1", FinalityHeight: 30}); err != nil {
		t.Fatalf("merge evidence: %v", err)
	}
	record, err := GetEvidenceRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if record.RetentionStartHeight != 30 {
		t.Fatalf("RetentionStartHeight = %d, want the finality height to advance it", record.RetentionStartHeight)
	}

	// Never regresses, in either field.
	if err := MergeEvidence(ctx, s, taskHash, Evidence{FinalityHeight: 10, RetentionStartHeight: 5}); err != nil {
		t.Fatalf("merge lower heights: %v", err)
	}
	record, err = GetEvidenceRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if record.FinalityHeight != 30 || record.RetentionStartHeight != 30 {
		t.Fatalf("finality=%d retention=%d, want both held at 30", record.FinalityHeight, record.RetentionStartHeight)
	}
}

func TestUpsertChallengeRespectsPosition(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")
	old := ChallengeLifecycle{Open: true, OpenedHeight: 10, LastPosition: Position{Height: 1}}
	if err := UpsertChallenge(ctx, s, taskHash, "c1", old); err != nil {
		t.Fatalf("upsert challenge: %v", err)
	}
	newer := ChallengeLifecycle{Open: false, OpenedHeight: 20, LastPosition: Position{Height: 2}}
	if err := UpsertChallenge(ctx, s, taskHash, "c1", newer); err != nil {
		t.Fatalf("upsert newer: %v", err)
	}
	older := ChallengeLifecycle{Open: true, OpenedHeight: 30, LastPosition: Position{Height: 0}}
	if err := UpsertChallenge(ctx, s, taskHash, "c1", older); err == nil {
		t.Fatalf("upsert older with zero position should fail")
	}
	stored, err := GetChallengeLifecycle(ctx, s, taskHash, "c1")
	if err != nil {
		t.Fatalf("get challenge: %v", err)
	}
	if stored.Open {
		t.Fatal("older position overwrote newer record")
	}
}

func TestAdmissionBatchRejectsStaleReplacement(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	sessionID := "session-1"
	orderSequence := uint64(7)

	firstHash := hash("first-task")
	first := CandidateAdmission{SignedOrder: []byte("order1"), HandraiseDigest: firstHash, PublishTS: 100}
	if err := AdmissionBatch(ctx, s, sessionID, orderSequence, firstHash, first); err != nil {
		t.Fatalf("admission: %v", err)
	}

	secondHash := hash("second-task")
	second := CandidateAdmission{SignedOrder: []byte("order2"), HandraiseDigest: secondHash, PublishTS: 50}
	if err := AdmissionBatch(ctx, s, sessionID, orderSequence, secondHash, second); !errors.Is(err, ErrStaleCandidateReplacement) {
		t.Fatalf("stale replacement err = %v, want ErrStaleCandidateReplacement", err)
	}

	// Locator and first candidate should remain.
	locator, err := s.GetRaw(ctx, CandidateCurrentKey(sessionID, orderSequence))
	if err != nil || !bytes.Equal(locator, firstHash[:]) {
		t.Fatalf("locator = %x, want %x", locator, firstHash[:])
	}
	if _, err := s.GetRaw(ctx, CandidateKey(firstHash)); err != nil {
		t.Fatalf("first candidate should remain: %v", err)
	}
}

func TestAdmissionBatchAllowsCandidateSchemaUpgradeAtSamePublishTime(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("candidate-schema-upgrade")
	legacy := CandidateAdmission{
		SchemaVersion: 1, SignedOrder: []byte("order"), HandraisePayload: []byte("legacy-base64-frame"),
		HandraiseDigest: hash("legacy-base64-frame"), PublishTS: 100, DedupID: "stable-dedup",
	}
	if err := AdmissionBatch(ctx, s, "session-1", 1, taskHash, legacy); err != nil {
		t.Fatalf("write legacy candidate: %v", err)
	}
	current := legacy
	current.SchemaVersion = 2
	current.HandraisePayload = []byte("current-hex-frame")
	current.HandraiseDigest = hash("current-hex-frame")
	if err := AdmissionBatch(ctx, s, "session-1", 1, taskHash, current); err != nil {
		t.Fatalf("upgrade candidate schema at the same publish time: %v", err)
	}
	stored, err := GetCandidateAdmission(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("read upgraded candidate: %v", err)
	}
	if !candidateAdmissionsEqual(stored, current) {
		t.Fatalf("stored candidate = %#v, want schema-upgraded %#v", stored, current)
	}
}

func TestAdmissionBatchRejectsFutureCandidateSchema(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	err := AdmissionBatch(ctx, s, "session-1", 1, hash("future-candidate"), CandidateAdmission{
		SchemaVersion: CandidateAdmissionSchemaVersion + 1,
	})
	if err == nil {
		t.Fatal("AdmissionBatch accepted a future candidate schema")
	}
}

func TestAdmissionBatchRepointsLocator(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	sessionID := "session-1"
	orderSequence := uint64(7)

	oldHash := hash("old-task")
	admission1 := CandidateAdmission{SignedOrder: []byte("order1"), HandraiseDigest: oldHash, PublishTS: 100}
	if err := AdmissionBatch(ctx, s, sessionID, orderSequence, oldHash, admission1); err != nil {
		t.Fatalf("admission1: %v", err)
	}

	newHash := hash("new-task")
	admission2 := CandidateAdmission{SignedOrder: []byte("order2"), HandraiseDigest: newHash, PublishTS: 200}
	if err := AdmissionBatch(ctx, s, sessionID, orderSequence, newHash, admission2); err != nil {
		t.Fatalf("admission2: %v", err)
	}

	// Old candidate should be deleted.
	if _, err := s.GetRaw(ctx, CandidateKey(oldHash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old candidate should be deleted: %v", err)
	}

	// Locator should point to new task.
	locator, err := s.GetRaw(ctx, CandidateCurrentKey(sessionID, orderSequence))
	if err != nil {
		t.Fatalf("locator: %v", err)
	}
	if !bytes.Equal(locator, newHash[:]) {
		t.Fatalf("locator points to wrong hash")
	}
}

func TestAssignmentTransferBatch(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	sessionID := "session-1"
	orderSequence := uint64(7)
	taskHash := hash("task")

	admission := CandidateAdmission{SignedOrder: []byte("order"), HandraiseDigest: taskHash}
	if err := AdmissionBatch(ctx, s, sessionID, orderSequence, taskHash, admission); err != nil {
		t.Fatalf("admission: %v", err)
	}

	task := TaskRecord{SessionID: sessionID, OrderSequence: orderSequence, ModelID: "model"}
	infer := InferRecord{Stage: StageQueued, TaskID: "task-1"}
	if err := InferAssignmentBatch(ctx, s, taskHash, task, infer); err != nil {
		t.Fatalf("infer assignment: %v", err)
	}

	if _, err := GetTaskRecord(ctx, s, taskHash); err != nil {
		t.Fatalf("task missing: %v", err)
	}
	if _, err := GetInferRecord(ctx, s, taskHash); err != nil {
		t.Fatalf("infer missing: %v", err)
	}
	// With terminal-only admission cleanup, candidate/locator are left intact.
	if _, err := s.GetRaw(ctx, CandidateKey(taskHash)); err != nil {
		t.Fatalf("candidate should remain until terminal: %v", err)
	}
	if _, err := s.GetRaw(ctx, CandidateCurrentKey(sessionID, orderSequence)); err != nil {
		t.Fatalf("locator should remain until terminal: %v", err)
	}

	// Idempotent replay succeeds.
	if err := InferAssignmentBatch(ctx, s, taskHash, task, infer); err != nil {
		t.Fatalf("idempotent infer assignment: %v", err)
	}
}

func TestTaskTerminalBatchKeepsEvidence(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")

	if err := MergeTask(ctx, s, taskHash, TaskRecord{SessionID: "session", OrderSequence: 1, ModelID: "m"}); err != nil {
		t.Fatalf("task: %v", err)
	}
	if err := MergeInfer(ctx, s, taskHash, InferRecord{Stage: StageQueued}); err != nil {
		t.Fatalf("infer: %v", err)
	}
	if err := PutDelivery(ctx, s, taskHash, "OUTPUT", StorageConfirmation{BuilderOperator: "b"}); err != nil {
		t.Fatalf("delivery: %v", err)
	}

	evidence := Evidence{SessionID: "session", TaskID: "task-1", TerminalOrSettled: true}
	if err := TaskTerminalBatch(ctx, s, taskHash, evidence); err != nil {
		t.Fatalf("terminal batch: %v", err)
	}

	if _, err := GetTaskRecord(ctx, s, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("task should be deleted: %v", err)
	}
	if _, err := GetInferRecord(ctx, s, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("infer should be deleted: %v", err)
	}
	if _, err := s.GetRaw(ctx, DeliveryKey(taskHash, "OUTPUT")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delivery should be deleted: %v", err)
	}
	stored, err := GetEvidenceRecord(ctx, s, taskHash)
	if err != nil {
		t.Fatalf("evidence should remain: %v", err)
	}
	if !stored.TerminalOrSettled {
		t.Fatal("evidence should be terminal")
	}
}

func TestCleanupBatch(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")

	if err := MergeEvidence(ctx, s, taskHash, Evidence{SessionID: "session", TaskID: "task-1"}); err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if err := UpsertChallenge(ctx, s, taskHash, "c1", ChallengeLifecycle{Open: true, LastPosition: Position{Height: 1}}); err != nil {
		t.Fatalf("challenge: %v", err)
	}

	if err := CleanupBatch(ctx, s, taskHash); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := GetEvidenceRecord(ctx, s, taskHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("evidence should be deleted: %v", err)
	}
	if _, err := s.GetRaw(ctx, ChallengeKey(taskHash, "c1")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("challenge should be deleted: %v", err)
	}
	// Repeat is a no-op.
	if err := CleanupBatch(ctx, s, taskHash); err != nil {
		t.Fatalf("cleanup repeat: %v", err)
	}
}

// TestReopenAfterClose checks that a normal close and reopen preserves layout
// records. A true crash test would run in a subprocess, but this still
// exercises Pebble durability.
func TestReopenAfterClose(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cortex.kv")
	s, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	taskHash := hash("task")
	if err := MergeTask(ctx, s, taskHash, TaskRecord{SessionID: "session", OrderSequence: 1, ModelID: "m"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	stored, err := GetTaskRecord(ctx, reopened, taskHash)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if stored.SessionID != "session" {
		t.Fatalf("session id = %q", stored.SessionID)
	}
}

func TestListInferRecordsAndDelete(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	h1 := hash("infer1")
	h2 := hash("infer2")
	if err := MergeTask(ctx, s, h1, TaskRecord{SessionID: "s1", OrderSequence: 1}); err != nil {
		t.Fatalf("merge task1: %v", err)
	}
	if err := MergeTask(ctx, s, h2, TaskRecord{SessionID: "s2", OrderSequence: 2}); err != nil {
		t.Fatalf("merge task2: %v", err)
	}
	if err := MergeInfer(ctx, s, h1, InferRecord{TaskID: "t1", Stage: StageQueued}); err != nil {
		t.Fatalf("merge infer1: %v", err)
	}
	if err := MergeInfer(ctx, s, h2, InferRecord{TaskID: "t2", Stage: StageFailed}); err != nil {
		t.Fatalf("merge infer2: %v", err)
	}
	hashes, records, err := ListInferRecords(ctx, s)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(hashes) != 2 {
		t.Fatalf("len = %d, want 2", len(hashes))
	}
	if records[0].TaskID != "t1" && records[1].TaskID != "t1" {
		t.Fatalf("t1 missing: %#v", records)
	}
	if err := DeleteInferRecord(ctx, s, h1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	hashes, records, err = ListInferRecords(ctx, s)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(hashes) != 1 || records[0].TaskID != "t2" {
		t.Fatalf("after delete = %#v", records)
	}
}

func TestListVerifyRecordsAndDelete(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	h := hash("verify1")
	if err := MergeTask(ctx, s, h, TaskRecord{SessionID: "s", OrderSequence: 1}); err != nil {
		t.Fatalf("merge task: %v", err)
	}
	if err := MergeVerify(ctx, s, h, VerifyRecord{TaskID: "t1", Stage: StageQueued}); err != nil {
		t.Fatalf("merge verify: %v", err)
	}
	hashes, records, err := ListVerifyRecords(ctx, s)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(hashes) != 1 || records[0].TaskID != "t1" {
		t.Fatalf("got %#v", records)
	}
	if err := DeleteVerifyRecord(ctx, s, h); err != nil {
		t.Fatalf("delete: %v", err)
	}
	hashes, _, err = ListVerifyRecords(ctx, s)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(hashes) != 0 {
		t.Fatalf("want empty, got %d", len(hashes))
	}
}

func TestFindInferRecordByTaskIDUsesIndex(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	h := hash("infer-idx")
	if err := MergeTask(ctx, s, h, TaskRecord{SessionID: "s", OrderSequence: 1}); err != nil {
		t.Fatalf("merge task: %v", err)
	}
	if err := MergeInfer(ctx, s, h, InferRecord{TaskID: "task-1", Stage: StageQueued}); err != nil {
		t.Fatalf("merge infer: %v", err)
	}
	gotHash, rec, err := FindInferRecordByTaskID(ctx, s, "task-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if gotHash != h || rec.TaskID != "task-1" {
		t.Fatalf("got (%v, %#v), want (%v, task-1)", gotHash, rec, h)
	}
	if err := DeleteInferRecord(ctx, s, h); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, _, err = FindInferRecordByTaskID(ctx, s, "task-1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestFindVerifyRecordByTaskIDUsesIndex(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	h := hash("verify-idx")
	if err := MergeTask(ctx, s, h, TaskRecord{SessionID: "s", OrderSequence: 1}); err != nil {
		t.Fatalf("merge task: %v", err)
	}
	if err := MergeVerify(ctx, s, h, VerifyRecord{TaskID: "task-2", Stage: StageQueued}); err != nil {
		t.Fatalf("merge verify: %v", err)
	}
	gotHash, rec, err := FindVerifyRecordByTaskID(ctx, s, "task-2")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if gotHash != h || rec.TaskID != "task-2" {
		t.Fatalf("got (%v, %#v), want (%v, task-2)", gotHash, rec, h)
	}
}

func TestInferAssignmentBatchCreatesTaskIDIndexAndValidates(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")
	task := TaskRecord{SessionID: "s", OrderSequence: 1, ModelID: "m"}
	infer := InferRecord{TaskID: "task-1", Stage: StageQueued, WinnerConfirmHeight: 1, InferDeadlineHeight: 2, DeadlineHeight: 2}
	if err := InferAssignmentBatch(ctx, s, taskHash, task, infer); err != nil {
		t.Fatalf("infer assignment: %v", err)
	}
	// task-id/infer index should exist immediately.
	got, rec, err := FindInferRecordByTaskID(ctx, s, "task-1")
	if err != nil {
		t.Fatalf("find by task id: %v", err)
	}
	if got != taskHash || rec.TaskID != "task-1" {
		t.Fatalf("got (%v, %#v), want (%v, task-1)", got, rec, taskHash)
	}
	// Invalid stage is refused even on the assignment path.
	if err := InferAssignmentBatch(ctx, s, taskHash, task, InferRecord{TaskID: "task-1", Stage: "bogus"}); err == nil {
		t.Fatal("expected invalid stage to fail")
	}
	// Conflicting infer record is refused.
	if err := InferAssignmentBatch(ctx, s, taskHash, task, InferRecord{TaskID: "task-1", Stage: StageQueued, WinnerConfirmHeight: 9}); err == nil {
		t.Fatal("expected conflicting WinnerConfirmHeight to fail")
	}
}

func TestMergeInferRejectsConflictingWriteOnceFields(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")
	if err := MergeTask(ctx, s, taskHash, TaskRecord{SessionID: "s", OrderSequence: 1, ModelID: "m"}); err != nil {
		t.Fatalf("task: %v", err)
	}
	if err := MergeInfer(ctx, s, taskHash, InferRecord{TaskID: "task-1", Stage: StageQueued}); err != nil {
		t.Fatalf("infer: %v", err)
	}
	// OutputDigest is write-once.
	digest1 := hash("digest1")
	digest2 := hash("digest2")
	if err := MergeInfer(ctx, s, taskHash, InferRecord{Stage: StageQueued, OutputDigest: digest1}); err != nil {
		t.Fatalf("first output digest: %v", err)
	}
	if err := MergeInfer(ctx, s, taskHash, InferRecord{OutputDigest: digest2}); err == nil {
		t.Fatal("expected conflicting OutputDigest to fail")
	}
}

func TestAdmissionBatchRefusesConflictingSameHash(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("task")
	admission := CandidateAdmission{SignedOrder: []byte("order-1"), HandraiseDigest: taskHash, PublishTS: 100}
	if err := AdmissionBatch(ctx, s, "session-1", 1, taskHash, admission); err != nil {
		t.Fatalf("admission: %v", err)
	}
	// Identical replay succeeds.
	if err := AdmissionBatch(ctx, s, "session-1", 1, taskHash, admission); err != nil {
		t.Fatalf("identical replay: %v", err)
	}
	// Same hash, different content, same PublishTS is refused.
	conflict := admission
	conflict.SignedOrder = []byte("order-2")
	if err := AdmissionBatch(ctx, s, "session-1", 1, taskHash, conflict); err == nil {
		t.Fatal("expected conflicting admission with same hash to fail")
	}
}

// The claim marks completed work, not an attempt. An incomplete row means an
// earlier delivery took the claim and then died, and suppressing on that would
// strand the task with no confirmation and no handraise.
func TestVerifyAdmissionSuppressesOnlyACompletedClaim(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("verify-admission")
	admission := VerifierAdmission{OutputHash: hash("output")}

	claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, admission)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if claimed {
		t.Fatal("first claim reported a duplicate")
	}

	claimed, err = VerifyAdmissionBatch(ctx, s, taskHash, 1, admission)
	if err != nil {
		t.Fatalf("claim after a failed attempt: %v", err)
	}
	if claimed {
		t.Fatal("an incomplete claim suppressed the retry")
	}

	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, admission); err != nil {
		t.Fatalf("complete claim: %v", err)
	}
	claimed, err = VerifyAdmissionBatch(ctx, s, taskHash, 1, admission)
	if err != nil {
		t.Fatalf("claim after completion: %v", err)
	}
	if !claimed {
		t.Fatal("a completed claim did not suppress the duplicate")
	}

	// Conflicting content is still refused rather than silently overwritten.
	if _, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, VerifierAdmission{OutputHash: hash("other-output")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting claim error = %v, want ErrConflict", err)
	}
}

func TestVerifyAdmissionSchemaUpgradeReopensCompletedClaim(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("verify-admission-schema-upgrade")
	legacy := VerifierAdmission{SchemaVersion: 1, OutputHash: hash("output")}
	if claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, legacy); err != nil || claimed {
		t.Fatalf("legacy claim = (%v, %v), want (false, nil)", claimed, err)
	}
	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, legacy); err != nil {
		t.Fatalf("complete legacy claim: %v", err)
	}
	current := legacy
	current.SchemaVersion = 2
	if claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, current); err != nil || claimed {
		t.Fatalf("schema-upgraded claim = (%v, %v), want reopened (false, nil)", claimed, err)
	}
}

func TestVerifyAdmissionKeepsTheFirstDataReadyBuilderAcrossEquivalentTriggers(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("verify-data-ready-builder")
	first := VerifierAdmission{
		SchemaVersion:            VerifierAdmissionSchemaVersion,
		OutputHash:               hash("output"),
		DataReadyBuilderOperator: "builder-1",
		InferReceiptHash:         hash("receipt"),
	}
	if claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, VerifierAdmission{OutputHash: first.OutputHash}); err != nil || claimed {
		t.Fatalf("first claim = (%v, %v), want (false, nil)", claimed, err)
	}
	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.DataReadyBuilderOperator = "builder-2"
	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, second); err != nil {
		t.Fatalf("complete from equivalent second Builder: %v", err)
	}
	stored, err := GetVerifierAdmission(ctx, s, taskHash, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DataReadyBuilderOperator != "builder-1" || stored.InferReceiptHash != second.InferReceiptHash {
		t.Fatalf("enriched admission = %#v, want the first Builder and later authoritative receipt", stored)
	}
	conflict := second
	conflict.InferReceiptHash = hash("other-receipt")
	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting receipt error = %v, want ErrConflict", err)
	}
}

func TestVerifyAdmissionSchemaUpgradeAddsDataReadyBuilderAndReopensCompletion(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	taskHash := hash("verify-builder-upgrade")
	legacy := VerifierAdmission{SchemaVersion: 2, OutputHash: hash("output")}
	if claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, legacy); err != nil || claimed {
		t.Fatalf("legacy claim = (%v, %v), want (false, nil)", claimed, err)
	}
	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, legacy); err != nil {
		t.Fatal(err)
	}

	current := VerifierAdmission{
		SchemaVersion: VerifierAdmissionSchemaVersion,
		OutputHash:    hash("output"),
	}
	if claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, current); err != nil || claimed {
		t.Fatalf("upgraded claim = (%v, %v), want reopened (false, nil)", claimed, err)
	}
	completed := current
	completed.DataReadyBuilderOperator = "builder-1"
	if err := CompleteVerifyAdmission(ctx, s, taskHash, 1, completed); err != nil {
		t.Fatal(err)
	}
	stored, err := GetVerifierAdmission(ctx, s, taskHash, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SchemaVersion != VerifierAdmissionSchemaVersion || !stored.Completed || stored.DataReadyBuilderOperator != "builder-1" {
		t.Fatalf("upgraded admission = %#v", stored)
	}
}

func TestVerifyAssignmentAndAdmissionCompletionConvergeAcrossConcurrentOrdering(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	for i := byte(1); i <= 20; i++ {
		taskHash := hash("concurrent-verify-ready")
		taskHash[0] = i
		outputHash := hash("concurrent-output")
		receiptHash := hash("concurrent-receipt")
		if claimed, err := VerifyAdmissionBatch(ctx, s, taskHash, 1, VerifierAdmission{OutputHash: outputHash}); err != nil || claimed {
			t.Fatalf("claim %d = (%v, %v), want (false, nil)", i, claimed, err)
		}

		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs <- CompleteVerifyAdmission(ctx, s, taskHash, 1, VerifierAdmission{
				SchemaVersion: VerifierAdmissionSchemaVersion, OutputHash: outputHash,
				InferReceiptHash: receiptHash, DataReadyBuilderOperator: "builder-1",
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			errs <- VerifyAssignmentBatch(ctx, s, taskHash,
				TaskRecord{SessionID: "session-1"},
				VerifyRecord{TaskID: "task-1", VerifyRound: 1, OutputDigest: outputHash, InferReceiptDigest: receiptHash, Stage: StageQueued},
			)
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent operation %d: %v", i, err)
			}
		}
		stored, err := GetTaskRecord(ctx, s, taskHash)
		if err != nil {
			t.Fatal(err)
		}
		if stored.BuilderOperatorAddress != "builder-1" {
			t.Fatalf("iteration %d Builder = %q, want builder-1", i, stored.BuilderOperatorAddress)
		}
	}
}

func TestVerifyAdmissionBatchRejectsFutureVerifierSchema(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	if _, err := VerifyAdmissionBatch(ctx, s, hash("future-verifier"), 1, VerifierAdmission{
		SchemaVersion: VerifierAdmissionSchemaVersion + 1,
	}); err == nil {
		t.Fatal("VerifyAdmissionBatch accepted a future verifier schema")
	}
}
