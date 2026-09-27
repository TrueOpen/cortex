package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"os"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/worker"
)

type fixedVerifierMemberReader struct {
	snapshot chainclient.VerifierCandidateMemberSnapshot
}

// VerifierCandidateMember refuses the way a real closed window does. The verify
// executor must never ask the handraise question -- by the time it runs, the
// interval has closed -- so a regression back to that read fails here instead of
// silently working against a fake that answers both the same.
func (r fixedVerifierMemberReader) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf(
		"%w: handraise_close_height=581 committed_height=586", chainclient.ErrVerifierWindowClosed)
}

func (r fixedVerifierMemberReader) FrozenVerifierWindowMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return r.snapshot, nil
}

func TestProductionVerifyExecutorUsesKeeperInferReceiptDigest(t *testing.T) {
	sessionID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	taskID := identity.TaskIDString(sessionID, 1)
	receiptHash := codec.HashBytes([]byte("accepted-infer-receipt"))
	outputHash := codec.HashBytes([]byte("committed-output"))
	seed := codec.HashBytes([]byte("selection-beacon"))
	confirmer := &recordingOutputConfirmer{pkg: builderclient.OutputPackage{TaskID: taskID, OutputHash: outputHash}}
	executor := newProductionVerifyExecutor(TaskRunnerConfig{
		OutputConfirmer:      confirmer,
		LocalVerifierAddress: "verifier-1",
		ChainID:              "chain",
		TaskDataAuth:         taskRunnerTaskDataAuth(t),
		// A real node's verify path resolves its commit exit before it spends a
		// GPU on verification, so the fixture carries the tx client and the
		// service address that exit signs as.
		Tx:            txclient.NewFake(),
		SignerAddress: "service-1",
		TxFeeCap:      txclient.Coin{Amount: 25, Denom: "utrueopen"},
		VerifierMemberReader: fixedVerifierMemberReader{snapshot: chainclient.VerifierCandidateMemberSnapshot{
			CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
				CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x11}, 32)),
				Slot:                    2, SlotVersion: 1, OperatorAddress: "verifier-1",
			},
			InferReceiptHash: chainclient.ProtoBytes32(receiptHash[:]), ExpiryHeight: 20,
		}},
	})
	task := store.VerifyTask{
		TaskID: taskID, SessionID: sessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("accepted-order")),
		ModelID:     testModelID, ProfileVersion: 1, Capability: "llm-text",
		WorkerAddress: "worker-1", BuilderOperatorAddress: "builder-1",
		OutputDigest: outputHash, InferReceiptDigest: receiptHash,
		VerifyRound: 1, OpenVerifyHeight: 10, CommitDeadlineHeight: 30, DeadlineHeight: 40,
		AssignedVerifiers: []string{"verifier-1"}, VerificationSampleSeed: seed,
		Stage: string(layout.StageQueued),
	}

	_, terminal, err := executor.RunVerify(context.Background(), codec.HashBytes([]byte("task-hash")), task)
	if err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunVerify() error = %v, want the next boundary after matching the accepted infer receipt", err)
	}
	if terminal || len(confirmer.received) != 1 {
		t.Fatalf("RunVerify() terminal=%v confirmations=%#v", terminal, confirmer.received)
	}
}

// recordedVerifierWindowReads answers both readings and reports which ones a
// caller used.
type recordedVerifierWindowReads struct {
	snapshot        chainclient.VerifierCandidateMemberSnapshot
	handraise       int
	frozen          int
	handraiseClosed bool
}

func (r *recordedVerifierWindowReads) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	r.handraise++
	if r.handraiseClosed {
		return chainclient.VerifierCandidateMemberSnapshot{}, fmt.Errorf(
			"%w: handraise_close_height=581 committed_height=586", chainclient.ErrVerifierWindowClosed)
	}
	return r.snapshot, nil
}

func (r *recordedVerifierWindowReads) FrozenVerifierWindowMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	r.frozen++
	return r.snapshot, nil
}

// A selected Verifier always starts verifying after handraise_close_height has
// passed (06-challenge-and-evidence.md §5.1 puts selection_height after it), so the verify
// executor asking "may I still raise my hand" produced a retry that could never
// succeed: on devnet three Verifiers spent 28 rounds each re-fetching the same
// output before the log ran out. The executor must read the frozen window, and
// must not consult the handraise reading at all -- even one call would put the
// closed-window refusal back on the verify path.
func TestVerifyExecutorReadsTheFrozenWindowRatherThanTheHandraiseWindow(t *testing.T) {
	sessionID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	taskID := identity.TaskIDString(sessionID, 1)
	receiptHash := codec.HashBytes([]byte("accepted-infer-receipt"))
	outputHash := codec.HashBytes([]byte("committed-output"))
	reader := &recordedVerifierWindowReads{
		// The devnet shape: this node is in the frozen set, and the interval it
		// raised its hand in is long closed.
		handraiseClosed: true,
		snapshot: chainclient.VerifierCandidateMemberSnapshot{
			CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
				CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x11}, 32)),
				Slot:                    2, SlotVersion: 1, OperatorAddress: "verifier-1",
			},
			InferReceiptHash: chainclient.ProtoBytes32(receiptHash[:]), ExpiryHeight: 581,
		},
	}
	confirmer := &recordingOutputConfirmer{pkg: builderclient.OutputPackage{TaskID: taskID, OutputHash: outputHash}}
	executor := newProductionVerifyExecutor(TaskRunnerConfig{
		OutputConfirmer:      confirmer,
		LocalVerifierAddress: "verifier-1",
		ChainID:              "chain",
		TaskDataAuth:         taskRunnerTaskDataAuth(t),
		// A real node's verify path resolves its commit exit before it spends a
		// GPU on verification, so the fixture carries the tx client and the
		// service address that exit signs as.
		Tx:                   txclient.NewFake(),
		SignerAddress:        "service-1",
		TxFeeCap:             txclient.Coin{Amount: 25, Denom: "utrueopen"},
		VerifierMemberReader: reader,
	})
	task := store.VerifyTask{
		TaskID: taskID, SessionID: sessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("accepted-order")),
		ModelID:     testModelID, ProfileVersion: 1, Capability: "llm-text",
		WorkerAddress: "worker-1", BuilderOperatorAddress: "builder-1",
		OutputDigest: outputHash, InferReceiptDigest: receiptHash,
		VerifyRound: 1, OpenVerifyHeight: 586, CommitDeadlineHeight: 886, DeadlineHeight: 1286,
		AssignedVerifiers: []string{"verifier-1"}, VerificationSampleSeed: codec.HashBytes([]byte("selection-beacon")),
		Stage: string(layout.StageQueued),
	}

	_, terminal, err := executor.RunVerify(context.Background(), codec.HashBytes([]byte("task-hash")), task)
	// Reaching the model boundary is the point: the window read no longer stops
	// the task before verification is even attempted.
	if err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunVerify() error = %v, want the run to reach the model boundary", err)
	}
	if terminal {
		t.Fatalf("RunVerify() terminal = true, want the task still live")
	}
	if reader.frozen != 1 {
		t.Fatalf("frozen window reads = %d, want exactly 1", reader.frozen)
	}
	if reader.handraise != 0 {
		t.Fatalf("handraise window reads = %d, want 0 -- the verify path must not ask whether it may still raise a hand", reader.handraise)
	}
}

func TestCheckpointInferReceiptDedupsByMaterialDigest(t *testing.T) {
	p := newTestDocumentWorkerPersistence()
	ctx := context.Background()

	receipt := worker.InferReceiptCheckpoint{
		TaskID:         "task-1",
		MaterialDigest: "deadbeef",
		Payload:        []byte("payload-1"),
	}
	if err := p.CheckpointInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("CheckpointInferReceipt first call error = %v", err)
	}
	if err := p.CheckpointInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("CheckpointInferReceipt second call error = %v", err)
	}

	receipts, err := p.InferReceipts(ctx, "task-1")
	if err != nil {
		t.Fatalf("InferReceipts() error = %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("len(receipts) = %d, want 1", len(receipts))
	}
}

func TestCheckpointStorageConfirmationDedups(t *testing.T) {
	p := newTestDocumentWorkerPersistence()
	ctx := context.Background()

	confirmation := worker.StorageConfirmationCheckpoint{
		TaskID:          "task-1",
		DataKind:        "output",
		BuilderOperator: "builder-1",
		MaterialDigest:  "cafebabe",
		SemanticHash:    "hash-1",
		SizeBytes:       42,
		Signature:       []byte("sig-1"),
	}
	if err := p.CheckpointStorageConfirmation(ctx, confirmation); err != nil {
		t.Fatalf("CheckpointStorageConfirmation first call error = %v", err)
	}
	if err := p.CheckpointStorageConfirmation(ctx, confirmation); err != nil {
		t.Fatalf("CheckpointStorageConfirmation second call error = %v", err)
	}

	confirmations, err := p.StorageConfirmations(ctx, "task-1")
	if err != nil {
		t.Fatalf("StorageConfirmations() error = %v", err)
	}
	if len(confirmations) != 1 {
		t.Fatalf("len(confirmations) = %d, want 1", len(confirmations))
	}
}

func TestEvidenceManifestDoesNotStorePayloads(t *testing.T) {
	var last layout.Evidence
	p := newTestEvidenceWorkerPersistence(func(_ context.Context, _ codec.Hash, _ store.InferTask, ev layout.Evidence) error {
		last = ev
		return nil
	})
	ctx := context.Background()

	receipt := worker.InferReceiptCheckpoint{TaskID: "task-1", MaterialDigest: "deadbeef", Payload: []byte("receipt-bytes")}
	if err := p.CheckpointInferReceipt(ctx, receipt); err != nil {
		t.Fatalf("CheckpointInferReceipt: %v", err)
	}
	message := worker.OutboxRecord{TaskID: "task-1", Subject: "subject", Payload: []byte("message-bytes"), Digest: codec.HashBytes([]byte("message-bytes"))}
	if err := p.WriteBuilderOutbox(ctx, message); err != nil {
		t.Fatalf("WriteBuilderOutbox: %v", err)
	}
	confirmation := worker.StorageConfirmationCheckpoint{TaskID: "task-1", DataKind: "output", BuilderOperator: "builder-1", MaterialDigest: "cafebabe", Signature: []byte("sig-bytes")}
	if err := p.CheckpointStorageConfirmation(ctx, confirmation); err != nil {
		t.Fatalf("CheckpointStorageConfirmation: %v", err)
	}

	// Operational artifacts (outbox, confirmation) are not tracked in the manifest.
	var artifactBytes []byte
	for _, a := range last.Artifacts {
		artifactBytes = append(artifactBytes, []byte(a.Kind)...)
	}
	if bytes.Contains(artifactBytes, []byte("worker-outbox:")) || bytes.Contains(artifactBytes, []byte("worker-confirmation:")) {
		t.Fatalf("operational artifacts should not be in evidence manifest: %s", string(artifactBytes))
	}
}

func TestCheckpointInferReceiptRejectsEmptyMaterialDigest(t *testing.T) {
	p := newTestDocumentWorkerPersistence()
	ctx := context.Background()
	err := p.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: "task-1"})
	if err == nil {
		t.Fatalf("CheckpointInferReceipt with empty MaterialDigest error = nil, want error")
	}
}

func newTestEvidenceWorkerPersistence(persist func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error) *evidenceWorkerPersistence {
	ctx := context.Background()
	tmp, err := os.MkdirTemp("", "cortex-daemon-test-")
	if err != nil {
		panic(err)
	}
	hash := codec.HashBytes([]byte("taskhash"))
	root := filepath.Join(tmp, "evidence")
	idx, err := store.Open(ctx, filepath.Join(tmp, "idx"))
	if err != nil {
		panic(err)
	}
	evStore, err := evidence.NewStore(root, idx)
	if err != nil {
		panic(err)
	}
	return &evidenceWorkerPersistence{
		taskHash: hash,
		task:     &store.InferTask{TaskID: "task-1", SessionID: "session-1"},
		evidence: evStore,
		store:    idx,
		persist:  persist,
	}
}

func newTestDocumentWorkerPersistence() *evidenceWorkerPersistence {
	return newTestEvidenceWorkerPersistence(func(_ context.Context, _ codec.Hash, task store.InferTask, ev layout.Evidence) error {
		return nil
	})
}

func TestInferInputPersistenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer idx.Close()
	evStore, err := evidence.NewStore(root, idx)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	p := &evidenceWorkerPersistence{
		taskHash: codec.HashBytes([]byte("taskhash")),
		task:     &store.InferTask{TaskID: "task-1", SessionID: "session-1"},
		evidence: evStore,
		persist: func(_ context.Context, _ codec.Hash, task store.InferTask, ev layout.Evidence) error {
			return nil
		},
	}

	_, err = p.InferInput(ctx, "task-1")
	if !errors.Is(err, worker.ErrCheckpointNotFound) {
		t.Fatalf("InferInput() error = %v, want ErrCheckpointNotFound", err)
	}

	input := []byte("persisted task input")
	if err := p.CheckpointInferInput(ctx, worker.InferInputCheckpoint{TaskID: "task-1", Payload: input}); err != nil {
		t.Fatalf("CheckpointInferInput() error = %v", err)
	}

	got, err := p.InferInput(ctx, "task-1")
	if err != nil {
		t.Fatalf("InferInput() error = %v", err)
	}
	if !bytes.Equal(got.Payload, input) {
		t.Fatalf("InferInput() payload = %q, want %q", got.Payload, input)
	}
}

func TestInferInputRejectsCorruptedPersistedInput(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	idx, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer idx.Close()
	evStore, err := evidence.NewStore(root, idx)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	taskHash := codec.HashBytes([]byte("taskhash"))
	p := &evidenceWorkerPersistence{
		taskHash: taskHash,
		task:     &store.InferTask{TaskID: "task-1", SessionID: "session-1"},
		evidence: evStore,
		persist: func(_ context.Context, _ codec.Hash, task store.InferTask, ev layout.Evidence) error {
			return nil
		},
	}

	input := []byte("persisted task input")
	if err := p.CheckpointInferInput(ctx, worker.InferInputCheckpoint{TaskID: "task-1", Payload: input}); err != nil {
		t.Fatalf("CheckpointInferInput() error = %v", err)
	}

	// Corrupt the stored file by overwriting its contents. The input lives under
	// this task's own directory, so the corruption is planted there rather than
	// in a task-agnostic content-addressed tree.
	digest := codec.HashBytes(input)
	digestHex := hex.EncodeToString(digest[:])
	taskHashHex := hex.EncodeToString(taskHash[:])
	corruptPath := filepath.Join(root, "tasks", taskHashHex[:2], taskHashHex, "input", digestHex)
	if err := os.WriteFile(corruptPath, []byte("corrupted contents"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := p.InferInput(ctx, "task-1")
	if err == nil {
		t.Fatalf("InferInput() = %+v, expected error for corrupted input", got)
	}
}

// TestCheckpointInferOutputSetsFinishReasonAndArtifacts verifies that a single
// CheckpointInferOutput call persists the artifact bytes and updates the
// InferRecord finish reason.
func TestCheckpointInferOutputSetsFinishReasonAndArtifacts(t *testing.T) {
	ctx := context.Background()
	p := newTestEvidenceWorkerPersistence(func(_ context.Context, _ codec.Hash, _ store.InferTask, _ layout.Evidence) error {
		return nil
	})
	if err := layout.MergeInfer(ctx, p.store, layout.StoredHash(p.taskHash), layout.InferRecord{
		TaskID: "task-1",
		Stage:  layout.StageQueued,
	}); err != nil {
		t.Fatalf("seed infer record: %v", err)
	}

	output := []byte("output")
	trace := []byte("trace")
	checkpoint := []byte("checkpoint")
	descriptor := []byte(`{"finish_reason":1}`)
	cp := worker.InferOutputCheckpoint{
		JobID: "job-1", OutputRef: "output-ref", TokenIDsRef: "trace-ref",
		PositionValuesRef: "checkpoint-ref", FinishReason: 1, DescriptorJSON: descriptor,
	}
	if err := p.CheckpointInferOutput(ctx, "task-1", output, trace, checkpoint, cp); err != nil {
		t.Fatalf("CheckpointInferOutput: %v", err)
	}

	for _, kind := range []string{"worker-output", "worker-token-ids-material", "worker-position-values-material", "worker-output-descriptor"} {
		data, err := p.ReadArtifact(ctx, "task-1", kind)
		if err != nil {
			t.Fatalf("ReadArtifact(%s): %v", kind, err)
		}
		if len(data) == 0 {
			t.Fatalf("ReadArtifact(%s) is empty", kind)
		}
	}
	rec, err := layout.GetInferRecord(ctx, p.store, layout.StoredHash(p.taskHash))
	if err != nil {
		t.Fatalf("GetInferRecord: %v", err)
	}
	if rec.FinishReason != layout.FinishReasonEOS {
		t.Fatalf("FinishReason = %q, want %q", rec.FinishReason, layout.FinishReasonEOS)
	}
}

// TestCheckpointInferOutputRefusesConflictingFinishReason verifies that the
// finish reason set by the first checkpoint is not silently overwritten by a
// later call with a different reason.
func TestCheckpointInferOutputRefusesConflictingFinishReason(t *testing.T) {
	ctx := context.Background()
	p := newTestEvidenceWorkerPersistence(func(_ context.Context, _ codec.Hash, _ store.InferTask, _ layout.Evidence) error {
		return nil
	})
	if err := layout.MergeInfer(ctx, p.store, layout.StoredHash(p.taskHash), layout.InferRecord{
		TaskID: "task-1", Stage: layout.StageQueued,
	}); err != nil {
		t.Fatalf("seed infer record: %v", err)
	}

	first := worker.InferOutputCheckpoint{FinishReason: 1, DescriptorJSON: []byte(`{}`)}
	if err := p.CheckpointInferOutput(ctx, "task-1", []byte("o1"), []byte("t1"), []byte("c1"), first); err != nil {
		t.Fatalf("first checkpoint: %v", err)
	}
	second := worker.InferOutputCheckpoint{FinishReason: 2, DescriptorJSON: []byte(`{}`)}
	if err := p.CheckpointInferOutput(ctx, "task-1", []byte("o2"), []byte("t2"), []byte("c2"), second); err == nil {
		t.Fatalf("second checkpoint with different finish reason succeeded, want conflict")
	}
}

// Exercise the real Pebble/evidence adapter, not recordingPersistence's sentinel.
func TestWorkerFinCheckpointStorageErrors(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	ev, err := evidence.NewStore(root, db)
	if err != nil {
		t.Fatal(err)
	}
	hash := codec.HashBytes([]byte("fin-checkpoint"))
	p := &evidenceWorkerPersistence{store: db, evidence: ev, taskHash: hash, task: &store.InferTask{TaskID: "task", SessionID: "session"}}
	p.persist = func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil }
	absent := func() {
		t.Helper()
		if _, err := p.ReadArtifact(ctx, "task", worker.OutputStreamFinKind); !errors.Is(err, worker.ErrCheckpointNotFound) {
			t.Fatalf("unindexed Fin: %v", err)
		}
	}
	absent() // no task index yet
	if err := p.WriteEvidence(ctx, worker.EvidenceRecord{TaskID: "task", Kind: "worker-model-result", Data: []byte("result")}); err != nil {
		t.Fatal(err)
	}
	absent() // normal first Fin: task exists, Fin does not
	data := []byte("retained signed fin")
	if err := p.WriteEvidence(ctx, worker.EvidenceRecord{TaskID: "task", Kind: worker.OutputStreamFinKind, Data: data}); err != nil {
		t.Fatal(err)
	}
	got, err := p.ReadArtifact(ctx, "task", worker.OutputStreamFinKind)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("retained Fin: %q, %v", got, err)
	}
	digest := codec.HashBytes(data)
	path := filepath.Join(root, "tasks", hash.String()[:2], hash.String(), "evidence", "artifacts", digest.String())
	for _, mutation := range []string{"corrupt", "missing"} {
		t.Run(mutation, func(t *testing.T) {
			if mutation == "corrupt" {
				err = os.WriteFile(path, bytes.Repeat([]byte("x"), len(data)), 0600)
			} else {
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.ReadArtifact(ctx, "task", worker.OutputStreamFinKind)
			if err == nil || errors.Is(err, worker.ErrCheckpointNotFound) || errors.Is(err, evidence.ErrArtifactNotFound) {
				t.Fatalf("indexed %s Fin must not permit signing again: %v", mutation, err)
			}
		})
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReadArtifact(ctx, "task", worker.OutputStreamFinKind); err == nil || errors.Is(err, worker.ErrCheckpointNotFound) {
		t.Fatalf("index failure must propagate: %v", err)
	}
}

// A zero-token generation (max_output_duration before the first token) has an
// empty output and an empty position-values artifact. Both are checkpointed
// and read back as empty.
func TestCheckpointInferOutputStoresAZeroTokenGeneration(t *testing.T) {
	ctx := context.Background()
	p := newTestDocumentWorkerPersistence()
	if err := layout.MergeInfer(ctx, p.store, layout.StoredHash(p.taskHash), layout.InferRecord{TaskID: "task-1", Stage: layout.StageQueued}); err != nil {
		t.Fatalf("seed infer record: %v", err)
	}
	tokenIDs, err := modelservice.EncodeTokenIDsArtifact(modelservice.TokenIDs{Input: []uint32{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	positionValues, err := modelservice.EncodePositionValuesArtifact(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(positionValues) != 0 {
		t.Fatalf("an empty position-values artifact is %d bytes; this test expects it empty", len(positionValues))
	}
	cp := worker.InferOutputCheckpoint{JobID: "job-1", OutputRef: "output-ref", TokenIDsRef: "ids-ref",
		PositionValuesRef: "values-ref", FinishReason: nodewire.FinishReasonV1MaxOutputDuration, DescriptorJSON: []byte(`{"finish_reason":4}`)}
	if err := p.CheckpointInferOutput(ctx, "task-1", nil, tokenIDs, positionValues, cp); err != nil {
		t.Fatalf("CheckpointInferOutput of a zero-token generation: %v", err)
	}
	for _, kind := range []string{"worker-output", "worker-position-values-material"} {
		data, err := p.ReadArtifact(ctx, "task-1", kind)
		if err != nil || len(data) != 0 {
			t.Fatalf("ReadArtifact(%s) = %d bytes, %v, want an empty artifact", kind, len(data), err)
		}
	}
}
