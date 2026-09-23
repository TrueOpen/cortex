package daemon

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/worker"
)

func TestStorageConfirmationCheckpointPreservesFirstVerificationAtomically(t *testing.T) {
	ctx := context.Background()
	p := newTestEvidenceWorkerPersistence(func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil })
	first := time.Unix(100, 0).UTC()
	record := worker.StorageConfirmationCheckpoint{TaskID: p.task.TaskID, DataKind: "OUTPUT", BuilderOperator: "builder", MaterialDigest: "digest", Signature: []byte("signature"), VerifiedAt: first}
	if err := p.CheckpointStorageConfirmation(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.VerifiedAt = first.Add(time.Minute)
	if err := p.CheckpointStorageConfirmation(ctx, record); err != nil {
		t.Fatalf("idempotent finalization after partial progress: %v", err)
	}
	got, err := p.StorageConfirmations(ctx, record.TaskID)
	if err != nil || len(got) != 1 {
		t.Fatalf("restore confirmation: %v %v", got, err)
	}
	if !got[0].VerifiedAt.Equal(first) || !bytes.Equal(got[0].Signature, record.Signature) {
		t.Fatalf("lost first complete verification: %+v", got[0])
	}
	artifacts, err := p.evidence.TaskArtifacts(ctx, p.taskHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range artifacts {
		if strings.HasPrefix(string(artifact.Kind), "worker-confirmation:") {
			t.Fatal("signature must not require a second independent write")
		}
	}
	record.Signature = []byte("different-signature")
	if err := p.CheckpointStorageConfirmation(ctx, record); err == nil {
		t.Fatal("conflicting receipt overwrote the saved verification")
	}
}

func TestWireRoundTwoIsNeverPersistedAsRoundOne(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var refused error
	runner := NewTaskRunner(TaskRunnerConfig{Store: db, LocalVerifierAddress: outputTestWorker, OnQuarantinedEffect: func(_ ReconcilerEffect, err error) { refused = err }})
	hash := codec.HashBytes([]byte("round-two-task"))
	effect := ReconcilerEffect{Type: ReconcilerEffectVerifyReady, TaskHash: hash, TaskID: outputTestTaskID, Snapshot: chainclient.TaskSnapshot{VerifierAssignment: chainclient.VerifierAssignmentSnapshot{VerifyRound: chainclient.NewUint64String(2), FormalVerifierSet: chainclient.CSVStrings{outputTestWorker}}}}
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{effect}); err != nil {
		t.Fatal(err)
	}
	if refused == nil || !strings.Contains(refused.Error(), "unsupported verify_round 2") {
		t.Fatalf("missing explicit refusal: %v", refused)
	}
	if _, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("round two created a round-one record: %v", err)
	}
}
