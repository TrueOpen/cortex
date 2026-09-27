package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// enableEvidenceSchema wires the locked Profile evidence schema into the worker
// config so the full infer+receipt path can run without the daemon.
func enableEvidenceSchema(h *harness) {
	inputs := workerTestWorkerValueEvidenceInputs()
	h.worker.cfg.EvidenceSchemaHash = inputs.EvidenceSchemaHash
	h.worker.cfg.ProfileEvidenceRequirements = builderclient.WorkerEvidenceRequirementsV3()
	h.worker.cfg.RequiredTopK = workerTestRequiredTopK
}

// NoKeysRemainForTaskID is a shared assertion for crash/cleanup tests. It fails
// if the persistence still holds any receipt record for the given task ID.
func NoKeysRemainForTaskID(t *testing.T, p Persistence, taskID string) {
	t.Helper()
	receipts, err := p.InferReceipts(context.Background(), taskID)
	if err != nil {
		t.Fatalf("InferReceipts: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("receipt keys remain for %s", taskID)
	}
}

// TestCrashAfterReceiptCommitRecoversSameSignedReceipt runs the prepared-output
// path to completion once to obtain the golden signed receipt, then simulates a
// crash immediately after the canonical receipt is persisted and verifies that a
// restarted worker returns byte-identical receipt bytes without re-running
// inference.
func TestCrashAfterReceiptCommitRecoversSameSignedReceipt(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	enableEvidenceSchema(&h)

	golden, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("golden HandleAssignmentFinalized: %v", err)
	}
	goldenBytes, err := json.Marshal(golden.TaskDataReceipt)
	if err != nil {
		t.Fatalf("marshal golden receipt: %v", err)
	}

	// Fresh harness sharing the model/builder/fixtures but with its own
	// persistence, so the crash+restart is independent of the golden run.
	h2 := newHarness(t)
	enableEvidenceSchema(&h2)
	crashed := false
	h2.worker.cfg.CrashHook = func(point string) error {
		if point == CrashPointReceiptCommitted && !crashed {
			crashed = true
			return errors.New("simulated crash after receipt commit")
		}
		return nil
	}
	if _, err := h2.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatalf("expected crash error, got nil")
	}

	// Simulate process restart: new worker instance, same persistence, no hook.
	restarted := New(h2.worker.cfg)
	restarted.cfg.CrashHook = nil
	result, err := restarted.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized after restart: %v", err)
	}
	resultBytes, err := json.Marshal(result.TaskDataReceipt)
	if err != nil {
		t.Fatalf("marshal recovered receipt: %v", err)
	}

	if !bytes.Equal(resultBytes, goldenBytes) {
		t.Fatalf("receipt bytes changed across crash+restart:\n recovered = %s\n golden    = %s", string(resultBytes), string(goldenBytes))
	}
	if h2.model.InferCalls != 1 {
		t.Fatalf("model infer calls = %d, want exactly 1 (no re-run)", h2.model.InferCalls)
	}
	if !result.Started {
		t.Fatalf("result.Started = false, want true after recovery")
	}
}

// TestCrashAfterOutputFsyncRecoversWithoutReRunning verifies that the output
// reference and its descriptor are made durable together, so a crash after the
// sync point recovers the prepared output without re-running inference.
func TestCrashAfterOutputFsyncRecoversWithoutReRunning(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	enableEvidenceSchema(&h)
	crashed := false
	h.worker.cfg.CrashHook = func(point string) error {
		if point == CrashPointOutputFsync && !crashed {
			crashed = true
			return errors.New("simulated crash after output fsync")
		}
		return nil
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatalf("expected crash error, got nil")
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls before restart = %d, want 1", h.model.InferCalls)
	}

	restarted := New(h.worker.cfg)
	restarted.cfg.CrashHook = nil
	if _, err := restarted.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized after restart: %v", err)
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls after restart = %d, want 1 (no re-run)", h.model.InferCalls)
	}
}

// TestCrashHookNoOpByDefault verifies that a nil CrashHook does not disturb the
// normal success path.
func TestCrashHookNoOpByDefault(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	if h.worker.cfg.CrashHook != nil {
		t.Fatalf("default CrashHook should be nil")
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
}

// TestCrashAfterOutputAvailableHeldDoesNotPublishTwice verifies that a crash
// after the OUTPUT_AVAILABLE outbox record is held, but before it is released,
// recovers without publishing the same event twice.
func TestCrashAfterOutputAvailableHeldDoesNotPublishTwice(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	crashed := false
	h.worker.cfg.CrashHook = func(point string) error {
		if point == CrashPointOutputAvailableHeld && !crashed {
			crashed = true
			return errors.New("simulated crash after output available held")
		}
		return nil
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatalf("expected crash error, got nil")
	}

	restarted := New(h.worker.cfg)
	restarted.cfg.CrashHook = nil
	if _, err := restarted.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized after restart: %v", err)
	}

	published := 0
	for _, rec := range h.persistence.outbox {
		if rec.Status == "pending" && rec.Subject == builderclient.NATSOutputAvailableSubject(event.TaskID) {
			published++
		}
	}
	if published != 1 {
		t.Fatalf("OUTPUT_AVAILABLE pending records = %d, want 1", published)
	}
}

// TestCrashAfterOutputAvailableReleasedRecoversResult verifies that a crash
// after OUTPUT_AVAILABLE is released still leaves the task result durable and a
// restart returns it immediately.
func TestCrashAfterOutputAvailableReleasedRecoversResult(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	crashed := false
	h.worker.cfg.CrashHook = func(point string) error {
		if point == CrashPointOutputAvailableReleased && !crashed {
			crashed = true
			return errors.New("simulated crash after output available released")
		}
		return nil
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatalf("expected crash error, got nil")
	}

	restarted := New(h.worker.cfg)
	restarted.cfg.CrashHook = nil
	result, err := restarted.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized after restart: %v", err)
	}
	if !result.Started {
		t.Fatalf("result.Started = false, want true")
	}
}

// TestCrashAfterReceiptSignedRecovers verifies that a crash after the legacy
// receipt is signed, but before the canonical receipt is persisted, recovers
// by rebuilding the receipt from the durable artifacts and descriptor.
func TestCrashAfterReceiptSignedRecovers(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	enableEvidenceSchema(&h)
	crashed := false
	h.worker.cfg.CrashHook = func(point string) error {
		if point == CrashPointReceiptSigned && !crashed {
			crashed = true
			return errors.New("simulated crash after receipt signed")
		}
		return nil
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatalf("expected crash error, got nil")
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls before restart = %d, want 1", h.model.InferCalls)
	}

	restarted := New(h.worker.cfg)
	restarted.cfg.CrashHook = nil
	if _, err := restarted.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized after restart: %v", err)
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls after restart = %d, want 1 (no re-run)", h.model.InferCalls)
	}
}

// The completed model response permits recovering artifact references without
// rerunning generation, even before the final output checkpoint is written.
func TestCrashAfterPackageSaveResumesCompletedModelResponse(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	enableEvidenceSchema(&h)
	crashed := false
	h.worker.cfg.CrashHook = func(point string) error {
		if point == CrashPointBuilderSaveOutputPackage && !crashed {
			crashed = true
			return errors.New("simulated crash after builder save output package")
		}
		return nil
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil {
		t.Fatalf("expected crash error, got nil")
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls before restart = %d, want 1", h.model.InferCalls)
	}

	restarted := New(h.worker.cfg)
	restarted.cfg.CrashHook = nil
	if _, err := restarted.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("restart did not resume completed generation: %v", err)
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls after restart = %d, want no re-run", h.model.InferCalls)
	}
}

// TestValidateOutputPackageHappensAfterArtifactCheckpoint verifies that the
// builder only sees the output package after the infer output, trace, checkpoint
// and descriptor have been checkpointed.
func TestValidateOutputPackageHappensAfterArtifactCheckpoint(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	enableEvidenceSchema(&h)

	events := []string{}
	h.persistence.events = &events
	h.builder.Events = &events
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}

	checkpointIndex := -1
	validateIndex := -1
	for i, e := range events {
		switch e {
		case "checkpoint:infer-output":
			checkpointIndex = i
		case "builder:validate":
			validateIndex = i
		}
	}
	if checkpointIndex == -1 {
		t.Fatalf("checkpoint:infer-output not recorded")
	}
	if validateIndex == -1 {
		t.Fatalf("builder validate not recorded")
	}
	if checkpointIndex > validateIndex {
		t.Fatalf("ValidateOutputPackage happened before CheckpointInferOutput")
	}
}
