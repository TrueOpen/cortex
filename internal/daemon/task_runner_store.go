package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// errInferCheckpointOrphaned reports that the infer record a checkpoint would
// have been merged into no longer exists, so there is nothing to write - not
// that the checkpoint failed.
//
// The distinction is the whole point. A terminal Keeper event deletes the infer
// record (ReconcilerEffectInferTerminal, and TaskTerminalBatch deletes the task
// record with it) while the executor that owns the responsibility may still be
// finishing a step, and a checkpoint arriving after that is a legitimate race,
// not a fault: the artifact bytes are already durable in the evidence store
// before any merge is attempted, and the merge target is gone precisely because
// nobody will read it again. Returning a plain error here reported one
// successful infer round as failed and - far worse - aborted the caller mid-step,
// which is how a Worker lost its OUTPUT_AVAILABLE publication. Callers treat
// this as a no-op success; see commitManifest.
var errInferCheckpointOrphaned = errors.New("infer checkpoint has no owning record")

func (r *TaskRunner) persistInferCheckpoint(ctx context.Context, taskHash codec.Hash, checkpoint store.InferTask, ev layout.Evidence) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, err := layout.GetInferRecord(ctx, r.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("infer record %x: %w", taskHash, errInferCheckpointOrphaned)
		}
		return err
	}
	if rec.TaskID == "" || rec.TaskID != checkpoint.TaskID {
		return fmt.Errorf("owning infer task %x is no longer active: %w", taskHash, errInferCheckpointOrphaned)
	}
	tr, err := layout.GetTaskRecord(ctx, r.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("task record %x: %w", taskHash, errInferCheckpointOrphaned)
		}
		return err
	}
	// A session mismatch is NOT orphaning. The record exists and names a
	// different session, which is a divergence between this node's durable state
	// and the checkpoint's claim - it must stay loud.
	if tr.SessionID != checkpoint.SessionID {
		return fmt.Errorf("owning infer task %x session mismatch", taskHash)
	}
	if err := layout.MergeInferWithEvidence(ctx, r.cfg.Store, layout.StoredHash(taskHash), rec, ev); err != nil {
		return err
	}
	return nil
}

// loadActiveTasks loads active tasks from the new layout records.
func (r *TaskRunner) loadActiveTasks(ctx context.Context) (map[codec.Hash]store.InferTask, map[codec.Hash]store.VerifyTask, error) {
	infer := make(map[codec.Hash]store.InferTask)
	verify := make(map[codec.Hash]store.VerifyTask)

	inferHashes, inferRecords, err := layout.ListInferRecords(ctx, r.cfg.Store)
	if err != nil {
		return infer, verify, err
	}
	for i, h := range inferHashes {
		if h.IsZero() {
			continue
		}
		rec := inferRecords[i]
		if rec.Stage == layout.StageSucceeded || rec.Stage == layout.StageFailed {
			continue
		}
		tr, err := layout.GetTaskRecord(ctx, r.cfg.Store, h)
		if err != nil {
			return infer, verify, err
		}
		// A missing mapping is not fatal here: the task stays loaded without a
		// capability and the executor's own precheck refuses it by name. Dropping
		// the row instead would hide an assigned responsibility.
		capability, _ := r.capabilityFor(tr.ModelID, tr.ProfileVersion)
		infer[codec.Hash(h)] = inferTaskFromRecords(tr, rec, capability)
	}

	verifyHashes, verifyRecords, err := layout.ListVerifyRecords(ctx, r.cfg.Store)
	if err != nil {
		return infer, verify, err
	}
	for i, h := range verifyHashes {
		if h.IsZero() {
			continue
		}
		rec := verifyRecords[i]
		if rec.Stage == layout.StageSucceeded || rec.Stage == layout.StageFailed {
			continue
		}
		tr, err := layout.GetTaskRecord(ctx, r.cfg.Store, h)
		if err != nil {
			return infer, verify, err
		}
		capability, _ := r.capabilityFor(tr.ModelID, tr.ProfileVersion)
		verify[codec.Hash(h)] = verifyTaskFromRecords(tr, rec, capability)
	}

	return infer, verify, nil
}

// persistInferTaskToLayout mirrors one updated infer task back to the layout
// when a layout record already exists. A task that only lives in the legacy
// active document is skipped; it will be migrated once its callers seed layout
// records.
//
// One task, not the whole active set: it replaces a sweep that rewrote every
// active infer record whenever any one of them changed. That sweep was safe only
// while executions could not outlive the pass that read them - with overlapping
// passes it would write a running task's pre-run stage over the stage its own
// executor had just committed. The record is re-read here rather than carried
// in so the stable fields (and anything a Keeper effect advanced meanwhile) come
// from the current document; only the execution fields come from the task.
func (r *TaskRunner) persistInferTaskToLayout(ctx context.Context, hash codec.Hash, task store.InferTask) error {
	rec, err := layout.GetInferRecord(ctx, r.cfg.Store, layout.StoredHash(hash))
	if err != nil || rec.TaskID == "" {
		return nil
	}
	return layout.MergeInfer(ctx, r.cfg.Store, layout.StoredHash(hash), inferRecordFromTask(task, rec))
}

// persistVerifyTaskToLayout is the verify half of persistInferTaskToLayout, with
// the same scope and for the same reason.
func (r *TaskRunner) persistVerifyTaskToLayout(ctx context.Context, hash codec.Hash, task store.VerifyTask) error {
	rec, err := layout.GetVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(hash))
	if err != nil || rec.TaskID == "" {
		return nil
	}
	return layout.MergeVerify(ctx, r.cfg.Store, layout.StoredHash(hash), verifyRecordFromTask(task, rec))
}

func mergeInferExecution(current, updated store.InferTask) store.InferTask {
	if updated.TaskID == "" {
		return current
	}
	current.Stage = updated.Stage
	current.OutputCID, current.OutputDigest = updated.OutputCID, updated.OutputDigest
	current.ReceiptCID, current.ReceiptDigest = updated.ReceiptCID, updated.ReceiptDigest
	return current
}

func mergeVerifyExecution(current, updated store.VerifyTask) store.VerifyTask {
	if updated.TaskID == "" {
		return current
	}
	current.Stage = updated.Stage
	current.ReceiptCID, current.ReceiptDigest = updated.ReceiptCID, updated.ReceiptDigest
	// A stop the executor decided itself (a failed Stage with its reason) must
	// keep that reason; a later failure overwrites it through applyRunFailure.
	current.LastError = updated.LastError
	return current
}

func copyInfer(in map[codec.Hash]store.InferTask) map[codec.Hash]store.InferTask {
	out := make(map[codec.Hash]store.InferTask, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyVerify(in map[codec.Hash]store.VerifyTask) map[codec.Hash]store.VerifyTask {
	out := make(map[codec.Hash]store.VerifyTask, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
