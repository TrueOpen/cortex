package evidence

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

var (
	ErrCleanupDigestRequired = errors.New("cleanup plan digest required")
	ErrCleanupDigestMismatch = errors.New("cleanup plan digest mismatch")
)

type CleanupConfig struct {
	Root                   string
	Index                  MetadataStore
	TaskHashes             []codec.Hash
	CurrentHeight          uint64
	RetentionPolicyVersion string
	MinimumRetentionBlocks uint64
	TaskStatus             func(context.Context, codec.Hash) (TaskCleanupStatus, error)
	// ConfirmDigest is the operator-supplied plan digest. Cleanup refuses to
	// delete anything until it matches the deterministic digest recomputed
	// from the current eligible evidence.
	ConfirmDigest string
	// SweepGracePeriod is how long a trashed task directory must remain on disk
	// before Sweep will delete it.
	SweepGracePeriod time.Duration
	removeTask       func(string) error
}

// TaskCleanupStatus is the authoritative task lifecycle information cleanup
// needs but the compact evidence index deliberately does not persist.
type TaskCleanupStatus struct {
	TerminalOrSettled bool
	OpenChallenge     bool
}

type CleanupResult struct {
	Scanned int
	Cleaned int
	// Trashed counts task directories moved out of the live tree by this call.
	// It is lower than Cleaned whenever a task had no local bytes left to move,
	// which is the normal shape of a retried cleanup.
	Trashed int
	Records []CleanupRecord
}

type CleanupPlan struct {
	CurrentHeight          uint64            `json:"current_height"`
	RetentionPolicyVersion string            `json:"retention_policy_version"`
	MinimumRetentionBlocks uint64            `json:"minimum_retention_blocks"`
	Digest                 string            `json:"digest"`
	Items                  []CleanupPlanItem `json:"items"`
}

type CleanupPlanItem struct {
	TaskHash             string `json:"task_hash"`
	DigestSHA256         string `json:"digest_sha256"`
	SizeBytes            uint64 `json:"size_bytes"`
	CleanupHeight        uint64 `json:"cleanup_height"`
	FinalityHeight       uint64 `json:"finality_height"`
	RetentionStartHeight uint64 `json:"retention_start_height"`
	TerminalOrSettled    bool   `json:"terminal_or_settled"`
	Action               string `json:"action"`
}

type CleanupRecord struct {
	TaskHash          string `json:"task_hash"`
	DigestSHA256      string `json:"digest_sha256"`
	SizeBytes         uint64 `json:"size_bytes"`
	TerminalOrSettled bool   `json:"terminal_or_settled"`
}

type CleanupError struct {
	TaskHash  codec.Hash
	Operation string
	Err       error
}

func (e *CleanupError) Error() string {
	return fmt.Sprintf("evidence cleanup task %x %s: %v", e.TaskHash, e.Operation, e.Err)
}

func (e *CleanupError) Unwrap() error { return e.Err }

type cleanupItem struct {
	taskHash codec.Hash
	metadata layout.Evidence
}

func PlanCleanup(ctx context.Context, cfg CleanupConfig) (CleanupPlan, error) {
	if err := validateCleanupConfig(ctx, cfg); err != nil {
		return CleanupPlan{}, err
	}
	items, err := eligibleEvidence(ctx, cfg)
	if err != nil {
		return CleanupPlan{}, err
	}
	plan := CleanupPlan{
		CurrentHeight: cfg.CurrentHeight, RetentionPolicyVersion: cfg.RetentionPolicyVersion,
		MinimumRetentionBlocks: cfg.MinimumRetentionBlocks,
	}
	for _, item := range items {
		plan.Items = append(plan.Items, CleanupPlanItem{
			TaskHash: hex.EncodeToString(item.taskHash[:]), DigestSHA256: hex.EncodeToString(item.metadata.Digest[:]),
			SizeBytes: item.metadata.Size, CleanupHeight: item.metadata.CleanupHeight,
			FinalityHeight: item.metadata.FinalityHeight, RetentionStartHeight: item.metadata.RetentionStartHeight,
			TerminalOrSettled: item.metadata.TerminalOrSettled, Action: "delete",
		})
	}
	plan.Digest = cleanupPlanDigest(plan)
	return plan, nil
}

func Cleanup(ctx context.Context, cfg CleanupConfig) (CleanupResult, error) {
	if err := validateCleanupConfig(ctx, cfg); err != nil {
		return CleanupResult{}, err
	}

	plan, err := PlanCleanup(ctx, cfg)
	if err != nil {
		return CleanupResult{}, err
	}

	if cfg.ConfirmDigest == "" {
		return CleanupResult{}, fmt.Errorf("%w", ErrCleanupDigestRequired)
	}
	if plan.Digest != cfg.ConfirmDigest {
		return CleanupResult{}, fmt.Errorf("%w: got %s want %s", ErrCleanupDigestMismatch, plan.Digest, cfg.ConfirmDigest)
	}

	result := CleanupResult{Scanned: len(plan.Items)}
	for _, item := range plan.Items {
		taskHashBytes, err := hex.DecodeString(item.TaskHash)
		if err != nil || len(taskHashBytes) != len(codec.Hash{}) {
			return result, fmt.Errorf("invalid task hash in cleanup plan: %s", item.TaskHash)
		}
		var taskHash codec.Hash
		copy(taskHash[:], taskHashBytes)

		status, err := cfg.TaskStatus(ctx, taskHash)
		if err != nil {
			return result, cleanupFailure(taskHash, "recheck task cleanup status", err)
		}
		if !status.TerminalOrSettled || status.OpenChallenge {
			continue
		}
		// Move the whole task directory out of the live tree before the index
		// rows go, in that order. The trash locator is derived from the task
		// hash, so the renamed directory is itself the durable cleanup-pending
		// marker: a crash after the rename and before the index delete leaves a
		// task whose row still says "eligible" and whose directory is already
		// gone, and the next cleanup finds nothing to move and completes the
		// index delete. The reverse order would drop the only record of which
		// bytes were still owed a deletion.
		moved, err := trashTaskDirectory(cfg.Root, taskHash)
		if err != nil {
			return result, cleanupFailure(taskHash, "move task directory to trash", err)
		}
		if moved {
			result.Trashed++
		}
		if err := cfg.Index.CleanupEvidence(ctx, taskHash); err != nil {
			return result, cleanupFailure(taskHash, "cleanup evidence", err)
		}
		result.Cleaned++
		result.Records = append(result.Records, CleanupRecord{
			TaskHash: item.TaskHash, DigestSHA256: item.DigestSHA256,
			SizeBytes: item.SizeBytes, TerminalOrSettled: item.TerminalOrSettled,
		})
	}
	// Draining trash is idempotent and bounded by what is in there, so finish
	// the job in the same call rather than leaving deletion to an unscheduled
	// background runner. Whatever this pass does not remove - grace period, a
	// transient error - stays in trash/ and the next Sweep resumes it, which is
	// also how a crash mid-delete is recovered.
	if _, err := Sweep(ctx, cfg); err != nil {
		return result, err
	}
	return result, nil
}

// SweepResult reports what the trash drain did.
type SweepResult struct {
	Scanned int
	Removed int
	// Pending counts trashed task directories this pass deliberately left in
	// place, which today means only those still inside the grace period.
	Pending int
}

// Sweep deletes trashed task directories that are older than the configured
// grace period. It is the whole of local space reclamation: because a task
// directory shares no physical file with any other task, there is nothing to
// reference-count and no orphan to hunt - a directory under trash/ is garbage
// by construction. It is idempotent: a crash mid-sweep leaves the remainder for
// the next sweep.
func Sweep(ctx context.Context, cfg CleanupConfig) (SweepResult, error) {
	var result SweepResult
	if err := cfg.Index.WithArtifactLock(func() error {
		var err error
		result, err = sweepLocked(ctx, cfg)
		return err
	}); err != nil {
		return SweepResult{}, err
	}
	return result, nil
}

func sweepLocked(ctx context.Context, cfg CleanupConfig) (SweepResult, error) {
	if err := validateCleanupConfig(ctx, cfg); err != nil {
		return SweepResult{}, err
	}
	realRoot, err := resolveTrustedRoot(cfg.Root)
	if err != nil {
		return SweepResult{}, err
	}

	removeTask := cfg.removeTask
	if removeTask == nil {
		removeTask = func(path string) error {
			return removeTrashedTaskDirectory(realRoot, path)
		}
	}

	cutoff := time.Now().Add(-cfg.SweepGracePeriod)
	var result SweepResult
	if _, err := resolveEvidencePath(realRoot, trashRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return result, err
	}
	trashDir := filepath.Join(realRoot, trashRoot)
	shards, err := os.ReadDir(trashDir)
	if err != nil {
		return result, err
	}
	for _, shard := range shards {
		// Shape first, then the symlink check, then the directory check. The
		// reverse order let a shard replaced by a symlink fall out of the
		// IsDir filter and be skipped in silence: nothing outside the root was
		// deleted, but a tampered tree drained forever without ever saying so.
		if !validShardHex(shard.Name()) {
			continue
		}
		if _, err := resolveEvidencePath(realRoot, filepath.Join(trashRoot, shard.Name())); err != nil {
			return result, err
		}
		if !shard.IsDir() {
			continue
		}
		shardPath := filepath.Join(trashDir, shard.Name())
		tasks, err := os.ReadDir(shardPath)
		if err != nil {
			return result, err
		}
		for _, task := range tasks {
			if !validSHA256Hex(task.Name()) || task.Name()[:2] != shard.Name() {
				continue
			}
			if _, err := resolveEvidencePath(realRoot, filepath.Join(trashRoot, shard.Name(), task.Name())); err != nil {
				return result, err
			}
			if !task.IsDir() {
				continue
			}
			taskPath := filepath.Join(shardPath, task.Name())
			info, err := task.Info()
			if err != nil {
				return result, err
			}
			result.Scanned++
			if info.ModTime().After(cutoff) {
				result.Pending++
				continue
			}
			if err := removeTask(taskPath); err != nil {
				return result, err
			}
			result.Removed++
		}
	}
	return result, nil
}

// trashTaskDirectory renames a task's whole local directory to
// trash/<prefix>/<taskHash>. It reports false when the task had no directory
// left to move, which is the idempotent case of a retried cleanup.
func trashTaskDirectory(root string, taskHash codec.Hash) (bool, error) {
	realRoot, err := resolveTrustedRoot(root)
	if err != nil {
		return false, err
	}
	source := filepath.Join(realRoot, taskRelDir(taskHash))
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, ErrEvidenceEscape
	}
	destination := filepath.Join(realRoot, trashRelDir(taskHash))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return false, err
	}
	// A destination left by an interrupted earlier cleanup holds bytes that were
	// already condemned, so it is dropped rather than merged with the live
	// directory being retired.
	if _, err := os.Lstat(destination); err == nil {
		if err := removeTrashedTaskDirectory(realRoot, destination); err != nil {
			return false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.Rename(source, destination); err != nil {
		return false, err
	}
	if err := fsyncDir(filepath.Dir(source)); err != nil {
		return false, err
	}
	if err := fsyncDir(filepath.Dir(destination)); err != nil {
		return false, err
	}
	return true, nil
}

// resolveTrustedRoot resolves the configured root and re-applies the ownership
// and permission precondition. Cleanup resolves the root itself rather than
// reusing the one NewStore pinned, so it has to make the same trust check: it
// deletes directories under a tree it re-resolved, and without this,
// retargeting the configured symlink between a store opening and a cleanup
// would point the delete at another tree that nothing had ever vouched for.
func resolveTrustedRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	realRoot, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	if err := verifyRootTrust(realRoot); err != nil {
		return "", err
	}
	return realRoot, nil
}

func validateCleanupConfig(ctx context.Context, cfg CleanupConfig) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cfg.Index == nil {
		return fmt.Errorf("evidence cleanup index is required")
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return fmt.Errorf("evidence root is required")
	}
	if cfg.SweepGracePeriod < 0 {
		return fmt.Errorf("sweep grace period must not be negative")
	}
	return nil
}

func eligibleEvidence(ctx context.Context, cfg CleanupConfig) ([]cleanupItem, error) {
	hashes := append([]codec.Hash(nil), cfg.TaskHashes...)
	if len(hashes) == 0 {
		enumerator, ok := cfg.Index.(MetadataEnumerator)
		if !ok {
			return nil, fmt.Errorf("evidence cleanup index cannot enumerate evidence")
		}
		entries, err := enumerator.ListEvidence(ctx)
		if err != nil {
			return nil, fmt.Errorf("enumerate evidence: %w", err)
		}
		for _, entry := range entries {
			hashes = append(hashes, entry.TaskHash)
		}
	}
	sort.Slice(hashes, func(i, j int) bool {
		return strings.Compare(hex.EncodeToString(hashes[i][:]), hex.EncodeToString(hashes[j][:])) < 0
	})
	cutoff := retentionCutoffHeight(cfg.CurrentHeight, cfg.MinimumRetentionBlocks)
	items := make([]cleanupItem, 0, len(hashes))
	var previous codec.Hash
	havePrevious := false
	for _, taskHash := range hashes {
		if havePrevious && taskHash == previous {
			continue
		}
		previous, havePrevious = taskHash, true
		metadata, err := cfg.Index.Evidence(ctx, taskHash)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, cleanupFailure(taskHash, "read metadata", err)
		}
		// Spec eligibility 5 and 7: nonzero, nonfuture RetentionStartHeight, and
		// currentHeight - RetentionStartHeight >= MinimumRetentionBlocks. The
		// clock is RetentionStartHeight, not FinalityHeight: a task that reached
		// terminal without a settlement finality has no finality height at all,
		// and gating on that one retained its evidence forever.
		heightEligible := metadata.CleanupHeight > 0 && metadata.CleanupHeight <= cfg.CurrentHeight &&
			metadata.RetentionStartHeight > 0 && metadata.RetentionStartHeight <= cutoff
		if !heightEligible {
			continue
		}
		// A missing callback is deliberately fail-closed. The daemon must wire
		// authoritative task/challenge state before any package is discoverable
		// as deletable.
		if cfg.TaskStatus == nil {
			continue
		}
		status, err := cfg.TaskStatus(ctx, taskHash)
		if err != nil {
			return nil, cleanupFailure(taskHash, "read task cleanup status", err)
		}
		if status.TerminalOrSettled && !status.OpenChallenge {
			items = append(items, cleanupItem{taskHash: taskHash, metadata: metadata})
		}
	}
	return items, nil
}

func cleanupPlanDigest(plan CleanupPlan) string {
	parts := make([][]byte, 0, 3+len(plan.Items)*8)
	parts = append(parts, codec.Uint64Bytes(plan.CurrentHeight), []byte(plan.RetentionPolicyVersion), codec.Uint64Bytes(plan.MinimumRetentionBlocks))
	for _, item := range plan.Items {
		parts = append(parts, []byte(item.TaskHash), []byte(item.DigestSHA256), codec.Uint64Bytes(item.SizeBytes),
			codec.Uint64Bytes(item.CleanupHeight), codec.Uint64Bytes(item.FinalityHeight),
			codec.Uint64Bytes(item.RetentionStartHeight), []byte(item.Action))
		if item.TerminalOrSettled {
			parts = append(parts, []byte{1})
		} else {
			parts = append(parts, []byte{0})
		}
	}
	// V3: the preimage gained RetentionStartHeight, which is the height
	// eligibility now turns on. The digest has to commit to the facts the
	// decision used, or a replan could match on a stale reason.
	digest := codec.HashWithDomain("CORTEX_EVIDENCE_CLEANUP_PLAN_V3", parts...)
	return hex.EncodeToString(digest[:])
}

func retentionCutoffHeight(currentHeight, minimumRetentionBlocks uint64) uint64 {
	if currentHeight < minimumRetentionBlocks {
		return 0
	}
	return currentHeight - minimumRetentionBlocks
}

func cleanupFailure(taskHash codec.Hash, operation string, err error) error {
	return &CleanupError{TaskHash: taskHash, Operation: operation, Err: err}
}

// removeTrashedTaskDirectory deletes one condemned task directory. It refuses
// anything that is not a plain directory under the root, and it walks the path
// once more before deleting: a component replaced by a symlink must never turn
// reclaiming local space into a delete somewhere else.
func removeTrashedTaskDirectory(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if _, err := resolveEvidencePath(root, rel); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrEvidenceEscape
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func validSHA256Hex(value string) bool {
	return len(value) == 64 && lowercaseHex(value)
}

// validShardHex matches the two-character shard directory of the task and trash
// trees.
func validShardHex(value string) bool {
	return len(value) == 2 && lowercaseHex(value)
}

func lowercaseHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// OpenChallengeDiagnostic describes one task that currently holds open
// challenges, along with the age of the evidence record in blocks.
type OpenChallengeDiagnostic struct {
	TaskHash          string   `json:"task_hash"`
	ChallengeIDs      []string `json:"challenge_ids"`
	EvidenceAgeBlocks uint64   `json:"evidence_age_blocks"`
}

// CleanupDiagnosticsReport reports retention and sweep state for the evidence store.
type CleanupDiagnosticsReport struct {
	CurrentHeight    uint64                    `json:"current_height"`
	RetainedBytes    uint64                    `json:"retained_bytes"`
	CleanupAgeBlocks uint64                    `json:"cleanup_age_blocks"`
	OpenChallenges   []OpenChallengeDiagnostic `json:"open_challenges"`
	Sweep            SweepResult               `json:"sweep"`
}

// CleanupDiagnostics returns the current retention picture: total retained
// bytes, the oldest cleanup age among stored evidence, the open challenge IDs
// and their ages, and the result of a fresh sweep pass.
func CleanupDiagnostics(ctx context.Context, cfg CleanupConfig) (CleanupDiagnosticsReport, error) {
	if err := validateCleanupConfig(ctx, cfg); err != nil {
		return CleanupDiagnosticsReport{}, err
	}

	entries, err := listEvidenceEntries(ctx, cfg)
	if err != nil {
		return CleanupDiagnosticsReport{}, err
	}

	var retained uint64
	var maxAge uint64
	var open []OpenChallengeDiagnostic
	for _, entry := range entries {
		ev := entry.Evidence
		retained += ev.Size

		var age uint64
		if cfg.CurrentHeight > ev.CleanupHeight {
			age = cfg.CurrentHeight - ev.CleanupHeight
		}
		if age > maxAge {
			maxAge = age
		}

		challengeIDs, err := cfg.Index.ListEvidenceChallenges(ctx, entry.TaskHash)
		if err != nil {
			return CleanupDiagnosticsReport{}, err
		}
		if len(challengeIDs) > 0 {
			ids := make([]string, len(challengeIDs))
			copy(ids, challengeIDs)
			sort.Strings(ids)
			open = append(open, OpenChallengeDiagnostic{
				TaskHash:          hex.EncodeToString(entry.TaskHash[:]),
				ChallengeIDs:      ids,
				EvidenceAgeBlocks: age,
			})
		}
	}

	sweep, err := Sweep(ctx, cfg)
	if err != nil {
		return CleanupDiagnosticsReport{}, err
	}

	return CleanupDiagnosticsReport{
		CurrentHeight:    cfg.CurrentHeight,
		RetainedBytes:    retained,
		CleanupAgeBlocks: maxAge,
		OpenChallenges:   open,
		Sweep:            sweep,
	}, nil
}

func listEvidenceEntries(ctx context.Context, cfg CleanupConfig) ([]layout.EvidenceEntry, error) {
	enumerator, ok := cfg.Index.(MetadataEnumerator)
	if !ok {
		return nil, fmt.Errorf("evidence cleanup index cannot enumerate evidence")
	}
	return enumerator.ListEvidence(ctx)
}
