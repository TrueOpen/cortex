package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// legacyArtifactKinds are evidence kinds only a pre-v0.3 node wrote: the
// Worker trace and checkpoint the v0.3 two-bundle evidence replaced.
var legacyArtifactKinds = map[string]bool{"worker-trace": true, "worker-checkpoint": true}

// LegacyTaskStatus reports whether a task is terminal or settled and whether it
// still has an open challenge; it is the callback evidence cleanup uses.
type LegacyTaskStatus func(context.Context, codec.Hash) (evidence.TaskCleanupStatus, error)

// RefuseLegacyState stops startup only when pre-v0.3 task data belongs to a
// task that can still need work: one that is not terminal or settled, or that
// has an open challenge. Such a task can neither be finished nor verified under
// v0.3, and skipping it would drop a responsibility the chain still expects.
//
// Pre-v0.3 evidence of a finished task is only waiting for retention cleanup,
// which runs through this daemon's own admin API; it is logged and left for
// that cleanup instead of blocking the start that cleanup needs.
//
// Legacy data is trace or checkpoint evidence, or an infer receipt that is not
// a readable V3 receipt.
func RefuseLegacyState(ctx context.Context, db *store.Store, ev *evidence.Store, status LegacyTaskStatus) error {
	entries, err := layout.ListEvidence(ctx, db)
	if err != nil {
		return fmt.Errorf("scan stored evidence for pre-v0.3 data: %w", err)
	}
	var blocking []string
	for _, entry := range entries {
		reason := legacyReason(ctx, ev, entry)
		if reason == "" {
			continue
		}
		item := fmt.Sprintf("task %s %s", entry.Evidence.TaskID, reason)
		live := true
		if status != nil {
			taskStatus, err := status(ctx, entry.TaskHash)
			if err != nil {
				return fmt.Errorf("the store holds pre-v0.3 task data (%s) and its task status cannot be read (%v); drain in-flight "+
					"tasks on the previous release before upgrading, or start from an empty store", item, err)
			}
			live = !taskStatus.TerminalOrSettled || taskStatus.OpenChallenge
		}
		if !live {
			slog.Warn("pre-v0.3 evidence of a finished task is left for retention cleanup", "item", item)
			continue
		}
		blocking = append(blocking, item)
	}
	if len(blocking) > 0 {
		return fmt.Errorf("the store holds pre-v0.3 data of %d unfinished task(s), first: %s; drain every in-flight task on the "+
			"previous release before upgrading, or start from an empty store", len(blocking), blocking[0])
	}
	return nil
}

// legacyReason names the first pre-v0.3 artifact of a task, or "".
func legacyReason(ctx context.Context, ev *evidence.Store, entry layout.EvidenceEntry) string {
	for _, artifact := range entry.Evidence.Artifacts {
		kind := string(artifact.Kind)
		if legacyArtifactKinds[kind] {
			return "kind " + kind
		}
		if !strings.HasPrefix(kind, "worker-infer-receipt:") || ev == nil {
			continue
		}
		payload, err := ev.ReadTaskKind(ctx, entry.TaskHash, kind)
		if err != nil {
			// An indexed receipt that cannot be read is no more usable than an
			// old one, and gets the same guidance.
			return "unreadable infer receipt"
		}
		var receipt struct{ SchemaVersion uint32 }
		if err := json.Unmarshal(payload, &receipt); err != nil || receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV3 {
			return fmt.Sprintf("infer receipt schema %d", receipt.SchemaVersion)
		}
	}
	return ""
}
