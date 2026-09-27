package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// legacyArtifactKinds are evidence kinds only a pre-v0.3 node wrote: the
// Worker trace and checkpoint the v0.3 two-bundle evidence replaced.
var legacyArtifactKinds = map[string]bool{"worker-trace": true, "worker-checkpoint": true}

// RefuseLegacyState stops startup when the store holds task data written by a
// pre-v0.3 node: trace/checkpoint evidence, or an infer receipt of an older
// schema. Such a task can neither be finished nor verified under v0.3, and
// silently skipping it would drop a responsibility the chain still expects,
// so the operator must drain those tasks on the previous release first.
func RefuseLegacyState(ctx context.Context, db *store.Store, ev *evidence.Store) error {
	entries, err := layout.ListEvidence(ctx, db)
	if err != nil {
		return fmt.Errorf("scan stored evidence for pre-v0.3 data: %w", err)
	}
	var legacy []string
	for _, entry := range entries {
		for _, artifact := range entry.Evidence.Artifacts {
			kind := string(artifact.Kind)
			if legacyArtifactKinds[kind] {
				legacy = append(legacy, fmt.Sprintf("task %s kind %s", entry.Evidence.TaskID, kind))
				continue
			}
			if !strings.HasPrefix(kind, "worker-infer-receipt:") || ev == nil {
				continue
			}
			payload, err := ev.ReadTaskKind(ctx, entry.TaskHash, kind)
			if err != nil {
				return fmt.Errorf("read stored infer receipt of task %s: %w", entry.Evidence.TaskID, err)
			}
			var receipt struct{ SchemaVersion uint32 }
			if err := json.Unmarshal(payload, &receipt); err != nil || receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV3 {
				legacy = append(legacy, fmt.Sprintf("task %s infer receipt schema %d", entry.Evidence.TaskID, receipt.SchemaVersion))
			}
		}
	}
	if len(legacy) > 0 {
		return fmt.Errorf("the store holds pre-v0.3 task data (%d item(s), first: %s); drain every in-flight task on the "+
			"previous release before upgrading, or start from an empty store", len(legacy), legacy[0])
	}
	return nil
}
