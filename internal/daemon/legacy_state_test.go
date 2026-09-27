package daemon

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/worker"
)

// seedLegacy leaves the store as a pre-v0.3 node would have: trace evidence
// (a kind today's merge boundary refuses, so the record is written raw) or a
// V2 infer receipt, with the task locally finished or not.
func seedLegacy(t *testing.T, p *evidenceWorkerPersistence, kind string, finished bool) {
	t.Helper()
	ctx := context.Background()
	switch kind {
	case "trace":
		record, _ := json.Marshal(layout.Evidence{SchemaVersion: 1, TaskID: p.task.TaskID, SessionID: p.task.SessionID, TerminalOrSettled: finished,
			Artifacts: []layout.EvidenceArtifact{{Kind: "worker-trace", Digest: layout.StoredHash(codec.HashBytes([]byte("trace"))), Size: 5}}})
		if err := p.store.ApplyBatch(ctx, func(b *store.Batch) error { return b.Set(layout.EvidenceKey(layout.StoredHash(p.taskHash)), record) }); err != nil {
			t.Fatal(err)
		}
	case "v2 receipt":
		payload, _ := json.Marshal(map[string]any{"SchemaVersion": 2})
		if err := p.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: p.task.TaskID, MaterialDigest: "v2", Payload: payload}); err != nil {
			t.Fatal(err)
		}
		if finished {
			if err := (&evidence.LayoutStoreIndex{Store: p.store}).SetEvidenceTerminal(ctx, p.taskHash); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Pre-v0.3 data of a task this node has not finished blocks startup; the same
// data of a locally finished task only waits for retention cleanup. The
// decision reads only the local record: after the v0.3 fresh genesis the chain
// has never heard of these tasks, so no chain lookup (which would fail or find
// nothing) takes part in it.
func TestRefuseLegacyStateBlocksOnlyLocallyUnfinishedTasks(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"trace", "v2 receipt"} {
		for name, finished := range map[string]bool{"in flight": false, "finished locally": true} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				p := newTestDocumentWorkerPersistence()
				seedLegacy(t, p, kind, finished)
				err := RefuseLegacyState(ctx, p.store, p.evidence)
				if !finished && (err == nil || !strings.Contains(err.Error(), "drain")) {
					t.Fatalf("RefuseLegacyState = %v, want a drain-before-upgrade refusal", err)
				}
				if finished && err != nil {
					t.Fatalf("locally finished legacy data blocked startup: %v", err)
				}
			})
		}
	}
	clean := newTestDocumentWorkerPersistence()
	payload, _ := json.Marshal(map[string]any{"SchemaVersion": nodewire.InferReceiptSchemaVersionV3})
	if err := clean.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: clean.task.TaskID, MaterialDigest: "v3", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if err := RefuseLegacyState(ctx, clean.store, clean.evidence); err != nil {
		t.Fatalf("a v0.3 store was refused: %v", err)
	}
}

// An indexed receipt whose bytes are gone is treated as legacy data, with the
// same guidance, rather than failing startup with a bare read error.
func TestRefuseLegacyStateTreatsAnUnreadableReceiptAsLegacy(t *testing.T) {
	ctx := context.Background()
	p := newTestDocumentWorkerPersistence()
	payload, _ := json.Marshal(map[string]any{"SchemaVersion": nodewire.InferReceiptSchemaVersionV3})
	if err := p.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: p.task.TaskID, MaterialDigest: "v3", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	// Writing the same bytes again is idempotent and names the stored file.
	ref, err := p.evidence.Write(ctx, evidence.WriteRequest{TaskHash: p.taskHash, SessionID: p.task.SessionID, TaskID: p.task.TaskID,
		Kind: "worker-infer-receipt:v3", Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ref.Path); err != nil {
		t.Fatal(err)
	}
	err = RefuseLegacyState(ctx, p.store, p.evidence)
	if err == nil || !strings.Contains(err.Error(), "unreadable infer receipt") || !strings.Contains(err.Error(), "drain") {
		t.Fatalf("RefuseLegacyState = %v, want the unreadable receipt reported as legacy data", err)
	}
}
