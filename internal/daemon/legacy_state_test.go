package daemon

import (
	"context"
	"encoding/json"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/worker"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// Startup refuses a store holding pre-v0.3 task data, and names what it found.
func TestRefuseLegacyStateNamesPreV03Data(t *testing.T) {
	ctx := context.Background()
	for name, seed := range map[string]func(p *evidenceWorkerPersistence) error{
		// A pre-v0.3 node wrote this record; today's merge boundary would
		// refuse the kind, so it is written as the old node left it.
		"trace evidence": func(p *evidenceWorkerPersistence) error {
			record, _ := json.Marshal(layout.Evidence{SchemaVersion: 1, TaskID: p.task.TaskID, SessionID: p.task.SessionID,
				Artifacts: []layout.EvidenceArtifact{{Kind: "worker-trace", Digest: layout.StoredHash(codec.HashBytes([]byte("trace"))), Size: 5}}})
			return p.store.ApplyBatch(ctx, func(b *store.Batch) error { return b.Set(layout.EvidenceKey(layout.StoredHash(p.taskHash)), record) })
		},
		"v2 receipt": func(p *evidenceWorkerPersistence) error {
			payload, _ := json.Marshal(map[string]any{"SchemaVersion": 2})
			return p.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: p.task.TaskID, MaterialDigest: "v2", Payload: payload})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newTestDocumentWorkerPersistence()
			if err := seed(p); err != nil {
				t.Fatal(err)
			}
			err := RefuseLegacyState(ctx, p.store, p.evidence)
			if err == nil || !strings.Contains(err.Error(), "drain") {
				t.Fatalf("RefuseLegacyState = %v, want a drain-before-upgrade refusal", err)
			}
		})
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
