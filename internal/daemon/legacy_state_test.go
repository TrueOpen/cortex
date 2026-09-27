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

func legacyStatus(terminal, openChallenge bool) LegacyTaskStatus {
	return func(context.Context, codec.Hash) (evidence.TaskCleanupStatus, error) {
		return evidence.TaskCleanupStatus{TerminalOrSettled: terminal, OpenChallenge: openChallenge}, nil
	}
}

// seedLegacy leaves the store as a pre-v0.3 node would have: trace evidence
// (a kind today's merge boundary refuses, so the record is written raw) or a
// V2 infer receipt.
func seedLegacy(t *testing.T, p *evidenceWorkerPersistence, kind string) {
	t.Helper()
	ctx := context.Background()
	switch kind {
	case "trace":
		record, _ := json.Marshal(layout.Evidence{SchemaVersion: 1, TaskID: p.task.TaskID, SessionID: p.task.SessionID,
			Artifacts: []layout.EvidenceArtifact{{Kind: "worker-trace", Digest: layout.StoredHash(codec.HashBytes([]byte("trace"))), Size: 5}}})
		if err := p.store.ApplyBatch(ctx, func(b *store.Batch) error { return b.Set(layout.EvidenceKey(layout.StoredHash(p.taskHash)), record) }); err != nil {
			t.Fatal(err)
		}
	case "v2 receipt":
		payload, _ := json.Marshal(map[string]any{"SchemaVersion": 2})
		if err := p.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: p.task.TaskID, MaterialDigest: "v2", Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
}

// Pre-v0.3 data of an unfinished task, or of one with an open challenge,
// blocks startup; the same data of a finished task only waits for cleanup.
func TestRefuseLegacyStateBlocksOnlyUnfinishedTasks(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"trace", "v2 receipt"} {
		for name, tc := range map[string]struct {
			status LegacyTaskStatus
			block  bool
		}{
			"in flight":          {legacyStatus(false, false), true},
			"open challenge":     {legacyStatus(true, true), true},
			"terminal / settled": {legacyStatus(true, false), false},
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				p := newTestDocumentWorkerPersistence()
				seedLegacy(t, p, kind)
				err := RefuseLegacyState(ctx, p.store, p.evidence, tc.status)
				if tc.block && (err == nil || !strings.Contains(err.Error(), "drain")) {
					t.Fatalf("RefuseLegacyState = %v, want a drain-before-upgrade refusal", err)
				}
				if !tc.block && err != nil {
					t.Fatalf("finished-task legacy data blocked startup: %v", err)
				}
			})
		}
	}
	clean := newTestDocumentWorkerPersistence()
	payload, _ := json.Marshal(map[string]any{"SchemaVersion": nodewire.InferReceiptSchemaVersionV3})
	if err := clean.CheckpointInferReceipt(ctx, worker.InferReceiptCheckpoint{TaskID: clean.task.TaskID, MaterialDigest: "v3", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if err := RefuseLegacyState(ctx, clean.store, clean.evidence, legacyStatus(false, false)); err != nil {
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
	err = RefuseLegacyState(ctx, p.store, p.evidence, legacyStatus(false, false))
	if err == nil || !strings.Contains(err.Error(), "unreadable infer receipt") || !strings.Contains(err.Error(), "drain") {
		t.Fatalf("RefuseLegacyState = %v, want the unreadable receipt reported as legacy data", err)
	}
}
