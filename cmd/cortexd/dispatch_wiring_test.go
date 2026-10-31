package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func TestWireDispatchRunnerConfigWithoutStreamsLeavesTheRunnerAlone(t *testing.T) {
	var cfg daemon.TaskRunnerConfig
	if link := wireDispatchRunnerConfig(&cfg, &daemon.Runtime{}); link != nil || cfg.VerifierSender != nil || cfg.DispatchRecords != nil {
		t.Fatal("no dispatch streams: nothing is wired")
	}
	if got := workloadRunners(&daemon.Runtime{}, daemon.NewTaskRunner(daemon.TaskRunnerConfig{})); len(got) != 1 {
		t.Fatalf("workload runners = %d, want the task runner only", len(got))
	}
}

// S6 Q9: a per-ticket evidence scope follows its task's cleanup status.
func TestEvidenceCleanupStatusFollowsTheScopeOwner(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	task, ticket := layout.StoredHash{1}, layout.StoredHash{2}
	if _, _, err := layout.PutDispatchOffer(ctx, db, layout.DispatchRecord{TicketHash: ticket, TaskID: layout.StoredHash{3}, TaskHash: task,
		Builder: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe", Ticket: []byte{1}, SignedOrder: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	index := &evidence.LayoutStoreIndex{Store: db}
	if err := index.PutEvidence(ctx, codec.Hash(task), layout.Evidence{TerminalOrSettled: true}); err != nil {
		t.Fatal(err)
	}
	scope := layout.DispatchEvidenceScope(task, ticket)
	if err := index.PutEvidence(ctx, codec.Hash(scope), layout.Evidence{}); err != nil {
		t.Fatal(err)
	}
	cc := newEvidenceCleanupConfig(config.Config{}, &daemon.Runtime{Store: db}, 10)
	status, err := cc.TaskStatus(ctx, codec.Hash(scope))
	if err != nil || !status.TerminalOrSettled {
		t.Fatalf("scope status = %+v, %v: it follows its terminal task", status, err)
	}
	if !strings.HasPrefix(daemon.StreamDependencyName("b"), "dispatch_stream:") {
		t.Fatal("stream row name")
	}
}
