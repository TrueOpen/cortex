package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

func TestSettledTicketsAreCollectedAfterTheirRetention(t *testing.T) {
	ctx := context.Background()
	x, _ := claimHarness(t) // span = max(20+10, 30+5) + 40 = 75
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF)); err != nil {
		t.Fatal(err)
	}
	rec := x.record(t)
	scope := codec.Hash(layout.DispatchEvidenceScope(rec.TaskHash, rec.TicketHash))
	if _, err := x.ev.Write(ctx, evidence.WriteRequest{TaskHash: scope, TaskID: "t", Kind: "worker-output-fin", Data: []byte("fin")}); err != nil {
		t.Fatal(err)
	}
	tomb := layout.StoredHash{0x99}
	if _, err := layout.PutDispatchRevoke(ctx, x.st, tomb, layout.StoredHash{0x98}, hrBuilderA, []byte("revoke")); err != nil {
		t.Fatal(err)
	}
	until := rec.ClaimFromHeight + 75
	x.atHeight(t, until-1)
	if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); err != nil {
		t.Fatal("kept until retention ends")
	}
	x.atHeight(t, until)
	if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("collected: %v", err)
	}
	if recs, _ := layout.DispatchRecordsForTask(ctx, x.st, rec.TaskID); len(recs) != 0 {
		t.Fatal("task index collected")
	}
	if _, err := x.ev.ReadTaskKind(ctx, scope, "worker-output-fin"); err == nil {
		t.Fatal("a never-recorded ticket's evidence scope is retired")
	}
	tr, err := layout.GetDispatchRecord(ctx, x.st, tomb)
	if err != nil || tr.GCFromHeight == 0 {
		t.Fatalf("a tombstone is anchored at the first GC pass that sees it: %+v, %v", tr, err)
	}
	x.atHeight(t, tr.GCFromHeight+74)
	if _, err := layout.GetDispatchRecord(ctx, x.st, tomb); err != nil {
		t.Fatal("tombstone kept")
	}
	x.atHeight(t, tr.GCFromHeight+75)
	if _, err := layout.GetDispatchRecord(ctx, x.st, tomb); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("tombstone collected")
	}
}

// A revoke whose stop failed is written before the stop (the revoke is
// stored first); the GC pass retries the stop and the lease release until
// they succeed, long before the record itself is collected.
func TestGCFinishesTheStopOfARevokedTicket(t *testing.T) {
	ctx := context.Background()
	x, _ := claimHarness(t)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.infer.setErrs(nil, errors.New("runner busy"))
	if err := x.d.HandleRevoke(ctx, hrBuilderA, dpRevoke(t, x, nexusv1.DispatchRevokeReasonV1_DISPATCH_REVOKE_REASON_V1_RBF)); err == nil {
		t.Fatal("a failed stop is reported")
	}
	rec := x.record(t)
	if rec.State != layout.DispatchRevoked || !x.leaseHeld(t) {
		t.Fatalf("state %s, lease %v: the revoke is stored, the stop and release are owed", rec.State, x.leaseHeld(t))
	}
	x.infer.setErrs(nil, nil)
	x.atHeight(t, rec.ClaimFromHeight+1)
	if !x.infer.stopped(rec.TicketHash) || x.leaseHeld(t) {
		t.Fatal("the GC pass finished the stop and gave the lease back")
	}
	if _, err := layout.GetDispatchRecord(ctx, x.st, rec.TicketHash); err != nil {
		t.Fatal("the record itself waits for its retention")
	}
}
