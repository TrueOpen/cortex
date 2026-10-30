package layout

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
)

func acceptedRec(t *testing.T, s *store.Store, label string) DispatchRecord {
	t.Helper()
	rec := dispatchRec(label)
	rec.TaskID, rec.TaskHash = hash("task-"+label), hash("hash-"+label)
	if _, _, err := PutDispatchOffer(context.Background(), s, rec); err != nil {
		t.Fatal(err)
	}
	out, err := UpdateDispatch(context.Background(), s, rec.TicketHash, accept)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDispatchClaimStates(t *testing.T) {
	ctx, s := context.Background(), openTestLayout(t)
	a := acceptedRec(t, s, "a")
	set := func(fn func(*DispatchRecord)) error {
		_, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { fn(r); return nil })
		return err
	}
	if err := set(func(r *DispatchRecord) { r.State = DispatchClaimable }); !errors.Is(err, ErrConflict) {
		t.Fatalf("claimable needs its window: %v", err)
	}
	if err := set(func(r *DispatchRecord) { r.State, r.ClaimWindowCloseHeight = DispatchClaimable, 179 }); err != nil {
		t.Fatal(err)
	}
	if c, _ := ClaimDispatches(ctx, s); len(c) != 1 {
		t.Fatal("a claimable ticket is on the claim list")
	}
	if w, _ := AwaitingRecordDispatches(ctx, s); len(w) != 0 {
		t.Fatal("settled at D_ticket: no longer awaiting")
	}
	if o, _ := OpenDispatches(ctx, s); len(o) != 0 {
		t.Fatal("a claimable ticket fetches no input")
	}
	if err := set(func(r *DispatchRecord) { r.ClaimWindowCloseHeight = 180 }); !errors.Is(err, ErrConflict) {
		t.Fatalf("the window is write-once: %v", err)
	}
	if err := set(func(r *DispatchRecord) { r.State = DispatchClaimPending }); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending needs the chain's claimed height: %v", err)
	}
	if err := set(func(r *DispatchRecord) {
		r.State, r.ClaimedHeight, r.RebuttalDeadlineHeight = DispatchClaimPending, 170, 180
	}); err != nil {
		t.Fatal(err)
	}
	if err := set(func(r *DispatchRecord) { r.State = DispatchClaimPaid }); err != nil {
		t.Fatal(err)
	}
	if c, _ := ClaimDispatches(ctx, s); len(c) != 0 {
		t.Fatal("a paid claim leaves the claim list")
	}
	if g, _ := CollectableDispatchTickets(ctx, s, StoredHash{}, 10); len(g) != 1 || g[0] != a.TicketHash {
		t.Fatalf("collectable = %v", g)
	}
	if err := set(func(r *DispatchRecord) { r.State = DispatchClaimPending }); !errors.Is(err, ErrConflict) {
		t.Fatal("paid is final")
	}
	b := acceptedRec(t, s, "b")
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error {
		r.State, r.WinnerTicketHash, r.RecordedHeight, r.InferDeadlineHeight = DispatchRecorded, r.TicketHash, 120, 150
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error {
		r.State, r.ClaimWindowCloseHeight = DispatchClaimable, 179
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatal("a recorded ticket is never claimable")
	}
}

func TestDeleteDispatchRecordOnlyWhenSettledAndFree(t *testing.T) {
	ctx, s := context.Background(), openTestLayout(t)
	a := acceptedRec(t, s, "a")
	if err := DeleteDispatchRecord(ctx, s, a.TicketHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("an accepted ticket is not settled: %v", err)
	}
	if _, _, err := AcquireWorkerLease(ctx, s, WorkerLease{TicketHash: a.TicketHash, TaskID: a.TaskID}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.State = DispatchSuperseded; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDispatchRecord(ctx, s, a.TicketHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("a leased ticket stays: %v", err)
	}
	if _, err := ReleaseWorkerLease(ctx, s, a.TicketHash); err != nil {
		t.Fatal(err)
	}
	if _, err := PutDispatchInputChunk(ctx, s, a.TicketHash, 0, []byte("left over")); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDispatchRecord(ctx, s, a.TicketHash); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDispatchRecord(ctx, s, a.TicketHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("record gone")
	}
	if r, _ := DispatchRecordsForTask(ctx, s, a.TaskID); len(r) != 0 {
		t.Fatal("task index gone")
	}
	if c, _ := DispatchInputChunks(ctx, s, a.TicketHash); len(c) != 0 {
		t.Fatal("input gone")
	}
	if g, _ := CollectableDispatchTickets(ctx, s, StoredHash{}, 10); len(g) != 0 {
		t.Fatal("gc index gone")
	}
	if err := DeleteDispatchRecord(ctx, s, a.TicketHash); err != nil {
		t.Fatal("idempotent")
	}
	b := acceptedRec(t, s, "b")
	if err := InferAssignmentBatch(ctx, s, b.TaskHash, TaskRecord{}, InferRecord{TaskID: "t", DispatchTicketHash: b.TicketHash, Stage: StageQueued}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error { r.State = DispatchSuperseded; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDispatchRecord(ctx, s, b.TicketHash); !errors.Is(err, ErrConflict) {
		t.Fatal("a ticket that still owns the InferRecord stays")
	}
}
