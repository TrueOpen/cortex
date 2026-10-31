package layout

import (
	"context"
	"errors"
	"testing"
)

func TestDispatchRecordObservationStates(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	a := dispatchRec("a")
	if _, _, err := PutDispatchOffer(ctx, s, a); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, accept); err != nil {
		t.Fatal(err)
	}
	if await, err := AwaitingRecordDispatches(ctx, s); err != nil || len(await) != 1 {
		t.Fatalf("awaiting = %d, %v", len(await), err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error {
		r.State, r.RecordNotice, r.NoticeStatus = DispatchPendingClaim, []byte("notice"), 3
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if await, _ := AwaitingRecordDispatches(ctx, s); len(await) != 1 {
		t.Fatal("a paused ticket still awaits its record (S6 settles it at D_ticket)")
	}
	if open, _ := OpenDispatchEntries(ctx, s); len(open) != 1 || open[0].State != DispatchPendingClaim {
		t.Fatalf("a paused ticket keeps fetching its input: %+v", open)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.RecordNotice = []byte("other"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("the notice is write-once: %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.State = DispatchRecorded; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("recorded needs the chain facts: %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error {
		r.State, r.WinnerTicketHash, r.RecordedHeight, r.InferDeadlineHeight = DispatchRecorded, r.TicketHash, 120, 150
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if await, _ := AwaitingRecordDispatches(ctx, s); len(await) != 0 {
		t.Fatal("a recorded ticket no longer awaits")
	}
	if open, _ := openDispatches(ctx, s); len(open) != 1 {
		t.Fatal("a recorded ticket keeps fetching its input")
	}
	if _, staged, err := StageDispatchInputChunk(ctx, s, a.TicketHash, 0, 1, []byte("0123456789")); err != nil || !staged {
		t.Fatalf("a recorded ticket stages its input: %v, %v", staged, err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.InferDeadlineHeight = 151; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("infer deadline is write-once: %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.Receipt = []byte("receipt"); return nil }); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReceiptRescueCandidates(ctx, s); len(c) != 1 {
		t.Fatal("a signed, unaccepted receipt is a rescue candidate")
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.ReceiptAccepted = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if c, _ := ReceiptRescueCandidates(ctx, s); len(c) != 0 {
		t.Fatal("an accepted receipt needs no rescue")
	}
	b := dispatchRec("b")
	if _, _, err := PutDispatchOffer(ctx, s, b); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, accept); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error { r.Receipt = []byte("x"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("a receipt is signed only for a recorded ticket (Q1): %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error {
		r.State, r.WinnerTicketHash, r.RecordedHeight, r.InferDeadlineHeight = DispatchRecorded, hash("other"), 120, 150
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a ticket is recorded only as its own winner: %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error {
		r.State, r.StateReason = DispatchConflict, "chain disagrees"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if open, _ := openDispatches(ctx, s); len(open) != 1 {
		t.Fatal("a conflicted ticket holds no duty and fetches nothing")
	}
}

func TestWorkerLeaseRebindsToTheTaskKey(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	lease := WorkerLease{TicketHash: hash("t1"), TaskID: hash("task"), Builder: "b", ExpiryHeight: 9}
	if ok, _, err := AcquireWorkerLease(ctx, s, lease, 2); err != nil || !ok {
		t.Fatal(err)
	}
	if moved, err := RebindWorkerLease(ctx, s, hash("t1"), hash("task")); err != nil || !moved {
		t.Fatalf("rebind = %v, %v", moved, err)
	}
	if n, _ := CountWorkerLeases(ctx, s); n != 1 {
		t.Fatalf("count = %d: the slot moves, it is not added", n)
	}
	if held, _ := hasWorkerLease(ctx, s, hash("t1")); held {
		t.Fatal("the ticket key is gone")
	}
	if held, _ := hasWorkerTaskLease(ctx, s, hash("task")); !held {
		t.Fatal("the task key holds it")
	}
	if moved, err := RebindWorkerLease(ctx, s, hash("t1"), hash("task")); err != nil || moved {
		t.Fatalf("a replayed rebind is a no-op: %v, %v", moved, err)
	}
	if _, err := RebindWorkerLease(ctx, s, hash("t2"), hash("other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("a ticket that never reserved capacity: %v", err)
	}
	if tickets, _ := WorkerTicketLeases(ctx, s); len(tickets) != 0 {
		t.Fatal("no ticket leases remain")
	}
	if ok, _, err := AcquireWorkerLease(ctx, s, WorkerLease{TicketHash: hash("t3"), TaskID: hash("task3")}, 1); err != nil || ok {
		t.Fatalf("the task-keyed lease still counts against capacity: %v, %v", ok, err)
	}
	if released, err := ReleaseWorkerTaskLease(ctx, s, hash("task")); err != nil || !released {
		t.Fatal(err)
	}
	if released, err := ReleaseWorkerTaskLease(ctx, s, hash("task")); err != nil || released {
		t.Fatalf("a second release is a no-op: %v, %v", released, err)
	}
	if n, _ := CountWorkerLeases(ctx, s); n != 0 {
		t.Fatal("released")
	}
}

func TestDispatchEvidenceScopeSeparatesTickets(t *testing.T) {
	a := DispatchEvidenceScope(hash("task"), hash("t1"))
	if a == DispatchEvidenceScope(hash("task"), hash("t2")) || a == hash("task") || a != DispatchEvidenceScope(hash("task"), hash("t1")) {
		t.Fatal("one deterministic namespace per (task, ticket), distinct from the task hash")
	}
}
