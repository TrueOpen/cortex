package layout

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/store"
)

func dispatchRec(label string) DispatchRecord {
	return DispatchRecord{
		TicketHash: hash("ticket-" + label), TaskID: hash("task"), TaskHash: hash("task-hash"), SessionID: hash("session"),
		OrderSequence: 1, DispatchRound: 1, Builder: "trueopen1builder", ModelID: "ab", ProfileVersion: 1,
		InputHash: hash("input"), InputSizeBytes: 10, Ticket: []byte("ticket-" + label), SignedOrder: []byte("order"),
		ReceivedAtUnixMs: 1, AcceptDeadlineUnixMs: 2, ClaimFromHeight: 159,
	}
}

func accept(r *DispatchRecord) error {
	r.State, r.Accept, r.AcceptDigest = DispatchAccepted, []byte("accept"), hash("accept-digest")
	return nil
}

func rejectIt(r *DispatchRecord) error {
	r.State, r.Reject = DispatchRejected, []byte("reject")
	return nil
}

func TestDispatchOfferIsWriteOnceAndIndexedByTask(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	rec := dispatchRec("a")
	got, created, err := PutDispatchOffer(ctx, s, rec)
	if err != nil || !created || got.State != DispatchOffered || got.SchemaVersion != DispatchRecordSchemaVersion {
		t.Fatalf("first put = %+v, %v, %v", got, created, err)
	}
	if _, created, err := PutDispatchOffer(ctx, s, rec); err != nil || created {
		t.Fatalf("a redelivered offer is the same record: created=%v err=%v", created, err)
	}
	changed := rec
	changed.Ticket = []byte("different bytes")
	if _, _, err := PutDispatchOffer(ctx, s, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("same ticket hash, different bytes: err = %v", err)
	}
	b := dispatchRec("b")
	b.DispatchRound = 2
	if _, _, err := PutDispatchOffer(ctx, s, b); err != nil {
		t.Fatal(err)
	}
	recs, err := DispatchRecordsForTask(ctx, s, hash("task"))
	if err != nil || len(recs) != 2 {
		t.Fatalf("records for task = %d, %v", len(recs), err)
	}
	if _, _, err := PutDispatchOffer(ctx, s, DispatchRecord{TicketHash: hash("x")}); err == nil {
		t.Fatal("an incomplete offer record must be refused")
	}
}

func TestDispatchAcceptAndRejectAreMutuallyExclusive(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	a, b, c := dispatchRec("a"), dispatchRec("b"), dispatchRec("c")
	for _, r := range []DispatchRecord{a, b, c} {
		if _, _, err := PutDispatchOffer(ctx, s, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, rejectIt); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, accept); !errors.Is(err, ErrConflict) {
		t.Fatalf("accept after reject: err = %v (CD §4.2.0: never both)", err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, accept); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, rejectIt); !errors.Is(err, ErrConflict) {
		t.Fatalf("reject after accept: err = %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error { r.Accept = []byte("other"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("accept bytes are write-once: err = %v", err)
	}
	if _, err := UpdateDispatch(ctx, s, c.TicketHash, func(r *DispatchRecord) error { r.State = DispatchAccepted; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted without the signed accept: err = %v", err)
	}
}

func TestDispatchStateTransitionsAndOpenIndex(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	a, b := dispatchRec("a"), dispatchRec("b")
	for _, r := range []DispatchRecord{a, b} {
		if _, _, err := PutDispatchOffer(ctx, s, r); err != nil {
			t.Fatal(err)
		}
		if _, err := UpdateDispatch(ctx, s, r.TicketHash, accept); err != nil {
			t.Fatal(err)
		}
	}
	if open, err := OpenDispatches(ctx, s); err != nil || len(open) != 2 {
		t.Fatalf("open = %d, %v", len(open), err)
	}
	if _, err := UpdateDispatch(ctx, s, a.TicketHash, func(r *DispatchRecord) error { r.InputCommitted = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error { r.State = DispatchAcceptUnsent; return nil }); err != nil {
		t.Fatal(err)
	}
	if open, _ := OpenDispatches(ctx, s); len(open) != 0 {
		t.Fatalf("committed input and unsent accepts are not open, got %d", len(open))
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, func(r *DispatchRecord) error { r.State = DispatchAccepted; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("an unsent accept never becomes accepted again: err = %v", err)
	}
	c := dispatchRec("c")
	if _, _, err := PutDispatchOffer(ctx, s, c); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, c.TicketHash, func(r *DispatchRecord) error { r.State = DispatchSuperseded; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, c.TicketHash, func(r *DispatchRecord) error { r.State = DispatchRevoked; return nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked needs the revoke bytes: err = %v", err)
	}
}

func TestDispatchRevokeBeforeOfferLeavesATombstone(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	rec := dispatchRec("a")
	got, err := PutDispatchRevoke(ctx, s, rec.TicketHash, rec.TaskID, rec.Builder, []byte("revoke"))
	if err != nil || got.State != DispatchRevoked || len(got.Ticket) != 0 {
		t.Fatalf("tombstone = %+v, %v", got, err)
	}
	stored, created, err := PutDispatchOffer(ctx, s, rec)
	if err != nil || created || stored.State != DispatchRevoked || !bytes.Equal(stored.Ticket, rec.Ticket) || !bytes.Equal(stored.Revoke, []byte("revoke")) {
		t.Fatalf("offer after revoke = %+v, %v, %v", stored, created, err)
	}
	if _, err := PutDispatchRevoke(ctx, s, rec.TicketHash, rec.TaskID, "trueopen1other", []byte("revoke")); !errors.Is(err, ErrConflict) {
		t.Fatalf("a revoke from another Builder: err = %v", err)
	}
	if _, err := PutDispatchRevoke(ctx, s, rec.TicketHash, rec.TaskID, rec.Builder, []byte("revoke")); err != nil {
		t.Fatalf("a redelivered revoke is idempotent: %v", err)
	}
	b := dispatchRec("b")
	if _, _, err := PutDispatchOffer(ctx, s, b); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, rejectIt); err != nil {
		t.Fatal(err)
	}
	got, err = PutDispatchRevoke(ctx, s, b.TicketHash, b.TaskID, b.Builder, []byte("revoke-b"))
	if err != nil || got.State != DispatchRejected || !bytes.Equal(got.Revoke, []byte("revoke-b")) {
		t.Fatalf("revoke after reject keeps the reject: %+v, %v", got, err)
	}
	c := dispatchRec("c")
	if _, _, err := PutDispatchOffer(ctx, s, c); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, c.TicketHash, accept); err != nil {
		t.Fatal(err)
	}
	if got, err = PutDispatchRevoke(ctx, s, c.TicketHash, c.TaskID, c.Builder, []byte("revoke-c")); err != nil || got.State != DispatchRevoked || len(got.Accept) == 0 {
		t.Fatalf("revoke after accept keeps the accept and stops the ticket: %+v, %v", got, err)
	}
}

func TestWorkerLeasesAreBoundedByCapacity(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	lease := func(label string) WorkerLease {
		return WorkerLease{TicketHash: hash(label), TaskID: hash("task-" + label), Builder: "b", ExpiryHeight: 9}
	}
	for _, c := range []struct {
		label            string
		acquired, create bool
	}{{"a", true, true}, {"a", true, false}, {"b", true, true}, {"c", false, false}} {
		ok, created, err := AcquireWorkerLease(ctx, s, lease(c.label), 2)
		if err != nil || ok != c.acquired || created != c.create {
			t.Fatalf("acquire %s = %v %v %v, want %v %v", c.label, ok, created, err, c.acquired, c.create)
		}
	}
	if n, err := CountWorkerLeases(ctx, s); err != nil || n != 2 {
		t.Fatalf("count = %d, %v", n, err)
	}
	if held, err := HasWorkerLease(ctx, s, hash("a")); err != nil || !held {
		t.Fatalf("held a = %v, %v", held, err)
	}
	if released, err := ReleaseWorkerLease(ctx, s, hash("a")); err != nil || !released {
		t.Fatalf("release a = %v, %v", released, err)
	}
	if released, err := ReleaseWorkerLease(ctx, s, hash("a")); err != nil || released {
		t.Fatalf("second release a = %v, %v", released, err)
	}
	if ok, _, err := AcquireWorkerLease(ctx, s, lease("c"), 2); err != nil || !ok {
		t.Fatalf("acquire c after a release = %v, %v", ok, err)
	}
	tickets, err := WorkerTicketLeases(ctx, s)
	if err != nil || len(tickets) != 2 {
		t.Fatalf("ticket leases = %v, %v", tickets, err)
	}
}

func TestDispatchInputChunksAreWriteOnce(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	if stored, err := PutDispatchInputChunk(ctx, s, hash("t"), 1, []byte("bb")); err != nil || !stored {
		t.Fatalf("first = %v, %v", stored, err)
	}
	if stored, err := PutDispatchInputChunk(ctx, s, hash("t"), 1, []byte("bb")); err != nil || stored {
		t.Fatalf("duplicate = %v, %v", stored, err)
	}
	if _, err := PutDispatchInputChunk(ctx, s, hash("t"), 1, []byte("xx")); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed chunk: err = %v", err)
	}
	if _, err := PutDispatchInputChunk(ctx, s, hash("t"), 0, []byte("aa")); err != nil {
		t.Fatal(err)
	}
	if _, err := PutDispatchInputChunk(ctx, s, hash("u"), 0, []byte("cc")); err != nil {
		t.Fatal(err)
	}
	chunks, err := DispatchInputChunks(ctx, s, hash("t"))
	if err != nil || len(chunks) != 2 || string(chunks[0]) != "aa" || string(chunks[1]) != "bb" {
		t.Fatalf("chunks = %q, %v", chunks, err)
	}
	if err := DeleteDispatchInputChunks(ctx, s, hash("t")); err != nil {
		t.Fatal(err)
	}
	if chunks, _ := DispatchInputChunks(ctx, s, hash("t")); len(chunks) != 0 {
		t.Fatal("chunks of t must be gone")
	}
	if chunks, _ := DispatchInputChunks(ctx, s, hash("u")); len(chunks) != 1 {
		t.Fatal("another ticket's chunks are untouched")
	}
}

func acceptedForInput(t *testing.T, s *store.Store, size uint64) DispatchRecord {
	t.Helper()
	ctx := context.Background()
	rec := dispatchRec("in")
	rec.InputSizeBytes = size
	if _, _, err := PutDispatchOffer(ctx, s, rec); err != nil {
		t.Fatal(err)
	}
	got, err := UpdateDispatch(ctx, s, rec.TicketHash, accept)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// C1: staging is bounded by input_size_bytes and per chunk, counted in the
// same batch as the chunk, and assembled in index order into one buffer.
func TestStageDispatchInputChunkIsBoundedAndCounted(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	rec := acceptedForInput(t, s, 10)
	got, stored, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 1, 3, []byte("4567"))
	if err != nil || !stored || got.InputChunkCount != 3 || got.InputChunksReceived != 1 || got.InputStagedBytes != 4 {
		t.Fatalf("first chunk = %+v, %v, %v", got, stored, err)
	}
	if got, stored, err = StageDispatchInputChunk(ctx, s, rec.TicketHash, 1, 3, []byte("4567")); err != nil || stored || got.InputChunksReceived != 1 {
		t.Fatalf("a redelivered chunk counts once: %+v, %v, %v", got, stored, err)
	}
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 1, 3, []byte("xxxx")); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed bytes: err = %v", err)
	}
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 0, 4, []byte("0")); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed chunk_count: err = %v", err)
	}
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 0, 3, []byte("0123456")); !errors.Is(err, ErrInputBound) {
		t.Fatalf("4+7 > 10 staged bytes: err = %v", err)
	}
	if got, _ := GetDispatchRecord(ctx, s, rec.TicketHash); got.InputStagedBytes != 4 || got.InputChunksReceived != 1 {
		t.Fatalf("a refused chunk changes nothing: %+v", got)
	}
	if chunks, _ := DispatchInputChunks(ctx, s, rec.TicketHash); len(chunks) != 1 {
		t.Fatalf("a refused chunk is not stored: %d chunks", len(chunks))
	}
	for i, c := range []string{"0123", "89"} {
		if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, []uint32{0, 2}[i], 3, []byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	got, _ = GetDispatchRecord(ctx, s, rec.TicketHash)
	if got.InputChunksReceived != 3 || got.InputStagedBytes != 10 {
		t.Fatalf("complete by counter: %+v", got)
	}
	input, err := AssembleDispatchInput(ctx, s, rec.TicketHash, 3, 10)
	if err != nil || string(input) != "0123456789" || cap(input) != 10 {
		t.Fatalf("assembled %q (cap %d), %v", input, cap(input), err)
	}
	if _, err := ResetDispatchInput(ctx, s, rec.TicketHash); err != nil {
		t.Fatal(err)
	}
	got, _ = GetDispatchRecord(ctx, s, rec.TicketHash)
	if got.InputChunkCount != 0 || got.InputChunksReceived != 0 || got.InputStagedBytes != 0 {
		t.Fatalf("reset = %+v", got)
	}
	if chunks, _ := DispatchInputChunks(ctx, s, rec.TicketHash); len(chunks) != 0 {
		t.Fatal("reset drops the chunks")
	}
}

// N1: a chunk may be as large as it likes as long as every chunk still
// missing keeps at least one byte; no per-chunk share is imposed.
func TestStageDispatchInputChunkLeavesRoomForTheRest(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	rec := acceptedForInput(t, s, 100)
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 0, 10, bytes.Repeat([]byte{1}, 92)); !errors.Is(err, ErrInputBound) {
		t.Fatalf("92 bytes leave 8 for 9 missing chunks: err = %v", err)
	}
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 0, 10, bytes.Repeat([]byte{1}, 91)); err != nil {
		t.Fatalf("91 bytes leave one for each missing chunk: %v", err)
	}
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 1, 10, []byte{1, 2}); !errors.Is(err, ErrInputBound) {
		t.Fatalf("2 bytes would leave 7 for 8 missing chunks: err = %v", err)
	}
	for i := uint32(1); i < 10; i++ {
		if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, i, 10, []byte{byte(i)}); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	if got, _ := GetDispatchRecord(ctx, s, rec.TicketHash); got.InputChunksReceived != 10 || got.InputStagedBytes != 100 {
		t.Fatalf("complete = %+v", got)
	}
}

// I7: terminal transitions drop staged input in the same batch.
func TestDispatchTerminalStatesDropStagedInput(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	rec := acceptedForInput(t, s, 10)
	if _, _, err := StageDispatchInputChunk(ctx, s, rec.TicketHash, 0, 2, []byte("01234")); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatchDroppingInput(ctx, s, rec.TicketHash, func(r *DispatchRecord) error { r.State = DispatchSuperseded; return nil }); err != nil {
		t.Fatal(err)
	}
	if chunks, _ := DispatchInputChunks(ctx, s, rec.TicketHash); len(chunks) != 0 {
		t.Fatal("superseded drops its chunks")
	}
	b := dispatchRec("b")
	if _, _, err := PutDispatchOffer(ctx, s, b); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateDispatch(ctx, s, b.TicketHash, accept); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StageDispatchInputChunk(ctx, s, b.TicketHash, 0, 2, []byte("01234")); err != nil {
		t.Fatal(err)
	}
	if _, err := PutDispatchRevoke(ctx, s, b.TicketHash, b.TaskID, b.Builder, []byte("revoke")); err != nil {
		t.Fatal(err)
	}
	if chunks, _ := DispatchInputChunks(ctx, s, b.TicketHash); len(chunks) != 0 {
		t.Fatal("a revoke drops the chunks")
	}
}

// M5: the open index carries what the sweep decides on.
func TestOpenDispatchEntriesAreSlimAndCurrent(t *testing.T) {
	ctx := context.Background()
	s := openTestLayout(t)
	rec := acceptedForInput(t, s, 10)
	if _, err := UpdateDispatch(ctx, s, rec.TicketHash, func(r *DispatchRecord) error {
		r.AcceptSeq, r.InputRequestSeq, r.InputRequestedAtUnixMs = 3, 4, 77
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	es, err := OpenDispatchEntries(ctx, s)
	if err != nil || len(es) != 1 {
		t.Fatalf("entries = %v, %v", es, err)
	}
	e := es[0]
	if e.TicketHash != rec.TicketHash || e.Builder != rec.Builder || e.AcceptDeadlineUnixMs != rec.AcceptDeadlineUnixMs ||
		e.AcceptSeq != 3 || e.InputRequestSeq != 4 || e.InputRequestedAtUnixMs != 77 || e.ClaimFromHeight != rec.ClaimFromHeight || e.AcceptEnqueuing {
		t.Fatalf("entry = %+v", e)
	}
}
