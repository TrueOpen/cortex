package daemon

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func dpNotice(t *testing.T, x *dispatchHarness, status taskv1.DispatchRecordStatusV1) *nexusv1.RecordResultNoticeV1 {
	t.Helper()
	th := x.fx.ticketHash()
	n := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: th[:], Status: status, RecordedHeight: 120}
	if status == taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED {
		n.RecordedHeight, n.RejectCode = 0, taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE
	}
	d, err := dispatchwire.Digest(n)
	if err != nil {
		t.Fatal(err)
	}
	if n.BuilderServiceSignature, err = signer.SignDigestWithPrivateKeyHex(hrBuilderKey, codec.Hash(d)); err != nil {
		t.Fatal(err)
	}
	return n
}

func dpGenerationDigest(t *testing.T, fx *offerFixture) codec.Hash {
	t.Helper()
	raw, err := dispatchwire.Raw(fx.order)
	if err != nil {
		t.Fatal(err)
	}
	d, err := orderGenerationDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// chainRecords makes the fake chain answer that ticket won for winner.
func (x *dispatchHarness) chainRecords(t *testing.T, ticket [32]byte, winner string, recorded, deadline uint64) {
	t.Helper()
	digest := dpGenerationDigest(t, x.fx)
	x.chain.with(func(f *fakeDispatchChain) {
		f.recordErr = nil
		f.record = chainclient.DispatchRecordSnapshot{Height: f.height, TaskID: bytes.Clone(x.fx.ticket.TaskId), RecordHash: bytes.Repeat([]byte{0x77}, 32),
			TicketHash: bytes.Clone(ticket[:]), Builder: hrBuilderA, Winner: winner, WinnerRound: 1, RecordedHeight: recorded}
		f.assignment = chainclient.DispatchAssignmentSnapshot{Height: f.height, TaskID: bytes.Clone(x.fx.ticket.TaskId),
			AcceptedTaskHash: bytes.Clone(x.fx.ticket.TaskHash), GenerationParamsDigest: bytes.Clone(digest[:]),
			RecordHeight: recorded, InferDeadlineHeight: deadline, DispatchTicketHash: bytes.Clone(ticket[:]), WinnerWorker: winner}
	})
}

func (x *dispatchHarness) fact(recorded, deadline uint64) DispatchRecordedFact {
	th := x.fx.ticketHash()
	return DispatchRecordedFact{
		Height: recorded, TaskID: layout.StoredHash(x.fx.ticket.TaskId), SessionID: layout.StoredHash(x.fx.ticket.SessionId),
		OrderSequence: x.fx.ticket.OrderSequence, Builder: hrBuilderA, Winner: hrCortex,
		TicketHash: layout.StoredHash(th), RecordHash: layout.StoredHash(bytes.Repeat([]byte{0x77}, 32)), InferDeadline: deadline,
	}
}

// committed drives the harness to an accepted ticket whose input is committed.
func (x *dispatchHarness) committed(t *testing.T) layout.DispatchRecord {
	t.Helper()
	ctx := context.Background()
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, x.fx.input)); err != nil {
		t.Fatal(err)
	}
	return x.record(t)
}

func TestRecordNoticeRejectedPausesDeliveryOnly(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	n := dpNotice(t, x, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED)
	if err := x.d.HandleRecordResult(ctx, hrBuilderB, n); err == nil {
		t.Fatal("a notice from a Builder that did not dispatch the ticket is refused")
	}
	for i := 0; i < 2; i++ {
		if err := x.d.HandleRecordResult(ctx, hrBuilderA, n); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	got := x.record(t)
	if got.State != layout.DispatchPendingClaim || len(got.RecordNotice) == 0 {
		t.Fatalf("record = %+v", got)
	}
	if held, _ := layout.HasWorkerLease(ctx, x.st, rec.TicketHash); !held || x.infer.stopped(rec.TicketHash) {
		t.Fatal("a REJECTED notice only pauses delivery: the lease is kept and inference continues (CD §8.6)")
	}
	if err := x.d.HandleFrame(ctx, hrBuilderA, &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_RecordResult{RecordResult: n}}); err != nil {
		t.Fatalf("the stream routes record_result to the Dispatcher: %v", err)
	}
}

func TestRecordNoticeRecordedIsConfirmedOnChain(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	if err := x.d.HandleRecordResult(ctx, hrBuilderA, dpNotice(t, x, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED)); err != nil {
		t.Fatal(err)
	}
	if got := x.record(t); got.State != layout.DispatchAccepted {
		t.Fatalf("state = %s: a notice is never enough on its own (W6)", got.State)
	}
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	queries := 0
	x.chain.with(func(f *fakeDispatchChain) { queries = f.recordQueries })
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	x.chain.with(func(f *fakeDispatchChain) {
		if f.recordQueries != queries {
			t.Error("the sweep asks the chain again only when the committed height moved")
		}
	})
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	x.chain.with(func(f *fakeDispatchChain) { f.height++ })
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	got := x.record(t)
	if got.State != layout.DispatchRecorded || got.RecordedHeight != 120 || got.InferDeadlineHeight != 150 || got.WinnerTicketHash != rec.TicketHash {
		t.Fatalf("record = %+v", got)
	}
	if held, _ := layout.HasWorkerLease(ctx, x.st, rec.TicketHash); held {
		t.Fatal("the ticket key is released after the record")
	}
	if held, _ := layout.HasWorkerTaskLease(ctx, x.st, rec.TaskID); !held {
		t.Fatal("the lease moved to (task_id, WORKER)")
	}
	if n, _ := layout.CountWorkerLeases(ctx, x.st); n != 1 {
		t.Fatalf("leases = %d, capacity is unchanged by the move", n)
	}
	if r := x.infer.recorded(); len(r) != 1 || r[0].inferDeadline != 150 || r[0].recordedHeight != 120 || r[0].ticket != rec.TicketHash {
		t.Fatalf("infer record = %+v", r)
	}
}

func TestDispatchRecordedEventIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	for i := 0; i < 2; i++ {
		if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if got := x.record(t); got.State != layout.DispatchRecorded {
		t.Fatalf("state = %s", got.State)
	}
	bad := x.fact(121, 150)
	if err := x.d.ObserveDispatchRecorded(ctx, bad); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("an event that disagrees with QueryDispatchRecord: err = %v, want permanent", err)
	}
	other := newDispatchHarness(t, 2, nil)
	if err := other.d.ObserveDispatchRecorded(ctx, other.fact(120, 150)); err != nil {
		t.Fatal("a task this node was never offered is not its concern (S8 reads it)")
	}
}

func TestDispatchRecordedEventMustMatchTheTaskViewDeadline(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 160)); err == nil || builderclient.IsRetryable(err) || !strings.Contains(err.Error(), "ChainObservationConflict") {
		t.Fatalf("an event infer_deadline the task view contradicts: err = %v, want a permanent conflict", err)
	}
	if got := x.record(t); got.State != layout.DispatchAccepted {
		t.Fatalf("state = %s: a contradicted event moves nothing (Q2)", got.State)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.assignment.Height = f.record.Height - 1 })
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 160)); err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("a task view read below the record is a lag: err = %v, want retryable", err)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.record = chainclient.DispatchRecordSnapshot{} })
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("an event the query does not serve yet: err = %v, want retryable", err)
	}
}

func TestAnotherTicketRecordedPausesThisOne(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	x.chainRecords(t, [32]byte{0xee}, hrCortex, 120, 150)
	if err := x.d.HandleRecordResult(ctx, hrBuilderA, dpNotice(t, x, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED)); err != nil {
		t.Fatal(err)
	}
	got := x.record(t)
	if got.State != layout.DispatchPendingClaim {
		t.Fatalf("state = %s: another ticket won; S6 claims at D_ticket", got.State)
	}
	if held, _ := layout.HasWorkerLease(ctx, x.st, rec.TicketHash); !held {
		t.Fatal("the lease is S6's to release")
	}
}

func TestRecordedTicketWithForeignTaskHashIsAConflict(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	x.chain.with(func(f *fakeDispatchChain) { f.assignment.AcceptedTaskHash = bytes.Repeat([]byte{0x99}, 32) })
	err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150))
	if err == nil || builderclient.IsRetryable(err) || !strings.Contains(err.Error(), "ChainObservationConflict") {
		t.Fatalf("err = %v", err)
	}
	if got := x.record(t); got.State != layout.DispatchConflict {
		t.Fatalf("state = %s", got.State)
	}
	if held, _ := layout.HasWorkerLease(ctx, x.st, rec.TicketHash); held || !x.infer.stopped(rec.TicketHash) {
		t.Fatal("a conflict fails closed: inference stopped, lease released")
	}
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("a redelivered event for a conflicted ticket stays a permanent refusal: %v", err)
	}
}

func TestFalseRejectedNoticeIsOverruledByTheChain(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	x.committed(t)
	if err := x.d.HandleRecordResult(ctx, hrBuilderA, dpNotice(t, x, taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED)); err != nil {
		t.Fatal(err)
	}
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err != nil {
		t.Fatal(err)
	}
	got := x.record(t)
	if got.State != layout.DispatchRecorded || len(got.RecordNotice) == 0 {
		t.Fatalf("record = %+v: the chain wins, the false notice stays on file (CD §8.6a)", got)
	}
}

func TestRecordBeforeInputStillStartsInferenceWithTheDeadline(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err != nil {
		t.Fatal(err)
	}
	if open, _ := layout.OpenDispatches(ctx, x.st); len(open) != 1 {
		t.Fatal("a recorded ticket keeps fetching its input")
	}
	if err := x.handle(ctx); err != nil {
		t.Fatalf("a redelivered offer for a recorded ticket is answered quietly: %v", err)
	}
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, x.fx.input)); err != nil {
		t.Fatal(err)
	}
	starts := x.infer.starts()
	if len(starts) != 1 || starts[0].InferDeadlineHeight != 150 || starts[0].RecordedHeight != 120 {
		t.Fatalf("starts = %+v", starts)
	}
	x.open() // restart
	if n, _ := layout.CountWorkerLeases(ctx, x.st); n != 1 {
		t.Fatal("a restart keeps the recorded task's lease")
	}
	if free, _ := x.leases.FreeSlots(); free != 1 {
		t.Fatalf("free slots after restart = %d: the task-keyed lease still counts", free)
	}
}

func TestTaskRunnerRecordsTheInferDeadline(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: st})
	e := DispatchInferEntry{
		TicketHash: layout.StoredHash{1}, TaskHash: layout.StoredHash{2}, TaskID: strings.Repeat("03", 32), SessionID: strings.Repeat("04", 32),
		OrderSequence: 1, ModelID: hrModelAB, ProfileVersion: 1, InputHash: layout.StoredHash{5}, InputSizeBytes: 10,
		BuilderOperator: hrBuilderA, WorkerAddress: hrCortex, BuilderSetID: "7", BuilderSetHash: bytes.Repeat([]byte{0x15}, 32), ClaimFromHeight: 159,
	}
	if err := r.StartDispatchedInfer(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordDispatchedInfer(ctx, e.TaskHash, layout.StoredHash{9}, 120, 150); err != nil {
		t.Fatal(err)
	}
	if rec, _ := layout.GetInferRecord(ctx, st, e.TaskHash); rec.InferDeadlineHeight != 0 {
		t.Fatal("another ticket's record does not touch this responsibility")
	}
	for i := 0; i < 2; i++ {
		if err := r.RecordDispatchedInfer(ctx, e.TaskHash, e.TicketHash, 120, 150); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := layout.GetInferRecord(ctx, st, e.TaskHash)
	if err != nil || rec.InferDeadlineHeight != 150 || rec.DeadlineHeight != 150 || rec.WinnerConfirmHeight != 120 {
		t.Fatalf("infer record = %+v, %v", rec, err)
	}
	if err := r.RecordDispatchedInfer(ctx, layout.StoredHash{7}, e.TicketHash, 120, 150); err != nil {
		t.Fatal("no responsibility yet: commitInput carries the record instead")
	}
	e2 := e
	e2.TaskHash, e2.TicketHash, e2.RecordedHeight, e2.InferDeadlineHeight = layout.StoredHash{8}, layout.StoredHash{6}, 120, 150
	if err := r.StartDispatchedInfer(ctx, e2); err != nil {
		t.Fatal(err)
	}
	if rec, _ := layout.GetInferRecord(ctx, st, e2.TaskHash); rec.DeadlineHeight != 150 || rec.InferDeadlineHeight != 150 || rec.WinnerConfirmHeight != 120 {
		t.Fatalf("a recorded entry starts with its infer deadline: %+v", rec)
	}
}
