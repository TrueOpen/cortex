package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/worker"
)

func TestDispatchedInferFactsComeFromTheTicket(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	taskID := hex.EncodeToString(rec.TaskID[:])
	task := store.InferTask{TaskID: taskID, DispatchTicketHash: codec.Hash(rec.TicketHash)}
	d, err := loadDispatchedInfer(ctx, x.st, task)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := d.TaskFacts(ctx, taskID)
	if err != nil || facts.Validate(taskID) != nil {
		t.Fatalf("facts = %+v, %v", facts, err)
	}
	want := dpGenerationDigest(t, x.fx)
	if !bytes.Equal(facts.AcceptedTaskHash, x.fx.ticket.TaskHash) || !bytes.Equal(facts.GenerationParamsDigest, want[:]) {
		t.Fatal("pre-record facts are the ticket's task_hash and the order's generation digest (Q12)")
	}
	snap, err := d.TaskSnapshot(ctx, taskID)
	if err != nil || snap.Assignment.SelectedWorker != hrCortex || snap.Assignment.TaskID != taskID ||
		!bytes.Equal(snap.Assignment.AcceptedOrderPayloadHash[:], x.fx.ticket.InputHash) {
		t.Fatalf("snapshot = %+v, %v", snap, err)
	}
	if _, err := d.TaskFacts(ctx, strings.Repeat("00", 32)); err == nil {
		t.Fatal("facts for another task are refused")
	}
	if _, err := loadDispatchedInfer(ctx, x.st, store.InferTask{TaskID: taskID}); err == nil {
		t.Fatal("a responsibility without a ticket has no Phase 1 source")
	}
	if _, err := loadDispatchedInfer(ctx, x.st, store.InferTask{TaskID: strings.Repeat("00", 32), DispatchTicketHash: codec.Hash(rec.TicketHash)}); err == nil {
		t.Fatal("a ticket whose record names another task is refused")
	}
}

func TestDispatchGateFollowsTheRecord(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	rec := x.committed(t)
	g := dispatchGate{st: x.st}
	ticket := codec.Hash(rec.TicketHash)
	if s, err := g.DeliveryState(ctx, ticket); err != nil || s.Paused || s.InferDeadlineHeight != 0 {
		t.Fatalf("accepted = %+v, %v", s, err)
	}
	receipt := builderclient.SignedInferReceipt{TaskID: hex.EncodeToString(rec.TaskID[:]), DispatchTicketHash: ticket.String()}
	if err := g.ReceiptSigned(ctx, ticket, receipt); err == nil {
		t.Fatal("no receipt before the record")
	}
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err != nil {
		t.Fatal(err)
	}
	if s, _ := g.DeliveryState(ctx, ticket); s.Paused || s.RecordedHeight != 120 || s.InferDeadlineHeight != 150 {
		t.Fatalf("recorded = %+v", s)
	}
	for i := 0; i < 2; i++ {
		if err := g.ReceiptSigned(ctx, ticket, receipt); err != nil {
			t.Fatalf("receipt %d: %v", i, err)
		}
	}
	other := receipt
	other.DispatchTicketHash = strings.Repeat("ab", 32)
	if err := g.ReceiptSigned(ctx, ticket, other); err == nil {
		t.Fatal("a receipt for another ticket is refused")
	}
	y := newDispatchHarness(t, 2, nil)
	yr := y.committed(t)
	if err := y.d.HandleRecordResult(ctx, hrBuilderA, dpNotice(t, y, 3)); err != nil {
		t.Fatal(err)
	}
	if s, _ := (dispatchGate{st: y.st}).DeliveryState(ctx, codec.Hash(yr.TicketHash)); !s.Paused {
		t.Fatal("pending-claim pauses delivery")
	}
}

func TestWorkerMaterialIsScopedPerTicket(t *testing.T) {
	ctx := context.Background()
	a := newTestDocumentWorkerPersistence()
	b := *a
	b.evidenceRef = nil
	a.evidenceKey = codec.Hash(layout.DispatchEvidenceScope(layout.StoredHash(a.taskHash), layout.StoredHash{1}))
	b.evidenceKey = codec.Hash(layout.DispatchEvidenceScope(layout.StoredHash(a.taskHash), layout.StoredHash{2}))
	input := []byte("verified input")
	if err := a.WriteEvidence(ctx, worker.EvidenceRecord{TaskID: "task-1", Kind: string(layout.ArtifactTaskInput), Data: input}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(builderclient.OutputChunk{Seq: 0, Text: []byte("x"), WorkerSignature: []byte{1}})
	if err := a.WriteEvidence(ctx, worker.EvidenceRecord{TaskID: "task-1", Kind: worker.OutputStreamFrameKind(0), Data: raw}); err != nil {
		t.Fatal(err)
	}
	if frames, err := a.OutputStreamFrames(ctx, "task-1"); err != nil || len(frames) != 1 {
		t.Fatalf("ticket 1 frames = %d, %v", len(frames), err)
	}
	if frames, err := b.OutputStreamFrames(ctx, "task-1"); err != nil || len(frames) != 0 {
		t.Fatal("ticket 2 never sees the frames ticket 1 signed (Q13)")
	}
	if got, err := b.ReadArtifact(ctx, "task-1", string(layout.ArtifactTaskInput)); err != nil || !bytes.Equal(got, input) {
		t.Fatalf("the verified input is shared by every round of the task: %q, %v", got, err)
	}
	ida, erra := a.workerBundleID("task-1", nodewire.EvidenceKindWorkerTokenOpening)
	idb, errb := b.workerBundleID("task-1", nodewire.EvidenceKindWorkerTokenOpening)
	if erra != nil || errb != nil || reflect.DeepEqual(ida, idb) || !reflect.DeepEqual(ida, evidence.WorkerTokenBundle(a.evidenceKey)) {
		t.Fatal("each ticket publishes its Worker bundles in its own namespace")
	}
}

func TestTaskRunnerWaitsForTheRecordWithoutSpendingRetries(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r := NewTaskRunner(TaskRunnerConfig{Store: st, DispatchWaitInterval: time.Second})
	task := store.InferTask{TaskID: "t"}
	now := time.UnixMilli(1_000)
	r.recordInferRetry(&task, builderclient.Retryable(fmt.Errorf("%w: %w", errChainStateWaiting, worker.ErrAwaitingDispatchRecord)), now, codec.Hash{1})
	if task.RetryCount != 0 || task.RetryAtUnixMilli != 2_000 || task.Stage == "failed" {
		t.Fatalf("task = %+v", task)
	}
	r.recordInferRetry(&task, errors.New("boom"), now, codec.Hash{1})
	if task.RetryCount != 1 {
		t.Fatal("a real failure still counts")
	}
}

func TestTaskRunnerReleasesTheTaskLease(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var released []layout.StoredHash
	r := NewTaskRunner(TaskRunnerConfig{Store: st, ReleaseDispatchLease: func(_ context.Context, id layout.StoredHash) error {
		released = append(released, id)
		return nil
	}})
	taskID := strings.Repeat("03", 32)
	hash := codec.Hash{2}
	r.infer = map[codec.Hash]store.InferTask{hash: {TaskID: taskID, DispatchTicketHash: codec.Hash{9}, Stage: "running"}}
	for i := 0; i < 2; i++ {
		if err := r.applyOutcome(ctx, taskOutcome{role: "infer", hash: hash, infer: store.InferTask{TaskID: taskID, Stage: "succeeded"}}); err != nil {
			t.Fatal(err)
		}
	}
	want := layout.StoredHash(bytes.Repeat([]byte{0x03}, 32))
	if len(released) != 1 || released[0] != want {
		t.Fatalf("released = %v: once, when the infer succeeds", released)
	}
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{Type: ReconcilerEffectInferTerminal, TaskID: taskID, TaskHash: codec.Hash{4}}}); err != nil {
		t.Fatal(err)
	}
	if len(released) != 2 {
		t.Fatal("an infer terminal releases it too (idempotent in the ledger)")
	}
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{Type: ReconcilerEffectTaskTerminal, TaskID: taskID, TaskHash: codec.Hash{4}}}); err != nil {
		t.Fatal(err)
	}
	if len(released) != 3 {
		t.Fatal("a task terminal releases it too")
	}
}

func TestDispatcherReleasesARecordedTaskLease(t *testing.T) {
	ctx := context.Background()
	x, _, _ := seedDispatchedInfer(t)
	rec := x.record(t)
	before := x.hr.notifications()
	if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil {
		t.Fatal(err)
	}
	if held, _ := layout.HasWorkerTaskLease(ctx, x.st, rec.TaskID); held {
		t.Fatal("the (task_id, WORKER) lease is released")
	}
	if free, _ := x.leases.FreeSlots(); free != 2 || x.hr.notifications() != before+1 {
		t.Fatalf("free = %d: the slot returns and the handraise is re-evaluated", free)
	}
	if err := x.d.ReleaseTaskLease(ctx, rec.TaskID); err != nil || x.hr.notifications() != before+1 {
		t.Fatal("a second release is a quiet no-op")
	}
	if err := x.d.ObserveDispatchRecorded(ctx, x.fact(120, 150)); err != nil {
		t.Fatalf("a redelivered record after the lease went back is a no-op: %v", err)
	}
}

// seedDispatchedInfer drives the S4/S5 harness to a recorded ticket and returns
// its store with the matching InferTask, so executor tests run the Phase 1
// source of facts.
func seedDispatchedInfer(t *testing.T) (*dispatchHarness, store.InferTask, codec.Hash) {
	return seedDispatchedInferWith(t, nil)
}

func seedDispatchedInferWith(t *testing.T, tweak func(*DispatcherConfig)) (*dispatchHarness, store.InferTask, codec.Hash) {
	t.Helper()
	x := newDispatchHarness(t, 2, tweak)
	rec := x.committed(t)
	x.chainRecords(t, x.fx.ticketHash(), hrCortex, 120, 150)
	if err := x.d.ObserveDispatchRecorded(context.Background(), x.fact(120, 150)); err != nil {
		t.Fatal(err)
	}
	task := store.InferTask{
		TaskID: hex.EncodeToString(rec.TaskID[:]), SessionID: hex.EncodeToString(rec.SessionID[:]), OrderSequence: rec.OrderSequence,
		ModelID: rec.ModelID, ProfileVersion: rec.ProfileVersion, InputDigest: codec.Hash(rec.InputHash), InputSizeBytes: rec.InputSizeBytes,
		WorkerAddress: hrCortex, BuilderOperatorAddress: rec.Builder, DeadlineHeight: 150, WinnerConfirmHeight: 120,
		DispatchTicketHash: codec.Hash(rec.TicketHash), Stage: string(layout.StageQueued),
		Capability: modelservice.CapabilityLLMTextV1,
	}
	return x, task, codec.Hash(rec.TaskHash)
}
