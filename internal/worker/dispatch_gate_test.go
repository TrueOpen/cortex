package worker

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

type fakeGate struct {
	mu       sync.Mutex
	state    DeliveryState
	err      error
	receipts []builderclient.SignedInferReceipt
}

func (g *fakeGate) DeliveryState(_ context.Context, ticket codec.Hash) (DeliveryState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ticket != workerTestTicket {
		return DeliveryState{}, errors.New("gate asked about another ticket")
	}
	return g.state, g.err
}

func (g *fakeGate) ReceiptSigned(_ context.Context, ticket codec.Hash, r builderclient.SignedInferReceipt) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ticket != workerTestTicket {
		return errors.New("receipt handed over for another ticket")
	}
	g.receipts = append(g.receipts, r)
	return nil
}

func (g *fakeGate) set(s DeliveryState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = s
}

func (g *fakeGate) signed() []builderclient.SignedInferReceipt {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]builderclient.SignedInferReceipt(nil), g.receipts...)
}

func TestWorkerWaitsForTheRecordBeforeSigningTheReceipt(t *testing.T) {
	ctx := context.Background()
	gate := &fakeGate{}
	h := newHarnessWithConfig(t, func(c *Config) { c.Dispatch = gate })
	enableEvidenceSchema(&h)
	event := finalizedTask()
	// Pre-record the executor passes provisional local heights (the ticket's
	// reference height, D_ticket); no chain infer deadline exists yet.
	event.WinnerConfirmHeight, event.InferDeadlineHeight = 100, 260
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(ctx, event); !errors.Is(err, ErrAwaitingDispatchRecord) {
		t.Fatalf("err = %v", err)
	}
	if len(h.taskData.UploadedOutputFins) != 1 {
		t.Fatal("frames and the Fin reach the dispatching Builder before the record (W11)")
	}
	if len(h.taskData.relays) != 0 || len(h.taskData.FinalizedTaskResults) != 0 || len(gate.signed()) != 0 {
		t.Fatal("no receipt and no evidence before the record (W6, Q1)")
	}
	gate.set(DeliveryState{RecordedHeight: 200, InferDeadlineHeight: 230})
	result, err := New(h.worker.cfg).HandleAssignmentFinalized(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if result.TaskDataReceipt.ExpiryHeight != 230 || result.InferDeadlineHeight != 230 {
		t.Fatalf("expiry_height = %d, want the record's infer_deadline_height, not the provisional bound", result.TaskDataReceipt.ExpiryHeight)
	}
	if got := gate.signed(); len(got) != 1 || got[0].ServiceSignature != result.TaskDataReceipt.ServiceSignature {
		t.Fatal("the signed receipt is handed to the dispatch record (self-rescue source)")
	}
	if len(h.taskData.UploadedOutputFins) != 1 {
		t.Fatal("the stored Fin is not sent twice")
	}
	if len(h.taskData.relays) != 1 || len(h.taskData.FinalizedTaskResults) == 0 {
		t.Fatal("after the record: receipt to the dispatching Builder, evidence to the group")
	}
}

func TestWorkerPausesDeliveryWithoutStoppingGeneration(t *testing.T) {
	ctx := context.Background()
	gate := &fakeGate{state: DeliveryState{Paused: true, Reason: "pending-claim"}}
	h := newHarnessWithConfig(t, func(c *Config) { c.Dispatch = gate })
	enableEvidenceSchema(&h)
	event := finalizedTask()
	event.WinnerConfirmHeight, event.InferDeadlineHeight = 100, 260
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(ctx, event); !errors.Is(err, ErrDeliveryPaused) {
		t.Fatalf("err = %v", err)
	}
	frames, err := h.persistence.OutputStreamFrames(ctx, event.TaskID)
	if err != nil || len(frames) == 0 {
		t.Fatal("inference ran and every frame is journaled (CD §8.6: inference continues)")
	}
	if len(h.taskData.UploadedOutputFins) != 0 || len(h.taskData.relays) != 0 {
		t.Fatal("no Fin and no receipt leave a paused ticket")
	}
	gate.set(DeliveryState{RecordedHeight: 200, InferDeadlineHeight: 230}) // the notice was false (§8.6a)
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(ctx, event); err != nil {
		t.Fatal(err)
	}
	last := h.taskData.UploadedOutputStreams[len(h.taskData.UploadedOutputStreams)-1]
	if len(last.ReplayChunks) != len(frames) || len(h.taskData.UploadedOutputFins) != 1 {
		t.Fatal("delivery resumes by replaying the journaled frames, never regenerating")
	}
	if calls := h.model.InferCalls; calls != 1 {
		t.Fatalf("model ran %d times; a paused ticket resumes without regenerating", calls)
	}
}

func TestWorkerTreatsAnUnreadableGateAsPaused(t *testing.T) {
	gate := &fakeGate{err: errors.New("store unavailable")}
	h := newHarnessWithConfig(t, func(c *Config) { c.Dispatch = gate })
	if !h.worker.deliveryPaused(context.Background()) {
		t.Fatal("a frame is never sent on a state this node cannot read")
	}
}

func TestEvidenceRedundancyTargetIsTwoThirdsRoundedUp(t *testing.T) {
	for n, want := range map[int]int{1: 1, 2: 2, 3: 2, 4: 3, 5: 4, 6: 4, 7: 5} {
		if got := evidenceRedundancyTarget(n); got != want {
			t.Fatalf("target(%d) = %d, want %d", n, got, want)
		}
	}
}

// M2: a ticket whose delivery pauses (a REJECTED notice) while it resumes
// sends nothing: the resumed recorder opens no stream and replays no frame,
// and the Fin is not sent past the gate.
func TestWorkerSendsNothingWhenDeliveryPausesDuringResume(t *testing.T) {
	ctx := context.Background()
	gate := &fakeGate{}
	h := newHarnessWithConfig(t, func(c *Config) { c.Dispatch = gate })
	event := finalizedTask()
	recorder, err := h.worker.newOutputRecorder(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	recorder.awaitOpen()
	for _, text := range []string{"first-frame-text", "tail"} {
		if err := recorder.ObserveInferFrame(ctx, modelservice.InferStreamFrame{TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: text}); err != nil {
			t.Fatal(err)
		}
	}
	saved := completedModelInference{TaskHash: recorder.taskHash, FrameCount: uint64(len(recorder.frames)), Pending: recorder.pending, ObservedBytes: recorder.total}
	_ = recorder.stream.Close()
	gate.set(DeliveryState{Paused: true, Reason: "pending-claim"})
	opened := len(h.taskData.UploadedOutputStreams)
	restored, err := h.worker.resumeOutputRecorder(ctx, event, saved)
	if err != nil {
		t.Fatal(err)
	}
	if restored.stream != nil || len(h.taskData.UploadedOutputStreams) != opened {
		t.Fatal("a paused ticket's resume opened a stream and replayed its frames")
	}
}

func TestWorkerFinWaitsForTheGateRightBeforeItIsSent(t *testing.T) {
	ctx := context.Background()
	gate := &fakeGate{state: DeliveryState{Paused: true, Reason: "pending-claim"}}
	h := newHarnessWithConfig(t, func(c *Config) { c.Dispatch = gate })
	enableEvidenceSchema(&h)
	event := finalizedTask()
	event.WinnerConfirmHeight, event.InferDeadlineHeight = 100, 260
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(ctx, event); !errors.Is(err, ErrDeliveryPaused) {
		t.Fatalf("err = %v", err)
	}
	if err := h.worker.ensureFinDelivered(ctx, event); !errors.Is(err, ErrDeliveryPaused) {
		t.Fatalf("Fin past a paused gate: %v", err)
	}
	if len(h.taskData.UploadedOutputFins) != 0 {
		t.Fatal("the Fin left a paused ticket")
	}
}

// M3: the evidence floor is never met by an empty group.
func TestEvidenceFloorRefusesAnEmptyGroup(t *testing.T) {
	if err := evidenceFloorReached(0, 0, nil); err == nil {
		t.Fatal("no Task Builder group is not success")
	}
	if err := evidenceFloorReached(1, 3, nil); !builderclient.IsRetryable(err) {
		t.Fatalf("below ceil(2/3) retries: %v", err)
	}
	if err := evidenceFloorReached(2, 3, nil); err != nil {
		t.Fatal(err)
	}
}
