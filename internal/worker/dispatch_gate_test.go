package worker

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
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
