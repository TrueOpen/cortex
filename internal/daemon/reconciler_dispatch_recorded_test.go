package daemon

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

func dispatchRecordedEvent(ticket string) chainclient.KeeperEvent {
	return chainclient.KeeperEvent{
		Type: chainclient.KeeperEventDispatchRecorded, Known: true, ContractVersion: chainclient.KeeperEventContractVersionV1,
		RawType: "task.v1.EventDispatchRecorded", Height: 120, Position: chainclient.EventPosition{Height: 120},
		TaskID: strings.Repeat("03", 32), SessionID: strings.Repeat("04", 32), OrderSequence: 7, Worker: hrCortex, InferDeadlineHeight: 150,
		Attributes: map[string]string{"dispatch_ticket_hash": ticket, "dispatch_record_hash": strings.Repeat("77", 32), "builder": hrBuilderA},
	}
}

func TestReconcilerTurnsDispatchRecordedIntoAnEffect(t *testing.T) {
	quarantined := 0
	r := NewReconciler(ReconcilerOptions{OnQuarantinedEvent: func(chainclient.KeeperEvent) { quarantined++ }})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{dispatchRecordedEvent(strings.Repeat("42", 32))})
	if err != nil || len(effects) != 1 {
		t.Fatalf("effects = %d, %v (no Task snapshot is read for it)", len(effects), err)
	}
	e := effects[0]
	f := e.Dispatch
	if e.Type != ReconcilerEffectDispatchRecorded || f.Height != 120 || f.OrderSequence != 7 || f.Winner != hrCortex || f.Builder != hrBuilderA ||
		f.InferDeadline != 150 || f.TicketHash != layout.StoredHash(bytes.Repeat([]byte{0x42}, 32)) ||
		f.TaskID != layout.StoredHash(bytes.Repeat([]byte{0x03}, 32)) || f.SessionID != layout.StoredHash(bytes.Repeat([]byte{0x04}, 32)) ||
		f.RecordHash != layout.StoredHash(bytes.Repeat([]byte{0x77}, 32)) || e.Event.Attributes != nil {
		t.Fatalf("effect = %+v", e)
	}
	for name, ev := range map[string]chainclient.KeeperEvent{
		"no ticket": dispatchRecordedEvent(""),
		"no deadline": func() chainclient.KeeperEvent {
			e := dispatchRecordedEvent(strings.Repeat("42", 32))
			e.InferDeadlineHeight = 0
			return e
		}(),
		"no builder": func() chainclient.KeeperEvent {
			e := dispatchRecordedEvent(strings.Repeat("42", 32))
			delete(e.Attributes, "builder")
			return e
		}(),
		"short record": func() chainclient.KeeperEvent {
			e := dispatchRecordedEvent(strings.Repeat("42", 32))
			e.Attributes["dispatch_record_hash"] = "77"
			return e
		}(),
	} {
		before := quarantined
		if effects, _ := r.Apply(context.Background(), []chainclient.KeeperEvent{ev}); len(effects) != 0 || quarantined != before+1 {
			t.Fatalf("%s: an incomplete event is quarantined: %d effects", name, len(effects))
		}
	}
}

type recordingObserver struct {
	mu     sync.Mutex
	facts  []DispatchRecordedFact
	err    error
	runner *TaskRunner
}

func (o *recordingObserver) ObserveDispatchRecorded(_ context.Context, f DispatchRecordedFact) error {
	if !o.runner.mu.TryLock() {
		return errors.New("called under the runner lock")
	}
	o.runner.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.facts = append(o.facts, f)
	return o.err
}

func (o *recordingObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.facts)
}

func TestTaskRunnerForwardsDispatchRecordedOutsideItsLock(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	obs := &recordingObserver{}
	var refused []error
	r := NewTaskRunner(TaskRunnerConfig{Store: st, DispatchRecords: obs, OnQuarantinedEffect: func(_ ReconcilerEffect, err error) { refused = append(refused, err) }})
	obs.runner = r
	effect := ReconcilerEffect{Type: ReconcilerEffectDispatchRecorded, TaskID: strings.Repeat("03", 32), Dispatch: DispatchRecordedFact{Height: 120}}
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{effect}); err != nil || obs.count() != 1 {
		t.Fatalf("forwarded %d, %v", obs.count(), err)
	}
	obs.err = builderclient.Retryable(errors.New("query lags"))
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{effect}); !builderclient.IsRetryable(err) || !chainclient.IsRetryable(err) {
		t.Fatalf("a lagging confirmation retries the page, and the poller reads it as retryable: %v", err)
	}
	obs.err = errors.New("ChainObservationConflict")
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{effect}); err != nil || len(refused) != 1 {
		t.Fatalf("a permanent refusal is reported, not retried forever: %v, %d", err, len(refused))
	}
	if err := NewTaskRunner(TaskRunnerConfig{Store: st}).ApplyReconcilerEffects(ctx, []ReconcilerEffect{effect}); err != nil {
		t.Fatal("no observer wired (before S9) is not an error")
	}
}
