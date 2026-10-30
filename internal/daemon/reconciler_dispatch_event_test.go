package daemon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store"
)

func compensationEvent(kind chainclient.KeeperEventType, raw, ticket string, index uint32) chainclient.KeeperEvent {
	return chainclient.KeeperEvent{Type: kind, Known: true, ContractVersion: chainclient.KeeperEventContractVersionV1, RawType: raw,
		Height: 180, Position: chainclient.EventPosition{Height: 180, EventIndex: index}, TaskID: strings.Repeat("03", 32),
		Attributes: map[string]string{"dispatch_ticket_hash": ticket, "builder": hrBuilderA, "worker": hrCortex}}
}

func TestReconcilerTurnsCompensationEventsIntoEffects(t *testing.T) {
	quarantined := 0
	r := NewReconciler(ReconcilerOptions{OnQuarantinedEvent: func(chainclient.KeeperEvent) { quarantined++ }})
	ticket := strings.Repeat("42", 32)
	events := []chainclient.KeeperEvent{
		compensationEvent(chainclient.KeeperEventDispatchCompensationClaimed, "task.v1.EventDispatchCompensationClaimed", ticket, 0),
		compensationEvent(chainclient.KeeperEventDispatchCompensationPaid, "task.v1.EventDispatchCompensationPaid", ticket, 1),
		compensationEvent(chainclient.KeeperEventDispatchCompensationRebutted, "task.v1.EventDispatchCompensationRebutted", ticket, 2),
	}
	effects, err := r.Apply(context.Background(), events)
	if err != nil || len(effects) != 3 {
		t.Fatalf("effects = %d, %v", len(effects), err)
	}
	for i, e := range effects {
		f := e.DispatchEvent
		if e.Type != ReconcilerEffectDispatchEvent || f.Type != events[i].Type || f.TicketHash[0] != 0x42 || f.Worker != hrCortex || f.Builder != hrBuilderA || f.Height != 180 {
			t.Fatalf("effect %d = %+v", i, e)
		}
	}
	bad := compensationEvent(chainclient.KeeperEventDispatchCompensationPaid, "task.v1.EventDispatchCompensationPaid", "", 3)
	if effects, _ := r.Apply(context.Background(), []chainclient.KeeperEvent{bad}); len(effects) != 0 || quarantined != 1 {
		t.Fatal("an event without its ticket is quarantined")
	}
}

type recordingEvents struct {
	mu     sync.Mutex
	facts  []DispatchEventFact
	err    error
	runner *TaskRunner
}

func (o *recordingEvents) ObserveDispatchEvent(_ context.Context, f DispatchEventFact) error {
	if !o.runner.mu.TryLock() {
		return errors.New("called under the runner lock")
	}
	o.runner.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.facts = append(o.facts, f)
	return o.err
}

func TestTaskRunnerForwardsDispatchEventsOutsideItsLock(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	obs := &recordingEvents{}
	r := NewTaskRunner(TaskRunnerConfig{Store: st, DispatchEvents: obs})
	obs.runner = r
	e := ReconcilerEffect{Type: ReconcilerEffectDispatchEvent, TaskID: strings.Repeat("03", 32),
		DispatchEvent: DispatchEventFact{Type: chainclient.KeeperEventDispatchCompensationPaid}}
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{e}); err != nil || len(obs.facts) != 1 {
		t.Fatalf("forwarded %d, %v", len(obs.facts), err)
	}
	obs.err = builderclient.Retryable(errors.New("query lags"))
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{e}); !builderclient.IsRetryable(err) {
		t.Fatalf("lag retries the page: %v", err)
	}
	obs.err = errors.New("ChainObservationConflict")
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{e}); err != nil {
		t.Fatal("a permanent refusal is reported, not retried")
	}
	if err := NewTaskRunner(TaskRunnerConfig{Store: st}).ApplyReconcilerEffects(ctx, []ReconcilerEffect{e}); err != nil {
		t.Fatal("no observer before S9 is not an error")
	}
}
