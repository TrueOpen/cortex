package daemon

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func dispatchChallengeEvent(kind string) chainclient.KeeperEvent {
	return chainclient.KeeperEvent{Type: chainclient.KeeperEventDispatchChallengeResolved, Known: true, ContractVersion: chainclient.KeeperEventContractVersionV1,
		RawType: "task.v1.EventDispatchChallengeResolved", Height: 230, Position: chainclient.EventPosition{Height: 230}, TaskID: strings.Repeat("03", 32),
		Attributes: map[string]string{"challenge_id": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xc1", 32))), "kind": kind,
			"outcome": "DISPATCH_CHALLENGE_STATUS_V1_UPHELD"}}
}

func TestReconcilerTurnsChallengeEventsIntoEffects(t *testing.T) {
	quarantined := 0
	r := NewReconciler(ReconcilerOptions{OnQuarantinedEvent: func(chainclient.KeeperEvent) { quarantined++ }})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{dispatchChallengeEvent("DISPATCH_CHALLENGE_KIND_V1_OMISSION")})
	if err != nil || len(effects) != 1 {
		t.Fatalf("effects %d, %v", len(effects), err)
	}
	e := effects[0]
	f := e.DispatchEvent
	if e.Type != ReconcilerEffectDispatchEvent || f.ChallengeID[0] != 0xc1 || f.Kind != sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION ||
		f.Height != 230 || f.TaskID[0] != 3 || f.Type != chainclient.KeeperEventDispatchChallengeResolved || e.Event.Attributes != nil {
		t.Fatalf("effect = %+v", e)
	}
	if effects, _ := r.Apply(context.Background(), []chainclient.KeeperEvent{dispatchChallengeEvent("")}); len(effects) != 0 || quarantined != 1 {
		t.Fatalf("an event without a kind is quarantined: %d effects", len(effects))
	}
}

func TestChallengeEffectsReachEveryObserverThroughTheTaskRunner(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	dispatcher, omission := &recordingEvents{}, &fanoutEvents{}
	r := NewTaskRunner(TaskRunnerConfig{Store: st, DispatchEvents: DispatchEventObservers{dispatcher, omission}})
	dispatcher.runner = r
	effects, err := NewReconciler(ReconcilerOptions{}).Apply(ctx, []chainclient.KeeperEvent{dispatchChallengeEvent("DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE")})
	if err != nil || len(effects) != 1 {
		t.Fatalf("effects %d, %v", len(effects), err)
	}
	if err := r.ApplyReconcilerEffects(ctx, effects); err != nil || len(dispatcher.facts) != 1 || len(omission.events) != 1 ||
		omission.events[0].ChallengeID[0] != 0xc1 || omission.events[0].Kind != sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_ROSTER_UNAVAILABLE {
		t.Fatalf("forwarded %d/%d, %v", len(dispatcher.facts), len(omission.events), err)
	}
}
