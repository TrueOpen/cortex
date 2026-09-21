package chainclient

import (
	"strconv"
	"testing"
)

func TestKeeperEventsPageRejectsLagBeyondLimit(t *testing.T) {
	page := KeeperEventsPage{ChainHeight: 100, LastEventHeight: 80}
	if err := page.ValidateLag(19); err == nil {
		t.Fatalf("ValidateLag() error = nil, want lag refusal")
	}
	if err := page.ValidateLag(20); err != nil {
		t.Fatalf("ValidateLag(20) error = %v, want allowed exact limit", err)
	}
}

func TestKeeperEventDigestIsStableAndHeightSensitive(t *testing.T) {
	event := KeeperEvent{Type: KeeperEventAssignmentFinalized, TaskID: "task-1", Height: 91, Worker: "worker-local"}
	first := event.Digest()
	second := event.Digest()
	if first == "" || first != second {
		t.Fatalf("Digest() first=%q second=%q, want stable non-empty digest", first, second)
	}
	event.Height++
	if event.Digest() == first {
		t.Fatalf("Digest() did not change after height changed")
	}
	if _, err := strconv.ParseUint(first, 16, 64); err == nil && len(first) <= 16 {
		t.Fatalf("Digest() = %q, want full hash not short integer", first)
	}
}

func TestKeeperEventDigestBindsRawContractVersion(t *testing.T) {
	event := KeeperEvent{Type: KeeperEventSettleAccepted, ContractVersion: KeeperEventContractVersionV1, RawType: "task.v1.EventSettleAccepted", Known: true, TaskID: "task-1", Height: 91}
	first := event.Digest()
	event.ContractVersion = "node-event-indexer-v2"
	if event.Digest() == first {
		t.Fatal("Keeper event digest does not bind contract version")
	}
}

func TestKeeperEventValidateRejectsUnversionedRecognizedRawEvent(t *testing.T) {
	event := KeeperEvent{Type: KeeperEventSettleAccepted, RawType: "task.v1.EventSettleAccepted", Known: true, TaskID: "task-1", Height: 91}
	if err := event.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want raw event contract version requirement")
	}
}

func TestKeeperEventValidateAllowsModelLevelProjectionEventsWithoutTaskID(t *testing.T) {
	types := []KeeperEventType{
		KeeperEventEmergencyFreezeAccepted,
		KeeperEventFreezeSignalSubmitted,
		KeeperEventModelProfileStateChanged,
		KeeperEventModelSupportUpdated,
	}

	for _, eventType := range types {
		t.Run(string(eventType), func(t *testing.T) {
			event := KeeperEvent{
				Type:           eventType,
				Height:         10,
				ModelID:        "model-a",
				ProfileVersion: "1",
			}
			if eventType == KeeperEventModelSupportUpdated {
				event.Worker = "node-1"
			}

			if err := event.Validate(); err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}
		})
	}
}

func TestKeeperEventValidateRequiresOperatorForModelSupport(t *testing.T) {
	event := KeeperEvent{Type: KeeperEventModelSupportUpdated, Height: 10, ModelID: "model-a", ProfileVersion: "1"}
	if err := event.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want operator_address requirement")
	}
}

func TestKeeperEventValidateAllowsIndependentRegistrationEvents(t *testing.T) {
	if err := (KeeperEvent{Type: KeeperEventModelRegistered, Height: 10, ModelID: "model-a"}).Validate(); err != nil {
		t.Fatalf("model registration Validate() error = %v", err)
	}
	if err := (KeeperEvent{Type: KeeperEventProfileRegistered, Height: 11, ModelID: "model-a", ProfileVersion: "1"}).Validate(); err != nil {
		t.Fatalf("profile registration Validate() error = %v", err)
	}
	if err := (KeeperEvent{Type: KeeperEventProfileRegistered, Height: 11, ModelID: "model-a"}).Validate(); err == nil {
		t.Fatal("profile registration Validate() error = nil, want profile_version requirement")
	}
}

func TestKeeperEventValidateRejectsLegacyProfileVersion(t *testing.T) {
	for _, version := range []string{"v1", "llm_text_v1", "01", "0"} {
		event := KeeperEvent{Type: KeeperEventProfileRegistered, Height: 11, ModelID: "model-a", ProfileVersion: version}
		if err := event.Validate(); err == nil {
			t.Fatalf("Validate profile_version %q error = nil, want canonical uint32 rejection", version)
		}
	}
}

func TestKeeperEventValidateRequiresTaskIDForTaskScopedEvents(t *testing.T) {
	types := []KeeperEventType{
		KeeperEventRewardMarked,
		KeeperEventTaskFailureClassUpdated,
		KeeperEventSettlementFinalityUpdated,
	}
	for _, eventType := range types {
		t.Run(string(eventType), func(t *testing.T) {
			if err := (KeeperEvent{Type: eventType, Height: 10}).Validate(); err == nil {
				t.Fatalf("Validate returned nil, want task_id requirement")
			}
		})
	}
}

func TestKeeperEventValidateAllowsGlobalEventsWithoutTaskOrModel(t *testing.T) {
	for _, eventType := range []KeeperEventType{KeeperEventModelSupportBatchAccepted, KeeperEventMarkGateUpdated, KeeperEventBuilderSetUpdated, KeeperEventFaultRecorded} {
		if err := (KeeperEvent{Type: eventType, Height: 10}).Validate(); err != nil {
			t.Fatalf("Validate(%s) returned error: %v", eventType, err)
		}
	}
}

// TestKeeperEventValidateAcceptsSessionScopedDeadlineSweep pins the one
// task-scoped event type the chain also emits without a task_id.
//
// task's sweep has two emitters, and EventDeadlineSwept's session_id and
// task_id are both `optional` on the wire because of it:
// emitDeadlineSweptEvent carries both, and emitSessionDeadlineSweptEvent
// carries a session_id, DEADLINE_KIND_V1_SESSION_LIFECYCLE and no task at all.
// Demanding a task_id from every sweep quarantined the session-scoped one on
// every occurrence, which is a refusal of a frame the chain emits by design.
func TestKeeperEventValidateAcceptsSessionScopedDeadlineSweep(t *testing.T) {
	sessionScoped := KeeperEvent{
		Type:      KeeperEventDeadlineSwept,
		Height:    13872,
		SessionID: "a1b2c3",
	}
	if err := sessionScoped.Validate(); err != nil {
		t.Fatalf("session-scoped EventDeadlineSwept Validate() error = %v, want accepted", err)
	}
	taskScoped := KeeperEvent{
		Type:   KeeperEventDeadlineSwept,
		Height: 13772,
		TaskID: "fb0197fe",
	}
	if err := taskScoped.Validate(); err != nil {
		t.Fatalf("task-scoped EventDeadlineSwept Validate() error = %v, want accepted", err)
	}
	// Neither scope is not a sweep of anything: the identification layer
	// produced no subject at all, and accepting it would let a malformed frame
	// through both branches below it.
	if err := (KeeperEvent{Type: KeeperEventDeadlineSwept, Height: 13872}).Validate(); err == nil {
		t.Fatal("scopeless EventDeadlineSwept Validate() error = nil, want a session_id or task_id requirement")
	}
}
