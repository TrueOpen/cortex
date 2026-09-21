package taskfsm

import (
	"errors"
	"testing"
)

func TestStateNamesMatchMVPMainlineSpec(t *testing.T) {
	required := []State{
		StateDiscovered,
		StateWorkerPrechecked,
		StateWorkerHandraised,
		StateAssignRandomnessPending,
		StateAssignmentFinalized,
		StateWorkerAssigned,
		StateInferRunning,
		StateInferDelivering,
		StateInferReceiptAccepted,
		StateVerifyAssigned,
		StateWorkerRevealAccepted,
		StateSettled,
		StateSweepObserved,
		StateChallengeWindow,
		StateEvidenceCleanable,
		StateClosed,
	}
	for _, state := range required {
		if state == "" {
			t.Fatalf("required state is empty")
		}
	}
}

func TestMsgAssignAcceptedOnlyEntersRandomnessPending(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "worker-local", Duties: []Duty{DutyWorker}})
	task := Task{ID: "task-1", State: StateDiscovered}

	next, effects, err := fsm.Apply(task, Event{Type: EventMsgAssignAccepted, TaskID: task.ID, Worker: "worker-local"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.State != StateAssignRandomnessPending {
		t.Fatalf("state = %s, want %s", next.State, StateAssignRandomnessPending)
	}
	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none before finalized winner", effects)
	}
}

func TestOnlyAssignmentFinalizedWithLocalWinnerEntersWorkerAssigned(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "worker-local", Duties: []Duty{DutyWorker}})
	task := Task{ID: "task-1", State: StateAssignRandomnessPending}

	nonWinner, effects, err := fsm.Apply(task, Event{Type: EventAssignmentFinalized, TaskID: task.ID, Worker: "worker-other"})
	if err != nil {
		t.Fatalf("non-winner Apply returned error: %v", err)
	}
	if nonWinner.State == StateWorkerAssigned {
		t.Fatalf("non-local winner state = %s, must not enter %s", nonWinner.State, StateWorkerAssigned)
	}
	if len(effects) != 0 {
		t.Fatalf("non-local winner effects = %#v, want none", effects)
	}

	localWinner, effects, err := fsm.Apply(task, Event{Type: EventAssignmentFinalized, TaskID: task.ID, Worker: "worker-local"})
	if err != nil {
		t.Fatalf("local winner Apply returned error: %v", err)
	}
	if localWinner.State != StateWorkerAssigned {
		t.Fatalf("local winner state = %s, want %s", localWinner.State, StateWorkerAssigned)
	}
	if len(effects) != 1 || effects[0] != EffectStartInfer {
		t.Fatalf("local winner effects = %#v, want [%s]", effects, EffectStartInfer)
	}
}

func TestAssignmentFinalizedRequiresConfiguredWorkerDuty(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}})
	task := Task{ID: "task-1", State: StateAssignRandomnessPending}

	next, effects, err := fsm.Apply(task, Event{Type: EventAssignmentFinalized, TaskID: task.ID, Worker: "node-1"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.State != StateClosed || len(effects) != 0 {
		t.Fatalf("next/effects = %#v/%#v, want closed without worker duty", next, effects)
	}
}

func TestRoleLockRejectsDualWorkerVerifierRoleForSameTask(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyWorker, DutyVerifier}})
	task := Task{ID: "task-1", State: StateWorkerAssigned, Role: RoleWorker}

	_, _, err := fsm.Apply(task, Event{Type: EventVerifierAssigned, TaskID: task.ID, Verifier: "node-1"})
	if !errors.Is(err, ErrDualRole) {
		t.Fatalf("Apply error = %v, want %v", err, ErrDualRole)
	}
}

func TestRoleLockRejectsVerifierBecomingWorker(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyWorker, DutyVerifier}})
	task := Task{ID: "task-1", State: StateAssignRandomnessPending, Role: RoleVerifier}

	_, _, err := fsm.Apply(task, Event{Type: EventAssignmentFinalized, TaskID: task.ID, Worker: "node-1"})
	if !errors.Is(err, ErrDualRole) {
		t.Fatalf("Apply error = %v, want %v", err, ErrDualRole)
	}
}

func TestOpenVerifyDoesNotBypassWorkerVerifierRoleLock(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}})
	task := Task{ID: "task-1", State: StateWorkerAssigned, Role: RoleWorker}

	_, _, err := fsm.Apply(task, Event{Type: EventOpenVerifyAccepted, TaskID: task.ID, Verifier: "node-1"})
	if !errors.Is(err, ErrDualRole) {
		t.Fatalf("Apply error = %v, want %v", err, ErrDualRole)
	}
}

func TestOpenVerifyAcceptedWaitsForSampleSeedBeforeStartingVerify(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}})
	task := Task{ID: "task-1", State: StateInferReceiptAccepted}

	next, effects, err := fsm.Apply(task, Event{Type: EventOpenVerifyAccepted, TaskID: task.ID, Verifier: "node-1"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.State != StateVerifyAssigned || next.Role != RoleVerifier {
		t.Fatalf("next task = %#v, want verifier assigned", next)
	}
	if len(effects) != 0 {
		t.Fatalf("open verify effects = %#v, want none before sample seed", effects)
	}

	ready, effects, err := fsm.Apply(next, Event{Type: EventVerificationSampleSeedReady, TaskID: task.ID, Verifier: "node-1"})
	if err != nil {
		t.Fatalf("sample-ready Apply returned error: %v", err)
	}
	if ready.State != StateVerifyAssigned || ready.Role != RoleVerifier {
		t.Fatalf("sample-ready task = %#v, want verifier assigned", ready)
	}
	if len(effects) != 1 || effects[0] != EffectStartVerify {
		t.Fatalf("sample-ready effects = %#v, want [%s]", effects, EffectStartVerify)
	}
}

func TestVerificationSampleSeedReadyAssignsAndStartsVerifierWithoutOpenVerifyEvent(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}})
	task := Task{ID: "task-1", State: StateInferReceiptAccepted}

	next, effects, err := fsm.Apply(task, Event{
		Type:      EventVerificationSampleSeedReady,
		TaskID:    task.ID,
		Verifiers: []string{"node-1", "node-2"},
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.State != StateVerifyAssigned || next.Role != RoleVerifier {
		t.Fatalf("next task = %#v, want assigned verifier", next)
	}
	if len(effects) != 1 || effects[0] != EffectStartVerify {
		t.Fatalf("effects = %#v, want START_VERIFY", effects)
	}
}

func TestOutOfOrderProtocolEventsDoNotRegressClosedTask(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}})
	task := Task{ID: "task-1", State: StateClosed}

	next, effects, err := fsm.Apply(task, Event{Type: EventInferReceiptAccepted, TaskID: task.ID})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.State != StateClosed {
		t.Fatalf("state = %s, want %s", next.State, StateClosed)
	}
	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none", effects)
	}
}

func TestTerminalStatesDoNotRegressOnDelayedEvents(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyWorker, DutyVerifier}})
	for _, state := range []State{StateClosed, StateSettled, StateSweepObserved} {
		t.Run(string(state), func(t *testing.T) {
			task := Task{ID: "task-1", State: state}
			events := []Event{
				{Type: EventMsgAssignAccepted, TaskID: task.ID},
				{Type: EventVerifierAssigned, TaskID: task.ID, Verifier: "node-1"},
				{Type: EventSweepDeadlineAccepted, TaskID: task.ID},
			}
			for _, event := range events {
				next, effects, err := fsm.Apply(task, event)
				if err != nil {
					t.Fatalf("Apply(%s, %s) error = %v", state, event.Type, err)
				}
				if next.State != state {
					t.Fatalf("Apply(%s, %s) state = %s, want %s", state, event.Type, next.State, state)
				}
				if len(effects) != 0 {
					t.Fatalf("Apply(%s, %s) effects = %#v, want none", state, event.Type, effects)
				}
			}
		})
	}
}

func TestChallengeVerifierDisabledRecordsAlertOnlyState(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}, ChallengeVerifierEnabled: false})
	task := Task{ID: "task-1", State: StateClosed}

	next, effects, err := fsm.Apply(task, Event{Type: EventChallengeVerifierAssigned, TaskID: task.ID, ChallengeID: "challenge-1", Verifier: "node-1"})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.ChallengeState != ChallengeStateAlertOnly {
		t.Fatalf("challenge state = %s, want %s", next.ChallengeState, ChallengeStateAlertOnly)
	}
	if len(effects) != 1 || effects[0] != EffectRecordChallengeAlert {
		t.Fatalf("effects = %#v, want [%s]", effects, EffectRecordChallengeAlert)
	}
}

func TestChallengeVerifierEnabledFollowsSeparateChallengeStatePath(t *testing.T) {
	fsm := New(Config{LocalOperatorAddress: "node-1", Duties: []Duty{DutyVerifier}, ChallengeVerifierEnabled: true})
	task := Task{ID: "task-1", State: StateSettled}

	steps := []struct {
		event Event
		want  ChallengeState
	}{
		{Event{Type: EventChallengeOpened, TaskID: task.ID, ChallengeID: "challenge-1"}, ChallengeStateObserved},
		{Event{Type: EventChallengeSampleSeedReady, TaskID: task.ID, ChallengeID: "challenge-1"}, ChallengeStateSeedPending},
		{Event{Type: EventChallengeVerifierAssigned, TaskID: task.ID, ChallengeID: "challenge-1", Verifier: "node-1"}, ChallengeStateAssigned},
		{Event{Type: EventChallengeVerifyStarted, TaskID: task.ID, ChallengeID: "challenge-1", Verifier: "node-1"}, ChallengeStateVerifyRunning},
		{Event{Type: EventChallengeCommitAccepted, TaskID: task.ID, ChallengeID: "challenge-1", Verifier: "node-1"}, ChallengeStateCommitSent},
		{Event{Type: EventChallengeResultAccepted, TaskID: task.ID, ChallengeID: "challenge-1", Verifier: "node-1"}, ChallengeStateResultSent},
		{Event{Type: EventChallengeOutcomeRecorded, TaskID: task.ID, ChallengeID: "challenge-1"}, ChallengeStateSettled},
	}

	for _, step := range steps {
		next, effects, err := fsm.Apply(task, step.event)
		if err != nil {
			t.Fatalf("Apply(%s) returned error: %v", step.event.Type, err)
		}
		if next.State != StateSettled {
			t.Fatalf("ordinary task state changed to %s, want %s", next.State, StateSettled)
		}
		if next.ChallengeState != step.want {
			t.Fatalf("Apply(%s) challenge state = %s, want %s", step.event.Type, next.ChallengeState, step.want)
		}
		if len(effects) != 0 {
			t.Fatalf("Apply(%s) effects = %#v, want none", step.event.Type, effects)
		}
		task = next
	}
}
