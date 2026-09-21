package taskfsm

import (
	"errors"
	"fmt"
	"slices"
)

var (
	ErrDualRole          = errors.New("local node cannot be worker and verifier for same task")
	ErrProtocolEventOnly = errors.New("state requires accepted chain event")
)

type Config struct {
	LocalOperatorAddress     string
	Duties                   []Duty
	ChallengeVerifierEnabled bool
}

type Duty string

const (
	DutyWorker   Duty = "WORKER"
	DutyVerifier Duty = "VERIFIER"
)

type FSM struct {
	cfg Config
}

type Task struct {
	ID             string
	State          State
	Role           Role
	ChallengeState ChallengeState
}

type Event struct {
	Type        EventType
	TaskID      string
	Worker      string
	Verifier    string
	Verifiers   []string
	ChallengeID string
}

func New(cfg Config) *FSM {
	return &FSM{cfg: cfg}
}

func (f *FSM) Apply(task Task, event Event) (Task, []Effect, error) {
	if event.TaskID != "" && task.ID != "" && event.TaskID != task.ID {
		return task, nil, fmt.Errorf("event task %q does not match task %q", event.TaskID, task.ID)
	}

	next := task
	if isTerminal(task.State) && !isChallengeEvent(event.Type) {
		return next, nil, nil
	}
	switch event.Type {
	case EventMsgAssignAccepted:
		next.State = StateAssignRandomnessPending
		return next, nil, nil
	case EventAssignmentFinalized:
		if task.State != StateAssignRandomnessPending {
			return next, nil, nil
		}
		if event.Worker != f.cfg.LocalOperatorAddress || !f.hasDuty(DutyWorker) {
			next.State = StateClosed
			return next, nil, nil
		}
		if task.Role == RoleVerifier {
			return task, nil, ErrDualRole
		}
		next.State = StateWorkerAssigned
		next.Role = RoleWorker
		return next, []Effect{EffectStartInfer}, nil
	case EventVerifierAssigned:
		if event.Verifier != f.cfg.LocalOperatorAddress || !f.hasDuty(DutyVerifier) {
			return next, nil, nil
		}
		if task.Role == RoleWorker {
			return task, nil, ErrDualRole
		}
		next.State = StateVerifyAssigned
		next.Role = RoleVerifier
		return next, nil, nil
	case EventChallengeOpened:
		next.ChallengeState = ChallengeStateObserved
		return next, nil, nil
	case EventChallengeSampleSeedReady:
		if task.ChallengeState != ChallengeStateObserved {
			return next, nil, nil
		}
		next.ChallengeState = ChallengeStateSeedPending
		return next, nil, nil
	case EventChallengeVerifierAssigned:
		if event.Verifier != f.cfg.LocalOperatorAddress || !f.hasDuty(DutyVerifier) {
			return next, nil, nil
		}
		if !f.cfg.ChallengeVerifierEnabled {
			next.ChallengeState = ChallengeStateAlertOnly
			return next, []Effect{EffectRecordChallengeAlert}, nil
		}
		next.ChallengeState = ChallengeStateAssigned
		return next, nil, nil
	case EventChallengeVerifyStarted:
		if event.Verifier != "" && event.Verifier != f.cfg.LocalOperatorAddress {
			return next, nil, nil
		}
		if task.ChallengeState != ChallengeStateAssigned {
			return next, nil, nil
		}
		next.ChallengeState = ChallengeStateVerifyRunning
		return next, nil, nil
	case EventChallengeCommitAccepted:
		if event.Verifier != "" && event.Verifier != f.cfg.LocalOperatorAddress {
			return next, nil, nil
		}
		if task.ChallengeState != ChallengeStateVerifyRunning && task.ChallengeState != ChallengeStateAssigned {
			return next, nil, ErrProtocolEventOnly
		}
		next.ChallengeState = ChallengeStateCommitSent
		return next, nil, nil
	case EventChallengeResultAccepted:
		if event.Verifier != "" && event.Verifier != f.cfg.LocalOperatorAddress {
			return next, nil, nil
		}
		if task.ChallengeState != ChallengeStateCommitSent {
			return next, nil, ErrProtocolEventOnly
		}
		next.ChallengeState = ChallengeStateResultSent
		return next, nil, nil
	case EventChallengeOutcomeRecorded:
		if task.ChallengeState != ChallengeStateResultSent {
			return next, nil, nil
		}
		next.ChallengeState = ChallengeStateSettled
		return next, nil, nil
	case EventInferReceiptAccepted:
		if task.State != StateWorkerAssigned && task.State != StateInferRunning && task.State != StateInferDelivering {
			return next, nil, nil
		}
		next.State = StateInferReceiptAccepted
		return next, nil, nil
	case EventOpenVerifyAccepted:
		if !f.hasDuty(DutyVerifier) {
			return next, nil, nil
		}
		if task.Role == RoleWorker {
			return task, nil, ErrDualRole
		}
		if len(event.Verifiers) > 0 && !slices.Contains(event.Verifiers, f.cfg.LocalOperatorAddress) {
			return next, nil, nil
		}
		if len(event.Verifiers) == 0 && event.Verifier != "" && event.Verifier != f.cfg.LocalOperatorAddress {
			return next, nil, nil
		}
		if task.State != StateInferReceiptAccepted && task.State != StateDiscovered && task.State != StateWorkerHandraised {
			return next, nil, nil
		}
		next.State = StateVerifyAssigned
		next.Role = RoleVerifier
		return next, nil, nil
	case EventVerificationSampleSeedReady:
		if !f.hasDuty(DutyVerifier) {
			return next, nil, nil
		}
		if task.Role == RoleWorker {
			return task, nil, ErrDualRole
		}
		if len(event.Verifiers) > 0 && !slices.Contains(event.Verifiers, f.cfg.LocalOperatorAddress) {
			return next, nil, nil
		}
		if len(event.Verifiers) == 0 && event.Verifier != "" && event.Verifier != f.cfg.LocalOperatorAddress {
			return next, nil, nil
		}
		if task.State != StateVerifyAssigned && task.State != StateInferReceiptAccepted && task.State != StateDiscovered && task.State != StateWorkerHandraised {
			return next, nil, nil
		}
		next.State = StateVerifyAssigned
		next.Role = RoleVerifier
		return next, []Effect{EffectStartVerify}, nil
	case EventVerifierCommitAccepted:
		if task.State != StateVerifyAssigned {
			return task, nil, ErrProtocolEventOnly
		}
		next.State = StateVerifierCommitAccepted
		return next, nil, nil
	case EventVerifierResultAccepted:
		if task.State != StateVerifierCommitAccepted {
			return task, nil, ErrProtocolEventOnly
		}
		next.State = StateVerifierResultAccepted
		return next, nil, nil
	case EventSettleAccepted:
		if task.State == StateClosed {
			return next, nil, nil
		}
		next.State = StateSettled
		return next, nil, nil
	case EventSweepDeadlineAccepted:
		next.State = StateSweepObserved
		return next, nil, nil
	default:
		return task, nil, fmt.Errorf("unsupported event type %q", event.Type)
	}
}

func (f *FSM) hasDuty(duty Duty) bool {
	return slices.Contains(f.cfg.Duties, duty)
}

func isTerminal(state State) bool {
	return state == StateClosed || state == StateSettled || state == StateSweepObserved || state == StateEvidenceCleanable
}

func isChallengeEvent(event EventType) bool {
	switch event {
	case EventChallengeOpened,
		EventChallengeSampleSeedReady,
		EventChallengeVerifierAssigned,
		EventChallengeVerifyStarted,
		EventChallengeCommitAccepted,
		EventChallengeResultAccepted,
		EventChallengeOutcomeRecorded:
		return true
	default:
		return false
	}
}
