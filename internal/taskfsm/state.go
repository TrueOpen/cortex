package taskfsm

type State string

const (
	StateDiscovered              State = "DISCOVERED"
	StateWorkerPrechecked        State = "WORKER_PRECHECKED"
	StateWorkerHandraised        State = "WORKER_HANDRAISED"
	StateAssignRandomnessPending State = "ASSIGN_RANDOMNESS_PENDING"
	StateAssignmentFinalized     State = "ASSIGNMENT_FINALIZED"
	StateWorkerAssigned          State = "WORKER_ASSIGNED"
	StateInferRunning            State = "INFER_RUNNING"
	StateInferDelivering         State = "INFER_DELIVERING"
	StateInferReceiptAccepted    State = "INFER_RECEIPT_ACCEPTED"
	StateVerifyAssigned          State = "VERIFY_ASSIGNED"
	StateVerifierCommitAccepted  State = "VERIFY_COMMIT_ACCEPTED"
	StateVerifierResultAccepted  State = "VERIFY_REVEAL_ACCEPTED"
	StateWorkerRevealAccepted    State = "WORKER_REVEAL_ACCEPTED"
	StateSettlementReady         State = "SETTLEMENT_READY_SENT"
	StateSettled                 State = "SETTLED"
	StateSweepObserved           State = "SWEEP_OBSERVED"
	StateChallengeWindow         State = "CHALLENGE_WINDOW"
	StateEvidenceCleanable       State = "EVIDENCE_CLEANABLE"
	StateClosed                  State = "CLOSED"
)

type ChallengeState string

const (
	ChallengeStateNone          ChallengeState = ""
	ChallengeStateAlertOnly     ChallengeState = "ALERT_ONLY"
	ChallengeStateObserved      ChallengeState = "CHALLENGE_OBSERVED"
	ChallengeStateSeedPending   ChallengeState = "CHALLENGE_SEED_PENDING"
	ChallengeStateAssigned      ChallengeState = "CHALLENGE_ASSIGNED"
	ChallengeStateVerifyRunning ChallengeState = "CHALLENGE_VERIFY_RUNNING"
	ChallengeStateCommitSent    ChallengeState = "CHALLENGE_COMMIT_SENT"
	ChallengeStateResultSent    ChallengeState = "CHALLENGE_RESULT_SENT"
	ChallengeStateSettled       ChallengeState = "CHALLENGE_SETTLED"
)

type Role string

const (
	RoleNone     Role = ""
	RoleWorker   Role = "worker"
	RoleVerifier Role = "verifier"
)

type EventType string

const (
	EventMsgAssignAccepted           EventType = "MsgAssignTx accepted"
	EventAssignmentFinalized         EventType = "EventAssignmentFinalized"
	EventVerifierAssigned            EventType = "EventVerifierAssigned"
	EventChallengeOpened             EventType = "EventChallengeOpened"
	EventChallengeSampleSeedReady    EventType = "EventChallengeSampleSeedReady"
	EventChallengeVerifierAssigned   EventType = "EventChallengeVerifierAssigned"
	EventChallengeVerifyStarted      EventType = "EventChallengeVerifyStarted"
	EventChallengeCommitAccepted     EventType = "EventChallengeCommitAccepted"
	EventChallengeResultAccepted     EventType = "EventChallengeResultAccepted"
	EventChallengeOutcomeRecorded    EventType = "EventChallengeOutcomeRecorded"
	EventInferReceiptAccepted        EventType = "EventInferReceiptAccepted"
	EventOpenVerifyAccepted          EventType = "EventOpenVerifyAccepted"
	EventVerificationSampleSeedReady EventType = "EventVerificationSampleSeedReady"
	EventVerifierCommitAccepted      EventType = "EventVerifierCommitAccepted"
	EventVerifierResultAccepted      EventType = "EventVerifierResultAccepted"
	EventSettleAccepted              EventType = "EventSettleAccepted"
	EventSweepDeadlineAccepted       EventType = "EventSweepDeadlineAccepted"
)

type Effect string

const (
	EffectStartInfer           Effect = "START_INFER"
	EffectStartVerify          Effect = "START_VERIFY"
	EffectRecordChallengeAlert Effect = "RECORD_CHALLENGE_ALERT"
)
