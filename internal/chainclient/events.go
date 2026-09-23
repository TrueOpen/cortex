package chainclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
)

type KeeperEventType string

const KeeperEventContractVersionV1 = "node-event-indexer-v1"

const (
	KeeperEventProtocolProjection              KeeperEventType = "ProtocolEventProjection"
	KeeperEventAssignAcceptedPendingRandomness KeeperEventType = "EventAssignAcceptedPendingRandomness"
	KeeperEventAssignmentFinalized             KeeperEventType = "EventAssignmentFinalized"
	KeeperEventAssignmentFailed                KeeperEventType = "EventAssignmentFailed"
	KeeperEventOpenVerifyAccepted              KeeperEventType = "EventOpenVerifyAccepted"
	KeeperEventVerificationSampleSeedReady     KeeperEventType = "EventVerificationSampleSeedReady"
	KeeperEventInferReceiptAccepted            KeeperEventType = "EventInferReceiptAccepted"
	KeeperEventCommitAccepted                  KeeperEventType = "EventCommitAccepted"
	KeeperEventCommitItemRejected              KeeperEventType = "EventCommitItemRejected"
	KeeperEventRevealPhaseStarted              KeeperEventType = "EventRevealPhaseStarted"
	KeeperEventCommitDeadlineClosed            KeeperEventType = "EventCommitDeadlineClosed"
	KeeperEventWorkerTimeout                   KeeperEventType = "EventWorkerTimeout"
	KeeperEventVerifyOpenDeadlineClosed        KeeperEventType = "EventVerifyOpenDeadlineClosed"
	KeeperEventWorkerRevealDeadlineClosed      KeeperEventType = "EventWorkerRevealDeadlineClosed"
	KeeperEventRevealDeadlineClosed            KeeperEventType = "EventRevealDeadlineClosed"
	KeeperEventResultCredentialAccepted        KeeperEventType = "EventResultCredentialAccepted"
	KeeperEventFullResultRevealAccepted        KeeperEventType = "EventFullResultRevealAccepted"
	KeeperEventWorkerRevealReceiptAccepted     KeeperEventType = "EventWorkerRevealReceiptAccepted"
	KeeperEventSettleAccepted                  KeeperEventType = "EventSettleAccepted"
	KeeperEventTaskEvidenceRootRecorded        KeeperEventType = "EventTaskEvidenceRootRecorded"
	KeeperEventDeadlineSwept                   KeeperEventType = "EventDeadlineSwept"
	KeeperEventVerdictFraudProofSubmitted      KeeperEventType = "EventVerdictFraudProofSubmitted"
	KeeperEventVerdictFraudProofSucceeded      KeeperEventType = "EventVerdictFraudProofSucceeded"
	KeeperEventFaultRecorded                   KeeperEventType = "EventFaultRecorded"
	KeeperEventChallengeOpened                 KeeperEventType = "EventChallengeOpened"
	KeeperEventChallengeSampleSeedReady        KeeperEventType = "EventChallengeSampleSeedReady"
	KeeperEventChallengeVerifierAssigned       KeeperEventType = "EventChallengeVerifierAssigned"
	KeeperEventChallengeCommitAccepted         KeeperEventType = "EventChallengeCommitAccepted"
	KeeperEventChallengeResultAccepted         KeeperEventType = "EventChallengeResultAccepted"
	KeeperEventChallengeFullResultReveal       KeeperEventType = "EventChallengeFullResultRevealAccepted"
	KeeperEventChallengeOutcomeRecorded        KeeperEventType = "EventChallengeOutcomeRecorded"
	KeeperEventChallengeLivenessIssueRecorded  KeeperEventType = "EventChallengeLivenessIssueRecorded"
	KeeperEventChallengeEconomicEffectApplied  KeeperEventType = "EventChallengeEconomicEffectApplied"
	KeeperEventChallengeClosed                 KeeperEventType = "EventChallengeClosed"
	KeeperEventEvidenceRequested               KeeperEventType = "EventEvidenceRequested"
	KeeperEventEvidenceRequestSatisfied        KeeperEventType = "EventEvidenceRequestSatisfied"
	KeeperEventEvidenceRequestDefaulted        KeeperEventType = "EventEvidenceRequestDefaulted"
	KeeperEventFreezeSignalSubmitted           KeeperEventType = "EventFreezeSignalSubmitted"
	KeeperEventEmergencyFreezeAccepted         KeeperEventType = "EventEmergencyFreezeAccepted"
	KeeperEventTaskFailureClassUpdated         KeeperEventType = "EventTaskFailureClassUpdated"
	KeeperEventSettlementFinalityUpdated       KeeperEventType = "EventSettlementFinalityUpdated"
	KeeperEventRewardMarked                    KeeperEventType = "EventRewardMarked"
	KeeperEventMarkGateUpdated                 KeeperEventType = "EventMarkGateUpdated"
	KeeperEventEvidenceCleanupDue              KeeperEventType = "EventEvidenceCleanupDue"
	KeeperEventEvidenceCleanupDeferred         KeeperEventType = "EventEvidenceCleanupDeferred"
	KeeperEventModelRegistered                 KeeperEventType = "EventModelRegistered"
	KeeperEventProfileRegistered               KeeperEventType = "EventProfileRegistered"
	KeeperEventModelProfileRegistered          KeeperEventType = "EventModelProfileRegistered"
	KeeperEventModelProfileStateChanged        KeeperEventType = "EventModelProfileStateChanged"
	KeeperEventModelSupportUpdated             KeeperEventType = "EventModelSupportUpdated"
	KeeperEventModelSupportBatchAccepted       KeeperEventType = "EventModelSupportBatchAccepted"
	KeeperEventBuilderSetUpdated               KeeperEventType = "EventBuilderSetUpdated"
)

type KeeperEvent struct {
	Type            KeeperEventType `json:"type"`
	ContractVersion string          `json:"contract_version,omitempty"`
	RawType         string          `json:"raw_type,omitempty"`
	Known           bool            `json:"known,omitempty"`
	// Quarantined marks a recognized event that failed validation. Chain
	// history is permanent, so such an event can never be repaired by retrying
	// and the node must still advance past it. It is carried through parsing so
	// the failure stays visible and auditable, but no effect is derived from it.
	Quarantined         bool          `json:"quarantined,omitempty"`
	QuarantineReason    string        `json:"quarantine_reason,omitempty"`
	ChainID             string        `json:"chain_id,omitempty"`
	Position            EventPosition `json:"position"`
	TaskID              string        `json:"task_id"`
	Height              uint64        `json:"height"`
	SessionID           string        `json:"session_id,omitempty"`
	OrderSequence       uint64        `json:"order_sequence,omitempty"`
	OrderDigest         codec.Hash    `json:"order_digest,omitempty"`
	Worker              string        `json:"worker,omitempty"`
	Verifier            string        `json:"verifier,omitempty"`
	FormalVerifiers     []string      `json:"formal_verifiers,omitempty"`
	ChallengeID         string        `json:"challenge_id,omitempty"`
	WinnerConfirmHeight uint64        `json:"winner_confirm_height,omitempty"`
	// InferDeadlineHeight is the protocol height after which a worker task can
	// no longer be accepted. EventAssignmentFinalized carries it, so the local
	// queue can terminate on a protocol fact instead of an attempt count.
	InferDeadlineHeight uint64            `json:"infer_deadline_height,omitempty"`
	ModelID             string            `json:"model_id,omitempty"`
	ProfileVersion      string            `json:"profile_version,omitempty"`
	DeclaredSupport     bool              `json:"declared_support,omitempty"`
	SupportActive       bool              `json:"support_active,omitempty"`
	Phase               string            `json:"phase,omitempty"`
	TxHash              string            `json:"tx_hash,omitempty"`
	Payload             json.RawMessage   `json:"payload,omitempty"`
	Attributes          map[string]string `json:"attributes,omitempty"`
}

type KeeperEventsPage struct {
	ChainHeight     uint64 `json:"chain_height"`
	FinalizedHeight uint64 `json:"finalized_height"`
	// RangeStartHeight and RangeEndHeight identify the inclusive block range
	// actually scanned for this response. RangeComplete is true only when every
	// block in that range was read and no continuation page remains.
	RangeStartHeight uint64        `json:"range_start_height"`
	RangeEndHeight   uint64        `json:"range_end_height"`
	RangeComplete    bool          `json:"range_complete"`
	LastEventHeight  uint64        `json:"last_event_height"`
	LastPosition     EventPosition `json:"last_position"`
	NextPageToken    string        `json:"next_page_token"`
	Events           []KeeperEvent `json:"events"`
}

// Lag reports how far behind the chain tip this page is, in blocks. Zero means
// the page reaches the tip, or that the heights needed to tell are unknown.
func (p KeeperEventsPage) Lag() uint64 {
	observedHeight := p.LastEventHeight
	if p.FinalizedHeight > 0 {
		observedHeight = p.FinalizedHeight
	}
	if p.ChainHeight == 0 || observedHeight == 0 || p.ChainHeight <= observedHeight {
		return 0
	}
	return p.ChainHeight - observedHeight
}

func (p KeeperEventsPage) ValidateLag(maxLag uint64) error {
	if lag := p.Lag(); lag > maxLag {
		return fmt.Errorf("keeper event lag %d exceeds max %d", lag, maxLag)
	}
	return nil
}

func (e KeeperEvent) Digest() string {
	material := struct {
		ContractVersion string            `json:"contract_version,omitempty"`
		ChainID         string            `json:"chain_id,omitempty"`
		Position        EventPosition     `json:"position"`
		RawType         string            `json:"raw_type,omitempty"`
		Type            KeeperEventType   `json:"type"`
		TaskID          string            `json:"task_id"`
		Height          uint64            `json:"height"`
		SessionID       string            `json:"session_id,omitempty"`
		OrderSequence   uint64            `json:"order_sequence,omitempty"`
		OrderDigest     codec.Hash        `json:"order_digest,omitempty"`
		Worker          string            `json:"worker,omitempty"`
		Verifier        string            `json:"verifier,omitempty"`
		Verifiers       []string          `json:"formal_verifiers,omitempty"`
		ChallengeID     string            `json:"challenge_id,omitempty"`
		ModelID         string            `json:"model_id,omitempty"`
		Profile         string            `json:"profile_version,omitempty"`
		Declared        bool              `json:"declared_support,omitempty"`
		SupportActive   bool              `json:"support_active,omitempty"`
		TxHash          string            `json:"tx_hash,omitempty"`
		Attributes      map[string]string `json:"attributes,omitempty"`
	}{
		ContractVersion: e.ContractVersion,
		ChainID:         e.ChainID,
		Position:        e.Position,
		RawType:         e.RawType,
		Type:            e.Type,
		TaskID:          e.TaskID,
		Height:          e.Height,
		SessionID:       e.SessionID,
		OrderSequence:   e.OrderSequence,
		OrderDigest:     e.OrderDigest,
		Worker:          e.Worker,
		Verifier:        e.Verifier,
		Verifiers:       e.FormalVerifiers,
		ChallengeID:     e.ChallengeID,
		ModelID:         e.ModelID,
		Profile:         e.ProfileVersion,
		Declared:        e.DeclaredSupport,
		SupportActive:   e.SupportActive,
		TxHash:          e.TxHash,
		Attributes:      e.Attributes,
	}
	b, _ := json.Marshal(material)
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

func (e KeeperEvent) Validate() error {
	if e.Type == "" {
		return fmt.Errorf("keeper event type is required")
	}
	if e.Height == 0 {
		return fmt.Errorf("keeper event height is required")
	}
	if e.Known && e.RawType != "" && e.ContractVersion != KeeperEventContractVersionV1 {
		return fmt.Errorf("recognized Keeper raw event requires contract version %s", KeeperEventContractVersionV1)
	}
	if !e.Known {
		// An event whose wire type the identification layer never claimed has no
		// field contract here to enforce.
		if e.RawType != "" && !abciEventTypeRecognized(e.RawType) {
			return nil
		}
	}
	switch e.Type {
	case KeeperEventProtocolProjection, KeeperEventModelSupportBatchAccepted, KeeperEventMarkGateUpdated, KeeperEventBuilderSetUpdated, KeeperEventFaultRecorded:
		return nil
	case KeeperEventChallengeOpened,
		KeeperEventChallengeClosed,
		KeeperEventChallengeSampleSeedReady,
		KeeperEventChallengeVerifierAssigned,
		KeeperEventChallengeCommitAccepted,
		KeeperEventChallengeResultAccepted,
		KeeperEventChallengeFullResultReveal,
		KeeperEventChallengeOutcomeRecorded,
		KeeperEventChallengeLivenessIssueRecorded,
		KeeperEventChallengeEconomicEffectApplied,
		KeeperEventEvidenceRequested,
		KeeperEventEvidenceRequestSatisfied,
		KeeperEventEvidenceRequestDefaulted:
		if e.ChallengeID == "" {
			return fmt.Errorf("%s requires challenge_id", e.Type)
		}
		return nil
	case KeeperEventModelRegistered:
		if e.ModelID == "" {
			return fmt.Errorf("%s requires model_id", e.Type)
		}
		return nil
	case KeeperEventModelSupportUpdated:
		if e.Worker == "" || e.ModelID == "" || !canonicalEventProfileVersion(e.ProfileVersion) {
			return fmt.Errorf("%s requires operator_address, model_id, and profile_version", e.Type)
		}
		return nil
	case KeeperEventProfileRegistered,
		KeeperEventModelProfileRegistered,
		KeeperEventModelProfileStateChanged,
		KeeperEventEmergencyFreezeAccepted,
		KeeperEventFreezeSignalSubmitted:
		if e.ModelID == "" || !canonicalEventProfileVersion(e.ProfileVersion) {
			return fmt.Errorf("%s requires model_id and profile_version", e.Type)
		}
	case KeeperEventDeadlineSwept:
		// The sweep is the one deadline event with two scopes, and task
		// declares both session_id and task_id `optional` because of it:
		// emitDeadlineSweptEvent carries a task, while
		// emitSessionDeadlineSweptEvent carries only a session and
		// DEADLINE_KIND_V1_SESSION_LIFECYCLE. Requiring a task_id here
		// quarantined the session-scoped sweep on every occurrence — a refusal
		// of a frame the chain emits by design, which then also stalled the
		// terminal effect of the task-scoped sweeps in the same block.
		if e.TaskID == "" && e.SessionID == "" {
			return fmt.Errorf("%s requires session_id or task_id", e.Type)
		}
		return nil
	default:
		if e.TaskID == "" {
			return fmt.Errorf("%s requires task_id", e.Type)
		}
	}
	if e.Type == KeeperEventAssignmentFinalized && e.Worker == "" {
		return fmt.Errorf("%s requires worker", e.Type)
	}
	return nil
}

func canonicalEventProfileVersion(value string) bool {
	parsed, err := parseProfileVersion(value, false)
	return err == nil && NewProfileVersion(parsed).String() == value
}
