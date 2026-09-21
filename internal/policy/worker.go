package policy

import (
	"fmt"
	"slices"

	"github.com/SingaXYZ/cortex/internal/modelservice"
)

const (
	SupportActive            = "ACTIVE"
	SupportDeclaredBootstrap = "DECLARED_BOOTSTRAP"
)

type WorkerPrecheckInput struct {
	ChainSynced                     bool
	CurrentHeight                   uint64
	SupportState                    string
	SupportLastConfirmedHeight      uint64
	SupportFreshnessWindow          uint64
	P30ColdStartCandidate           bool
	P30ColdStartRank                int
	Profile                         string
	SupportedProfiles               []string
	AvailableSlots                  int
	CapacitySnapshotRef             string
	RewardEligible                  bool
	SelfRescueGasAvailable          bool
	SelfRescueGasBudgetNanoTRUEOPEN uint64
}

type WorkerDecision struct {
	Accepted                        bool
	RejectCode                      string
	ShouldSignWorkerHandraise       bool
	SupportEligibility              string
	CapacitySnapshotRef             string
	RewardEligibilityEstimate       bool
	SelfRescueGasBudgetNanoTRUEOPEN uint64
	AuditSummary                    string
}

func EvaluateWorkerPrecheck(in WorkerPrecheckInput) WorkerDecision {
	decision := WorkerDecision{
		SupportEligibility:              in.SupportState,
		CapacitySnapshotRef:             in.CapacitySnapshotRef,
		RewardEligibilityEstimate:       in.RewardEligible,
		SelfRescueGasBudgetNanoTRUEOPEN: in.SelfRescueGasBudgetNanoTRUEOPEN,
		AuditSummary:                    fmt.Sprintf("profile=%s capacity_ref=%s", in.Profile, in.CapacitySnapshotRef),
	}
	if !in.ChainSynced {
		return reject(decision, "L0_CHAIN_NOT_SYNCED")
	}
	if !supportEligible(in) {
		if in.SupportState == SupportDeclaredBootstrap {
			return reject(decision, "L1_DECLARED_BOOTSTRAP_NOT_FIRST_P30")
		}
		return reject(decision, "L1_SUPPORT_STALE")
	}
	if !profileSupported(in.Profile, in.SupportedProfiles) {
		return reject(decision, "L2_UNSUPPORTED_PROFILE")
	}
	if in.AvailableSlots <= 0 {
		return reject(decision, "L3_INSUFFICIENT_CAPACITY")
	}
	if !in.RewardEligible {
		return reject(decision, "L4_REWARD_INELIGIBLE")
	}
	decision.Accepted = true
	decision.ShouldSignWorkerHandraise = true
	return decision
}

func reject(decision WorkerDecision, code string) WorkerDecision {
	decision.Accepted = false
	decision.RejectCode = code
	decision.ShouldSignWorkerHandraise = false
	decision.RewardEligibilityEstimate = false
	return decision
}

func supportEligible(in WorkerPrecheckInput) bool {
	if in.SupportState == SupportDeclaredBootstrap {
		return in.P30ColdStartCandidate
	}
	if in.SupportState != SupportActive {
		return false
	}
	if in.SupportFreshnessWindow == 0 {
		return false
	}
	if in.CurrentHeight < in.SupportLastConfirmedHeight {
		return false
	}
	return in.CurrentHeight-in.SupportLastConfirmedHeight <= in.SupportFreshnessWindow
}

func profileSupported(profile string, supported []string) bool {
	if profile != modelservice.CapabilityLLMTextV1 {
		return false
	}
	return slices.Contains(supported, profile)
}
