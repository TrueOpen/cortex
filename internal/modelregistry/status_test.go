package modelregistry

import "testing"

func TestRegisteredProfileDisplaysFeeOnlyNoBlockReward(t *testing.T) {
	projection := ProjectStatus(StatusObservation{
		ModelID:           "llama-text-8b",
		ProfileVersion:    "profile-v1",
		ChainState:        ChainStateRegistered,
		DisplayVisibility: DisplayVisible,
		VerificationLabel: VerificationOfficial,
	})

	if projection.RewardState != RewardFeeOnlyNoBlockReward {
		t.Fatalf("reward state = %q, want %q", projection.RewardState, RewardFeeOnlyNoBlockReward)
	}
}

func TestStatusProjectionIncludesSupportRiskTreasuryAndBuilderState(t *testing.T) {
	projection := ProjectStatus(StatusObservation{
		ModelID:                 "llama-text-8b",
		ProfileVersion:          "profile-v1",
		ChainState:              ChainStateActive,
		DeclaredSupport:         true,
		SupportActive:           true,
		LastP30TaskID:           "task-p30",
		P30Cutoff:               30,
		Top10Cutoff:             90,
		MarkGateOpen:            true,
		HardwareTier:            "gpu-l4",
		HardwareTierProofTaskID: "verify-task-p30",
		HardwareTierProofRole:   "verifier",
		Treasury: TreasuryState{
			Denom:                   "utrueopen",
			Balance:                 1_000,
			MaintenanceRate:         7,
			MaxReimbursementPerTx:   11,
			MaxReimbursementPerTask: 22,
		},
		Builder: BuilderObservation{
			Connected:       false,
			MissedMessages:  2,
			FaultedMessages: 1,
		},
		FailureClasses: []FailureClassObservation{
			{Class: FailureClassValueMismatch, Count: 2},
			{Class: FailureClassInsufficientVerifier, Count: 9},
		},
		EmergencyFreezeAccepted: true,
	})

	if projection.Support.SupportState != SupportActive {
		t.Fatalf("support state = %q, want %q", projection.Support.SupportState, SupportActive)
	}
	if !projection.MarkGate.Open || projection.MarkGate.P30Cutoff != 30 || projection.MarkGate.Top10Cutoff != 90 {
		t.Fatalf("mark gate projection = %#v", projection.MarkGate)
	}
	if projection.Risk.EmergencyFreezeRiskCount != 2 {
		t.Fatalf("emergency risk count = %d, want 2", projection.Risk.EmergencyFreezeRiskCount)
	}
	if !projection.EmergencyFreeze.Frozen {
		t.Fatalf("emergency freeze projection = %#v, want frozen", projection.EmergencyFreeze)
	}
	if projection.Treasury.MaxReimbursementPerTask != 22 {
		t.Fatalf("treasury projection = %#v", projection.Treasury)
	}
	if projection.Builder.MissedMessages != 2 || projection.Builder.FaultedMessages != 1 {
		t.Fatalf("builder projection = %#v", projection.Builder)
	}
	if projection.HardwareTierProof.Role != "verifier" || projection.HardwareTierProof.TaskID != "verify-task-p30" {
		t.Fatalf("hardware tier proof = %#v", projection.HardwareTierProof)
	}
}

func TestFailureClassRiskOnlyCountsFreezeEligibleClasses(t *testing.T) {
	risk := ProjectProfileRisk([]FailureClassObservation{
		{Class: FailureClassNone, Count: 1},
		{Class: FailureClassInsufficientVerifier, Count: 10},
		{Class: FailureClassValueMismatch, Count: 2},
		{Class: FailureClassSchemaFault, Count: 3},
		{Class: FailureClassWorkerRevealFault, Count: 4},
	})

	if risk.EmergencyFreezeRiskCount != 9 {
		t.Fatalf("risk count = %d, want 9", risk.EmergencyFreezeRiskCount)
	}
	if risk.Counts[FailureClassInsufficientVerifier] != 10 {
		t.Fatalf("dashboard count for insufficient verifier missing: %#v", risk.Counts)
	}
}

func TestEarningsViewIsReadOnlyAndMarksWalletSDKClaimResponsibility(t *testing.T) {
	view := ProjectEarnings(EarningsObservation{
		PendingTaskFee:        12,
		ClaimableTaskFee:      34,
		TaskFinalityHeight:    100,
		ClaimableAfterHeight:  120,
		LatestClaimTxObserved: "tx-old",
	})

	if !view.ReadOnly {
		t.Fatalf("earnings view ReadOnly = false, want true")
	}
	if view.ClaimResponsibility != ClaimResponsibilityWalletSDK {
		t.Fatalf("claim responsibility = %q, want %q", view.ClaimResponsibility, ClaimResponsibilityWalletSDK)
	}
	if view.PendingTaskFee != 12 || view.ClaimableTaskFee != 34 {
		t.Fatalf("earnings amounts = %#v", view)
	}
}

func TestStatusProjectionIncludesReadOnlyEarningsAndTaskFinality(t *testing.T) {
	projection := ProjectStatus(StatusObservation{
		ModelID:        "llama-text-8b",
		ProfileVersion: "profile-v1",
		ChainState:     ChainStateActive,
		Earnings: EarningsObservation{
			PendingTaskFee:       12,
			ClaimableTaskFee:     34,
			TaskFinalityHeight:   100,
			ClaimableAfterHeight: 120,
		},
	})

	if projection.Earnings.PendingTaskFee != 12 || projection.Earnings.ClaimableTaskFee != 34 {
		t.Fatalf("earnings projection = %#v", projection.Earnings)
	}
	if projection.Earnings.TaskFinalityHeight != 100 || projection.Earnings.ClaimResponsibility != ClaimResponsibilityWalletSDK {
		t.Fatalf("task finality earnings view = %#v", projection.Earnings)
	}
}

func TestProjectStatusFromModelStatusUsesProfileVersion(t *testing.T) {
	status := ModelStatus{
		ModelID:        "model-a",
		ManifestHash:   "manifest-hash",
		ProfileVersion: "profile-v1",
		ChainState:     ChainStateRegistered,
	}
	projection := ProjectStatusFromModelStatus(status)
	if projection.ProfileVersion != "profile-v1" {
		t.Fatalf("ProfileVersion = %q, want profile-v1", projection.ProfileVersion)
	}
}
