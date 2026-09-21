package policy

import (
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/modelservice"
)

func TestWorkerL0L4AnyFailureDoesNotSignHandraise(t *testing.T) {
	valid := validWorkerPrecheck()
	tests := []struct {
		name   string
		mutate func(*WorkerPrecheckInput)
		code   string
	}{
		{"L0 chain not synced", func(in *WorkerPrecheckInput) { in.ChainSynced = false }, "L0_CHAIN_NOT_SYNCED"},
		{"L1 support stale", func(in *WorkerPrecheckInput) { in.SupportLastConfirmedHeight = 69 }, "L1_SUPPORT_STALE"},
		{"L1 support window missing", func(in *WorkerPrecheckInput) { in.SupportFreshnessWindow = 0 }, "L1_SUPPORT_STALE"},
		{"L2 unsupported profile", func(in *WorkerPrecheckInput) { in.Profile = "image_v1" }, "L2_UNSUPPORTED_PROFILE"},
		{"L3 insufficient capacity", func(in *WorkerPrecheckInput) { in.AvailableSlots = 0 }, "L3_INSUFFICIENT_CAPACITY"},
		{"L4 reward ineligible", func(in *WorkerPrecheckInput) { in.RewardEligible = false }, "L4_REWARD_INELIGIBLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid
			tt.mutate(&in)

			decision := EvaluateWorkerPrecheck(in)

			if decision.Accepted {
				t.Fatalf("decision accepted; want reject")
			}
			if decision.ShouldSignWorkerHandraise {
				t.Fatalf("decision signs WorkerHandraise on failure")
			}
			if decision.RejectCode != tt.code {
				t.Fatalf("reject code = %q, want %q", decision.RejectCode, tt.code)
			}
			if decision.CapacitySnapshotRef == "" {
				t.Fatalf("capacity snapshot ref should be retained for audit")
			}
			if decision.RewardEligibilityEstimate {
				t.Fatalf("reward estimate should reflect failed eligibility")
			}
		})
	}
}

func TestWorkerSupportFreshnessAndDeclaredBootstrap(t *testing.T) {
	stale := validWorkerPrecheck()
	stale.SupportLastConfirmedHeight = 69
	if got := EvaluateWorkerPrecheck(stale); got.Accepted || got.RejectCode != "L1_SUPPORT_STALE" {
		t.Fatalf("stale support decision = %+v, want L1_SUPPORT_STALE reject", got)
	}

	bootstrap := validWorkerPrecheck()
	bootstrap.SupportState = SupportDeclaredBootstrap
	bootstrap.P30ColdStartCandidate = true
	if got := EvaluateWorkerPrecheck(bootstrap); !got.Accepted {
		t.Fatalf("Keeper-eligible cold-start candidate rejected: %+v", got)
	}

	notEligible := bootstrap
	notEligible.P30ColdStartCandidate = false
	if got := EvaluateWorkerPrecheck(notEligible); got.Accepted || got.RejectCode != "L1_DECLARED_BOOTSTRAP_NOT_FIRST_P30" {
		t.Fatalf("ineligible bootstrap decision = %+v, want L1_DECLARED_BOOTSTRAP_NOT_FIRST_P30 reject", got)
	}
}

func TestUnsupportedProfileRejectsBeforeCapacity(t *testing.T) {
	for _, profile := range []string{"multimodal_image_v1", "audio_v1", "video_v1"} {
		t.Run(profile, func(t *testing.T) {
			in := validWorkerPrecheck()
			in.Profile = profile
			in.AvailableSlots = 0

			got := EvaluateWorkerPrecheck(in)

			if got.Accepted || got.RejectCode != "L2_UNSUPPORTED_PROFILE" {
				t.Fatalf("decision = %+v, want unsupported profile reject", got)
			}
		})
	}
}

func TestAcceptedWorkerPrecheckSignsHandraiseWithAuditMaterial(t *testing.T) {
	got := EvaluateWorkerPrecheck(validWorkerPrecheck())

	if !got.Accepted {
		t.Fatalf("decision rejected: %+v", got)
	}
	if !got.ShouldSignWorkerHandraise {
		t.Fatalf("accepted decision should sign WorkerHandraise")
	}
	if got.SupportEligibility != SupportActive {
		t.Fatalf("support eligibility = %q, want %q", got.SupportEligibility, SupportActive)
	}
	if got.CapacitySnapshotRef != "capacity://snapshot/1" {
		t.Fatalf("capacity snapshot ref = %q", got.CapacitySnapshotRef)
	}
	if !strings.Contains(got.AuditSummary, "llm_text_v1") {
		t.Fatalf("audit summary should include profile, got %q", got.AuditSummary)
	}
}

func TestWorkerCanHandraiseWithoutSelfRescueFeeBudget(t *testing.T) {
	in := validWorkerPrecheck()
	in.SelfRescueGasAvailable = false
	in.SelfRescueGasBudgetNanoTRUEOPEN = 0

	got := EvaluateWorkerPrecheck(in)
	if !got.Accepted || !got.ShouldSignWorkerHandraise || got.RejectCode != "" {
		t.Fatalf("no self-rescue fee budget decision = %+v, want accepted handraise", got)
	}
}

func validWorkerPrecheck() WorkerPrecheckInput {
	return WorkerPrecheckInput{
		ChainSynced:                     true,
		CurrentHeight:                   100,
		SupportState:                    SupportActive,
		SupportLastConfirmedHeight:      95,
		SupportFreshnessWindow:          30,
		Profile:                         modelservice.CapabilityLLMTextV1,
		SupportedProfiles:               []string{modelservice.CapabilityLLMTextV1},
		AvailableSlots:                  1,
		CapacitySnapshotRef:             "capacity://snapshot/1",
		RewardEligible:                  true,
		SelfRescueGasAvailable:          true,
		SelfRescueGasBudgetNanoTRUEOPEN: 10,
	}
}
