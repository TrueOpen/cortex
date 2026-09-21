package daemon

import (
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/policy"
)

// A precheck refusal must not be silent, and must not mark this admission complete.
//
// In integration the verifier received OPEN_VERIFY and nothing happened: no
// handraise, no log, and redeliveries were deduplicated away. The cause was that
// EvaluateAndHandraise returned a "precheck refusal" as a normal return (err == nil),
// the caller dropped the result and then marked the admission complete - after which
// every redelivery of the same task took the dedup path. The reasons for a refusal
// (slots, support freshness, deadline) mostly change over time, so the right
// behaviour is to report an error carrying the reject code and keep the redelivery
// alive until the chain sweeps the task at its deadline.
func TestOpenVerifyPrecheckRejectionIsReportedAndRetried(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	noSlots := staticEligibility{verifierInput: policy.VerifierPrecheckInput{
		ChainSynced: true, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 0, SupportFreshnessWindow: 20,
		SupportedProfiles: []string{modelservice.CapabilityLLMTextV1}, AvailableSlots: 0,
	}}
	fixture.runner.cfg.HandraiseEligibility = noSlots

	err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())
	if err == nil {
		t.Fatal("a precheck refusal was swallowed as a success")
	}
	if !strings.Contains(err.Error(), "precheck") {
		t.Fatalf("the error must say it is a precheck refusal and carry a reject code, got %v", err)
	}
	if !builderclient.IsRetryable(err) {
		t.Fatalf("a precheck refusal's reason can change, so the redelivery must be kept, got %v", err)
	}
	if len(fixture.builder.published) != 0 {
		t.Fatalf("no handraise may be published after a refusal, published = %d", len(fixture.builder.published))
	}

	// Redelivering the same message once conditions recover has to run the precheck
	// again for real and raise a hand - dedup must not stop it.
	fixture.runner.cfg.HandraiseEligibility = staticEligibility{verifierInput: policy.VerifierPrecheckInput{
		ChainSynced: true, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 0, SupportFreshnessWindow: 20,
		SupportedProfiles: []string{modelservice.CapabilityLLMTextV1}, AvailableSlots: 1,
	}}
	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("the redelivery after conditions recovered was refused: %v", err)
	}
	// Only the handraise matters here: output confirmation happens before the precheck
	// and a redelivery confirms again, which is not what this test guards.
	if len(fixture.builder.published) != 1 ||
		fixture.builder.published[0].Subject != builderclient.NATSVerifierHandraiseSubject(fixture.taskID) {
		t.Fatalf("exactly one handraise must follow the redelivery, published = %#v", fixture.builder.published)
	}
}
