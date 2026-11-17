package modelservice_test

import (
	"testing"

	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

// The seed rule is named twice: config.Validate accepts config's constant and
// the capability probe requires the engine to declare modelservice's. Neither
// package imports the other, so only this test keeps them one value; if they
// drift, a configuration that validates is refused by every probe and no kind
// 5 Profile is ever offered.
func TestAnchorSeedRuleIsOneValueInConfigAndModelService(t *testing.T) {
	if config.AnchorSeedRuleV2 != modelservice.AnchorSeedRuleV2 {
		t.Fatalf("config.AnchorSeedRuleV2 = %q, modelservice.AnchorSeedRuleV2 = %q: the configured rule would never match the probe",
			config.AnchorSeedRuleV2, modelservice.AnchorSeedRuleV2)
	}
}
