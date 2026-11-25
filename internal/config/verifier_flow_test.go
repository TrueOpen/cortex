package config

import (
	"strings"
	"testing"
)

func TestAuditDutyNeedsASpoolDirectory(t *testing.T) {
	var c Config
	c.Verifier.Audit.Enabled = true
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "verifier.audit.spool_dir") {
		t.Fatalf("want the spool_dir problem, got %v", err)
	}
}

func TestVerifierFlowOptionsAreOffByDefault(t *testing.T) {
	var c Config
	if c.Verifier.Audit.Enabled || c.Dispatch.HonourChainPause {
		t.Fatal("the audit capability and the chain pause are opt-in")
	}
	if err := c.Validate(); err != nil && strings.Contains(err.Error(), "verifier.audit") {
		t.Fatalf("a node without verifier.audit has no audit problem: %v", err)
	}
}
