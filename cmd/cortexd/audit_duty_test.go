package main

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/auditduty"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
)

type auditKeeper struct{ daemon.KeeperClient }

func (auditKeeper) PanelAssignments(context.Context, string) ([]chainclient.PanelAssignment, error) {
	return nil, chainclient.ErrQueryUnsupported
}

func cleanHost() auditduty.Host {
	return auditduty.Host{Env: func(string) string { return "" }, Exists: func(string) bool { return false }}
}

func TestAuditDutyIsOffByDefault(t *testing.T) {
	r, err := newAuditDuty(config.Config{}, &daemon.Runtime{}, cleanHost())
	if r != nil || err != nil {
		t.Fatalf("an unconfigured node must not build the audit duty: %v %v", r, err)
	}
}

func TestAuditDutyRefusesABlockProducersMachine(t *testing.T) {
	cfg := config.Config{}
	cfg.Verifier.Audit = config.AuditDutyConfig{Enabled: true, SpoolDir: t.TempDir(), NodeHomes: []string{"/srv/node"}}
	host := auditduty.Host{Env: func(string) string { return "" },
		Exists: func(p string) bool { return p == "/srv/node/config/priv_validator_key.json" }}
	rt := &daemon.Runtime{}
	rt.Dependencies.Keeper = auditKeeper{}
	_, err := newAuditDuty(cfg, rt, host)
	if err == nil || !strings.Contains(err.Error(), "block producer") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestAuditDutyStartsOnACleanMachine(t *testing.T) {
	cfg := config.Config{ChainID: "chain-1"}
	cfg.LocalIdentity.OperatorAddress = "op"
	cfg.Verifier.Audit = config.AuditDutyConfig{Enabled: true, SpoolDir: t.TempDir()}
	rt := &daemon.Runtime{}
	rt.Dependencies.Keeper = auditKeeper{}
	r, err := newAuditDuty(cfg, rt, cleanHost())
	if err != nil || r == nil {
		t.Fatalf("got %v %v", r, err)
	}
	if err := r.Step(context.Background()); err != nil {
		t.Fatalf("a chain without panels leaves the duty idle: %v", err)
	}
}
