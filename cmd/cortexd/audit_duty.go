package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/TrueOpen/cortex/internal/auditduty"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
)

// newAuditDuty builds the audit capability, or returns nil when it is off. It
// refuses a machine that holds a block producer's key material: a block
// producer may not also vote on audits.
//
// The node only moves assignments and votes between the chain and the local
// Verifier program; the program broadcasts its vote itself, so no submitter
// is wired here.
func newAuditDuty(cfg config.Config, rt *daemon.Runtime, host auditduty.Host) (*auditduty.Runner, error) {
	audit := cfg.Verifier.Audit
	if !audit.Enabled {
		return nil, nil
	}
	if err := auditduty.RefuseIfBlockProducer(audit.NodeHomes, host); err != nil {
		return nil, err
	}
	source, ok := rt.Dependencies.Keeper.(auditduty.AssignmentSource)
	if !ok {
		return nil, fmt.Errorf("verifier.audit needs a Keeper client that reads panel assignments")
	}
	spool, err := auditduty.OpenSpool(audit.SpoolDir)
	if err != nil {
		return nil, err
	}
	return auditduty.NewRunner(auditduty.Config{
		ChainID: cfg.ChainID, Operator: cfg.LocalIdentity.OperatorAddress, Source: source, Spool: spool,
		PollEvery: time.Duration(audit.PollMS) * time.Millisecond, Logger: slog.Default(),
	})
}
