// Package auditduty is the "audit capability" mode of a Cortex node: the node
// serves as a Verifier of anchor audits without running a model. It reads the
// panel rounds the chain assigned to it, hands each one to the local Verifier
// program over a spool directory, and takes back one of three votes.
//
// The audit itself (fetching the material, checking the proof) is the
// Verifier program's work. This package only moves assignments in and votes
// out, and refuses to run on a machine that holds a block producer's keys.
package auditduty

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// consensusFiles are the files a block producer's signing key lives in,
// relative to a node home.
var consensusFiles = []string{
	"config/priv_validator_key.json",
	"data/priv_validator_state.json",
	"priv_validator_key.json",
}

// wellKnownNodeHomes are node home directories looked for under $HOME.
var wellKnownNodeHomes = []string{".node", ".noded", ".trueopen", ".cometbft", ".tendermint"}

// Host is what the independence check reads from the machine; tests replace it.
type Host struct {
	Env    func(string) string
	Exists func(string) bool
}

// OSHost reads the real environment and file system.
func OSHost() Host {
	return Host{Env: os.Getenv, Exists: func(p string) bool { _, err := os.Stat(p); return err == nil }}
}

// ConsensusKeyFindings lists the consensus key material detectable on this
// machine: a block producer may not also vote on audits, so any finding makes
// the node refuse the audit capability. It looks in the directories named in
// nodeHomes, in NODE_HOME and DAEMON_HOME, in the well-known node homes under
// HOME, and at environment variables that name a validator key file.
//
// It cannot see keys held on another machine or by a remote signer, nor one
// person running both roles under separate addresses.
func ConsensusKeyFindings(nodeHomes []string, host Host) []string {
	homes := append([]string(nil), nodeHomes...)
	for _, name := range []string{"NODE_HOME", "DAEMON_HOME"} {
		homes = append(homes, host.Env(name))
	}
	if home := strings.TrimSpace(host.Env("HOME")); home != "" {
		for _, d := range wellKnownNodeHomes {
			homes = append(homes, filepath.Join(home, d))
		}
	}
	seen := map[string]bool{}
	var findings []string
	for _, h := range homes {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		for _, f := range consensusFiles {
			p := filepath.Join(h, f)
			if !seen[p] && host.Exists(p) {
				seen[p] = true
				findings = append(findings, "consensus key material at "+p)
			}
		}
	}
	for _, name := range []string{"PRIV_VALIDATOR_KEY_FILE", "PRIV_VALIDATOR_KEY", "CMT_PRIV_VALIDATOR_KEY_FILE", "TM_PRIV_VALIDATOR_KEY_FILE"} {
		if strings.TrimSpace(host.Env(name)) != "" {
			findings = append(findings, "environment variable "+name+" names a validator key")
		}
	}
	sort.Strings(findings)
	return findings
}

// RefuseIfBlockProducer is the start-up gate of the audit capability.
func RefuseIfBlockProducer(nodeHomes []string, host Host) error {
	findings := ConsensusKeyFindings(nodeHomes, host)
	if len(findings) == 0 {
		return nil
	}
	return fmt.Errorf("verifier.audit refused: this machine holds a block producer's key material, and a block producer may not vote on audits (%s)",
		strings.Join(findings, "; "))
}
