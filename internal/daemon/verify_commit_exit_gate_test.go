package daemon

import (
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/txclient"
)

// The gate in front of the commit exit, asserted from the devnet symptom it
// produced: three selected Verifiers finished verification, held a wired
// nexus#70 relay, and never sent anything -- each logged "verifier commit exit
// requires a workload tx client" every 30s until the commit deadline. The
// refusal came from commitSubmitter, which runs BEFORE the Verifier is
// constructed, so the relay it would have been handed was never asked.
//
// The order itself (relay first, self-submission only on a deterministic
// refusal) is verifier.deliverCommit's and is pinned there. What these
// assertions pin is which of the two routes this executor is willing to start a
// round with.
func TestCommitSubmitterYieldsToTheRelayWhenTheNodeCannotSelfSubmit(t *testing.T) {
	// A file:// keystore node: signer.LocalSigner.CanSignCosmosTx is false, so
	// BuildRuntimeWithOptions wires no workload tx client at all.
	relayOnly := &productionVerifyExecutor{cfg: TaskRunnerConfig{LocalVerifierAddress: "trueopen1verifier"}}

	submitter, err := relayOnly.commitSubmitter("trueopen1service", true)
	if err != nil {
		t.Fatalf("commitSubmitter() error = %v, want a relay-only round admitted", err)
	}
	if submitter != nil {
		t.Fatalf("submitter = %#v, want nil: there is no transaction path to submit with", submitter)
	}

	// Without a relay the same node has no exit at all, and that is still
	// refused before the commit is signed rather than after.
	if _, err := relayOnly.commitSubmitter("trueopen1service", false); err == nil ||
		!strings.Contains(err.Error(), "requires a workload tx client") {
		t.Fatalf("commitSubmitter() error = %v, want the relay-less node refused up front", err)
	}
}

// A node that can do both keeps both. The relay's presence must not cost the
// self-submission fallback: nexus can refuse a round deterministically
// (NEXUS_INGRESS_RELAY_NOT_OFFERED), and the fallback is the only thing that
// puts a CommitState on chain when it does.
func TestCommitSubmitterKeepsTheDirectFallbackBesideTheRelay(t *testing.T) {
	withTx := &productionVerifyExecutor{cfg: TaskRunnerConfig{
		LocalVerifierAddress: "trueopen1verifier",
		Tx:                   txclient.NewFake(),
	}}

	submitter, err := withTx.commitSubmitter("trueopen1service", true)
	if err != nil {
		t.Fatalf("commitSubmitter() error = %v", err)
	}
	if submitter == nil {
		t.Fatal("submitter = nil, want the direct fallback kept beside the relay")
	}

	// The outer Cosmos Tx signer is keeper §10.6 rule 6's "current Cortex
	// service address", and a round that cannot name it is refused whether or
	// not a relay is wired: a submitter built on an empty identity would sign as
	// nobody.
	if _, err := withTx.commitSubmitter("  ", true); err == nil ||
		!strings.Contains(err.Error(), "current Cortex service address") {
		t.Fatalf("commitSubmitter() error = %v, want the missing service address refused", err)
	}
}
