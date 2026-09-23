package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/diagnostics"
)

// The three assertions here are one devnet symptom: five nodes logged
// `dependency still not ready dep="tx_broadcaster" endpoint="…:26657"
// reason="tx_broadcaster readiness probe failed"` every five minutes for 30
// minutes, 1186 consecutive checks, with no way to learn either what failed or
// that it did not matter.

// TestTxBroadcasterStatusNamesTheEndpointTheProbeReads pins the endpoint the
// record reports. The probe queries the Cosmos Auth account over
// node.rest_endpoint; it never touches node.rpc_endpoint, so naming the RPC
// endpoint sent operators to inspect a port this dependency does not use.
func TestTxBroadcasterStatusNamesTheEndpointTheProbeReads(t *testing.T) {
	cfg := realConfig()
	cfg.Node.RPCEndpoint = "http://127.0.0.1:26657"
	cfg.Node.RESTEndpoint = "http://127.0.0.1:1317"
	deps, err := BuildDependencies(cfg, DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	status, ok := deps.Diagnostics.Dependency("tx_broadcaster")
	if !ok {
		t.Fatal("tx_broadcaster has no dependency record")
	}
	if status.Endpoint != cfg.Node.RESTEndpoint {
		t.Fatalf("tx_broadcaster endpoint = %q, want the REST endpoint %q the probe reads",
			status.Endpoint, cfg.Node.RESTEndpoint)
	}
}

// TestDependencyReadinessReportsTheProbeError pins the reason. The probe
// already knows why - "signer cannot produce Cosmos transactions" is exact and
// actionable - and overwriting it with the probe's own name discarded the only
// useful field on the line. checkModelServiceReadiness has always reported
// err.Error(); this path was the outlier.
func TestDependencyReadinessReportsTheProbeError(t *testing.T) {
	rt := &Runtime{cfg: realConfig()}
	rt.Dependencies.Diagnostics = diagnostics.Diagnostics{Dependencies: []diagnostics.DependencyStatus{
		{Name: "tx_broadcaster", Endpoint: "http://127.0.0.1:1317"},
	}}
	probe := readinessProbeFunc(func(context.Context) error {
		return errors.New("signer cannot produce Cosmos transactions")
	})
	status := rt.checkDependencyReadiness(context.Background(), "tx_broadcaster", probe)
	if status.Ready {
		t.Fatalf("status = %#v, want not ready", status)
	}
	if !strings.Contains(status.Error, "signer cannot produce Cosmos transactions") {
		t.Fatalf("status.Error = %q, want the probe's own reason preserved", status.Error)
	}
}

// TestTxBroadcasterDoesNotGateARealNodeWithoutADirectPath replaces a test that
// asserted the opposite: that every real-mode node must hold its whole workload
// down until tx_broadcaster is ready, because a selected Verifier's commit has
// no relay and must be self-submitted.
//
// The commit exit is still the only route to CommitState, but it is not a
// whole-node dependency. Nexus relays every other duty message as its own
// transaction -- worker handraise, infer receipt, verifier handraise, and the
// Verifier result receipt -- so a node whose signer cannot produce Cosmos
// transactions (a file:// keystore: signer.LocalSigner.CanSignCosmosTx is
// false) can serve a full Worker round. Gating readiness on the broadcaster
// turned "cannot commit" into "does nothing", and the commit exit already
// refuses per round, before the commit is signed
// (productionVerifyExecutor.commitSubmitter).
//
// The optionality tracks RequiresWorkloadTx rather than being hardcoded, so a
// scheduled direct path still gates.
func TestTxBroadcasterDoesNotGateARealNodeWithoutADirectPath(t *testing.T) {
	cfg := realConfig()
	if cfg.RequiresWorkloadTx() {
		t.Fatal("RequiresWorkloadTx() = true for a real-mode node with both direct paths disabled")
	}
	deps, err := BuildDependencies(cfg, DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	status, _ := deps.Diagnostics.Dependency("tx_broadcaster")
	if !status.Optional {
		t.Fatalf("tx_broadcaster = %#v, want optional: nexus relays every duty message this node owes", status)
	}
	if workloadDependenciesReady(deps.Diagnostics, cfg.RequiresWorkloadTx(),
		notReadyTxStatus()) != workloadDependenciesReady(deps.Diagnostics, cfg.RequiresWorkloadTx()) {
		t.Fatal("an unready tx_broadcaster changed the workload gate for a node with no direct path")
	}

	// A scheduled direct path has no relay at all, so there the broadcaster is
	// the only exit and still gates.
	direct := realConfig()
	direct.SelfRescue.Enabled = true
	if !direct.RequiresWorkloadTx() {
		t.Fatal("RequiresWorkloadTx() = false with self_rescue enabled")
	}
	if requiredStatus := txBroadcasterStatus(direct, false); requiredStatus.Optional {
		t.Fatalf("tx_broadcaster = %#v, want required where a scheduled direct path submits transactions", requiredStatus)
	}
}

func notReadyTxStatus() diagnostics.DependencyStatus {
	return diagnostics.DependencyStatus{
		Name: "tx_broadcaster", Configured: true, Optional: true,
		Error: "signer cannot produce Cosmos transactions",
	}
}

// TestDependencyReadinessScrubsCredentialsFromTheProbeReason is the constraint
// that made the reason a fixed string in the first place.
//
// A probe error can quote the endpoint it dialled, and a NATS URL may carry
// userinfo (config.NexusConfig.NATSURLCredentials). Discarding the whole
// message was one way to guarantee no credential reached the log; keeping the
// message and scrubbing the userinfo is the other, and it is the one that also
// tells an operator what failed. The host stays: it is already published in
// DependencyStatus.Endpoint, so hiding it buys nothing.
func TestDependencyReadinessScrubsCredentialsFromTheProbeReason(t *testing.T) {
	cfg := realConfig()
	cfg.Nexus.NATSURL = "tls://operator:s3cret@nexus.devnet.trueopen.xyz:4222"
	rt := &Runtime{cfg: cfg}
	rt.Dependencies.Diagnostics = diagnostics.Diagnostics{Dependencies: []diagnostics.DependencyStatus{
		{Name: "nexus", Endpoint: cfg.Nexus.NATSURL},
	}}
	probe := readinessProbeFunc(func(context.Context) error {
		return errors.New("nats: no servers available at " + cfg.Nexus.NATSURL)
	})

	status := rt.checkDependencyReadiness(context.Background(), "nexus", probe)
	if strings.Contains(status.Error, "s3cret") {
		t.Fatalf("status.Error = %q, want the NATS userinfo scrubbed", status.Error)
	}
	if !strings.Contains(status.Error, "no servers available") {
		t.Fatalf("status.Error = %q, want the probe's reason preserved", status.Error)
	}
	if !strings.Contains(status.Error, "nexus.devnet.trueopen.xyz:4222") {
		t.Fatalf("status.Error = %q, want the host kept: it is already in the Endpoint field", status.Error)
	}
}
