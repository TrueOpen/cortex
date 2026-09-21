package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/config"
	"github.com/SingaXYZ/cortex/internal/diagnostics"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/natsidentity"
	"github.com/SingaXYZ/cortex/internal/signer"
)

// natsIdentityKeeper makes the committed service key read fail only after the runtime
// is constructed: construction itself needs that read to succeed (task-data
// authentication reads it too), so failure injection can only happen at the probe step.
type natsIdentityKeeper struct {
	confirmationKeeperReader
	failing *atomic.Bool
}

func (k natsIdentityKeeper) CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	if k.failing != nil && k.failing.Load() {
		return chainclient.ServiceKeySnapshot{}, 0, errors.New("keeper unreachable")
	}
	return k.confirmationKeeperReader.CommittedCurrentServiceKey(ctx, participantType, operatorAddress)
}

// natsIdentityTestConfig is a real-mode config wired to the on-chain identity: no creds
// file, only the local NATS user key file, from which the runtime must construct a Binder.
func natsIdentityTestConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	// The binding declaration's projection requires a canonical bech32 operator address,
	// and realConfig's placeholder string is not one.
	cfg.LocalIdentity.OperatorAddress = natsIdentityTestOperator
	cfg.Nexus.NATSCredsFile = ""
	cfg.Nexus.NATSUserKeyFile = filepath.Join(t.TempDir(), "nats-user.nk")
	return cfg
}

// natsIdentityTestOptions leaves NexusPublisher/NexusSubscriber empty so that the real
// NATS constructors run (they connect lazily and never dial).
func natsIdentityTestOptions(t *testing.T, cfg *config.Config, keeper KeeperClient, signingClient signer.Signer) RuntimeOptions {
	t.Helper()
	return RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		Keeper:                      keeper,
		KeeperEvents:                emptyKeeperEvents{},
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		// The sentinel source is a double here: a real source sends a GET to a Builder's
		// ingress, and these cases are about the binding itself. The default (ingress)
		// source is covered by TestNATSChainIdentityWithoutASentinelSourceIsUnready and
		// TestNATSSentinelIngress*.
		NATSSentinel: staticNATSSentinel{},
		ChainStatus:  staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	}
}

// staticNATSSentinel is a fixed AUTH sentinel, which saves running a real ingress.
type staticNATSSentinel struct{}

func (staticNATSSentinel) Sentinel(context.Context) (natsidentity.Sentinel, error) {
	return natsidentity.Sentinel{AuthAccountPublicKey: "ADBUILDERAUTHACCOUNT", JWT: "eyJ.sentinel.one"}, nil
}

// natsIdentityTestOperator is a canonical bech32 operator address: the on-chain
// identity binding's projection validates it.
const natsIdentityTestOperator = "trueopen1j5me037hs26kmqz7xy6s5f0y224trsphlqjfd2"

// natsIdentityTestSigner makes the signer, the on-chain snapshot and the config all
// name the same operator address.
func natsIdentityTestSigner(t *testing.T) (signer.Signer, staticKeeperIdentityReader) {
	t.Helper()
	signingClient, identityReader := readyRuntimeServiceSigner(t)
	identityReader.node.OperatorAddress = natsIdentityTestOperator
	identityReader.bond.OperatorAddress = natsIdentityTestOperator
	identityReader.key.OperatorAddress = natsIdentityTestOperator
	return signingClient, identityReader
}

func natsIdentityTestRuntime(t *testing.T) (*Runtime, *atomic.Bool) {
	t.Helper()
	cfg := natsIdentityTestConfig(t)
	signingClient, identityReader := natsIdentityTestSigner(t)
	failing := &atomic.Bool{}
	keeper := natsIdentityKeeper{
		confirmationKeeperReader: confirmationKeeperReader{staticKeeperIdentityReader: identityReader},
		failing:                  failing,
	}
	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, natsIdentityTestOptions(t, &cfg, keeper, signingClient))
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt, failing
}

// real mode + nats_user_key_file: the runtime must construct a Binder and wire it into
// the NATS connections and into diagnostics.
func TestRealModeBuildsNATSChainIdentity(t *testing.T) {
	rt, _ := natsIdentityTestRuntime(t)

	if rt.natsIdentity == nil {
		t.Fatal("real mode with nats_user_key_file must build a chain identity binder")
	}
	diag := rt.DiagnosticsSnapshot()
	if diag.NexusNATSIdentity == nil || diag.NexusNATSIdentity.UserPublicKey == "" {
		t.Fatalf("diagnostics must expose the nats identity: %+v", diag.NexusNATSIdentity)
	}
	status, ok := diag.Dependency("nexus_nats_identity")
	if !ok || !status.Configured {
		t.Fatalf("nexus_nats_identity dependency row missing or unconfigured: %+v", status)
	}
}

// Without a user key file this is the creds/token path: no Binder, and no binding
// diagnostic.
func TestRealModeWithoutUserKeyFileHasNoBinder(t *testing.T) {
	cfg := natsIdentityTestConfig(t)
	// Loopback: config validation allows no user key here.
	cfg.Nexus.NATSURL = "tls://127.0.0.1:4222"
	cfg.Nexus.NATSUserKeyFile = ""
	signingClient, identityReader := natsIdentityTestSigner(t)
	keeper := confirmationKeeperReader{staticKeeperIdentityReader: identityReader}

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, natsIdentityTestOptions(t, &cfg, keeper, signingClient))
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.natsIdentity != nil || rt.DiagnosticsSnapshot().NexusNATSIdentity != nil {
		t.Fatal("no user key file means creds/token path, no binder")
	}
	status, ok := rt.DiagnosticsSnapshot().Dependency("nexus_nats_identity")
	if !ok || status.Configured || !status.Optional {
		t.Fatalf("unconfigured nats identity row = %+v, want optional and unconfigured", status)
	}
}

// Only half injected: the other connection is still built by the runtime, so it has to
// carry the on-chain identity.
func TestPartiallyInjectedNexusTransportStillBuildsNATSChainIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		with func(*RuntimeOptions)
	}{
		{name: "publisher injected", with: func(o *RuntimeOptions) { o.NexusPublisher = fakePublisher{} }},
		{name: "subscriber injected", with: func(o *RuntimeOptions) { o.NexusSubscriber = fakeSubscriber{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := natsIdentityTestConfig(t)
			signingClient, identityReader := natsIdentityTestSigner(t)
			opts := natsIdentityTestOptions(t, &cfg, confirmationKeeperReader{staticKeeperIdentityReader: identityReader}, signingClient)
			tc.with(&opts)

			rt, err := BuildRuntimeWithOptions(context.Background(), cfg, opts)
			if err != nil {
				t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
			}
			t.Cleanup(func() { _ = rt.Close() })

			if rt.natsIdentity == nil {
				t.Fatal("a runtime-built nats connection must carry the chain identity")
			}
		})
	}
}

// An injected publisher/subscriber is a test double with no on-chain identity to
// attach, so no Binder should be constructed.
func TestInjectedNexusTransportSkipsNATSChainIdentity(t *testing.T) {
	cfg := natsIdentityTestConfig(t)
	signingClient, identityReader := natsIdentityTestSigner(t)
	opts := natsIdentityTestOptions(t, &cfg, confirmationKeeperReader{staticKeeperIdentityReader: identityReader}, signingClient)
	opts.NexusPublisher = fakePublisher{}
	opts.NexusSubscriber = fakeSubscriber{}

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.natsIdentity != nil {
		t.Fatal("injected nexus transports leave nothing to attach a chain identity to")
	}
}

// The probe is one real Credential: readiness means a credential can be signed, and a
// failed chain read has to carry its reason out.
func TestNATSChainIdentityReadinessFollowsBinder(t *testing.T) {
	rt, failing := natsIdentityTestRuntime(t)

	ready := rt.natsIdentityReadiness(context.Background())
	if !ready.Ready || ready.Error != "" {
		t.Fatalf("nats identity readiness = %+v, want ready", ready)
	}
	if rt.DiagnosticsSnapshot().NexusNATSIdentity.BindingNonce == 0 {
		t.Fatal("a successful credential must record the binding nonce in diagnostics")
	}

	failing.Store(true)
	rt.natsIdentity.Invalidate()
	unready := rt.natsIdentityReadiness(context.Background())
	if unready.Ready {
		t.Fatalf("nats identity readiness = %+v, want not ready once the chain read fails", unready)
	}
	if unready.Error == "" {
		t.Fatal("a failing binder must explain itself in the dependency row")
	}
	if last := rt.DiagnosticsSnapshot().NexusNATSIdentity.LastError; last == "" {
		t.Fatal("a failing binder must record its last error in diagnostics")
	}
}

// The default (uninjected) sentinel source is the Builder ingress: with neither
// nexus.builder_operator_address configured nor a readable BuilderSet, this dependency
// must report not-ready and say the sentinel could not be fetched, rather than quietly
// connecting without a jwt.
func TestNATSChainIdentityWithoutASentinelSourceIsUnready(t *testing.T) {
	cfg := natsIdentityTestConfig(t)
	signingClient, identityReader := natsIdentityTestSigner(t)
	opts := natsIdentityTestOptions(t, &cfg, confirmationKeeperReader{staticKeeperIdentityReader: identityReader}, signingClient)
	opts.NATSSentinel = nil

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	status := rt.natsIdentityReadiness(context.Background())
	if status.Ready || !strings.Contains(status.Error, "nats sentinel") {
		t.Fatalf("nats identity readiness = %+v, want not ready naming the sentinel", status)
	}
}

// The gate itself: a node that configured a user key file but cannot sign a binding
// should take on no new work. The path without one is creds/token and is not a missing
// dependency.
func TestWorkloadDependenciesRequireConfiguredNATSChainIdentity(t *testing.T) {
	names := []string{"chain", "model_service", "store", "keeper", "nexus", "nexus_envelope_auth", "builder_descriptor"}
	report := diagnostics.Diagnostics{}
	for _, name := range names {
		report.Dependencies = append(report.Dependencies, diagnostics.DependencyStatus{Name: name, Configured: true, Ready: true})
	}
	unconfigured := diagnostics.DependencyStatus{Name: natsIdentityDependency, Configured: false, Optional: true}
	if !workloadDependenciesReady(report, false, unconfigured) {
		t.Fatal("workloadDependenciesReady() = false on the creds/token path, which has no binding to gate on")
	}
	ready := diagnostics.DependencyStatus{Name: natsIdentityDependency, Configured: true, Ready: true}
	if !workloadDependenciesReady(report, false, ready) {
		t.Fatal("workloadDependenciesReady() = false with a signable chain identity binding")
	}
	unready := diagnostics.DependencyStatus{Name: natsIdentityDependency, Configured: true, Ready: false,
		Error: "read committed cortex service key: keeper unreachable"}
	if workloadDependenciesReady(report, false, unready) {
		t.Fatal("workloadDependenciesReady() = true while this node cannot sign the binding it presents to NATS")
	}
}

// End to end: a failed probe has to reach the workload gate, not just show red in
// diagnostics.
func TestFailingNATSChainIdentityWithholdsWorkload(t *testing.T) {
	rt, failing := natsIdentityTestRuntime(t)
	failing.Store(true)
	rt.natsIdentity.Invalidate()

	readiness := rt.CheckWorkloadReadiness(context.Background())
	if readiness.NATSIdentity.Ready {
		t.Fatalf("nats identity status = %+v, want not ready", readiness.NATSIdentity)
	}
	if readiness.DependenciesReady {
		t.Fatal("DependenciesReady = true while the chain identity binding cannot be signed")
	}
	if readiness.Ready() {
		t.Fatal("workload readiness = true while the chain identity binding cannot be signed")
	}
}
