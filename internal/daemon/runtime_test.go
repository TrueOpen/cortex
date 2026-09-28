package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/txclient"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type taskInputResolverFunc func(context.Context, TaskInputRef) ([]byte, error)

func (f taskInputResolverFunc) ResolveTaskInput(ctx context.Context, ref TaskInputRef) ([]byte, error) {
	return f(ctx, ref)
}

func TestBuildRuntimeKeepsOperatorControlPlaneWithoutKeeperIdentity(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	keeper := missingIdentityKeeper{confirmationKeeperReader: confirmationKeeperReader{staticKeeperIdentityReader: readyKeeperIdentityReader()}}

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:     modelservice.NewFakeService(),
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          keeper,
		KeeperEvents:    emptyKeeperEvents{},
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.Dependencies.Tx != nil {
		t.Fatal("operator transaction client must not exist in cortexd")
	}
	if rt.Reconciler == nil {
		t.Fatal("Reconciler = nil while Keeper identity is absent")
	}
	if rt.ProtocolTx != nil || rt.ServiceAddress != "" {
		t.Fatalf("workload plane activated while identity is absent: service=%q protocol=%#v", rt.ServiceAddress, rt.ProtocolTx)
	}
	status, ok := rt.Dependencies.Diagnostics.Dependency("keeper_identity")
	if !ok || status.Ready {
		t.Fatalf("keeper_identity status = %#v ok=%v, want degraded", status, ok)
	}
}

func TestBuildRuntimeProductionTaskDataClientRefusesPlaintextEndpoint(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	keeper := missingIdentityKeeper{confirmationKeeperReader: confirmationKeeperReader{staticKeeperIdentityReader: readyKeeperIdentityReader()}}

	strict, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:     modelservice.NewFakeService(),
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          keeper,
		KeeperEvents:    emptyKeeperEvents{},
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() strict error = %v", err)
	}
	t.Cleanup(func() { _ = strict.Close() })
	_, err = strict.Dependencies.TaskData.GetTaskDataMetadata(context.Background(),
		"http://builder.invalid", runtimeTaskDataMetadataRequest(t))
	if err == nil || !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor") {
		t.Fatalf("plaintext endpoint error = %v, want a refusal naming nexus.allow_insecure_descriptor", err)
	}
}

func TestBuildRuntimeProductionRefusesInsecureDescriptorOptIn(t *testing.T) {
	cfg := realConfig()
	cfg.Nexus.AllowInsecureDescriptor = true
	cfg.Store.Path = filepath.Join(t.TempDir(), "insecure.kv")
	keeper := missingIdentityKeeper{confirmationKeeperReader: confirmationKeeperReader{staticKeeperIdentityReader: readyKeeperIdentityReader()}}
	if _, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:     modelservice.NewFakeService(),
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          keeper,
		KeeperEvents:    emptyKeeperEvents{},
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	}); err == nil || !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor must be false in real mode") {
		t.Fatalf("BuildRuntimeWithOptions() error = %v, want real mode refusal of allow_insecure_descriptor", err)
	}
}

// TestBuildRuntimeProductionTaskDataClientRefusesCrossOriginRedirect verifies that
// a runtime with the insecure opt-in refuses to follow cross-origin redirects.
// Real mode now refuses the opt-in entirely, so this scenario is exercised by a
// dedicated fake-mode test below.
func TestBuildRuntimeProductionTaskDataClientRefusesCrossOriginRedirect(t *testing.T) {
	t.Skip("real mode refuses allow_insecure_descriptor; cross-origin redirect policy is covered by a fake-mode test")
}

func TestBuildRuntimePreservesInjectedTaskDataClient(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	keeper := missingIdentityKeeper{confirmationKeeperReader: confirmationKeeperReader{staticKeeperIdentityReader: readyKeeperIdentityReader()}}
	injected := builderclient.NewFakeClient()

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:     modelservice.NewFakeService(),
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		TaskDataClient:  injected,
		Keeper:          keeper,
		KeeperEvents:    emptyKeeperEvents{},
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.Dependencies.TaskData != injected {
		t.Fatalf("runtime task-data client = %T %p, want injected %p", rt.Dependencies.TaskData, rt.Dependencies.TaskData, injected)
	}
}

func runtimeTaskDataMetadataRequest(t *testing.T) builderclient.GetTaskDataMetadataRequest {
	t.Helper()
	private, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	public := private.PubKey().SerializeCompressed()
	requester, err := signer.AddressFromCompressedPublicKey("trueopen", public)
	if err != nil {
		t.Fatalf("AddressFromCompressedPublicKey: %v", err)
	}
	key := builderclient.TaskDataKey{TaskHash: strings.Repeat("44", 32), ContentHash: strings.Repeat("55", 32), SessionID: strings.Repeat("11", 32), TaskID: strings.Repeat("22", 32), Kind: builderclient.DataKindInput}
	bodyDigest, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	auth := builderclient.TaskDataRequestAuth{
		SchemaVersion: 1, ChainID: "trueopen-devnet-1", BuilderAddress: inputTestBuilder, Method: builderclient.TaskDataProcedure("GetTaskDataMetadata"), BodyDigest: bodyDigest,
		Requester: requester, RequesterKind: builderclient.TaskDataRequesterCortexService, ServiceAuthorizationNonce: 1, RequestNonce: bytes.Repeat([]byte{0x51}, 32), ExpiresAtHeight: 200,
	}
	digest, err := builderclient.TaskDataRequestSigningHash(auth)
	if err != nil {
		t.Fatalf("TaskDataRequestSigningHash: %v", err)
	}
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	auth.Signature = make([]byte, 64)
	r.PutBytesUnchecked(auth.Signature[:32])
	s.PutBytesUnchecked(auth.Signature[32:])
	return builderclient.GetTaskDataMetadataRequest{Key: key, Auth: auth}
}

type missingIdentityKeeper struct{ confirmationKeeperReader }

func (missingIdentityKeeper) CortexNode(context.Context, string) (chainclient.CortexNodeSnapshot, error) {
	return chainclient.CortexNodeSnapshot{}, errors.New("not found")
}

type emptyKeeperEvents struct{}

func (emptyKeeperEvents) FinalizedEvents(context.Context, chainclient.EventPosition) (chainclient.KeeperEventsPage, error) {
	return chainclient.KeeperEventsPage{}, nil
}

func TestBuildRuntimeRealModeConstructsKeeperConfirmedCosmosTxClient(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	signingClient, identityReader := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	keeper := confirmationKeeperReader{staticKeeperIdentityReader: identityReader}

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		Keeper:                      keeper,
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		TxReadinessProbe: readinessProbeFunc(func(context.Context) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	if rt.Dependencies.Tx != nil {
		t.Fatal("operator transaction client must not exist in cortexd")
	}
	if rt.WorkloadTx == nil {
		t.Fatal("WorkloadTx = nil, want current service-key client")
	}
	if rt.ProtocolTx == nil {
		t.Fatal("ProtocolTx = nil, want runtime-constructed protocol adapters")
	}
	if rt.ServiceAddress != identityReader.key.ServiceAddress {
		t.Fatalf("ServiceAddress = %q", rt.ServiceAddress)
	}
	status, _ := rt.Dependencies.Diagnostics.Dependency("tx_broadcaster")
	if !status.Ready {
		t.Fatalf("tx_broadcaster = %#v", status)
	}
}

func runtimeTestEnvelopeAuthenticator() builderclient.BusEnvelopeAuthenticator {
	return builderclient.BusEnvelopeAuthenticatorFunc(func(context.Context, string, builderclient.BusEnvelope) error { return nil })
}

func runtimeTestEnvelopeSigner() builderclient.BusEnvelopeSigner {
	return builderclient.BusEnvelopeSignerFunc(func(builderclient.BusEnvelope) ([]byte, error) {
		return []byte("runtime-test-envelope-signature"), nil
	})
}

type confirmationKeeperReader struct{ staticKeeperIdentityReader }

func (confirmationKeeperReader) Model(context.Context, string) (chainclient.ModelSnapshot, error) {
	return chainclient.ModelSnapshot{}, nil
}

func (confirmationKeeperReader) Profile(context.Context, string, string) (chainclient.ProfileSnapshot, error) {
	return chainclient.ProfileSnapshot{}, nil
}

func (confirmationKeeperReader) Settlement(context.Context, string, string) (chainclient.TaskSettlementSnapshot, error) {
	return chainclient.TaskSettlementSnapshot{}, nil
}
func (confirmationKeeperReader) ChallengeCommit(context.Context, string, string) (chainclient.ChallengeCommitSnapshot, error) {
	return chainclient.ChallengeCommitSnapshot{}, nil
}
func (confirmationKeeperReader) ChallengeResultReceipt(context.Context, string, string) (chainclient.ChallengeResultReceiptSnapshot, error) {
	return chainclient.ChallengeResultReceiptSnapshot{}, nil
}
func (confirmationKeeperReader) ChallengeFullResultReveal(context.Context, string, string) (chainclient.ChallengeFullResultRevealSnapshot, error) {
	return chainclient.ChallengeFullResultRevealSnapshot{}, nil
}

var _ txclient.KeeperConfirmationReader = confirmationKeeperReader{}

func TestLoadNexusTokenTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("\n token-1 \t\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	token, err := loadNexusToken(config.NexusConfig{AuthTokenFile: path})
	if err != nil {
		t.Fatalf("loadNexusToken() error = %v", err)
	}
	if token != "token-1" {
		t.Fatalf("token = %q, want %q", token, "token-1")
	}
}

func TestLoadNexusTokenEmptyPathReturnsEmptyToken(t *testing.T) {
	token, err := loadNexusToken(config.NexusConfig{})
	if err != nil {
		t.Fatalf("loadNexusToken() error = %v", err)
	}
	if token != "" {
		t.Fatalf("token = %q, want empty", token)
	}
}

func TestBuildRuntimeFakeModeOpensStoreAndCreatesFakeDependencies(t *testing.T) {
	cfg := fakeConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	if rt.Store == nil {
		t.Fatalf("Store = nil")
	}
	if got := reflect.TypeOf(rt.Dependencies.Model).String(); got != "*modelservice.FakeService" {
		t.Fatalf("Model = %T, want *modelservice.FakeService", rt.Dependencies.Model)
	}
	if got := reflect.TypeOf(rt.Dependencies.Builder).String(); got != "*builderclient.FakeClient" {
		t.Fatalf("Builder = %T, want *builderclient.FakeClient", rt.Dependencies.Builder)
	}
}

func TestBuildRuntimeRealModeUnavailableTransportReportsDiagnostic(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	// When the runtime builds the NATS connection itself it generates the local user key
	// at nats_user_key_file, so tests point it at a temp dir.
	cfg.Nexus.NATSUserKeyFile = filepath.Join(t.TempDir(), "nats-user.nk")

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	status, ok := rt.Dependencies.Diagnostics.Dependency("model_service")
	if !ok {
		t.Fatalf("missing model_service diagnostic")
	}
	if status.Ready {
		t.Fatalf("model_service status = %#v", status)
	}
	if status.Error == "" || status.Error == "model transport is required" {
		t.Fatalf("model_service error = %q, want runtime transport detail", status.Error)
	}
	if want := "modelservice health check failed"; !strings.Contains(status.Error, want) {
		t.Fatalf("model_service error = %q, want %q", status.Error, want)
	}
}

func TestBuildRuntimeRealModeReportsModelServiceHealth(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	// When the runtime builds the NATS connection itself it generates the local user key
	// at nats_user_key_file, so tests point it at a temp dir.
	cfg.Nexus.NATSUserKeyFile = filepath.Join(t.TempDir(), "nats-user.nk")
	cfg.ModelManagement.Endpoint = "127.0.0.1:19001" // a loopback name: real mode allows plaintext only on the same host; the dial still goes through bufnet
	newDaemonGRPCTestServer(t, cfg.ModelManagement.Endpoint, &daemonModelManagementServer{healthy: true})

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	status, ok := rt.Dependencies.Diagnostics.Dependency("model_service")
	if !ok {
		t.Fatalf("missing model_service diagnostic")
	}
	if !status.Ready || status.Error != "" {
		t.Fatalf("model_service status = %#v, want healthy", status)
	}
}

func TestBuildRuntimeRealModeLocalModelServiceSkipsGRPCHealthProbe(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.ModelManagement.Transport = " LOCAL "
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 4

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          readyKeeperIdentityReader(),
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	if _, ok := rt.Dependencies.Model.(*modelservice.LocalService); !ok {
		t.Fatalf("Model = %T, want *modelservice.LocalService", rt.Dependencies.Model)
	}
	status, ok := rt.Dependencies.Diagnostics.Dependency("model_service")
	if !ok || !status.Configured || !status.Ready || status.Error != "" {
		t.Fatalf("model_service status = %#v ok=%v, want ready local model service", status, ok)
	}
}

func TestBuildRuntimeRealModeReportsUnhealthyModelService(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	// When the runtime builds the NATS connection itself it generates the local user key
	// at nats_user_key_file, so tests point it at a temp dir.
	cfg.Nexus.NATSUserKeyFile = filepath.Join(t.TempDir(), "nats-user.nk")
	cfg.ModelManagement.Endpoint = "127.0.0.1:19002" // as above
	newDaemonGRPCTestServer(t, cfg.ModelManagement.Endpoint, &daemonModelManagementServer{
		healthy: false,
		respError: &cortexv1.ModelServiceError{
			Code:    "MODEL_WARMING",
			Message: "temporary warmup; secret-token and prompt text must not appear",
		},
	})

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	status, ok := rt.Dependencies.Diagnostics.Dependency("model_service")
	if !ok {
		t.Fatalf("missing model_service diagnostic")
	}
	if status.Ready {
		t.Fatalf("model_service status = %#v, want unhealthy", status)
	}
	if want := "modelservice health unhealthy: MODEL_WARMING"; !strings.Contains(status.Error, want) {
		t.Fatalf("model_service error = %q, want %q", status.Error, want)
	}
	for _, leaked := range []string{"secret-token", "prompt text"} {
		if strings.Contains(status.Error, leaked) {
			t.Fatalf("model_service error leaked %q: %q", leaked, status.Error)
		}
	}
}

func TestBuildRuntimeRealModeConstructsNexusPublisherAndSubscriber(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	// When the runtime builds the NATS connection itself it generates the local user key
	// at nats_user_key_file, so tests point it at a temp dir.
	cfg.Nexus.NATSUserKeyFile = filepath.Join(t.TempDir(), "nats-user.nk")
	cfg.Nexus.NATSURL = "tls://nexus.devnet.trueopen.xyz:4222"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	status, ok := rt.Dependencies.Diagnostics.Dependency("nexus")
	if !ok {
		t.Fatalf("missing nexus diagnostic")
	}
	if !status.Ready || status.Error != "" {
		t.Fatalf("nexus status = %#v, want ready with concrete NATS publisher/subscriber", status)
	}
}

func TestBuildRuntimeRealModeInjectedNexusPublisherIsReady(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          readyKeeperIdentityReader(),
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	status, ok := rt.Dependencies.Diagnostics.Dependency("nexus")
	if !ok {
		t.Fatalf("missing nexus diagnostic")
	}
	if !status.Ready || status.Error != "" {
		t.Fatalf("nexus status = %#v, want ready with injected publisher", status)
	}
}

func TestRuntimeReadinessTracksNexusAndTxBroadcasterLoss(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	signingClient, keeper := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	nexusProbe := &controlledReadinessProbe{}
	txProbe := &controlledReadinessProbe{}
	nexusProbe.healthy.Store(true)
	txProbe.healthy.Store(true)

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		NexusReadinessProbe:         nexusProbe,
		TxReadinessProbe:            txProbe,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if readiness := rt.CheckWorkloadReadiness(context.Background()); !readiness.Ready() || !readiness.Nexus.Ready || !readiness.TxBroadcaster.Ready {
		t.Fatalf("initial readiness = %#v, want ready", readiness)
	}
	nexusProbe.healthy.Store(false)
	readiness := rt.CheckWorkloadReadiness(context.Background())
	if readiness.Ready() || readiness.Nexus.Ready || !readiness.TxBroadcaster.Ready {
		t.Fatalf("Nexus-loss readiness = %#v", readiness)
	}
	if strings.Contains(readiness.Nexus.Error, cfg.Nexus.NATSURL) {
		t.Fatalf("Nexus readiness error leaked endpoint: %q", readiness.Nexus.Error)
	}
	status, ok := rt.DiagnosticsSnapshot().Dependency("nexus")
	// The reason carries the probe's own message now. It used to be exactly
	// "nexus readiness probe failed", which is why 30 minutes of tx_broadcaster
	// lines said nothing: the probe knew, and the record threw it away. What
	// must still never appear is a credential - see
	// TestDependencyReadinessScrubsCredentialsFromTheProbeReason.
	if !ok || status.Ready || !strings.HasPrefix(status.Error, "nexus readiness probe failed") {
		t.Fatalf("live Nexus diagnostic = %#v ok=%v", status, ok)
	}
	if !strings.Contains(status.Error, "dependency unavailable") {
		t.Fatalf("live Nexus diagnostic = %#v, want the probe's own reason reported", status)
	}

	// tx loss is reported but does not hold the workload down. A selected
	// Verifier's commit does need a self-submitted MsgSubmitVerifyCommit
	// (internal/verifier/commit_exit.go) and will fail its round while the
	// broadcaster is down, but every other duty message is relayed by nexus, so
	// refusing the whole workload here would stop work that needs no
	// transaction at all -- including on a node whose signer can never produce
	// one (TestBuildRuntimeStartsWorkloadWithoutCosmosTxSigner).
	nexusProbe.healthy.Store(true)
	txProbe.healthy.Store(false)
	readiness = rt.CheckWorkloadReadiness(context.Background())
	if !readiness.Ready() || !readiness.Nexus.Ready {
		t.Fatalf("tx-loss readiness = %#v, want ready with only the broadcaster degraded", readiness)
	}
	if readiness.TxBroadcaster.Ready {
		t.Fatalf("tx-loss readiness = %#v, want the broadcaster reported as unready", readiness)
	}
	txProbe.healthy.Store(true)
	if readiness = rt.CheckWorkloadReadiness(context.Background()); !readiness.Ready() {
		t.Fatalf("recovered readiness = %#v, want ready", readiness)
	}
}

// TestRuntimeTrustedNATSDevRefusedInRealMode verifies that a runtime configured
// for the unsafe dev-only transport boundary is rejected when mode is real.
func TestRuntimeTrustedNATSDevRefusedInRealMode(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AuthTokenFile = filepath.Join(t.TempDir(), "nexus.token")
	const secret = "runtime-trusted-token"
	if err := os.WriteFile(cfg.Nexus.AuthTokenFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	signingClient, keeper := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	if _, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient: modelservice.NewFakeService(), NexusPublisher: fakePublisher{}, NexusSubscriber: fakeSubscriber{},
		TxClient: txclient.NewFake(), Keeper: keeper, SigningClient: signingClient, TrustInjectedSignerForTests: true,
		ChainStatus: staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	}); err == nil || !strings.Contains(err.Error(), "nexus.envelope_auth_mode must not be trusted_nats_dev in real mode") {
		t.Fatalf("BuildRuntimeWithOptions() error = %v, want real mode refusal of trusted_nats_dev", err)
	}
}

// TestBuildRuntimeStartsWorkloadWithoutCosmosTxSigner replaces a test that
// asserted the opposite: that a signer which cannot produce Cosmos transactions
// must hold the whole workload down, because a Verifier's commit has no relay
// and must be self-submitted.
//
// The commit exit is unchanged and still the only route to CommitState. What
// changed is the blast radius: holding readiness down for it also refused the
// Worker duty, which owes no transaction at all -- nexus relays worker
// handraise, infer receipt, verifier handraise and the Verifier result receipt
// as its own. So a file:// keystore node (LocalSigner.CanSignCosmosTx is false)
// now runs and reports tx_broadcaster's real reason as an optional dependency.
// Its verify rounds take the nexus#70 Builder relay; only a round with no relay
// either fails, at commitSubmitter, before the commit is signed.
func TestBuildRuntimeStartsWorkloadWithoutCosmosTxSigner(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.SelfRescue.Enabled = false
	keeper := readyKeeperIdentityReader()

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		Keeper:                      confirmationKeeperReader{staticKeeperIdentityReader: keeper},
		SigningClient:               incapableSigner{capable: false},
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	readiness := rt.CheckWorkloadReadiness(context.Background())
	if !readiness.Ready() {
		t.Fatalf("readiness = %#v, want ready: no duty this node owes needs a direct transaction", readiness)
	}
	// The broadcaster still reports honestly. It is simply not a gate.
	if readiness.TxBroadcaster.Ready {
		t.Fatalf("tx_broadcaster = %#v, want the incapable signer reported", readiness.TxBroadcaster)
	}
	if !strings.Contains(readiness.TxBroadcaster.Error, "signer cannot produce Cosmos transactions") {
		t.Fatalf("tx_broadcaster status = %#v, want the signer's own reason", readiness.TxBroadcaster)
	}
	if !readiness.Identity.Ready || !readiness.ModelSupport.Ready || !readiness.Nexus.Ready {
		t.Fatalf("readiness = %#v, want every gating boundary ready", readiness)
	}
	// Activation succeeds with no tx client, and nothing pretends one exists:
	// the verifier commit exit resolves its submitter per round and refuses
	// there when it finds none.
	if err := rt.ActivateWorkload(readiness.ServiceAddress, readiness.ServicePubkey); err != nil {
		t.Fatalf("ActivateWorkload() error = %v, want activation without a direct transaction path", err)
	}
	if !rt.WorkloadActive() {
		t.Fatal("workload inactive after ActivateWorkload")
	}
	if rt.WorkloadTx != nil || rt.ProtocolTx != nil {
		t.Fatalf("direct tx unexpectedly wired: tx=%#v protocol=%#v", rt.WorkloadTx, rt.ProtocolTx)
	}
}

func TestActivateWorkloadRequiresTxForEnabledDirectPath(t *testing.T) {
	rt := &Runtime{cfg: config.Config{SelfRescue: config.SelfRescueConfig{Enabled: true}}}
	err := rt.ActivateWorkload("trueopen1service", "02"+strings.Repeat("02", 32))
	if err == nil || !strings.Contains(err.Error(), "enabled direct transaction path") {
		t.Fatalf("ActivateWorkload() error = %v, want required tx failure", err)
	}
	if rt.WorkloadActive() {
		t.Fatal("workload activated without required direct transaction client")
	}
}

func TestBuildRuntimeRealModeCreatesKeeperReconciler(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	keeper := readyKeeperIdentityReader()

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelTransport:  fakeModelTransport{},
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          keeper,
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	if rt.Reconciler == nil {
		t.Fatalf("Reconciler = nil, want real-mode keeper reconciler")
	}
	if rt.Reconciler.tasks == nil {
		t.Fatalf("Reconciler task reader = nil, want authoritative Keeper Query reader")
	}
	if _, ok := rt.KeeperEvents.(*chainclient.CometEventClient); !ok {
		t.Fatalf("KeeperEvents = %T, want *chainclient.CometEventClient", rt.KeeperEvents)
	}
}

func TestBuildRuntimeRealModeReconcilerEmitsAssignmentEffect(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.LocalIdentity.OperatorAddress = "node-local"
	cfg.TaskExecution.InputResolver = config.InputResolverNexus
	keeper := readyKeeperIdentityReader()
	keeper.node.OperatorAddress = "node-local"
	keeper.bond.OperatorAddress = "node-local"
	keeper.key.OperatorAddress = "node-local"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelTransport:  fakeModelTransport{},
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          keeper,
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		TaskInputResolver: taskInputResolverFunc(func(context.Context, TaskInputRef) ([]byte, error) {
			return []byte("reconciler test input"), nil
		}),
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	taskHash := codec.HashBytes([]byte("task-1"))
	rt.Reconciler.tasks = &staticKeeperTaskReader{snapshot: validTaskSnapshot("session-1", "task-1", taskHash)}

	effects, err := rt.Reconciler.Apply(context.Background(), []chainclient.KeeperEvent{
		{Type: chainclient.KeeperEventAssignmentFinalized, SessionID: "session-1", TaskID: "task-1", Height: 11, Worker: "worker-1"},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 || effects[0].Type != ReconcilerEffectAssignment || effects[0].TaskHash != taskHash {
		t.Fatalf("effects = %#v, want task-hash-keyed assignment", effects)
	}
}

func TestBuildRuntimeRealModeIdentityMismatchKeepsChainSyncButDisablesWorkload(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	keeper := readyKeeperIdentityReader()
	keeper.node.OperatorAddress = "trueopen1other"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelTransport:  fakeModelTransport{},
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		Keeper:          keeper,
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	status, ok := rt.Dependencies.Diagnostics.Dependency("keeper_identity")
	if !ok || status.Ready || !strings.Contains(status.Error, "operator") {
		t.Fatalf("keeper_identity status = %#v, want fail-closed operator mismatch", status)
	}
	if rt.Reconciler == nil {
		t.Fatal("Reconciler = nil, want base control-plane chain sync")
	}
	if rt.ProtocolTx != nil || rt.WorkloadTx != nil {
		t.Fatalf("workload dependencies activated with invalid identity: tx=%#v protocol=%#v", rt.WorkloadTx, rt.ProtocolTx)
	}
}

func TestBuildRuntimeFakeModeDoesNotCreateKeeperReconciler(t *testing.T) {
	cfg := fakeConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	if rt.Reconciler != nil {
		t.Fatalf("Reconciler = %#v, want nil in fake mode", rt.Reconciler)
	}
}

func TestBuildRuntimeRealModeInvalidNexusURLReportsDiagnostic(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	// When the runtime builds the NATS connection itself it generates the local user key
	// at nats_user_key_file, so tests point it at a temp dir.
	cfg.Nexus.NATSUserKeyFile = filepath.Join(t.TempDir(), "nats-user.nk")
	cfg.Nexus.NATSURL = "http://127.0.0.1:4222" // a loopback address does not trigger real mode's tls:// requirement, leaving only the scheme error itself

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{Keeper: readyKeeperIdentityReader()})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	status, ok := rt.Dependencies.Diagnostics.Dependency("nexus")
	if !ok {
		t.Fatalf("missing nexus diagnostic")
	}
	if status.Ready || !strings.Contains(status.Error, "unsupported nexus nats url scheme") {
		t.Fatalf("nexus status = %#v, want invalid NATS URL diagnostic", status)
	}
}

func TestRuntimeCloseNilSafe(t *testing.T) {
	var rt *Runtime
	if err := rt.Close(); err != nil {
		t.Fatalf("nil Runtime Close() error = %v", err)
	}

	rt = &Runtime{}
	if err := rt.Close(); err != nil {
		t.Fatalf("empty Runtime Close() error = %v", err)
	}
}

func TestRuntimeCloseClosesNexusTransports(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	publisher := &closeTrackingPublisher{}
	subscriber := &closeTrackingSubscriber{}

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		NexusPublisher:  publisher,
		NexusSubscriber: subscriber,
		Keeper:          readyKeeperIdentityReader(),
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !publisher.closed || !subscriber.closed {
		t.Fatalf("closed publisher=%v subscriber=%v, want both closed", publisher.closed, subscriber.closed)
	}
}

func TestRuntimeRealModeFakeModelWiresFixtureDependencies(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.ModelManagement.Transport = "fake"
	cfg.ModelManagement.Endpoint = ""
	cfg.TaskExecution.InputResolver = "fixture"
	cfg.TaskExecution.FixtureRoot = t.TempDir()
	signingClient, identityReader := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	taskData := builderclient.NewFakeClient()

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      confirmationKeeperReader{staticKeeperIdentityReader: identityReader},
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		TaskDataClient:              taskData,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	defer rt.Close()
	if _, ok := rt.Dependencies.Model.(*modelservice.FakeService); !ok {
		t.Fatalf("Model = %T, want shared *modelservice.FakeService", rt.Dependencies.Model)
	}
	if _, ok := rt.TaskInputResolver.(*FixtureTaskInputResolver); !ok {
		t.Fatalf("TaskInputResolver = %T, want *FixtureTaskInputResolver", rt.TaskInputResolver)
	}
	if rt.Dependencies.TaskData != taskData || rt.TaskDataAuth == nil {
		t.Fatalf("fixture Worker TaskData/Auth = %T/%v, want shared client and runtime authenticator", rt.Dependencies.TaskData, rt.TaskDataAuth != nil)
	}
	status, ok := rt.Dependencies.Diagnostics.Dependency("model_service")
	if !ok || !status.Ready || !status.Configured {
		t.Fatalf("model status = %#v ok=%v, want configured and ready", status, ok)
	}
}

func TestBuildRuntimeNexusInputUsesInjectedTaskDataClientEverywhere(t *testing.T) {
	cfg := realConfig()
	cfg.TaskExecution.InputResolver = config.InputResolverNexus
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	signingClient, identityReader := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	keeper := confirmationKeeperReader{staticKeeperIdentityReader: identityReader}
	taskData := builderclient.NewFakeClient()

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		Keeper:                      keeper,
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		TaskDataClient:              taskData,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.Dependencies.TaskData != taskData {
		t.Fatalf("Dependencies.TaskData = %T, want injected %T", rt.Dependencies.TaskData, taskData)
	}
	resolver, ok := rt.TaskInputResolver.(*NexusTaskInputResolver)
	if !ok {
		t.Fatalf("TaskInputResolver = %T, want *NexusTaskInputResolver", rt.TaskInputResolver)
	}
	if resolver.cfg.TaskData != taskData {
		t.Fatalf("resolver TaskData = %T, want injected %T", resolver.cfg.TaskData, taskData)
	}
	if rt.TaskDataAuth == nil {
		t.Fatal("TaskDataAuth = nil, want runtime-owned current service-key authenticator")
	}
}

type heightOnlyTaskDataKeeper struct{}

func (heightOnlyTaskDataKeeper) ChainHeight(context.Context) (uint64, error) {
	return 200, nil
}

func TestBuildRuntimeNexusInputFailsClosedWithoutServiceKeyReader(t *testing.T) {
	cfg := realConfig()
	cfg.TaskExecution.InputResolver = config.InputResolverNexus
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		Keeper:                      heightOnlyTaskDataKeeper{},
		SigningClient:               incapableSigner{capable: false},
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		TaskDataClient:              builderclient.NewFakeClient(),
	})
	if rt != nil {
		_ = rt.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "read service keys") {
		t.Fatalf("BuildRuntimeWithOptions() error = %v, want missing service-key reader rejection", err)
	}
}

type closeTrackingPublisher struct {
	fakePublisher
	closed bool
}

type controlledReadinessProbe struct {
	healthy atomic.Bool
}

func (p *controlledReadinessProbe) Probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.healthy.Load() {
		return errors.New("dependency unavailable with secret endpoint")
	}
	return nil
}

func (p *closeTrackingPublisher) Close() error {
	p.closed = true
	return nil
}

type closeTrackingSubscriber struct {
	fakeSubscriber
	closed bool
}

func (s *closeTrackingSubscriber) Close() error {
	s.closed = true
	return nil
}

var _ interface{ Close() error } = (*closeTrackingPublisher)(nil)
var _ interface{ Close() error } = (*closeTrackingSubscriber)(nil)
var _ builderclient.Publisher = (*closeTrackingPublisher)(nil)
var _ builderclient.Subscriber = (*closeTrackingSubscriber)(nil)

type daemonModelManagementServer struct {
	cortexv1.UnimplementedModelManagementServiceServer
	healthy   bool
	respError *cortexv1.ModelServiceError
}

func (s *daemonModelManagementServer) Health(context.Context, *cortexv1.HealthRequest) (*cortexv1.HealthResponse, error) {
	return &cortexv1.HealthResponse{ModelServiceId: "daemon-test-model-service", Healthy: s.healthy, Error: s.respError}, nil
}

func newDaemonGRPCTestServer(t *testing.T, endpoint string, service cortexv1.ModelManagementServiceServer) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	cortexv1.RegisterModelManagementServiceServer(server, service)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(modelservice.RegisterGRPCTestDialer(endpoint, func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
}

// incapableSigner stands in for the in-process signer, which cannot build
// Cosmos transactions.
type incapableSigner struct{ capable bool }

func (s incapableSigner) SignDigest(context.Context, signer.DigestRequest) ([]byte, error) {
	return bytes.Repeat([]byte{1}, 64), nil
}

func (s incapableSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, signer.ErrCosmosTxUnsupported
}

func (s incapableSigner) CanSignCosmosTx() bool { return s.capable }

type cosmosCapableTestSigner struct{ *signer.LocalSigner }

func (cosmosCapableTestSigner) CanSignCosmosTx() bool { return true }

func (cosmosCapableTestSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return []byte("signed-test-tx"), nil
}

func readyRuntimeServiceSigner(t *testing.T) (signer.Signer, staticKeeperIdentityReader) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(runtimeTestKeystore), 0o600); err != nil {
		t.Fatalf("write service keystore: %v", err)
	}
	local, err := signer.NewLocalSigner(dir, []byte(runtimeTestKeystorePassword), "trueopen", []signer.KeyRef{{Ref: "service.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	key := local.Keys()[0]
	keeper := readyKeeperIdentityReader()
	keeper.node.CurrentServiceAddress = key.Address
	keeper.node.CurrentServicePubkey = key.CompressedPubkey
	keeper.key.ServiceAddress = key.Address
	keeper.key.ServicePubkey = key.CompressedPubkey
	return cosmosCapableTestSigner{LocalSigner: local}, keeper
}

// A broadcaster whose signer cannot sign must not report that optional direct
// transaction capability as ready.
func TestCosmosTxCapableProbeFailsWhenSignerCannotSign(t *testing.T) {
	reached := false
	next := readinessProbeFunc(func(context.Context) error {
		reached = true
		return nil
	})

	err := cosmosTxCapableProbe(incapableSigner{capable: false}, next).Probe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cannot produce Cosmos transactions") {
		t.Fatalf("Probe() error = %v, want a signing capability failure", err)
	}
	if reached {
		t.Fatalf("Probe consulted the node account query despite an incapable signer")
	}

	if err := cosmosTxCapableProbe(incapableSigner{capable: true}, next).Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v, want the underlying probe to run", err)
	}
	if !reached {
		t.Fatalf("Probe skipped the underlying probe for a capable signer")
	}
}

// cortexd loads only the online service key; operator key material must not be
// present in the daemon configuration.
func TestCheckLocalSignerKeysRequiresServiceKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(runtimeTestKeystore), 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
	local, err := signer.NewLocalSigner(dir, []byte(runtimeTestKeystorePassword), "trueopen",
		[]signer.KeyRef{{Ref: "service.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	cfg := realConfig()
	cfg.LocalIdentity.ServiceKeyRef = "service.json"

	if err := checkLocalSignerKeys(local, cfg); err != nil {
		t.Fatalf("checkLocalSignerKeys() error = %v, want the matching address to pass", err)
	}

	// The configured service key was never loaded.
	missing := cfg
	missing.LocalIdentity.ServiceKeyRef = "absent.json"
	err = checkLocalSignerKeys(local, missing)
	if err == nil || !strings.Contains(err.Error(), "has no service key") {
		t.Fatalf("checkLocalSignerKeys() error = %v, want a missing key failure", err)
	}

	// A remote signer enforces the expected service address itself.
	if err := checkLocalSignerKeys(incapableSigner{capable: true}, cfg); err != nil {
		t.Fatalf("checkLocalSignerKeys() error = %v for a remote signer, want no local check", err)
	}
}

func TestVerifyWorkloadSignerBlocksMissingOrMismatchedServiceKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(runtimeTestKeystore), 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
	local, err := signer.NewLocalSigner(dir, []byte(runtimeTestKeystorePassword), "trueopen",
		[]signer.KeyRef{{Ref: "service.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	loaded, _ := local.AddressFor("service.json")
	binding := chainclient.ServiceKeySnapshot{
		ServiceAddress: loaded, ServicePubkey: local.Keys()[0].CompressedPubkey,
		AuthorizationNonce: chainclient.NewUint64String(1),
	}

	cfg := realConfig()
	cfg.LocalIdentity.ServiceKeyRef = "service.json"

	if err := verifyWorkloadSigner(context.Background(), local, cfg, binding); err != nil {
		t.Fatalf("verifyWorkloadSigner() error = %v, want the matching address to pass", err)
	}

	// Keeper reports a different service address than the key signs as.
	mismatch := binding
	mismatch.ServiceAddress = "trueopen1someoneelse"
	err = verifyWorkloadSigner(context.Background(), local, cfg, mismatch)
	if err == nil || !strings.Contains(err.Error(), "signs as") {
		t.Fatalf("verifyWorkloadSigner() error = %v, want an address mismatch", err)
	}

	// The configured service key was never loaded.
	missing := cfg
	missing.LocalIdentity.ServiceKeyRef = "absent.json"
	err = verifyWorkloadSigner(context.Background(), local, missing, binding)
	if err == nil || !strings.Contains(err.Error(), "has no service key") {
		t.Fatalf("verifyWorkloadSigner() error = %v, want a missing key failure", err)
	}

}

func TestVerifyWorkloadSignerProvesRemoteCurrentServiceKeyPossession(t *testing.T) {
	testSigner, keeper := readyRuntimeServiceSigner(t)
	local := testSigner.(cosmosCapableTestSigner).LocalSigner
	binding := keeper.key
	var corrupt atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sign/digest" {
			http.NotFound(w, r)
			return
		}
		var request signer.DigestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode digest request: %v", err)
		}
		signature, err := local.SignDigest(r.Context(), request)
		if err != nil {
			t.Fatalf("sign readiness digest: %v", err)
		}
		if corrupt.Load() {
			signature[0] ^= 0xff
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"signature": hex.EncodeToString(signature), "signer_address": binding.ServiceAddress,
		})
	}))
	defer server.Close()

	cfg := realConfig()
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	remote := signer.NewClient(signer.ClientConfig{Endpoint: server.URL})
	if err := verifyWorkloadSigner(context.Background(), remote, cfg, binding); err != nil {
		t.Fatalf("verifyWorkloadSigner valid remote proof: %v", err)
	}
	corrupt.Store(true)
	if err := verifyWorkloadSigner(context.Background(), remote, cfg, binding); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("verifyWorkloadSigner corrupt remote proof error = %v", err)
	}
}

func TestRuntimeCachesSignerProofUntilBindingChangesOrRemoteProofExpires(t *testing.T) {
	testSigner, keeper := readyRuntimeServiceSigner(t)
	local := testSigner.(cosmosCapableTestSigner).LocalSigner
	binding := keeper.key
	var calls atomic.Int64
	var corrupt atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request signer.DigestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode digest request: %v", err)
		}
		signature, err := local.SignDigest(r.Context(), request)
		if err != nil {
			t.Fatalf("sign readiness digest: %v", err)
		}
		if corrupt.Load() {
			signature[0] ^= 0xff
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"signature": hex.EncodeToString(signature), "signer_address": binding.ServiceAddress,
		})
	}))
	defer server.Close()

	cfg := realConfig()
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	cfg.Signer.ReadinessProofIntervalMS = 30000
	rt := &Runtime{cfg: cfg, signingClient: signer.NewClient(signer.ClientConfig{Endpoint: server.URL})}
	if err := rt.ensureWorkloadSignerProof(context.Background(), binding); err != nil {
		t.Fatalf("initial proof: %v", err)
	}
	if err := rt.ensureWorkloadSignerProof(context.Background(), binding); err != nil {
		t.Fatalf("cached proof: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("unchanged binding produced %d signatures, want one", got)
	}

	rotated := binding
	rotated.AuthorizationNonce = chainclient.NewUint64String(binding.AuthorizationNonce.Uint64() + 1)
	if err := rt.ensureWorkloadSignerProof(context.Background(), rotated); err != nil {
		t.Fatalf("rotated binding proof: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("binding change produced %d total signatures, want two", got)
	}

	corrupt.Store(true)
	rt.signerProofMu.Lock()
	rt.signerProofValidUntil = time.Now().Add(-time.Second)
	rt.signerProofMu.Unlock()
	if err := rt.ensureWorkloadSignerProof(context.Background(), rotated); err == nil {
		t.Fatal("expired remote proof hid a corrupt signer response")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expired proof produced %d total signatures, want three", got)
	}
}

func TestVerifyWorkloadSignerRejectsUnknownInjectedSigner(t *testing.T) {
	err := verifyWorkloadSigner(context.Background(), incapableSigner{capable: true}, realConfig(), readyKeeperIdentityReader().key)
	if err == nil || !strings.Contains(err.Error(), "unsupported signer implementation") {
		t.Fatalf("verifyWorkloadSigner error = %v, want explicit unknown signer rejection", err)
	}
}

const runtimeTestKeystorePassword = "testpassword"

const runtimeTestKeystore = `{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
    "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
    "kdf": "scrypt",
    "kdfparams": {"dklen": 32, "n": 262144, "p": 8, "r": 1, "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},
    "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
  },
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "version": 3
}`

// The signer check has to be wired into readiness, not merely available: a
// node whose service key is missing or signs as a different address must not
// report ready, because activating the workload commits it to task
// liabilities it cannot settle.
func TestWorkloadReadinessBlocksOnLocalServiceKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.json"), []byte(runtimeTestKeystore), 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
	local, err := signer.NewLocalSigner(dir, []byte(runtimeTestKeystorePassword), "trueopen",
		[]signer.KeyRef{{Ref: "service.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	newRuntime := func(t *testing.T, serviceKeyRef string) *Runtime {
		t.Helper()
		cfg := realConfig()
		cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
		cfg.LocalIdentity.ServiceKeyRef = serviceKeyRef
		healthy := &controlledReadinessProbe{}
		healthy.healthy.Store(true)
		rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
			ModelClient:                modelservice.NewFakeService(),
			NexusPublisher:             fakePublisher{},
			NexusSubscriber:            fakeSubscriber{},
			NexusEnvelopeAuthenticator: runtimeTestEnvelopeAuthenticator(),
			NexusEnvelopeSigner:        runtimeTestEnvelopeSigner(),
			TxClient:                   txclient.NewFake(),
			Keeper:                     readyKeeperIdentityReader(),
			ChainStatus:                staticChainStatusReader{height: 200, chainID: cfg.ChainID},
			NexusReadinessProbe:        healthy,
			TxReadinessProbe:           healthy,
			SigningClient:              local,
		})
		if err != nil {
			t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
		}
		t.Cleanup(func() { _ = rt.Close() })
		return rt
	}

	// The keystore that exists signs as a different address than the Keeper
	// stub reports for this node.
	readiness := newRuntime(t, "service.json").CheckWorkloadReadiness(context.Background())
	if readiness.Ready() {
		t.Fatalf("readiness = %#v, want blocked on a service key address mismatch", readiness)
	}
	if !strings.Contains(readiness.Identity.Error, "signs as") {
		t.Fatalf("Identity.Error = %q, want an address mismatch", readiness.Identity.Error)
	}

	// The configured service key was never loaded at all.
	readiness = newRuntime(t, "absent.json").CheckWorkloadReadiness(context.Background())
	if readiness.Ready() {
		t.Fatalf("readiness = %#v, want blocked on a missing service key", readiness)
	}
	if !strings.Contains(readiness.Identity.Error, "has no service key") {
		t.Fatalf("Identity.Error = %q, want a missing key failure", readiness.Identity.Error)
	}
}

// Staleness used to stop Keeper event consumption, which made recovery from
// downtime impossible. It now gates workload activation instead: a node
// replaying a backlog keeps consuming events but must not take new work, so the
// protection has to actually be in effect here.
func TestChainSyncGatesWorkloadReadinessWhileCatchingUp(t *testing.T) {
	rt := &Runtime{cfg: config.Config{
		Node:   config.NodeConfig{RPCEndpoint: "http://127.0.0.1:26657"},
		Keeper: config.KeeperConfig{MaxLagBlocks: 20},
	}}

	// Before the first poll the lag is unknown, which must not read as synced.
	if status := rt.chainSyncStatus(); status.Ready {
		t.Fatalf("chain_sync = %#v, want not ready until a page has been consumed", status)
	}

	rt.ObserveChainProgress(ChainProgress{CursorHeight: 700, ChainHeight: 1004})
	status := rt.chainSyncStatus()
	if status.Ready {
		t.Fatalf("chain_sync = %#v, want not ready while 304 blocks behind", status)
	}
	if !strings.Contains(status.Error, "304") || !strings.Contains(status.Error, "catching up") {
		t.Fatalf("chain_sync error = %q, want the lag and that it is catching up", status.Error)
	}

	// A readiness snapshot carrying an unready ChainSync must not be Ready even
	// when everything else is.
	readiness := WorkloadReadiness{
		ServiceAddress: "trueopen1service", DependenciesReady: true,
		Identity:     diagnostics.DependencyStatus{Ready: true},
		ModelSupport: diagnostics.DependencyStatus{Ready: true},
		ChainSync:    status,
	}
	if readiness.Ready() {
		t.Fatalf("WorkloadReadiness.Ready() = true while catching up")
	}

	rt.ObserveChainProgress(ChainProgress{CursorHeight: 1002, ChainHeight: 1004})
	readiness.ChainSync = rt.chainSyncStatus()
	if !readiness.ChainSync.Ready || !readiness.Ready() {
		t.Fatalf("readiness = %#v, want ready once caught up", readiness)
	}
}

// Without a configured bound there is nothing to gate on, and the node must not
// be permanently unready.
func TestChainSyncIsReadyWhenNoLagBoundIsConfigured(t *testing.T) {
	rt := &Runtime{cfg: config.Config{Keeper: config.KeeperConfig{MaxLagBlocks: 0}}}
	if status := rt.chainSyncStatus(); !status.Ready {
		t.Fatalf("chain_sync = %#v, want ready when max_lag_blocks is unset", status)
	}
}

// The field case left nothing to look at: /healthz returned 200, every
// dependency read ready, and the log was empty. The cursor and the tip have to
// be legible without opening SQLite, and a refusal must not read as synced even
// when max_lag_blocks is unset and lag reports 0.
func TestChainProgressMakesACursorAboveTheTipVisible(t *testing.T) {
	rt := &Runtime{cfg: config.Config{
		Node:   config.NodeConfig{RPCEndpoint: "http://127.0.0.1:26657"},
		Keeper: config.KeeperConfig{MaxLagBlocks: 0},
	}}

	refusal := &chainclient.CursorAheadOfChainError{
		ChainID: "trueopen-localnet-1", CursorHeight: 33161, ChainHeight: 13134,
	}
	rt.ObserveChainProgress(ChainProgress{CursorHeight: 33161, ChainHeight: 13134, Refusal: refusal})

	status := rt.chainSyncStatus()
	if status.Ready {
		t.Fatalf("chain_sync = %#v, want not ready while the cursor is above the tip", status)
	}
	if !strings.Contains(status.Error, "33161") || !strings.Contains(status.Error, "13134") {
		t.Fatalf("chain_sync error = %q, want both heights", status.Error)
	}

	report := rt.DiagnosticsSnapshot()
	if report.ChainCursorHeight != 33161 || report.ChainTipHeight != 13134 {
		t.Fatalf("diagnostics = %#v, want cursor 33161 and tip 13134 reported", report)
	}
	// Lag is 0 here by design. That is exactly why the two heights and the
	// refusal are published beside it.
	if report.ChainLagBlocks != 0 || report.ChainCursorRefusal == "" {
		t.Fatalf("diagnostics = %#v, want lag 0 alongside an explicit refusal", report)
	}

	// Recovery has to clear it: after the store is replayed the node reports a
	// normal cursor again.
	rt.ObserveChainProgress(ChainProgress{CursorHeight: 13444, ChainHeight: 13444})
	if status := rt.chainSyncStatus(); !status.Ready {
		t.Fatalf("chain_sync = %#v, want ready once the cursor is back under the tip", status)
	}
	if report := rt.DiagnosticsSnapshot(); report.ChainCursorRefusal != "" || report.ChainCursorHeight != 13444 {
		t.Fatalf("diagnostics = %#v, want the refusal cleared", report)
	}
}

// The JetStream durable identity is the operator address alone. Duties used to
// be folded into the prefix, which meant adding or removing a duty renamed
// every durable: the old consumers were orphaned server-side and the new ones
// restarted from DeliverAll, replaying the whole retention window. Duty
// selection is now retired outright, so the only way a durable could still be
// duty-shaped is a prefix built from something other than the operator address.
func TestDurableIdentityIsTheOperatorAddressAlone(t *testing.T) {
	const operator = "trueopen1operator"
	subject := builderclient.NATSWorkerAssignmentSubject("*")

	node := config.Config{LocalIdentity: config.LocalIdentityConfig{OperatorAddress: operator}}
	workerName := builderclient.NATSDurableName(nexusDurablePrefix(node), subject)

	// The old shape must produce a different name, or this test would pass
	// without duties actually having been removed from the identity.
	if legacy := builderclient.NATSDurableName(operator+"-WORKER", subject); legacy == workerName {
		t.Fatalf("durable name %q is insensitive to its prefix", workerName)
	}

	// Different operators must still get different durables.
	other := config.Config{LocalIdentity: config.LocalIdentityConfig{OperatorAddress: "trueopen1other"}}
	if builderclient.NATSDurableName(nexusDurablePrefix(other), subject) == workerName {
		t.Fatalf("durable name %q is shared across operators", workerName)
	}
}

// togglingChainStatusReader flips between serving the configured chain and failing.
type togglingChainStatusReader struct {
	height  uint64
	chainID string
	failing atomic.Bool
}

func (r *togglingChainStatusReader) ChainStatus(context.Context) (uint64, string, error) {
	if r.failing.Load() {
		return 0, "", errors.New("dial tcp 127.0.0.1:26657: connect: connection refused")
	}
	return r.height, r.chainID, nil
}

// chain, keeper and store used to be reported from a startup constant that
// hardcoded readiness. A devnet whose chain had been unreachable for eighteen
// hours still reported `"chain": {"ready": true}`, which is the state that hid the
// outage in #134.
func TestReadinessReportsChainLossInsteadOfStartupConstant(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	signingClient, keeper := readyRuntimeServiceSigner(t)
	chain := &togglingChainStatusReader{height: 200, chainID: cfg.ChainID}

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 chain,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	readiness := rt.CheckWorkloadReadiness(context.Background())
	if !readiness.Chain.Ready || !readiness.Keeper.Ready || !readiness.Store.Ready {
		t.Fatalf("healthy readiness = %#v, want chain, keeper and store ready", readiness)
	}
	if !readiness.DependenciesReady {
		t.Fatalf("healthy readiness = %#v, want dependencies ready", readiness)
	}

	chain.failing.Store(true)
	readiness = rt.CheckWorkloadReadiness(context.Background())
	if readiness.Chain.Ready {
		t.Fatalf("chain status = %#v, want not ready once the endpoint refuses connections", readiness.Chain)
	}
	if readiness.Chain.Error == "" {
		t.Fatalf("chain status = %#v, want the failure explained", readiness.Chain)
	}
	// The workload must stop taking new work, not merely log.
	if readiness.DependenciesReady || readiness.Ready() {
		t.Fatalf("readiness = %#v, want the workload gated while the chain is down", readiness)
	}
	// The same verdict has to reach `cortexctl diagnostics`, which is where an
	// operator looks first.
	status, ok := rt.DiagnosticsSnapshot().Dependency("chain")
	if !ok || status.Ready {
		t.Fatalf("live chain diagnostic = %#v ok=%v, want not ready", status, ok)
	}

	chain.failing.Store(false)
	if readiness = rt.CheckWorkloadReadiness(context.Background()); !readiness.Chain.Ready {
		t.Fatalf("recovered chain status = %#v, want ready", readiness.Chain)
	}
	// A recovered dependency must not keep the explanation of its outage.
	if readiness.Chain.Error != "" {
		t.Fatalf("recovered chain status = %#v, want the outage error cleared", readiness.Chain)
	}
}

// The store probe verifies the database is reachable. An unwritable or corrupt
// file previously looked healthy for as long as the process stayed up.
func TestReadinessReportsStoreLossWhenDatabaseIsClosed(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	signingClient, keeper := readyRuntimeServiceSigner(t)

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if readiness := rt.CheckWorkloadReadiness(context.Background()); !readiness.Store.Ready {
		t.Fatalf("store status = %#v, want ready", readiness.Store)
	}
	if err := rt.Store.Close(); err != nil {
		t.Fatalf("Store.Close() error = %v", err)
	}

	readiness := rt.CheckWorkloadReadiness(context.Background())
	if readiness.Store.Ready || readiness.Store.Error == "" {
		t.Fatalf("store status = %#v, want an explained failure once the database is gone", readiness.Store)
	}
	if readiness.DependenciesReady {
		t.Fatalf("readiness = %#v, want the workload gated without a store", readiness)
	}
}

// A read-only store must fail readiness because the workload cannot durably
// record task state.
func TestReadinessReportsStoreNotReadyWhenReadOnly(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	cfg.LocalIdentity.ServiceKeyRef = "service.json"
	signingClient, keeper := readyRuntimeServiceSigner(t)

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:                 modelservice.NewFakeService(),
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		NexusEnvelopeAuthenticator:  runtimeTestEnvelopeAuthenticator(),
		NexusEnvelopeSigner:         runtimeTestEnvelopeSigner(),
		TxClient:                    txclient.NewFake(),
		Keeper:                      keeper,
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
		ChainStatus:                 staticChainStatusReader{height: 200, chainID: cfg.ChainID},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if readiness := rt.CheckWorkloadReadiness(context.Background()); !readiness.Store.Ready {
		t.Fatalf("store status = %#v, want ready before making read-only", readiness.Store)
	}
	rt.Store.SetReadOnlyForTests()

	readiness := rt.CheckWorkloadReadiness(context.Background())
	if readiness.Store.Ready || readiness.Store.Error == "" {
		t.Fatalf("store status = %#v, want an explained failure once the store is read-only", readiness.Store)
	}
	if readiness.DependenciesReady {
		t.Fatalf("readiness = %#v, want the workload gated without a writable store", readiness)
	}
}

type probingPublisher struct {
	fakePublisher
	probes int
}

func (p *probingPublisher) Probe(context.Context) error {
	p.probes++
	return nil
}

type probingSubscriber struct {
	fakeSubscriber
}

func (probingSubscriber) Probe(context.Context) error { return nil }

// TestBuildRuntimeReportsOutboundPublishesWithoutHidingThePublisherProbe pins
// both halves of the observability seam: the Builder client reports what it
// sends, and the readiness path still holds the raw publisher. Wrapping the
// value the runtime keeps would silently drop the Probe method and, with it,
// the nexus dependency's live readiness check.
func TestBuildRuntimeReportsOutboundPublishesWithoutHidingThePublisherProbe(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
	publisher := &probingPublisher{}
	var completions []builderclient.PublishCompletion

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		ModelClient:     modelservice.NewFakeService(),
		NexusPublisher:  publisher,
		NexusSubscriber: probingSubscriber{},
		Keeper:          missingIdentityKeeper{confirmationKeeperReader: confirmationKeeperReader{staticKeeperIdentityReader: readyKeeperIdentityReader()}},
		KeeperEvents:    emptyKeeperEvents{},
		ChainStatus:     staticChainStatusReader{height: 200, chainID: cfg.ChainID},
		NexusPublishObserver: func(completion builderclient.PublishCompletion) {
			completions = append(completions, completion)
		},
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if err := rt.Dependencies.Builder.Publish(context.Background(), builderclient.PublishRequest{
		Subject: builderclient.NATSVerifierHandraiseSubject("task-1"), TaskID: "task-1",
		Payload: []byte("payload"), DedupID: "dedup-1",
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(completions) != 1 {
		t.Fatalf("completions = %d, want 1", len(completions))
	}

	if rt.nexusProbe == nil {
		t.Fatal("nexus readiness probe = nil; the observer hid the publisher's Probe method")
	}
	before := publisher.probes
	if err := rt.nexusProbe.Probe(context.Background()); err != nil {
		t.Fatalf("nexus probe: %v", err)
	}
	if publisher.probes != before+1 {
		t.Fatalf("publisher probes = %d, want %d: the probe must reach the raw publisher", publisher.probes, before+1)
	}
}

// The Verifier's output confirmer used to require deps.OutputPackages, which is
// populated only under the fake model transport. On a node running a real model
// transport it was therefore always nil, every OPEN_VERIFY was refused with
// "Verifier handraise requires a Nexus output confirmer", no Verifier ever
// raised its hand, and the chain swept the handraise window into
// TASK_FAILURE_CLASS_INSUFFICIENT_VERIFIER. grpc is the transport that regressed
// in the field, so it is the one asserted here.
func TestBuildRuntimeConstructsTheOutputConfirmerWithoutASharedPackageStore(t *testing.T) {
	for _, transport := range []string{"grpc", "local"} {
		t.Run(transport, func(t *testing.T) {
			cfg := realConfig()
			cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
			cfg.ModelManagement.Transport = transport
			cfg.ModelManagement.MaxConcurrency = 4
			if transport == "local" {
				cfg.ModelManagement.Endpoint = "http://127.0.0.1:8000"
			}

			rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
				NexusPublisher:  fakePublisher{},
				NexusSubscriber: fakeSubscriber{},
				TaskDataClient:  builderclient.NewFakeClient(),
				Keeper:          readyKeeperIdentityReader(),
			})
			if err != nil {
				t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
			}
			t.Cleanup(func() { _ = rt.Close() })

			if rt.Dependencies.OutputPackages != nil {
				t.Fatalf("OutputPackages = %T, want none for transport %q -- otherwise this test proves nothing", rt.Dependencies.OutputPackages, transport)
			}
			if rt.OutputConfirmer == nil {
				t.Fatalf("OutputConfirmer = nil for transport %q, want one built without a shared package store", transport)
			}
		})
	}
}
