package daemon

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
)

const descriptorTestOperator = "trueopen1builderoperator"

type descriptorKeeper struct {
	height     uint64
	descriptor chainclient.ServiceDescriptorSnapshot
}

// ChainHeight answers the runtime's Keeper liveness probe. It is deliberately not
// what any read is pinned to.
func (k *descriptorKeeper) ChainHeight(context.Context) (uint64, error) { return k.height, nil }

func (k *descriptorKeeper) CommittedBuilder(context.Context, string) (chainclient.BuilderStateSnapshot, uint64, error) {
	return chainclient.BuilderStateSnapshot{
		Address:                  descriptorTestOperator,
		CurrentServiceKeyStatus:  "ACTIVE",
		RegisteredHeight:         chainclient.Uint64String(10),
		CurrentDescriptorVersion: chainclient.Uint64String(4),
	}, k.height, nil
}

func (k *descriptorKeeper) ServiceDescriptor(context.Context, string, string, uint64) (chainclient.ServiceDescriptorSnapshot, error) {
	return k.descriptor, nil
}

// descriptorTestBuilderPubkey is a real point on secp256k1 whose derived
// address is descriptorTestBuilderService. The pair has to be genuine now that
// every real-mode runtime builds a task-data authenticator, which refuses a key
// that does not derive its own service address.
const (
	descriptorTestBuilderPubkey = "02" + "2222222222222222222222222222222222222222222222222222222222222222"
	descriptorTestBuilderSvc    = "trueopen1gdm6ttxkdhzukec53gjgrrg728apsw7j73xf2q"
)

// CurrentServiceKey answers per participant type. The Cortex node key is this
// node's own identity, which the task-data authenticator resolves at startup;
// the Builder key is the peer's, which descriptor verification resolves.
// Serving one key for both made the Cortex-side lookup return a Builder key.
func (k *descriptorKeeper) CurrentServiceKey(_ context.Context, participantType, _ string, _ uint64) (chainclient.ServiceKeySnapshot, error) {
	if participantType == chainclient.ParticipantTypeCortexNode {
		return chainclient.ServiceKeySnapshot{
			ParticipantType:    chainclient.ParticipantTypeCortexNode,
			OperatorAddress:    "trueopen1operator",
			ServiceAddress:     readyServiceAddress,
			ServicePubkey:      readyServicePubkey,
			AuthorizationNonce: chainclient.Uint64String(1),
			Status:             "ACTIVE",
		}, nil
	}
	return chainclient.ServiceKeySnapshot{
		ParticipantType:          chainclient.ParticipantTypeBuilder,
		OperatorAddress:          descriptorTestOperator,
		ServiceAddress:           descriptorTestBuilderSvc,
		ServicePubkey:            descriptorTestBuilderPubkey,
		CurrentDescriptorVersion: chainclient.NewUint64String(4),
		AuthorizationNonce:       chainclient.Uint64String(2),
		Status:                   "ACTIVE",
	}, nil
}

// CommittedCurrentServiceKey serves the key and the height it came from together,
// which is what the bootstrap endpoint path and the task-data authenticator use.
func (k *descriptorKeeper) CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	key, err := k.CurrentServiceKey(ctx, participantType, operatorAddress, k.height)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, err
	}
	return key, k.height, nil
}

// CommittedBuilderSet is the chain's membership authority. The stub keeps the
// envelope test Builder in the set so runtime construction reflects a live
// network rather than an empty one.
func (k *descriptorKeeper) CommittedBuilderSet(context.Context) (chainclient.BuilderSetSnapshot, uint64, error) {
	return chainclient.BuilderSetSnapshot{
		BuilderSetVersion: chainclient.Uint64String(7),
		BuilderSetID:      "builder-set-7",
		SetHash:           descriptorTestHashValue(),
		Builders:          []string{descriptorTestOperator},
		SnapshotHeight:    chainclient.Uint64String(k.height),
	}, k.height, nil
}

func descriptorTestHashValue() chainclient.HexHash {
	var hash chainclient.HexHash
	for i := range hash {
		hash[i] = 0x5a
	}
	return hash
}

// serviceKeyOnlyKeeper can read service keys but not the current BuilderSet, so
// it has no way to authorize a sender. It forwards explicitly rather than
// embedding: embedding descriptorKeeper would inherit CommittedBuilderSet and
// satisfy the very interface this stub exists to lack.
type serviceKeyOnlyKeeper struct {
	inner *descriptorKeeper
}

func (k serviceKeyOnlyKeeper) ChainHeight(ctx context.Context) (uint64, error) {
	return k.inner.ChainHeight(ctx)
}

func (k serviceKeyOnlyKeeper) CommittedBuilder(ctx context.Context, operator string) (chainclient.BuilderStateSnapshot, uint64, error) {
	return k.inner.CommittedBuilder(ctx, operator)
}

func (k serviceKeyOnlyKeeper) ServiceDescriptor(ctx context.Context, participantType, operator string, height uint64) (chainclient.ServiceDescriptorSnapshot, error) {
	return k.inner.ServiceDescriptor(ctx, participantType, operator, height)
}

func (k serviceKeyOnlyKeeper) CurrentServiceKey(ctx context.Context, participantType, operator string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	return k.inner.CurrentServiceKey(ctx, participantType, operator, height)
}

func (k serviceKeyOnlyKeeper) CommittedCurrentServiceKey(ctx context.Context, participantType, operator string) (chainclient.ServiceKeySnapshot, uint64, error) {
	return k.inner.CommittedCurrentServiceKey(ctx, participantType, operator)
}

func descriptorTestHash(t *testing.T, repeated string) chainclient.HexHash {
	t.Helper()
	decoded, err := hex.DecodeString(strings.Repeat(repeated, 32))
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode hash: %v", err)
	}
	var hash chainclient.HexHash
	copy(hash[:], decoded)
	return hash
}

// descriptorRow builds the on-chain descriptor row the Keeper reader would have
// produced for one published NEXUS_GRPC endpoint.
func descriptorRow(t *testing.T, endpoint string) chainclient.ServiceDescriptorSnapshot {
	t.Helper()
	descriptor, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, descriptorTestOperator, 4, descriptorTestHash(t, "cd"), 120, 1,
		[]chainclient.ServiceEndpointSnapshot{{
			Kind:            chainclient.EndpointKindNexusGRPC,
			URI:             endpoint,
			ProtocolVersion: "v1",
		}},
	)
	if err != nil {
		t.Fatalf("build descriptor snapshot: %v", err)
	}
	return descriptor
}

func newDescriptorRuntime(t *testing.T, committedEndpoint, configuredIngress string) (*Runtime, *descriptorKeeper) {
	t.Helper()
	keeper := &descriptorKeeper{height: 900, descriptor: descriptorRow(t, committedEndpoint)}
	resolver, err := builderdirectory.New(keeper, builderdirectory.Options{})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	// The chain recognises the configured Builder, so these tests are about the
	// descriptor rather than about membership.
	members, err := builderdirectory.NewMembership(keeper, builderdirectory.MembershipOptions{})
	if err != nil {
		t.Fatalf("builderdirectory.NewMembership: %v", err)
	}
	cfg := config.Config{
		Mode: config.ModeReal,
		Nexus: config.NexusConfig{
			IngressURL:             configuredIngress,
			BuilderOperatorAddress: descriptorTestOperator,
		},
	}
	return &Runtime{cfg: cfg, builderDirectory: resolver, builderMembers: members}, keeper
}

func TestBuilderDescriptorReadinessAcceptsTheCommittedEndpoint(t *testing.T) {
	runtime, _ := newDescriptorRuntime(t, "https://nexus.devnet.invalid:8080", "https://nexus.devnet.invalid:8080")

	status := runtime.checkBuilderDescriptorReadiness(context.Background())

	if !status.Ready || status.Error != "" {
		t.Fatalf("status = %+v, want ready", status)
	}
	if status.Endpoint != "https://nexus.devnet.invalid:8080" {
		t.Fatalf("status endpoint = %q, want the descriptor-published endpoint", status.Endpoint)
	}
}

func TestBuilderDescriptorReadinessHoldsWorkloadDownOnBootstrapConflict(t *testing.T) {
	runtime, _ := newDescriptorRuntime(t, "https://nexus.devnet.invalid:8080", "https://nexus.other.invalid:8080")

	status := runtime.checkBuilderDescriptorReadiness(context.Background())

	if status.Ready {
		t.Fatalf("status = %+v, want the conflicting bootstrap endpoint to fail closed", status)
	}
	if !strings.Contains(status.Error, "is not the NEXUS_GRPC endpoint") {
		t.Fatalf("status error = %q, want a descriptor endpoint conflict", status.Error)
	}
	if status.Endpoint != descriptorTestOperator {
		t.Fatalf("status endpoint = %q, want the operator under verification", status.Endpoint)
	}
}

// The chain view is byte-exact now that the endpoint comes straight out of
// consensus state: a configured ingress that differs only in a trailing slash is
// not the string the descriptor publishes, and the old resolver's normalisation
// would have accepted it.
func TestBuilderDescriptorReadinessRefusesANormalisedIngress(t *testing.T) {
	runtime, _ := newDescriptorRuntime(t, "https://nexus.devnet.invalid:8080", "https://nexus.devnet.invalid:8080/")

	status := runtime.checkBuilderDescriptorReadiness(context.Background())

	if status.Ready {
		t.Fatalf("status = %+v, want a byte-inexact ingress to fail closed", status)
	}
}

func TestBuilderDescriptorReadinessStaysUnconfiguredWithoutAnOperator(t *testing.T) {
	runtime := &Runtime{cfg: config.Config{Mode: config.ModeReal, Nexus: config.NexusConfig{IngressURL: "https://nexus.example.org"}}}

	status := runtime.checkBuilderDescriptorReadiness(context.Background())

	if !status.Ready || status.Configured {
		t.Fatalf("status = %+v, want ready and unconfigured when verification is not requested", status)
	}
}

func TestBuilderDescriptorReadinessFailsClosedWithoutAResolver(t *testing.T) {
	runtime := &Runtime{cfg: config.Config{
		Mode:  config.ModeReal,
		Nexus: config.NexusConfig{IngressURL: "https://nexus.example.org", BuilderOperatorAddress: descriptorTestOperator},
	}}

	status := runtime.checkBuilderDescriptorReadiness(context.Background())

	if status.Ready || !strings.Contains(status.Error, "resolver is unavailable") {
		t.Fatalf("status = %+v, want a fail-closed resolver error", status)
	}
}

// The descriptor row must be the version the Builder's own row calls current.
func TestBuilderDescriptorReadinessRejectsASupersededDescriptor(t *testing.T) {
	runtime, keeper := newDescriptorRuntime(t, "https://nexus.devnet.invalid:8080", "https://nexus.devnet.invalid:8080")
	superseded, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, descriptorTestOperator, 3, descriptorTestHash(t, "cd"), 120, 1,
		[]chainclient.ServiceEndpointSnapshot{{
			Kind: chainclient.EndpointKindNexusGRPC, URI: "https://nexus.devnet.invalid:8080", ProtocolVersion: "v1",
		}},
	)
	if err != nil {
		t.Fatalf("build descriptor snapshot: %v", err)
	}
	keeper.descriptor = superseded

	status := runtime.checkBuilderDescriptorReadiness(context.Background())

	if status.Ready {
		t.Fatalf("status = %+v, want fail-closed on a superseded descriptor version", status)
	}
	if !strings.Contains(status.Error, "is not the current version 4") {
		t.Fatalf("status error = %q", status.Error)
	}
}

// The wired daemon must reach the same verdict as the isolated probe: a real-mode
// runtime whose configured ingress is not the endpoint the Builder descriptor
// publishes keeps builder_descriptor unready, so the workload never activates.
func TestBuildRuntimeRealModeVerifiesTheBuilderDescriptor(t *testing.T) {
	keeper := &descriptorKeeper{height: 900, descriptor: descriptorRow(t, "https://nexus.devnet.invalid:8080")}

	for _, testCase := range []struct {
		name        string
		ingress     string
		wantReady   bool
		wantMessage string
	}{
		{name: "committed", ingress: "https://nexus.devnet.invalid:8080", wantReady: true},
		{name: "conflicting", ingress: "https://nexus.other.invalid:8080", wantMessage: "is not the NEXUS_GRPC endpoint"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := realConfig()
			cfg.Store.Path = filepath.Join(t.TempDir(), "cortex.kv")
			cfg.ModelManagement.Transport = "local"
			cfg.ModelManagement.ManifestDir = t.TempDir()
			cfg.ModelManagement.Endpoint = ""
			cfg.ModelManagement.MaxConcurrency = 1
			cfg.Nexus.IngressURL = testCase.ingress
			cfg.Nexus.BuilderOperatorAddress = descriptorTestOperator

			resolver, err := builderdirectory.New(keeper, builderdirectory.Options{})
			if err != nil {
				t.Fatalf("builderdirectory.New: %v", err)
			}
			rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
				Keeper:           keeper,
				BuilderDirectory: resolver,
				NexusPublisher:   fakePublisher{},
				NexusSubscriber:  fakeSubscriber{},
			})
			if err != nil {
				t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
			}
			t.Cleanup(func() {
				if err := rt.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			})

			status, ok := rt.Dependencies.Diagnostics.Dependency("builder_descriptor")
			if !ok {
				t.Fatalf("missing builder_descriptor diagnostic")
			}
			if status.Ready != testCase.wantReady {
				t.Fatalf("builder_descriptor status = %+v, want ready=%v", status, testCase.wantReady)
			}
			if testCase.wantMessage != "" && !strings.Contains(status.Error, testCase.wantMessage) {
				t.Fatalf("builder_descriptor error = %q, want %q", status.Error, testCase.wantMessage)
			}
		})
	}
}
