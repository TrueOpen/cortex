package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/worker"
)

const endpointTestBuilder = "trueopen1builderoperator"

type endpointKeeper struct {
	descriptorErr error
	descriptor    chainclient.ServiceDescriptorSnapshot
	key           chainclient.ServiceKeySnapshot
	keyErr        error
	// noDescriptor models a Builder that has never published one.
	noDescriptor bool
	// committedHeight is the height the application has committed; zero means the
	// default 900. Reads are served from it and pinned to it.
	committedHeight uint64
	// pinned records the heights the pinned sub-reads were issued at.
	pinned []uint64
}

func (k *endpointKeeper) servedHeight() uint64 {
	if k.committedHeight != 0 {
		return k.committedHeight
	}
	return 900
}

func (k *endpointKeeper) CommittedBuilder(context.Context, string) (chainclient.BuilderStateSnapshot, uint64, error) {
	version := chainclient.Uint64String(3)
	if k.noDescriptor {
		version = 0
	}
	return chainclient.BuilderStateSnapshot{
		Address: endpointTestBuilder, CurrentServiceKeyStatus: "ACTIVE",
		RegisteredHeight: chainclient.Uint64String(1), CurrentDescriptorVersion: version,
	}, k.servedHeight(), nil
}

func (k *endpointKeeper) ServiceDescriptor(_ context.Context, _, _ string, height uint64) (chainclient.ServiceDescriptorSnapshot, error) {
	k.pinned = append(k.pinned, height)
	if k.descriptorErr != nil {
		return chainclient.ServiceDescriptorSnapshot{}, k.descriptorErr
	}
	return k.descriptor, nil
}

func (k *endpointKeeper) CurrentServiceKey(_ context.Context, participantType, operatorAddress string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	k.pinned = append(k.pinned, height)
	return k.currentServiceKey(participantType, operatorAddress)
}

// CommittedCurrentServiceKey is the bootstrap path's reader: it serves the key
// and the height it was served at from the same read.
func (k *endpointKeeper) CommittedCurrentServiceKey(_ context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	key, err := k.currentServiceKey(participantType, operatorAddress)
	if err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, err
	}
	return key, k.servedHeight(), nil
}

func (k *endpointKeeper) currentServiceKey(participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, error) {
	if k.keyErr != nil {
		return chainclient.ServiceKeySnapshot{}, k.keyErr
	}
	if participantType != chainclient.ParticipantTypeBuilder {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("unexpected participant type %q", participantType)
	}
	if operatorAddress != k.key.OperatorAddress {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("unexpected operator %q", operatorAddress)
	}
	return k.key, nil
}

func builderServiceKey() chainclient.ServiceKeySnapshot {
	return chainclient.ServiceKeySnapshot{
		ParticipantType:          chainclient.ParticipantTypeBuilder,
		OperatorAddress:          endpointTestBuilder,
		ServiceAddress:           "trueopen1builderservice",
		ServicePubkey:            "02" + strings.Repeat("ab", 32),
		AuthorizationNonce:       chainclient.Uint64String(4),
		CurrentDescriptorVersion: chainclient.Uint64String(3),
		Status:                   "ACTIVE",
	}
}

// endpointDescriptor builds the on-chain descriptor row for one published
// NEXUS_GRPC endpoint, exactly as the Keeper reader would have decoded it.
func endpointDescriptor(t *testing.T, publishedEndpoint string) chainclient.ServiceDescriptorSnapshot {
	t.Helper()
	var hash chainclient.HexHash
	for i := range hash {
		hash[i] = 0xab
	}
	descriptor, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, endpointTestBuilder, 3, hash, 120, 1,
		[]chainclient.ServiceEndpointSnapshot{{
			Kind:            chainclient.EndpointKindNexusGRPC,
			URI:             publishedEndpoint,
			ProtocolVersion: "v1",
		}},
	)
	if err != nil {
		t.Fatalf("build descriptor snapshot: %v", err)
	}
	return descriptor
}

// descriptorBackedEndpoints wires a resolver to a Keeper serving that descriptor
// row, so the authoritative path is exercised end to end.
func descriptorBackedEndpoints(t *testing.T, publishedEndpoint string) *builderEndpoints {
	t.Helper()
	keeper := &endpointKeeper{descriptor: endpointDescriptor(t, publishedEndpoint), key: builderServiceKey()}
	directory, err := builderdirectory.New(keeper, builderdirectory.Options{AllowInsecure: true})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	return newBuilderEndpoints(directory, keeper, "", "", false)
}

func TestBuilderEndpointsPrefersTheOnChainDescriptor(t *testing.T) {
	resolver := descriptorBackedEndpoints(t, "https://nexus.example.org")
	// A configured bootstrap endpoint must not win over the chain view.
	resolver.bootstrapOperator = endpointTestBuilder
	resolver.bootstrapEndpoint = "http://stale.example.org"
	resolver.allowBootstrap = true

	endpoint, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint: %v", err)
	}
	if endpoint.Endpoint != "https://nexus.example.org" || endpoint.Source != BuilderEndpointSourceDescriptor {
		t.Fatalf("endpoint = %+v, want the descriptor-published endpoint", endpoint)
	}
	if endpoint.AuthorizationNonce != 4 || endpoint.DescriptorVersion != 3 || endpoint.ServicePubkey != builderServiceKey().ServicePubkey {
		t.Fatalf("endpoint = %+v", endpoint)
	}
}

func TestBuilderEndpointsFallsBackToTheNamedBootstrapBuilderOnly(t *testing.T) {
	keeper := &endpointKeeper{descriptorErr: fmt.Errorf("no descriptor"), key: builderServiceKey()}
	keeper.key.CurrentDescriptorVersion = 0
	resolver := newBuilderEndpoints(nil, keeper, endpointTestBuilder, "http://127.0.0.1:8080", true)

	endpoint, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint: %v", err)
	}
	if endpoint.Endpoint != "http://127.0.0.1:8080" || endpoint.Source != BuilderEndpointSourceBootstrap {
		t.Fatalf("endpoint = %+v, want the configured bootstrap endpoint", endpoint)
	}
	// The Builder's own service key still comes from chain, so Builder-signed
	// material remains verifiable on the bootstrap path.
	if endpoint.AuthorizationNonce != 4 || endpoint.ServicePubkey != builderServiceKey().ServicePubkey {
		t.Fatalf("endpoint = %+v, want the chain service key", endpoint)
	}

	if _, err := resolver.ResolveBuilderEndpoint(context.Background(), "trueopen1otherbuilder"); err == nil ||
		!strings.Contains(err.Error(), "belongs to another Builder") {
		t.Fatalf("err = %v, want the bootstrap endpoint refused for another Builder", err)
	}
}

// The bootstrap path reports the height its service-key read was served at, and
// applies the revocation check at that height: a key revoked exactly there is
// refused. Previously the height came from a separate /status read that the chain
// could reject outright.
func TestBuilderEndpointsBindsBootstrapToTheServedHeight(t *testing.T) {
	keeper := &endpointKeeper{
		descriptorErr:   fmt.Errorf("no descriptor"),
		key:             builderServiceKey(),
		committedHeight: 4321,
	}
	keeper.key.CurrentDescriptorVersion = 0
	resolver := newBuilderEndpoints(nil, keeper, endpointTestBuilder, "http://127.0.0.1:8080", true)

	endpoint, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint: %v", err)
	}
	if endpoint.SnapshotHeight != 4321 {
		t.Fatalf("SnapshotHeight = %d, want the served height 4321", endpoint.SnapshotHeight)
	}

	revokedAtServedHeight := builderServiceKey()
	revokedAtServedHeight.RevokedHeight = chainclient.Uint64String(4321)
	resolver = newBuilderEndpoints(nil, &endpointKeeper{
		descriptorErr:   fmt.Errorf("no descriptor"),
		key:             revokedAtServedHeight,
		committedHeight: 4321,
	}, endpointTestBuilder, "http://127.0.0.1:8080", true)
	if _, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder); err == nil ||
		!strings.Contains(err.Error(), "revoked at height 4321") {
		t.Fatalf("err = %v, want a key revoked at the served height refused", err)
	}
}

func TestBuilderEndpointsRefusesBootstrapWithoutThePlaintextOptIn(t *testing.T) {
	keeper := &endpointKeeper{key: builderServiceKey()}
	resolver := newBuilderEndpoints(nil, keeper, endpointTestBuilder, "http://127.0.0.1:8080", false)

	_, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err == nil || !strings.Contains(err.Error(), "requires nexus.allow_insecure_descriptor") {
		t.Fatalf("err = %v, want the bootstrap endpoint gated on the explicit opt-in", err)
	}
}

func TestBuilderEndpointsFailsClosedWithNoDescriptorAndNoBootstrap(t *testing.T) {
	keeper := &endpointKeeper{descriptorErr: fmt.Errorf("no descriptor"), key: builderServiceKey()}
	resolver := newBuilderEndpoints(nil, keeper, "", "", true)

	_, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err == nil || !strings.Contains(err.Error(), "no service descriptor and no configured bootstrap endpoint") {
		t.Fatalf("err = %v, want a fail-closed resolution", err)
	}
}

func TestBuilderEndpointsRejectsABootstrapBuilderWithoutAnActiveKey(t *testing.T) {
	key := builderServiceKey()
	key.Status = "REVOKED"
	resolver := newBuilderEndpoints(nil, &endpointKeeper{key: key}, endpointTestBuilder, "http://127.0.0.1:8080", true)

	_, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err == nil || !strings.Contains(err.Error(), "service key status") {
		t.Fatalf("err = %v, want a revoked Builder key to be refused", err)
	}
}

func TestBuilderEndpointsRequiresACanonicalOperator(t *testing.T) {
	resolver := newBuilderEndpoints(nil, &endpointKeeper{key: builderServiceKey()}, endpointTestBuilder, "http://127.0.0.1:8080", true)
	for _, operator := range []string{"", " " + endpointTestBuilder} {
		if _, err := resolver.ResolveBuilderEndpoint(context.Background(), operator); err == nil {
			t.Fatalf("ResolveBuilderEndpoint(%q) error = nil, want a canonical operator requirement", operator)
		}
	}
}

// A descriptor that exists and fails to verify must never be answered with the
// configured endpoint: falling back would discard exactly the check that failed.
// A plaintext endpoint with the gate closed is that case, and it is the refusal
// most likely to tempt an operator into a bootstrap workaround.
func TestBuilderEndpointsRefusesBootstrapWhenADescriptorFailsVerification(t *testing.T) {
	keeper := &endpointKeeper{
		descriptor: endpointDescriptor(t, "http://nexus.devnet.invalid:8080"),
		key:        builderServiceKey(),
	}
	directory, err := builderdirectory.New(keeper, builderdirectory.Options{AllowInsecure: false})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	resolver := newBuilderEndpoints(directory, keeper, endpointTestBuilder, "http://127.0.0.1:8080", true)

	_, err = resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err == nil || !errors.Is(err, builderdirectory.ErrPlaintextEndpoint) {
		t.Fatalf("err = %v, want the descriptor failure to be terminal", err)
	}
}

// A descriptor that publishes no NEXUS_GRPC endpoint is the same class of
// terminal failure: the Builder published something, it just is not a Nexus.
func TestBuilderEndpointsRefusesBootstrapWhenNoNexusEndpointIsPublished(t *testing.T) {
	var hash chainclient.HexHash
	for i := range hash {
		hash[i] = 0xab
	}
	descriptor, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, endpointTestBuilder, 3, hash, 120, 1,
		[]chainclient.ServiceEndpointSnapshot{{
			Kind: chainclient.EndpointKindHealthHTTPS, URI: "https://health.example.org", ProtocolVersion: "v1",
		}},
	)
	if err != nil {
		t.Fatalf("build descriptor snapshot: %v", err)
	}
	keeper := &endpointKeeper{descriptor: descriptor, key: builderServiceKey()}
	directory, err := builderdirectory.New(keeper, builderdirectory.Options{AllowInsecure: true})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	resolver := newBuilderEndpoints(directory, keeper, endpointTestBuilder, "http://127.0.0.1:8080", true)

	_, err = resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err == nil || !strings.Contains(err.Error(), "publishes no NEXUS_GRPC endpoint") {
		t.Fatalf("err = %v, want the missing kind to be terminal", err)
	}
}

// Only a Builder that never published a descriptor may be reached through the
// configured bootstrap endpoint.
func TestBuilderEndpointsAllowsBootstrapOnlyWithoutAnyDescriptor(t *testing.T) {
	keeper := &endpointKeeper{key: builderServiceKey(), noDescriptor: true}
	keeper.key.CurrentDescriptorVersion = 0
	directory, err := builderdirectory.New(keeper, builderdirectory.Options{AllowInsecure: true})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	resolver := newBuilderEndpoints(directory, keeper, endpointTestBuilder, "http://127.0.0.1:8080", true)

	endpoint, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint: %v", err)
	}
	if endpoint.Source != BuilderEndpointSourceBootstrap {
		t.Fatalf("endpoint = %+v, want the bootstrap source", endpoint)
	}
}

func TestBuilderEndpointsRefusesBootstrapWhenCurrentKeyPublishesDescriptor(t *testing.T) {
	keeper := &endpointKeeper{key: builderServiceKey(), noDescriptor: true}
	resolver := newBuilderEndpoints(nil, keeper, endpointTestBuilder, "http://127.0.0.1:8080", true)
	if _, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder); err == nil || !builderclient.IsRetryable(err) || !strings.Contains(err.Error(), "current descriptor") {
		t.Fatalf("published descriptor did not prevent bootstrap fallback: %v", err)
	}
}

// The receiving-Builder provider is the seam the Worker resolves task material
// through, so the per-task Builder authority Node exposes today (the operator
// address on the finalized assignment) is bound here and nowhere else.
func TestReceivingBuildersResolvesTheAssignedBuilder(t *testing.T) {
	resolver := descriptorBackedEndpoints(t, "https://nexus.example.org")
	provider := NewReceivingBuilders(resolver)

	builder, err := provider.ResolveReceivingBuilder(context.Background(), worker.ReceivingBuilderRef{
		SessionID: "session-1", TaskID: "session-1/7", AssignedBuilderOperator: endpointTestBuilder,
	})
	if err != nil {
		t.Fatalf("ResolveReceivingBuilder: %v", err)
	}
	if builder.OperatorAddress != endpointTestBuilder || builder.Endpoint != "https://nexus.example.org" ||
		builder.ServicePubkey != builderServiceKey().ServicePubkey || builder.CurrentHeight != 900 || builder.AuthorizationNonce != 4 {
		t.Fatalf("builder = %+v, want the descriptor identity pinned at the read height", builder)
	}
}

func TestReceivingBuildersRequiresACanonicalAssignedOperator(t *testing.T) {
	resolver := descriptorBackedEndpoints(t, "https://nexus.example.org")
	provider := NewReceivingBuilders(resolver)

	for name, operator := range map[string]string{
		"empty":   "",
		"blank":   "   ",
		"padded":  " " + endpointTestBuilder + " ",
		"trailer": endpointTestBuilder + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := provider.ResolveReceivingBuilder(context.Background(), worker.ReceivingBuilderRef{
				SessionID: "session-1", TaskID: "session-1/7", AssignedBuilderOperator: operator,
			})
			if err == nil || !strings.Contains(err.Error(), "must be canonical") {
				t.Fatalf("err = %v, want a canonical operator requirement", err)
			}
		})
	}
}

// An unknown Builder has no descriptor and no bootstrap entitlement, so the
// provider fails closed instead of handing back an unverified endpoint.
func TestReceivingBuildersFailsClosedForAnUnknownBuilder(t *testing.T) {
	keeper := &endpointKeeper{descriptorErr: fmt.Errorf("no descriptor"), key: builderServiceKey()}
	provider := NewReceivingBuilders(newBuilderEndpoints(nil, keeper, "", "", true))

	_, err := provider.ResolveReceivingBuilder(context.Background(), worker.ReceivingBuilderRef{
		SessionID: "session-1", TaskID: "session-1/7", AssignedBuilderOperator: "trueopen1unknownbuilder",
	})
	if err == nil || !strings.Contains(err.Error(), "no service descriptor and no configured bootstrap endpoint") {
		t.Fatalf("err = %v, want a fail-closed resolution", err)
	}
}

// A resolver that answers with another Builder's identity is refused: the Worker
// must never authenticate one Builder's material against another's key.
func TestReceivingBuildersRefusesAMismatchedResolvedIdentity(t *testing.T) {
	provider := NewReceivingBuilders(misdirectedEndpoints{endpoint: BuilderEndpoint{
		OperatorAddress: "trueopen1otherbuilder", Endpoint: "https://other.example",
		ServicePubkey: builderServiceKey().ServicePubkey, SnapshotHeight: 900, AuthorizationNonce: 4,
	}})

	_, err := provider.ResolveReceivingBuilder(context.Background(), worker.ReceivingBuilderRef{
		SessionID: "session-1", TaskID: "session-1/7", AssignedBuilderOperator: endpointTestBuilder,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match the assigned Builder") {
		t.Fatalf("err = %v, want a mismatched Builder identity refused", err)
	}
}

// misdirectedEndpoints answers every request with one fixed identity, modelling a
// resolver that returns a Builder other than the one asked for.
type misdirectedEndpoints struct {
	endpoint BuilderEndpoint
}

func (m misdirectedEndpoints) ResolveBuilderEndpoint(context.Context, string) (BuilderEndpoint, error) {
	return m.endpoint, nil
}

// A daemon with no endpoint resolver yields no provider, so the Worker fails
// closed rather than relaying to an unverified Builder.
func TestNewReceivingBuildersWithoutAResolverYieldsNoProvider(t *testing.T) {
	if provider := NewReceivingBuilders(nil); provider != nil {
		t.Fatalf("provider = %#v, want no provider without an endpoint resolver", provider)
	}
}

// recordingEndpoints records which operators were asked and returns an endpoint per
// operator.
type recordingEndpoints struct {
	asked     []string
	endpoints map[string]BuilderEndpoint
	errs      map[string]error
}

func (r *recordingEndpoints) ResolveBuilderEndpoint(_ context.Context, operator string) (BuilderEndpoint, error) {
	r.asked = append(r.asked, operator)
	if err := r.errs[operator]; err != nil {
		return BuilderEndpoint{}, err
	}
	endpoint, ok := r.endpoints[operator]
	if !ok {
		return BuilderEndpoint{}, fmt.Errorf("no descriptor for %s", operator)
	}
	endpoint.OperatorAddress = operator
	return endpoint, nil
}

// With nexus.builder_operator_address configured only that one is asked, even when
// the set has other members: config may only narrow the range this node accepts.
func TestNATSSentinelIngressNarrowsToTheConfiguredBuilder(t *testing.T) {
	endpoints := &recordingEndpoints{endpoints: map[string]BuilderEndpoint{
		endpointTestBuilder: {Endpoint: "https://nexus.example:8080", TLSPubkeyHash: strings.Repeat("ab", 32)},
		"trueopen1second":   {Endpoint: "https://second.example:8080"},
	}}
	members := testMembership(t, endpointTestBuilder, "trueopen1second")
	resolver := natsSentinelIngress{
		operator:  endpointTestBuilder,
		members:   func() *builderdirectory.Membership { return members },
		endpoints: func() BuilderEndpointResolver { return endpoints },
	}
	candidates, err := resolver.ResolveIngresses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Operator != endpointTestBuilder ||
		candidates[0].Endpoint != "https://nexus.example:8080" || candidates[0].TLSPubkeyHash != strings.Repeat("ab", 32) {
		t.Fatalf("candidates = %+v, want only the configured Builder", candidates)
	}
	if len(endpoints.asked) != 1 || endpoints.asked[0] != endpointTestBuilder {
		t.Fatalf("asked = %v, want only the configured Builder", endpoints.asked)
	}
}

// With no operator configured the candidates are every member of the active on-chain
// BuilderSet, in set order.
func TestNATSSentinelIngressOffersEveryBuilderSetMember(t *testing.T) {
	endpoints := &recordingEndpoints{endpoints: map[string]BuilderEndpoint{
		endpointTestBuilder: {Endpoint: "https://first.example:8080"},
		"trueopen1second":   {Endpoint: "https://second.example:8080"},
	}}
	members := testMembership(t, endpointTestBuilder, "trueopen1second")
	resolver := natsSentinelIngress{
		members:   func() *builderdirectory.Membership { return members },
		endpoints: func() BuilderEndpointResolver { return endpoints },
	}
	candidates, err := resolver.ResolveIngresses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].Operator != endpointTestBuilder || candidates[1].Operator != "trueopen1second" {
		t.Fatalf("candidates = %+v, want both members in BuilderSet order", candidates)
	}
}

// The first member is an unusable plaintext endpoint (exactly what the genesis
// descriptor looks like in integration): it eliminates only itself, its reason stays
// in Err, and the later members become candidates as usual.
func TestNATSSentinelIngressKeepsGoingPastAnUnusableBuilder(t *testing.T) {
	endpoints := &recordingEndpoints{
		endpoints: map[string]BuilderEndpoint{
			endpointTestBuilder: {Endpoint: "grpc://127.0.0.1:8081"},
			"trueopen1second":   {Endpoint: "https://second.example:8080"},
		},
		errs: map[string]error{"trueopen1third": errors.New("no current descriptor")},
	}
	members := testMembership(t, endpointTestBuilder, "trueopen1second", "trueopen1third")
	resolver := natsSentinelIngress{
		members:   func() *builderdirectory.Membership { return members },
		endpoints: func() BuilderEndpointResolver { return endpoints },
	}
	candidates, err := resolver.ResolveIngresses(context.Background())
	if err != nil {
		t.Fatalf("an unusable member must not fail the whole lookup: %v", err)
	}
	if len(candidates) != 3 {
		t.Fatalf("candidates = %+v, want one per member", candidates)
	}
	if candidates[0].Err == nil || !strings.Contains(candidates[0].Err.Error(), "allow_insecure_descriptor") {
		t.Fatalf("plaintext member = %+v, want the plaintext gate as its reason", candidates[0])
	}
	if candidates[1].Err != nil || candidates[1].Endpoint != "https://second.example:8080" {
		t.Fatalf("working member = %+v", candidates[1])
	}
	if candidates[2].Err == nil || !strings.Contains(candidates[2].Err.Error(), "no current descriptor") {
		t.Fatalf("unresolvable member = %+v, want the resolution failure as its reason", candidates[2])
	}
}

// A plaintext endpoint is a usable candidate once allow_insecure_descriptor is given.
func TestNATSSentinelIngressAcceptsPlaintextWithTheOptIn(t *testing.T) {
	endpoints := &recordingEndpoints{endpoints: map[string]BuilderEndpoint{
		endpointTestBuilder: {Endpoint: "grpc://127.0.0.1:8081"},
	}}
	resolver := natsSentinelIngress{
		operator:  endpointTestBuilder,
		members:   func() *builderdirectory.Membership { return nil },
		endpoints: func() BuilderEndpointResolver { return endpoints },
		transport: builderclient.TaskDataTransport{AllowInsecureEndpoint: true},
	}
	candidates, err := resolver.ResolveIngresses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Err != nil || candidates[0].Endpoint != "http://127.0.0.1:8081" {
		t.Fatalf("candidates = %+v", candidates)
	}
}

// Neither an operator configured nor a readable BuilderSet: there are no candidates
// to give, and it has to say so.
func TestNATSSentinelIngressRequiresABuilderSource(t *testing.T) {
	resolver := natsSentinelIngress{
		members:   func() *builderdirectory.Membership { return nil },
		endpoints: func() BuilderEndpointResolver { return &recordingEndpoints{} },
	}
	if _, err := resolver.ResolveIngresses(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "builder_operator_address") {
		t.Fatalf("err = %v, want the missing Builder source named", err)
	}
}

func testMembership(t *testing.T, builders ...string) *builderdirectory.Membership {
	t.Helper()
	members, err := builderdirectory.NewMembership(staticBuilderSet{builders: builders}, builderdirectory.MembershipOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return members
}

// staticBuilderSet is a fixed active BuilderSet.
type staticBuilderSet struct {
	builders []string
}

func (s staticBuilderSet) CommittedBuilderSet(context.Context) (chainclient.BuilderSetSnapshot, uint64, error) {
	return chainclient.BuilderSetSnapshot{
		BuilderSetVersion: chainclient.Uint64String(1),
		BuilderSetID:      "set-1",
		SetHash:           chainclient.HexHash{0x11},
		EffectiveHeight:   chainclient.Uint64String(10),
		Builders:          s.builders,
		SnapshotHeight:    chainclient.Uint64String(100),
	}, 100, nil
}
