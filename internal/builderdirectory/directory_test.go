package builderdirectory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
)

const testOperator = "trueopen1builder"

type stubKeeper struct {
	// height is the height the application has committed, so it is what
	// CommittedBuilder serves the Builder state from and what every later read in
	// the resolution must be pinned to.
	height      uint64
	builder     chainclient.BuilderStateSnapshot
	descriptor  chainclient.ServiceDescriptorSnapshot
	serviceKey  chainclient.ServiceKeySnapshot
	heights     []uint64
	builderErr  error
	descriptErr error
	keyErr      error
	// block, when non-nil, holds every resolution at its first read until the
	// channel is closed. It exists so a test can have many callers in flight at
	// once and observe how many of them reach the chain.
	block chan struct{}
	// entered reports that a resolution has actually reached the chain and is
	// parked on block. A test that needs a second caller to be a waiter rather
	// than a second leader has to wait for this rather than assume goroutine
	// ordering.
	entered chan struct{}
	mu      sync.Mutex
}

func (k *stubKeeper) CommittedBuilder(_ context.Context, address string) (chainclient.BuilderStateSnapshot, uint64, error) {
	if k.entered != nil {
		select {
		case k.entered <- struct{}{}:
		default:
		}
	}
	if k.block != nil {
		<-k.block
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.builderErr != nil {
		return chainclient.BuilderStateSnapshot{}, 0, k.builderErr
	}
	if address != testOperator {
		return chainclient.BuilderStateSnapshot{}, 0, fmt.Errorf("unexpected builder %q", address)
	}
	k.heights = append(k.heights, k.height)
	return k.builder, k.height, nil
}

func (k *stubKeeper) ServiceDescriptor(_ context.Context, participantType, operator string, height uint64) (chainclient.ServiceDescriptorSnapshot, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.heights = append(k.heights, height)
	if height == 0 {
		return chainclient.ServiceDescriptorSnapshot{}, fmt.Errorf("descriptor read was not pinned to a height")
	}
	if k.descriptErr != nil {
		return chainclient.ServiceDescriptorSnapshot{}, k.descriptErr
	}
	if participantType != chainclient.ParticipantTypeBuilder || operator != testOperator {
		return chainclient.ServiceDescriptorSnapshot{}, fmt.Errorf("unexpected descriptor query %s/%s", participantType, operator)
	}
	return k.descriptor, nil
}

func (k *stubKeeper) CurrentServiceKey(_ context.Context, participantType, operator string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.heights = append(k.heights, height)
	if height == 0 {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("service key read was not pinned to a height")
	}
	if k.keyErr != nil {
		return chainclient.ServiceKeySnapshot{}, k.keyErr
	}
	if participantType != chainclient.ParticipantTypeBuilder || operator != testOperator {
		return chainclient.ServiceKeySnapshot{}, fmt.Errorf("unexpected service key query %s/%s", participantType, operator)
	}
	return k.serviceKey, nil
}

func mustHexHash(t *testing.T, value string) chainclient.HexHash {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("parse hex hash %q: %v", value, err)
	}
	var hash chainclient.HexHash
	copy(hash[:], decoded)
	return hash
}

func testDescriptorHash(t *testing.T) chainclient.HexHash {
	t.Helper()
	return mustHexHash(t, strings.Repeat("11", 32))
}

func nexusEndpoint(uri string) chainclient.ServiceEndpointSnapshot {
	return chainclient.ServiceEndpointSnapshot{
		Kind:            chainclient.EndpointKindNexusGRPC,
		URI:             uri,
		ProtocolVersion: "v1",
	}
}

// descriptorWith builds the snapshot the Keeper reader would have produced. It
// goes through the exported constructor on purpose: the endpoint index is
// unexported, so a test cannot assemble a descriptor the reader would refuse.
func descriptorWith(t *testing.T, endpoints ...chainclient.ServiceEndpointSnapshot) chainclient.ServiceDescriptorSnapshot {
	t.Helper()
	descriptor, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, testOperator, 7, testDescriptorHash(t), 120,
		uint32(len(endpoints)), endpoints,
	)
	if err != nil {
		t.Fatalf("build descriptor snapshot: %v", err)
	}
	return descriptor
}

func newFixture(t *testing.T, endpoint chainclient.ServiceEndpointSnapshot, opts Options) (*Resolver, *stubKeeper) {
	t.Helper()
	keeper := &stubKeeper{
		height: 500,
		builder: chainclient.BuilderStateSnapshot{
			Address:                  testOperator,
			CurrentServiceKeyStatus:  "ACTIVE",
			RegisteredHeight:         chainclient.Uint64String(10),
			CurrentDescriptorVersion: chainclient.Uint64String(7),
		},
		descriptor: descriptorWith(t, endpoint),
		serviceKey: chainclient.ServiceKeySnapshot{
			ParticipantType:          chainclient.ParticipantTypeBuilder,
			OperatorAddress:          testOperator,
			ServiceAddress:           "trueopen1builderservice",
			ServicePubkey:            "02" + strings.Repeat("ab", 32),
			AuthorizationNonce:       chainclient.Uint64String(3),
			Status:                   "ACTIVE",
			CurrentDescriptorVersion: chainclient.Uint64String(7),
		},
	}
	resolver, err := New(keeper, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return resolver, keeper
}

func TestResolveReturnsTheOnChainNexusEndpointFromOnePinnedHeight(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org:8443"), Options{})

	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.Endpoint != "https://nexus.example.org:8443" {
		t.Fatalf("endpoint = %q", identity.Endpoint)
	}
	if identity.EndpointProtocolVersion != "v1" {
		t.Fatalf("protocol version = %q", identity.EndpointProtocolVersion)
	}
	if identity.SnapshotHeight != 500 || identity.DescriptorVersion != 7 {
		t.Fatalf("identity = %+v", identity)
	}
	if identity.AuthorizationNonce != 3 || identity.ServicePubkey != keeper.serviceKey.ServicePubkey {
		t.Fatalf("identity = %+v", identity)
	}
	if len(keeper.heights) != 3 {
		t.Fatalf("chain reads = %v, want three pinned reads", keeper.heights)
	}
	for _, height := range keeper.heights {
		if height != 500 {
			t.Fatalf("chain reads = %v, want every read pinned to height 500", keeper.heights)
		}
	}
}

// The height a resolution runs at is the one Keeper served the Builder state
// from, and SnapshotHeight reports exactly that. A resolver that obtained its
// height from a separate liveness read would show a different value here, and the
// stub refuses any sub-read that arrives unpinned.
func TestResolvePinsEveryReadToTheHeightBuilderStateWasServedAt(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	keeper.height = 4321

	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.SnapshotHeight != 4321 {
		t.Fatalf("SnapshotHeight = %d, want the served height 4321", identity.SnapshotHeight)
	}
	if len(keeper.heights) != 3 {
		t.Fatalf("chain reads = %v, want Builder, descriptor, and service key", keeper.heights)
	}
	for _, height := range keeper.heights {
		if height != 4321 {
			t.Fatalf("chain reads = %v, want every read at the served height 4321", keeper.heights)
		}
	}
}

// The endpoint is selected by naming NEXUS_GRPC. A descriptor that publishes the
// object gateway and the health probe but no Nexus must refuse, not fall through
// to whichever endpoint happens to be first.
//
// This is also the test that kills an `endpoints[0]` fallback, and it is the only
// one that can be: OBJECT_GATEWAY_HTTPS is first here, so a positional selection
// would resolve successfully to the gateway instead of refusing. A descriptor
// whose Nexus endpoint sits at a non-zero index does not exist to test against -
// see the note on TestResolveSelectsTheNexusEndpointAmongOtherKinds.
func TestResolveRefusesADescriptorWithoutANexusEndpoint(t *testing.T) {
	gateway := chainclient.ServiceEndpointSnapshot{
		Kind:            chainclient.EndpointKindObjectGatewayHTTPS,
		URI:             "https://gateway.example.org",
		ProtocolVersion: "v1",
	}
	health := chainclient.ServiceEndpointSnapshot{
		Kind:            chainclient.EndpointKindHealthHTTPS,
		URI:             "https://health.example.org",
		ProtocolVersion: "v1",
	}
	resolver, keeper := newFixture(t, gateway, Options{})
	keeper.descriptor = descriptorWith(t, gateway, health)

	_, err := resolver.Resolve(context.Background(), testOperator)
	if err == nil || !strings.Contains(err.Error(), "publishes no NEXUS_GRPC endpoint") {
		t.Fatalf("err = %v, want a refusal naming the missing kind", err)
	}
	// The refusal must not be answerable by retrying.
	if builderclient.IsRetryable(err) {
		t.Fatalf("missing kind must be permanent: %v", err)
	}
}

// A descriptor that publishes other kinds alongside NEXUS_GRPC resolves to the
// Nexus endpoint's own uri and protocol version, never a neighbouring kind's -
// the gateway here carries a deliberately different protocol_version so a value
// taken from the wrong endpoint shows up.
//
// What this test does NOT do is vary the Nexus endpoint's position in the list,
// despite being the obvious place to: NewServiceDescriptorSnapshot requires
// ascending kind order and SERVICE_ENDPOINT_KIND_NEXUS_GRPC = 1 is the smallest
// kind consensus admits (TrueOpen/node d8792e6
// proto/hub/v1/participant_identity.proto:11-20), so in every descriptor
// that has one, the Nexus endpoint is entry zero. The `[0]`-fallback property is
// pinned by TestResolveRefusesADescriptorWithoutANexusEndpoint, which is the
// only shape that can distinguish it.
func TestResolveSelectsTheNexusEndpointAmongOtherKinds(t *testing.T) {
	nexus := nexusEndpoint("https://nexus.example.org")
	gateway := chainclient.ServiceEndpointSnapshot{
		Kind:            chainclient.EndpointKindObjectGatewayHTTPS,
		URI:             "https://gateway.example.org",
		ProtocolVersion: "v9",
	}
	resolver, keeper := newFixture(t, nexus, Options{})
	keeper.descriptor = descriptorWith(t, nexus, gateway)

	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.Endpoint != "https://nexus.example.org" || identity.EndpointProtocolVersion != "v1" {
		t.Fatalf("identity = %+v, want the NEXUS_GRPC endpoint, not the gateway", identity)
	}
}

// The freshness contract that replaced the deleted effective/expires window: the
// descriptor row must be the version the Builder's own row calls current.
func TestResolveRefusesASupersededDescriptorVersion(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	keeper.builder.CurrentDescriptorVersion = chainclient.Uint64String(9)

	_, err := resolver.Resolve(context.Background(), testOperator)
	if err == nil || !strings.Contains(err.Error(), "is not the current version 9") {
		t.Fatalf("err = %v, want a superseded-version refusal", err)
	}
}

func TestResolveRejectsRevokedOrForeignServiceKey(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})

	keeper.serviceKey.Status = "REVOKED"
	if _, err := resolver.Resolve(context.Background(), testOperator); err == nil || !strings.Contains(err.Error(), "service key status") {
		t.Fatalf("err = %v, want revoked status rejection", err)
	}

	keeper.serviceKey.Status = "ACTIVE"
	keeper.serviceKey.RevokedHeight = chainclient.Uint64String(400)
	if _, err := resolver.Resolve(context.Background(), testOperator); err == nil || !strings.Contains(err.Error(), "revoked at height") {
		t.Fatalf("err = %v, want revocation-height rejection", err)
	}

	keeper.serviceKey.RevokedHeight = chainclient.Uint64String(0)
	keeper.serviceKey.OperatorAddress = "trueopen1other"
	if _, err := resolver.Resolve(context.Background(), testOperator); err == nil || !strings.Contains(err.Error(), "does not belong to Builder") {
		t.Fatalf("err = %v, want operator mismatch rejection", err)
	}
}

// The plaintext gate defaults to refusing.
//
// This test exists because http:// is REACHABLE IN COMMITTED STATE, not merely
// conceivable: GenesisState.Validate runs the loose scheme validator that admits
// http (TrueOpen/node d8792e6 x/hub/types/genesis.go:278-281 calling
// x/hub/types/participant_identity.go:62-65) and InitGenesis writes those
// rows into the descriptor map with no further scheme check
// (x/hub/keeper/genesis.go:91-95). A devnet genesis can seed exactly this
// endpoint. Deleting the gate as "guarding a scheme nothing can publish" would
// silently admit that seeded state, so this test is what makes that deletion
// fail.
//
// The gate is also distinct from the scheme allowlist, which is why both
// assertions below matter: http:// is a RECOGNISED scheme that this specific
// flag guards, while a scheme outside {https, grpcs, http, grpc} is refused as
// unrecognised no matter what the flag says
// (TestResolveRejectsUnsupportedEndpointSchemes). Collapsing the two would make
// the gate look redundant.
func TestResolveRefusesPlaintextEndpointWithoutTheInsecureOptIn(t *testing.T) {
	const uri = "http://nexus.devnet.invalid:8080"
	resolver, _ := newFixture(t, nexusEndpoint(uri), Options{})
	_, err := resolver.Resolve(context.Background(), testOperator)
	if err == nil || !errors.Is(err, ErrPlaintextEndpoint) {
		t.Fatalf("err = %v, want ErrPlaintextEndpoint", err)
	}
	if !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor") {
		t.Fatalf("err = %v, want the refusal to name the config flag", err)
	}
	// It must be the gate refusing, not the scheme allowlist. If someone deletes
	// the gate and http:// starts falling through to "unsupported scheme", this
	// catches it as loudly as an outright accept would be caught.
	if strings.Contains(err.Error(), "scheme is not one of") {
		t.Fatalf("err = %v, want the plaintext gate to refuse http, not the scheme allowlist", err)
	}
	if builderclient.IsRetryable(err) {
		t.Fatalf("a policy refusal must never be retryable: %v", err)
	}

	// The same descriptor resolves once the operator opts in. This is the half
	// that proves the gate is a gate and not a blanket refusal.
	opted, _ := newFixture(t, nexusEndpoint(uri), Options{AllowInsecure: true})
	identity, err := opted.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve with AllowInsecure: %v", err)
	}
	if identity.Endpoint != uri {
		t.Fatalf("endpoint = %q, want %q", identity.Endpoint, uri)
	}
}

// A pin on a plaintext endpoint has nothing to check against (no TLS means no
// certificate), so the refusal has to say that the scheme and the pin contradict
// each other, rather than leaving the operator thinking the pin value was miscomputed.
func TestPinnedPlaintextErrorNamesTheConflict(t *testing.T) {
	message := ErrPinnedPlaintextEndpoint.Error()
	for _, want := range []string{"tls_pubkey_hash", "plaintext"} {
		if !strings.Contains(message, want) {
			t.Fatalf("ErrPinnedPlaintextEndpoint = %q, want it to mention %q", message, want)
		}
	}
	for _, forbidden := range []string{"invalid", "malformed", "wrong", "does not match", "corrupt"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("ErrPinnedPlaintextEndpoint = %q, must not suggest the published pin is at fault (%q)", message, forbidden)
		}
	}
}

// The gate is the same for every kind. Nothing infers security from the enum
// name, and no kind gets a looser scheme set than another. It classifies on
// transport security, not on scheme spelling: grpcs is https, grpc is http.
func TestResolveAppliesTheSameTransportRuleToEveryKind(t *testing.T) {
	for _, kind := range []chainclient.ServiceEndpointKind{
		chainclient.EndpointKindNexusGRPC,
		chainclient.EndpointKindObjectGatewayHTTPS,
		chainclient.EndpointKindHealthHTTPS,
	} {
		t.Run(string(kind), func(t *testing.T) {
			secure := chainclient.ServiceEndpointSnapshot{Kind: kind, URI: "https://svc.example.org", ProtocolVersion: "v1"}
			if err := CheckEndpointTransport(secure, false); err != nil {
				t.Fatalf("err = %v, want https accepted with the gate closed", err)
			}
			plaintext := chainclient.ServiceEndpointSnapshot{Kind: kind, URI: "http://svc.example.org", ProtocolVersion: "v1"}
			if err := CheckEndpointTransport(plaintext, false); !errors.Is(err, ErrPlaintextEndpoint) {
				t.Fatalf("err = %v, want a plaintext refusal", err)
			}
			if err := CheckEndpointTransport(plaintext, true); err != nil {
				t.Fatalf("err = %v, want the opt-in to admit it", err)
			}
			// grpcs is the TLS spelling and is accepted with the gate closed;
			// grpc is the plaintext spelling and is gated exactly like http.
			// Refusing either outright, which this build used to do, rejected
			// the SECURE gRPC endpoint and made the opt-in unreachable for the
			// insecure one.
			secureGRPC := chainclient.ServiceEndpointSnapshot{Kind: kind, URI: "grpcs://svc.example.org", ProtocolVersion: "v1"}
			if err := CheckEndpointTransport(secureGRPC, false); err != nil {
				t.Fatalf("err = %v, want grpcs accepted with the gate closed", err)
			}
			plaintextGRPC := chainclient.ServiceEndpointSnapshot{Kind: kind, URI: "grpc://svc.example.org", ProtocolVersion: "v1"}
			if err := CheckEndpointTransport(plaintextGRPC, false); !errors.Is(err, ErrPlaintextEndpoint) {
				t.Fatalf("err = %v, want grpc refused by the plaintext gate, not the scheme allowlist", err)
			}
			if err := CheckEndpointTransport(plaintextGRPC, true); err != nil {
				t.Fatalf("err = %v, want the opt-in to admit grpc", err)
			}
		})
	}
}

// A kind with no transport decision fails closed rather than inheriting a
// branch. chainclient refuses an unknown kind at decode too; this is the policy
// side of the same closed enum.
func TestCheckEndpointTransportRefusesAKindItHasNoRuleFor(t *testing.T) {
	unknown := chainclient.ServiceEndpointSnapshot{Kind: "FUTURE_KIND", URI: "https://svc.example.org", ProtocolVersion: "v1"}
	if err := CheckEndpointTransport(unknown, false); err == nil ||
		!strings.Contains(err.Error(), "has no transport rule in this build") {
		t.Fatalf("err = %v, want an unknown kind refused", err)
	}
}

// tls_pubkey_hash = sha256(certificate SubjectPublicKeyInfo DER), written on chain
// with the registration after nexus self-signs its certificate (TrueOpen/nexus#63).
// A pin on an https/grpcs endpoint is carried into Identity unchanged and checked by
// builderclient at dial time; a plaintext endpoint has no certificate to check, so a
// pin on one is self-contradictory and is refused whether or not the plaintext
// opt-in is on.
func TestResolveCarriesAPinOnTLSEndpointsAndRefusesItOnPlaintext(t *testing.T) {
	pin := testDescriptorHash(t)
	for _, uri := range []string{"https://nexus.example.org", "grpcs://nexus.example.org:8443"} {
		pinned := nexusEndpoint(uri)
		pinned.TLSPubkeyHash = chainclient.NewOptionalHash32(pin)
		t.Run(uri, func(t *testing.T) {
			resolver, _ := newFixture(t, pinned, Options{})
			identity, err := resolver.Resolve(context.Background(), testOperator)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			got, present := identity.EndpointTLSPubkeyHash.Hash()
			if !present || got != pin {
				t.Fatalf("EndpointTLSPubkeyHash = %s (present=%v), want the published pin", identity.EndpointTLSPubkeyHash, present)
			}
		})
	}
	for _, uri := range []string{"http://nexus.devnet.invalid:8080", "grpc://nexus.devnet.invalid:8080"} {
		pinned := nexusEndpoint(uri)
		pinned.TLSPubkeyHash = chainclient.NewOptionalHash32(pin)
		for name, allowInsecure := range map[string]bool{"gate closed": false, "gate open": true} {
			t.Run(uri+"/"+name, func(t *testing.T) {
				resolver, _ := newFixture(t, pinned, Options{AllowInsecure: allowInsecure})
				_, err := resolver.Resolve(context.Background(), testOperator)
				if err == nil || !errors.Is(err, ErrPinnedPlaintextEndpoint) {
					t.Fatalf("err = %v, want ErrPinnedPlaintextEndpoint", err)
				}
				if builderclient.IsRetryable(err) {
					t.Fatalf("a policy refusal must never be retryable: %v", err)
				}
			})
		}
	}
}

// An absent pin resolves, and stays visibly absent all the way onto Identity.
// Nothing downstream may read it as a pin against the zero digest, and the two
// states reach different outcomes: absent resolves, present refuses.
func TestResolveKeepsAnAbsentPinDistinguishableFromAPresentOne(t *testing.T) {
	resolver, _ := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.EndpointTLSPubkeyHash.Present() {
		t.Fatalf("absent pin reports Present() = true")
	}
	if got := identity.EndpointTLSPubkeyHash.String(); got != "absent" {
		t.Fatalf("absent pin renders as %q, want it never to look like a digest", got)
	}
	if _, present := identity.EndpointTLSPubkeyHash.Hash(); present {
		t.Fatalf("absent pin yields a hash")
	}

	// Present is not flattened either: the same endpoint resolves with the pin visible.
	pinned := nexusEndpoint("https://nexus.example.org")
	pinned.TLSPubkeyHash = chainclient.NewOptionalHash32(testDescriptorHash(t))
	resolver, _ = newFixture(t, pinned, Options{})
	identity, err = resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve pinned: %v", err)
	}
	if !identity.EndpointTLSPubkeyHash.Present() {
		t.Fatal("present pin reports Present() = false")
	}
}

// The four schemes consensus admits (node d8792e6
// x/hub/types/participant_identity.go:62-65) are all admissible here now,
// classified by transport security: https/grpcs accepted, http/grpc gated on
// the plaintext opt-in. What must still be refused is anything outside that
// set, with or without the opt-in, because the opt-in is a TLS concession and
// not a parser.
//
// Schemes consensus does not admit cannot reach Resolve at all: chainclient
// refuses to build a descriptor snapshot carrying one, which is why this drives
// the exported gate directly rather than the resolver. That refusal is covered
// by TestServiceEndpointURIShapeMatchesTheWritePath in that package; what is
// checked here is that the last gate before a dialer does not widen it.
func TestResolveRejectsUnsupportedEndpointSchemes(t *testing.T) {
	for _, uri := range []string{"ws://nexus.example.org", "file:///nexus", "ipfs://nexus", "ftp://nexus.example.org", "nexus.example.org"} {
		t.Run(uri, func(t *testing.T) {
			endpoint := chainclient.ServiceEndpointSnapshot{
				Kind: chainclient.EndpointKindNexusGRPC, URI: uri, ProtocolVersion: "v1",
			}
			if err := CheckEndpointTransport(endpoint, true); err == nil ||
				!strings.Contains(err.Error(), "scheme is not one of") &&
					!strings.Contains(err.Error(), "absolute base URL") {
				t.Fatalf("err = %v, want a refusal even with the opt-in set", err)
			}
		})
	}
}

// The devnet BuilderSet publishes grpc://, and grpcs:// is the secure spelling
// of the same transport. Resolve must reach both, because refusing them was a
// second blocker on the round trip that no configuration could relax: the
// refusal came from the scheme allowlist rather than the plaintext gate, so
// allow_insecure_descriptor did not apply to it.
func TestResolveReachesTheGRPCSchemesByTransportClass(t *testing.T) {
	secure, _ := newFixture(t, nexusEndpoint("grpcs://nexus.example.org:8443"), Options{})
	identity, err := secure.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve(grpcs, gate closed) = %v, want the TLS spelling accepted", err)
	}
	// The published URI is reported verbatim: SameEndpoint compares it against
	// configuration exactly, so a normalised value here would accept a
	// configured string the chain never committed.
	if identity.Endpoint != "grpcs://nexus.example.org:8443" {
		t.Fatalf("Endpoint = %q, want the committed URI unmodified", identity.Endpoint)
	}

	closed, _ := newFixture(t, nexusEndpoint("grpc://nexus.example.org:8080"), Options{})
	if _, err := closed.Resolve(context.Background(), testOperator); !errors.Is(err, ErrPlaintextEndpoint) {
		t.Fatalf("Resolve(grpc, gate closed) = %v, want ErrPlaintextEndpoint", err)
	}
	opted, _ := newFixture(t, nexusEndpoint("grpc://nexus.example.org:8080"), Options{AllowInsecure: true})
	plaintext, err := opted.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve(grpc, opt-in) = %v, want the plaintext spelling admitted", err)
	}
	if plaintext.Endpoint != "grpc://nexus.example.org:8080" {
		t.Fatalf("Endpoint = %q, want the committed URI unmodified", plaintext.Endpoint)
	}
}

func TestResolveRejectsBuilderWithoutCurrentDescriptor(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	keeper.builder.CurrentDescriptorVersion = chainclient.Uint64String(0)
	_, err := resolver.Resolve(context.Background(), testOperator)
	if err == nil || !errors.Is(err, ErrNoCurrentDescriptor) {
		t.Fatalf("err = %v, want ErrNoCurrentDescriptor", err)
	}
}

func TestResolveRejectsCurrentKeyDescriptorMismatch(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	keeper.serviceKey.CurrentDescriptorVersion = chainclient.Uint64String(8)
	if _, err := resolver.Resolve(context.Background(), testOperator); err == nil {
		t.Fatal("accepted current key and descriptor version mismatch")
	}
}

// The comparison is byte-exact against what consensus committed. Any
// normalisation would accept a configured string the chain does not carry.
func TestSameEndpointComparesTheCommittedURIExactly(t *testing.T) {
	identity := Identity{OperatorAddress: testOperator, DescriptorVersion: 7, Endpoint: "https://nexus.example.org"}
	if err := identity.SameEndpoint("https://nexus.example.org"); err != nil {
		t.Fatalf("SameEndpoint(exact) = %v", err)
	}
	for _, configured := range []string{
		"https://nexus.example.org/",
		"https://NEXUS.example.org",
		"https://nexus.example.org:8443",
		"grpc://nexus.example.org",
		"http://nexus.example.org",
		" https://nexus.example.org",
	} {
		if err := identity.SameEndpoint(configured); err == nil {
			t.Fatalf("SameEndpoint(%q) accepted a string the chain does not commit", configured)
		}
	}
}

func TestResolveRestatesKeeperTransportFailuresWithOneRetryContract(t *testing.T) {
	for name, inject := range map[string]func(*stubKeeper){
		"builder read": func(k *stubKeeper) { k.builderErr = chainclient.Retryable(fmt.Errorf("keeper builder request failed")) },
		"descriptor read": func(k *stubKeeper) {
			k.descriptErr = chainclient.Retryable(fmt.Errorf("keeper descriptor request failed"))
		},
		"service key read": func(k *stubKeeper) {
			k.keyErr = chainclient.Retryable(fmt.Errorf("keeper service key request failed"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
			inject(keeper)

			_, err := resolver.Resolve(context.Background(), testOperator)
			if err == nil {
				t.Fatalf("Resolve() error = nil, want the Keeper transport failure")
			}
			if !builderclient.IsRetryable(err) {
				t.Fatalf("err = %v, want a retryable Keeper transport failure", err)
			}
		})
	}
}

// A Keeper that cannot serve Query/ServiceDescriptor at all -- which is what the
// deployed pre-freeze chain does, answering the frozen route Not Implemented --
// fails the resolution closed with the chain's own reason attached, never a
// fallback endpoint.
func TestResolveFailsClosedWhenTheDescriptorReadIsUnavailable(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	// This is the literal shape the deployed pre-freeze chain returns for the
	// frozen route: participant_type is field 1 of both wires but a string
	// pre-freeze and a varint enum frozen, so the node rejects the request before
	// reading it. Probed against devnet 6ebe9b2 at height 140076 on 2026-08-21.
	keeper.descriptErr = fmt.Errorf(
		`Keeper /hub.v1.Query/ServiceDescriptor ABCI query failed (codespace "sdk" code 18): ` +
			`proto: wrong wireType = 0 for field ParticipantType: invalid request`,
	)

	_, err := resolver.Resolve(context.Background(), testOperator)
	if err == nil || !strings.Contains(err.Error(), "wrong wireType = 0 for field ParticipantType") {
		t.Fatalf("err = %v, want the chain's own unavailability reason", err)
	}
	if errors.Is(err, ErrNoCurrentDescriptor) {
		t.Fatalf("an unavailable read must not be reported as a missing descriptor: %v", err)
	}
	if builderclient.IsRetryable(err) {
		t.Fatalf("a non-retryable chain refusal must not be marked retryable: %v", err)
	}
}

func TestResolvePublishesTheDescriptorSnapshotHeightForDiagnostics(t *testing.T) {
	resolver, keeper := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})

	identity, err := resolver.Resolve(context.Background(), testOperator)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.SnapshotHeight != keeper.height || identity.DescriptorHash != keeper.descriptor.DescriptorHash.String() {
		t.Fatalf("identity = %+v, want the pinned height and committed hash", identity)
	}
}

func TestNewRequiresAKeeperReader(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatalf("New(nil) error = nil, want a refusal")
	}
}

func TestResolveRequiresACanonicalOperatorAddress(t *testing.T) {
	resolver, _ := newFixture(t, nexusEndpoint("https://nexus.example.org"), Options{})
	for _, operator := range []string{"", " " + testOperator, testOperator + " "} {
		if _, err := resolver.Resolve(context.Background(), operator); err == nil {
			t.Fatalf("Resolve(%q) error = nil, want a canonical address refusal", operator)
		}
	}
}
