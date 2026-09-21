package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderdirectory"
	"github.com/SingaXYZ/cortex/internal/chainclient"
)

// The on-chain descriptor registers an https endpoint with a tls_pubkey_hash: the
// resolve result carries that hash (hex) out for checking the certificate public key
// at dial time, and stays the empty string when none is registered.
func TestBuilderEndpointsCarryTheDescriptorTLSPubkeyHash(t *testing.T) {
	var pin chainclient.HexHash
	for i := range pin {
		pin[i] = 0x5c
	}
	var descriptorHash chainclient.HexHash
	for i := range descriptorHash {
		descriptorHash[i] = 0xab
	}
	descriptor, err := chainclient.NewServiceDescriptorSnapshot(
		chainclient.ParticipantTypeBuilder, endpointTestBuilder, 3, descriptorHash, 120, 1,
		[]chainclient.ServiceEndpointSnapshot{{
			Kind:            chainclient.EndpointKindNexusGRPC,
			URI:             "https://nexus.example.org",
			ProtocolVersion: "v1",
			TLSPubkeyHash:   chainclient.NewOptionalHash32(pin),
		}},
	)
	if err != nil {
		t.Fatalf("build descriptor snapshot: %v", err)
	}
	keeper := &endpointKeeper{descriptor: descriptor, key: builderServiceKey()}
	directory, err := builderdirectory.New(keeper, builderdirectory.Options{})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	resolver := newBuilderEndpoints(directory, keeper, "", "", false)

	endpoint, err := resolver.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint: %v", err)
	}
	if endpoint.TLSPubkeyHash != strings.Repeat("5c", 32) {
		t.Fatalf("TLSPubkeyHash = %q, want the descriptor pin as hex", endpoint.TLSPubkeyHash)
	}

	unpinned := descriptorBackedEndpoints(t, "https://nexus.example.org")
	plain, err := unpinned.ResolveBuilderEndpoint(context.Background(), endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint (no pin): %v", err)
	}
	if plain.TLSPubkeyHash != "" {
		t.Fatalf("absent pin must stay empty, got %q", plain.TLSPubkeyHash)
	}
}

// After a certificate change the on-chain fingerprint changed while the resolver's
// cache still holds the old one; RefreshBuilderEndpoint re-reads the descriptor past
// the cache and gets the new fingerprint. This is the basis for "fingerprint mismatch
// -> re-read the descriptor and retry once".
func TestRefreshBuilderEndpointBypassesTheDescriptorCache(t *testing.T) {
	pinned := func(fill byte) chainclient.ServiceDescriptorSnapshot {
		var pin, descriptorHash chainclient.HexHash
		for i := range pin {
			pin[i] = fill
			descriptorHash[i] = fill ^ 0xff
		}
		descriptor, err := chainclient.NewServiceDescriptorSnapshot(
			chainclient.ParticipantTypeBuilder, endpointTestBuilder, 3, descriptorHash, 120, 1,
			[]chainclient.ServiceEndpointSnapshot{{
				Kind: chainclient.EndpointKindNexusGRPC, URI: "https://nexus.example.org",
				ProtocolVersion: "v1", TLSPubkeyHash: chainclient.NewOptionalHash32(pin),
			}},
		)
		if err != nil {
			t.Fatalf("build descriptor snapshot: %v", err)
		}
		return descriptor
	}
	keeper := &endpointKeeper{descriptor: pinned(0x5c), key: builderServiceKey()}
	directory, err := builderdirectory.New(keeper, builderdirectory.Options{})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	resolver := newBuilderEndpoints(directory, keeper, "", "", false)
	ctx := context.Background()

	first, err := resolver.ResolveBuilderEndpoint(ctx, endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint: %v", err)
	}
	keeper.descriptor = pinned(0x6d) // the certificate changed on chain
	cached, err := resolver.ResolveBuilderEndpoint(ctx, endpointTestBuilder)
	if err != nil {
		t.Fatalf("ResolveBuilderEndpoint (cached): %v", err)
	}
	if cached.TLSPubkeyHash != first.TLSPubkeyHash {
		t.Fatalf("second resolve should still be served from cache, got %q", cached.TLSPubkeyHash)
	}
	fresh, err := resolver.RefreshBuilderEndpoint(ctx, endpointTestBuilder)
	if err != nil {
		t.Fatalf("RefreshBuilderEndpoint: %v", err)
	}
	if fresh.TLSPubkeyHash != strings.Repeat("6d", 32) {
		t.Fatalf("refreshed TLSPubkeyHash = %q, want the new on-chain pin", fresh.TLSPubkeyHash)
	}
}
