package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiagnosticsFindsDependencyStatus(t *testing.T) {
	report := Diagnostics{
		Mode:           "real",
		ModelTransport: "grpc",
		Dependencies: []DependencyStatus{{
			Name:       "keeper",
			Endpoint:   "https://keeper.devnet.trueopen.xyz",
			Configured: true,
			Ready:      true,
		}},
	}

	status, ok := report.Dependency("keeper")
	if !ok {
		t.Fatalf("Dependency(keeper) ok = false")
	}
	if status.Endpoint != "https://keeper.devnet.trueopen.xyz" || !status.Ready {
		t.Fatalf("status = %#v", status)
	}

	if _, ok := report.Dependency("nexus"); ok {
		t.Fatalf("Dependency(nexus) ok = true, want false")
	}
}

func TestDiagnosticsOmitsNATSIdentityWhenNil(t *testing.T) {
	report := Diagnostics{Mode: "real", ModelTransport: "grpc"}

	out, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal() err = %v", err)
	}
	if strings.Contains(string(out), "nexus_nats_identity") {
		t.Fatalf("Marshal() = %s, want no nexus_nats_identity field", out)
	}
}

func TestDiagnosticsIncludesNATSIdentityWhenSet(t *testing.T) {
	report := Diagnostics{
		Mode:           "real",
		ModelTransport: "grpc",
		NexusNATSIdentity: &NATSIdentityStatus{
			UserPublicKey:  "UAB123",
			BindingNonce:   7,
			IssuedAtUnixMS: 1700000000000,
		},
	}

	out, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal() err = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("Unmarshal() err = %v", err)
	}
	identity, ok := decoded["nexus_nats_identity"].(map[string]any)
	if !ok {
		t.Fatalf("decoded[nexus_nats_identity] = %#v, want object", decoded["nexus_nats_identity"])
	}
	if identity["user_public_key"] != "UAB123" {
		t.Fatalf("user_public_key = %v, want UAB123", identity["user_public_key"])
	}
	if identity["binding_nonce"] != float64(7) {
		t.Fatalf("binding_nonce = %v, want 7", identity["binding_nonce"])
	}
}
