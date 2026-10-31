package diagnostics

import (
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
