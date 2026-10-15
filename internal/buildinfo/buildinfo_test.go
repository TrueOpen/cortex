package buildinfo

import "testing"

func TestCurrentReportsTheLinkedVersion(t *testing.T) {
	previous := Version
	t.Cleanup(func() { Version = previous })

	Version = "v0.1.0"
	if got := Current(); got != "v0.1.0" {
		t.Fatalf("Current() = %q, want the linked v0.1.0", got)
	}
	// A test binary is not built from a tagged module, so an unset version
	// reads as dev rather than as anything that looks like a release.
	Version = "dev"
	if got := Current(); got != "dev" {
		t.Fatalf("Current() = %q, want dev", got)
	}
}
