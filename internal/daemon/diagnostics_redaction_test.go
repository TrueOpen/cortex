package daemon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// The top-level nexus_nats field has been redacted since it was added, and
// scrubReadinessDetail redacts a probe error that quotes the same URL "because
// the host is already published in DependencyStatus.Endpoint". That premise was
// false: the dependency list carried nats://user:password@host verbatim, on
// both the nexus and the nexus_envelope_auth rows. `cortexctl diagnostics
// --format json` is the first thing an operator pastes into an issue, so the
// credential travelled with it.
func TestDiagnosticsDependencyEndpointsCarryNoCredentials(t *testing.T) {
	const password = "s3cr3t-nats-password"
	cfg := realConfig()
	cfg.Nexus.NATSURL = "tls://nexus-user:" + password + "@nats.devnet.trueopen.xyz:4222" // a remote NATS in real mode must be tls://; the password is still in the URL, which is what redaction is tested on
	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelTransport: fakeModelTransport{}, NexusPublisher: fakePublisher{}, NexusSubscriber: fakeSubscriber{},
		NexusToken: "token-1", TxClient: txclient.NewFake(),
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	encoded, err := json.Marshal(deps.Diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), password) {
		t.Fatalf("diagnostics JSON leaks the NATS password:\n%s", encoded)
	}
	// Redacted, not dropped: the host is what an operator is reading the row for.
	status, ok := deps.Diagnostics.Dependency("nexus")
	if !ok || !strings.Contains(status.Endpoint, "nats.devnet.trueopen.xyz:4222") || !status.Configured {
		t.Fatalf("nexus status = %#v ok=%v, want the host kept and the credential removed", status, ok)
	}
}

// Every dependency row in this package is built by one of three constructors,
// and the readiness pass rebuilds rows from the same config after startup
// (runtime_workload.go re-derives nexus_envelope_auth from Nexus.NATSURL). So
// the redaction belongs to the constructors rather than to one call site: a row
// added later gets it without anyone having to remember.
func TestDependencyStatusConstructorsRedactEndpointCredentials(t *testing.T) {
	const raw = "nats://nexus-user:s3cr3t-nats-password@nats.devnet.trueopen.xyz:4222"
	for name, status := range map[string]diagnostics.DependencyStatus{
		"unprobed":     unprobed("nexus", raw),
		"realStatus":   realStatus("nexus", raw, false, "not ready"),
		"fixtureReady": fixtureReady("nexus", raw),
	} {
		if strings.Contains(status.Endpoint, "s3cr3t-nats-password") {
			t.Errorf("%s endpoint = %q, want the credential removed", name, status.Endpoint)
		}
		if !strings.Contains(status.Endpoint, "nats.devnet.trueopen.xyz:4222") || !status.Configured {
			t.Errorf("%s status = %#v, want the host kept and the row still configured", name, status)
		}
	}
}

// A non-URL endpoint is passed through untouched. Most rows carry a filesystem
// path, an operator address or a comma-separated model list, and rewriting
// those through a URL parser is how a redaction pass corrupts the values it was
// never meant to touch.
func TestDependencyStatusEndpointsWithoutCredentialsAreUnchanged(t *testing.T) {
	for _, raw := range []string{
		"/var/lib/cortex/store.kv",
		"trueopen1ak99ag095wrn6ywxzm8spvwjth4an5kdzah0f0",
		"model-a,model-b",
		"http://194.233.91.14:26657",
	} {
		if got := unprobed("dependency", raw).Endpoint; got != raw {
			t.Errorf("endpoint %q was rewritten to %q", raw, got)
		}
	}
}
