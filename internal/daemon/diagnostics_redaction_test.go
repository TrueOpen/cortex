package daemon

import (
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/diagnostics"
)

// Every dependency row in this package is built by one of three constructors,
// and the readiness pass rebuilds rows from the same config after startup. So
// the redaction belongs to the constructors rather than to one call site: a row
// added later gets it without anyone having to remember.
func TestDependencyStatusConstructorsRedactEndpointCredentials(t *testing.T) {
	const raw = "https://keeper-user:s3cr3t-keeper-password@keeper.devnet.trueopen.xyz:443"
	for name, status := range map[string]diagnostics.DependencyStatus{
		"unprobed":     unprobed("keeper", raw),
		"realStatus":   realStatus("keeper", raw, false, "not ready"),
		"fixtureReady": fixtureReady("keeper", raw),
	} {
		if strings.Contains(status.Endpoint, "s3cr3t-keeper-password") {
			t.Errorf("%s endpoint = %q, want the credential removed", name, status.Endpoint)
		}
		if !strings.Contains(status.Endpoint, "keeper.devnet.trueopen.xyz:443") || !status.Configured {
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
