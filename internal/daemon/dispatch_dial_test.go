package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

type dialResolver struct {
	ep        BuilderEndpoint
	refreshes int
}

func (r *dialResolver) ResolveBuilderEndpoint(context.Context, string) (BuilderEndpoint, error) {
	return r.ep, nil
}
func (r *dialResolver) RefreshBuilderEndpoint(ctx context.Context, op string) (BuilderEndpoint, error) {
	r.refreshes++
	return r.ep, nil
}

type dialMembers map[string]bool

func (m dialMembers) HasBuilder(_ context.Context, op string) (bool, error) { return m[op], nil }

func TestDescriptorClientDialsOnlyTheOnChainDescriptor(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto+" "+r.URL.Path)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pin := builderclient.TLSPubkeyHash(srv.Certificate())
	r := &dialResolver{ep: BuilderEndpoint{OperatorAddress: hrBuilderA, Endpoint: srv.URL + "/nexus", TLSPubkeyHash: pin, Source: BuilderEndpointSourceDescriptor}}
	c := &descriptorClient{builder: hrBuilderA, endpoints: r, members: dialMembers{hrBuilderA: true}, http: builderclient.NewDispatchStreamHTTPClient()}
	do := func() (string, error) {
		req, _ := http.NewRequest(http.MethodPost, dispatchStreamBase+"/nexus.v1.IngressAPI/DispatchStream", nil)
		resp, err := c.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	if got, err := do(); err != nil || got != "HTTP/2.0 /nexus/nexus.v1.IngressAPI/DispatchStream" {
		t.Fatalf("dial = %q, %v: the descriptor's origin and path prefix, pinned, over h2", got, err)
	}
	r.ep.TLSPubkeyHash = strings.Repeat("ab", 32)
	if _, err := do(); err == nil || r.refreshes != 1 {
		t.Fatalf("pin mismatch = %v, refreshes %d: refused and the descriptor re-read once (ADR-0015)", err, r.refreshes)
	}
	r.ep.TLSPubkeyHash, r.ep.Source = pin, BuilderEndpointSourceBootstrap
	if _, err := do(); err == nil || !strings.Contains(err.Error(), "dials only the on-chain descriptor") {
		t.Fatalf("bootstrap source = %v", err)
	}
	r.ep.Source = BuilderEndpointSourceDescriptor
	c.members = dialMembers{}
	if _, err := do(); err == nil || !strings.Contains(err.Error(), "not in the current BuilderSet") {
		t.Fatalf("non-member = %v", err)
	}
}
