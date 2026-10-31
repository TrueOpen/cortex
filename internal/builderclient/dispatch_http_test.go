package builderclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func protoOf(t *testing.T, c *http.Client, ctx context.Context, url string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// A connect bidi stream needs HTTP/2 end to end, and a stream lives as long
// as the binding, so the client has no overall timeout.
func TestDispatchStreamHTTPClientSpeaksHTTP2(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Proto) })
	c := NewDispatchStreamHTTPClient()
	if c.Timeout != 0 {
		t.Fatalf("Timeout = %v, want none", c.Timeout)
	}
	tlsSrv := httptest.NewUnstartedServer(echo)
	tlsSrv.EnableHTTP2 = true
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	pinned := WithTLSPubkeyHash(context.Background(), TLSPubkeyHash(tlsSrv.Certificate()))
	if got := protoOf(t, c, pinned, tlsSrv.URL); got != "HTTP/2.0" {
		t.Fatalf("pinned TLS proto = %s", got)
	}
	plain := httptest.NewUnstartedServer(echo)
	plain.Config.Protocols = new(http.Protocols)
	plain.Config.Protocols.SetHTTP1(true)
	plain.Config.Protocols.SetUnencryptedHTTP2(true)
	plain.Start()
	defer plain.Close()
	if got := protoOf(t, c, context.Background(), plain.URL); got != "HTTP/2.0" {
		t.Fatalf("devnet plaintext proto = %s, want h2c", got)
	}
	req, _ := http.NewRequest(http.MethodGet, tlsSrv.URL, nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("an unpinned self-signed Builder must fail CA verification")
	}
}
