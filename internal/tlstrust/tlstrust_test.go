package tlstrust

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenCertPEM is a fixed self-signed certificate. goldenPubkeyHash was
// computed from it with the command operators are told to run:
//
//	openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | cut -d" " -f1
const goldenCertPEM = `-----BEGIN CERTIFICATE-----
MIIBfjCCASOgAwIBAgIUAe3pk8uUbi82c6E6UY/66CNkro4wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbm9kZS50ZXN0MB4XDTI2MDkyODAzMTE1NloXDTM2MDkyNTAz
MTE1NlowFDESMBAGA1UEAwwJbm9kZS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAELKUW8rpfqBC+tK613jKziyyOWEZlneAL6U6QcfPIEpeD9Hb6yVVz5jWF
8wJFanV1LTXRrqr24/FHkTn3IWGGlaNTMFEwHQYDVR0OBBYEFHOiawOURnHz1rJJ
a2xqWWkQRDXNMB8GA1UdIwQYMBaAFHOiawOURnHz1rJJa2xqWWkQRDXNMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANE3kZyFiNflbCTZtGH2l01V
G6lQIpXosKm9feRioo+FAiEAi1tYllVHz7oBGmfV3i3Xb9oL+aramaivH+nIrII9
48g=
-----END CERTIFICATE-----
`

const goldenPubkeyHash = "a7b473f882690eb271f7c89eaa51e49ffaa03c425888952286a4917ed700f65c"

func TestPubkeyHashMatchesTheDocumentedOpenSSLCommand(t *testing.T) {
	block, _ := pem.Decode([]byte(goldenCertPEM))
	if block == nil {
		t.Fatal("golden certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := PubkeyHash(cert); got != goldenPubkeyHash {
		t.Fatalf("PubkeyHash = %s, want %s (openssl)", got, goldenPubkeyHash)
	}
}

func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	return server
}

func get(t *testing.T, transport http.RoundTripper, url string) error {
	t.Helper()
	client := &http.Client{Transport: transport}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	return nil
}

func TestHTTPTransportAcceptsTheServerPin(t *testing.T) {
	server := okServer(t)
	transport, err := HTTPTransport("node tls", "", PubkeyHash(server.Certificate()))
	if err != nil || transport == nil {
		t.Fatalf("HTTPTransport = %v, %v", transport, err)
	}
	if err := get(t, transport, server.URL); err != nil {
		t.Fatalf("pinned request to the matching server failed: %v", err)
	}
}

func TestHTTPTransportAcceptsAnUppercasePin(t *testing.T) {
	server := okServer(t)
	transport, err := HTTPTransport("node tls", "", strings.ToUpper(PubkeyHash(server.Certificate())))
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, transport, server.URL); err != nil {
		t.Fatalf("uppercase pin rejected at dial time: %v", err)
	}
}

func TestHTTPTransportRefusesAWrongPin(t *testing.T) {
	server := okServer(t)
	transport, err := HTTPTransport("node tls", "", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	err = get(t, transport, server.URL)
	if err == nil || !strings.Contains(err.Error(), "node tls: certificate pubkey_hash") {
		t.Fatalf("wrong pin: err = %v, want a pubkey_hash mismatch", err)
	}
}

func TestHTTPTransportTrustsTheCAFile(t *testing.T) {
	server := okServer(t)
	path := filepath.Join(t.TempDir(), "node-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := HTTPTransport("node tls", path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, transport, server.URL); err != nil {
		t.Fatalf("ca_file request failed: %v", err)
	}
}

func TestHTTPTransportCAFileStillChecksTheChain(t *testing.T) {
	server := okServer(t)
	// A certificate that did not sign the server's is no trust anchor for it.
	block, _ := pem.Decode([]byte(goldenCertPEM))
	path := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := HTTPTransport("node tls", path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, transport, server.URL); err == nil {
		t.Fatal("ca_file that did not issue the server certificate was accepted")
	}
}

func TestHTTPTransportWithoutConfigKeepsTheSystemRoots(t *testing.T) {
	transport, err := HTTPTransport("node tls", " ", " ")
	if err != nil || transport != nil {
		t.Fatalf("HTTPTransport with nothing set = %v, %v; want nil, nil", transport, err)
	}
	server := okServer(t)
	if err := get(t, transport, server.URL); err == nil {
		t.Fatal("a self-signed server was accepted with no node.tls configured")
	}
}

func TestClientConfigRefusesBadInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, ca, hash, want string
	}{
		{"both", "/etc/ca.pem", strings.Repeat("ab", 32), "set ca_file or pubkey_hash, not both"},
		{"short hash", "", "abcd", "pubkey_hash must be 64 lowercase hex"},
		{"non-hex hash", "", strings.Repeat("zz", 32), "pubkey_hash must be 64 lowercase hex"},
		{"missing ca file", filepath.Join(t.TempDir(), "absent.pem"), "", "read ca_file"},
		{"ca file without a certificate", path, "", "contains no certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ClientConfig("node tls", tc.ca, tc.hash)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "node tls: ") {
				t.Fatalf("ClientConfig = %v, want %q", err, tc.want)
			}
		})
	}
}
