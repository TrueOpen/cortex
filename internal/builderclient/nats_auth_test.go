package builderclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// The ADR-0016 transition state: cortex connects to NATS over tls:// and replaces the
// token with a creds file. Only option assembly is asserted.

func applyNATSAuth(t *testing.T, auth NATSAuth) nats.Options {
	t.Helper()
	opts, err := natsAuthOptions(auth)
	if err != nil {
		t.Fatalf("natsAuthOptions: %v", err)
	}
	applied := nats.GetDefaultOptions()
	for _, opt := range opts {
		if err := opt(&applied); err != nil {
			t.Fatalf("apply option: %v", err)
		}
	}
	return applied
}

func writeAuthFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nats-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Test-only creds file content (a throwaway nkey, matching no environment).
const testNATSCreds = `-----BEGIN NATS USER JWT-----
eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJURVNUIn0.c2ln
------END NATS USER JWT------

-----BEGIN USER NKEY SEED-----
SUAGKSV4OGPS3VCFLJ5V2R6ZVRA3NAOP6WQGKKTAYJWSSRSHCWZ2QVBBBI
------END USER NKEY SEED------
`

func TestNATSAuthUsesCredsAndCAFile(t *testing.T) {
	applied := applyNATSAuth(t, NATSAuth{
		URL:       "tls://nats.example:4222",
		CredsFile: writeAuthFile(t, "cortex.creds", testNATSCreds),
		CAFile:    writeAuthFile(t, "ca.pem", selfSignedPEM(t)),
	})
	if applied.UserJWT == nil || applied.SignatureCB == nil {
		t.Fatal("creds file must install the user JWT and nkey signature callbacks")
	}
	if applied.Token != "" {
		t.Fatalf("token must not be set with creds, got %q", applied.Token)
	}
	if !applied.Secure && applied.TLSConfig == nil {
		t.Fatal("tls:// with ca_file must produce a TLS configuration")
	}
}

func TestNATSAuthTLSSchemeRequiresTLSEvenWithoutCAFile(t *testing.T) {
	applied := applyNATSAuth(t, NATSAuth{URL: "tls://nats.example:4222"})
	if !applied.Secure {
		t.Fatal("tls:// must require TLS (system roots when no ca_file)")
	}
}

func TestNATSAuthKeepsTokenForDev(t *testing.T) {
	applied := applyNATSAuth(t, NATSAuth{URL: "nats://127.0.0.1:4222", Token: "dev-token"})
	if applied.Token != "dev-token" || applied.Secure || applied.UserJWT != nil {
		t.Fatalf("dev token options changed: token=%q secure=%v", applied.Token, applied.Secure)
	}
}

func TestNATSAuthRejectsMissingFiles(t *testing.T) {
	if _, err := natsAuthOptions(NATSAuth{URL: "tls://n:4222", CredsFile: "/nonexistent/cortex.creds"}); err == nil || !strings.Contains(err.Error(), "nats_creds_file") {
		t.Fatalf("missing creds = %v, want an error naming nats_creds_file", err)
	}
	if _, err := natsAuthOptions(NATSAuth{URL: "tls://n:4222", CAFile: "/nonexistent/ca.pem"}); err == nil || !strings.Contains(err.Error(), "nats_ca_file") {
		t.Fatalf("missing ca = %v, want an error naming nats_ca_file", err)
	}
}
