package builderclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func servedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "served-nats"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func servedIdentity(servers []string, caPEM string) *fakeChainIdentity {
	return &fakeChainIdentity{cred: NATSChainCredential{
		UserPublicKey: "UA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCTYM5",
		SignNonce:     func(nonce []byte) ([]byte, error) { return nonce, nil },
		Token:         "trueopen-nub1.abc", SentinelJWT: "eyJ.sentinel.one",
		NATSServers: servers, NATSCAPEM: caPEM,
	}}
}

// No nexus.nats_url or nexus.nats_ca_file: the address and the certificate come from
// the sentinel (§4.12), and the server is verified against exactly that certificate.
func TestNATSConnectUsesServedAddressAndCertificate(t *testing.T) {
	certPEM := servedCertPEM(t)
	natsURL, opts, err := natsConnectOptions(NATSAuth{
		ChainIdentity: servedIdentity([]string{"tls://203.0.113.10:4222", "tls://203.0.113.11:4222"}, certPEM), RequireServerTLS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if natsURL != "tls://203.0.113.10:4222,tls://203.0.113.11:4222" {
		t.Fatalf("url = %q", natsURL)
	}
	o := applyOptions(t, opts)
	if !o.Secure || o.TLSConfig == nil || o.TLSConfig.RootCAs == nil {
		t.Fatalf("tls = secure %v config %v", o.Secure, o.TLSConfig)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: o.TLSConfig.RootCAs}); err != nil {
		t.Fatalf("served certificate is not the trust root: %v", err)
	}
}

// Configured values win over served ones.
func TestNATSConnectPrefersConfiguredValues(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(servedCertPEM(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	natsURL, opts, err := natsConnectOptions(NATSAuth{
		URL: "tls://configured.example:4222", CAFile: caFile,
		ChainIdentity: servedIdentity([]string{"tls://served.example:4222"}, servedCertPEM(t)), RequireServerTLS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if natsURL != "tls://configured.example:4222" {
		t.Fatalf("url = %q, want the configured one", natsURL)
	}
	// nats.RootCAs loads the file through RootCAsCB; the served PEM would have set
	// TLSConfig.RootCAs instead.
	if o := applyOptions(t, opts); o.RootCAsCB == nil || (o.TLSConfig != nil && o.TLSConfig.RootCAs != nil) {
		t.Fatal("configured ca file was not the trust root")
	}
}

func TestNATSConnectRefusesMissingOrWeakServedValues(t *testing.T) {
	for name, c := range map[string]struct {
		auth NATSAuth
		want string
	}{
		"no address anywhere": {NATSAuth{ChainIdentity: servedIdentity(nil, "")}, "served no nats_servers"},
		"plaintext served in real mode": {NATSAuth{ChainIdentity: servedIdentity([]string{"nats://203.0.113.10:4222"}, ""), RequireServerTLS: true},
			"must be tls:// in real mode"},
		"remote without certificate in real mode": {NATSAuth{ChainIdentity: servedIdentity([]string{"tls://203.0.113.10:4222"}, ""), RequireServerTLS: true},
			"no certificate to verify the server"},
		"configured remote without certificate in real mode": {NATSAuth{URL: "tls://nats.example:4222", ChainIdentity: servedIdentity(nil, ""), RequireServerTLS: true},
			"no certificate to verify the server"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := natsConnectOptions(c.auth)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// Loopback needs no certificate, as before.
	if _, _, err := natsConnectOptions(NATSAuth{URL: "tls://127.0.0.1:4222", ChainIdentity: servedIdentity(nil, ""), RequireServerTLS: true}); err != nil {
		t.Fatalf("loopback without certificate refused: %v", err)
	}
}

// Only the on-chain identity may leave nats_url empty at construction.
func TestNATSClientsAcceptEmptyURLOnlyWithChainIdentity(t *testing.T) {
	if _, err := NewNATSPublisherWithAuth(NATSAuth{ChainIdentity: servedIdentity(nil, "")}); err != nil {
		t.Fatalf("publisher with chain identity and no url: %v", err)
	}
	if _, err := NewNATSSubscriberWithAuth(NATSAuth{ChainIdentity: servedIdentity(nil, "")}, "TRUEOPEN_TASK"); err != nil {
		t.Fatalf("subscriber with chain identity and no url: %v", err)
	}
	if _, err := NewNATSPublisherWithAuth(NATSAuth{}); err == nil {
		t.Fatal("publisher without url or chain identity accepted")
	}
}

// A failed server certificate check drops the cached sentinel with the binding, so a
// rotated certificate is fetched again (§5.14.4).
func TestCertificateVerificationFailureInvalidatesIdentity(t *testing.T) {
	provider := servedIdentity(nil, "")
	invalidateOnAuthError(NATSAuth{ChainIdentity: provider}, fmt.Errorf("dial: %w", x509.UnknownAuthorityError{}))
	if provider.invalidated != 1 {
		t.Fatalf("invalidated = %d, want 1", provider.invalidated)
	}
	invalidateOnAuthError(NATSAuth{ChainIdentity: provider}, fmt.Errorf("dial: connection refused"))
	if provider.invalidated != 1 {
		t.Fatal("a plain dial error invalidated the identity")
	}
}
