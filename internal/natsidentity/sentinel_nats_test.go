package natsidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testNATSCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-nats"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The optional NATS address and certificate served with the sentinel (§4.12) are
// carried through; a document without them is unchanged.
func TestValidateSentinelCarriesServedNATS(t *testing.T) {
	account, token := newTestSentinelJWT(t, true)
	certPEM := testNATSCertPEM(t)
	sentinel, err := validateSentinel(sentinelResponse{
		SchemaVersion: 1, AuthAccountPublicKey: account, SentinelJWT: token,
		NATSServers: []string{" tls://203.0.113.10:4222 ", "tls://[2001:db8::1]:4222"}, NATSCAPEM: certPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(sentinel.NATSServers, ",") != "tls://203.0.113.10:4222,tls://[2001:db8::1]:4222" {
		t.Fatalf("nats servers = %v", sentinel.NATSServers)
	}
	if strings.TrimSpace(sentinel.NATSCAPEM) != strings.TrimSpace(certPEM) {
		t.Fatalf("nats ca pem = %q", sentinel.NATSCAPEM)
	}

	plain, err := validateSentinel(sentinelResponse{SchemaVersion: 1, AuthAccountPublicKey: account, SentinelJWT: token})
	if err != nil {
		t.Fatal(err)
	}
	if plain.NATSServers != nil || plain.NATSCAPEM != "" {
		t.Fatalf("a document without the optional fields produced %+v", plain)
	}
}

// A malformed served address or certificate fails this Builder's document, so the
// next candidate is tried instead of dialling something half-understood.
func TestValidateSentinelRefusesMalformedServedNATS(t *testing.T) {
	account, token := newTestSentinelJWT(t, true)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("key")}))
	for name, c := range map[string]struct {
		servers []string
		caPEM   string
		want    string
	}{
		"no port":         {[]string{"tls://203.0.113.10"}, "", "not tls://host:port"},
		"other scheme":    {[]string{"https://203.0.113.10:4222"}, "", "not tls://host:port"},
		"credentials":     {[]string{"tls://user:pass@203.0.113.10:4222"}, "", "not tls://host:port"},
		"private key":     {nil, keyPEM, "only certificates"},
		"bad certificate": {nil, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})), "does not parse"},
		"not pem":         {nil, "hello", "no certificate"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validateSentinel(sentinelResponse{
				SchemaVersion: 1, AuthAccountPublicKey: account, SentinelJWT: token,
				NATSServers: c.servers, NATSCAPEM: c.caPEM,
			})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
