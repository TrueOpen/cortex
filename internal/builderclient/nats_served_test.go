package builderclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
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
	if !o.Secure || o.TLSConfig == nil || o.RootCAsCB == nil {
		t.Fatalf("tls = secure %v config %v rootCAsCB %v", o.Secure, o.TLSConfig, o.RootCAsCB != nil)
	}
	requireTrusts(t, o, certPEM)
}

func requireTrusts(t *testing.T, o nats.Options, certPEM string) {
	t.Helper()
	pool, err := o.RootCAsCB()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("certificate is not the trust root: %v", err)
	}
}

// nats.go reconnects with the options it was dialled with; the served certificate is
// asked for again on every handshake, so a rotation reaches those reconnects. When
// the identity cannot answer, the previous certificate is kept.
func TestServedCertificateIsRereadOnReconnect(t *testing.T) {
	first, second := servedCertPEM(t), servedCertPEM(t)
	provider := servedIdentity([]string{"tls://203.0.113.10:4222"}, first)
	_, opts, err := natsConnectOptions(NATSAuth{ChainIdentity: provider, RequireServerTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	o := applyOptions(t, opts)
	requireTrusts(t, o, first)

	provider.cred.NATSCAPEM = second
	requireTrusts(t, o, second)

	provider.err = errors.New("chain unavailable")
	requireTrusts(t, o, second)
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
	// With a configured nats_ca_file the served certificate is not in use, and
	// refetching the sentinel cannot fix a bad local file.
	invalidateOnAuthError(NATSAuth{ChainIdentity: provider, CAFile: "/etc/cortex/nats-ca.pem"}, fmt.Errorf("dial: %w", x509.UnknownAuthorityError{}))
	if provider.invalidated != 1 {
		t.Fatal("a certificate failure against the configured file invalidated the identity")
	}
}

type closableTransport struct {
	closed bool
}

func (c *closableTransport) Publish(context.Context, NATSMessage) error { return nil }
func (c *closableTransport) IsClosed() bool                             { return c.closed }
func (c *closableTransport) Close() error                               { c.closed = true; return nil }

// A connection nats.go closed for good (reconnects exhausted) is dialled again on the
// next publish, which re-reads the served address and certificate; one this side
// closed is not.
func TestLazyPublisherRedialsAfterTheConnectionClosed(t *testing.T) {
	var dialed []*closableTransport
	previous := connectNATSPublishTransport
	connectNATSPublishTransport = func(NATSAuth) (natsPublishTransport, error) {
		transport := &closableTransport{}
		dialed = append(dialed, transport)
		return transport, nil
	}
	t.Cleanup(func() { connectNATSPublishTransport = previous })

	lazy := &lazyNATSPublishTransport{}
	ctx := context.Background()
	if err := lazy.Publish(ctx, NATSMessage{}); err != nil {
		t.Fatal(err)
	}
	if err := lazy.Publish(ctx, NATSMessage{}); err != nil || len(dialed) != 1 {
		t.Fatalf("a live connection was redialled: dials=%d err=%v", len(dialed), err)
	}
	dialed[0].closed = true
	if err := lazy.Publish(ctx, NATSMessage{}); err != nil || len(dialed) != 2 {
		t.Fatalf("a closed connection was not redialled: dials=%d err=%v", len(dialed), err)
	}
	if err := lazy.Close(); err != nil {
		t.Fatal(err)
	}
	_ = lazy.Publish(ctx, NATSMessage{})
	if len(dialed) != 2 {
		t.Fatalf("a transport closed by this side was redialled: dials=%d", len(dialed))
	}
}
