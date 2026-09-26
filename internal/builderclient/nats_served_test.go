package builderclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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
		IPAddresses: []net.IP{net.ParseIP("203.0.113.10")},
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
	if !o.Secure || o.TLSConfig == nil || o.TLSConfig.VerifyConnection == nil {
		t.Fatalf("tls = secure %v config %v", o.Secure, o.TLSConfig)
	}
	if err := o.TLSConfig.VerifyConnection(presented(t, certPEM)); err != nil {
		t.Fatalf("served certificate refused: %v", err)
	}
}

// presented is the connection state of a server presenting certPEM at 203.0.113.10.
func presented(t *testing.T, certPEM string) tls.ConnectionState {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, ServerName: "203.0.113.10"}
}

// nats.go reconnects on its own and reports no reconnect handshake error, so a
// certificate the Builder rotated must be picked up inside the handshake: a server
// presenting it is verified after the identity is invalidated and the served
// certificate fetched again. A certificate the Builder does not serve is refused.
func TestServedCertificateRotationIsPickedUpOnReconnect(t *testing.T) {
	first, second, stranger := servedCertPEM(t), servedCertPEM(t), servedCertPEM(t)
	provider := servedIdentity([]string{"tls://203.0.113.10:4222"}, first)
	_, opts, err := natsConnectOptions(NATSAuth{ChainIdentity: provider, RequireServerTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	verify := applyOptions(t, opts).TLSConfig.VerifyConnection

	if err := verify(presented(t, first)); err != nil || provider.invalidated != 0 {
		t.Fatalf("current certificate: err=%v invalidated=%d", err, provider.invalidated)
	}
	// The Builder rotates: the server presents the new certificate, which the provider
	// now serves.
	provider.cred.NATSCAPEM = second
	if err := verify(presented(t, second)); err != nil || provider.invalidated != 1 {
		t.Fatalf("rotated certificate: err=%v invalidated=%d", err, provider.invalidated)
	}
	// It is kept: the next handshake needs no refetch.
	if err := verify(presented(t, second)); err != nil || provider.invalidated != 1 {
		t.Fatalf("after rotation: err=%v invalidated=%d", err, provider.invalidated)
	}
	if err := verify(presented(t, stranger)); err == nil {
		t.Fatal("a certificate the builder does not serve was accepted")
	}
	// Wrong host for an otherwise trusted certificate.
	state := presented(t, second)
	state.ServerName = "nats.other.example"
	if err := verify(state); err == nil {
		t.Fatal("a certificate for another host was accepted")
	}
}

// For an IP literal crypto/tls leaves ServerName empty: the leaf must still be valid
// for one of the dialled hosts, or a certificate of another server under the same
// root would pass.
func TestServedCertificateIsCheckedAgainstDialledIP(t *testing.T) {
	certPEM := servedCertPEM(t) // IP SAN 203.0.113.10
	for name, c := range map[string]struct {
		servers []string
		ok      bool
	}{
		"matching ip":       {[]string{"tls://203.0.113.10:4222"}, true},
		"one of several":    {[]string{"tls://198.51.100.7:4222", "tls://203.0.113.10:4222"}, true},
		"ip not in the san": {[]string{"tls://198.51.100.7:4222"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			provider := servedIdentity(c.servers, certPEM)
			_, opts, err := natsConnectOptions(NATSAuth{ChainIdentity: provider, RequireServerTLS: true})
			if err != nil {
				t.Fatal(err)
			}
			state := presented(t, certPEM)
			state.ServerName = ""
			err = applyOptions(t, opts).TLSConfig.VerifyConnection(state)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
		})
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
