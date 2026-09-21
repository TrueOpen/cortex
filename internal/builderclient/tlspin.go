package builderclient

// Checking a Builder's (nexus's) TLS certificate against the tls_pubkey_hash in its
// on-chain descriptor.
//
// nexus terminates TLS itself with a self-signed certificate;
// ServiceEndpointV1.tls_pubkey_hash is the sha256 of that certificate's public key
// (SubjectPublicKeyInfo DER), registered on chain with the descriptor by the Builder's
// operator (monorepo ADR-0015). The client accepts that one public key and does not
// care who issued the certificate, so a pinned dial validates no CA chain: it compares
// the public key hash once the handshake completes and before a single request byte
// goes out, and disconnects immediately on a mismatch. An https endpoint with no pin
// still validates its CA chain, with no downgrade.
//
// The pin reaches the transport through the context: the task-data client's methods
// take an endpoint string only, while the pin is a property of the Builder descriptor,
// so the caller that resolved the endpoint puts it into ctx alongside.
//
// The connection pool is split by pin. http.Transport reuses connections by host:port
// alone, so with one pool shared by every pin a keep-alive connection established under
// the correct pin would be reused directly by a later request carrying another pin (or
// none), bypassing the check made at dial time - which is exactly how checking against
// a real nexus failed.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sync"
)

// ErrTLSPubkeyMismatch reports a Builder that presented a certificate whose
// public key is not the one its on-chain descriptor commits.
var ErrTLSPubkeyMismatch = errors.New("nexus TLS certificate public key does not match the tls_pubkey_hash the descriptor commits")

var tlsPubkeyHashHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type tlsPubkeyHashKey struct{}

// WithTLSPubkeyHash carries the descriptor pin (64 lowercase hex) for every
// dial made under ctx. An empty or malformed value carries nothing, so a
// caller that forgot to resolve the pin does not accidentally pin to garbage.
func WithTLSPubkeyHash(ctx context.Context, hashHex string) context.Context {
	if !tlsPubkeyHashHex.MatchString(hashHex) {
		return ctx
	}
	return context.WithValue(ctx, tlsPubkeyHashKey{}, hashHex)
}

// TLSPubkeyHashFromContext returns the fingerprint WithTLSPubkeyHash put into ctx.
func TLSPubkeyHashFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(tlsPubkeyHashKey{}).(string)
	return value, ok && value != ""
}

// TLSPubkeyHash is hex(sha256(SubjectPublicKeyInfo DER)) of a certificate, the
// value nexus publishes as tls_pubkey_hash.
func TLSPubkeyHash(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// pinnedDialTLSContext returns a TLS dialer that verifies the presented leaf's
// public key hash against expected instead of the CA chain.
func pinnedDialTLSContext(base *tls.Config, expected string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		config := base.Clone()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if config.ServerName == "" {
			config.ServerName = host
		}
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("%w: peer presented no certificate", ErrTLSPubkeyMismatch)
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("%w: parse peer certificate: %v", ErrTLSPubkeyMismatch, err)
			}
			if got := TLSPubkeyHash(leaf); got != expected {
				return fmt.Errorf("%w: %s presented %s, descriptor commits %s", ErrTLSPubkeyMismatch, host, got, expected)
			}
			return nil
		}
		dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
		return dialer.DialContext(ctx, network, addr)
	}
}

// pinRouter is the http.RoundTripper newNexusHTTPClient installs: one
// http.Transport (and therefore one connection pool) per distinct pin, plus the
// unpinned base transport with the standard CA verification. A request picks
// its transport by the pin in its context, so a keep-alive connection verified
// under one pin can never serve a request that asked for another.
type pinRouter struct {
	base *http.Transport

	mu     sync.Mutex
	pinned map[string]*http.Transport
}

func newPinRouter(base *http.Transport) *pinRouter {
	return &pinRouter{base: base, pinned: make(map[string]*http.Transport)}
}

func (r *pinRouter) RoundTrip(request *http.Request) (*http.Response, error) {
	pin, pinned := TLSPubkeyHashFromContext(request.Context())
	if !pinned {
		return r.base.RoundTrip(request)
	}
	return r.transportFor(pin).RoundTrip(request)
}

func (r *pinRouter) transportFor(pin string) *http.Transport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if transport, ok := r.pinned[pin]; ok {
		return transport
	}
	transport := r.base.Clone()
	transport.DialTLSContext = pinnedDialTLSContext(transport.TLSClientConfig, pin)
	r.pinned[pin] = transport
	return transport
}

// CloseIdleConnections mirrors http.Transport so http.Client.CloseIdleConnections
// reaches every pool.
func (r *pinRouter) CloseIdleConnections() {
	r.base.CloseIdleConnections()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, transport := range r.pinned {
		transport.CloseIdleConnections()
	}
}
