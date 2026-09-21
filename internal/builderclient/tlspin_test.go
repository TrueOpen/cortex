package builderclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The on-chain tls_pubkey_hash = sha256(certificate SubjectPublicKeyInfo DER), the
// same algorithm the nexus side uses.
func TestTLSPubkeyHashIsSHA256OfSubjectPublicKeyInfo(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	leaf := server.Certificate()
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if got, want := TLSPubkeyHash(leaf), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("TLSPubkeyHash = %s, want %s", got, want)
	}
}

// Dialling with the on-chain hash: a self-signed certificate connects, and what is
// checked is the public key rather than a CA chain.
func TestNexusHTTPClientConnectsWhenPubkeyHashMatches(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := newNexusHTTPClient(nil, nexusDataTimeout)
	ctx := WithTLSPubkeyHash(context.Background(), TLSPubkeyHash(server.Certificate()))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("pinned GET: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("status = %d, hits = %d", response.StatusCode, hits.Load())
	}
}

// A hash mismatch: disconnect right after the handshake, without sending the peer a
// single byte of the request.
func TestNexusHTTPClientRefusesPubkeyHashMismatchBeforeSendingAnything(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	client := newNexusHTTPClient(nil, nexusDataTimeout)
	ctx := WithTLSPubkeyHash(context.Background(), strings.Repeat("ab", 32))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	if err == nil || !errors.Is(err, ErrTLSPubkeyMismatch) {
		t.Fatalf("err = %v, want ErrTLSPubkeyMismatch", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("server handled %d requests after a pin mismatch", hits.Load())
	}
}

// After one successful connection with the correct pin on the same client, a later
// request with a wrong pin or no pin must not reuse that keep-alive connection to
// bypass the check: the connection pool has to be split by pin. This is exactly what
// cross-implementation checking against a real nexus exposed.
func TestNexusHTTPClientDoesNotReuseAPinnedConnectionAcrossPins(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	client := newNexusHTTPClient(nil, nexusDataTimeout)
	get := func(ctx context.Context) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		return nil
	}
	right := WithTLSPubkeyHash(context.Background(), TLSPubkeyHash(server.Certificate()))
	if err := get(right); err != nil {
		t.Fatalf("first pinned GET: %v", err)
	}
	if err := get(WithTLSPubkeyHash(context.Background(), strings.Repeat("ab", 32))); !errors.Is(err, ErrTLSPubkeyMismatch) {
		t.Fatalf("wrong pin after a pinned connection exists: err = %v, want ErrTLSPubkeyMismatch", err)
	}
	if err := get(context.Background()); err == nil {
		t.Fatal("no pin after a pinned connection exists must fall back to CA verification and fail")
	}
	if err := get(right); err != nil {
		t.Fatalf("correct pin still works afterwards: %v", err)
	}
}

// No on-chain hash: no downgrade, ordinary CA chain validation, and a self-signed
// certificate is refused.
func TestNexusHTTPClientWithoutPinKeepsCAVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()

	client := newNexusHTTPClient(nil, nexusDataTimeout)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); err == nil {
		t.Fatal("self-signed server must be refused without a pin")
	}
}

// A transport injected by the caller is left as it is (that is how the test's trusted
// root gets in) and is never overwritten.
func TestNexusHTTPClientKeepsInjectedTransportEvenWithPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()

	client := newNexusHTTPClient(server.Client(), nexusDataTimeout)
	ctx := WithTLSPubkeyHash(context.Background(), strings.Repeat("ab", 32))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("injected transport must be kept: %v", err)
	}
	response.Body.Close()
}

func TestWithTLSPubkeyHashRejectsMalformedValues(t *testing.T) {
	for _, bad := range []string{"", "xyz", strings.Repeat("A", 64), strings.Repeat("0", 63)} {
		if _, ok := TLSPubkeyHashFromContext(WithTLSPubkeyHash(context.Background(), bad)); ok {
			t.Fatalf("%q must not be carried as a pin", bad)
		}
	}
	if got, ok := TLSPubkeyHashFromContext(WithTLSPubkeyHash(context.Background(), strings.Repeat("0a", 32))); !ok || got != strings.Repeat("0a", 32) {
		t.Fatalf("well-formed pin dropped: %q %v", got, ok)
	}
}
