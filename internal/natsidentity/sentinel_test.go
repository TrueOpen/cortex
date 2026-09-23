package natsidentity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// fakeSentinelSource is the sentinel source the Binder tests use.
type fakeSentinelSource struct {
	mu          sync.Mutex
	sentinel    Sentinel
	err         error
	calls       int
	invalidated int
}

func newFakeSentinel() *fakeSentinelSource {
	return &fakeSentinelSource{sentinel: Sentinel{
		AuthAccountPublicKey: "ADBUILDERAUTHACCOUNT",
		JWT:                  "eyJ.sentinel.one",
	}}
}

func (f *fakeSentinelSource) Sentinel(context.Context) (Sentinel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return Sentinel{}, f.err
	}
	return f.sentinel, nil
}

func (f *fakeSentinelSource) Invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated++
}

func (f *fakeSentinelSource) invalidateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.invalidated
}

// staticIngress is a fixed set of candidate Builder ingresses.
type staticIngress struct {
	candidates []BuilderIngress
	err        error
}

func (s staticIngress) ResolveIngresses(context.Context) ([]BuilderIngress, error) {
	return s.candidates, s.err
}

// oneIngress is the common shape: a single candidate.
func oneIngress(endpoint, pin string) staticIngress {
	return staticIngress{candidates: []BuilderIngress{{Operator: "trueopen1builderone", Endpoint: endpoint, TLSPubkeyHash: pin}}}
}

// newTestSentinelJWT mints a real bearer user JWT, issued by an AUTH account key.
func newTestSentinelJWT(t *testing.T, bearer bool) (account string, token string) {
	t.Helper()
	accountKey, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	account, err = accountKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := userKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.NewUserClaims(userPub)
	claims.Name = "sentinel"
	claims.BearerToken = bearer
	token, err = claims.Encode(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	return account, token
}

// sentinelServer starts a TLS ingress stand-in and returns its address, its
// certificate pin and the paths it was asked for.
func sentinelServer(t *testing.T, handler http.HandlerFunc) (endpoint string, pin string, paths *[]string) {
	t.Helper()
	seen := make([]string, 0, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	leaf := server.Certificate()
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return server.URL, hex.EncodeToString(sum[:]), &seen
}

func sentinelJSON(t *testing.T, account, token string) string {
	t.Helper()
	return fmt.Sprintf(`{"schema_version":1,"auth_account_public_key":%q,"sentinel_jwt":%q}`, account, token)
}

// The normal path: over the link pinned by tls_pubkey_hash, fetch the sentinel and
// cache it; the request lands on the agreed /v1/nats/sentinel.
func TestIngressSentinelSourceFetchesAndCaches(t *testing.T) {
	account, token := newTestSentinelJWT(t, true)
	endpoint, pin, paths := sentinelServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sentinelJSON(t, account, token)))
	})
	source, err := NewIngressSentinelSource(oneIngress(endpoint, pin), nil)
	if err != nil {
		t.Fatal(err)
	}
	sentinel, err := source.Sentinel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sentinel.JWT != token || sentinel.AuthAccountPublicKey != account {
		t.Fatalf("sentinel = %+v", sentinel)
	}
	if _, err := source.Sentinel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*paths) != 1 || (*paths)[0] != SentinelPath {
		t.Fatalf("requests = %v, want one GET %s (the second call is served from cache)", *paths, SentinelPath)
	}
	source.Invalidate()
	if _, err := source.Sentinel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*paths) != 2 {
		t.Fatalf("invalidate must force a re-fetch, requests = %v", *paths)
	}
}

// A wrong pin must yield nothing: the same tls_pubkey_hash check the task-data
// client performs.
func TestIngressSentinelSourceRefusesOnTLSPinMismatch(t *testing.T) {
	account, token := newTestSentinelJWT(t, true)
	endpoint, _, _ := sentinelServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sentinelJSON(t, account, token)))
	})
	wrongPin := "cc" + hex.EncodeToString(make([]byte, 31))
	source, err := NewIngressSentinelSource(oneIngress(endpoint, wrongPin), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Sentinel(context.Background())
	if err == nil || !errors.Is(err, builderclient.ErrTLSPubkeyMismatch) {
		t.Fatalf("a mismatched descriptor pin must refuse the fetch, got %v", err)
	}
}

// A 404 is the Builder saying outright "I have no sentinel": fail closed, do not
// guess, and do not fall back to a connection without a jwt.
func TestIngressSentinelSourceRefusesWhenBuilderHasNone(t *testing.T) {
	endpoint, pin, _ := sentinelServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"nats auth callout is not configured"}`))
	})
	source, err := NewIngressSentinelSource(oneIngress(endpoint, pin), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Sentinel(context.Background())
	if !errors.Is(err, ErrNoSentinel) {
		t.Fatalf("404 must map to ErrNoSentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "nats auth callout is not configured") {
		t.Fatalf("the server's reason must survive into the error: %v", err)
	}
}

func TestIngressSentinelSourceRefusesUnusableSentinels(t *testing.T) {
	bearerAccount, bearerToken := newTestSentinelJWT(t, true)
	_, nonBearerToken := newTestSentinelJWT(t, false)
	otherAccount, _ := newTestSentinelJWT(t, true)
	cases := []struct {
		name string
		body string
	}{
		{"unknown schema version", fmt.Sprintf(`{"schema_version":2,"auth_account_public_key":%q,"sentinel_jwt":%q}`, bearerAccount, bearerToken)},
		{"not a bearer token", sentinelJSON(t, bearerAccount, nonBearerToken)},
		{"account is not an account nkey", sentinelJSON(t, "not-an-nkey", bearerToken)},
		{"account does not match the issuer", sentinelJSON(t, otherAccount, bearerToken)},
		{"jwt is not a user jwt", sentinelJSON(t, bearerAccount, "eyJ.not.a.jwt")},
		{"no jwt", fmt.Sprintf(`{"schema_version":1,"auth_account_public_key":%q,"sentinel_jwt":""}`, bearerAccount)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, pin, _ := sentinelServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			source, err := NewIngressSentinelSource(oneIngress(endpoint, pin), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Sentinel(context.Background()); err == nil {
				t.Fatal("expected the sentinel to be refused")
			}
		})
	}
}

func TestIngressSentinelSourceRequiresAResolver(t *testing.T) {
	if _, err := NewIngressSentinelSource(nil, nil); err == nil {
		t.Fatal("a sentinel source without a Builder resolver must be refused")
	}
}

func TestIngressSentinelSourcePropagatesResolverFailure(t *testing.T) {
	source, err := NewIngressSentinelSource(staticIngress{err: errors.New("no active builder")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Sentinel(context.Background()); err == nil || !strings.Contains(err.Error(), "no active builder") {
		t.Fatalf("resolver failure must reach the caller, got %v", err)
	}
}

// The earlier member of the BuilderSet is unusable (a plaintext endpoint is out
// already at the resolve stage) and the later one serves normally: the bad one
// must be skipped for the good one rather than stopping at the first.
func TestIngressSentinelSourceSkipsUnusableBuilders(t *testing.T) {
	account, token := newTestSentinelJWT(t, true)
	endpoint, pin, paths := sentinelServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sentinelJSON(t, account, token)))
	})
	source, err := NewIngressSentinelSource(staticIngress{candidates: []BuilderIngress{
		{Operator: "trueopen1plaintext", Err: errors.New("ingress http://127.0.0.1:8081 is plaintext: set nexus.allow_insecure_descriptor to accept it")},
		{Operator: "trueopen1nexusone", Endpoint: endpoint, TLSPubkeyHash: pin},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sentinel, err := source.Sentinel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sentinel.JWT != token {
		t.Fatalf("sentinel = %+v, want the one the second Builder served", sentinel)
	}
	if len(*paths) != 1 {
		t.Fatalf("requests = %v, want exactly the working Builder to be dialled", *paths)
	}
}

// Everything fails: one error has to spell out why each candidate failed,
// otherwise the operator only sees "they all failed".
func TestIngressSentinelSourceAggregatesEveryFailure(t *testing.T) {
	endpoint, pin, _ := sentinelServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"nats auth callout is not configured"}`))
	})
	source, err := NewIngressSentinelSource(staticIngress{candidates: []BuilderIngress{
		{Operator: "trueopen1plaintext", Err: errors.New("is plaintext")},
		{Operator: "trueopen1nosentinel", Endpoint: endpoint, TLSPubkeyHash: pin},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Sentinel(context.Background())
	if err == nil {
		t.Fatal("expected every candidate to be refused")
	}
	for _, want := range []string{"no builder served a nats sentinel", "trueopen1plaintext: is plaintext", "trueopen1nosentinel", "nats auth callout is not configured"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// No candidate at all: say so, rather than returning an empty sentinel.
func TestIngressSentinelSourceRefusesAnEmptyCandidateList(t *testing.T) {
	source, err := NewIngressSentinelSource(staticIngress{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Sentinel(context.Background()); err == nil {
		t.Fatal("no candidate must be an error")
	}
}
