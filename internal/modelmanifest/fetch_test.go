package modelmanifest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// routes serves fixed bodies by path and records what was requested.
type routes struct {
	mu        sync.Mutex
	bodies    map[string][]byte
	requested []string
}

func (r *routes) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	r.requested = append(r.requested, request.URL.Path)
	body, ok := r.bodies[request.URL.Path]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, request)
		return
	}
	w.Write(body)
}

func (r *routes) paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requested...)
}

// withURI returns chain with its registered manifest_uri set to uri.
func withURI(chain chainclient.CurrentModelProfileSnapshot, uri string) chainclient.CurrentModelProfileSnapshot {
	chain.Profile.ManifestURI = uri
	return chain
}

func newTestFetcher(t *testing.T, bodies map[string][]byte, cfg FetcherConfig) (*Fetcher, *routes) {
	t.Helper()
	server := &routes{bodies: bodies}
	downloader, _ := newTestDownloader(t, server, nil, DownloaderConfig{MaxAttempts: 1})
	fetcher, err := NewFetcher(cfg, downloader)
	if err != nil {
		t.Fatal(err)
	}
	return fetcher, server
}

func TestFetchPrefersAVerifiedCache(t *testing.T) {
	body, _, chain := goldenChain(t)
	cache := t.TempDir()
	if err := os.WriteFile(filepath.Join(cache, chain.Profile.ManifestHash.Hex()+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	fetcher, server := newTestFetcher(t, nil, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/mirror"}})
	fetched, err := fetcher.Fetch(context.Background(), withURI(chain, "https://example.com/m.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Source != "cache" || len(server.paths()) != 0 {
		t.Fatalf("source %s, requests %v", fetched.Source, server.paths())
	}
}

// Order is cache, then manifest_uri, then mirrors, and the hash is checked at
// each: a stale cache entry and a wrong manifest_uri body are skipped, the
// mirror's verified copy is used and then cached.
func TestFetchFallsThroughInOrderAndRechecksTheHash(t *testing.T) {
	body, _, chain := goldenChain(t)
	hashHex := chain.Profile.ManifestHash.Hex()
	cache := t.TempDir()
	cached := filepath.Join(cache, hashHex+".json")
	if err := os.WriteFile(cached, []byte(`{"stale":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fetcher, server := newTestFetcher(t, map[string][]byte{
		"/m.json":            []byte(`{"not":"it"}`),
		"/mirror/" + hashHex: body,
	}, FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/empty", "https://example.com/mirror/"}})
	fetched, err := fetcher.Fetch(context.Background(), withURI(chain, "https://example.com/m.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Source != "mirror https://example.com/mirror/"+hashHex {
		t.Fatalf("source %s", fetched.Source)
	}
	want := []string{"/m.json", "/empty/" + hashHex, "/mirror/" + hashHex}
	if got := server.paths(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("requested %v, want %v", got, want)
	}
	if stored, err := os.ReadFile(cached); err != nil || !bytes.Equal(stored, body) {
		t.Fatalf("verified manifest was not cached: %v", err)
	}
}

// Bytes the chain committed to that fail verification are invalid wherever
// they come from, so no further source is tried and nothing is cached.
func TestFetchStopsOnACommittedInvalidManifest(t *testing.T) {
	body, _, chain := goldenChain(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", " "); err != nil {
		t.Fatal(err)
	}
	chain.Profile.ManifestHash = hashBytes(pretty.Bytes())
	cache := t.TempDir()
	fetcher, server := newTestFetcher(t, map[string][]byte{"/m.json": pretty.Bytes()},
		FetcherConfig{CacheDir: cache, Mirrors: []string{"https://example.com/mirror"}})
	if _, err := fetcher.Fetch(context.Background(), withURI(chain, "https://example.com/m.json")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	if got := server.paths(); len(got) != 1 {
		t.Fatalf("requested %v after an invalid committed manifest", got)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Fatalf("invalid manifest was cached: %v", entries)
	}
}

func TestFetchReportsEverySourceWhenNoneHasTheManifest(t *testing.T) {
	_, _, chain := goldenChain(t)
	fetcher, _ := newTestFetcher(t, nil, FetcherConfig{Mirrors: []string{"https://example.com/mirror"}})
	_, err := fetcher.Fetch(context.Background(), withURI(chain, "https://example.com/m.json"))
	if err == nil || !strings.Contains(err.Error(), "manifest_uri https://example.com/m.json") || !strings.Contains(err.Error(), "mirror https://example.com/mirror/") {
		t.Fatalf("error does not name every source: %v", err)
	}
	unconfigured, _ := newTestFetcher(t, nil, FetcherConfig{})
	if _, err := unconfigured.Fetch(context.Background(), withURI(chain, "")); err == nil || !strings.Contains(err.Error(), "no cache, manifest_uri or mirror") {
		t.Fatalf("unconfigured fetch: %v", err)
	}
}

func TestFetchRefusesAnInvalidManifestURI(t *testing.T) {
	_, _, chain := goldenChain(t)
	fetcher, server := newTestFetcher(t, nil, FetcherConfig{})
	for _, uri := range []string{"http://example.com/m.json", "https://example.com/m.json#x", "https://Example.com/m.json"} {
		if _, err := fetcher.Fetch(context.Background(), withURI(chain, uri)); err == nil {
			t.Errorf("%s was fetched", uri)
		}
	}
	if len(server.paths()) != 0 {
		t.Fatalf("invalid URIs reached the network: %v", server.paths())
	}
}

func TestFetchUsesOnlyTheConfiguredIPFSGateway(t *testing.T) {
	body, _, chain := goldenChain(t)
	const cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	uri := "ipfs://" + cid + "/manifests/golden.json"

	without, _ := newTestFetcher(t, nil, FetcherConfig{})
	if _, err := without.Fetch(context.Background(), withURI(chain, uri)); err == nil || !strings.Contains(err.Error(), "IPFS gateway") {
		t.Fatalf("ipfs:// without a gateway: %v", err)
	}

	// A local gateway on loopback over plain http is the operator's own.
	gateway := &routes{bodies: map[string][]byte{"/ipfs/" + cid + "/manifests/golden.json": body}}
	server := httptest.NewServer(gateway)
	defer server.Close()
	fetcher, err := NewFetcher(FetcherConfig{IPFSGateway: server.URL + "/"}, NewDownloader(DownloaderConfig{MaxAttempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := fetcher.Fetch(context.Background(), withURI(chain, uri))
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Manifest == nil || len(gateway.paths()) != 1 {
		t.Fatalf("gateway requests %v", gateway.paths())
	}
}

func TestNewFetcherValidatesItsSources(t *testing.T) {
	for name, cfg := range map[string]FetcherConfig{
		"http mirror":            {Mirrors: []string{"http://mirror.example/m"}},
		"mirror with query":      {Mirrors: []string{"https://mirror.example/m?x=1"}},
		"public http gateway":    {IPFSGateway: "http://gateway.example"},
		"gateway with userinfo":  {IPFSGateway: "https://user@gateway.example"},
		"gateway without a host": {IPFSGateway: "https://"},
	} {
		if _, err := NewFetcher(cfg, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, cfg := range map[string]FetcherConfig{
		"https gateway":      {IPFSGateway: "https://gateway.example"},
		"local http gateway": {IPFSGateway: "http://127.0.0.1:8080"},
		"localhost gateway":  {IPFSGateway: "http://localhost:8080"},
		"https mirror":       {Mirrors: []string{"https://mirror.example/by-hash"}},
	} {
		if _, err := NewFetcher(cfg, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
