package modelmanifest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// publicIP stands in for a public address; the test dialer routes it to the
// local httptest server. The httptest certificate is valid for example.com.
const (
	publicIP = "93.184.216.34"
	testHost = "example.com"
)

// fakeNet answers DNS from a script and records every dial.
type fakeNet struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr // host -> answer per lookup, last one repeats
	lookups map[string]int
	dials   []string
	server  string // real address of the httptest server
}

func (n *fakeNet) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	script, ok := n.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	index := n.lookups[host]
	n.lookups[host]++
	if index >= len(script) {
		index = len(script) - 1
	}
	return script[index], nil
}

func (n *fakeNet) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	n.mu.Lock()
	n.dials = append(n.dials, address)
	n.mu.Unlock()
	host, _, _ := net.SplitHostPort(address)
	if host == publicIP {
		address = n.server
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (n *fakeNet) dialed() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dials...)
}

func addrs(values ...string) []netip.Addr {
	out := make([]netip.Addr, len(values))
	for index, value := range values {
		out[index] = netip.MustParseAddr(value)
	}
	return out
}

// newTestDownloader serves handler over TLS and resolves testHost to
// publicIP unless answers says otherwise.
func newTestDownloader(t *testing.T, handler http.Handler, answers map[string][][]netip.Addr, cfg DownloaderConfig) (*Downloader, *fakeNet) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	if answers == nil {
		answers = map[string][][]netip.Addr{testHost: {addrs(publicIP)}}
	}
	network := &fakeNet{answers: answers, lookups: map[string]int{}, server: server.Listener.Addr().String()}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	cfg.Resolver, cfg.Dial, cfg.RootCAs = network, network.Dial, roots
	return NewDownloader(cfg), network
}

func serveBytes(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(body) })
}

func TestDownloadFetchesOverHTTPSFromTheCheckedAddress(t *testing.T) {
	downloader, network := newTestDownloader(t, serveBytes([]byte("manifest")), nil, DownloaderConfig{})
	body, err := downloader.Get(context.Background(), "https://example.com/m.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "manifest" {
		t.Fatalf("body = %q", body)
	}
	if got := network.dialed(); len(got) != 1 || got[0] != publicIP+":443" {
		t.Fatalf("dialed %v, want only the checked address", got)
	}
}

func TestDownloadRefusesHTTP(t *testing.T) {
	downloader, network := newTestDownloader(t, serveBytes(nil), nil, DownloaderConfig{})
	if _, err := downloader.Get(context.Background(), "http://example.com/m.json"); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("http was fetched: %v", err)
	}
	if len(network.dialed()) != 0 {
		t.Fatal("http URL reached the network")
	}
}

func TestDownloadRefusesNonPublicAddresses(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "0.0.0.0", "169.254.169.254", "169.254.170.2",
		"100.100.100.200", "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.0.192",
		"::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "fec0::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:100.100.100.200", "::7f00:1",
		"64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
	} {
		t.Run(address, func(t *testing.T) {
			answers := map[string][][]netip.Addr{testHost: {addrs(address)}}
			downloader, network := newTestDownloader(t, serveBytes(nil), answers, DownloaderConfig{})
			if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil {
				t.Fatal("non-public address was fetched")
			}
			if len(network.dialed()) != 0 {
				t.Fatalf("dialed %v", network.dialed())
			}
		})
	}
}

func TestDownloadRefusesNonPublicIPLiterals(t *testing.T) {
	downloader, network := newTestDownloader(t, serveBytes(nil), nil, DownloaderConfig{})
	for _, target := range []string{"https://127.0.0.1/m.json", "https://[::1]/m.json", "https://[::ffff:10.0.0.1]/m.json", "https://169.254.169.254/latest"} {
		if _, err := downloader.Get(context.Background(), target); err == nil {
			t.Errorf("%s was fetched", target)
		}
	}
	if len(network.dialed()) != 0 {
		t.Fatalf("dialed %v", network.dialed())
	}
}

func TestDownloadRefusesAMixedDNSAnswer(t *testing.T) {
	answers := map[string][][]netip.Addr{testHost: {addrs(publicIP, "10.0.0.1")}}
	downloader, network := newTestDownloader(t, serveBytes(nil), answers, DownloaderConfig{})
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil {
		t.Fatal("mixed answer was fetched")
	}
	if len(network.dialed()) != 0 {
		t.Fatal("mixed answer reached the network")
	}
}

// A rebinding name answers public first and private after. The download
// resolves once per hop and dials the address it checked, so the second
// answer is never used.
func TestDownloadConnectsOnlyToTheAddressItChecked(t *testing.T) {
	answers := map[string][][]netip.Addr{testHost: {addrs(publicIP), addrs("127.0.0.1")}}
	downloader, network := newTestDownloader(t, serveBytes([]byte("ok")), answers, DownloaderConfig{})
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err != nil {
		t.Fatal(err)
	}
	if network.lookups[testHost] != 1 {
		t.Fatalf("resolved %d times for one hop", network.lookups[testHost])
	}
	if got := network.dialed(); len(got) != 1 || got[0] != publicIP+":443" {
		t.Fatalf("dialed %v", got)
	}
}

func TestDownloadRechecksEveryRedirectHop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/next", http.StatusFound) })
	mux.HandleFunc("/next", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	answers := map[string][][]netip.Addr{testHost: {addrs(publicIP), addrs("192.168.0.10")}}
	downloader, network := newTestDownloader(t, mux, answers, DownloaderConfig{})
	if _, err := downloader.Get(context.Background(), "https://example.com/start"); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("redirect to a rebound name was followed: %v", err)
	}
	if network.lookups[testHost] != 2 || len(network.dialed()) != 1 {
		t.Fatalf("lookups %d, dials %v", network.lookups[testHost], network.dialed())
	}
}

func TestDownloadRechecksEveryRetry(t *testing.T) {
	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	answers := map[string][][]netip.Addr{testHost: {addrs(publicIP), addrs("10.0.0.1")}}
	downloader, network := newTestDownloader(t, handler, answers, DownloaderConfig{MaxAttempts: 3})
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("retry reused a stale answer: %v", err)
	}
	if attempts != 1 || network.lookups[testHost] != 2 {
		t.Fatalf("attempts %d, lookups %d", attempts, network.lookups[testHost])
	}
}

func TestDownloadRetriesTransientFailures(t *testing.T) {
	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok"))
	})
	downloader, network := newTestDownloader(t, handler, nil, DownloaderConfig{MaxAttempts: 2})
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || network.lookups[testHost] != 2 {
		t.Fatalf("attempts %d, lookups %d", attempts, network.lookups[testHost])
	}
}

func TestDownloadDoesNotRetryANotFound(t *testing.T) {
	attempts := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { attempts++; http.NotFound(w, nil) })
	downloader, _ := newTestDownloader(t, handler, nil, DownloaderConfig{MaxAttempts: 3})
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil {
		t.Fatal("404 succeeded")
	}
	if attempts != 1 {
		t.Fatalf("404 was tried %d times", attempts)
	}
}

func TestDownloadFollowsAtMostThreeRedirects(t *testing.T) {
	mux := http.NewServeMux()
	// /0 -> /1 -> /2 -> /3 -> /4
	for hop := 0; hop < 4; hop++ {
		next := fmt.Sprintf("/%d", hop+1)
		mux.HandleFunc(fmt.Sprintf("/%d", hop), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, next, http.StatusTemporaryRedirect)
		})
	}
	mux.HandleFunc("/4", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	downloader, _ := newTestDownloader(t, mux, nil, DownloaderConfig{})
	if body, err := downloader.Get(context.Background(), "https://example.com/1"); err != nil || string(body) != "ok" {
		t.Fatalf("three redirects: %q %v", body, err)
	}
	if _, err := downloader.Get(context.Background(), "https://example.com/0"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("four redirects were followed: %v", err)
	}
}

func TestDownloadRefusesARedirectToHTTP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/m.json", http.StatusMovedPermanently)
	})
	downloader, network := newTestDownloader(t, handler, nil, DownloaderConfig{})
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("downgrade was followed: %v", err)
	}
	if len(network.dialed()) != 1 {
		t.Fatalf("dialed %v", network.dialed())
	}
}

// TLS verifies the certificate against the name in the URL, not the dialed
// address: the test certificate is not valid for other.example.
func TestDownloadVerifiesTLSAgainstTheOriginalHost(t *testing.T) {
	answers := map[string][][]netip.Addr{"other.example": {addrs(publicIP)}}
	downloader, network := newTestDownloader(t, serveBytes([]byte("ok")), answers, DownloaderConfig{MaxAttempts: 3})
	if _, err := downloader.Get(context.Background(), "https://other.example/m.json"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("certificate for another name was accepted: %v", err)
	}
	if len(network.dialed()) != 1 {
		t.Fatalf("certificate failure was retried: %v", network.dialed())
	}
}

func TestDownloadBoundsTheBody(t *testing.T) {
	oversize := bytes.Repeat([]byte("a"), MaxManifestBytes+1)
	var bomb bytes.Buffer
	writer := gzip.NewWriter(&bomb)
	writer.Write(oversize)
	writer.Close()
	var small bytes.Buffer
	writer = gzip.NewWriter(&small)
	writer.Write([]byte("decoded manifest"))
	writer.Close()
	flusher := func(w http.ResponseWriter) { w.(http.Flusher).Flush() }

	cases := map[string]struct {
		handler http.HandlerFunc
		want    string
		errText string
	}{
		"declared length over the limit": {handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "4194305")
			w.Write(oversize)
		}, errText: "declared body"},
		"undeclared length over the limit": {handler: func(w http.ResponseWriter, _ *http.Request) {
			flusher(w)
			w.Write(oversize)
		}, errText: "above max_manifest_bytes"},
		"gzip decoding over the limit": {handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(bomb.Bytes())
		}, errText: "above max_manifest_bytes"},
		"gzip within the limit": {handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(small.Bytes())
		}, want: "decoded manifest"},
		"other content encoding": {handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "br")
			w.Write([]byte("x"))
		}, errText: "not accepted"},
	}
	if bomb.Len() > MaxManifestBytes/100 {
		t.Fatalf("test bomb is not small when compressed: %d", bomb.Len())
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			downloader, _ := newTestDownloader(t, test.handler, nil, DownloaderConfig{})
			body, err := downloader.Get(context.Background(), "https://example.com/m.json")
			if test.errText != "" {
				if err == nil || !strings.Contains(err.Error(), test.errText) {
					t.Fatalf("expected %q, got %v", test.errText, err)
				}
				return
			}
			if err != nil || string(body) != test.want {
				t.Fatalf("body %q, err %v", body, err)
			}
		})
	}
}

func TestDownloadTotalTimeout(t *testing.T) {
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-release })
	downloader, _ := newTestDownloader(t, handler, nil, DownloaderConfig{TotalTimeout: 200 * time.Millisecond, MaxAttempts: 3})
	defer close(release)
	start := time.Now()
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil {
		t.Fatal("stalled server succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("total timeout took %s", elapsed)
	}
}

func TestDownloadConnectTimeout(t *testing.T) {
	downloader := NewDownloader(DownloaderConfig{
		ConnectTimeout: 100 * time.Millisecond, TotalTimeout: 5 * time.Second, MaxAttempts: 1,
		Resolver: &fakeNet{answers: map[string][][]netip.Addr{testHost: {addrs(publicIP)}}, lookups: map[string]int{}},
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	start := time.Now()
	if _, err := downloader.Get(context.Background(), "https://example.com/m.json"); err == nil {
		t.Fatal("unreachable host succeeded")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("connect timeout took %s", elapsed)
	}
}
