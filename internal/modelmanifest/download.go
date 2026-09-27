package modelmanifest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// MaxRedirects bounds the redirect hops followed for one request.
	MaxRedirects = 3

	defaultConnectTimeout = 5 * time.Second
	defaultTotalTimeout   = 30 * time.Second
	defaultMaxAttempts    = 2
	// gzipOverhead lets an incompressible body carry its gzip framing.
	gzipOverhead = 64 << 10
)

// Resolver looks up a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a TCP connection. The downloader only ever passes an IP
// literal address that it has already checked.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DownloaderConfig bounds one download. Zero values take the defaults.
type DownloaderConfig struct {
	// ConnectTimeout bounds each TCP connect and TLS handshake.
	ConnectTimeout time.Duration
	// TotalTimeout bounds a whole download, every attempt and redirect hop
	// included.
	TotalTimeout time.Duration
	// MaxAttempts is how many times a transient failure (network error, 429
	// or 5xx) is tried in total.
	MaxAttempts int
	// Resolver and Dial replace the system resolver and dialer; tests use
	// them to stand in for DNS and the network.
	Resolver Resolver
	Dial     DialFunc
	// RootCAs replaces the system roots for TLS verification.
	RootCAs *x509.CertPool
}

// Downloader fetches a manifest over HTTPS without letting the URL steer the
// request into the operator's own network:
//
//   - only https is fetched, and a redirect to any other scheme is refused;
//   - the host is resolved by the downloader, every returned address is
//     checked (see checkPublicAddr), and the connection goes to that checked
//     IP through a dialer that never resolves a name again, so a DNS answer
//     cannot change between the check and the connect;
//   - TLS still verifies the certificate against the original host name;
//   - every attempt and every redirect hop resolves and checks again, and at
//     most MaxRedirects hops are followed;
//   - no proxy is used, since a proxy would do its own resolution;
//   - the body is bounded to MaxManifestBytes by Content-Length and by the
//     bytes actually read, after gzip decoding; any other content encoding
//     is refused.
type Downloader struct {
	cfg DownloaderConfig
}

func NewDownloader(cfg DownloaderConfig) *Downloader {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	if cfg.TotalTimeout <= 0 {
		cfg.TotalTimeout = defaultTotalTimeout
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{}).DialContext
	}
	return &Downloader{cfg: cfg}
}

// Get downloads rawURL, which must be https.
func (d *Downloader) Get(ctx context.Context, rawURL string) ([]byte, error) {
	return d.get(ctx, rawURL, false)
}

// getTrusted downloads from an operator-configured origin, such as a local
// IPFS gateway. Only the first hop to that origin skips the address check,
// and plain http is allowed there only for a loopback host. Redirects away
// from it are checked like any other.
func (d *Downloader) getTrusted(ctx context.Context, rawURL string) ([]byte, error) {
	return d.get(ctx, rawURL, true)
}

func (d *Downloader) get(ctx context.Context, rawURL string, trusted bool) ([]byte, error) {
	start, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse download URL: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, d.cfg.TotalTimeout)
	defer cancel()
	var lastErr error
	for attempt := 1; attempt <= d.cfg.MaxAttempts; attempt++ {
		body, err := d.follow(ctx, start, trusted)
		if err == nil {
			return body, nil
		}
		lastErr = err
		var transient *transientError
		if !errors.As(err, &transient) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// transientError marks a failure worth another attempt.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func (d *Downloader) follow(ctx context.Context, current *url.URL, trusted bool) ([]byte, error) {
	for hop := 0; ; hop++ {
		response, err := d.roundTrip(ctx, current, trusted && hop == 0)
		if err != nil {
			return nil, err
		}
		switch response.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			location := response.Header.Get("Location")
			response.Body.Close()
			if hop >= MaxRedirects {
				return nil, fmt.Errorf("more than %d redirects", MaxRedirects)
			}
			next, err := current.Parse(location)
			if err != nil || location == "" {
				return nil, fmt.Errorf("redirect from %s has an invalid Location %q", current.Redacted(), location)
			}
			current = next
			continue
		case http.StatusOK:
			defer response.Body.Close()
			return readBoundedBody(response)
		default:
			response.Body.Close()
			err := fmt.Errorf("%s answered %s", current.Redacted(), response.Status)
			if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
				return nil, &transientError{err}
			}
			return nil, err
		}
	}
}

// roundTrip sends one GET to target, connecting only to an address it has
// just resolved and checked.
func (d *Downloader) roundTrip(ctx context.Context, target *url.URL, trusted bool) (*http.Response, error) {
	host := target.Hostname()
	if target.User != nil || host == "" {
		return nil, fmt.Errorf("download URL %s must have a host and no userinfo", target.Redacted())
	}
	switch {
	case target.Scheme == "https":
	case target.Scheme == "http" && trusted && isLoopbackHost(host):
	default:
		return nil, fmt.Errorf("download URL %s is not https", target.Redacted())
	}
	port := target.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[target.Scheme]
	}
	addr, err := d.resolve(ctx, host, trusted)
	if err != nil {
		return nil, err
	}
	dialAddress := net.JoinHostPort(addr.String(), port)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, d.cfg.ConnectTimeout)
			defer cancel()
			return d.cfg.Dial(ctx, network, dialAddress)
		},
		// ServerName is the original host, never the dialed IP.
		TLSClientConfig:     &tls.Config{ServerName: host, RootCAs: d.cfg.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: d.cfg.ConnectTimeout,
		DisableCompression:  true,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "gzip")
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		// A certificate that does not match the host will not start
		// matching on retry; anything else on the wire may be transient.
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return nil, fmt.Errorf("fetch %s: %w", target.Redacted(), err)
		}
		return nil, &transientError{fmt.Errorf("fetch %s via %s: %w", target.Redacted(), dialAddress, err)}
	}
	return response, nil
}

// resolve returns the address to dial for host. Every address the name
// resolves to must pass the check; a mixed answer is refused as a whole.
func (d *Downloader) resolve(ctx context.Context, host string, trusted bool) (netip.Addr, error) {
	var addrs []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{literal}
	} else {
		resolved, err := d.cfg.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return netip.Addr{}, &transientError{fmt.Errorf("resolve %s: %w", host, err)}
		}
		addrs = resolved
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	if !trusted {
		for _, addr := range addrs {
			if err := checkPublicAddr(addr); err != nil {
				return netip.Addr{}, fmt.Errorf("host %s resolves to %s: %w", host, addr, err)
			}
		}
	}
	return addrs[0].Unmap(), nil
}

// blockedPrefixes are special-purpose ranges that netip's predicates do not
// cover. Cloud metadata endpoints fall inside the checked ranges:
// 169.254.169.254 and 169.254.170.2 are link-local, 100.100.100.200 is in
// shared address space, and fd00:ec2::254 is a unique local address.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // shared address space (carrier-grade NAT)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, including broadcast
	netip.MustParsePrefix("::/96"),          // IPv4-compatible IPv6
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64, embeds an IPv4 address
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo, embeds an IPv4 address
	netip.MustParsePrefix("2002::/16"),      // 6to4, embeds an IPv4 address
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
}

// checkPublicAddr refuses loopback, private, link-local, unspecified,
// multicast, metadata and other special-purpose addresses, for IPv4 and IPv6.
// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
func checkPublicAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid():
		return errors.New("invalid address")
	case addr.Zone() != "":
		return errors.New("scoped address")
	case addr.IsUnspecified():
		return errors.New("unspecified address")
	case addr.IsLoopback():
		return errors.New("loopback address")
	case addr.IsPrivate():
		return errors.New("private address")
	case addr.IsLinkLocalUnicast():
		return errors.New("link-local address (including cloud metadata)")
	case addr.IsMulticast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		return errors.New("multicast address")
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("special-purpose address in %s", prefix)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// readBoundedBody reads at most MaxManifestBytes of decoded body. A declared
// length over the limit is refused before reading; a gzip body is bounded
// both as sent and after decoding.
func readBoundedBody(response *http.Response) ([]byte, error) {
	encoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	declaredLimit := int64(MaxManifestBytes)
	if encoding == "gzip" {
		declaredLimit += gzipOverhead
	}
	if response.ContentLength > declaredLimit {
		return nil, fmt.Errorf("declared body of %d bytes is above max_manifest_bytes %d", response.ContentLength, MaxManifestBytes)
	}
	var reader io.Reader
	switch encoding {
	case "", "identity":
		reader = response.Body
	case "gzip":
		decoded, err := gzip.NewReader(io.LimitReader(response.Body, MaxManifestBytes+gzipOverhead))
		if err != nil {
			return nil, fmt.Errorf("gzip body: %w", err)
		}
		defer decoded.Close()
		reader = decoded
	default:
		return nil, fmt.Errorf("content encoding %q is not accepted", encoding)
	}
	var body bytes.Buffer
	if _, err := io.Copy(&body, io.LimitReader(reader, MaxManifestBytes+1)); err != nil {
		return nil, &transientError{fmt.Errorf("read body: %w", err)}
	}
	if body.Len() > MaxManifestBytes {
		return nil, fmt.Errorf("body is above max_manifest_bytes %d", MaxManifestBytes)
	}
	return body.Bytes(), nil
}
