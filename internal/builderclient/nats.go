package builderclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"
)

const natsDedupHeader = nats.MsgIdHdr

type NATSMessage struct {
	Subject   string
	Header    http.Header
	Data      []byte
	JetStream bool
}

type MessageHandler func(context.Context, NATSMessage) error

type Subscription interface {
	Unsubscribe() error
}

type Subscriber interface {
	Subscribe(context.Context, string, MessageHandler) (Subscription, error)
}

// SubscriberErrors is implemented by subscribers that report delivery failures
// out of band. Core NATS is fire-and-forget: a handler error on an orders,
// handraise or prepare subject cannot be nak'd or redelivered, so this channel
// is the only trace such a message ever existed. It is an optional interface so
// test fakes are not forced to implement it.
type SubscriberErrors interface {
	Errors() <-chan error
}

// SubscriberDroppedErrors is implemented alongside SubscriberErrors when a
// non-blocking producer can lose reports under backpressure. The consumer
// swaps the count after every delivered error, so a burst is summarized even
// when no later producer call arrives to flush it.
type SubscriberDroppedErrors interface {
	TakeDroppedErrors() int64
}

type natsPublishTransport interface {
	Publish(context.Context, NATSMessage) error
}

type natsReadinessProbe interface {
	Probe(context.Context) error
}

var newNATSPublishTransport = newLazyNATSPublishTransport
var connectNATSPublishTransport = connectConcreteNATSPublishTransport
var connectNATSSubscriber = connectConcreteNATSSubscriber

// natsConnect is the seam over nats.Connect; tests use it to inject authentication
// failures.
var natsConnect = nats.Connect

// NATSAuth is the transport and authentication setting for connecting to NATS (the
// ADR-0016 transition state):
//   - ChainIdentity: the on-chain identity (decision three, interface-and-topic-list §5.14.2),
//     handshaking with CONNECT.jwt (the AUTH sentinel) + a nonce signature + the
//     binding declaration token; the only way in real mode, and CredsFile and Token
//     are ignored when it is present;
//   - CredsFile: NATS creds (user JWT + nkey seed), kept for dev, removed by ADR-0016 P5;
//   - Token: kept for dev, removed by ADR-0016 P5, ignored when creds are present;
//   - CAFile: the server certificate / CA PEM, used to validate the server on tls://;
//     the system root CAs are used when it is absent.
//
// With ChainIdentity, URL and CAFile may be left empty: the NATS address and the
// certificate then come from the Builder's sentinel response (§4.12). Configured
// values win. RequireServerTLS (real mode) makes a served address that is not
// tls:// fail, and a remote server with neither CAFile nor a served certificate
// fail, rather than fall back to the system roots.
//
// A tls:// URL requires TLS.
type NATSAuth struct {
	URL              string
	Token            string
	CredsFile        string
	CAFile           string
	ChainIdentity    ChainIdentityProvider
	RequireServerTLS bool
}

// natsConnectOptions resolves the URL to dial and the options for it. With a chain
// identity the credential is fetched first, since it may carry the address and the
// certificate.
func natsConnectOptions(auth NATSAuth) (string, []nats.Option, error) {
	var opts []nats.Option
	natsURL := strings.TrimSpace(auth.URL)
	servedCAPEM := ""
	if auth.ChainIdentity != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cred, err := auth.ChainIdentity.Credential(ctx)
		cancel()
		if err != nil {
			return "", nil, fmt.Errorf("nexus nats chain identity: %w", err)
		}
		natsURL, servedCAPEM, err = resolveServedNATS(auth, cred)
		if err != nil {
			return "", nil, err
		}
		if strings.TrimSpace(cred.SentinelJWT) == "" {
			// fail closed: an operator-mode server wants to see a user JWT of its own account
			// at the CONNECT stage, so without a sentinel do not even connect - otherwise the
			// reason hides behind a bare Authorization Violation from the server.
			return "", nil, fmt.Errorf("nexus nats chain identity: builder served no auth sentinel jwt; the operator-mode server refuses a CONNECT without one")
		}
		provider := auth.ChainIdentity
		// The signing function does not change within one connection: the user key does not
		// rotate with the binding. The last* values are read and written by two callbacks
		// that nats.go calls from the reconnect goroutine, so a lock keeps them from racing
		// the first connect.
		var mu sync.Mutex
		last := cred.Token
		lastJWT := cred.SentinelJWT
		opts = append(opts,
			// Present the AUTH account's sentinel user JWT (a bearer with no permissions,
			// public material) and sign the server's nonce with the local NATS user key.
			// nats.Nkey is not sent: nats.go refuses an nkey and a jwt together, and in
			// operator mode a CONNECT without a jwt never reaches the auth callback at all
			// (nats-server v2.10.22 server/auth.go:731-736). The server does not verify a
			// bearer JWT's sig - the auth callback does, against the nats_user_pubkey in the
			// binding declaration.
			nats.UserJWT(func() (string, error) {
				// The same constraint as TokenHandler: it runs on the connection path, is bounded
				// at 5s, and falls back to the previous sentinel when it cannot be fetched
				// (rotation is rare; an unreachable chain is the common case).
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				current, err := provider.Credential(ctx)
				mu.Lock()
				defer mu.Unlock()
				if err != nil || strings.TrimSpace(current.SentinelJWT) == "" {
					return lastJWT, nil
				}
				lastJWT = current.SentinelJWT
				return lastJWT, nil
			}, cred.SignNonce),
			// Fetch the current binding on every (re)connect: this is how a token rebuilt after
			// a service key rotation enters the next handshake. When it cannot be fetched the
			// previous token is reused - better refused than sent empty.
			nats.TokenHandler(func() string {
				// nats.go calls this callback on the connection path while holding the connection
				// lock, so blocking here is deliberate and bounded at 5s: without the current
				// binding, fall back to the previous token rather than stalling the whole
				// connection. The provider must honour ctx (return on timeout), or that bound
				// does not hold.
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				current, err := provider.Credential(ctx)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					return last
				}
				last = current.Token
				return last
			}),
			// Authentication failures that only happen at run time (an expired token, a revoked
			// binding) surface through these two callbacks alone: invalidate the binding here,
			// so that nats.go's own reconnect carries the rebuilt token.
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				invalidateOnAuthError(auth, err)
			}),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
				invalidateOnAuthError(auth, err)
			}),
		)
	} else if creds := strings.TrimSpace(auth.CredsFile); creds != "" {
		if _, err := os.Stat(creds); err != nil {
			return "", nil, fmt.Errorf("nexus.nats_creds_file: %w", err)
		}
		opts = append(opts, nats.UserCredentials(creds))
	} else if token := strings.TrimSpace(auth.Token); token != "" {
		opts = append(opts, nats.Token(token))
	}
	if err := validateNATSServers(natsURL); err != nil {
		return "", nil, err
	}
	switch ca := strings.TrimSpace(auth.CAFile); {
	case ca != "":
		if _, err := os.Stat(ca); err != nil {
			return "", nil, fmt.Errorf("nexus.nats_ca_file: %w", err)
		}
		opts = append(opts, nats.RootCAs(ca))
	case servedCAPEM != "" && strings.HasPrefix(strings.ToLower(natsURL), "tls://"):
		pool, err := servedCertPool(servedCAPEM)
		if err != nil {
			return "", nil, err
		}
		opts = append(opts, servedTLS(auth.ChainIdentity, pool, natsHosts(natsURL)))
	case auth.RequireServerTLS && !allLoopbackNATS(natsURL):
		return "", nil, fmt.Errorf("nexus nats: no certificate to verify the server: set nexus.nats_ca_file or have the builder serve nats_ca_pem with the sentinel (ADR-0016); the system roots are not used in real mode")
	}
	if strings.HasPrefix(strings.ToLower(natsURL), "tls://") {
		opts = append(opts, nats.Secure())
	}
	return natsURL, opts, nil
}

// resolveServedNATS picks the address and certificate: configured values win over the
// served ones, and a difference is logged, since it usually means stale local config.
func resolveServedNATS(auth NATSAuth, cred NATSChainCredential) (string, string, error) {
	served := strings.Join(cred.NATSServers, ",")
	configured := strings.TrimSpace(auth.URL)
	natsURL := configured
	switch {
	case configured == "" && served == "":
		return "", "", fmt.Errorf("nexus nats: nexus.nats_url is not set and the builder served no nats_servers with the sentinel")
	case configured == "":
		if auth.RequireServerTLS {
			for _, server := range cred.NATSServers {
				if !strings.HasPrefix(strings.ToLower(server), "tls://") {
					return "", "", fmt.Errorf("nexus nats: builder-served nats server %q must be tls:// in real mode (ADR-0016)", server)
				}
			}
		}
		natsURL = served
	case served != "" && served != configured:
		slog.Warn("nexus.nats_url differs from the nats_servers the builder serves; using the configured value",
			"configured", diagnosticsSafeURL(configured), "served", served)
	}
	servedCA := strings.TrimSpace(cred.NATSCAPEM)
	if servedCA != "" && strings.TrimSpace(auth.CAFile) != "" {
		if local, err := os.ReadFile(strings.TrimSpace(auth.CAFile)); err == nil && strings.TrimSpace(string(local)) != servedCA {
			slog.Warn("nexus.nats_ca_file differs from the nats_ca_pem the builder serves; using the configured file",
				"file", strings.TrimSpace(auth.CAFile))
		}
	}
	return natsURL, servedCA, nil
}

// servedTLS verifies the NATS server against the certificate the Builder serves with
// the sentinel. The check is made here, in VerifyConnection, rather than by crypto/tls,
// so that a failure can refetch the served certificate inside the same handshake:
// nats.go reconnects on its own and reports a reconnect's handshake error to no
// callback, so after a Builder rotates its NATS certificate a cached one would
// otherwise be retried for ever. On a mismatch the identity is invalidated (dropping
// the cached sentinel), the credential fetched again, and the chain verified against
// the fresh certificate; only if that fails too is the handshake refused.
//
// hosts are the hosts of the servers being dialled. crypto/tls leaves
// ConnectionState.ServerName empty for an IP literal, so for those the leaf must be
// valid for one of these hosts instead (the served or configured address list is the
// authorised set); otherwise any certificate chaining to the same root would pass.
func servedTLS(provider ChainIdentityProvider, initial *x509.CertPool, hosts []string) nats.Option {
	var mu sync.Mutex
	current := initial
	return func(o *nats.Options) error {
		o.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Not skipped: VerifyConnection below performs the full chain and host check.
			InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				mu.Lock()
				pool := current
				mu.Unlock()
				first := verifyServedChain(state, pool, hosts)
				if first == nil {
					return nil
				}
				provider.Invalidate()
				// Well inside the 5s nats.Timeout that bounds the whole connect, so the
				// rotation can succeed in this handshake rather than the next reconnect.
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				cred, err := provider.Credential(ctx)
				if err != nil || strings.TrimSpace(cred.NATSCAPEM) == "" {
					return first
				}
				fresh, err := servedCertPool(cred.NATSCAPEM)
				if err != nil {
					return first
				}
				if err := verifyServedChain(state, fresh, hosts); err != nil {
					return err
				}
				mu.Lock()
				current = fresh
				mu.Unlock()
				slog.Info("nats server certificate changed; verified against the one the builder now serves")
				return nil
			},
		}
		return nil
	}
}

// verifyServedChain is the check crypto/tls would make: the leaf chains to roots
// through the presented intermediates and is valid for the dialled host. For an IP
// literal ServerName is empty, and the leaf must be valid for one of hosts.
func verifyServedChain(state tls.ConnectionState, roots *x509.CertPool, hosts []string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("nats server presented no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	leaf := state.PeerCertificates[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, DNSName: state.ServerName,
	}); err != nil {
		return err
	}
	if state.ServerName != "" {
		return nil
	}
	var last error = errors.New("no nats server host to check the certificate against")
	for _, host := range hosts {
		if last = leaf.VerifyHostname(host); last == nil {
			return nil
		}
	}
	return last
}

// natsHosts lists the hosts of a comma-separated server list.
func natsHosts(servers string) []string {
	var hosts []string
	for _, server := range strings.Split(servers, ",") {
		if parsed, err := url.Parse(strings.TrimSpace(server)); err == nil && parsed.Hostname() != "" {
			hosts = append(hosts, parsed.Hostname())
		}
	}
	return hosts
}

func servedCertPool(caPEM string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("nexus nats: the builder-served nats_ca_pem holds no usable certificate")
	}
	return pool, nil
}

// validateNATSServers checks every entry of a comma-separated server list.
func validateNATSServers(servers string) error {
	for _, server := range strings.Split(servers, ",") {
		if err := validateNATSURL(strings.TrimSpace(server)); err != nil {
			return err
		}
	}
	return nil
}

func allLoopbackNATS(servers string) bool {
	for _, server := range strings.Split(servers, ",") {
		parsed, err := url.Parse(strings.TrimSpace(server))
		if err != nil {
			return false
		}
		host := parsed.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return false
		}
	}
	return true
}

// diagnosticsSafeURL drops userinfo, which a dev nats_url may carry.
func diagnosticsSafeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parsed.User = nil
	return parsed.String()
}

type natsPublisher struct {
	transport natsPublishTransport
}

// NewNATSPublisher connects with a token (dev); production uses
// NewNATSPublisherWithAuth with creds and CA files.
func NewNATSPublisher(natsURL string, token string) (Publisher, error) {
	return NewNATSPublisherWithAuth(NATSAuth{URL: natsURL, Token: token})
}

func NewNATSPublisherWithAuth(auth NATSAuth) (Publisher, error) {
	trimmed := strings.TrimSpace(auth.URL)
	if err := validateConfiguredNATSURL(trimmed, auth); err != nil {
		return nil, err
	}
	auth.URL = trimmed
	transport, err := newNATSPublishTransport(auth)
	if err != nil {
		return nil, err
	}
	return natsPublisher{
		transport: transport,
	}, nil
}

func (p natsPublisher) Publish(ctx context.Context, req PublishRequest) error {
	if err := validatePublishRequest(req); err != nil {
		return err
	}
	msg := NATSMessage{
		Subject:   strings.TrimSpace(req.Subject),
		Header:    make(http.Header),
		Data:      append([]byte(nil), req.Payload...),
		JetStream: isJetStreamSubject(req.Subject),
	}
	if msg.JetStream {
		msg.Header.Set(natsDedupHeader, NATSDedupID(req))
	}
	if err := p.transport.Publish(ctx, msg); err != nil {
		return retryableError{err: fmt.Errorf("nats publish %q: %w", msg.Subject, err)}
	}
	return nil
}

// Probe verifies the publisher connection without publishing a message.
func (p natsPublisher) Probe(ctx context.Context) error {
	probe, ok := p.transport.(natsReadinessProbe)
	if !ok {
		return fmt.Errorf("nats publisher readiness probe is unavailable")
	}
	return probe.Probe(ctx)
}

func (p natsPublisher) Close() error {
	if closer, ok := p.transport.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func NATSDedupID(req PublishRequest) string {
	// Prefer the caller-supplied stable dedup ID. Fall back to hashing the
	// payload only for callers that have not been migrated yet; this keeps the
	// old behavior while the new helpers are being rolled out.
	var source string
	if strings.TrimSpace(req.DedupID) != "" {
		source = req.DedupID
	} else {
		payloadDigest := sha256.Sum256(req.Payload)
		source = hex.EncodeToString(payloadDigest[:])
	}
	material := strings.Join([]string{
		strings.TrimSpace(req.Subject),
		strings.TrimSpace(req.TaskID),
		source,
	}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// OutputAvailableDedupID returns a stable dedup ID for an OUTPUT_AVAILABLE event.
func OutputAvailableDedupID(taskID, outputHash string) string {
	material := strings.Join([]string{"output-available", taskID, outputHash}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// WorkerHandraiseDedupID returns a stable dedup ID for a worker handraise.
func WorkerHandraiseDedupID(taskID, handraiseDigest string) string {
	material := strings.Join([]string{"worker-handraise", taskID, handraiseDigest}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// VerifierHandraiseDedupID returns a stable dedup ID for a verifier handraise.
func VerifierHandraiseDedupID(taskID string, round int, handraiseDigest string) string {
	material := strings.Join([]string{"verifier-handraise", taskID, fmt.Sprintf("%d", round), handraiseDigest}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func validatePublishRequest(req PublishRequest) error {
	if strings.TrimSpace(req.Subject) == "" {
		return fmt.Errorf("nats publish subject is required")
	}
	if strings.TrimSpace(req.TaskID) == "" {
		return fmt.Errorf("nats publish task id is required")
	}
	if len(req.Payload) == 0 {
		return fmt.Errorf("nats publish payload is required")
	}
	return nil
}

// validateConfiguredNATSURL allows an empty URL only with a chain identity, whose
// sentinel then supplies the address at connect time.
func validateConfiguredNATSURL(rawURL string, auth NATSAuth) error {
	if rawURL == "" && auth.ChainIdentity != nil {
		return nil
	}
	return validateNATSServers(rawURL)
}

func validateNATSURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("nexus nats url is required")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse nexus nats url: %w", err)
	}
	if parsed.Scheme != "nats" && parsed.Scheme != "tls" {
		return fmt.Errorf("unsupported nexus nats url scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("nexus nats url host is required")
	}
	return nil
}

type lazyNATSPublishTransport struct {
	auth NATSAuth

	mu        sync.Mutex
	transport natsPublishTransport
	closed    bool
}

func newLazyNATSPublishTransport(auth NATSAuth) (natsPublishTransport, error) {
	return &lazyNATSPublishTransport{auth: auth}, nil
}

func (t *lazyNATSPublishTransport) Publish(ctx context.Context, msg NATSMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	transport, err := t.transportForPublish(ctx)
	if err != nil {
		return err
	}
	return transport.Publish(ctx, msg)
}

func (t *lazyNATSPublishTransport) Probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	transport, err := t.transportForPublish(ctx)
	if err != nil {
		return err
	}
	probe, ok := transport.(natsReadinessProbe)
	if !ok {
		return fmt.Errorf("nats publish transport readiness probe is unavailable")
	}
	return probe.Probe(ctx)
}

func (t *lazyNATSPublishTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if closer, ok := t.transport.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func (t *lazyNATSPublishTransport) transportForPublish(ctx context.Context) (natsPublishTransport, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.transport != nil {
		// nats.go gives up after MaxReconnects and closes the connection for good. Dial
		// again then, which re-reads the credential: this is how a NATS address or
		// certificate the Builder serves with the sentinel reaches a publisher whose
		// old connection could not recover. A transport this side closed stays closed.
		if closed, ok := t.transport.(interface{ IsClosed() bool }); !ok || !closed.IsClosed() || t.closed {
			return t.transport, nil
		}
		t.transport = nil
	}
	type connectResult struct {
		transport natsPublishTransport
		err       error
	}
	connector := connectNATSPublishTransport
	resultCh := make(chan connectResult, 1)
	go func() {
		transport, err := connector(t.auth)
		resultCh <- connectResult{transport: transport, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if closer, ok := result.transport.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}()
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		t.transport = result.transport
		return result.transport, nil
	}
}

type concreteNATSPublishTransport struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

func connectConcreteNATSPublishTransport(auth NATSAuth) (natsPublishTransport, error) {
	opts := []nats.Option{
		nats.Name("cortex-builderclient"),
		nats.Timeout(5 * time.Second),
	}
	natsURL, authOpts, err := natsConnectOptions(auth)
	if err != nil {
		return nil, err
	}
	opts = append(opts, authOpts...)
	conn, err := natsConnect(natsURL, opts...)
	if err != nil {
		invalidateOnAuthError(auth, err)
		return nil, err
	}
	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return concreteNATSPublishTransport{conn: conn, js: js}, nil
}

func (t concreteNATSPublishTransport) Publish(ctx context.Context, msg NATSMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dedupID := msg.Header.Get(natsDedupHeader)
	natsMsg := &nats.Msg{
		Subject: msg.Subject,
		Header:  nats.Header(msg.Header.Clone()),
		Data:    append([]byte(nil), msg.Data...),
	}
	if !msg.JetStream {
		return t.conn.PublishMsg(natsMsg)
	}
	_, err := t.js.PublishMsg(natsMsg, nats.Context(ctx), nats.MsgId(dedupID))
	return err
}

func (t concreteNATSPublishTransport) Probe(ctx context.Context) error {
	if t.conn == nil || !t.conn.IsConnected() {
		return fmt.Errorf("nats publisher is disconnected")
	}
	return t.conn.FlushWithContext(ctx)
}

// IsClosed reports that nats.go has closed the connection for good.
func (t concreteNATSPublishTransport) IsClosed() bool {
	return t.conn == nil || t.conn.IsClosed()
}

func (t concreteNATSPublishTransport) Close() error {
	if t.conn != nil {
		t.conn.Drain()
		t.conn.Close()
	}
	return nil
}

type natsSubscriber struct {
	auth          NATSAuth
	durable       string
	stream        string
	errCh         chan error
	droppedErrors atomic.Int64

	mu   sync.Mutex
	conn *nats.Conn
}

const jetStreamNakDelay = time.Second

// jetStreamContext is the JetStream surface the subscriber needs. Subscribe
// returns this package's Subscription rather than *nats.Subscription so the
// stop path — the whole point of binding instead of letting the library own the
// consumer — is reachable without a broker.
type jetStreamContext interface {
	AddConsumer(stream string, cfg *nats.ConsumerConfig) (*nats.ConsumerInfo, error)
	Subscribe(subject string, handler nats.MsgHandler, opts ...nats.SubOpt) (Subscription, error)
}

type natsJetStreamContext struct {
	js nats.JetStreamContext
}

func (c natsJetStreamContext) AddConsumer(stream string, cfg *nats.ConsumerConfig) (*nats.ConsumerInfo, error) {
	return c.js.AddConsumer(stream, cfg)
}

func (c natsJetStreamContext) Subscribe(subject string, handler nats.MsgHandler, opts ...nats.SubOpt) (Subscription, error) {
	sub, err := c.js.Subscribe(subject, handler, opts...)
	if err != nil {
		return nil, err
	}
	return natsSubscription{sub: sub}, nil
}

var jetStreamContextFor = func(conn *nats.Conn) (jetStreamContext, error) {
	js, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	return natsJetStreamContext{js: js}, nil
}

// jetStreamConsumerConfig describes the durable consumer this node owns. It
// states only what a consumer created by nats.go's own subscribe path already
// holds, because every restart calls AddConsumer and nats.go compares each
// stated field against the server's value (js.go checkConfig): DeliverPolicy
// and AckPolicy are the two the previous subscribe options set, FilterSubject
// is what that path always wrote, and a deliver subject is what makes it a push
// consumer — a bound push subscribe rejects a pull consumer. The deliver
// subject is a fresh inbox because it is only read at creation: it is not one
// of the compared fields, so a consumer that already exists keeps its own.
//
// MaxDeliver stays unset for the reason in jetStreamSubscribeOptions: existing
// consumers hold the server default (-1), and stating a different value turns a
// rolling upgrade into a configuration conflict.
func jetStreamConsumerConfig(durable string, subject string) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{
		Durable:        durable,
		FilterSubject:  subject,
		DeliverSubject: nats.NewInbox(),
		DeliverPolicy:  nats.DeliverAllPolicy,
		AckPolicy:      nats.AckExplicitPolicy,
	}
}

// jetStreamSubscribeOptions binds to the consumer ensureJetStreamConsumer
// created. nats.Bind is what keeps the durable alive across a stop: nats.go
// marks a consumer it created itself as its own and deletes it server-side on
// Unsubscribe (nats.go@v1.37.0 js.go:1858-1861, deleted asynchronously at
// js.go:2131). The previous nats.Durable form therefore destroyed the ack
// position on every readiness blip and the next start replayed the whole
// retention window at DeliverAll. A bound subscription only unbinds.
//
// Nothing else is stated here on purpose. Every consumer field named through a
// SubOpt is compared against the server's consumer at bind time, so restating
// DeliverAll or AckExplicit would only add ways for a rolling upgrade to fail;
// jetStreamConsumerConfig already fixes both. Do not set MaxDeliver: existing
// deterministic durable consumers were created with the server default (-1),
// and requesting a different value makes nats.go reject the bind. Permanent
// frames are acknowledged by InboxRunner; transient store/context failures
// retain the durable's unlimited delivery budget and are delayed below.
func jetStreamSubscribeOptions(stream string, durable string) []nats.SubOpt {
	return []nats.SubOpt{nats.Bind(stream, durable), nats.ManualAck()}
}

// NewNATSSubscriber connects with a token (dev); production uses
// NewNATSSubscriberWithAuth with creds and CA files.
func NewNATSSubscriber(natsURL string, token string, jetStreamStream string, durablePrefix ...string) (Subscriber, error) {
	return NewNATSSubscriberWithAuth(NATSAuth{URL: natsURL, Token: token}, jetStreamStream, durablePrefix...)
}

func NewNATSSubscriberWithAuth(auth NATSAuth, jetStreamStream string, durablePrefix ...string) (Subscriber, error) {
	trimmed := strings.TrimSpace(auth.URL)
	if err := validateConfiguredNATSURL(trimmed, auth); err != nil {
		return nil, err
	}
	auth.URL = trimmed
	// Binding a consumer needs the stream by name; nothing resolves it from a
	// subject any more. Refuse the subscriber outright rather than discovering
	// the gap on the first JetStream subject.
	stream := strings.TrimSpace(jetStreamStream)
	if stream == "" {
		return nil, fmt.Errorf("nexus jetstream stream name is required: set nexus.jetstream_stream (CORTEX_NEXUS_JETSTREAM_STREAM) to the JetStream stream Nexus publishes task frames to")
	}
	prefix := "cortex"
	if len(durablePrefix) > 0 && strings.TrimSpace(durablePrefix[0]) != "" {
		prefix = strings.TrimSpace(durablePrefix[0])
	}
	return &natsSubscriber{auth: auth, durable: prefix, stream: stream, errCh: make(chan error, 16)}, nil
}

// ensureJetStreamConsumer makes the durable exist before anything binds to it.
// AddConsumer returns the existing consumer when the configuration matches
// (jsm.go:432-460), which is what every restart after the first one relies on.
func (s *natsSubscriber) ensureJetStreamConsumer(js jetStreamContext, subject string, durable string) error {
	if _, err := js.AddConsumer(s.stream, jetStreamConsumerConfig(durable, subject)); err != nil {
		switch {
		case errors.Is(err, nats.ErrConsumerNameAlreadyInUse):
			// The server holds a durable of this name that Cortex cannot bind.
			// Recreating it would silently drop the ack position this whole
			// path exists to preserve, so name the operator action instead.
			return fmt.Errorf("nats jetstream consumer %q on stream %q exists with a conflicting configuration: %w; inspect it with `nats consumer info %s %s` and delete it once no node is bound, or point nexus.jetstream_stream at the stream this node should read", durable, s.stream, err, s.stream, durable)
		case errors.Is(err, nats.ErrStreamNotFound):
			return fmt.Errorf("nats jetstream stream %q does not exist: %w; set nexus.jetstream_stream to the stream Nexus publishes task frames to, or create it on the broker", s.stream, err)
		default:
			return retryableError{err: fmt.Errorf("nats jetstream consumer %q on stream %q: %w", durable, s.stream, err)}
		}
	}
	return nil
}

func (s *natsSubscriber) Subscribe(ctx context.Context, subject string, handler MessageHandler) (Subscription, error) {
	if err := ValidateNATSSubscribeSubject(subject); err != nil {
		return nil, err
	}
	if handler == nil {
		return nil, fmt.Errorf("nats message handler is required")
	}
	conn, err := s.connForSubscribe(ctx)
	if err != nil {
		return nil, retryableError{err: fmt.Errorf("nats subscribe %q: %w", subject, err)}
	}
	if isJetStreamSubject(subject) {
		js, jsErr := jetStreamContextFor(conn)
		if jsErr != nil {
			return nil, retryableError{err: fmt.Errorf("nats jetstream context %q: %w", subject, jsErr)}
		}
		durable := NATSDurableName(s.durable, subject)
		if err := s.ensureJetStreamConsumer(js, subject, durable); err != nil {
			return nil, err
		}
		sub, subErr := js.Subscribe(subject, func(msg *nats.Msg) {
			s.handleJetStreamMessage(ctx, subject, handler, msg)
		}, jetStreamSubscribeOptions(s.stream, durable)...)
		if subErr != nil {
			return nil, retryableError{err: fmt.Errorf("nats subscribe %q: %w", subject, subErr)}
		}
		return sub, nil
	}
	sub, err := conn.Subscribe(subject, func(msg *nats.Msg) {
		s.handleMessage(ctx, subject, handler, msg)
	})
	if err != nil {
		return nil, retryableError{err: fmt.Errorf("nats subscribe %q: %w", subject, err)}
	}
	return natsSubscription{sub: sub}, nil
}

// Probe verifies the subscriber connection without creating a subscription.
func (s *natsSubscriber) Probe(ctx context.Context) error {
	conn, err := s.connForSubscribe(ctx)
	if err != nil {
		return err
	}
	if !conn.IsConnected() {
		return fmt.Errorf("nats subscriber is disconnected")
	}
	return conn.FlushWithContext(ctx)
}

func (s *natsSubscriber) handleJetStreamMessage(ctx context.Context, subject string, handler MessageHandler, msg *nats.Msg) {
	message := NATSMessage{
		Subject:   msg.Subject,
		Header:    cloneNATSHeader(msg.Header),
		Data:      append([]byte(nil), msg.Data...),
		JetStream: true,
	}
	if err := handler(ctx, message); err != nil {
		if nakErr := msg.NakWithDelay(jetStreamNakDelay); nakErr != nil {
			s.reportError(fmt.Errorf("nats nak %q after handler error %v: %w", subject, err, nakErr))
		} else {
			s.reportError(fmt.Errorf("nats handler %q: %w", subject, err))
		}
		return
	}
	if err := msg.Ack(); err != nil {
		s.reportError(fmt.Errorf("nats ack %q: %w", subject, err))
	}
}

func (s *natsSubscriber) Errors() <-chan error {
	if s.errCh == nil {
		s.errCh = make(chan error, 16)
	}
	return s.errCh
}

func (s *natsSubscriber) TakeDroppedErrors() int64 {
	return s.droppedErrors.Swap(0)
}

func (s *natsSubscriber) handleMessage(ctx context.Context, subject string, handler MessageHandler, msg *nats.Msg) {
	message := NATSMessage{
		Subject: msg.Subject,
		Header:  cloneNATSHeader(msg.Header),
		Data:    append([]byte(nil), msg.Data...),
	}
	if err := handler(ctx, message); err != nil {
		s.reportError(fmt.Errorf("nats handler %q: %w", subject, err))
	}
}

func (s *natsSubscriber) reportError(err error) {
	if err == nil {
		return
	}
	if s.errCh == nil {
		s.errCh = make(chan error, 16)
	}
	// The send stays non-blocking: this runs on a NATS delivery callback, and
	// blocking it would stall the subscription. A full buffer still has to be
	// visible, so count what was dropped. DrainErrors consumes this counter
	// after each buffered report; a burst therefore produces a summary without
	// relying on a later callback to flush it.
	select {
	case s.errCh <- err:
	default:
		s.droppedErrors.Add(1)
	}
}

func (s *natsSubscriber) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Drain()
		s.conn.Close()
	}
	return nil
}

func (s *natsSubscriber) connForSubscribe(ctx context.Context) (*nats.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && !s.conn.IsClosed() {
		return s.conn, nil
	}
	type connectResult struct {
		conn *nats.Conn
		err  error
	}
	connector := connectNATSSubscriber
	resultCh := make(chan connectResult, 1)
	go func() {
		conn, err := connector(s.auth)
		resultCh <- connectResult{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				result.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		if result.conn == nil {
			return nil, fmt.Errorf("nats subscriber connection is unavailable")
		}
		s.conn = result.conn
		return result.conn, nil
	}
}

type natsSubscription struct {
	sub *nats.Subscription
}

func (s natsSubscription) Unsubscribe() error {
	if s.sub == nil {
		return nil
	}
	return s.sub.Unsubscribe()
}

func connectConcreteNATSSubscriber(auth NATSAuth) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("cortex-builderclient-subscriber"),
		nats.Timeout(5 * time.Second),
	}
	natsURL, authOpts, err := natsConnectOptions(auth)
	if err != nil {
		return nil, err
	}
	opts = append(opts, authOpts...)
	conn, err := natsConnect(natsURL, opts...)
	if err != nil {
		invalidateOnAuthError(auth, err)
		return nil, err
	}
	return conn, nil
}

func cloneNATSHeader(header nats.Header) http.Header {
	out := make(http.Header, len(header))
	for key, values := range header {
		out[key] = append([]string(nil), values...)
	}
	return out
}

// The §5.1 subject constructors. Each one is the single place its prefix is
// spelled outside busSubjectSpecs, so a rename lands in one line per subject.

// NATSTaskOpenSubject is the only model-scoped subject on this bus; every other
// one is scoped to a task id.
func NATSTaskOpenSubject(modelID string) string {
	return natsSubject("trueopen.task.open", modelID)
}

// NATSModelRegistrationSubject returns the canonical JetStream subject for a
// registration attempt. registrationID must be the stable registration digest
// so an operator retry addresses the same downstream deduplication identity.
//
// This is NOT a §5.1 contract subject: the contract table is a closed set of
// eight and has no model-registration row, and nexus has no producer or consumer
// for this name. Cortex still publishes it because registration is not a
// task-control message and nothing else carries it today; whether it stays on
// this bus at all is a contract-owner decision, tracked separately. It is
// deliberately absent from busSubjectSpecs so it cannot be mistaken for part of
// the contract vocabulary.
func NATSModelRegistrationSubject(registrationID string) string {
	return natsSubject("trueopen.model-registration", registrationID)
}

func NATSWorkerHandraiseSubject(taskID string) string {
	return natsSubject("trueopen.handraise.worker", taskID)
}

func NATSWorkerAssignmentSubject(taskID string) string {
	return natsSubject("trueopen.worker-assignment", taskID)
}

func NATSOutputAvailableSubject(taskID string) string {
	return natsSubject("trueopen.output-avail", taskID)
}

func NATSVerifyOpenSubject(taskID string) string {
	return natsSubject("trueopen.verify.open", taskID)
}

func NATSVerifierHandraiseSubject(taskID string) string {
	return natsSubject("trueopen.handraise.verifier", taskID)
}

func NATSVerifierAssignmentSubject(taskID string) string {
	return natsSubject("trueopen.verifier-assignment", taskID)
}

func NATSVerifyResultSubject(taskID string) string {
	return natsSubject("trueopen.verify-result", taskID)
}

// ValidateNATSSubscribeSubject admits the §5.1 subjects plus the one
// non-contract subject Cortex still publishes. The contract half is read
// straight off busSubjectSpecs so this cannot drift from the kind table.
func ValidateNATSSubscribeSubject(subject string) error {
	trimmed := strings.TrimSpace(subject)
	prefixes := append(BusContractSubjectPrefixes(), "trueopen.model-registration.")
	for _, prefix := range prefixes {
		if strings.HasPrefix(trimmed, prefix) && strings.TrimPrefix(trimmed, prefix) != "" {
			return nil
		}
	}
	return fmt.Errorf("unsupported nats subscribe subject %q", subject)
}

// isJetStreamSubject reads the tier column of the §5.1 table rather than
// guessing from the subject string.
//
// It used to be a blacklist - "not handraise, not orders, not prepare, so
// JetStream" - which silently mis-tiers every Core subject added afterwards.
// trueopen.verify.open.* is exactly such a subject: Core tier, but a blacklist puts
// it on JetStream, where the peer publishing it Core-side has no stream to
// deliver from.
//
// A subject outside the table gets JetStream, which keeps the pre-existing
// behaviour for trueopen.model-registration.*: an operator registration retry wants
// at-least-once, not best-effort.
func isJetStreamSubject(subject string) bool {
	if tier, ok := BusSubjectTierForSubject(subject); ok {
		return tier == TierJetStream
	}
	return true
}

func NATSDurableName(prefix string, subject string) string {
	material := strings.TrimSpace(prefix) + "\x00" + strings.TrimSpace(subject)
	digest := sha256.Sum256([]byte(material))
	var label strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(prefix)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			label.WriteRune(r)
		} else {
			label.WriteByte('_')
		}
		if label.Len() >= 32 {
			break
		}
	}
	if label.Len() == 0 {
		label.WriteString("cortex")
	}
	return "cortex_" + label.String() + "_" + hex.EncodeToString(digest[:8])
}

func natsSubject(prefix string, id string) string {
	return prefix + "." + strings.TrimSpace(id)
}
