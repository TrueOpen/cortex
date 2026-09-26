package natsidentity

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// SentinelPath is where every Builder's nexus ingress serves its sentinel:
// application/json on 200, and 404 when that Builder has no sentinel configured.
const SentinelPath = "/v1/nats/sentinel"

// sentinelSchemaVersion is the only schema_version this implementation accepts.
const sentinelSchemaVersion = 1

// sentinelCandidateTimeout bounds one fetch against a single candidate Builder.
// The whole fetch runs on the NATS connection path (Credential -> connection
// callback) and multiplies by the number of candidates, so a single attempt has to
// be short.
const sentinelCandidateTimeout = 3 * time.Second

// maxSentinelResponseBytes: a sentinel is one JWT, normally a few hundred bytes;
// reading more is pointless.
const maxSentinelResponseBytes = 64 << 10

// Sentinel is an AUTH account's sentinel user JWT plus the account public key it
// belongs to.
//
// It is public material: a bearer with no permissions, which cannot send or receive
// anything on its own. An operator-mode nats-server requires CONNECT to carry a user
// JWT the account can verify before it asks the auth callback at all (nats-server
// v2.10.22 server/auth.go:731-736), and the sentinel is what satisfies that step;
// the real identity travels in the on-chain binding declaration inside auth_token.
//
// NATSServers and NATSCAPEM are optional: the NATS address and the PEM that verifies
// the NATS server, served with the sentinel so a new Cortex needs neither handed to
// it (interface-and-topic-list §4.12, ADR-0016 decision one item 1). They are as
// trustworthy as the sentinel: both come over the ingress TLS pinned by the on-chain
// tls_pubkey_hash.
type Sentinel struct {
	AuthAccountPublicKey string
	JWT                  string
	NATSServers          []string
	NATSCAPEM            string
}

// SentinelSource supplies the Binder with the sentinel to present. An implementation
// may cache, but it has to be invalidatable: a source that implements Invalidate is
// dropped along with the binding on an authentication failure (a rotated sentinel is
// one of the causes of an Authorization Violation).
type SentinelSource interface {
	Sentinel(ctx context.Context) (Sentinel, error)
}

// sentinelInvalidator is an optional capability of a SentinelSource: see the
// SentinelSource documentation.
type sentinelInvalidator interface {
	Invalidate()
}

// BuilderIngress is one candidate Builder's ingress: a directly dialable origin and
// the tls_pubkey_hash from its descriptor (the empty string when there is none). A
// non-nil Err means this candidate was already out at the resolve stage (an invalid
// endpoint, a plaintext endpoint without allow_insecure_descriptor, and so on) and
// need not be dialled - but its reason still has to appear in the final summary
// error, or the operator only sees "they all failed" without seeing why each one did.
type BuilderIngress struct {
	Operator      string
	Endpoint      string
	TLSPubkeyHash string
	Err           error
}

// BuilderIngressResolver answers "which Builders' ingresses may be asked for a
// sentinel", in the order they should be tried. The daemon's implementation: when
// builder_operator_address is configured it returns that one alone (config can only
// narrow), otherwise it returns every member of the active on-chain BuilderSet in
// order.
//
// It returns several rather than one because the members of a BuilderSet are not all
// online and not all serving a sentinel: in integration the first member's genesis
// descriptor is a plaintext endpoint nobody listens on, while another Builder in the
// same set serves normally. A sentinel is public material, so whichever live Builder
// hands one over will do.
type BuilderIngressResolver interface {
	ResolveIngresses(ctx context.Context) ([]BuilderIngress, error)
}

// ErrNoSentinel is a Builder answering outright "I have no sentinel" (404). Fail
// closed: do not guess a default, and do not fall back to a CONNECT without a jwt.
var ErrNoSentinel = errors.New("builder has no nats sentinel configured")

// IngressSentinelSource fetches the sentinel from a Builder's nexus ingress over the
// link cortex already uses: the same TLS pin (tls_pubkey_hash from the descriptor)
// and the same HTTP client construction (builderclient.NewNexusHTTPClient), so this
// GET is subject to the same checks as a task-data call.
type IngressSentinelSource struct {
	resolver BuilderIngressResolver
	client   *http.Client

	mu sync.Mutex
	// cached holds the sentinel already fetched; it is dropped after an authentication
	// failure and a Builder is chosen again. previous survives Invalidate so a change
	// in the served NATS address or certificate can be logged.
	cached   *Sentinel
	previous *Sentinel
}

// NewIngressSentinelSource assembles the source; a nil client means the default
// Nexus client with pin routing.
func NewIngressSentinelSource(resolver BuilderIngressResolver, client *http.Client) (*IngressSentinelSource, error) {
	if resolver == nil {
		return nil, fmt.Errorf("nats sentinel source requires a builder ingress resolver")
	}
	if client == nil {
		client = builderclient.NewNexusHTTPClient(sentinelCandidateTimeout)
	}
	return &IngressSentinelSource{resolver: resolver, client: client}, nil
}

var _ SentinelSource = (*IngressSentinelSource)(nil)

// Sentinel returns the cached sentinel, fetching one when there is no cache. A
// sentinel changes very rarely, so the cache has no TTL: rotation is driven by
// Invalidate (the Binder calls it after an authentication failure).
func (s *IngressSentinelSource) Sentinel(ctx context.Context) (Sentinel, error) {
	if cached, ok := s.load(); ok {
		return cached, nil
	}
	sentinel, operator, err := s.fetch(ctx)
	if err != nil {
		return Sentinel{}, err
	}
	slog.Info("fetched nats auth sentinel", "builder", operator, "auth_account", sentinel.AuthAccountPublicKey,
		"nats_servers", strings.Join(sentinel.NATSServers, ","), "nats_ca_pem", sentinel.NATSCAPEM != "")
	s.mu.Lock()
	// §5.14.4: a change in the served address or certificate is worth a line of its own.
	if s.previous != nil && (strings.Join(s.previous.NATSServers, ",") != strings.Join(sentinel.NATSServers, ",") ||
		s.previous.NATSCAPEM != sentinel.NATSCAPEM) {
		slog.Info("builder-served nats address or certificate changed", "builder", operator,
			"nats_servers", strings.Join(sentinel.NATSServers, ","))
	}
	s.cached = &sentinel
	s.previous = &sentinel
	s.mu.Unlock()
	return sentinel, nil
}

// Invalidate drops the cache: the next Sentinel call necessarily fetches again.
func (s *IngressSentinelSource) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

func (s *IngressSentinelSource) load() (Sentinel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil {
		return Sentinel{}, false
	}
	return *s.cached, true
}

type sentinelResponse struct {
	SchemaVersion        int      `json:"schema_version"`
	AuthAccountPublicKey string   `json:"auth_account_public_key"`
	SentinelJWT          string   `json:"sentinel_jwt"`
	NATSServers          []string `json:"nats_servers"`
	NATSCAPEM            string   `json:"nats_ca_pem"`
	Error                string   `json:"error"`
}

// fetch tries the candidates in order and returns the first sentinel it obtains.
// Any kind of failure (refused at resolve, undialable, 404, an invalid document)
// eliminates that one candidate only: members of a BuilderSet being offline is
// normal, and the whole connection must not stop at the first broken Builder. When
// they all fail, every candidate's reason is summarised into one error.
func (s *IngressSentinelSource) fetch(ctx context.Context) (Sentinel, string, error) {
	candidates, err := s.resolver.ResolveIngresses(ctx)
	if err != nil {
		return Sentinel{}, "", fmt.Errorf("resolve builder ingress for the nats sentinel: %w", err)
	}
	if len(candidates) == 0 {
		return Sentinel{}, "", fmt.Errorf("no builder is available to serve a nats sentinel")
	}
	failures := make([]error, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", candidate.Operator, candidate.Err))
			continue
		}
		sentinel, err := s.fetchFrom(ctx, candidate)
		if err == nil {
			return sentinel, candidate.Operator, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", candidate.Operator, err))
	}
	return Sentinel{}, "", newSentinelFetchError(failures)
}

// sentinelFetchError summarises why each candidate failed. It joins the reasons
// itself (candidates separated by "; ", because errors.Join's newlines are
// unreadable in a one-line log) while keeping Unwrap() []error, so callers can still
// use errors.Is to recognise specific causes such as ErrNoSentinel or a TLS pin
// mismatch.
type sentinelFetchError struct {
	failures []error
}

func newSentinelFetchError(failures []error) error {
	return &sentinelFetchError{failures: failures}
}

func (e *sentinelFetchError) Error() string {
	reasons := make([]string, 0, len(e.failures))
	for _, failure := range e.failures {
		reasons = append(reasons, failure.Error())
	}
	return "no builder served a nats sentinel: " + strings.Join(reasons, "; ")
}

func (e *sentinelFetchError) Unwrap() []error { return e.failures }

func (s *IngressSentinelSource) fetchFrom(ctx context.Context, candidate BuilderIngress) (Sentinel, error) {
	parsed, err := builderclient.ParseNexusEndpoint(candidate.Endpoint)
	if err != nil {
		return Sentinel{}, fmt.Errorf("ingress %q: %w", candidate.Endpoint, err)
	}
	// Each candidate carries its own bound: there may be several, and one undialable
	// candidate must not squeeze the rest out of the probe's ctx.
	ctx, cancel := context.WithTimeout(ctx, sentinelCandidateTimeout)
	defer cancel()
	// The pin is handed to the transport through ctx, the same path the task-data
	// client uses (builderclient/tlspin.go).
	request, err := http.NewRequestWithContext(
		builderclient.WithTLSPubkeyHash(ctx, candidate.TLSPubkeyHash),
		http.MethodGet, parsed.DialURI+SentinelPath, nil)
	if err != nil {
		return Sentinel{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return Sentinel{}, builderclient.Retryable(fmt.Errorf("fetch nats sentinel from %s: %w", parsed.DialURI, err))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSentinelResponseBytes))
	if err != nil {
		return Sentinel{}, builderclient.Retryable(fmt.Errorf("read nats sentinel from %s: %w", parsed.DialURI, err))
	}
	switch {
	case response.StatusCode == http.StatusNotFound:
		return Sentinel{}, fmt.Errorf("%w: %s answered 404%s", ErrNoSentinel, parsed.DialURI, sentinelServerReason(body))
	case response.StatusCode != http.StatusOK:
		return Sentinel{}, builderclient.Retryable(fmt.Errorf("fetch nats sentinel from %s: status %d%s", parsed.DialURI, response.StatusCode, sentinelServerReason(body)))
	}
	var decoded sentinelResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return Sentinel{}, fmt.Errorf("decode nats sentinel from %s: %w", parsed.DialURI, err)
	}
	sentinel, err := validateSentinel(decoded)
	if err != nil {
		return Sentinel{}, fmt.Errorf("nats sentinel from %s: %w", parsed.DialURI, err)
	}
	return sentinel, nil
}

// sentinelServerReason attaches the server's error field to the diagnostic, and
// adds nothing when it cannot be read.
func sentinelServerReason(body []byte) string {
	var decoded sentinelResponse
	if err := json.Unmarshal(body, &decoded); err != nil || strings.TrimSpace(decoded.Error) == "" {
		return ""
	}
	return ": " + strings.TrimSpace(decoded.Error)
}

// validateSentinel is the fail-closed gate: a schema we recognise, a self-consistent
// JWT, a bearer (otherwise the server would require the signature to correspond to
// the JWT's subject, while ours uses the local user key), and an announced AUTH
// account public key that really is the account that issued this JWT.
func validateSentinel(decoded sentinelResponse) (Sentinel, error) {
	if decoded.SchemaVersion != sentinelSchemaVersion {
		return Sentinel{}, fmt.Errorf("schema_version %d is not %d", decoded.SchemaVersion, sentinelSchemaVersion)
	}
	account := strings.TrimSpace(decoded.AuthAccountPublicKey)
	if !nkeys.IsValidPublicAccountKey(account) {
		return Sentinel{}, fmt.Errorf("auth_account_public_key is not an account nkey")
	}
	token := strings.TrimSpace(decoded.SentinelJWT)
	if token == "" {
		return Sentinel{}, fmt.Errorf("sentinel_jwt is required")
	}
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return Sentinel{}, fmt.Errorf("sentinel_jwt does not decode as a user jwt: %w", err)
	}
	if !claims.BearerToken {
		return Sentinel{}, fmt.Errorf("sentinel_jwt is not a bearer token")
	}
	// When issued with a signing key the account is in IssuerAccount and Issuer is that
	// signing key; when issued with the account key directly there is only Issuer.
	issuer := strings.TrimSpace(claims.IssuerAccount)
	if issuer == "" {
		issuer = strings.TrimSpace(claims.Issuer)
	}
	if issuer != account {
		return Sentinel{}, fmt.Errorf("sentinel_jwt was issued by account %s, not the published %s", issuer, account)
	}
	servers, caPEM, err := validateServedNATS(decoded)
	if err != nil {
		return Sentinel{}, err
	}
	return Sentinel{AuthAccountPublicKey: account, JWT: token, NATSServers: servers, NATSCAPEM: caPEM}, nil
}

// validateServedNATS checks the optional address and certificate. A malformed one
// fails this Builder's document outright, like any other invalid field, so the next
// candidate is tried instead of dialling something half-understood.
func validateServedNATS(decoded sentinelResponse) ([]string, string, error) {
	var servers []string
	for _, server := range decoded.NATSServers {
		server = strings.TrimSpace(server)
		parsed, err := url.Parse(server)
		if err != nil || (parsed.Scheme != "tls" && parsed.Scheme != "nats") || parsed.Port() == "" ||
			parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") {
			return nil, "", fmt.Errorf("nats_servers entry %q is not tls://host:port", server)
		}
		servers = append(servers, server)
	}
	caPEM := strings.TrimSpace(decoded.NATSCAPEM)
	if caPEM != "" {
		certificates := 0
		for rest := []byte(caPEM); ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil, "", fmt.Errorf("nats_ca_pem holds a %s block, only certificates are accepted", block.Type)
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, "", fmt.Errorf("nats_ca_pem certificate does not parse: %w", err)
			}
			certificates++
		}
		if certificates == 0 {
			return nil, "", fmt.Errorf("nats_ca_pem holds no certificate")
		}
		caPEM += "\n"
	}
	return servers, caPEM, nil
}
