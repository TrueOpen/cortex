package builderclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
)

const maxNexusResponseBytes = 64 << 20

// nexusDataTimeout bounds Nexus payload transfers, including task-data Connect
// calls whose contexts can otherwise live for the lifetime of the daemon.
const nexusDataTimeout = 60 * time.Second

// errNexusRedirect marks a refused redirect: a policy rejection, never a
// transport failure.
var errNexusRedirect = errors.New("nexus endpoint redirect refused")

// nexusTLSConfig is the TLS floor every Nexus call runs under.
//
// The binding between this transport and the descriptor identity is hostname
// verification against the endpoint the descriptor publishes, and nothing more.
// ServerName is left empty on purpose so net/http verifies the certificate
// against the request host, which is the published host and — by the redirect
// policy below — the only origin any hop may reach.
//
// ServiceEndpointV1.tls_pubkey_hash is the pin: sha256 of the certificate's
// SubjectPublicKeyInfo DER, published by nexus alongside its self-signed
// certificate (TrueOpen/nexus#63). The chain declares the field "a
// caller-authored opaque 32-byte value" and defines no preimage itself; the
// preimage is a nexus/cortex/sdk convention, stated in tlspin.go and checked
// there at dial time whenever the caller put the descriptor pin in the request
// context. An endpoint without a pin keeps the CA-chain verification below.
//
// Identity.ServicePubkey is the chain service key that signs Builder material,
// not a TLS key, so it is not a pin.
func nexusTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Stated rather than inherited: hostname verification is the whole
		// binding to the descriptor identity, so switching it off has to be an
		// edit to this line rather than an omission somewhere else.
		InsecureSkipVerify: false,
	}
}

// newNexusHTTPClient copies the caller's client, applies the bounded data
// timeout, and installs the shared Nexus redirect policy. A 307 or 308 can
// replay a signed plaintext body, so every hop must remain on the absolute
// origin of the first verified request. This also permits explicitly insecure
// dev endpoints to redirect within their own HTTP origin without permitting a
// cross-origin replay or an HTTPS downgrade.
func newNexusHTTPClient(base *http.Client, timeout time.Duration) *http.Client {
	client := &http.Client{}
	if base != nil {
		copied := *base
		client = &copied
	}
	client.Timeout = timeout
	// A caller that brought its own transport keeps it: an injected client is
	// how a test server's own root is trusted. A client without one gets the
	// Nexus TLS floor rather than whatever http.DefaultTransport happens to
	// carry.
	if client.Transport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = nexusTLSConfig()
		// Requests carrying a tls_pubkey_hash in their context are routed to a
		// per-pin transport whose dial verifies the presented public key
		// instead of the CA chain; requests without one use this transport
		// and the standard verification nexusTLSConfig states. See tlspin.go.
		client.Transport = newPinRouter(transport)
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxNexusRedirects {
			return fmt.Errorf("%w: more than %d hops", errNexusRedirect, maxNexusRedirects)
		}
		if req == nil || req.URL == nil || len(via) == 0 || via[0] == nil || via[0].URL == nil {
			return fmt.Errorf("%w: redirect chain has no absolute origin", errNexusRedirect)
		}
		origin := via[0].URL
		if !sameNexusOrigin(origin, req.URL) {
			return fmt.Errorf("%w: %s leaves origin %s://%s", errNexusRedirect, req.URL.Redacted(), origin.Scheme, origin.Host)
		}
		return nil
	}
	return client
}

// NewNexusHTTPClient builds the same kind of Nexus HTTP client the task-data client
// uses: bounded timeouts, a same-origin redirect policy, and a transport pooled by
// tls_pubkey_hash (see tlspin.go). Callers outside this package that send ordinary
// HTTP requests to the same nexus ingress (natsidentity's sentinel fetch) use it, so
// the pin is checked exactly as it is for task-data instead of each assembling its own
// client. A timeout <= 0 means Nexus's default data timeout.
func NewNexusHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = nexusDataTimeout
	}
	return newNexusHTTPClient(nil, timeout)
}

func sameNexusOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		nexusOriginPort(left) == nexusOriginPort(right)
}

func nexusOriginPort(endpoint *url.URL) string {
	if port := endpoint.Port(); port != "" {
		return port
	}
	switch strings.ToLower(endpoint.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

const maxNexusRedirects = 3

type retryableError struct {
	err error
}

func (e retryableError) Error() string {
	return e.err.Error()
}

func (e retryableError) Unwrap() error {
	return e.err
}

func IsRetryable(err error) bool {
	var target retryableError
	return errors.As(err, &target)
}

func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableError{err: err}
}

// permanentError marks a refusal that no redelivery can fix. Permanent is
// already the default for an unmarked error, so this exists for one reason:
// some inbox dispositions redeliver by subject rather than by classification
// (outbox.verifierFrame), and against those the verdict has to be assertable
// rather than merely implied. Marking it is how a handler says "acknowledge
// this and surface it" instead of letting the frame NAK forever.
type permanentError struct {
	err error
}

func (e permanentError) Error() string {
	return e.err.Error()
}

func (e permanentError) Unwrap() error {
	return e.err
}

func IsPermanent(err error) bool {
	var target permanentError
	return errors.As(err, &target)
}

func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err: err}
}

// transportProtocolMismatch names the transport-layer disagreement behind a
// dial failure, or "" when the failure is not one. Both directions are
// deployment errors rather than outages: the descriptor's scheme and the port's
// actual behaviour contradict each other, and only one of the two can move.
func transportProtocolMismatch(err error) string {
	if errors.Is(err, http.ErrSchemeMismatch) {
		return "the endpoint was dialled as TLS but answered in plaintext"
	}
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &recordHeader) {
		return "the endpoint was dialled in plaintext but answered with TLS"
	}
	return ""
}

// classifyConnectError maps a Connect code to retryable or permanent. The code is
// the whole decision: it is the machine-readable verdict the server chose, and
// unlike the HTTP status it is not rewritten by a proxy in between.
//
// This mapping decides whether an active responsibility is retried or retired, so the
// default has to be stated rather than inherited. A code Cortex has not reasoned
// about is treated as permanent: retrying an unrecognised rejection is how an
// unbounded retry loop starts, and the row can still be requeued by an operator.
func classifyConnectError(procedure string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errNexusRedirect) {
		return fmt.Errorf("call %s: %w", procedure, err)
	}
	wrapped := fmt.Errorf("%s: %w", procedure, err)
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeResourceExhausted, connect.CodeInternal, connect.CodeDeadlineExceeded:
		// One Unavailable is not an outage. A scheme mismatch means this node
		// and the Builder disagree about whether the origin speaks TLS, and the
		// origin is the Builder's on-chain ServiceDescriptorV1 uri: it cannot
		// change until the Builder republishes the descriptor, so every
		// redelivery fails identically. Retrying it burned a task's whole
		// deadline window on devnet at roughly one attempt per 30 seconds.
		if mismatch := transportProtocolMismatch(err); mismatch != "" {
			return Permanent(fmt.Errorf("%w: %s; the dialled origin comes from the Builder's on-chain ServiceDescriptorV1, so this cannot clear by retrying: the Builder must republish the descriptor with the scheme it actually serves, or the node must opt into nexus.downgrade_descriptor_tls", wrapped, mismatch))
		}
		return Retryable(wrapped)
	case connect.CodeCanceled:
		return wrapped
	default:
		return wrapped
	}
}
