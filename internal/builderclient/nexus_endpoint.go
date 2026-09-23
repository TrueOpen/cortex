package builderclient

import (
	"fmt"
	"net/url"
	"strings"
)

// NexusEndpoint is the transport decision a published Nexus endpoint URI asks
// for, resolved once so every gate downstream agrees.
//
// The chain admits four schemes in committed state — http, https, grpc, grpcs
// (TrueOpen/node x/hub/types/participant_identity.go:206-208) — and all
// four are dialable, because the deployed ingress is a connect-go server: it
// answers the Connect protocol over HTTP/1.1 and gRPC over h2c on the same
// port. Measured against the devnet ingress at 207.180.235.236:8080, an
// HTTP/1.1 Connect POST returns a Connect error envelope
// ({"code":"invalid_argument","message":"NEXUS_DATA_MALFORMED"}) and an unknown
// procedure returns 404, so the existing Connect client reaches it with no
// protocol option and no h2c transport.
//
// The scheme therefore selects TLS or plaintext, nothing else. grpcs is an
// alias of https and grpc is an alias of http, which is why they are normalised
// to one dial origin rather than given a second code path: a second path is how
// the descriptor gate and the dial gate drift apart.
type NexusEndpoint struct {
	// DialURI is the endpoint rewritten to the http(s) origin the Connect
	// client dials. It is NEVER the value to compare against configuration or
	// to report as the published endpoint: Identity.SameEndpoint compares the
	// committed URI exactly, on purpose.
	DialURI string
	// Plaintext reports that this transport carries V1 Task payloads — prompts
	// and outputs — in the clear.
	Plaintext bool
}

// NexusEndpointSchemes is the admissible set, in the order the error names them.
const NexusEndpointSchemes = "https://, grpcs://, http://, grpc://"

// WithoutTLS rewrites a TLS dial origin to its plaintext counterpart and says
// so in Plaintext, leaving an already-plaintext endpoint untouched.
//
// It exists because the devnet BuilderSet publishes https://…:8080 while the
// ingress it names terminates no TLS at all (TrueOpen/nexus
// internal/ingress/server.go serves h2c/HTTP1.1 only), so every task-data call
// dies with `http: server gave HTTP response to HTTPS client`. The descriptor
// is consensus state and Cortex cannot edit it; the only local remedy is to
// dial the origin the server actually speaks.
//
// This is a DOWNGRADE, not a normalisation: the result carries V1 Task payloads
// in the clear against a descriptor that asked for TLS. It is therefore never
// applied by ParseNexusEndpoint and never reached without the stated operator
// opt-in — see TaskDataTransport.DowngradeEndpointTLS, which is refused in real
// mode by internal/config. The published URI itself is never rewritten:
// Identity.SameEndpoint still compares the committed string exactly.
func (e NexusEndpoint) WithoutTLS() NexusEndpoint {
	if e.Plaintext {
		return e
	}
	return NexusEndpoint{
		DialURI:   "http://" + strings.TrimPrefix(e.DialURI, "https://"),
		Plaintext: true,
	}
}

// ParseNexusEndpoint classifies a published endpoint URI. It rejects anything
// that could make the dialled origin differ from the published one: credentials,
// a query or a fragment.
func ParseNexusEndpoint(uri string) (NexusEndpoint, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(uri), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return NexusEndpoint{}, fmt.Errorf("endpoint must be an absolute base URL with no credentials, query or fragment")
	}
	var scheme string
	var plaintext bool
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		scheme, plaintext = "https", false
	case "grpcs":
		scheme, plaintext = "https", false
	case "http":
		scheme, plaintext = "http", true
	case "grpc":
		scheme, plaintext = "http", true
	default:
		return NexusEndpoint{}, fmt.Errorf("scheme is not one of %s", NexusEndpointSchemes)
	}
	parsed.Scheme = scheme
	return NexusEndpoint{DialURI: parsed.String(), Plaintext: plaintext}, nil
}
