package builderclient

import (
	"strings"
	"testing"
)

// The four schemes consensus admits map onto exactly two transports. grpcs is
// https and grpc is http; anything else is refused, because the classifier is
// the single place every gate downstream agrees on.
func TestParseNexusEndpointClassifiesTheFourAdmittedSchemes(t *testing.T) {
	for _, testCase := range []struct {
		uri           string
		wantDial      string
		wantPlaintext bool
	}{
		{uri: "https://nexus.example.org", wantDial: "https://nexus.example.org"},
		{uri: "https://nexus.example.org:8443", wantDial: "https://nexus.example.org:8443"},
		{uri: "grpcs://nexus.example.org:8443", wantDial: "https://nexus.example.org:8443"},
		{uri: "http://nexus.example.org", wantDial: "http://nexus.example.org", wantPlaintext: true},
		{uri: "grpc://207.180.235.236:8080", wantDial: "http://207.180.235.236:8080", wantPlaintext: true},
		// Case and a trailing slash are normalised for the dial origin only.
		{uri: "GRPCS://nexus.example.org", wantDial: "https://nexus.example.org"},
		{uri: "grpc://nexus.example.org:8080/", wantDial: "http://nexus.example.org:8080", wantPlaintext: true},
	} {
		t.Run(testCase.uri, func(t *testing.T) {
			parsed, err := ParseNexusEndpoint(testCase.uri)
			if err != nil {
				t.Fatalf("ParseNexusEndpoint(%q) error = %v", testCase.uri, err)
			}
			if parsed.DialURI != testCase.wantDial {
				t.Fatalf("DialURI = %q, want %q", parsed.DialURI, testCase.wantDial)
			}
			if parsed.Plaintext != testCase.wantPlaintext {
				t.Fatalf("Plaintext = %v, want %v", parsed.Plaintext, testCase.wantPlaintext)
			}
		})
	}
}

// A scheme outside the admitted set is refused, and so is anything that could
// make the dialled origin differ from the published one. The opt-in upstream is
// a TLS concession, so it must never reach a parser decision.
func TestParseNexusEndpointRefusesEverythingElse(t *testing.T) {
	for _, testCase := range []struct {
		uri  string
		want string
	}{
		{uri: "ws://nexus.example.org", want: "scheme is not one of"},
		{uri: "ftp://nexus.example.org", want: "scheme is not one of"},
		{uri: "ipfs://nexus", want: "scheme is not one of"},
		{uri: "nexus.example.org", want: "absolute base URL"},
		{uri: "", want: "absolute base URL"},
		{uri: "https://user:pass@nexus.example.org", want: "absolute base URL"},
		{uri: "grpc://nexus.example.org?a=1", want: "absolute base URL"},
		{uri: "grpcs://nexus.example.org#frag", want: "absolute base URL"},
	} {
		t.Run(testCase.uri, func(t *testing.T) {
			_, err := ParseNexusEndpoint(testCase.uri)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("ParseNexusEndpoint(%q) error = %v, want %q", testCase.uri, err, testCase.want)
			}
		})
	}
}

// The error names every admitted spelling, so an operator reading a refusal can
// see that grpcs is available rather than concluding gRPC is unsupported.
func TestParseNexusEndpointRefusalNamesEveryAdmittedScheme(t *testing.T) {
	_, err := ParseNexusEndpoint("ws://nexus.example.org")
	if err == nil {
		t.Fatal("ParseNexusEndpoint(ws://) = nil, want a refusal")
	}
	for _, scheme := range []string{"https://", "grpcs://", "http://", "grpc://"} {
		if !strings.Contains(err.Error(), scheme) {
			t.Fatalf("refusal %q does not name %q", err, scheme)
		}
	}
}

// WithoutTLS is the devnet compatibility rewrite: a descriptor that published a
// TLS scheme in front of an ingress that terminates no TLS is dialled at its
// plaintext origin, and the result says it is plaintext so the gate that guards
// cleartext payloads still sees it. An already-plaintext endpoint is untouched.
func TestNexusEndpointWithoutTLSDowngradesTheDialOrigin(t *testing.T) {
	for _, testCase := range []struct {
		uri      string
		wantDial string
	}{
		{uri: "https://167.86.69.213:8080", wantDial: "http://167.86.69.213:8080"},
		{uri: "grpcs://nexus.example.org:8443", wantDial: "http://nexus.example.org:8443"},
		{uri: "http://nexus.example.org", wantDial: "http://nexus.example.org"},
		{uri: "grpc://207.180.235.236:8080", wantDial: "http://207.180.235.236:8080"},
	} {
		t.Run(testCase.uri, func(t *testing.T) {
			parsed, err := ParseNexusEndpoint(testCase.uri)
			if err != nil {
				t.Fatalf("ParseNexusEndpoint(%q) error = %v", testCase.uri, err)
			}
			classified := parsed.DialURI
			downgraded := parsed.WithoutTLS()
			if downgraded.DialURI != testCase.wantDial {
				t.Fatalf("WithoutTLS().DialURI = %q, want %q", downgraded.DialURI, testCase.wantDial)
			}
			if !downgraded.Plaintext {
				t.Fatal("WithoutTLS().Plaintext = false, want the cleartext transport reported")
			}
			// The classification the descriptor gate reads is left alone: the
			// rewrite is a value the dial site derives, not a mutation.
			if parsed.DialURI != classified {
				t.Fatalf("classified endpoint mutated to %q, want %q", parsed.DialURI, classified)
			}
		})
	}
}
