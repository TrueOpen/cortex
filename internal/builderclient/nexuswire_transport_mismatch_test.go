package builderclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"connectrpc.com/connect"
)

// TestTransportProtocolMismatchIsPermanent pins the one Unavailable that no
// redelivery can fix.
//
// Connect reports every dial failure as CodeUnavailable, and Unavailable is
// retryable because it usually is a passing outage. A scheme mismatch is not:
// the dialled origin is the on-chain ServiceDescriptorV1 uri, which changes
// only when the Builder republishes its descriptor, so the next attempt fails
// identically. On devnet this retried a permanent deployment error roughly
// every 30 seconds with no cap and no ceiling on the count, holding a task
// until its deadline instead of surfacing the misconfiguration.
func TestTransportProtocolMismatchIsPermanent(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			// Descriptor says https://, the Builder speaks plaintext HTTP.
			// This is the devnet failure verbatim.
			name: "descriptor_https_peer_plaintext",
			err: connect.NewError(connect.CodeUnavailable, &url.Error{
				Op:  "Post",
				URL: "https://167.86.69.213:8080/nexus.v1.IngressAPI/GetTaskDataMetadata",
				Err: http.ErrSchemeMismatch,
			}),
		},
		{
			// The mirror image: descriptor says http://, the Builder
			// terminates TLS. The handshake never starts.
			name: "descriptor_plaintext_peer_tls",
			err: connect.NewError(connect.CodeUnavailable, &url.Error{
				Op:  "Post",
				URL: "http://167.86.69.213:8443/nexus.v1.IngressAPI/GetTaskDataMetadata",
				Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyConnectError("/nexus.v1.IngressAPI/GetTaskDataMetadata", tc.err)
			if got == nil {
				t.Fatal("classifyConnectError returned nil, want a refusal")
			}
			if IsRetryable(got) {
				t.Fatalf("classifyConnectError(%v) is retryable, want a permanent verdict", got)
			}
			if !IsPermanent(got) {
				t.Fatalf("classifyConnectError(%v) is not asserted permanent; the subject-keyed inbox dispositions need the assertion, not the default", got)
			}
			if !errors.Is(got, tc.err) {
				t.Fatalf("classifyConnectError dropped the cause: %v", got)
			}
		})
	}
}

// A genuine Unavailable must stay retryable: turning every dial failure
// permanent would make one restart of a Builder discard the work.
func TestOrdinaryUnavailableStaysRetryable(t *testing.T) {
	err := connect.NewError(connect.CodeUnavailable, fmt.Errorf("connection refused"))
	got := classifyConnectError("/nexus.v1.IngressAPI/FetchTaskData", err)
	if !IsRetryable(got) {
		t.Fatalf("classifyConnectError(%v) is not retryable, want the outage retried", got)
	}
}
