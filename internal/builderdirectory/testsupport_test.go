package builderdirectory

import "github.com/TrueOpen/cortex/internal/chainclient"

// Declarations only tests use, kept out of the production binary.

// CheckEndpointTransport is the exported transport rule, for callers that hold
// an endpoint they did not resolve through Resolve.
func CheckEndpointTransport(endpoint chainclient.ServiceEndpointSnapshot, allowInsecure bool) error {
	return checkEndpointTransport(endpoint, allowInsecure)
}
