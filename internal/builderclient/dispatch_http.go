package builderclient

import (
	"net/http"
)

// NewDispatchStreamHTTPClient is the client every DispatchStream Session dials
// with. A connect bidi stream needs HTTP/2: h2 over TLS (ALPN), h2c for a
// devnet plaintext endpoint. It has no overall timeout because the stream
// lives as long as its binding; liveness is the keepalive's job. Requests
// carrying a descriptor pin (WithTLSPubkeyHash) dial through the per-pin
// transports of pinRouter; others verify the CA chain.
func NewDispatchStreamHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = nexusTLSConfig()
	transport.TLSClientConfig.NextProtos = []string{"h2"}
	transport.ForceAttemptHTTP2 = true
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	transport.Protocols = protocols
	return &http.Client{
		Transport: newPinRouter(transport),
		// A stream never follows a redirect: the descriptor is the address.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
