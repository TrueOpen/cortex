package daemon

import (
	"net/http"

	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/tlstrust"
)

// nodeHTTPTransport is the one transport every client that talks to the chain
// node uses: the Keeper ABCI query client, the CometBFT event and status
// client, and the Cosmos REST client behind transaction broadcast. With
// node.tls set it trusts exactly the configured certificate (ca_file) or public
// key (pubkey_hash); with node.tls empty it is nil, so each client keeps
// http.DefaultTransport and the system root CAs.
func nodeHTTPTransport(cfg config.Config) (http.RoundTripper, error) {
	return tlstrust.HTTPTransport("node tls", cfg.Node.TLS.CAFile, cfg.Node.TLS.PubkeyHash)
}
