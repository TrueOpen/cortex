package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/tlstrust"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// selfSignedNode stands in for a chain node serving CometBFT RPC and Cosmos REST
// over TLS with a self-signed certificate.
func selfSignedNode(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":-1,"result":{"node_info":{"network":"trueopen-devnet-1"},"sync_info":{"latest_block_height":"42"}}}`))
		case "/cosmos/auth/v1beta1/accounts/trueopen1service":
			_, _ = w.Write([]byte(`{"account":{"@type":"/cosmos.auth.v1beta1.BaseAccount","address":"trueopen1service","account_number":"7","sequence":"9"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func pinnedNodeConfig(server *httptest.Server, pin string) config.Config {
	cfg := realConfig()
	cfg.Node.RPCEndpoint = server.URL
	cfg.Node.RESTEndpoint = server.URL
	cfg.Node.TLS = config.NodeTLSConfig{PubkeyHash: pin}
	return cfg
}

// nodeClients builds the three node clients exactly as NewRuntime does.
func nodeClients(t *testing.T, cfg config.Config) (*chainclient.KeeperABCIClient, *chainclient.CometEventClient, *txclient.CosmosHTTPClient) {
	t.Helper()
	transport, err := nodeHTTPTransport(cfg)
	if err != nil {
		t.Fatalf("nodeHTTPTransport: %v", err)
	}
	return chainclient.NewKeeperABCIClientWithTransport(cfg.Node.RPCEndpoint, transport),
		chainclient.NewCometEventClient(chainclient.CometEventClientConfig{RPCURL: cfg.Node.RPCEndpoint, ChainID: cfg.ChainID, Transport: transport}),
		txclient.NewCosmosHTTPClient(txclient.CosmosHTTPConfig{Endpoint: cfg.Node.RESTEndpoint, Transport: transport})
}

func TestNodeTLSPinReachesEveryNodeClient(t *testing.T) {
	server := selfSignedNode(t)
	cfg := pinnedNodeConfig(server, tlstrust.PubkeyHash(server.Certificate()))
	keeper, events, rest := nodeClients(t, cfg)
	ctx := context.Background()

	if height, err := keeper.ChainHeight(ctx); err != nil || height != 42 {
		t.Fatalf("Keeper ChainHeight = %d, %v", height, err)
	}
	if height, chainID, err := events.ChainStatus(ctx); err != nil || height != 42 || chainID != "trueopen-devnet-1" {
		t.Fatalf("CometBFT ChainStatus = %d, %q, %v", height, chainID, err)
	}
	if account, err := rest.Account(ctx, "trueopen1service"); err != nil || account.AccountNumber != 7 {
		t.Fatalf("Cosmos REST Account = %+v, %v", account, err)
	}
}

func TestNodeTLSWrongPinFailsEveryNodeClient(t *testing.T) {
	server := selfSignedNode(t)
	cfg := pinnedNodeConfig(server, strings.Repeat("ab", 32))
	keeper, events, rest := nodeClients(t, cfg)
	ctx := context.Background()

	if _, err := keeper.ChainHeight(ctx); err == nil {
		t.Fatal("Keeper client accepted a node whose key does not match the pin")
	}
	if _, _, err := events.ChainStatus(ctx); err == nil {
		t.Fatal("CometBFT client accepted a node whose key does not match the pin")
	}
	if _, err := rest.Account(ctx, "trueopen1service"); err == nil {
		t.Fatal("Cosmos REST client accepted a node whose key does not match the pin")
	}
}

// Without node.tls the clients stay on the system roots, so a self-signed node
// is refused exactly as before.
func TestNodeWithoutTLSConfigRefusesASelfSignedNode(t *testing.T) {
	server := selfSignedNode(t)
	cfg := pinnedNodeConfig(server, "")
	transport, err := nodeHTTPTransport(cfg)
	if err != nil || transport != nil {
		t.Fatalf("nodeHTTPTransport without node.tls = %v, %v; want nil", transport, err)
	}
	keeper, events, rest := nodeClients(t, cfg)
	ctx := context.Background()
	if _, err := keeper.ChainHeight(ctx); err == nil {
		t.Fatal("Keeper client trusted a self-signed node without node.tls")
	}
	if _, _, err := events.ChainStatus(ctx); err == nil {
		t.Fatal("CometBFT client trusted a self-signed node without node.tls")
	}
	if _, err := rest.Account(ctx, "trueopen1service"); err == nil {
		t.Fatal("Cosmos REST client trusted a self-signed node without node.tls")
	}
}

func TestBuildDependenciesKeeperUsesNodeTLS(t *testing.T) {
	server := selfSignedNode(t)
	cfg := pinnedNodeConfig(server, tlstrust.PubkeyHash(server.Certificate()))
	deps, err := BuildDependencies(cfg, DependencyOptions{})
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	if height, err := deps.Keeper.ChainHeight(context.Background()); err != nil || height != 42 {
		t.Fatalf("Keeper ChainHeight through BuildDependencies = %d, %v", height, err)
	}
}
