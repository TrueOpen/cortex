# Vendored Keeper query contract

`proto/CHAIN_BINDINGS.md` is the provenance record for the `hub/v1`,
`task/v1` and `shared/v1` Go bindings in this directory, and it is the
only one. The generated files reproduce from Node's proto tree at any commit in
`f57a268..be663af`; the hand-written `*_frozen.pb.go` wires target Node main
`8dd6729`, except two that come from `contract/proto-v1-all-domains` (`d8792e6`)
— see `CHAIN_BINDINGS.md:20-26` and the table at `:61-74`.

What this file adds is the transport shape those bindings are generated for.
Cortex issues every Keeper read as a CometBFT `/abci_query` over JSON-RPC, with
the service path in the `path` parameter and the marshalled request hex-encoded
into `data` (`internal/chainclient/abci.go:96-107`, `:110`). Service methods are
built from the `/hub.v1.Query/` and `/task.v1.Query/` prefixes
(`internal/chainclient/keeper.go:17-20`), giving paths such as
`/hub.v1.Query/Model` (`keeper.go:365`) and `/task.v1.Query/Task`
(`keeper.go:330`). Because the query value is protobuf bytes rather than a URL
path segment, an identifier containing `/` survives the round trip. No generated
gRPC client is ever involved.

The small local `cosmos.base.v1beta1.Coin` and pagination bindings preserve the
wire fields these responses reference without importing the full Cosmos SDK
(`CHAIN_BINDINGS.md:64-65`). When Node changes its query contract, regenerate by
the recipe in `CHAIN_BINDINGS.md` and update the provenance record there,
together with the transport tests.
