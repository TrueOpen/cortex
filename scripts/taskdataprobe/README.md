# taskdataprobe

One real, correctly signed `GetTaskDataMetadata` against a live Nexus Builder,
using this node's own `CORTEX_NODE` service key, printing exactly what came back.

It is the live counterpart of `test/task_data_plane`: that harness proves the
Cortex-side logic in-process against a fake Builder; this proves the real hop
over real HTTP against the real chain identity. Nothing is reimplemented here —
the chain read (`internal/chainclient`), the request authority
(`internal/taskdataauth`), the endpoint resolution (`internal/builderdirectory`)
and the transport (`internal/builderclient`) are the same packages the daemon
runs.

Read-only in both directions: it never builds a chain transaction, never opens a
NATS connection, and issues only the metadata lookup — no upload, no receipt
relay.

## Run

```sh
go run ./scripts/taskdataprobe \
  -chain-rpc http://194.233.91.14:26657 \
  -chain-id trueopen-devnet-1 \
  -operator trueopen1... \
  -signer-dir /opt/cortex/node1/keystore \
  -service-key-ref service.json \
  -signer-password-file /opt/cortex/node1/keystore.pw \
  -builder trueopen1... \
  -session-id "$SESSION_ID" -task-id "$TASK_ID" \
  -task-hash "$ACCEPTED_TASK_HASH" -content-hash "$INPUT_HASH"
```

`-chain-rpc` is the CometBFT RPC endpoint (ABCI protobuf queries), not the REST
gateway on 1317: `chainclient.NewKeeperABCIClient` is what production uses.

All four object hashes are canonical 32-byte lowercase hex. The metadata body
digest commits the complete `TaskDataObjectRefV1`, including the accepted task
hash and content hash. Both values must match the object stored by the Builder.

The password is read from a file or an environment variable
(`-signer-password-env`), never from the command line. The keystore password, the
private key, the Nexus bearer token (`-nexus-token-file`) and NATS credentials
are never printed. The service public key is printed, in full and as a sha256
fingerprint.

## Endpoint resolution

By default the Builder endpoint comes from the chain: `Builder` →
`ServiceDescriptor` → the `NEXUS_GRPC` entry of
`ServiceDescriptorV1.endpoints`, read at one pinned height. The endpoint list is
consensus state, so there is no descriptor document to fetch and nothing to
dereference.

`-allow-plaintext-endpoint` (default off) maps to
`nexus.allow_insecure_descriptor`. Left off, a descriptor publishing a plaintext
`http://` endpoint is refused, so the advertised-https/served-http mismatch is
visible instead of silently tolerated. It admits nothing else: `grpc://` and
`grpcs://` are refused either way, and so is a `tls_pubkey_hash` this build
cannot check.

`-builder-endpoint URL` overrides the resolved endpoint. It exists for exactly
the case where the published scheme cannot be honoured. The override is always
reported as either matching what the descriptor publishes, diverging from it, or
not chain-verified at all.

## Output

Three sections, paste-ready:

1. `local service identity` — the queried participant type, the returned
   participant type, operator address, service address, service pubkey and its
   fingerprint, authorization nonce, revoked height, status, and the height the
   binding was read at.
2. `receiving Builder <addr>` — the raw on-chain descriptor commitment
   (version, URI, hash) plus the resolution outcome and the endpoint actually
   used.
3. `GetTaskDataMetadata request` — method, complete object key, requester,
   service authorization nonce, request nonce, expiry height, body digest and signature; then either
   `result: metadata` with the returned fields, or `result: error` with the full
   error text and whether `builderclient.IsRetryable` classifies it retryable.

Metadata reports readiness (`1` = stored, `2` = ready), content hash, exact byte
size, retention height, and any signed receipt. There is no `object_exists`
boolean in the released response.

Exit codes: `2` for a usage error, `1` for any probe failure, `0` only when the
Builder returned metadata.

## What it does not prove

- Nothing about `FetchTaskData`, upload, or receipt relay: only the metadata
  method is issued.
- Nothing about payload integrity: no bytes are fetched, so the
  `sha256(input) == Keeper payload hash` check that
  `NexusTaskInputResolver.ResolveTaskInput` performs is not exercised.
- Nothing about the returned metadata's correctness: the fields are printed, not
  compared against a Keeper task snapshot.
- Nothing about the Builder's own identity when `-builder-endpoint` is used:
  the override bypasses the descriptor commitment.
- Nothing about the daemon's wiring: the authenticator is constructed the way
  `internal/daemon/runtime.go` constructs it, but the runtime is not started.
