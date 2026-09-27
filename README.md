# cortex

Cortex is an integration-ready control plane for TrueOpen model execution. It wires
model registration, Worker inference, Verifier commit/reveal, settlement
material, evidence retention, challenge verifier state, and operator diagnostics
around explicit local or real infrastructure boundaries.

The repository is useful in two modes:

- **Developer mode** uses fake boundaries so the end-to-end control-plane path
  can run without live Keeper, Nexus, node RPC, signer, or model-management
  services.
- **Real mode** connects to configured Keeper, Nexus, tx broadcaster, signer,
  model-management, evidence, store, and admin socket boundaries. Readiness is
  fail-closed: missing dependencies are reported through diagnostics instead of
  being silently replaced by fake services.

## Architecture At A Glance

- `cortexd` is the long-running daemon. It loads config, opens the Pebble store,
  starts the admin Unix socket, exposes HTTP health checks, and runs the
  Keeper poller, task runner, outbox/inbox runners, and observability projector
  when their dependencies are ready.
- `cortexctl` is the local operator CLI. It talks to the `cortexd` admin socket
  for diagnostics, capability checks, model registry operations, treasury state,
  and read-only earnings views.
- Keeper is the chain-facing event/query boundary. The daemon reads finalized
  CometBFT blocks, applies each block idempotently, then advances one durable
  last-processed height after every relevant effect succeeds.
- Nexus is the Builder publish/subscribe boundary. The current NATS boundary
  includes concrete publish and subscribe adapters with dedup IDs, URL
  validation, retryable transport errors, and JetStream redelivery.
- The model-management service is the LLM execution boundary. Cortex supports
  fake, gRPC, and local in-process adapter modes.
- Pebble stores only restart-critical local state: signed handraise candidates,
  active infer and verify responsibility documents, the last processed Keeper
  height, and one evidence metadata record per task hash. It is not an audit or
  protocol-history database.
- Evidence bytes live under the configured evidence root. The Pebble record holds
  the digest, size, finality/cleanup heights, and cleanup state needed to manage
  the corresponding content-addressed package.

## Quick Start

Prerequisites:

- Go 1.23 or newer, matching the `go` directive in `go.mod`
- `make`

The store is pure Go; a CGO toolchain or SQLite development package is not
required.

Build both binaries:

```sh
make build
```

Start the daemon in fake mode:

```sh
bin/cortexd -config configs/dev.yaml
```

In another shell, query diagnostics through the default development admin
socket:

```sh
bin/cortexctl --admin-socket /tmp/cortexd.sock diagnostics --format json
```

Fake mode uses local fake Keeper, Builder/Nexus, tx, and model-service
boundaries. It is the default path for local development and integration-ready
tests.

## Build

The Makefile is the preferred local build entry point:

```sh
make build
make cortexd
make cortexctl
make install
make clean
make help
```

`make build` writes:

- `bin/cortexd`
- `bin/cortexctl`

The direct Go equivalents are:

```sh
go build -o bin/cortexd ./cmd/cortexd
go build -o bin/cortexctl ./cmd/cortexctl
```

The Makefile uses plain `go` by default. If your local environment wraps commands
with another launcher, use that outside `make`; the project build itself does
not require one.

`make install` installs only the two command binaries to `$(PREFIX)/bin`
(`PREFIX=/usr/local` by default). For a Linux systemd service install, use the
runbook in `docs/operations/installation.md`.

## Test

Run the full suite:

```sh
make test
```

Focused package checks:

```sh
make test-fast
```

Integration readiness smoke check:

```sh
make test-integration-readiness
```

Raw Go commands:

```sh
go test ./... -count=1
go test ./internal/evidence ./test/fakes
go test ./test/integration_readiness -count=1
```

Some current developer environments run commands through `rtk`; the equivalent
full check is:

```sh
rtk go test ./...
```

Before committing, run:

```sh
go test ./... -count=1
```

## Configuration

Cortex config files are strict YAML decoded with `yaml.v3`; unknown fields fail
startup and lists use normal YAML sequence syntax. Deployment configuration is
resolved in this order: built-in defaults, YAML, `CORTEX_*` environment
variables, then explicitly set `cortexd` flags. Environment values and flags
override only deployment-varying endpoints, identity, ports, and paths. Secret
values are never printed; configure paths or environment-variable names that
point to secret material instead. An environment variable that is present but
empty is treated as unset, while an explicitly supplied empty flag value is an
override and is validated normally.

Run `bin/cortexd --help` and `bin/cortexctl --help` for the generated command
and flag reference. The complete deployment environment allowlist is below;
the corresponding flag always has higher precedence.

| Environment variable | `cortexd` flag | Config target |
| --- | --- | --- |
| `CORTEX_MODE` | `--mode` | `mode` |
| `CORTEX_CHAIN_ID` | `--chain-id` | `chain_id` |
| `CORTEX_ADMIN_SOCKET` | `--admin-socket` | `admin.uds_path` |
| `CORTEX_MODEL_ENDPOINT` | `--model-endpoint` | `model_management.endpoint` |
| `CORTEX_MODEL_TRANSPORT` | `--model-transport` | `model_management.transport` |
| `CORTEX_MODEL_MAX_CONCURRENCY` | `--model-max-concurrency` | `model_management.max_concurrency` |
| `CORTEX_NODE_RPC` | `--node-rpc` | `node.rpc_endpoint` |
| `CORTEX_NODE_REST` | `--node-rest` | `node.rest_endpoint` |
| `CORTEX_KEEPER_API` | `--keeper-api` | deprecated compatibility setting; Keeper reads use `node.rpc_endpoint` |
| `CORTEX_KEEPER_POLL_INTERVAL_MS` | `--keeper-poll-interval-ms` | `keeper.poll_interval_ms` |
| `CORTEX_KEEPER_MAX_LAG_BLOCKS` | `--keeper-max-lag-blocks` | `keeper.max_lag_blocks` |
| `CORTEX_TASK_RETRY_DELAY_MS` | `--task-retry-delay-ms` | `task_execution.retry_delay_ms` |
| `CORTEX_TASK_MAX_RETRY_ATTEMPTS` | `--task-max-retry-attempts` | `task_execution.max_retry_attempts` |
| `CORTEX_TASK_INPUT_RESOLVER` | `--task-input-resolver` | `task_execution.input_resolver` |
| `CORTEX_TASK_FIXTURE_ROOT` | `--task-fixture-root` | `task_execution.fixture_root` |
| `CORTEX_NEXUS_INGRESS` | `--nexus-ingress` | `nexus.ingress_url` |
| `CORTEX_NEXUS_NATS` | `--nexus-nats` | `nexus.nats_url` |
| `CORTEX_NEXUS_AUTH_TOKEN_FILE` | `--nexus-auth-token-file` | `nexus.auth_token_file` |
| `CORTEX_NEXUS_ENVELOPE_AUTH_MODE` | `--nexus-envelope-auth-mode` | `nexus.envelope_auth_mode` |
| `CORTEX_NEXUS_ENVELOPE_TTL_MS` | `--nexus-envelope-ttl-ms` | `nexus.envelope_ttl_ms` |
| `CORTEX_NEXUS_ENVELOPE_CLOCK_SKEW_MS` | `--nexus-envelope-clock-skew-ms` | `nexus.envelope_clock_skew_ms` |
| `CORTEX_NEXUS_SUBSCRIBE_MODELS` | `--nexus-subscribe-models` | `nexus.subscribe_models` |
| `CORTEX_MODEL_ID` | `--nexus-subscribe-models` | `nexus.subscribe_models` (deployment alias) |
| `CORTEX_NEXUS_SUBSCRIBE_TASKS` | `--nexus-subscribe-tasks` | `nexus.subscribe_tasks` |
| `CORTEX_ARTIFACTS_ROOT` | `--artifacts-root` | `artifacts.root` |
| `CORTEX_EVIDENCE_ROOT` | `--evidence-root` | deprecated compatibility setting; use `artifacts.root` |
| `CORTEX_STORE_PATH` | `--store-path` | `store.path` |
| `CORTEX_SIGNER_URI` | `--signer-uri` | `signer.uri` |
| `CORTEX_SIGNER_READINESS_PROOF_INTERVAL_MS` | `--signer-readiness-proof-interval-ms` | `signer.readiness_proof_interval_ms` |
| `CORTEX_SIGNER_PASSWORD_ENV` | `--signer-password-env` | `signer.password_env` |
| `CORTEX_SIGNER_PASSWORD_FILE` | `--signer-password-file` | `signer.password_file` |
| `CORTEX_SIGNER_PASSWORD_STDIN` | `--signer-password-stdin` | `signer.password_stdin` |
| `CORTEX_OPERATOR_ADDRESS` | `--operator-address` | `local_identity.operator_address` |
| `CORTEX_SERVICE_KEY_REF` | `--service-key-ref` | `local_identity.service_key_ref` |
| `CORTEX_MODEL_PROFILES` | `--model-profiles` | `local_identity.supported_model_profiles` |
| `CORTEX_MODEL_SERVICE_ID` | `--model-service-id` | `local_identity.model_service_id` |
| `CORTEX_NEXUS_BUILDER_OPERATOR` | `--nexus-builder-operator` | `nexus.builder_operator_address` |
| `CORTEX_NEXUS_ALLOW_INSECURE_DESCRIPTOR` | `--nexus-allow-insecure-descriptor` | `nexus.allow_insecure_descriptor` |
| `CORTEX_NEXUS_DOWNGRADE_DESCRIPTOR_TLS` | `--nexus-downgrade-descriptor-tls` | `nexus.downgrade_descriptor_tls` |
| `CORTEX_HEALTH_BIND` | `--health-bind` | `health.bind` |

`CORTEX_MODEL_ID` is only a deployment-compatible alias for the Nexus model
subscription subject; it does not set `local_identity.model_service_id` or a
model profile. When both model-subscription environment variables are set,
`CORTEX_NEXUS_SUBSCRIBE_MODELS` wins, and `--nexus-subscribe-models` wins over
both.

### Model ids

A `model_id` is the chain's Hash32 model id, written as 64 lowercase hex
characters, in `local_identity.supported_model_profiles`
(`<model_id>@<profile_version>=<capability>`), `nexus.subscribe_models`,
`CORTEX_MODEL_ID` and `CORTEX_MODEL_PROFILES`. A name such as `llama-main` is
refused. Look the id up from the model's source on chain:

```sh
bin/cortexctl model find --rpc <keeper-rpc> --provider HUGGINGFACE --repo <owner/name> --format json
```

At startup, and on every readiness check, each configured model id is read
from its chain ModelState and bound to that model's `repo_id`. The local vLLM
adapter serves only `HUGGINGFACE` sources, and the vLLM served model name
(`--served-model-name`, or the model path vLLM reports under `/v1/models`)
must equal the chain `repo_id` exactly. Until it does, `model_service` stays red
with one of these reasons:

- `query ModelState <id>`: the id is not registered on this chain;
- `has source provider "<p>"; the local adapter serves only HUGGINGFACE`;
- `model <id> is registered for <repo>, but vLLM serves [...]`: the served
  model name differs from the chain `repo_id`;
- a vLLM health or `/v1/models` error: vLLM is not answering.

### Upgrading to v0.3

v0.3 changes the Worker evidence (two bundles of token ids and per-position
values instead of a trace and a checkpoint) and the receipts (InferReceiptV3,
ResultReceiptV3). Task data written by an older node cannot be finished or
verified under v0.3, so `cortexd` refuses to start while the store holds any:
trace or checkpoint evidence, or an infer receipt of an older schema. Drain
every in-flight task on the previous release first (let each responsibility
reach a terminal state), or start v0.3 from an empty `store.path` and
`artifacts.root`.

### Config migration from the legacy parser

The old parser accepted comma-separated scalars for list fields. Strict YAML
requires sequences, so migrate, for example,
`supported_model_profiles: a@1=llm_text_v1,b@1=llm_text_v1` to
`supported_model_profiles: [a@1=llm_text_v1, b@1=llm_text_v1]`. Apply the same
conversion to `nexus.subscribe_models`, `nexus.subscribe_tasks`,
`local_identity.supported_model_profiles`, and `self_rescue.allowed_tx_types`.

`local_identity.duties` is gone. Every node holds both the WORKER and the
VERIFIER responsibility and is drawn for either by the chain, so a config that
still carries the key is refused at startup with a message naming it. Delete the
line; there is nothing to replace it with. `CORTEX_DUTIES` and `--duties` are
gone with it.

Important examples:

- `configs/dev.yaml`: fake-mode local development.
- `configs/integration.example.yaml`: real-mode shape for integration
  environments.
- `configs/real.example.yaml`: production boundary checklist.

Core sections:

- `mode`: `fake` or `real`.
- `chain_id`: chain binding used in signed and hashed material.
- `admin.uds_path`: Unix socket consumed by `cortexctl`.
- `model_management`: LLM service transport and endpoint.
- `node`: CometBFT RPC and Cosmos REST endpoints.
- `keeper`: poll interval and max lag policy; state reads use `node.rpc_endpoint`
  via ABCI (`api_url` remains a deprecated compatibility setting).
- `task_execution`: retry delay plus `input_resolver`, which selects where a
  Worker reads task input. `nexus` resolves the receiving Builder's verified
  descriptor, authenticates with the current Cortex service key, reads metadata,
  streams ranged `FetchTaskData`, and verifies the complete size and
  Keeper-accepted payload hash. It requires `model_management.transport` `grpc`
  or `local` and is the production Worker shape. `fixture` reads from a local
  `task_execution.fixture_root`, requires `model_management.transport: fake`,
  and is only for fake-transport integration. V1 task data is plaintext
  protected in transit by verified TLS and end to end by semantic hashes and
  signatures; there is no application-layer encryption or payload key-store
  setting.
- `nexus`: Builder ingress, NATS URL, shared HTTP bearer-token file, and
  subscription subjects. Task-data endpoints come from per-task Builder
  descriptors rather than a static credential or endpoint fallback.
- `nexus.envelope_auth_mode`: `strict` (the default) or `trusted_nats_dev`.
  `strict` signs every outbound `trueopen.*` BusEnvelope with this node's current
  Cortex service key and requires a valid signature on every inbound envelope,
  verified against the sender's current on-chain service key. `trusted_nats_dev`
  treats the authenticated NATS transport plus its publish/subscribe ACL as the
  authentication boundary, publishes unsigned envelopes, and is reported as the
  `UNSAFE_TRUSTED_TRANSPORT` security warning. The Nexus that ships today does
  not sign BusEnvelopes, so a `strict` node rejects every inbound Builder
  message and takes no work; devnet deployments must use `trusted_nats_dev`
  until that upstream gap closes. See
  `docs/operations/cortexd-real-mode.md`.
- `nexus.envelope_ttl_ms` (default 30000) and `nexus.envelope_clock_skew_ms`
  (default 2000): the TTL stamped on outbound envelopes, the maximum accepted
  lifetime of an inbound one, and the tolerated clock skew when judging inbound
  `issued_at`/`expires_at`. These are deployment config, not chain governance
  parameters, and must be kept consistent between Nexus and Cortex.
- `tx`: fee, gas, retry, inclusion, and Keeper-confirmation settings.
- `evidence` and `store`: durable local evidence root and Pebble `path`.
- `signer`: HTTP signer endpoint exposing only the current online service key.
- `local_identity`: stable operator address (the Cortex node identity), duty
  set, service key reference, supported model/profile pairs, and model service ID.
- `nexus.builder_operator_address` and `nexus.allow_insecure_descriptor`: the
  operator address is an optional narrowing filter, not the authority over who
  may address this node. Bus senders are authorized against the chain's current
  BuilderSet, so an empty setting admits every current member and a Builder the
  chain has removed is refused even when the setting still names it. When it is
  set, cortexd additionally reads that Builder's on-chain service descriptor at a
  pinned height and stays unready unless the descriptor's `NEXUS_GRPC` endpoint is
  byte-for-byte the configured `nexus.ingress_url` and the Builder is in the
  current BuilderSet.
  The endpoint list lives in consensus state, so there is no descriptor document
  to fetch and nothing to dereference. V1 task data is plaintext over
  authenticated TLS, so the explicit insecure opt-in is what admits an `http://`
  endpoint; `https://` is the only other scheme cortexd will dial. It is devnet
  only; production leaves it false. It never relaxes anything else — a
  superseded descriptor version, a missing `NEXUS_GRPC` endpoint, a duplicate
  endpoint kind, and a `tls_pubkey_hash` this build cannot check all stay
  refused with the flag set.
- `self_rescue`: the **deadline-risk** direct tx policy, and only that. Real mode
  requires `enabled` to remain false until the durable scheduler in issue #108
  lands. It does not gate the verifier commit exit — a signed verify commit has
  no relay to travel on, so every real-mode node submits its own
  `MsgSubmitVerifyCommit` regardless of this flag, which is why `tx.enabled` is
  required in real mode. `max_fee_amount` does apply to that exit, as a bound
  that may only narrow `tx.max_fee_amount`.
- `challenge_verifier`: opt-in challenge verifier mode.
- `health`: HTTP health bind address.

## Runtime Modes

### Fake Mode

Fake mode is for local development and deterministic tests. It uses fake
boundaries while still exercising the same control-plane packages, store schema,
evidence root, model registry commands, Worker infer path, Verifier path, and
operator diagnostics.

Run it with:

```sh
bin/cortexd -config configs/dev.yaml
```

### Real Mode

Real mode is configured through `configs/real.example.yaml` and keeps the same
package interfaces while using explicit Keeper, Nexus, tx broadcaster, signer,
model-management gRPC, evidence, store, and admin socket boundaries.

Run it with:

```sh
bin/cortexd -config configs/real.example.yaml
bin/cortexctl --admin-socket /var/run/cortex/cortexd.sock diagnostics --format json
```

Real mode starts workload runners only when the required external boundaries are
ready. Otherwise JetStream retains unacknowledged delivery work, active local
responsibilities remain in Pebble, and diagnostics report the configuration error.

Keeper accepted events remain authoritative. Nexus delivery alone does not
start Worker or Verifier jobs without accepted Keeper effects.

## Model-Service Integration

`model_management.transport` selects how Cortex calls the LLM execution
boundary:

- `fake`: in-memory fake service for local tests and fake mode.
- `grpc`: production transport backed by the checked-in protobuf service.
- `local`: in-process adapter for a model service implemented inside this
  repository.

Model-management now has a concrete gRPC transport backed by the checked-in
protobuf service, request/response mapping for health, capabilities, model
artifact, provenance, derivation, and configuration details; load, estimate,
infer and verify, streaming artifact fetch, and artifact ref/digest/size
validation; retryable/deadline error classification; and real-mode readiness
diagnostics through `Health`.

`ListCapabilities.resource_snapshot` must report `queue_depth` and
`max_concurrency` in real mode. Queue depth counts admitted jobs currently
consuming that concurrency budget. Cortex computes free handraise capacity
from those values and fails closed when they are missing, inconsistent, or
exhausted; `loaded_models` alone is not capacity authority.

`model_management.max_concurrency` is also Cortex's local TaskRunner dispatch
ceiling. The configuration default is zero ("unset"). For `local`, validation
rejects zero; for `grpc` and `fake`, the TaskRunner conservatively normalizes
zero to one concurrent row. Start at one unless the exact model, profile, GPU,
and request-size mix has been load-tested. Increase it stepwise and select the
highest value whose end-to-end p95 inference latency, including task data
transfer and result publication margin, remains below the profile's protocol
deadline without sustained queue growth or GPU out-of-memory failures.
`resource_snapshot.max_concurrency` and vLLM `--max-num-seqs` are hard ceilings,
not recommended operating values. Keep the configured value at or below the
applicable ceiling. The TaskRunner waits for every dispatched row before
recovering failed lifecycle writes, so one row's retryable or terminal error
does not cancel its siblings or release rows that are still running.

The `local` adapter is intentionally a stub today. It implements the same
client-facing surface, including `Health`, `ListCapabilities`,
`GetModelDetails`, `LoadModel`, `Estimate`, `Infer`, `Verify`, and
`FetchArtifact`, but currently returns:

```text
modelservice local adapter not implemented
```

Use `local` when another engineer will implement the LLM `infer`, `verify`, and
artifact behavior inside the Cortex process instead of exposing it over gRPC.
`model_management.endpoint` is not required for `local`.

## Operator CLI

All commands talk to the daemon admin socket. Use `--admin-socket` when the
socket is not the default for your environment.

Diagnostics and capabilities:

```sh
bin/cortexctl diagnostics --format json
bin/cortexctl capability --format json
```

Model registry:

```sh
cp configs/model-profile.current.example.json profile.json
bin/cortexctl model manifest generate --profile profile.json --version 1.0.0 \
  --tokenizer tokenizer-v1 --model-service model-service-main --format json > model.json
bin/cortexctl model manifest validate --manifest model.json
bin/cortexctl model self-test --manifest model.json --format json
bin/cortexctl model list
bin/cortexctl model status <model_id> --format json
bin/cortexctl model show <model_id> --format json
bin/cortexctl model support <model_id> --dry-run
bin/cortexctl model daily-support <model_id> --dry-run
```

Model/profile registration is an offline operator action and is intentionally
not signed by cortexd. See [Model Registry Operations](docs/operations/model-registry.md)
for the schema-v3 projection format and digest behavior.
Current Node registration is atomic through `MsgRegisterModelProfile`, the only
model/profile creation message in the frozen `hub` contract.

Treasury and earnings:

```sh
bin/cortexctl treasury status --format json
bin/cortexctl earnings status --format json
```

The compact store has no durable generic task queue or failed-row requeue
surface. Operators should use diagnostics, structured task logs, Keeper state,
and JetStream consumer state; active infer/verify responsibilities are restored
automatically and terminal responsibilities are deleted.

Evidence retention:

```sh
bin/cortexctl evidence cleanup --format json
```

Default operator tables for `model status` and `model list` expose support
state/P30, MarkGate/top10, reward state, failure risk, TreasuryState,
hardware-tier proof, Builder fault observations, EmergencyFreeze, read-only
pending/claimable earnings, and task finality/claim height fields.

## Worker, Verifier, Settlement, And Challenge Flow

The Worker hot path evaluates and signs WorkerHandraise material only after
precheck acceptance, persists one stable candidate before Builder publish,
treats assignment-finalized events as the authority for starting local
inference, recomputes output hashes from fetched artifacts, and has validated
receipt-only and WorkerRevealReceipt rescue handlers through `txclient`.
Automatic deadline-driven invocation of those handlers is not yet wired and is
tracked by issue #108. Worker reveal
handling stores full `W_i` opening material in evidence while publishing or
broadcasting only the sampled-value receipt payload.

Production task output uses the same runtime-owned task-data client and current
service-key authenticator as input. After inference Cortex waits for the
`SubmitInferReceipt` relay ack, sends `UploadTaskResultData` through FIN, verifies
and persists the receiving Builder's signed storage confirmation, and only then
publishes `OUTPUT_AVAILABLE`. Input and output currently use the single receiving
Builder named by the assignment; three-Builder fan-out and 2-of-3 confirmation
tracking require an immutable task Builder list from the Node. Real integration
also remains gated on Nexus merging current Cortex service-key authorization,
including the generic method/body/nonce/height-bound auth path for
`SubmitInferReceipt`; Cortex does not fall back to an operator key.

NATS control messages use Nexus `BusEnvelope` schema v1 with the business
message nested under `payload`. Cortex rejects the former flattened JSON shape,
binds the actual subject/chain/kind/session/task/TTL before payload decoding,
and uses Nexus-compatible base64 encoding for byte fields. Exact-frame replay
state is an in-memory TTL cache. In `strict` mode cortexd
now constructs the envelope signer and authenticator from configuration: it
signs outbound envelopes with the node's current service key and verifies
inbound ones against the sender's current on-chain service key, with no
historical-key or unsigned fallback. What still blocks a
working `strict` deployment is upstream: Nexus does not sign the envelopes it
publishes and does not verify inbound signatures, so every inbound Builder
message is rejected for a missing signature. That is TrueOpen/nexus#45.
See `docs/reviews/nexus-bus-envelope-contract.md` and
`docs/operations/cortexd-real-mode.md`.

The Verifier hot path persists VerifierHandraise material before Builder
publish, requires OpenVerify accepted plus formal verifier assignment before
starting model-service verification, derives the verification sample seed with
chain/task/package bindings, stores local `V_i` and reveal skeleton evidence,
publishes commit material, and validates verifier self-rescue tx submissions
against deadline height and material digest. Automatic scheduling remains
disabled pending issue #108.

Settlement/evidence support includes a deterministic task evidence root builder
with fixed leaf ordering, `leaf_count_by_type`, manifest hash binding,
worker/verifier opening leaves, and full-result reveal references. Mismatch,
double-sign, and verdict-fraud observations are retained as local evidence
under `fault_id`. Their former proof type URLs are audit labels only: the
current Keeper does not register those messages, so Cortex has no encoder,
adapter, or broadcast path for them.

Challenge verifier mode is disabled by default and alert-only when not enabled.
When enabled, the challenge FSM uses a separate challenge state domain,
persists observations under independent `challenge_id`, validates the original
Worker evidence bundles and verifier-set bindings before compute, verifies
against the original committed material, submits challenge commit/result txs through
`txclient`, and mirrors final challenge outcome only from accepted Keeper
events.

## Storage, Evidence, And Observability

The Pebble store is intentionally compact. It groups keys by lifetime across the
prefixes `meta/`, `runtime/`, `candidate-current/`, `candidate/`,
`verify-candidate/`, `task/`, `infer/`, `verify/`, `delivery/`, `evidence/`,
and `challenge/`. Large evidence and result material stays in the
content-addressed evidence filesystem.

### SQLite/bbolt-to-Pebble cutover and rollback

`store.path`, `CORTEX_STORE_PATH`, and `--store-path` replace the old
legacy settings with no aliases. An existing SQLite or bbolt file is rejected
with migration/drain guidance; Cortex does not import it.
Before upgrading, stop the old daemon at a finalized Keeper boundary, drain or
explicitly account for active task responsibilities, and make a backup copy of
the old SQLite or bbolt file for rollback. Configure a new Pebble sibling
directory for the cutover.

For an operator backup, stop `cortexd`, copy the entire configured Pebble
`store.path` directory and `artifacts.root` into the same generation directory,
then restart the daemon. This is a sibling-directory swap, not an in-place
upgrade. Restore both directories from that generation while the daemon is
stopped. `Store.Checkpoint` is an internal Go/API option for integrations that
need an online Pebble snapshot; it is not a `cortexctl` or `cortexd` operator
command, and its output still must be paired with the evidence root as one
generation. To return to a legacy release, preserve the new Pebble/evidence
directories, restore the old database and configuration, then start the old
binary; the new binary never opens a legacy SQLite or bbolt file. See
[Real-mode operations](docs/operations/cortexd-real-mode.md) for the full
cutover checklist.

Rollback boundary: a plain paired-backup restore is safe only before delivery
resumes; afterwards the admission barrier must be repeated and the target
admission and role prefixes drained to zero.

Observability derives runtime and Keeper-facing gauges without treating Pebble as
an analytics database. The registry is served in Prometheus text format on the
health bind:

```sh
curl -fsS http://127.0.0.1:8081/metrics
```

Declared metrics render at zero when unobserved, so a missing series means a
broken exporter rather than an uninteresting value. Fake mode runs no projector
and serves an empty body rather than a different status code, so a scrape target
stays valid across modes.

Operator JSON views keep protocol `chain_state`, index/display
`display_visibility`, `verification_label`, and `reward_state` as distinct
fields. Readiness remains fail-closed when real dependencies are unavailable.

## Real-Mode Operations

Use `configs/real.example.yaml` as the production boundary checklist.

Required real-mode boundaries include:

- CometBFT RPC (ABCI state queries plus finalized block results)
- Nexus ingress and NATS publish/subscribe
- model-management gRPC or local model service
- tx broadcaster configuration
- signer URI
- stable Cortex node/operator identity, ServiceKey, and model service ID
- durable evidence root and Pebble KV path
- admin socket and health endpoint

Operator runbooks live in `docs/operations/`:

- `devnet-deployment.md`: Docker/Compose deployment, single-node identity
  bootstrap, readiness checks, and model support commands.
- `installation.md`: binary installation, systemd service setup, runtime user,
  config paths, and verification commands.
- `cortexd-real-mode.md`: startup, dependency matrix, diagnostics, and
  fail-closed readiness checks.
- `model-registry.md`: registration, support/daily-support, display/trust, and
  `reward_state` behavior.
- `evidence-retention.md`: cleanup, task finality, preserved settlement
  material, non-destructive cleanup planning, and earnings view expectations.
- `troubleshooting.md`: common fail-closed diagnostics for gRPC, NATS, Keeper,
  tx, and admin socket issues.
- `signer.md`: signer URI schemes, keystore v3 key directories, password
  sources, and which signing paths work in each mode.

Start troubleshooting with:

```sh
bin/cortexctl diagnostics --format json
```

Useful follow-up commands:

```sh
bin/cortexctl capability --format json
bin/cortexctl model list
bin/cortexctl model status <model_id> --format json
bin/cortexctl treasury status --format json
```

## Repository Layout

```text
cmd/
  cortexd/       daemon entry point
  cortexctl/     operator CLI
configs/         fake, integration, and real-mode examples
docs/
  operations/    operator runbooks
  specs/         current implementation designs
  reviews/       upstream contract reconciliation
internal/        daemon, boundaries, store, model service, registry, policies
proto/           vendored chain bindings (hub/, task/, shared/,
                 cosmos/), the vendored Nexus contract (nexus/), and the
                 model-management bindings (cortex/); provenance and
                 regeneration policy in proto/CHAIN_BINDINGS.md
test/
  fakes/         fake-backed end-to-end tests
  integration/   adapter-backed integration loop tests
  integration_readiness/
```

Important internal packages:

- `internal/daemon`: runtime wiring, task runner, Keeper poller, reconciler.
- `internal/modelservice`: fake, gRPC, local, and remote model-service clients.
- `internal/modelregistry`: manifest, registration, support, projections.
- `internal/store`: compact Pebble restart state keyed by task hash.
- `internal/evidence`: evidence storage, cleanup, roots, and proof material.
- `internal/txclient`: tx broadcaster abstraction and fake tx client.
- `internal/observability`: health checks, projector, and metrics.

## Integration Status

The implemented slice covers local and real-mode config, identity and protocol
hashes, model manifest registration, support confirmations, Worker infer,
Verifier commit/reveal, settlement/self-rescue material, evidence storage and
cleanup, challenge verifier state, observability projections, and operator
diagnostics.

`./test/fakes` exercises the end-to-end `llm_text_v1` control-plane path using
fake Keeper/Builder/Nexus/tx/model-service boundaries, Pebble store, and a local
evidence root.

`./test/integration` exercises the adapter-backed final loop: registration and
support, Keeper polling, scheduler queues, Worker infer, Verifier canonical
package fetch/verify, settlement, challenge full reveal, projector status,
cleanup, and restart recovery.

`./test/integration_readiness` covers adapter-level readiness for configured
real-mode boundaries without requiring live TrueOpen services.

Model registry support and daily-support generate exact signed Keeper messages,
submit Cosmos transactions, persist confirmed support rows, and reconcile
accepted Keeper model profile/support events into local projections.

The txclient uses Cosmos Auth and Tx REST, an external HTTP signer returning
signed `TxRaw`, and message-specific Keeper queries. It persists `BROADCAST`,
`INCLUDED`, `KEEPER_CONFIRMED`, and `REJECTED` separately, and never treats a
successful mempool response as protocol completion. Operator lifecycle actions
are offline; cortexd uses the current service key for task material and for
every direct Cosmos transaction it sends, including the verifier commit exit —
whose outer Tx signer must be this operator's current Cortex service address.
Real-mode automatic **deadline-risk** self-rescue remains disabled until issue
#108 supplies the durable deadline scheduler; the commit exit is not part of
that, because relay unavailability is known synchronously and needs no
scheduler.

Remaining deployment-specific integrations are live infrastructure concerns:
external Keeper and Nexus availability, signer/HSM policy, node RPC
credentials/rate limits, Builder discovery policy, TLS/auth policy, and
deployment policy for long-running Worker/Verifier capacity. The durable,
restart-safe deadline scheduling tracked by issue #108 is also required before
operators may enable `self_rescue` in real mode.

One upstream contract is still missing rather than deployment-specific: Nexus
publishes BusEnvelopes without a signature and does not verify the signature on
the ones it receives (nexus#45). Cortex builds the `strict` signer and
authenticator, so a `strict` node signs correctly but rejects every inbound
Builder message. Note what `nexus.envelope_auth_mode: trusted_nats_dev` does and
does not buy: it relaxes signature verification only. It does not relax the
20-field wire shape, which `DecodeBusEnvelope` enforces before any signature
check (`internal/builderclient/envelope.go:553-567`, reached first at
`internal/daemon/task_runner_nexus.go:395`), so a peer publishing the shorter legacy
envelope is refused in either mode. See
`docs/reviews/upstream-interop-status.md` §2.4.
