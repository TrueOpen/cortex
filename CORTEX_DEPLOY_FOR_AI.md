# Cortex deployment runbook (agent-readable)

Audience: an AI agent driving a Cortex deployment. Written to be executed, not
read for pleasure. Every command is copy-pasteable; every claim that was not
verified against this repository is marked **VERIFY**.

Source of truth for anything below is the repository itself. When this file and
the code disagree, the code wins — say so and fix this file.

---

## 0. What Cortex is, in one paragraph

Cortex is a Go control plane. It talks to four external systems and fakes all of
them in tests:

| Boundary | What it is | Config keys |
|---|---|---|
| Keeper / chain | CometBFT node, RPC + REST | `node.rpc_endpoint`, `node.rest_endpoint`, `node.tls` |
| Nexus | Builder ingress (connect-go) + one DispatchStream per Builder | `nexus.ingress_url`, `dispatch.builders` |
| Model service | vLLM over HTTP (`local`), or a model-management gRPC service (`grpc`) | `model_management.transport`, `model_management.endpoint` |
| Signer | local keystore (`file://`) or remote HTTP | `signer.uri`, `local_identity.service_key_ref` |

Two binaries: `cortexd` (daemon) and `cortexctl` (operator CLI over a Unix
socket, plus offline helpers such as `onboard` and `model find`).

**Fail-closed is the design.** Real mode never substitutes a fake for a missing
dependency. A red dependency means the affected runner stays stopped, not that
the daemon silently degrades. Do not "fix" a readiness failure by adding a
fallback.

---

## 1. Decisions to make before anything else

### 1.1 Mode

```yaml
mode: fake          # configs/dev.yaml
mode: integration   # same real dependencies, admits dev-only flags; never promote
mode: real          # deploy/testnet/cortex.yaml.template
```

`fake` replaces the model service, the Builders and the chain with fixtures
(`internal/daemon/dependencies.go`) and builds no task runner. It is the right
mode for exercising storage and restart recovery and the wrong mode for anything
about model output: the decode path in `internal/modelservice/local*.go` does
not execute.

- verifying scheduling, storage, restart recovery → `fake`, local, no GPU
- verifying decode / tokens / output commitment → `real` against a vLLM
- verifying the full round trip → a real deployment (see §1.3 first)

### 1.2 Model transport — the one most likely to be wrong

`model_management.transport` decides what `model_management.endpoint` points at.

| Transport | Endpoint | What must be listening | Extra requirements |
|---|---|---|---|
| `local` | vLLM base URL, e.g. `127.0.0.1:8000` (`http://` is added when no scheme is given; empty means `http://127.0.0.1:8000`) | vLLM's OpenAI server | `model_management.max_concurrency` > 0 (validation refuses 0) |
| `grpc` | `host:port` of a model-management gRPC service, e.g. `127.0.0.1:9090` | a service implementing `proto/cortex/v1` ModelManagementService | TLS (`model_management.tls`) unless loopback |
| `fake` | — | nothing | dev only; pairs with `task_execution.input_resolver: fixture` |

**Cortex + vLLM on the same GPU host means `local`.** The shipped testnet
template (`deploy/testnet/cortex.yaml.template`) and `configs/real.example.yaml`
both say `transport: grpc` with endpoint `127.0.0.1:9090`. This repository does
not ship the gRPC model service, so a vLLM-only host deployed with the template
as-is keeps `model_service` red forever. Override it in `.env`:

```sh
CORTEX_MODEL_TRANSPORT=local
CORTEX_MODEL_ENDPOINT=127.0.0.1:8000
CORTEX_MODEL_MAX_CONCURRENCY=1       # see §5.4 for sizing
```

All three are in `CORTEX_FORWARDED_OVERRIDES` in `scripts/testnet-deploy.sh`, so
`up` passes them to the remote `cortexd` as environment variables, which beat
the YAML.

The `local` transport speaks plaintext HTTP and has no TLS setting. Keep vLLM on
loopback with Cortex. Do not point `local` at another host.

(README.md still calls the `local` adapter "a stub". That paragraph is stale:
`internal/modelservice/local.go` is the full vLLM client.)

### 1.3 Dispatch — which Builders this node works for

Work arrives over Phase 1 direct dispatch. Real mode refuses to start without
the `dispatch:` block. The node keeps a standing handraise with, and one
`IngressAPI.DispatchStream` open to, every Builder operator listed in
`dispatch.builders` (`CORTEX_DISPATCH_BUILDERS`, comma-separated). Each stream
is dialled only at that Builder's on-chain service descriptor (endpoint and TLS
pin). There is nothing to configure per Builder beyond its operator address.

- Which Builders to list, and the shared parameter-table values
  (`CORTEX_DISPATCH_*`, §4.2), are human inputs (§3.1). Do not copy the
  `env.example` values into a real deployment without being told to.
- `max_concurrency` is also the standing handraise capacity. It must be greater
  than zero whenever `dispatch.builders` is set.
- Each Builder gets its own `dispatch_stream:<builder>` readiness row.
  `/readyz` needs at least one of them bound, not all.

The NATS bus is retired. `nexus.nats_url`, the NATS CA, creds and nkey,
`jetstream_stream`, `envelope_auth_mode`, the envelope TTL/skew and
`subscribe_*` are gone. A config or environment that still sets one of them is
**refused at startup**. Watch for them in old `.env` files and in a restored
`env.snapshot` (§4.7).

### 1.4 Topology

**The standard layout is one Cortex per machine: one GPU host runs one vLLM and
one `cortexd`, with one operator address and one service keystore.** Deploy
that unless you are explicitly told otherwise.

To deploy it with `scripts/testnet-deploy.sh`, set `CORTEX_NODE_COUNT=1` in the
`.env`. The script and `env.example` default to 4, which lays out four
`cortexd` processes on the same host. That is a test-bench shape, not the
deployment shape. Do not keep the default. With a count of 1, the node is
always `node1`: `$CORTEX_REMOTE_ROOT/node1/`, `CORTEX_NODE1_OPERATOR_ADDRESS`,
`$CORTEX_KEYSTORE_DIR/node1/service.json`, and health port
`CORTEX_HEALTH_PORT_BASE + 1`.

More machines means more `.env` files, one per host, each with its own
`CORTEX_SSH_HOST`, `CORTEX_NODE1_OPERATOR_ADDRESS` and keystore directory.
Select one with `CORTEX_ENV_FILE`:

```sh
CORTEX_ENV_FILE=deploy/testnet/gpu-a.env ./scripts/testnet-deploy.sh status
```

Keep these files **outside the repository tree** (e.g. `~/cortex-envs/gpu-a.env`,
`chmod 600`). `.gitignore` and `sync` exclude only the exact name `.env`, so a
`gpu-a.env` inside the repo would be committed and rsynced to the server along
with its keystore password.

(If you are told to run several `cortexd` on one host sharing one vLLM, the sum
of their `max_concurrency` must stay at or below vLLM's `--max-num-seqs`. Each
node admits work up to its own budget and none of them knows about the others.)

---

## 2. Local run (no GPU, no chain, no network)

```sh
make build                       # -> bin/cortexd, bin/cortexctl
bin/cortexd -config configs/dev.yaml &
sleep 12                         # do NOT check earlier than this, see below
pgrep -x cortexd || echo "EXITED"
bin/cortexctl --admin-socket /tmp/cortexd.sock diagnostics --format json
```

**Wait the full 12 seconds before declaring success.** A past incident had
`/healthz` answering 200 and the process exiting seconds later. Liveness is
"still alive after the wait", not "the port answered once".

Full test suite, all boundaries faked:

```sh
go test ./... -count=1
```

---

## 3. Prerequisites

### 3.1 Things only a human can provide — stop and ask

Do not invent, generate on your own, or reuse any of these. Each one is tied to
an on-chain identity or a shared secret. If one is missing, stop and ask for it
by name.

| Item | Where it goes | Notes |
|---|---|---|
| Operator address for this machine | `CORTEX_NODE1_OPERATOR_ADDRESS` | bech32; must be a registered CortexNode on chain |
| Service keystore for this machine | `$CORTEX_KEYSTORE_DIR/node1/service.json` | see §3.2 |
| Keystore password | `CORTEX_KEYSTORE_PASSWORD` | |
| On-chain registration (`MsgStakeService`), bond, model-support declaration | chain | Cortex never broadcasts these; `keeper_identity` / `model_support` stay red until done |
| Nexus auth token | file at `CORTEX_NEXUS_TOKEN_FILE` | |
| Builders to dispatch with | `CORTEX_DISPATCH_BUILDERS` | BuilderSet member operator addresses (§1.3) |
| Dispatch parameter-table values and local price floor | the other `CORTEX_DISPATCH_*` (§4.2) | shared with the Builders; `MIN_PRICE_BID` > 0 is this operator's own floor |
| Chain id, RPC/REST/Keeper/Nexus endpoints | `.env` | |
| Chain model id (Hash32) and profiles | `CORTEX_MODEL_ID`, `CORTEX_MODEL_PROFILES` | see §5.3 |
| Hugging Face token, if the model is gated | the vLLM host's environment | |

### 3.2 Creating a service keystore

```sh
bin/cortexctl onboard --chain-id <chain-id> --operator <operator-bech32> \
  --keystore "$CORTEX_KEYSTORE_DIR/node1/service.json" \
  --password-file <file> [--amount <atomic units>] --format json
```

This writes a keystore v3 file and prints the `MsgStakeService` transaction,
including the `service_key_proof`. It **never broadcasts**. Hand the printed
transaction to the human who controls the operator account. Running `onboard`
again creates a *new* key; never overwrite a keystore that is already
registered.

Check the derived addresses afterwards with `./scripts/testnet-deploy.sh addr`.

### 3.3 Operator machine (where the script runs)

`go` (1.25+), `ssh` with non-interactive login to `CORTEX_SSH_HOST`, `rsync`,
`scp`, `jq` (used by `diag` and `smoke`), `sed`, `curl`.

### 3.4 GPU server

| Need | Why | Check |
|---|---|---|
| Go ≥ 1.25 at `/usr/local/go/bin/go` | `build` hard-codes that path (`go.mod` says `go 1.25.0`) | `/usr/local/go/bin/go version` |
| `rsync` | `sync` | `rsync --version` |
| `curl` | `status`, `smoke` | |
| working NVIDIA driver | vLLM | §6 |
| Python env with vLLM | §5 | `python -c "import vllm; print(vllm.__version__)"` |
| `ninja` on the PATH that vLLM runs with | flashinfer JIT | `command -v ninja` |
| disk for model weights | HF cache | `df -h ~/.cache/huggingface` |
| NTP | handraise TTLs and stream keepalives are wall-clock timers agreed with the Builders | `timedatectl` |
| `CORTEX_REMOTE_ROOT` writable by the ssh user | everything | |

Install Go if it is missing (**VERIFY** the current 1.25.x point release and the
host architecture):

```sh
curl -fsSLO https://go.dev/dl/go1.25.<x>.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.<x>.linux-amd64.tar.gz
```

---

## 4. Real deployment

Everything is driven from the operator's machine by
`scripts/testnet-deploy.sh`. The script never runs on the server.

### 4.0 End-to-end order on a fresh GPU host

1. §6 GPU driver: `nvidia-smi` prints a table
2. §3.4 server prerequisites
3. §5 vLLM is serving, and `/v1/models` shows the chain `repo_id`
4. §3.1 / §3.2 human-provided inputs are present
5. §4.2 env file for this host written: `CORTEX_NODE_COUNT=1` (§1.4) and the §1.2 transport overrides
6. §4.3 `addr → sync → build → push → render → (read config) → up`, canary first
7. §4.5 `status` / `diag` / `smoke`; red items classified per §4.5

Each step has its acceptance check in the section it points to. Do not start a
step before the previous one has passed.

### 4.1 Subcommands

```
addr     derive bech32 addresses from the local keystores
sync     rsync this repository to the server
build    compile cortexd and cortexctl on the server
push     upload keystores, keystore password, and the Nexus token
render   render one config per node into deploy/testnet/generated/
up       upload configs and start every instance
down     stop every instance, leaving state intact
status   process, /healthz, and /readyz for every instance
diag     per-dependency readiness for every instance
logs [N] tail the last N log lines of every instance
smoke    read-only: /readyz and every Builder stream per node
```

`smoke` publishes nothing: it fails unless every node answers `/readyz` 200
with every configured `dispatch_stream:<builder>` row bound. It needs `jq`
locally. Being read-only, it is safe to run after every deployment. It is
stricter than `/readyz`, which needs only one stream bound.

### 4.2 Environment file

`deploy/testnet/.env` (gitignored; `env.example` is the template, `chmod 600`).
Override the path with `CORTEX_ENV_FILE`.

Required — `render` refuses without them:

```
CORTEX_CHAIN_ID  CORTEX_NODE_RPC  CORTEX_NODE_REST  CORTEX_KEEPER_API
CORTEX_NEXUS_INGRESS
CORTEX_MODEL_ENDPOINT  CORTEX_MODEL_ID  CORTEX_MODEL_PROFILES  CORTEX_MODEL_SERVICE_ID
CORTEX_RETENTION_POLICY_VERSION  CORTEX_MINIMUM_RETENTION_BLOCKS
CORTEX_DISPATCH_BUILDERS  CORTEX_DISPATCH_EVIDENCE_RETENTION_BLOCKS
CORTEX_DISPATCH_HEARTBEAT_MS  CORTEX_DISPATCH_TTL_MS  CORTEX_DISPATCH_MIN_CHANGE_INTERVAL_MS
CORTEX_DISPATCH_MIN_PRICE_BID  CORTEX_DISPATCH_KEEPALIVE_MS  CORTEX_DISPATCH_KEEPALIVE_MAX_MISSED
CORTEX_DISPATCH_RESCUE_MARGIN_BLOCKS  CORTEX_DISPATCH_ROSTER_GRACE_BLOCKS
CORTEX_DISPATCH_CHALLENGE_MARGIN_BLOCKS
CORTEX_NODE1_OPERATOR_ADDRESS          # one Cortex per machine (§1.4)
```

The template renders a `min_price_bid` for exactly one profile
(`<CORTEX_MODEL_ID>@1`). If `CORTEX_MODEL_PROFILES` lists more, add a key per
extra profile to `generated/node1.yaml` before `up`.

Required by `addr` / `push` / every remote command:

```
CORTEX_SSH_HOST  CORTEX_REMOTE_ROOT  CORTEX_NODE_COUNT  CORTEX_HEALTH_PORT_BASE
CORTEX_KEYSTORE_DIR  CORTEX_KEYSTORE_PASSWORD  CORTEX_NEXUS_TOKEN_FILE
```

Required for a vLLM-backed node (§1.2):

```
CORTEX_MODEL_TRANSPORT=local
CORTEX_MODEL_ENDPOINT=127.0.0.1:8000
CORTEX_MODEL_MAX_CONCURRENCY=<n>
```

Defaults worth knowing:

```
CORTEX_MODE=real
CORTEX_NODE_COUNT=4                # script default; SET IT TO 1 (§1.4)
CORTEX_HEALTH_PORT_BASE=18080      # node1 health port = 18081
CORTEX_MODEL_MAX_CONCURRENCY=1     # rendered into the YAML when unset
CORTEX_NEXUS_ALLOW_INSECURE_DESCRIPTOR=false
```

Delete every retired NATS variable from an old env file:
`CORTEX_NEXUS_NATS*`, `CORTEX_NEXUS_JETSTREAM_STREAM`, `CORTEX_NEXUS_ENVELOPE_*`
and `CORTEX_NEXUS_SUBSCRIBE_*` (§1.3).

**What reaches the remote daemon, and how.** A variable only affects the
deployment through one of two paths:

- rendered into the YAML by `render`: everything `render_one` substitutes for an
  `@@MARKER@@`;
- forwarded as an environment variable by `up`: exactly the names in
  `CORTEX_FORWARDED_OVERRIDES` (`CORTEX_MODEL_TRANSPORT CORTEX_MODEL_ENDPOINT
  CORTEX_MODEL_MAX_CONCURRENCY CORTEX_TASK_INPUT_RESOLVER CORTEX_TASK_FIXTURE_ROOT`).

Anything else you set in `.env` does nothing on the server, even though
`cortexd` understands it. That includes `CORTEX_NODE_TLS_*`. To change those,
edit `deploy/testnet/cortex.yaml.template`, or the rendered
`generated/node1.yaml` before `up`.

**Chain node with a self-signed certificate.** Set `node.tls` in the template
(uncomment the block) with exactly one of `pubkey_hash` (sha256 of the
certificate's SubjectPublicKeyInfo DER, 64 lowercase hex) or `ca_file` (the node
certificate or its CA, PEM; it must name the endpoint host or IP). Both node
endpoints must then be `https://`. Do not use `SSL_CERT_FILE` for this. Compute
the pin:

```sh
openssl x509 -in node.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | cut -d" " -f1
```

See "Chain node TLS" in README.md.

`CORTEX_NEXUS_BUILDER_OPERATOR` is optional. The chain's current BuilderSet is
the authority, so an empty value admits every current member. This setting
only narrows the node to one Builder and turns on `builder_descriptor`
verification for `CORTEX_NEXUS_INGRESS`. It is unrelated to
`CORTEX_DISPATCH_BUILDERS`.

### 4.3 Order of operations

```sh
./scripts/testnet-deploy.sh addr      # confirm the addresses match the chain
./scripts/testnet-deploy.sh sync
./scripts/testnet-deploy.sh build
./scripts/testnet-deploy.sh push
./scripts/testnet-deploy.sh render    # inspect deploy/testnet/generated/*.yaml
./scripts/testnet-deploy.sh up
./scripts/testnet-deploy.sh status
./scripts/testnet-deploy.sh diag
```

Read the rendered config before `up`. `render` is the last point where a wrong
chain id or operator address is cheap to fix. Remember that the transport and
endpoint in the rendered YAML still say `grpc` / `:9090`, and the forwarded
environment overrides them at start. Confirm the effective values afterwards
with `diag`.

### 4.4 Canary, always

Never restart every machine at once. Roll out machine by machine: bring up one
host, watch it for 30 seconds, re-check, and only then move to the next. Three
separate production incidents were caught by exactly this and would otherwise
have taken down every node.

```sh
CORTEX_ENV_FILE=<host-a.env> ./scripts/testnet-deploy.sh up
sleep 30
CORTEX_ENV_FILE=<host-a.env> ./scripts/testnet-deploy.sh status   # pid still up?
CORTEX_ENV_FILE=<host-a.env> ./scripts/testnet-deploy.sh diag
# only now: the next host
```

`load_env` sources the env file over the caller's environment, so a variable
given on the command line (e.g. `CORTEX_NODE_COUNT=1 ./scripts/...`) does
**not** override a value set in the file. Put the value in the file.

`/healthz` 200 is not "stable". Wait, then re-check.

### 4.5 Readiness, and how to read a red one

```sh
./scripts/testnet-deploy.sh diag
curl -s localhost:<health_port>/healthz    # process is up
curl -s localhost:<health_port>/readyz     # dependencies are satisfied
```

`healthz` 200 + `readyz` 503 is normal during startup and is **not** a failed
deployment.

| Red dependency | Meaning | Fixable on the machine? |
|---|---|---|
| `chain_sync` | replaying blocks toward the tip | no, wait |
| `chain` / `keeper` | RPC/REST/Keeper unreachable; the poller retries forever with backoff | usually no; check §4.6 |
| `model_service` | vLLM not answering, wrong transport, or the model id is not bound (§5.3) | yes, §1.2 and §5 |
| `keeper_identity` | operator bond is not ACTIVE / is JAILED, or the service key does not match | **no**, chain-side; ask a human |
| `model_support` | model support not declared on chain | **no**, chain-side; ask a human |
| `dispatch_stream:<builder>` | that Builder's stream is not bound (descriptor, TLS pin, keepalive) | usually peer-side; `/readyz` needs at least one bound |
| `builder_descriptor` | only when `CORTEX_NEXUS_BUILDER_OPERATOR` is set: descriptor missing or not committing this ingress | peer-side |
| `tx_broadcaster` | signer cannot sign Cosmos transactions | **optional**, ignore |

`tx_broadcaster` is red on every `file://` keystore node and does not block
readiness: `LocalSigner.CanSignCosmosTx()` returns false by construction, and the
workload only requires it when `self_rescue` or `challenge_verifier` is enabled
(`Config.RequiresWorkloadTx`). The comment above `tx:` in the template saying
the workload stays down without it is stale.

The consequence for dispatch is that a `file://` keystore node cannot submit
dispatch compensation claims, receipt rescues or omission challenges, even
though the template sets `tx.enabled: true`. The node still works; it just has
no direct transaction path. Report this. Do not try to fix it on the machine.

### 4.6 Diagnose the chain before the node

```sh
curl -s <rpc>/status                       # is the tip advancing?
curl -s <rpc>/block_results?height=<tip>   # a 500 here means the chain is stuck mid-commit
```

An unreachable chain no longer kills `cortexd`. The Keeper poller retries
retryable errors indefinitely, with backoff capped at 30 s
(`internal/daemon/poller.go`). The node keeps running with `/readyz` at 503, and
the log shows a climbing attempt number. If every machine shows the same red
chain dependency at the same time, the chain is the suspect. Restarting the
nodes changes nothing until the chain recovers. Non-retryable chain errors, and
32 consecutive cursor repositions, still end the process.

### 4.7 Process model

The testnet script runs `cortexd` as a bare `nohup` process with a pid file at
`$CORTEX_REMOTE_ROOT/node<i>/cortexd.pid` and a log at `node<i>/cortexd.log`. It
does not use systemd or screen. Other shapes exist in the repository but are not
what this script deploys: `packaging/systemd/cortexd.service` (single node,
installed binaries) and `deploy/devnet/` + `scripts/devnet-deploy.sh` (Docker
Compose).

**VERIFY / known hazard:** `start_one` uses `nohup` without `setsid`. A process
started from an interactive bastion session can be killed when that session
ends. When you start by hand, use `setsid nohup ... < /dev/null`.

**VERIFY / known hazard:** before restarting by hand, copy the live environment
from `/proc/<pid>/environ` into `node<i>/env.snapshot`, and restore from that
snapshot. Deployed variable names have drifted from the template before, and
restoring from the template instead changes behaviour silently. A snapshot
taken from a pre-dispatch process may still carry retired NATS variables
(§1.3). Remove them, or the new binary refuses to start.

`pgrep -f "<long pattern>"` matches the agent's own `bash -c` command line. Use
`pgrep -x cortexd`.

---

## 5. vLLM

### 5.1 What Cortex needs from it

With `transport: local`, Cortex calls vLLM's OpenAI-compatible HTTP API:

- `/v1/completions` for raw-text input, `/v1/chat/completions` when the input is
  a JSON object carrying a `messages` field;
- `/health`, `/v1/models` and `/metrics` for readiness and capacity.

It asks for per-token logprobs (16 top logprobs by default, more if the
registered profile asks) and token ids.

Required server properties:

| Property | Flag | Why |
|---|---|---|
| served model name == chain `repo_id` exactly | `--served-model-name <owner/name>` (or serve by that repo path) | otherwise `model_service` stays red |
| raw logprobs | `--logprobs-mode raw_logprobs` | §5.2 |
| enough logprobs | `--max-logprobs` ≥ the profile's logprobs count (vLLM default 20; **VERIFY** against the profile) | requests above the limit are refused |
| a known scheduler limit | `--max-num-seqs <n>` | needed to size `max_concurrency` (§5.4) |
| loopback | `--host 127.0.0.1 --port 8000` | `local` is plaintext |

**VERIFY the vLLM version.** The repository pins none. The detokenize contract
was checked against vLLM v0.10.0 (`internal/modelservice/detokenize.go`), and
`--logprobs-mode` only exists in recent releases. If the host already has a
working vLLM, use that version and report it. Do not upgrade it on your own.

### 5.2 Why `raw_logprobs`

The reported logprobs must be the raw model values, taken before the sampling
processors (temperature, top-k, top-p, the penalties). That is vLLM's current
default, so a server started without the flag is almost certainly already
correct. Pin the flag anyway: nothing in the protocol carries the mode, and an
upgrade that changes the default would change what this node commits without
any error to read.

What is at stake is agreement between two independently run engines. The
Verifier scores a task by re-running the committed token ids as a prefill, and
`prompt_logprobs` are identical in both modes, so the Verifier is unaffected by
this flag. A Worker serving `processed_logprobs`, however, disagrees with every
Verifier at every position, by however much its own temperature and penalties
shift the values. The task is simply scored as a mismatch, and no symptom names
the cause.

### 5.3 Model id and binding

`CORTEX_MODEL_ID` and the ids in `CORTEX_MODEL_PROFILES` are the chain's Hash32
model ids as 64 lowercase hex, never a name. Find one, and its `repo_id`, with:

```sh
bin/cortexctl model find --rpc <keeper-rpc> --provider HUGGINGFACE --repo <owner/name> --format json
```

`CORTEX_MODEL_PROFILES` entries have the form `<model-id-hex>@<version>=<profile>`,
e.g. `c2e5…29c1@1=llm_text_v1` (see `env.example`).

`model_service` stays red, with the reason in `diag`, when:

- `query ModelState <id>`: the id is not registered on this chain;
- `has source provider "<p>"; the local adapter serves only HUGGINGFACE`;
- `model <id> is registered for <repo>, but vLLM serves [...]`: rename with
  `--served-model-name`;
- a vLLM health or `/v1/models` error: vLLM is not answering.

### 5.4 Sizing `max_concurrency`

`CORTEX_MODEL_MAX_CONCURRENCY` is how many inference requests this node admits
at once. Handraise capacity is derived from it, and vLLM does not publish its
limit, so you have to state it. Start at `1`. Raise it only after load testing,
keeping end-to-end p95 latency under the profile deadline. With one Cortex per
machine, the node owns the whole vLLM, so the only ceiling is `--max-num-seqs`.

### 5.5 Install and start

**Check first.** If vLLM is already running on the host, do not start a second
one:

```sh
curl -s 127.0.0.1:8000/health && curl -s 127.0.0.1:8000/v1/models
ps -eo pid,args | grep -E '[v]llm|[e]ntrypoints.openai' 
nvidia-smi --query-compute-apps=pid,used_memory,process_name --format=csv
```

Install into a dedicated venv (**VERIFY** the Python and vLLM versions with the
human if none are given):

```sh
python3 -m venv /opt/vllm/venv
/opt/vllm/venv/bin/pip install -U pip
/opt/vllm/venv/bin/pip install "vllm==<VERSION>" ninja
/opt/vllm/venv/bin/python -c "import torch, vllm; print(vllm.__version__, torch.cuda.is_available())"
```

The last line must print `True`. If it prints `False`, see §6.3.

Start it with an idempotent wrapper that pins `setsid` and a full `PATH`. This
is the shape; adapt the paths:

```sh
#!/usr/bin/env bash
# /opt/vllm/start.sh — idempotent vLLM start for Cortex
set -euo pipefail
export PATH=/opt/vllm/venv/bin:/usr/local/bin:/usr/bin:/bin
# export HF_TOKEN=...            # only for gated models; from the human
MODEL=<owner/name>               # == chain repo_id
PORT=8000
LOG=/opt/vllm/vllm.log
PIDFILE=/opt/vllm/vllm.pid

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "vllm already running (pid $(cat "$PIDFILE"))"; exit 0
fi
command -v ninja >/dev/null || { echo "ninja missing from PATH" >&2; exit 1; }

setsid nohup vllm serve "$MODEL" \
  --served-model-name "$MODEL" \
  --host 127.0.0.1 --port "$PORT" \
  --logprobs-mode raw_logprobs \
  --max-logprobs 20 \
  --max-num-seqs <n> \
  --gpu-memory-utilization 0.90 \
  --max-model-len <len> \
  </dev/null >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"
echo "started vllm pid $(cat "$PIDFILE"); log $LOG"
```

Acceptance check, waiting up to ~10 minutes for the model to download and load:

```sh
for i in $(seq 1 120); do curl -sf 127.0.0.1:8000/health && break; sleep 5; done
curl -s 127.0.0.1:8000/v1/models | jq -r '.data[].id'     # must print the chain repo_id
curl -s 127.0.0.1:8000/v1/completions -H 'content-type: application/json' \
  -d '{"model":"<owner/name>","prompt":"hi","max_tokens":4,"logprobs":5}' | jq '.choices[0].logprobs.top_logprobs[0]'
```

**Known hazards on the current deployment (VERIFY):**

- A bare `nohup` start has been killed by systemd when the SSH session ended.
  Use `setsid`, as in the wrapper.
- flashinfer compiles kernels at runtime and needs `ninja` on `PATH`. A
  non-interactive start without the venv/pyenv bin directory fails with
  `FileNotFoundError` during engine init.
- Model load takes roughly 3–4 minutes once the weights are cached. Cortex's
  `readyz` stays 503 for that whole time.
- Out of memory at load usually means another tenant holds VRAM. See §6.3; do
  not kill their process.

### 5.6 Upgrading from a pre-v0.3 release

`cortexd` refuses to start while its store holds trace/checkpoint evidence, or
an older (or unreadable) infer receipt, for a task whose local record is not
terminal or settled. The check never asks the chain, because v0.3 is a fresh
genesis. Drain those tasks on the old release first, or start from an empty
store. Old evidence of finished tasks only logs a warning and is left for
retention cleanup.

---

## 6. GPU driver and CUDA

**Everything in this section is environment knowledge, not repository
knowledge. VERIFY against the actual host before running any of it.** The
repository pins no driver version and contains no GPU provisioning code.

### 6.1 Establish the current state first

```sh
nvidia-smi                                  # driver + CUDA runtime, or "command not found"
lspci | grep -i nvidia                      # is a GPU present at all
cat /proc/driver/nvidia/version 2>/dev/null # loaded kernel module
uname -r                                    # running kernel
dkms status 2>/dev/null                     # are modules DKMS-managed
```

If `nvidia-smi` prints a table, the driver works. **Do not reinstall it.** A
reinstall that fails leaves the host without a GPU and usually needs a reboot to
recover, which on a shared machine is an outage for everyone else.

### 6.2 Ubuntu / Debian install

**A driver install and reboot is a human decision on any shared host. Ask
first.**

```sh
sudo apt-get update
ubuntu-drivers devices          # lists the recommended driver for this GPU
sudo apt-get install -y nvidia-driver-<VERSION>   # VERSION from the line above
sudo reboot
```

After reboot:

```sh
nvidia-smi
```

The `CUDA Version` shown by `nvidia-smi` is the **maximum** the driver supports,
not what is installed. PyTorch and vLLM ship their own CUDA runtime, so a
separate CUDA toolkit is usually unnecessary. Install one only if something
needs `nvcc`. Make sure the driver is new enough for the CUDA build of the vLLM
wheel you install.

### 6.3 Things that actually go wrong

| Symptom | Cause | Action |
|---|---|---|
| `nvidia-smi` works, PyTorch sees no GPU | wrong CUDA build of torch, or driver too old for it | reinstall torch/vLLM for the right CUDA |
| driver fails to load after a kernel upgrade | DKMS did not rebuild | `sudo dkms autoinstall`, reboot |
| `Failed to initialize NVML: Driver/library version mismatch` | new driver installed, old module still loaded | reboot |
| out of memory at model load | another process holds VRAM | `nvidia-smi` and find the PID before killing anything |

Check for other tenants before touching VRAM:

```sh
nvidia-smi --query-compute-apps=pid,used_memory,process_name --format=csv
```

On a shared machine, **coordinate before killing any process**. Colleagues run
builds and deployments on the same hosts.

---

## 7. Data and state

Cortex stores only restart obligations: signed handraise candidates, active
infer/verify documents, the last processed chain height, chain identity, and one
evidence metadata record per task. It is not an audit database.

- store: Pebble, a **directory** (`store.path`), not a single file
- evidence: task-scoped, `tasks/<hash[0:2]>/<hash>/{input,output,evidence}/`
- secrets: `$CORTEX_REMOTE_ROOT/secrets/{keystore.pass,nexus.token}`, keystores
  in `node<i>/keystore/`
- dispatch: stream cursors and acks are persisted in the store, so a restart
  resumes each Builder stream instead of starting it over

**Never delete node state on a production deployment.** Evidence backs on-chain
obligations. Never delete or regenerate a keystore that is bound on chain. On a test deployment after a chain reset, wiping `node<i>/data` is
acceptable and the node replays from height 0. Expect `chain_sync` to sit red
for minutes while it catches up. `env.snapshot` lives in the node directory, not
under `data/`, so it survives.

---

## 8. Checklist for an agent

Before deploying:

- [ ] `go build ./...` and `go test ./... -count=1` pass locally
- [ ] target commit is known, and is not older than what is running
- [ ] every §3.1 human-provided item is present; if one is missing, stop and ask
- [ ] chain is alive (`/status` tip advancing, `/block_results` not 500)
- [ ] `nvidia-smi` prints a table; no unexplained VRAM tenants
- [ ] vLLM answers `/health`, and `/v1/models` lists exactly the chain `repo_id`
- [ ] vLLM was started with `--logprobs-mode raw_logprobs`
- [ ] `.env` sets `CORTEX_MODEL_TRANSPORT=local`, endpoint and max concurrency (§1.2)
- [ ] `CORTEX_DISPATCH_*` values come from a human, and no retired NATS variable is set (§1.3)
- [ ] no colleague is mid-deployment on the same host

Deploying:

- [ ] `render`, then read the generated config
- [ ] `CORTEX_NODE_COUNT=1` in this host's env file
- [ ] first host up, wait 30 s, confirm the process is still alive
- [ ] roll the remaining hosts one at a time
- [ ] `status`, `diag` and `smoke` on every host

Reporting:

- [ ] quote real command output, not a summary of it
- [ ] state which dependencies are red, whether each blocks readiness, and
      whether it is fixable on the machine (§4.5)
- [ ] state which `dispatch_stream:<builder>` rows are bound and which are not (§1.3)
- [ ] if anything was skipped, say so explicitly

---

## 9. Where to look in the code

| Question | File |
|---|---|
| how dependencies are chosen per mode / transport | `internal/daemon/dependencies.go`, `internal/modelservice/transport.go` |
| what readiness probes | `internal/daemon/runtime_readiness.go` |
| dispatch plane and Builder streams | `cmd/cortexd/dispatch.go`, `internal/daemon/dispatch_streams.go` |
| Keeper polling, retry, exit conditions | `internal/daemon/poller.go` |
| task lifecycle | `internal/daemon/task_runner_run.go` |
| vLLM HTTP client | `internal/modelservice/local.go`, `local_chat.go` |
| chat input schema | `proto/cortex/v1/chat_input.proto` |
| config fields, env var names, validation | `internal/config/config.go` |
| key generation / registration proof | `cmd/cortexctl/onboard.go` |
| admin socket routes | `internal/adminapi/admin.go` |
| what the deploy script renders and forwards | `scripts/testnet-deploy.sh` (`render_one`, `CORTEX_FORWARDED_OVERRIDES`) |

Per-task protocol tracing: every step logs one
`task trace event=<milestone>` line carrying the digests that step decided on.
Grep a task hash across all node logs to reconstruct a round.
