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
| Nexus | Builder ingress (connect-go) + NATS bus | `nexus.ingress_url`, `nexus.nats_url` |
| Model service | vLLM, OpenAI-compatible HTTP | `model_management.endpoint` |
| Signer | local keystore (`file://`) or remote HTTP | `local_identity.service_key_ref` |

Two binaries: `cortexd` (daemon) and `cortexctl` (operator CLI over a Unix
socket).

**Fail-closed is the design.** Real mode never substitutes a fake for a missing
dependency. A red dependency means the affected runner stays stopped, not that
the daemon silently degrades. Do not "fix" a readiness failure by adding a
fallback.

---

## 1. Decide the mode before anything else

```yaml
mode: fake   # configs/dev.yaml
mode: real   # deploy/testnet/cortex.yaml.template
```

`fake` replaces the model service, the bus and the chain with fixtures
(`internal/daemon/dependencies.go`). It is the right mode for exercising the
task lifecycle and the wrong mode for anything about model output: the whole
decode path in `internal/modelservice/local*.go` does not execute.

Rule of thumb for an agent:

- verifying task scheduling, storage, restart recovery → `fake`, local, no GPU
- verifying decode / tokens / output commitment → `real` mode against a vLLM
- verifying the full round trip → a real deployment

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

## 3. Real deployment

Everything is driven from the operator's laptop by
`scripts/testnet-deploy.sh`. It never runs on the server.

### 3.1 Subcommands

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
smoke confirm    publish one order onto the SHARED bus, report the round trip
```

`smoke` requires the literal word `confirm` because it publishes onto a shared
bus that other people are using.

### 3.2 Environment file

`deploy/testnet/.env` (gitignored; `env.example` is the template). Override the
path with `CORTEX_ENV_FILE`.

Required — `render` refuses without them:

```
CORTEX_CHAIN_ID  CORTEX_NODE_RPC  CORTEX_NODE_REST  CORTEX_KEEPER_API
CORTEX_NEXUS_INGRESS  CORTEX_NEXUS_NATS
CORTEX_MODEL_ENDPOINT  CORTEX_MODEL_ID  CORTEX_MODEL_PROFILES  CORTEX_MODEL_SERVICE_ID
CORTEX_RETENTION_POLICY_VERSION  CORTEX_MINIMUM_RETENTION_BLOCKS
CORTEX_NODE<i>_OPERATOR_ADDRESS        # one per node, i = 1..CORTEX_NODE_COUNT
```

Also needed by `addr` / `push`:

```
CORTEX_SSH_HOST  CORTEX_REMOTE_ROOT  CORTEX_NODE_COUNT  CORTEX_HEALTH_PORT_BASE
CORTEX_KEYSTORE_DIR  CORTEX_KEYSTORE_PASSWORD  CORTEX_NEXUS_TOKEN_FILE
```

Defaults worth knowing:

```
CORTEX_MODE=real
CORTEX_NEXUS_ENVELOPE_AUTH_MODE=strict
CORTEX_NEXUS_JETSTREAM_STREAM=TRUEOPEN_TASK
CORTEX_NEXUS_ALLOW_INSECURE_DESCRIPTOR=false
```

Chain node with a self-signed certificate: set exactly one of
`CORTEX_NODE_TLS_PUBKEY_HASH` (sha256 of the node certificate's
SubjectPublicKeyInfo DER, 64 lowercase hex) or `CORTEX_NODE_TLS_CA_FILE` (node
certificate or its CA, PEM; must name the endpoint host or IP), or `node.tls` in
the config file. Both node endpoints must then be `https://`. Do not use
`SSL_CERT_FILE` for this. Compute the pin from the node's PEM certificate:

```sh
openssl x509 -in node.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | cut -d" " -f1
```

See "Chain node TLS" in README.md.

`CORTEX_NEXUS_BUILDER_OPERATOR` is optional: strict authentication already
accepts any sender in the chain's current BuilderSet, and this only narrows it
to one Builder.

### 3.3 Order of operations

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
chain id or operator address is cheap to fix.

### 3.4 Canary, always

Never restart all instances at once. Bring up node1, watch it for 30 seconds,
then roll the rest. Three separate production incidents were caught by exactly
this and would have taken down all four nodes otherwise.

`/healthz` 200 is not "stable". Wait, then re-check.

### 3.5 Process model

`cortexd` runs as a bare `nohup` process with a pid file at
`$CORTEX_REMOTE_ROOT/node<i>/cortexd.pid`. Not systemd, not screen.

**VERIFY / known hazard:** starting it from an interactive bastion session can
get it killed when that session ends. Use `setsid nohup ... < /dev/null` so the
process fully detaches.

**VERIFY / known hazard:** when restarting by hand, copy the live environment
from `/proc/<pid>/environ` into `node<i>/env.snapshot` first and restore from
that. Deployed variable names have drifted from the template before; restoring
the template instead of the snapshot changes behaviour silently.

`pgrep -f "<long pattern>"` matches the agent's own `bash -c` command line. Use
`pgrep -x cortexd`.

---

## 4. Readiness, and how to read a red one

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
| `model_service` | vLLM is not answering, or a configured model id is not bound (see "vLLM" below) | yes, see "vLLM" below |
| `keeper_identity` | operator bond is not ACTIVE / is JAILED | **no**, chain-side |
| `model_support` | model support not declared on chain | **no**, chain-side |
| `nexus` | ingress or NATS unreachable / auth refused | usually peer-side |
| `tx_broadcaster` | signer cannot sign Cosmos transactions | **optional**, ignore |

`tx_broadcaster` is red on every `file://` keystore node and does not block
readiness. `LocalSigner.CanSignCosmosTx()` returns false by construction.

**Diagnose the chain before the node.** If every instance exits at the same
second, the chain is the first suspect, not the deployment:

```sh
curl -s <rpc>/status                       # is the tip advancing?
curl -s <rpc>/block_results?height=<tip>   # a 500 here means the chain is stuck mid-commit
```

Cortex exits after 6 consecutive Keeper poll failures. A stuck chain therefore
kills all instances together, and restarting them changes nothing until the
chain recovers.

---

## 5. vLLM

Cortex's `LocalService` is an HTTP client against an OpenAI-compatible endpoint.
It uses `/v1/completions` for raw-text input and `/v1/chat/completions` when the
input is a JSON object carrying a `messages` field.

Start that server with `--logprobs-mode raw_logprobs`:

```sh
vllm serve <model> --logprobs-mode raw_logprobs ...
```

The reported logprobs must be the raw model values, taken before the sampling
processors (temperature, top-k, top-p, the penalties). That is vLLM's current
default, so a server started without the flag is almost certainly already
correct; pin it anyway, because nothing in the protocol carries the mode and an
upgrade that changes the default would change what this node commits without
any error to read.

What is at stake is agreement between two independently run engines. The
Verifier scores a task by re-running the committed token ids as a prefill, and
`prompt_logprobs` are identical in both modes — so the Verifier is unaffected by
this flag and a Worker serving `processed_logprobs` disagrees with every
Verifier, at every position, by whatever its own temperature and penalties
shift the values. The task is simply scored as a mismatch; there is no symptom
that names the cause.

`readyz` reports `model_service` red whenever vLLM is absent. Check it directly:

```sh
curl -s 127.0.0.1:8000/health
curl -s 127.0.0.1:8000/v1/models          # the served model name must equal the chain repo_id
```

`CORTEX_MODEL_ID` and the ids in `CORTEX_MODEL_PROFILES` are the chain's Hash32
model ids as 64 lowercase hex, never a name. Find one with
`cortexctl model find --rpc <keeper-rpc> --provider HUGGINGFACE --repo <owner/name>`.
`model_service` also stays red, with the reason in `diag`, when that id is not
registered on this chain, when its source provider is not `HUGGINGFACE`, or when
vLLM's served model name differs from the chain `repo_id`.

Upgrading a node that ran a pre-v0.3 release: `cortexd` refuses to start while
its store holds trace/checkpoint evidence or an older (or unreadable) infer
receipt of a task whose local record is not terminal or settled (the check
never asks the chain: v0.3 is a fresh genesis). Drain those tasks on the old
release first, or start from an empty store. Old evidence of finished tasks only logs a warning and is left for
retention cleanup.

**VERIFY / known hazards on the current deployment:**

- Start vLLM with `setsid` and a full `PATH`. A bare `nohup` start has been
  killed by systemd when the SSH session ended.
- flashinfer compiles kernels at runtime and needs `ninja` on `PATH`. A
  non-interactive start without the pyenv bin directory fails with
  `FileNotFoundError` during engine init.
- Model load takes roughly 3–4 minutes. `readyz` stays 503 that whole time.

A wrapper script that pins both (`setsid`, `PATH`, idempotent) is the right
shape. Confirm the current path on the machine rather than assuming.

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
needs `nvcc`.

### 6.3 Things that actually go wrong

| Symptom | Cause | Action |
|---|---|---|
| `nvidia-smi` works, PyTorch sees no GPU | wrong CUDA build of torch | reinstall torch for the right CUDA |
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

**Never delete node state on a production deployment.** Evidence backs on-chain
obligations. On a test deployment after a chain reset, wiping `node<i>/data` is
acceptable and the node replays from height 0 — expect `chain_sync` to sit red
for minutes while it catches up. `env.snapshot` lives in the node directory, not
under `data/`, so it survives.

---

## 8. Checklist for an agent

Before deploying:

- [ ] `go build ./...` and `go test ./... -count=1` pass locally
- [ ] target commit is known, and is not older than what is running
- [ ] chain is alive (`/status` tip advancing, `/block_results` not 500)
- [ ] the vLLM this node talks to was started with `--logprobs-mode raw_logprobs`
- [ ] no colleague is mid-deployment on the same host

Deploying:

- [ ] `render`, then read the generated config
- [ ] canary node1, wait 30 s, confirm the process is still alive
- [ ] roll the rest
- [ ] `status` and `diag` on every instance

Reporting:

- [ ] quote real command output, not a summary of it
- [ ] state which dependencies are red and whether each blocks readiness
- [ ] if anything was skipped, say so explicitly

---

## 9. Where to look in the code

| Question | File |
|---|---|
| how dependencies are chosen per mode | `internal/daemon/dependencies.go` |
| what readiness probes | `internal/daemon/runtime_readiness.go` |
| task lifecycle | `internal/daemon/task_runner_run.go` |
| model HTTP client | `internal/modelservice/local.go`, `local_chat.go` |
| chat input schema | `proto/cortex/v1/chat_input.proto` |
| config fields | `internal/config/config.go` |
| admin socket routes | `internal/adminapi/admin.go` |

Per-task protocol tracing: every step logs one
`task trace event=<milestone>` line carrying the digests that step decided on.
Grep a task hash across all node logs to reconstruct a round.
