#!/usr/bin/env sh
# Deploy N cortexd instances to a test server without Docker or systemd.
#
# Each instance is an ordinary cortexd process with its own config, keystore,
# state directory, health port, and admin socket. Nothing here is multi-node
# aware: the daemon still runs as a single node, this only lays out N of them.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
deploy_dir="$repo_dir/deploy/testnet"
env_file=${CORTEX_ENV_FILE:-"$deploy_dir/.env"}
generated_dir="$deploy_dir/generated"
template="$deploy_dir/cortex.yaml.template"

die() { echo "$@" >&2; exit 1; }

load_env() {
	[ -f "$env_file" ] || die "missing env file: $env_file (copy deploy/testnet/env.example)"
	set -a
	# shellcheck disable=SC1090
	. "$env_file"
	set +a
	: "${CORTEX_SSH_HOST:?CORTEX_SSH_HOST is required}"
	: "${CORTEX_REMOTE_ROOT:?CORTEX_REMOTE_ROOT is required}"
	: "${CORTEX_NODE_COUNT:=4}"
	: "${CORTEX_HEALTH_PORT_BASE:=18080}"
}

require_env() {
	eval "value=\${$1:-}"
	[ -n "$value" ] || die "missing required environment variable: $1"
}

# Node-scoped lookup: node_value 2 OPERATOR_ADDRESS -> $CORTEX_NODE2_OPERATOR_ADDRESS
node_value() {
	eval "value=\${CORTEX_NODE$1_$2:-}"
	printf '%s' "$value"
}

# Values reach the config through sed, so template markers and newlines are
# rejected rather than silently reinterpreted.
sed_safe() {
	case "$1" in
	*'@@'*) die "value must not contain the template marker @@: $1" ;;
	esac
	case "$1" in
	*'
'*) die "value must not contain newlines" ;;
	esac
	printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

# Deployment-specific settings forwarded from .env to the remote cortexd. Kept
# as one list so scripts/tests/shell_quote_test.sh can assert against it rather
# than a copy that silently falls behind.
CORTEX_FORWARDED_OVERRIDES="CORTEX_NEXUS_ENVELOPE_AUTH_MODE CORTEX_NEXUS_JETSTREAM_STREAM CORTEX_MODEL_TRANSPORT CORTEX_MODEL_ENDPOINT CORTEX_MODEL_MAX_CONCURRENCY CORTEX_TASK_INPUT_RESOLVER CORTEX_TASK_FIXTURE_ROOT"

# shell_quote wraps a value in single quotes for the remote command line.
# sed_safe is for sed replacements and must not be used here: it rewrites & and
# \ for sed's benefit, and leaves single quotes intact, which would terminate
# the quoting and let the value run as remote shell.
shell_quote() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

remote() { ssh "$CORTEX_SSH_HOST" "$@"; }

each_node() {
	i=1
	while [ "$i" -le "$CORTEX_NODE_COUNT" ]; do
		"$@" "$i"
		i=$((i + 1))
	done
}

# --- commands ---------------------------------------------------------------

cmd_addr() {
	require_env CORTEX_KEYSTORE_DIR
	require_env CORTEX_KEYSTORE_PASSWORD
	command -v go >/dev/null 2>&1 || die "go is required to run scripts/keyaddr"
	i=1
	while [ "$i" -le "$CORTEX_NODE_COUNT" ]; do
		dir="$CORTEX_KEYSTORE_DIR/node$i"
		[ -d "$dir" ] || die "missing keystore directory: $dir"
		echo "node$i"
		CORTEX_KEYSTORE_PASSWORD="$CORTEX_KEYSTORE_PASSWORD" go run "$repo_dir/scripts/keyaddr" \
			-dir "$dir" -hrp "${CORTEX_BECH32_HRP:-trueopen}" \
			-password-env CORTEX_KEYSTORE_PASSWORD service.json |
			sed 's/^/  /'
		i=$((i + 1))
	done
}

cmd_sync() {
	remote "mkdir -p '$CORTEX_REMOTE_ROOT/src'"
	rsync -a --delete \
		--exclude '.git' --exclude 'bin' --exclude 'deploy/*/generated' \
		--exclude 'deploy/*/.env' \
		"$repo_dir/" "$CORTEX_SSH_HOST:$CORTEX_REMOTE_ROOT/src/"
	echo "synced $repo_dir -> $CORTEX_SSH_HOST:$CORTEX_REMOTE_ROOT/src"
}

cmd_build() {
	remote "set -eu
		export PATH=/usr/local/go/bin:\$PATH
		cd '$CORTEX_REMOTE_ROOT/src'
		mkdir -p '$CORTEX_REMOTE_ROOT/bin'
		CGO_ENABLED=0 go build -trimpath -o '$CORTEX_REMOTE_ROOT/bin/cortexd' ./cmd/cortexd
		CGO_ENABLED=0 go build -trimpath -o '$CORTEX_REMOTE_ROOT/bin/cortexctl' ./cmd/cortexctl
		ls -la '$CORTEX_REMOTE_ROOT/bin'"
}

cmd_push() {
	require_env CORTEX_KEYSTORE_DIR
	require_env CORTEX_KEYSTORE_PASSWORD
	require_env CORTEX_NEXUS_TOKEN_FILE
	[ -f "$CORTEX_NEXUS_TOKEN_FILE" ] || die "missing nexus token file: $CORTEX_NEXUS_TOKEN_FILE"

	remote "umask 077 && mkdir -p '$CORTEX_REMOTE_ROOT/secrets'"
	# The password is written server-side so it never appears in an scp
	# argument list or in the local shell history.
	remote "umask 077 && cat > '$CORTEX_REMOTE_ROOT/secrets/keystore.pass'" \
		<<-EOF
			$CORTEX_KEYSTORE_PASSWORD
		EOF
	scp -q "$CORTEX_NEXUS_TOKEN_FILE" "$CORTEX_SSH_HOST:$CORTEX_REMOTE_ROOT/secrets/nexus.token"
	remote "chmod 600 '$CORTEX_REMOTE_ROOT/secrets/keystore.pass' '$CORTEX_REMOTE_ROOT/secrets/nexus.token'"

	i=1
	while [ "$i" -le "$CORTEX_NODE_COUNT" ]; do
		dir="$CORTEX_KEYSTORE_DIR/node$i"
		[ -f "$dir/service.json" ] || die "missing $dir/service.json"
		remote "umask 077 && mkdir -p '$CORTEX_REMOTE_ROOT/node$i/keystore' '$CORTEX_REMOTE_ROOT/node$i/data/evidence'"
		scp -q "$dir/service.json" \
			"$CORTEX_SSH_HOST:$CORTEX_REMOTE_ROOT/node$i/keystore/"
		remote "chmod 600 '$CORTEX_REMOTE_ROOT/node$i/keystore/'*.json"
		echo "pushed keystore -> node$i"
		i=$((i + 1))
	done
}

render_one() {
	i=$1
	node_root="$CORTEX_REMOTE_ROOT/node$i"
	health_port=$((CORTEX_HEALTH_PORT_BASE + i))

	operator=$(node_value "$i" OPERATOR_ADDRESS)
	[ -n "$operator" ] || die "missing CORTEX_NODE${i}_OPERATOR_ADDRESS"

	for name in CORTEX_CHAIN_ID CORTEX_NODE_RPC CORTEX_NODE_REST CORTEX_KEEPER_API \
		CORTEX_NEXUS_INGRESS CORTEX_NEXUS_NATS CORTEX_MODEL_ENDPOINT CORTEX_MODEL_ID \
		CORTEX_MODEL_PROFILES CORTEX_MODEL_SERVICE_ID \
		CORTEX_RETENTION_POLICY_VERSION CORTEX_MINIMUM_RETENTION_BLOCKS; do
		require_env "$name"
	done

	# The template pins nexus.envelope_auth_mode: strict, and only
	# CORTEX_NEXUS_ENVELOPE_AUTH_MODE can override it on the remote daemon.
	# CORTEX_NEXUS_BUILDER_OPERATOR is optional: a strict authenticator authorizes
	# senders from the chain's current BuilderSet, and the setting only narrows
	# that to one Builder.

	out="$generated_dir/node$i.yaml"
	umask 077
	sed \
		-e "s|@@MODE@@|$(sed_safe "${CORTEX_MODE:-real}")|g" \
		-e "s|@@NEXUS_ENVELOPE_AUTH_MODE@@|$(sed_safe "${CORTEX_NEXUS_ENVELOPE_AUTH_MODE:-strict}")|g" \
		-e "s|@@CHAIN_ID@@|$(sed_safe "$CORTEX_CHAIN_ID")|g" \
		-e "s|@@NODE_ROOT@@|$(sed_safe "$node_root")|g" \
		-e "s|@@NODE_RPC@@|$(sed_safe "$CORTEX_NODE_RPC")|g" \
		-e "s|@@NODE_REST@@|$(sed_safe "$CORTEX_NODE_REST")|g" \
		-e "s|@@KEEPER_API@@|$(sed_safe "$CORTEX_KEEPER_API")|g" \
		-e "s|@@NEXUS_INGRESS@@|$(sed_safe "$CORTEX_NEXUS_INGRESS")|g" \
		-e "s|@@NEXUS_NATS@@|$(sed_safe "$CORTEX_NEXUS_NATS")|g" \
		-e "s|@@NEXUS_JETSTREAM_STREAM@@|$(sed_safe "${CORTEX_NEXUS_JETSTREAM_STREAM:-TRUEOPEN_TASK}")|g" \
		-e "s|@@NEXUS_TOKEN_PATH@@|$(sed_safe "$CORTEX_REMOTE_ROOT/secrets/nexus.token")|g" \
		-e "s|@@KEYSTORE_PASSWORD_PATH@@|$(sed_safe "$CORTEX_REMOTE_ROOT/secrets/keystore.pass")|g" \
		-e "s|@@MODEL_ENDPOINT@@|$(sed_safe "$CORTEX_MODEL_ENDPOINT")|g" \
		-e "s|@@MODEL_ID@@|$(sed_safe "$CORTEX_MODEL_ID")|g" \
		-e "s|@@MODEL_PROFILES@@|$(sed_safe "$CORTEX_MODEL_PROFILES")|g" \
		-e "s|@@MODEL_SERVICE_ID@@|$(sed_safe "$CORTEX_MODEL_SERVICE_ID")|g" \
		-e "s|@@NEXUS_BUILDER_OPERATOR@@|$(sed_safe "${CORTEX_NEXUS_BUILDER_OPERATOR:-}")|g" \
		-e "s|@@NEXUS_ALLOW_INSECURE_DESCRIPTOR@@|$(sed_safe "${CORTEX_NEXUS_ALLOW_INSECURE_DESCRIPTOR:-false}")|g" \
		-e "s|@@RETENTION_POLICY_VERSION@@|$(sed_safe "$CORTEX_RETENTION_POLICY_VERSION")|g" \
		-e "s|@@MODEL_TLS_PUBKEY_HASH@@|$(sed_safe "${CORTEX_MODEL_TLS_PUBKEY_HASH:-}")|g" \
		-e "s|@@NEXUS_NATS_CA_FILE@@|$(sed_safe "${CORTEX_NEXUS_NATS_CA_FILE:-}")|g" \
		-e "s|@@NEXUS_NATS_USER_KEY_FILE@@|$(sed_safe "${CORTEX_NEXUS_NATS_USER_KEY_FILE:-}")|g" \
		-e "s|@@MINIMUM_RETENTION_BLOCKS@@|$(sed_safe "$CORTEX_MINIMUM_RETENTION_BLOCKS")|g" \
		-e "s|@@OPERATOR_ADDRESS@@|$(sed_safe "$operator")|g" \
		-e "s|@@HEALTH_PORT@@|$health_port|g" \
		"$template" >"$out"

	remaining=$(grep -c '@@' "$out" || true)
	[ "$remaining" -eq 0 ] || die "unrendered markers left in $out"
	echo "$out"
}

cmd_render() {
	[ -f "$template" ] || die "missing template: $template"
	mkdir -p "$generated_dir"
	each_node render_one
}

push_config_one() {
	i=$1
	[ -f "$generated_dir/node$i.yaml" ] || die "run render first: missing $generated_dir/node$i.yaml"
	remote "umask 077 && mkdir -p '$CORTEX_REMOTE_ROOT/node$i'"
	scp -q "$generated_dir/node$i.yaml" "$CORTEX_SSH_HOST:$CORTEX_REMOTE_ROOT/node$i/config.yaml"
}

start_one() {
	i=$1
	root="$CORTEX_REMOTE_ROOT/node$i"
	health_port=$((CORTEX_HEALTH_PORT_BASE + i))
	# Deployment-specific overrides come from .env rather than the shipped
	# template, so the committed config keeps safe defaults. cortexd resolves
	# defaults < YAML < environment < flags.
	overrides=""
	for name in $CORTEX_FORWARDED_OVERRIDES; do
		eval "value=\${$name:-}"
		[ -n "$value" ] || continue
		overrides="$overrides$name=$(shell_quote "$value") \\
		"
	done
	remote "set -eu
		if [ -f '$root/cortexd.pid' ] && kill -0 \"\$(cat '$root/cortexd.pid')\" 2>/dev/null; then
			echo 'node$i already running (pid '\"\$(cat '$root/cortexd.pid')\"')'
			exit 0
		fi
		mkdir -p '$root/data/evidence'
		cd '$root'
		# cortexd appends to one log across restarts, so a failed start has to
		# be read from where this attempt began. Tailing a fixed line count
		# instead reports whatever the previous run was doing, which buries the
		# refusal that just happened under unrelated history.
		mark=0
		[ ! -f '$root/cortexd.log' ] || mark=\$(wc -c < '$root/cortexd.log')
		CORTEX_ADMIN_SOCKET='$root/cortexd.sock' \
		CORTEX_ARTIFACTS_ROOT='$root/data/evidence' \
		CORTEX_STORE_PATH='$root/data/store' \
		CORTEX_HEALTH_BIND='0.0.0.0:$health_port' \
		$overrides nohup '$CORTEX_REMOTE_ROOT/bin/cortexd' -config '$root/config.yaml' \
			>>'$root/cortexd.log' 2>&1 &
		echo \$! > '$root/cortexd.pid'
		sleep 1
		if kill -0 \"\$(cat '$root/cortexd.pid')\" 2>/dev/null; then
			echo 'node$i started (pid '\"\$(cat '$root/cortexd.pid')\"')'
		else
			echo 'node$i failed to start; its own log output:' >&2
			tail -c +\$((mark + 1)) '$root/cortexd.log' >&2
			exit 1
		fi"
}

cmd_up() {
	each_node push_config_one
	each_node start_one
}

stop_one() {
	i=$1
	root="$CORTEX_REMOTE_ROOT/node$i"
	remote "set -eu
		if [ ! -f '$root/cortexd.pid' ]; then echo 'node$i not running'; exit 0; fi
		pid=\$(cat '$root/cortexd.pid')
		if kill -0 \"\$pid\" 2>/dev/null; then
			kill \"\$pid\"
			for _ in 1 2 3 4 5 6 7 8 9 10; do
				kill -0 \"\$pid\" 2>/dev/null || break
				sleep 1
			done
			kill -0 \"\$pid\" 2>/dev/null && kill -9 \"\$pid\" || true
			echo 'node$i stopped'
		else
			echo 'node$i not running'
		fi
		rm -f '$root/cortexd.pid'"
}

# State under node*/data is deliberately left alone.
cmd_down() { each_node stop_one; }

status_one() {
	i=$1
	root="$CORTEX_REMOTE_ROOT/node$i"
	port=$((CORTEX_HEALTH_PORT_BASE + i))
	remote "set -u
		pid=\$(cat '$root/cortexd.pid' 2>/dev/null || echo -)
		if [ \"\$pid\" != '-' ] && kill -0 \"\$pid\" 2>/dev/null; then run=up; else run=down; fi
		health=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:$port/healthz || echo ---)
		ready=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:$port/readyz || echo ---)
		printf 'node$i\tpid=%s\t%s\thealthz=%s\treadyz=%s\n' \"\$pid\" \"\$run\" \"\$health\" \"\$ready\""
}

cmd_status() { each_node status_one; }

diag_one() {
	i=$1
	root="$CORTEX_REMOTE_ROOT/node$i"
	echo "== node$i =="
	remote "'$CORTEX_REMOTE_ROOT/bin/cortexctl' --admin-socket '$root/cortexd.sock' diagnostics --format json" |
		jq -r '.dependencies[]? | "  \(.name)\t\(if .ready then "ready" else "NOT READY" end)\t\(.detail // .error // "")"' 2>/dev/null ||
		echo "  (diagnostics unavailable)"
}

cmd_diag() { each_node diag_one; }

cmd_logs() {
	lines=${2:-40}
	i=1
	while [ "$i" -le "$CORTEX_NODE_COUNT" ]; do
		echo "== node$i =="
		remote "tail -n $lines '$CORTEX_REMOTE_ROOT/node$i/cortexd.log' 2>/dev/null || echo '  (no log yet)'"
		i=$((i + 1))
	done
}

# --- smoke ------------------------------------------------------------------

# One order ingress check followed by supported admin diagnostics. The compact
# Pebble store is active recovery state, not an operator query surface, so this
# command deliberately does not inspect the database file.
#
# It publishes onto the SHARED devnet bus, so it is gated on the literal word
# `confirm` rather than an environment variable: load_env sources
# deploy/testnet/.env with `set -a`, so an env gate written into that file once
# would silently arm every later invocation. A positional word has to be typed
# at the call site and stays in the shell history next to the run it authorized.
# up, status and diag never reach this code.
#
# Optional knobs:
#   CORTEX_SMOKE_TIMEOUT          seconds to wait for propagation (default 45)
#   CORTEX_SMOKE_INTERVAL         seconds between polls (default 3)
#   CORTEX_SMOKE_DEADLINE_BLOCKS  order deadline height above the live chain
#                                 tip (default 200)
#   CORTEX_SMOKE_BUILDER          builder address to attribute the order to,
#                                 when the node config carries none
#   CORTEX_SMOKE_BUILDER_SET_ID   fabricated BuilderSet id (default smoke)
#   CORTEX_SMOKE_BUILDER_SET_HASH 64 lowercase hex; default sha256(id)
#   CORTEX_SMOKE_AUTHORIZATION_NONCE  envelope field 7 (default 1)
# snapshot-height is the live chain tip, not an env knob.


# The order is published from the server, not from here: the NATS URL stays on
# the host that already holds it, it is read out of node1's own running config
# rather than passed in, and the extraction happens inside the remote shell so
# it never reaches the ssh command line or this terminal. testorder does not
# print it either.
smoke_publish() {
	blocks=$1
	builder=$2
	set_id=${CORTEX_SMOKE_BUILDER_SET_ID:-smoke}
	set_hash=${CORTEX_SMOKE_BUILDER_SET_HASH:-}
	nonce=${CORTEX_SMOKE_AUTHORIZATION_NONCE:-1}
	remote "set -eu
		export PATH=/usr/local/go/bin:\$PATH
		cfg='$CORTEX_REMOTE_ROOT/node1/config.yaml'
		[ -f \"\$cfg\" ] || { echo \"missing \$cfg: run render and up first\" >&2; exit 1; }
		[ -d '$CORTEX_REMOTE_ROOT/src' ] || { echo 'missing $CORTEX_REMOTE_ROOT/src: run sync first' >&2; exit 1; }
		nats=\$(sed -n 's|^  nats_url: *||p' \"\$cfg\" | head -n 1)
		model=\$(sed -n 's|^  subscribe_models: *||p' \"\$cfg\" | head -n 1 | tr -d '[] ' | cut -d, -f1)
		chain=\$(sed -n 's|^chain_id: *||p' \"\$cfg\" | head -n 1)
		rpc=\$(sed -n 's|^  rpc_endpoint: *||p' \"\$cfg\" | head -n 1)
		# testorder defaults to a 2 minute envelope lifetime, which every
		# correctly configured node refuses: the authenticator rejects any
		# lifetime past nexus.envelope_ttl_ms outright
		# (internal/daemon/envelope_auth.go:474). Take the bound from the
		# deployment being tested so the order is judged on its contents.
		ttl_ms=\$(sed -n 's|^  envelope_ttl_ms: *||p' \"\$cfg\" | head -n 1)
		builder='$builder'
		[ -n \"\$builder\" ] ||
			builder=\$(sed -n 's|^  builder_operator_address: *||p' \"\$cfg\" | head -n 1 | tr -d '\"')
		[ -n \"\$nats\" ] || { echo 'node1 config carries no nexus.nats_url' >&2; exit 1; }
		[ -n \"\$model\" ] || { echo 'node1 config carries no nexus.subscribe_models' >&2; exit 1; }
		[ -n \"\$chain\" ] || { echo 'node1 config carries no chain_id' >&2; exit 1; }
		[ -n \"\$rpc\" ] || { echo 'node1 config carries no node.rpc_endpoint' >&2; exit 1; }
		[ -n \"\$builder\" ] || { echo 'no builder address: node1 nexus.builder_operator_address is empty, set CORTEX_SMOKE_BUILDER' >&2; exit 1; }
		height=\$(curl -sS --max-time 10 \"\$rpc/status\" |
			sed -n 's/.*\"latest_block_height\":\"\([0-9]*\)\".*/\1/p' | head -n 1)
		[ -n \"\$height\" ] || { echo \"could not read latest_block_height from \$rpc/status\" >&2; exit 1; }
		set_hash='$set_hash'
		[ -n \"\$set_hash\" ] || set_hash=\$(printf '%s' '$set_id' | sha256sum | cut -d' ' -f1)
		echo \"smoke_chain_id=\$chain\"
		echo \"smoke_model_id=\$model\"
		echo \"smoke_height=\$height\"
		echo \"smoke_deadline_height=\$((height + $blocks))\"
		echo \"smoke_envelope_ttl_ms=\${ttl_ms:-default}\"
		cd '$CORTEX_REMOTE_ROOT/src'
		go run ./scripts/testorder -nats-url \"\$nats\" -chain-id \"\$chain\" \\
			-model-id \"\$model\" -builder \"\$builder\" \\
			-deadline-height \"\$((height + $blocks))\" \\
			-builder-set-id '$set_id' -builder-set-hash \"\$set_hash\" \\
			-authorization-nonce '$nonce' -snapshot-height \"\$height\" \\
			\${ttl_ms:+-ttl \"\${ttl_ms}ms\"}"
}

# Byte offset of every node's log before the order is published. The inbox
# outcome is only visible in the log, and these logs span restarts, so the run
# has to read the region this order produced rather than a line count that may
# still describe the previous run.
smoke_log_marks() {
	remote "set -u
		i=1
		while [ \"\$i\" -le $CORTEX_NODE_COUNT ]; do
			log='$CORTEX_REMOTE_ROOT/node'\$i'/cortexd.log'
			mark=0
			[ ! -f \"\$log\" ] || mark=\$(wc -c < \"\$log\")
			printf 'node%s\t%s\n' \"\$i\" \"\$mark\"
			i=\$((i + 1))
		done"
}

# Everything a node logged about this order after the publish mark, as
# 'nodeN<TAB>reason'. Admin diagnostics cannot answer this: a node that throws
# the order away keeps serving diagnostics perfectly, so reachability alone
# reports a pass for an order no Worker acted on.
#
# Two distinct outcomes are collected, because catching only the first one
# already produced a false pass here: an envelope refused at the inbox boundary,
# and an order that was ACCEPTED and then failed inside the task runner. The
# second is matched on the published task id so an unrelated earlier failure in
# the same log cannot be reported against this run.
smoke_refusals() {
	task_id=$2
	remote "set -u
		for pair in $1; do
			i=\${pair%%:*}
			mark=\${pair#*:}
			log='$CORTEX_REMOTE_ROOT/node'\$i'/cortexd.log'
			[ -f \"\$log\" ] || continue
			region=\$(tail -c +\$((mark + 1)) \"\$log\")
			reason=\$(printf '%s\n' \"\$region\" |
				sed -n 's/.*Nexus inbox refused [^ ]*: *//p' | tail -n 1)
			[ -n \"\$reason\" ] ||
				reason=\$(printf '%s\n' \"\$region\" |
					sed -n 's/.*task runner failure source=nexus_open_task record=$task_id: */admitted, then failed in the task runner: /p' |
					tail -n 1)
			[ -n \"\$reason\" ] || continue
			printf 'node%s\t%s\n' \"\$i\" \"\$reason\"
		done"
}

# The effective envelope auth mode changes only across restarts, so it is
# collected once rather than on every poll. It is read from
# the running daemon rather than config.yaml because up forwards
# CORTEX_NEXUS_ENVELOPE_AUTH_MODE as an environment override. In real mode that
# override can only ever agree with the rendered strict value or stop the daemon
# from starting (internal/config/config.go:831-834), so a disagreement here
# means the process is older than its config. Only that one field is extracted;
# the same diagnostics report also carries the NATS URL.
smoke_profile() {
	remote "set -u
		i=1
		while [ \"\$i\" -le $CORTEX_NODE_COUNT ]; do
			root='$CORTEX_REMOTE_ROOT/node'\$i
			auth=\$('$CORTEX_REMOTE_ROOT/bin/cortexctl' --admin-socket \"\$root/cortexd.sock\" \\
				diagnostics --format json 2>/dev/null |
				sed -n 's|.*\"nexus_envelope_auth_mode\": *\"\([^\"]*\)\".*|\1|p' | head -n 1)
			[ -n \"\$auth\" ] || auth=-
			printf 'node%s\t%s\n' \"\$i\" \"\$auth\"
			i=\$((i + 1))
		done"
}

# One line per node from the owner-only admin API. A successful diagnostics call
# proves the daemon and its Pebble health probe are reachable; authoritative task
# state remains in Keeper, while active responsibilities and evidence metadata
# are managed through typed daemon APIs rather than raw file inspection.
smoke_probe() {
	remote "set -u
		i=1
		while [ \"\$i\" -le $CORTEX_NODE_COUNT ]; do
			root='$CORTEX_REMOTE_ROOT/node'\$i
			if '$CORTEX_REMOTE_ROOT/bin/cortexctl' --admin-socket \"\$root/cortexd.sock\" diagnostics --format json >/dev/null 2>&1; then
				printf 'node%s\tadmin-ready\t-\t-\t-\n' \"\$i\"
			else
				printf 'node%s\tadmin-unavailable\t-\t-\tdiagnostics failed\n' \"\$i\"
			fi
			i=\$((i + 1))
		done"
}

# A probe that returns fewer lines than there are nodes has not observed the
# deployment, so it must never be summarised as a pass.
smoke_report() {
	smoke_report_lines=$(smoke_probe "$1" "$2" | sed -n '/^node[0-9]/p')
	count=$(printf '%s' "$smoke_report_lines" | sed -n '$=')
	[ "${count:-0}" -eq "$CORTEX_NODE_COUNT" ] ||
		die "smoke: probe returned ${count:-0} of $CORTEX_NODE_COUNT node lines"
	printf '%s\n' "$smoke_report_lines"
}

# True once every node exposes its admin diagnostics after publish. Duty
# selection is retired, so every node subscribes the orders subject and every
# node is expected to answer -- there is no node this poll may skip.
smoke_settled() {
	pending=0
	while IFS='	' read -r name inbox state raise err; do
		case "$name" in
		node[0-9]*) ;;
		*) continue ;;
		esac
		case "$inbox" in
		admin-ready) ;;
		*) pending=1 ;;
		esac
	done <<-EOF
		$1
	EOF
	[ "$pending" -eq 0 ]
}

cmd_smoke() {
	[ "${2:-}" = confirm ] ||
		die "smoke publishes a real order onto the shared devnet bus; re-run as: $0 smoke confirm"
	timeout=${CORTEX_SMOKE_TIMEOUT:-45}
	interval=${CORTEX_SMOKE_INTERVAL:-3}
	blocks=${CORTEX_SMOKE_DEADLINE_BLOCKS:-200}
	# Marked before the publish so the refusal scan below cannot pick up an
	# unrelated earlier order.
	marks=$(smoke_log_marks | sed -n '/^node[0-9]/p' |
		sed 's/^node//' | tr '\t' ':' | tr '\n' ' ')
	published=$(smoke_publish "$blocks" "${CORTEX_SMOKE_BUILDER:-}") ||
		die "smoke: publishing the order failed"
	task_id=$(printf '%s\n' "$published" | sed -n 's/^  task_id: *//p' | head -n 1)
	session_id=$(printf '%s\n' "$published" | sed -n 's/^  session_id: *//p' | head -n 1)
	model_id=$(printf '%s\n' "$published" | sed -n 's/^smoke_model_id=//p' | head -n 1)
	chain_id=$(printf '%s\n' "$published" | sed -n 's/^smoke_chain_id=//p' | head -n 1)
	height=$(printf '%s\n' "$published" | sed -n 's/^smoke_height=//p' | head -n 1)
	deadline_height=$(printf '%s\n' "$published" | sed -n 's/^smoke_deadline_height=//p' | head -n 1)
	envelope_ttl_ms=$(printf '%s\n' "$published" | sed -n 's/^smoke_envelope_ttl_ms=//p' | head -n 1)
	[ -n "$task_id" ] || die "smoke: could not read the published task id from testorder output"
	[ -n "$model_id" ] || die "smoke: could not read the model id from the node config"
	printf '%s\n' "$published" | sed '/^smoke_/d'

	profile=$(smoke_profile | sed -n '/^node[0-9]/p')
	profile_lines=$(printf '%s' "$profile" | sed -n '$=')
	[ "${profile_lines:-0}" -eq "$CORTEX_NODE_COUNT" ] ||
		die "smoke: read the envelope auth mode for ${profile_lines:-0} of $CORTEX_NODE_COUNT nodes"
	while IFS='	' read -r name auth; do
		case "$name" in
		node[0-9]*) ;;
		*) continue ;;
		esac
		eval "smoke_auth_${name#node}=\$auth"
	done <<-EOF
		$profile
	EOF

	started=$(date +%s)
	report=$(smoke_report "$task_id" "$model_id") || exit 1
	elapsed=0
	while ! smoke_settled "$report"; do
		[ "$elapsed" -lt "$timeout" ] || break
		sleep "$interval"
		report=$(smoke_report "$task_id" "$model_id") || exit 1
		elapsed=$(($(date +%s) - started))
	done

	# The settle loop can finish before the inbox has logged anything, because
	# admin diagnostics are already reachable when the order lands. One
	# interval makes the refusal scan observe this order's outcome instead of
	# racing it.
	sleep "$interval"
	refusals=$(smoke_refusals "$marks" "$task_id" | sed -n '/^node[0-9]/p')
	while IFS='	' read -r name reason; do
		case "$name" in
		node[0-9]*) ;;
		*) continue ;;
		esac
		eval "smoke_refusal_${name#node}=\$reason"
	done <<-EOF
		$refusals
	EOF

	echo
	echo "== smoke =="
	printf '  task_id:     %s\n' "$task_id"
	printf '  session_id:  %s\n' "$session_id"
	printf '  model_id:    %s\n' "$model_id"
	printf '  chain_id:    %s\n' "$chain_id"
	printf '  chain tip:   %s (order deadline height %s)\n' "$height" "$deadline_height"
	printf '  waited:      %ss of at most %ss\n' "$elapsed" "$timeout"
	printf '  envelope ttl: %sms (from the deployed nexus.envelope_ttl_ms)\n' "$envelope_ttl_ms"
	echo
	failures=0
	workers=0
	while IFS='	' read -r name inbox state raise err; do
		case "$name" in
		node[0-9]*) ;;
		*) continue ;;
		esac
		eval "auth=\${smoke_auth_${name#node}:--}"
		eval "refusal=\${smoke_refusal_${name#node}:-}"
		# Every node subscribes the orders subject now that duty selection is
		# retired, so "expected-silent" is gone as a verdict: silence is a
		# failure on every node.
		workers=$((workers + 1))
		# A refused envelope is the one outcome that looks like success
		# from the admin API, so it is judged before reachability: the
		# daemon is healthy and the order is gone.
		if [ -n "$refusal" ]; then
			verdict=FAIL-order-rejected
			failures=$((failures + 1))
		else
			case "$inbox" in
			admin-ready) verdict=published-admin-ready ;;
			*)
				verdict=FAIL
				failures=$((failures + 1))
				;;
			esac
		fi
		printf '%s\tauth=%s\tdiagnostics=%s\t%s\n' \
			"$name" "$auth" "$inbox" "$verdict"
		[ "$err" = - ] || printf '       diagnostics error: %s\n' "$err"
		[ -z "$refusal" ] || printf '       this order: %s\n' "$refusal"
	done <<-EOF
		$report
	EOF

	echo
	echo 'follow up on this task with an assign notify:'
	printf '  go run ./scripts/testassign -nats-url "$NEXUS_NATS_URL" -chain-id %s \\\n' "$chain_id"
	printf '    -session-id %s -task-id %s \\\n' "$session_id" "$task_id"
	echo '    -winner OPERATOR -finalized-height HEIGHT -payload-cid CID -builder BUILDER'
	echo '  (with no Keeper-authoritative assignment the node must refuse it: scripts/testassign/README.md)'

	if [ "$failures" -ne 0 ]; then
		echo "smoke: $failures node(s) failed for $task_id (order rejected at the inbox or in the task runner, or admin diagnostics unavailable)" >&2
		exit 1
	fi
	# A deployment reporting no node lines at all settles on the first poll, so
	# a zero failure count would report a pass for a run that observed nothing.
	[ "$workers" -gt 0 ] ||
		die "smoke: no node in this deployment, so nothing could admit the order for $task_id"
	echo "smoke: published $task_id; $workers node(s) retained admin diagnostics access"
}

usage() {
	cat >&2 <<-EOF
		usage: $0 <command>

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
		  smoke confirm
		           publish one order onto the SHARED devnet bus and report the
		           round trip per node; the literal word confirm is required
	EOF
	exit 2
}

# CORTEX_DEPLOY_LIB lets scripts/tests source this file to exercise the command
# construction without dispatching a deployment action.
if [ -z "${CORTEX_DEPLOY_LIB:-}" ]; then
	case "${1:-}" in
	addr | sync | build | push | render | up | down | status | diag | logs | smoke)
		load_env
		"cmd_$1" "$@"
		;;
	*) usage ;;
	esac
fi
