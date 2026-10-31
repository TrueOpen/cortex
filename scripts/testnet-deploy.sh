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
CORTEX_FORWARDED_OVERRIDES="CORTEX_MODEL_TRANSPORT CORTEX_MODEL_ENDPOINT CORTEX_MODEL_MAX_CONCURRENCY CORTEX_TASK_INPUT_RESOLVER CORTEX_TASK_FIXTURE_ROOT"

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
		CORTEX_NEXUS_INGRESS CORTEX_MODEL_ENDPOINT CORTEX_MODEL_ID \
		CORTEX_MODEL_PROFILES CORTEX_MODEL_SERVICE_ID \
		CORTEX_RETENTION_POLICY_VERSION CORTEX_MINIMUM_RETENTION_BLOCKS \
		CORTEX_DISPATCH_BUILDERS CORTEX_DISPATCH_EVIDENCE_RETENTION_BLOCKS \
		CORTEX_DISPATCH_HEARTBEAT_MS CORTEX_DISPATCH_TTL_MS CORTEX_DISPATCH_MIN_CHANGE_INTERVAL_MS \
		CORTEX_DISPATCH_MIN_PRICE_BID CORTEX_DISPATCH_KEEPALIVE_MS CORTEX_DISPATCH_KEEPALIVE_MAX_MISSED \
		CORTEX_DISPATCH_RESCUE_MARGIN_BLOCKS CORTEX_DISPATCH_ROSTER_GRACE_BLOCKS \
		CORTEX_DISPATCH_CHALLENGE_MARGIN_BLOCKS; do
		require_env "$name"
	done

	# CORTEX_NEXUS_BUILDER_OPERATOR is optional: the chain's current BuilderSet
	# is the authority, and the setting only narrows that to one Builder.

	out="$generated_dir/node$i.yaml"
	umask 077
	sed \
		-e "s|@@MODE@@|$(sed_safe "${CORTEX_MODE:-real}")|g" \
		-e "s|@@CHAIN_ID@@|$(sed_safe "$CORTEX_CHAIN_ID")|g" \
		-e "s|@@NODE_ROOT@@|$(sed_safe "$node_root")|g" \
		-e "s|@@NODE_RPC@@|$(sed_safe "$CORTEX_NODE_RPC")|g" \
		-e "s|@@NODE_REST@@|$(sed_safe "$CORTEX_NODE_REST")|g" \
		-e "s|@@KEEPER_API@@|$(sed_safe "$CORTEX_KEEPER_API")|g" \
		-e "s|@@NEXUS_INGRESS@@|$(sed_safe "$CORTEX_NEXUS_INGRESS")|g" \
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
		-e "s|@@MINIMUM_RETENTION_BLOCKS@@|$(sed_safe "$CORTEX_MINIMUM_RETENTION_BLOCKS")|g" \
		-e "s|@@DISPATCH_BUILDERS@@|$(sed_safe "$CORTEX_DISPATCH_BUILDERS")|g" \
		-e "s|@@DISPATCH_EVIDENCE_RETENTION_BLOCKS@@|$(sed_safe "$CORTEX_DISPATCH_EVIDENCE_RETENTION_BLOCKS")|g" \
		-e "s|@@DISPATCH_HEARTBEAT_MS@@|$(sed_safe "$CORTEX_DISPATCH_HEARTBEAT_MS")|g" \
		-e "s|@@DISPATCH_TTL_MS@@|$(sed_safe "$CORTEX_DISPATCH_TTL_MS")|g" \
		-e "s|@@DISPATCH_MIN_CHANGE_INTERVAL_MS@@|$(sed_safe "$CORTEX_DISPATCH_MIN_CHANGE_INTERVAL_MS")|g" \
		-e "s|@@DISPATCH_MIN_PRICE_BID@@|$(sed_safe "$CORTEX_DISPATCH_MIN_PRICE_BID")|g" \
		-e "s|@@DISPATCH_KEEPALIVE_MS@@|$(sed_safe "$CORTEX_DISPATCH_KEEPALIVE_MS")|g" \
		-e "s|@@DISPATCH_KEEPALIVE_MAX_MISSED@@|$(sed_safe "$CORTEX_DISPATCH_KEEPALIVE_MAX_MISSED")|g" \
		-e "s|@@DISPATCH_RESCUE_MARGIN_BLOCKS@@|$(sed_safe "$CORTEX_DISPATCH_RESCUE_MARGIN_BLOCKS")|g" \
		-e "s|@@DISPATCH_ROSTER_GRACE_BLOCKS@@|$(sed_safe "$CORTEX_DISPATCH_ROSTER_GRACE_BLOCKS")|g" \
		-e "s|@@DISPATCH_CHALLENGE_MARGIN_BLOCKS@@|$(sed_safe "$CORTEX_DISPATCH_CHALLENGE_MARGIN_BLOCKS")|g" \
		-e "s|@@MODEL_MAX_CONCURRENCY@@|$(sed_safe "${CORTEX_MODEL_MAX_CONCURRENCY:-1}")|g" \
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

# Phase 1 has no order a deployment script may publish: orders reach a Worker
# only through a Builder's DispatchStream. smoke therefore checks, read-only,
# what each node proves on its own: /readyz answers 200 and every configured
# Builder stream (dispatch_stream:<builder>) is bound. Nothing is written to
# the chain or to any Builder.

# smoke_stream_summary turns one diagnostics report into
# 'bound<TAB>configured<TAB>detail' for its dispatch_stream rows.
smoke_stream_summary() {
	printf '%s' "$1" | jq -r '
		[.dependencies[]? | select(.name | startswith("dispatch_stream:"))] as $s
		| "\([$s[] | select(.ready)] | length)\t\($s | length)\t\([$s[] | select(.ready | not) | "\(.name)=\(.error // "not ready")"] | join("; "))"' 2>/dev/null ||
		printf '0\t0\tdiagnostics unavailable'
}

# One line per node: 'nodeN<TAB>readyz<TAB>bound<TAB>configured<TAB>detail'.
smoke_node() {
	i=$1
	root="$CORTEX_REMOTE_ROOT/node$i"
	port=$((CORTEX_HEALTH_PORT_BASE + i))
	ready=$(remote "curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:$port/readyz || echo ---")
	diag=$(remote "'$CORTEX_REMOTE_ROOT/bin/cortexctl' --admin-socket '$root/cortexd.sock' diagnostics --format json" 2>/dev/null) || diag=
	printf 'node%s\t%s\t%s\n' "$i" "${ready:----}" "$(smoke_stream_summary "$diag")"
}

cmd_smoke() {
	lines=$(each_node smoke_node | sed -n '/^node[0-9]/p')
	count=$(printf '%s\n' "$lines" | sed -n '$=')
	[ "${count:-0}" -eq "$CORTEX_NODE_COUNT" ] ||
		die "smoke: read ${count:-0} of $CORTEX_NODE_COUNT nodes"
	failures=0
	echo "== smoke (read-only: readiness and Builder streams) =="
	while IFS='	' read -r name ready bound configured detail; do
		case "$name" in
		node[0-9]*) ;;
		*) continue ;;
		esac
		verdict=ok
		if [ "$ready" != 200 ] || [ "${configured:-0}" -eq 0 ] || [ "${bound:-0}" -ne "${configured:-0}" ]; then
			verdict=FAIL
			failures=$((failures + 1))
		fi
		printf '%s\treadyz=%s\tstreams=%s/%s\t%s\n' "$name" "$ready" "${bound:-0}" "${configured:-0}" "$verdict"
		[ -z "$detail" ] || printf '       %s\n' "$detail"
	done <<-EOF
		$lines
	EOF
	[ "$failures" -eq 0 ] ||
		die "smoke: $failures node(s) not ready, with an unbound Builder stream, or with no Builder configured"
	echo "smoke: every node ready with every Builder stream bound"
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
		  smoke    read-only: /readyz and every Builder stream per node
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
