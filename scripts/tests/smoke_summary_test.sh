#!/usr/bin/env sh
# smoke is read-only in Phase 1: orders reach a Worker only through a
# Builder's DispatchStream, so there is nothing a deployment script may
# publish. Its value is still honest failure: a node that answers /readyz
# but has an unbound Builder stream, or configures no Builder at all, must
# fail the run. This drives cmd_smoke with the per-node probe stubbed.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_script="$script_dir/../testnet-deploy.sh"
[ -f "$deploy_script" ] || { echo "missing $deploy_script" >&2; exit 1; }

CORTEX_DEPLOY_LIB=1
export CORTEX_DEPLOY_LIB
# shellcheck disable=SC1090
. "$deploy_script"

CORTEX_REMOTE_ROOT=/opt/cortex
CORTEX_SSH_HOST=stub
CORTEX_NODE_COUNT=2

failures=0
fail() {
	echo "FAIL: $1" >&2
	failures=$((failures + 1))
}

remote() { :; }

# shape selects what node2 reports.
shape=bound
smoke_node() {
	case "$1:$shape" in
	1:*) printf 'node1\t200\t2\t2\t\n' ;;
	2:bound) printf 'node2\t200\t2\t2\t\n' ;;
	2:unbound) printf 'node2\t503\t1\t2\tdispatch_stream:b2=dial refused\n' ;;
	2:none) printf 'node2\t200\t0\t0\t\n' ;;
	esac
}

output=$( (cmd_smoke smoke) 2>&1 ) && status=0 || status=$?
[ "$status" -eq 0 ] || fail "every node ready and bound must pass: $output"

shape=unbound
output=$( (cmd_smoke smoke) 2>&1 ) && status=0 || status=$?
[ "$status" -ne 0 ] || fail "an unbound Builder stream must fail the run"
case "$output" in
*"dispatch_stream:b2=dial refused"*) ;;
*) fail "smoke did not say which stream is down: $output" ;;
esac

shape=none
output=$( (cmd_smoke smoke) 2>&1 ) && status=0 || status=$?
[ "$status" -ne 0 ] || fail "a node with no Builder stream configured must fail"

if command -v jq >/dev/null 2>&1; then
	got=$(smoke_stream_summary '{"dependencies":[{"name":"dispatch_stream:b1","ready":true},{"name":"dispatch_stream:b2","ready":false,"error":"x"},{"name":"chain","ready":true}]}')
	[ "$got" = "$(printf '1\t2\tdispatch_stream:b2=x')" ] || fail "stream summary = $got"
fi

[ "$failures" -eq 0 ] || exit 1
echo "smoke_summary_test: ok"
