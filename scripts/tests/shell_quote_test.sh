#!/usr/bin/env sh
# Runtime overrides reach the daemon through an ssh command line. A value
# containing &, a single quote, or a backslash must arrive verbatim, and must
# not be able to terminate the quoting and run as remote shell.
#
# This exercises start_one itself with remote() stubbed, so it fails if the
# call site stops quoting correctly — not only if the helper does.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_script="$script_dir/../testnet-deploy.sh"
[ -f "$deploy_script" ] || { echo "missing $deploy_script" >&2; exit 1; }

CORTEX_DEPLOY_LIB=1
export CORTEX_DEPLOY_LIB
# shellcheck disable=SC1090
. "$deploy_script"

CORTEX_REMOTE_ROOT=/opt/cortex
CORTEX_HEALTH_PORT_BASE=18080
CORTEX_SSH_HOST=stub

# Capture the remote command instead of running it.
captured=""
remote() { captured="$1"; }

failures=0
fail() {
	echo "FAIL: $1" >&2
	failures=$((failures + 1))
}

# A NATS URL with & and a value with an embedded single quote are the realistic
# hostile shapes: sed-style escaping mangles the first and breaks on the second.
CORTEX_MODEL_TRANSPORT="fake"
CORTEX_NEXUS_ENVELOPE_AUTH_MODE="trusted_nats_dev"
CORTEX_NEXUS_JETSTREAM_STREAM="TRUEOPEN_TASK"
CORTEX_MODEL_ENDPOINT="http://user:pa&ss@127.0.0.1:8000/it's"
CORTEX_TASK_INPUT_RESOLVER="fixture"
CORTEX_TASK_FIXTURE_ROOT="/opt/cortex/fix tures"
CORTEX_MODEL_MAX_CONCURRENCY="8"
export CORTEX_MODEL_TRANSPORT CORTEX_NEXUS_ENVELOPE_AUTH_MODE CORTEX_MODEL_ENDPOINT CORTEX_NEXUS_JETSTREAM_STREAM
export CORTEX_TASK_INPUT_RESOLVER CORTEX_TASK_FIXTURE_ROOT CORTEX_MODEL_MAX_CONCURRENCY

# Every forwarded override must be set above, or the coverage below is vacuous
# for the ones that are missing.
for name in $CORTEX_FORWARDED_OVERRIDES; do
	eval "value=\${$name:-}"
	[ -n "$value" ] || { echo "FAIL: $name is forwarded by the deploy script but unset in this test" >&2; exit 1; }
done

start_one 1

[ -n "$captured" ] || { echo "start_one produced no remote command" >&2; exit 1; }

# The & must not have been rewritten by sed-style escaping.
case "$captured" in
*'pa\&ss'*) fail "value was sed-escaped: & became \\&" ;;
esac
case "$captured" in
*"pa&ss"*) ;;
*) fail "endpoint value did not survive into the remote command" ;;
esac

# The embedded single quote must be escaped so the quoting cannot be terminated.
case "$captured" in
*"it'\\''s"*) ;;
*) fail "embedded single quote was not escaped for the remote shell" ;;
esac

# Every configured override must appear.
for name in $CORTEX_FORWARDED_OVERRIDES; do
	case "$captured" in
	*"$name="*) ;;
	*) fail "$name missing from the remote command" ;;
	esac
done

# An unset override must not be emitted at all.
case "$captured" in
*"CORTEX_MODEL_ENDPOINT=''"*) fail "empty override was emitted" ;;
esac

# The generated assignments must be valid shell that round-trips every value.
# The captured command spans lines joined by backslash continuations, so fold
# them first; an extraction that yields nothing is a test defect, not a pass.
folded=$(printf '%s' "$captured" | sed -e ':a' -e 'N;$!ba' -e 's/\\\n[[:space:]]*/ /g' | tr '\n' ' ')
prefix=${folded#*CORTEX_ADMIN_SOCKET=}
prefix="CORTEX_ADMIN_SOCKET=$prefix"
prefix=${prefix%%nohup*}
case "$prefix" in
*CORTEX_MODEL_ENDPOINT=*) ;;
*) echo "FAIL: could not extract the generated assignments from the remote command" >&2; exit 1 ;;
esac

for probe in CORTEX_MODEL_ENDPOINT CORTEX_TASK_FIXTURE_ROOT CORTEX_NEXUS_ENVELOPE_AUTH_MODE; do
	expected=$(eval "printf '%s' \"\$$probe\"")
	got=$(eval "$prefix printf '%s' \"\$$probe\"" 2>&1) || {
		fail "generated assignments are not valid shell: $got"
		continue
	}
	[ "$got" = "$expected" ] || fail "$probe round-trip = $got, want $expected"
done

if [ "$failures" -ne 0 ]; then
	echo "$failures shell quoting cases failed" >&2
	exit 1
fi
echo "override quoting OK"
