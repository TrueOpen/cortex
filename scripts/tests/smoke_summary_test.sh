#!/usr/bin/env sh
# smoke's whole value is honest failure. Two shapes make it report a pass for a
# run that proved nothing, and both are checked here:
#
#   - a deployment with no WORKER-duty node admits no order at all, yet every
#     node is legitimately silent, so the failure count stays 0.
#   - a WORKER node that refuses the envelope at the inbox keeps serving admin
#     diagnostics perfectly, so reachability alone still reads as success while
#     the order is gone.
#
# This drives cmd_smoke itself with the remote calls stubbed, so it fails if a
# refusal is dropped from the command rather than only from a helper.
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
CORTEX_SMOKE_TIMEOUT=0
CORTEX_SMOKE_INTERVAL=0

failures=0
fail() {
	echo "FAIL: $1" >&2
	failures=$((failures + 1))
}

# Every remote call goes through the helpers stubbed below.
remote() { :; }

smoke_publish() {
	cat <<-PUB
		published order
		  task_id: stub-task-1
		  session_id: stub-session
		smoke_model_id=llm_text_v1
		smoke_chain_id=trueopen-devnet-1
		smoke_height=100
		smoke_deadline_height=300
		smoke_envelope_ttl_ms=30000
	PUB
}

smoke_log_marks() {
	printf 'node1\t0\n'
	printf 'node2\t0\n'
}

# No node refused anything unless a case below says so.
smoke_refusals() { :; }

# Two nodes, neither with WORKER duty, both silent - the shape that used to
# exit 0 having proved nothing.
smoke_profile() {
	printf 'node1\tVERIFIER\tstrict\n'
	printf 'node2\tVERIFIER\tstrict\n'
}

smoke_probe() {
	printf 'node1\tadmin-ready\t-\t-\t-\n'
	printf 'node2\tadmin-ready\t-\t-\t-\n'
}

output=$( (cmd_smoke smoke confirm) 2>&1 ) && status=0 || status=$?

[ "$status" -ne 0 ] || fail "smoke exited 0 with no WORKER-duty node"
case "$output" in
*"no WORKER-duty node"*) ;;
*) fail "smoke did not say why it refused: $output" ;;
esac

# The counterpart: one WORKER-duty node whose admin API answers and which
# refused nothing still passes, so the guards are not refusing everything.
smoke_profile() {
	printf 'node1\tWORKER\tstrict\n'
	printf 'node2\tVERIFIER\tstrict\n'
}

output=$( (cmd_smoke smoke confirm) 2>&1 ) && status=0 || status=$?
[ "$status" -eq 0 ] || fail "smoke refused a healthy WORKER-duty deployment: $output"
case "$output" in
*"1 WORKER-duty node(s) retained admin diagnostics access"*) ;;
*) fail "smoke did not report the WORKER count: $output" ;;
esac

# The rejection shapes. Admin diagnostics stay reachable in both, so without the
# log scan each reports published-admin-ready and exits 0 for an order no Worker
# acted on. The second one is why the scan cannot stop at inbox refusals: the
# order was ACCEPTED, went through envelope auth and canonical order
# verification, and then died inside the task runner. That produced a false pass
# on gpu-test.
for rejection in \
	'Nexus envelope carries no signature' \
	'admitted, then failed in the task runner: query current CandidatePool member: operator trueopen1node is not an ACTIVE CandidatePool member'
do
smoke_refusals() {
	printf 'node1\t%s\n' "$rejection"
}

output=$( (cmd_smoke smoke confirm) 2>&1 ) && status=0 || status=$?
[ "$status" -ne 0 ] || fail "smoke exited 0 for an order every WORKER rejected: $output"
case "$output" in
*FAIL-order-rejected*) ;;
*) fail "smoke did not name the rejected order: $output" ;;
esac
case "$output" in
*"$rejection"*) ;;
*) fail "smoke dropped the rejection reason: $output" ;;
esac
case "$output" in
*published-admin-ready*) fail "smoke still called the rejected order ready: $output" ;;
esac
done

[ "$failures" -eq 0 ] || exit 1
echo "smoke summary test: ok"
