#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
deploy_dir="$repo_dir/deploy/devnet"
generated_dir=${CORTEX_GENERATED_DIR:-"$deploy_dir/generated"}
config_path="$generated_dir/cortex.yaml"
compose_file="$deploy_dir/compose.yaml"

require_env() {
  name=$1
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "missing required environment variable: $name" >&2
    exit 2
  fi
}

sed_replacement() {
  name=$1
  eval "value=\${$name}"
  case "$value" in
    *'@@'*)
      echo "$name must not contain template markers" >&2
      exit 2
      ;;
  esac
  case "$value" in
    *'
'*)
      echo "$name must not contain newlines" >&2
      exit 2
      ;;
  esac
  printf '%s' "$value" | sed 's/[\\&|]/\\&/g'
}

render_config() {
  for name in \
    CORTEX_CHAIN_ID CORTEX_OPERATOR_ADDRESS \
    CORTEX_MODEL_ID CORTEX_MODEL_PROFILES CORTEX_MODEL_SERVICE_ID CORTEX_MODEL_ENDPOINT \
    CORTEX_NODE_RPC CORTEX_NODE_REST CORTEX_KEEPER_API CORTEX_NEXUS_INGRESS \
    CORTEX_NEXUS_NATS CORTEX_SIGNER_URI CORTEX_SERVICE_KEY_REF \
    CORTEX_RETENTION_POLICY_VERSION \
    CORTEX_MINIMUM_RETENTION_BLOCKS NEXUS_TOKEN_FILE
  do
    require_env "$name"
  done
  if [ ! -f "$NEXUS_TOKEN_FILE" ]; then
    echo "NEXUS_TOKEN_FILE does not exist: $NEXUS_TOKEN_FILE" >&2
    exit 2
  fi
  case "$NEXUS_TOKEN_FILE" in
    /*) ;;
    *)
      echo "NEXUS_TOKEN_FILE must be an absolute host path: $NEXUS_TOKEN_FILE" >&2
      exit 2
      ;;
  esac
  # Optional: empty is only valid when the corresponding endpoint is loopback;
  # real mode refuses to start otherwise (deployment security baseline).
  : "${CORTEX_MODEL_TLS_PUBKEY_HASH:=}"
  : "${CORTEX_NEXUS_NATS_CA_FILE:=}"
  : "${CORTEX_NEXUS_NATS_USER_KEY_FILE:=}"
  mkdir -p "$generated_dir"
  umask 077
  temp_config=$(mktemp "$generated_dir/cortex.yaml.XXXXXX")
  trap 'rm -f "$temp_config"' EXIT HUP INT TERM
  chain_id=$(sed_replacement CORTEX_CHAIN_ID)
  operator_address=$(sed_replacement CORTEX_OPERATOR_ADDRESS)
  model_id=$(sed_replacement CORTEX_MODEL_ID)
  model_profiles=$(sed_replacement CORTEX_MODEL_PROFILES)
  model_service_id=$(sed_replacement CORTEX_MODEL_SERVICE_ID)
  model_endpoint=$(sed_replacement CORTEX_MODEL_ENDPOINT)
  node_rpc=$(sed_replacement CORTEX_NODE_RPC)
  node_rest=$(sed_replacement CORTEX_NODE_REST)
  keeper_api=$(sed_replacement CORTEX_KEEPER_API)
  nexus_ingress=$(sed_replacement CORTEX_NEXUS_INGRESS)
  nexus_nats=$(sed_replacement CORTEX_NEXUS_NATS)
  signer_uri=$(sed_replacement CORTEX_SIGNER_URI)
  service_key_ref=$(sed_replacement CORTEX_SERVICE_KEY_REF)
  # The devnet Nexus publishes task frames to TRUEOPEN_TASK. Cortex binds its own
  # durable consumer on that stream, so the name has to reach the config; it is
  # defaulted rather than required so an existing env file keeps rendering.
  CORTEX_NEXUS_JETSTREAM_STREAM=${CORTEX_NEXUS_JETSTREAM_STREAM:-TRUEOPEN_TASK}
  nexus_jetstream_stream=$(sed_replacement CORTEX_NEXUS_JETSTREAM_STREAM)
  # Descriptor verification is opt-in: an unset Builder operator leaves it off.
  CORTEX_NEXUS_BUILDER_OPERATOR=${CORTEX_NEXUS_BUILDER_OPERATOR:-}
  nexus_builder_operator=$(sed_replacement CORTEX_NEXUS_BUILDER_OPERATOR)
  retention_policy_version=$(sed_replacement CORTEX_RETENTION_POLICY_VERSION)
  model_tls_pubkey_hash=$(sed_replacement CORTEX_MODEL_TLS_PUBKEY_HASH)
  nexus_nats_ca_file=$(sed_replacement CORTEX_NEXUS_NATS_CA_FILE)
  nexus_nats_user_key_file=$(sed_replacement CORTEX_NEXUS_NATS_USER_KEY_FILE)
  minimum_retention_blocks=$(sed_replacement CORTEX_MINIMUM_RETENTION_BLOCKS)
  sed \
    -e "s|@@CHAIN_ID@@|$chain_id|g" \
    -e "s|@@OPERATOR_ADDRESS@@|$operator_address|g" \
    -e "s|@@MODEL_ID@@|$model_id|g" \
    -e "s|@@MODEL_PROFILES@@|$model_profiles|g" \
    -e "s|@@MODEL_SERVICE_ID@@|$model_service_id|g" \
    -e "s|@@MODEL_ENDPOINT@@|$model_endpoint|g" \
    -e "s|@@NODE_RPC@@|$node_rpc|g" \
    -e "s|@@NODE_REST@@|$node_rest|g" \
    -e "s|@@KEEPER_API@@|$keeper_api|g" \
    -e "s|@@NEXUS_INGRESS@@|$nexus_ingress|g" \
    -e "s|@@NEXUS_NATS@@|$nexus_nats|g" \
    -e "s|@@NEXUS_JETSTREAM_STREAM@@|$nexus_jetstream_stream|g" \
    -e "s|@@SIGNER_URI@@|$signer_uri|g" \
    -e "s|@@SERVICE_KEY_REF@@|$service_key_ref|g" \
    -e "s|@@NEXUS_BUILDER_OPERATOR@@|$nexus_builder_operator|g" \
    -e "s|@@RETENTION_POLICY_VERSION@@|$retention_policy_version|g" \
    -e "s|@@MODEL_TLS_PUBKEY_HASH@@|$model_tls_pubkey_hash|g" \
    -e "s|@@NEXUS_NATS_CA_FILE@@|$nexus_nats_ca_file|g" \
    -e "s|@@NEXUS_NATS_USER_KEY_FILE@@|$nexus_nats_user_key_file|g" \
    -e "s|@@MINIMUM_RETENTION_BLOCKS@@|$minimum_retention_blocks|g" \
    "$deploy_dir/cortex.yaml.template" >"$temp_config"
  mv "$temp_config" "$config_path"
  trap - EXIT HUP INT TERM
  echo "$config_path"
}

compose() {
  docker compose --file "$compose_file" "$@"
}

case "${1:-}" in
  render)
    render_config
    ;;
  up)
    render_config >/dev/null
    CORTEX_CONFIG_PATH=$config_path
    export CORTEX_CONFIG_PATH
    compose up --detach --build
    ;;
  diagnostics)
    compose exec -T cortex cortexctl --admin-socket /var/run/cortex/cortexd.sock diagnostics --format json
    ;;
  preflight)
    compose exec -T cortex cortexctl --admin-socket /var/run/cortex/cortexd.sock diagnostics --format json
    compose exec -T cortex wget -q -O - http://127.0.0.1:8081/readyz
    ;;
  down)
    compose down
    ;;
  *)
    echo "usage: $0 {render|up|diagnostics|preflight|down}" >&2
    exit 2
    ;;
esac
