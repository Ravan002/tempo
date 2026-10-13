#!/usr/bin/env bash
# Runs a local devnet whose validators grant one operator privileged
# top-of-block access.
#
#   scripts/tob-devnet.sh nodes      # generate (once) and run the validators
#   scripts/tob-devnet.sh operator   # run the operator and its dashboard
#
# Build first: cargo build -p tempo --bin tempo --bin tempo-tob-operator && cargo build -p tempo-xtask
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${TOB_DEVNET_DIR:-$ROOT/.tob-devnet}"
BIN="${TOB_DEVNET_BIN:-$ROOT/target/debug}"
VALIDATORS="${VALIDATORS:-5}"
OPERATOR_SEED="${OPERATOR_SEED:-7}"
WINDOW_MS="${WINDOW_MS:-100}"
SECRET="tempo-localnet-signing-key-secret"

validator_dirs() {
  for i in $(seq 0 $((VALIDATORS - 1))); do
    echo "$DIR/127.0.0.$((i + 1)):$((8000 + i * 100))"
  done
}

generate() {
  [[ -f "$DIR/genesis.json" ]] && return
  local validators
  validators=$(for i in $(seq 0 $((VALIDATORS - 1))); do printf '127.0.0.%d:%d,' $((i + 1)) $((8000 + i * 100)); done)
  "$BIN/tempo-xtask" generate-localnet -o "$DIR" --force --seed 0 \
    --accounts 300 --epoch-length 302400 --validators "${validators%,}" >/dev/null
  printf '%s\n' "$SECRET" >"$DIR/consensus.secret"
  chmod 600 "$DIR/consensus.secret"
  cat >"$DIR/top-of-block.json" <<EOF
{
  "window_ms": $WINDOW_MS,
  "operators": [{
    "public_key": "$("$BIN/tempo-tob-operator" --seed "$OPERATOR_SEED" --print-public-key)",
    "address": "127.0.0.1:9900",
    "max_txs_per_block": 1000,
    "max_gas_per_block": 100000000
  }]
}
EOF
}

nodes() {
  generate
  local trusted_peers=""
  for dir in $(validator_dirs); do
    local addr="${dir##*/}"
    local ip="${addr%%:*}" port="${addr##*:}"
    trusted_peers+="enode://$(cat "$dir/enode.identity")@$ip:$((port + 1)),"
  done
  trusted_peers="${trusted_peers%,}"

  trap 'kill $(jobs -p) 2>/dev/null; wait' EXIT
  for dir in $(validator_dirs); do
    local addr="${dir##*/}"
    local ip="${addr%%:*}" port="${addr##*:}"
    local index=$(((port - 8000) / 100))
    mkdir -p "$DIR/logs"
    RUST_LOG="${RUST_LOG:-info}" "$BIN/tempo" node \
      --chain "$DIR/genesis.json" \
      --datadir "$dir" \
      --http --http.addr 0.0.0.0 --http.port $((8545 + index)) --http.api all \
      --ws --ws.addr 0.0.0.0 --ws.port $((8645 + index)) \
      --metrics "127.0.0.1:$((9001 + index))" \
      --ipcdisable \
      --consensus.signing-key "$dir/signing.key" \
      --consensus.secret "$DIR/consensus.secret" \
      --consensus.signing-share "$dir/signing.share" \
      --consensus.listen-address "$ip:$port" \
      --consensus.metrics-address "127.0.0.1:$((port + 2))" \
      --consensus.use-local-defaults \
      --consensus.bypass-ip-check \
      --consensus.top-of-block-operators "$DIR/top-of-block.json" \
      --trusted-peers "$trusted_peers" \
      --port $((port + 1)) --discovery.port $((port + 1)) --discovery.v5.port $((port + 4)) \
      --p2p-secret-key "$dir/enode.key" \
      --authrpc.port $((port + 3)) \
      >"$DIR/logs/validator-$index.log" 2>&1 &
    echo "validator $index: rpc http://127.0.0.1:$((8545 + index)), log $DIR/logs/validator-$index.log"
  done
  wait -n
  echo "a validator exited; see $DIR/logs" >&2
  exit 1
}

operator() {
  local args=()
  for dir in $(validator_dirs); do
    local addr="${dir##*/}"
    local ip="${addr%%:*}" port="${addr##*:}"
    local index=$(((port - 8000) / 100))
    local rpc="http://127.0.0.1:$((8545 + index))" key=""
    until key=$(curl -sf -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"admin_validatorKey","params":[]}' "$rpc" | jq -er .result); do
      echo "waiting for $rpc" >&2
      sleep 2
    done
    args+=(--validator "$key@$ip:$port" --rpc "$rpc")
  done
  exec "$BIN/tempo-tob-operator" --seed "$OPERATOR_SEED" "${args[@]}" "$@"
}

case "${1:-}" in
  nodes) nodes ;;
  operator) shift; operator "$@" ;;
  *) echo "usage: $0 nodes|operator" >&2; exit 2 ;;
esac
