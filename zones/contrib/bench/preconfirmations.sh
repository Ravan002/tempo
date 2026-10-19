#!/usr/bin/env bash

# Benchmark sequencer preconfirmations against today's transfer path on a real local deployment:
# one Tempo dev L1 node and a three-sequencer Zone (a leader and two followers connected over
# P2P), each a separate release process.
#
# Build the binaries first:
#
#   cargo build --release --bin tempo --bin tempo-zone --bin tempo-zone-xtask
#   (cd crates/zones/contracts && forge build --skip test)
#
# Then run `zones/contrib/bench/preconfirmations.sh [RESULTS_DIR]`. The results table is printed
# and written to RESULTS_DIR/preconfirmations.json. Set KEEP=1 to leave the nodes running.

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
readonly BIN_DIR="${BIN_DIR:-$REPO_ROOT/target/release}"
readonly TEMPO_BIN="${TEMPO_BIN:-$BIN_DIR/tempo}"
readonly ZONE_BIN="${ZONE_BIN:-$BIN_DIR/tempo-zone}"
readonly ZONES_XTASK_BIN="${ZONES_XTASK_BIN:-$BIN_DIR/tempo-zone-xtask}"
readonly RESULTS_DIR="$(mkdir -p "${1:-.}" && cd "${1:-.}" && pwd)"
readonly WORK_DIR="${WORK_DIR:-$(mktemp -d -t tempo-preconfirmations-XXXXXX)}"

# Zone blocks follow L1 blocks, so the L1 block time is the Zone block time.
readonly L1_BLOCK_TIME="${L1_BLOCK_TIME:-250ms}"
# Large enough that neither path is limited by block gas.
readonly ZONE_GAS_LIMIT="${ZONE_GAS_LIMIT:-2000000000}"
readonly TRANSFERS="${TRANSFERS:-2000}"
readonly CONCURRENCY="${CONCURRENCY:-1,16,64,256}"

readonly ZONE_FACTORY="0x5aF2000000000000000000000000000000000000"
readonly PATH_USD="0x20C0000000000000000000000000000000000000"
# Account #0 of the `test ... junk` mnemonic: funded in the dev genesis, owns the factory, and funds
# the benchmark senders.
readonly DEV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Accounts #1-#3: the three sequencers. The first is the leader and holds the deposit encryption key.
readonly SEQUENCER_KEYS=(
    0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
    0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
    0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
)
readonly L1_HTTP="http://127.0.0.1:8545"
readonly L1_WS="ws://127.0.0.1:8546"

pids=()

die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    if [[ "${KEEP:-0}" == 1 ]]; then
        echo "nodes left running (PIDs ${pids[*]}); data in $WORK_DIR"
        return
    fi
    for pid in "${pids[@]}"; do kill -INT "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT

rpc() {
    curl --silent --fail --header 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" "$1" |
        jq -er '.result'
}

wait_for_block() {
    local url="$1" block="$2" deadline=$((SECONDS + 120))
    until (( $(printf '%d' "$(rpc "$url" eth_blockNumber 2>/dev/null || echo 0)") >= block )); do
        (( SECONDS < deadline )) || die "$url did not reach block $block"
        sleep 0.5
    done
}

start() {
    local name="$1"
    shift
    "$@" >"$WORK_DIR/$name.log" 2>&1 &
    pids+=("$!")
    echo "started $name (PID $!), log $WORK_DIR/$name.log"
}

for bin in "$TEMPO_BIN" "$ZONE_BIN" "$ZONES_XTASK_BIN"; do
    [[ -x "$bin" ]] || die "missing executable $bin"
done
for command in cast curl jq; do
    command -v "$command" >/dev/null || die "missing command $command"
done

echo "installing the ZoneFactory into the dev genesis"
"$ZONES_XTASK_BIN" install-reference-zone-factory \
    --genesis "$REPO_ROOT/crates/chainspec/src/genesis/dev.json" \
    --output "$WORK_DIR/l1-genesis.json" \
    --owner "$(cast wallet address "$DEV_KEY")" \
    --specs-out "$REPO_ROOT/crates/zones/contracts/out"

start l1 "$TEMPO_BIN" node --dev --dev.block-time "$L1_BLOCK_TIME" --dev.finality-depth 1 \
    --chain "$WORK_DIR/l1-genesis.json" --datadir "$WORK_DIR/l1" \
    --http --http.addr 127.0.0.1 --http.port 8545 --http.api all \
    --ws --ws.addr 127.0.0.1 --ws.port 8546 --ws.api all \
    --rpc.eth-proof-window 100000 \
    --port 30303 --disable-discovery --authrpc.port 8551 --ipcdisable
wait_for_block "$L1_HTTP" 1

sequencers=()
for key in "${SEQUENCER_KEYS[@]}"; do
    address="$(cast wallet address "$key")"
    sequencers+=("$address")
    # Each sequencer submits settlement attestations from its own key.
    cast send --quiet --rpc-url "$L1_HTTP" --private-key "$DEV_KEY" \
        "$PATH_USD" 'transfer(address,uint256)' "$address" 1000000000000 >/dev/null
done

echo "creating a Zone with sequencers ${sequencers[*]}"
ZONE_FACTORY_OWNER_KEY="$DEV_KEY" "$ZONES_XTASK_BIN" create-zone \
    --output "$WORK_DIR/zone" --l1-rpc-url "$L1_HTTP" --zone-factory "$ZONE_FACTORY" \
    --initial-token "$PATH_USD" --admin "$(cast wallet address "$DEV_KEY")" \
    --sequencer "${sequencers[0]}" --sequencer "${sequencers[1]}" --sequencer "${sequencers[2]}" \
    --threshold 2 --gas-limit "$ZONE_GAS_LIMIT"
portal="$(jq -er .portal "$WORK_DIR/zone/zone.json")"
zone_id="$(jq -er .zoneId "$WORK_DIR/zone/zone.json")"
L1_RPC_URL="$L1_HTTP" L1_PORTAL_ADDRESS="$portal" PRIVATE_KEY="${SEQUENCER_KEYS[0]}" \
    "$ZONES_XTASK_BIN" set-encryption-key

p2p_keys=()
for index in 0 1 2; do
    mkdir -p "$WORK_DIR/node-$index"
    printf '%s\n' "${SEQUENCER_KEYS[index]}" >"$WORK_DIR/node-$index/sequencer.key"
    printf '%s\n' "${SEQUENCER_KEYS[0]}" >"$WORK_DIR/node-$index/decryption.keys"
    p2p_keys+=("$("$ZONES_XTASK_BIN" generate-p2p-key --out "$WORK_DIR/node-$index/p2p.key")")
done
manifest="$WORK_DIR/manifest.toml"
{
    printf 'zone_id = %s\nsequencer_set_version = 0\nleader_ed25519_public_key = "%s"\n' \
        "$zone_id" "${p2p_keys[0]}"
    for index in 0 1 2; do
        printf '\n[[nodes]]\nname = "node-%s"\ned25519_public_key = "%s"\nsecp256k1_address = "%s"\naddress = "127.0.0.1:%s"\n' \
            "$index" "${p2p_keys[index]}" "${sequencers[index]}" "$((9200 + index))"
    done
} >"$manifest"

for index in 0 1 2; do
    node="$WORK_DIR/node-$index"
    decryption_args=()
    # The leader's sequencer key is the deposit encryption key; followers need it to decrypt
    # deposits when they replay the leader's blocks or take over.
    (( index == 0 )) || decryption_args=(--deposit-decryption-keys-file "$node/decryption.keys")
    start "zone-$index" "$ZONE_BIN" node \
        --chain "$WORK_DIR/zone/genesis.json" --datadir "$node/data" \
        --l1.rpc-url "$L1_WS" --l1.portal-address "$portal" \
        --http --http.addr 127.0.0.1 --http.port "$((9545 + 10 * index))" --http.api all \
        --redacted-rpc.port "$((9544 + 10 * index))" \
        --port "$((30310 + index))" --disable-discovery --authrpc.port "$((8560 + index))" \
        --ipcdisable --builder.gaslimit "$ZONE_GAS_LIMIT" \
        --engine.disable-sparse-trie-cache-pruning \
        --sequencer-key-file "$node/sequencer.key" --secp256k1.key "$node/sequencer.key" \
        "${decryption_args[@]}" \
        --sequencer.manifest "$manifest" --p2p.key "$node/p2p.key" \
        --p2p.listen "127.0.0.1:$((9200 + index))"
done
for index in 0 1 2; do
    wait_for_block "http://127.0.0.1:$((9545 + 10 * index))" 3
done

echo "depositing pathUSD for the benchmark senders"
cast send --quiet --rpc-url "$L1_HTTP" --private-key "$DEV_KEY" \
    "$PATH_USD" 'approve(address,uint256)' "$portal" "$(cast max-uint)" >/dev/null
"$ZONES_XTASK_BIN" deposit --l1-rpc-url "$L1_HTTP" --portal "$portal" --private-key "$DEV_KEY" \
    --amount "$(( (TRANSFERS + 100) * 2000000 ))" --zone-rpc-url "http://127.0.0.1:9545"

"$ZONES_XTASK_BIN" bench-preconfirmations \
    --zone-rpc-url "http://127.0.0.1:9545" --redacted-rpc-url "http://127.0.0.1:9544" \
    --follower-rpc-url "http://127.0.0.1:9555" --follower-rpc-url "http://127.0.0.1:9565" \
    --private-key "$DEV_KEY" --transfers "$TRANSFERS" --concurrency "$CONCURRENCY" \
    --output "$RESULTS_DIR/preconfirmations.json"
