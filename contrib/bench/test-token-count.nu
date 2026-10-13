#!/usr/bin/env nu
# Run with: nu -c "source contrib/bench/test-token-count.nu"
source ../../bench-e2e.nu
use std/assert

let spec = "contrib/bench/txgen/presets/tip20/nonce-expiring.yml"
for count in [1 4 20] {
    e2e-validate-token-count $count
    txgen-configure-tip20-token-env $count
    let tokens = ($env.TXGEN_TIP20_TOKENS | from json)
    assert equal ($tokens | length) $count
    assert equal ($tokens | last) (txgen-tip20-token-address ($count - 1))

    txgen-configure-fee-amm-env $spec $count
    let steps = ($env.TXGEN_FEE_AMM_SETUP_STEPS | from json)
    let fragment = (open --raw "contrib/bench/txgen/presets/tip20/fee-amm-liquidity.yml"
        | str replace '${TXGEN_FEE_AMM_SETUP_STEPS}' $env.TXGEN_FEE_AMM_SETUP_STEPS)
    let rendered = ($fragment | ^uv run --no-project --with yq==3.4.3 yq -c . | from json)
    assert equal $rendered.append.setup.steps $steps
    assert equal ($steps | length) ($count - 1)
    assert equal ($steps | get tx.call.args | each { |args| $args | first }) ($tokens | skip 1)
    for step in $steps {
        assert equal ($step.tx.call.args | get 1) (txgen-tip20-token-address 0)
        assert equal ($step.tx.call.args | get 2) 10000000000
    }
    let args = (build-base-args genesis.json data logs "127.0.0.1" 8545 9001 $count)
    assert equal ($args | where { |arg| $arg == "--faucet.address" } | length) $count

    # Increasing token count redistributes one total size, rather than multiplying it.
    let accounts = (txgen-bloat-accounts-per-token 1024 $count)
    let bytes = $count * (104 + 64 * $accounts)
    assert ($bytes <= 1024 * 1024 * 1024)
    assert ($bytes > 1024 * 1024 * 1024 - 64 * $count)
}

txgen-configure-fee-amm-env "contrib/bench/txgen/presets/tip20/nonce-2d.yml" 20
assert equal (($env.TXGEN_FEE_AMM_SETUP_STEPS | from json | first).tx.call.args | get 2) 10000000000000
txgen-configure-keychain-env 1000 20
assert equal ($env.TXGEN_KEYCHAIN_TIP20_LIMITS | from json | length) 20
assert (($env.TXGEN_KEYCHAIN_AUTHORIZE_SETUP_GAS_LIMIT | into int) >= ($env.TXGEN_KEY_AUTHORIZATION_GAS_LIMIT | into int))

for count in [0 21] {
    let result = (^nu -c $"source bench-e2e.nu; e2e-validate-token-count ($count)" | complete)
    assert equal $result.exit_code 1
}

let legacy = {bloat_version: 1, bloat_mib: 1024, nonce_ring_hardfork: T13}
assert (bloat-matches $legacy 1024 T13 4)
assert (not (bloat-matches $legacy 1024 T13 20))
let twenty = ($legacy | insert bloat_token_count 20)
assert (bloat-matches $twenty 1024 T13 20)
assert (not (bloat-matches $twenty 1024 T13 4))
assert (not (bloat-matches $twenty 1000 T13 20))
assert (not (bloat-matches $twenty 1024 T14 20))
print "Token selection, liquidity, faucet, fixed total bloat, and snapshot compatibility checks passed"
