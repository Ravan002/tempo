#!/usr/bin/env nu
# Run with: nu -c "source contrib/bench/test-token-count.nu"
source ../../bench-e2e.nu
use std/assert

let legacy = {bloat_version: 1, bloat_mib: 1024, nonce_ring_hardfork: T13}
for count in [1 2 3 4 5 20] {
    e2e-validate-token-count $count
    let bloat_count = (e2e-bloat-token-count $count)
    assert equal $bloat_count (if $count <= 4 { 4 } else { $count })
    assert equal (bloat-matches $legacy 1024 T13 $bloat_count) ($count <= 4)
    let marker = ($legacy | insert bloat_token_count $bloat_count)
    assert (bloat-matches $marker 1024 T13 $bloat_count)
    assert equal (bloat-matches $marker 1024 T13 4) ($count <= 4)
}

for spec in [nonce-expiring nonce-2d] {
    txgen-configure-fee-amm-env $"contrib/bench/txgen/presets/tip20/($spec).yml" 20
    let fragment = (open --raw "contrib/bench/txgen/presets/tip20/fee-amm-liquidity.yml"
        | str replace '${TXGEN_FEE_AMM_SETUP_STEPS}' $env.TXGEN_FEE_AMM_SETUP_STEPS)
    let steps = ($fragment | ^uv run --no-project --with yq==3.4.3 yq -c . | from json | get append.setup.steps)
    assert equal ($steps | length) 19
    assert equal ($steps | get tx.call.args | each { |args| $args | first }) (1..<20 | each { |id| txgen-tip20-token-address $id })
    assert equal ($steps | first | get tx.call.args.2) (if $spec == nonce-2d { 10000000000000 } else { 10000000000 })
}
txgen-configure-keychain-env 1000 20
assert (($env.TXGEN_KEYCHAIN_AUTHORIZE_SETUP_GAS_LIMIT | into int) >= ($env.TXGEN_KEY_AUTHORIZATION_GAS_LIMIT | into int))

for count in [0 21] {
    let result = (^nu -c $"source bench-e2e.nu; e2e-validate-token-count ($count)" | complete)
    assert equal $result.exit_code 1
}
print "Token count, snapshot compatibility, liquidity, and keychain gas checks passed"
