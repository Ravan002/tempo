# tempo-xtask

Zones tooling is available through `cargo zone-xtask` (the `tempo-zone-xtask`
binary). See the [Zones command reference](src/zones/README.md).

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.

`generate-localnet` and `generate-genesis` accept `--extra-token-count 0..19`, in addition to
pathUSD. The default remains three extra tokens: AlphaUSD, BetaUSD, and ThetaUSD. Additional
tokens use reserved IDs 4..19, have USD currency, quote pathUSD, and fund the generated accounts.

E2E benchmarks accept `token-count=1..20` (`--token-count` in `nu bench-e2e.nu e2e`), defaulting
to four. For example, `derek bench preset=tip20 token-count=20 bloat=100` spreads the same total
100 GiB TIP-20 state bloat across twenty tokens; the nonce ring is additional. Selections of 1–4 tokens
retain the existing four-token bloat distribution and recipient range. Above four, increasing
token count reduces balances per token; cached snapshots are rebuilt when the bloat token count
changes. The four canonical genesis tokens remain available to static presets.
Scenarios with `fee-token=any_tip20` seed each selected non-pathUSD token's fee pool against
pathUSD during setup.
