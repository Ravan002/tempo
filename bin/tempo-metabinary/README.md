# Tempo metabinary

`tempo node` remains the entrypoint, with its existing arguments and defaults. The live node
runs in-process. An execution-independent library decorates its registered RPC callbacks and
starts frozen read-only workers lazily for historical execution.

![Tempo metabinary routing: native transports enter the live node. Historical execution uses frozen read-only era workers over shared chain storage.](assets/execution-routing.svg)

## Release configuration

The release supplies `tempo-eras.json` beside the executable. Each catalog entry binds a chain ID
to its ordered frozen eras:

```json
{"chains":[{
  "chain_id":"0x1079",
  "eras":[
    {"until":"T11","binary":"eras/tempo-t10",
     "checkpoint":{"number":1000000,"hash":"0x2222222222222222222222222222222222222222222222222222222222222222"}}
  ]
}]}
```

A frozen era executes blocks before its `until` hardfork. Its boundary is that fork's activation
timestamp in `tempo-hardfork`'s constants, so only mainnet and moderato can have frozen eras, and
`until` must be an already scheduled fork. Executables resolve relative to the catalog, and blocks
after the last frozen era run in the live node. A frozen era's optional `checkpoint` pins its last
canonical block. Network sync handoff requires it. The built-in development catalog
(`bin/tempo/eras.json`) is empty. Unmatched chains, custom genesis, and custom fork schedules use
the native path.

Workers inherit the selected genesis, datadir, custom static-file/RocksDB paths, and resolved SDK
`EthConfig` through private temporary files. Gas, simulation, memory, and tracing settings retain
the node's configured values. Execution concurrency budgets apply per process, while public
transport limits remain global. Historical workers are selected by requests, regardless of
`--full` or pruning. Missing historical state fails through the worker's ordinary storage behavior.

## Routing

- Stored blocks, receipts, logs, proofs, state queries, and live transaction operations stay native.
- Execution requests read native headers and transaction metadata to choose an era by timestamp.
  Historical forwarding pins tags other than `pending`, and preserves explicit hashes and
  `requireCanonical`. Pool and missing transactions stay native. Positional and named parameters
  are supported. Simulations select their generated child blocks' eras, including gap fillers. The
  base state may belong to an older era.
- Requests crossing eras return `-32004`, including trace filters, multi-block simulations, call
  bundles, and timestamp overrides. Split ranges rather than transferring speculative state
  between processes. Unreviewed execution methods fail closed until their selectors are supported.
- Native transports retain their registries, authentication, CORS, compression, subscriptions,
  batching, and limits. Metadata resolution works even when eth is disabled publicly.
  Live debug trace subscriptions stay native, and historical debug trace subscriptions are rejected.
- Raw-block tracing decodes only the Tempo header to select its execution era. The selected
  executor validates the body with its own transaction codec.
  Bad-block tracing and `ots_getContractCreator` remain unsupported with era routing:
  bad-block cache resolution and whole-history deployment searches are not implemented.

Workers are coalesced per era and verified by protocol, chain, genesis, read-only mode, and PID.
The PID check detects accidental port collisions. Local processes are trusted.
Workers shut down after five idle minutes, checked every 30 seconds, and restart on demand.
Active private RPC calls retain their worker. Cancelling a caller drops its forwarding future.
Shutdown reaps owned children. A failed or missing worker affects only historical requests for its
era, and live RPC stays available.

Cancelled startup keeps its child so the next request can resume the handshake. Startup failures
and detected child exits are retried on demand after a 30-second cooldown. Failed workers receive
graceful shutdown before forced termination, and their RocksDB secondary directories are removed
after reaping, including after crashes.

## Canonical-file bootstrap

`tempo-metabinary` sequentially imports finite canonical block files through frozen eras. Run the
ordinary `tempo node` entrypoint afterward for public RPC and live execution.

```sh
cargo build --release -p tempo -p tempo-metabinary --bin tempo --bin tempo-metabinary

tempo-metabinary --manifest /path/to/eras-manifest.json bootstrap
```

Copy the [example manifest](examples/eras-manifest.json) and replace its illustrative identity,
`until` forks, executable paths, and checkpoints. Binary, datadir, and explicit chain-spec paths are
manifest-relative. Paths inside import arguments should be absolute. Import commands share storage
and run one at a time. Checkpoint inspection uses the same private read-only worker manager as the
ordinary node, with an automatically selected loopback port. Partial startup failures clean up
owned children.

Each manifest entry pairs a frozen era, with a required trusted `checkpoint`, and the `args` of an
ordinary `import` command. Its file ends immediately before the `until` fork's activation. The wrapper forces
`--fail-on-invalid-block`, waits for import, opens a reader, and verifies the canonical checkpoint,
era timestamp, and exact head. Subsequent imports verify the predecessor and first successor.
No pipeline checkpoints or handoff markers are rewritten. An import failure may leave partial
progress, which the ordinary Tempo recovery workflow handles.

## Network sync handoff

Genesis network sync remains native unless the release catalog supplies a `checkpoint` for its one
frozen era. A checkpointed schedule with more frozen eras fails startup. Handoff is skipped for
`--dev`, `--debug.tip`, `--debug.max-block`, `--debug.terminate`, `--debug.rpc-consensus-url`, and
`--etherscan`, and when durable storage already reaches the checkpoint.

Otherwise `tempo node` runs the frozen writer with the operator's arguments, minus `--follow*` and
`TEMPO_FOLLOW`, plus `--history-sync --debug.tip=<hash> --debug.max-block=<number>
--debug.terminate`. It then verifies the durable checkpoint and reaps the writer before launching
live execution. Interrupted sync resumes from Reth's saved progress.

Before starting consensus, the live node verifies a recent finalization through the configured
follow upstream or the chain's default consensus RPC, syncs execution to that certified tip, and
verifies its epoch boundary header from the authenticated chain. No boundary certificate is required.
It persists the certified floor in the consensus archives. Cached executed blocks survive an
interrupted handoff and can be replayed without an upstream. Finality is persisted only through
the durable execution prefix. Historical validator-config reads use storage without constructing
an EVM.

## Re-execution

With a release schedule, `tempo re-execute` splits its range at the first local block of each
`until` fork, found by searching local header timestamps. Each frozen part runs as `<frozen binary> re-execute` with the operator's arguments and
only `--from`/`--to` replaced, one era at a time in block order. The live binary then re-executes
the remainder. It does not run if nothing remains or a shutdown signal stopped a frozen child.

- Genesis is skipped, `--to` is clamped to the local head, and ranges exclude `--to`.
- `TEMPO_RE_EXECUTE_ERA` marks frozen children so they never delegate again.

## Frozen artifact requirements

Frozen artifacts need this `rpc-only` discovery protocol and hidden `--rpc-config` interface,
backported where necessary, plus a recorded revision and checksum. A network sync writer must also
support `--history-sync`, which bounds execution, consensus payloads, and fork choice to its era.
`--debug.max-block` alone does not supply that contract. Artifacts must support their era and
shared storage layout, since identity discovery does not establish execution compatibility.
