# Light-client performance measurements

The historical devnet runs below are **debug-build, loopback smoke measurements**, not production
budgets or a complete performance evaluation. Their reproducible harness is
`scripts/light-client-devnet.py`; see [operation and trust documentation](light-client.md).
The [fresh-proof release experiment](#fresh-proof-release-experiment) measures generated proof
workloads and simulated RPC delay separately. Sustained load, upstream proof-generation CPU/IO,
memory/WAN bandwidth, multi-token scaling and a fair unverified-read baseline remain unqualified.

## Recorded run

- Hardware: Apple M4 Max, 14 logical CPUs, 36 GiB RAM.
- OS: macOS 26.7 arm64; Rust 1.96.0; default Cargo development build.
- Four real local validator processes, loopback HTTP; no network latency/TLS simulation.
- Requested block cadence: 200 ms; epoch length: 100 blocks. This is a target, not measured
  sustained cadence. RPC nodes allow a recent 128-block proof window.
- Daemon polls every 100 ms; default read deadline/concurrency and cache limits.
- The host also ran Cargo checks; CPU/memory were not isolated.

| Measurement | Observed |
| --- | ---: |
| Fresh daemon start to authenticated durable head (validators already running) | 319 ms |
| Restart/catch-up across one offline full-DKG signing-key rotation | 342 ms |
| Four-read batch latency, p50 (100 sequential samples) | 0.310 ms |
| Four-read batch latency, p95 | 0.471 ms |
| Four-read batch latency, maximum | 4.417 ms |

The sampled batch contained two balances, one allowance and total supply for one token. Samples
were predominantly same-head cache hits with a small number of proof refetches as heads changed;
these are not cold-read latency distributions or concurrent throughput measurements.

Across the exercised smoke scenarios, the first-provider proxy observed 76 compact header
responses (174,666 serialized JSON bytes) and 11 multiproof responses (71,135 bytes). These totals
include transaction checks, catch-up and adversarial proof attempts; they exclude the direct
second provider and HTTP framing, and are **not** steady-state bandwidth estimates. Final status
reported three account-root entries, five raw-slot entries and two rejected proof batches.

Mint, transfer, approve and burn reads matched full-node calls pinned to the exact reported block.
The signing identity changed in a real full DKG; disk-backed restart authenticated the new key.
The proxy changed genuine storage-proof scalar values: verification rejected them, a separate
provider supplied valid proofs, and removing that honest provider produced an explicit integrity
error rather than a forged/zero fallback. The light datadir contained only its lock and checkpoint.

The run's public header, transition and native storage evidence is retained in
`crates/light/fixtures/devnet-tip20-v1.json` and independently verified by the Rust conformance test.
It uses public development credentials and is not a production trust anchor. Every rerun emits its
own `report.json` and `conformance.json` in the chosen fresh workdir.

## Historical account-only scheduling follow-up

These runs used the former speculative account-only scheduler, which has since been removed.
The current light client requests full proofs for missing slots directly.
The timings below do not qualify that policy or active-payment workloads.

The expanded real-validator harness also passed with account-only cache scheduling enabled. It
forced a new global state root by transferring another token, authenticated AlphaUSD's unchanged
storage root, and reused its raw slots. Both real proxies then rejected account-only requests;
full hash-pinned proofs still produced verified reads. A genuine held proof returned its original
block/zero balance while a concurrent real mint advanced the head; the subsequent read returned
999 at the changed root. A corrupted remaining-slot proof in a mixed cached/new-slot batch produced
an integrity error without publishing the new account mapping or a partial result.

On the same host/debug/loopback setup, this expanded run observed 228 ms startup, 418 ms restart,
and four-read predominantly warm p50/p95/max of 0.265/0.335/7.708 ms (100 sequential samples).
The first proxy observed 11 account-only requests, including one deliberately rejected request;
the second proxy also rejected that optimization request. The harness uses a 10-second upstream
request timeout for its deliberate hold test and a shared 15-second read deadline. The scenarios
and request totals differ from the baseline above, so these figures are not a controlled speedup
or bandwidth comparison. Representative active-token/root-change workloads still require
measurement.

## Shared state-proof implementation smoke run

Before removing speculative scheduling, after migrating to `tempo-state-proof`, the same expanded four-validator debug/loopback harness
passed again: mint/transfer/approve/burn comparisons, unrelated-token root reuse, rejected optional
probes, slow snapshot retention, failed mixed-batch atomicity, full DKG rotation/restart, and corrupt
proof failover. Artifacts for this local run are `/tmp/tempo-state-proof-devnet.UPJKXf`.

| Measurement | Observed |
| --- | ---: |
| Startup to authenticated durable head | 238 ms |
| Restart/catch-up across rotation | 211 ms |
| Four-read predominantly warm p50 / p95 / maximum (100 samples) | 0.268 / 0.454 / 8.499 ms |
| First-proxy account-only requests / deliberately rejected | 11 / 1 |

The first proxy observed 96 compact-header responses (220,267 JSON bytes) and 27 multiproof
responses (112,578 bytes), including adversarial scenarios. Final cache counts were three account
mappings and nine word/root versions. These are scenario totals, not steady-state bandwidth or a
controlled old/new comparison. In particular, p95 differs from the preceding run; small loopback
samples with changing heads and no load isolation do not establish a regression tolerance or
production parity.

## Direct-only scheduling smoke run

After removing speculative account-only scheduling, the updated
four-validator debug/loopback harness passed exact-block mint/transfer/approve/burn comparisons,
fresh full proofs after unrelated-token mutations, retained slow snapshots, failed mixed-batch
atomicity, DKG rotation/restart and malicious-proof failover. Both proxies observed **zero
account-only requests**. Artifacts: `/tmp/tempo-direct-proofs-devnet.Pr6rBw`. A temporary launcher
disabled validator IPC to avoid collisions on the shared default socket; light startup was unchanged.

Startup/restart were 425/328 ms; 100 predominantly warm four-read batches had p50/p95/max
0.291/0.418/4.885 ms. The first proxy observed 14 multiproof responses (86,390 JSON bytes), including
adversarial attempts. These scenario totals and warm timings are not a controlled comparison with
the historical runs or qualification of sustained active-token workloads.

No numerical production resource/performance guarantees are inferred from these results.
Current resource ceilings remain provisional safety limits pending representative measurements.

## Fresh-proof release experiment

This experiment assesses whether local proof-node reuse is worth implementing with existing RPCs.
It does **not** implement an optimized verifier or persistent node cache. The opt-in harness is
`crates/light/tests/performance.rs`; no production code, public API or generated fixture changed.

```sh
TEMPO_LIGHT_BENCH_SAMPLES=100 cargo test --release -p tempo-light \
  --features rpc-server --test performance --locked --offline -- --ignored --nocapture
```

The default is 30 measured samples per case; the environment variable accepts 10–200. Three
warm-up bursts per case are excluded. The test is ignored in ordinary test runs and refuses to
measure an unoptimized build.

### Method and limitations

Recorded on 2026-10-07: Apple M4 Max, 14 logical CPUs, 36 GiB RAM, macOS 26.7.1, Rust 1.96.0,
workspace release profile (`opt-level=3`, thin LTO). The machine was not CPU-isolated; background
system/app activity contributed to socket/scheduler noise. No other Cargo work ran during the two
primary measured runs. Local raw logs are `/tmp/tempo-light-proof-benchmark/run-4.log` and
`run-5.log`; earlier runs were exploratory. A final 10-sample run passed after simplifying the
harness's derived slot representation.

- Generated, valid secure MPT proofs for one token with 100,000 nonzero holder balances; account
  proofs traverse a state trie containing the token and 4,096 background accounts.
- A deterministic test DKG signs every snapshot. These are modeled states, not executed validator
  blocks. Equal balance debits/credits change 25% of 1,024 tracked holders plus 200 unrelated holders
  at each snapshot. The one-slot case reads a changing holder; larger batches include unchanged
  holders. Both token storage root and global state root must change between successive snapshots.
- The real `Client::read` runs with default limits over a local JSON-RPC provider. Its response delay
  is 0, 20 or 80 ms. These delays model RPC waiting time, **not** WAN packet propagation or transfer
  bandwidth. Provider and client share a four-worker Tokio runtime; verification uses the client's
  real blocking workers.
- Cases contain 1, 32 or 128 balances per read, with one or eight simultaneous disjoint portfolios.
  Each burst selects a new authenticated root. Assertions require one proof RPC per read, the exact
  selected block hash and every expected balance. Each primary run contains 8,100 measured reads
  and 8,100 proof RPCs: neither warm hits nor coalescing can hide fresh verification work.
- Proofs are generated before timing. Provider response selection/serialization, HTTP transport,
  client parsing, scheduling, verification, local decoding and cache publication are included in
  client read latency. Head authentication/checkpoint persistence, provider database/proof generation,
  TLS, compression, packet loss and memory profiling are excluded. Burst reads/second in raw output
  excludes between-burst work and is **not sustained production throughput**.
- Isolated parsing measurements approximate the current JSON-DOM-then-typed-result path, omitting
  envelope validation. Verification and publication call the existing shared APIs. Isolated timings
  are not additive concurrent-client stage measurements.

### Components

Ranges are the p50 values across the two primary runs, rounded. Node counts include account proofs;
new nodes are byte-distinct from the preceding snapshot's same requested proof set.

| Balances | JSON response bytes | Node occurrences / unique / new | DOM + typed parsing | Verification | Publication |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 8,289 | 11 / 11 / 11 | 0.003 ms | 0.0074 ms | 0.0010–0.0014 ms |
| 32 | 146,526 | 195 / 146 / 71 | 0.042 ms | 0.128–0.129 ms | 0.0036–0.0050 ms |
| 128 | 573,918 | 761 / 492 / 214 | 0.160–0.161 ms | 0.502–0.503 ms | 0.0109–0.0115 ms |

Verification p95 was 0.509–0.517 ms for 128 balances.

### End-to-end fresh reads

Each cell is **p50 / p95 in milliseconds**, with ranges across both runs. Eight-way concurrency
uses disjoint requests, not eight callers sharing one proof job. The variation, especially in
zero-delay/concurrent cases, is a reason not to infer precise throughput or tail-latency guarantees.

| Balances/read | Injected RPC delay | One caller | Eight concurrent callers |
| --- | ---: | ---: | ---: |
| 1 | 0 ms | 0.35–0.41 / 0.54–0.58 | 0.59–0.65 / 1.36–1.39 |
| 32 | 0 ms | 1.33–1.72 / 1.85–2.31 | 1.03–2.41 / 3.24–3.69 |
| 128 | 0 ms | 2.13 / 3.56–4.17 | 3.03–3.18 / 3.72–4.26 |
| 1 | 20 ms | 22.54–22.59 / 22.88–23.13 | 22.53–22.91 / 22.93–24.84 |
| 32 | 20 ms | 23.77–24.41 / 24.45–26.14 | 25.12–26.13 / 26.33–28.56 |
| 128 | 20 ms | 26.69–27.41 / 28.12–28.89 | 27.39–30.75 / 30.05–33.95 |
| 1 | 80 ms | 82.54–82.66 / 83.04–83.14 | 82.72–83.11 / 83.72–84.89 |
| 32 | 80 ms | 82.98–83.59 / 84.00–84.96 | 83.59–85.77 / 85.80–88.50 |
| 128 | 80 ms | 87.32–88.68 / 88.61–90.86 | 86.66–95.14 / 91.46–99.71 |

### Node-reuse probes and decision

The harness also times hashing/decoding nodes without path verification. A simple byte-keyed
`HashSet` memo probe includes byte hashing, exact equality and insertion, skipping hash/decode work
on hits. The batch probe starts empty; the previous-snapshot probe starts with the preceding proof
set. This is a **work-elision microprobe**, not an authenticated cache or alternate verifier: it does
not retain decoded nodes, check proof paths, preserve target/error contracts or budget residency.
Previous-cache setup/eviction and decoded-node retention are excluded. More sophisticated indexing
could differ; these probes do not establish optimized read latency.

| Balances | Hash/decode every occurrence | Batch memo | Previous-snapshot memo |
| --- | ---: | ---: | ---: |
| 1 | 6.7 µs | 8.3 µs | 8.5 µs |
| 32 | 118–119 µs | 111–112 µs | 63–64 µs |
| 128 | 463–466 µs | 372–375 µs | 199–200 µs |

For 128 balances, processing unique nodes alone took 252–255 µs, but lookup/insertion overhead
reduced the batch memo's saving to about **0.09 ms**. The previous-snapshot probe saved about
**0.26–0.27 ms**, before real cache maintenance and verifier integration. For 32 balances that
saving was about **0.055 ms**; for a single changing balance the memo added overhead.

The previous-snapshot saving is roughly **1%** of the measured serial 128-balance read with 20 ms
injected delay, and **0.3%** with 80 ms delay. These are comparisons of CPU-work budgets, not measured
end-to-end speedups. Zero-delay large-portfolio reads have more potential: that same budget is about
12% of their median latency, and CPU-limited throughput/queuing could be more sensitive.

**Decision:** defer a persistent proof-node cache for ordinary remote-provider balance reads.
Consider shared-node verification if a deployment is co-located with a provider or demonstrably
verification-CPU-limited. Compact/cache-aware transport remains a more promising way to avoid
redundant downloads, but requires a separate end-to-end evaluation, including compression and
upstream proof-generation cost. Multi-token portfolios and lower-powered client CPUs remain
unmeasured; no production performance guarantee follows from this experiment.
