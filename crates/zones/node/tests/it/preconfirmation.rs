//! Sequencer preconfirmations for TIP-20 transfers.
//!
//! `zone_preconfirmTransaction` returns a sequencer-signed promise to include a transfer in a Zone
//! block numbered at most `includeBy`. These tests drive the redacted RPC over HTTP and check that
//! promises stack on each other, win over the pool, and are kept by the next block.

use std::time::{Duration, Instant};

use alloy_consensus::{BlockHeader as _, transaction::TxHashRef as _};
use alloy_eips::eip2718::Encodable2718 as _;
use alloy_network::ReceiptResponse as _;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address};
use alloy_provider::Provider as _;
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall as _;
use futures::{StreamExt as _, stream};
use serde_json::{Value, json};
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{Call, TempoTransaction},
};
use tokio_util::sync::CancellationToken;
use zone_payload::SignedPreconfirmation;
use zone_primitives::constants::MAX_UNPROCESSED_DEPOSITS;

use crate::utils::{
    DEFAULT_TIMEOUT, RedactedRpcTestCtx, TIP20_TX_GAS, start_zone_with_redacted_rpc,
};

/// Gas limit for a transfer from an account whose nonce is already in use.
const TRANSFER_GAS: u64 = 200_000;

/// pathUSD deposited to every sender.
const SENDER_BALANCE: u128 = 1_000_000;

/// Preconfirmations are only issued by a node that built the block it extends, and every promise
/// is kept by the next block.
#[tokio::test(flavor = "multi_thread")]
async fn preconfirmed_transfers_are_included_by_the_promised_block() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc(None).await?;
    let chain_id = ctx.config.chain_id;
    let senders: Vec<_> = (0..8).map(|_| PrivateKeySigner::random()).collect();
    let recipient = address!("0x00000000000000000000000000000000000ec1e1");

    // Nothing has been built yet, so this node cannot promise the next block.
    let (_, raw) = signed_transfer(&senders[0], chain_id, 0, recipient, 1)?;
    let response = ctx
        .call_as_user("zone_preconfirmTransaction", json!([raw]), &senders[0])
        .await?;
    assert_eq!(response["error"]["code"], -32005, "{response}");

    fund(&mut ctx, &senders).await?;
    ctx.fixture.seed_no_receive_policy(recipient)?;
    let head = ctx.zone.provider().get_block_number().await?;

    let mut promised = Vec::new();
    for (index, sender) in senders.iter().enumerate() {
        let (tx_hash, raw) = signed_transfer(sender, chain_id, 0, recipient, index as u64 + 1)?;
        let preconfirmation = preconfirm(&ctx, sender, &raw).await?;
        assert_eq!(preconfirmation.tx_hash, tx_hash);
        assert_eq!(preconfirmation.include_by, head + 1);
        assert_eq!(
            preconfirmation.recover_signer(chain_id)?,
            ctx.zone.sequencer()
        );
        promised.push(preconfirmation);
    }

    ctx.fixture.inject_empty_block(ctx.zone.deposit_queue());
    ctx.zone
        .wait_for_block_number(head + 1, DEFAULT_TIMEOUT)
        .await?;
    for preconfirmation in &promised {
        let receipt = ctx
            .zone
            .provider()
            .get_transaction_receipt(preconfirmation.tx_hash)
            .await?
            .ok_or_else(|| eyre::eyre!("missing receipt for {}", preconfirmation.tx_hash))?;
        assert!(receipt.status());
        assert_eq!(receipt.block_number(), Some(preconfirmation.include_by));
    }
    assert_eq!(
        ctx.zone.balance_of(PATH_USD_ADDRESS, recipient).await?,
        U256::from((1..=senders.len() as u64).sum::<u64>())
    );

    Ok(())
}

/// Each preconfirmation executes on top of the earlier ones, so conflicting or unaffordable
/// transfers are refused up front, and a pool transaction cannot take a promised nonce.
#[tokio::test(flavor = "multi_thread")]
async fn preconfirmations_stack_and_win_over_the_pool() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut ctx = start_zone_with_redacted_rpc(None).await?;
    let chain_id = ctx.config.chain_id;
    let sender = PrivateKeySigner::random();
    let [alice, bob, carol] = [
        address!("0x00000000000000000000000000000000000a11ce"),
        address!("0x0000000000000000000000000000000000000b0b"),
        address!("0x00000000000000000000000000000000000ca201"),
    ];
    fund(&mut ctx, core::slice::from_ref(&sender)).await?;
    for recipient in [alice, bob, carol] {
        ctx.fixture.seed_no_receive_policy(recipient)?;
    }

    // Concurrent copies of one transaction can land in one issuance batch or arrive after it is
    // queued; either way every copy gets the same promise.
    let (first, raw) = signed_transfer(&sender, chain_id, 0, alice, 100)?;
    let promises =
        futures::future::try_join_all((0..8).map(|_| preconfirm(&ctx, &sender, &raw))).await?;
    assert!(
        promises.iter().all(|promise| *promise == promises[0]),
        "resubmitting returns the same promise: {promises:?}"
    );
    // Nonce 1 is only valid on top of the pending nonce-0 transfer.
    let (second, raw) = signed_transfer(&sender, chain_id, 1, bob, 200)?;
    preconfirm(&ctx, &sender, &raw).await?;

    let (_, conflicting) = signed_transfer(&sender, chain_id, 1, carol, 300)?;
    let error = preconfirm_error(&ctx, &sender, &conflicting).await?;
    assert!(
        error.starts_with("transaction is invalid"),
        "a reused nonce must be refused: {error}"
    );
    let (_, overspend) = signed_transfer(&sender, chain_id, 2, carol, SENDER_BALANCE as u64)?;
    assert_eq!(
        preconfirm_error(&ctx, &sender, &overspend).await?,
        "transaction reverts"
    );
    let approve = signed_transaction(
        &sender,
        chain_id,
        2,
        TRANSFER_GAS,
        ITIP20::approveCall {
            spender: carol,
            amount: U256::ONE,
        }
        .abi_encode(),
    )?
    .1;
    assert_eq!(
        preconfirm_error(&ctx, &sender, &approve).await?,
        "only TIP-20 transfers can be preconfirmed"
    );
    let block_gas_limit = ctx
        .zone
        .provider()
        .get_block_by_number(Default::default())
        .await?
        .ok_or_else(|| eyre::eyre!("missing head block"))?
        .header
        .gas_limit();
    let oversized = signed_transaction(
        &sender,
        chain_id,
        2,
        block_gas_limit + 1,
        ITIP20::transferCall {
            to: carol,
            amount: U256::ONE,
        }
        .abi_encode(),
    )?
    .1;
    assert_eq!(
        preconfirm_error(&ctx, &sender, &oversized).await?,
        "preconfirmation capacity for the next block is exhausted"
    );

    // The pool accepts a nonce-2 transfer, but the preconfirmed nonce-2 transfer takes the slot.
    let (pool_tx, raw) = signed_transfer(&sender, chain_id, 2, carol, 400)?;
    let response = ctx
        .call_as_user("eth_sendRawTransaction", json!([raw]), &sender)
        .await?;
    assert_eq!(response["result"], json!(pool_tx), "{response}");
    let (third, raw) = signed_transfer(&sender, chain_id, 2, alice, 500)?;
    preconfirm(&ctx, &sender, &raw).await?;

    let head = ctx.zone.provider().get_block_number().await?;
    ctx.fixture.inject_empty_block(ctx.zone.deposit_queue());
    ctx.zone
        .wait_for_block_number(head + 1, DEFAULT_TIMEOUT)
        .await?;
    let provider = ctx.zone.provider();
    for tx_hash in [first, second, third] {
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await?
            .ok_or_else(|| eyre::eyre!("missing receipt for {tx_hash}"))?;
        assert!(receipt.status());
        assert_eq!(receipt.block_number(), Some(head + 1));
    }
    assert!(provider.get_transaction_receipt(pool_tx).await?.is_none());
    for (recipient, amount) in [(alice, 600u64), (bob, 200), (carol, 0)] {
        assert_eq!(
            ctx.zone.balance_of(PATH_USD_ADDRESS, recipient).await?,
            U256::from(amount)
        );
    }

    Ok(())
}

/// Compares how long a sender waits for a confirmed transfer today (`eth_sendRawTransactionSync`
/// returns once the transfer is in a block) with how long it waits for a signed preconfirmation.
///
/// Zone blocks are produced every `PRECONF_BENCH_BLOCK_MS` (default 250 ms, the Zone block time).
/// The block gas limit is raised so `PRECONF_BENCH_TRANSFERS` transfers (default 1000) fit in one
/// block and both paths measure latency rather than gas capacity.
///
/// Run with `cargo test --release -p zone-node --test it -- --ignored --nocapture
/// bench_preconfirmation_latency`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run explicitly with --ignored --nocapture"]
async fn bench_preconfirmation_latency() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let transfers = env_or("PRECONF_BENCH_TRANSFERS", 1000);
    let concurrency = env_or("PRECONF_BENCH_CONCURRENCY", 64);
    let block_interval = Duration::from_millis(env_or("PRECONF_BENCH_BLOCK_MS", 250) as u64);

    let mut genesis = zone_node::genesis::genesis_template()?;
    genesis.gas_limit = 2_000_000_000;
    let mut ctx = start_zone_with_redacted_rpc(Some(genesis)).await?;
    let recipient = address!("0x00000000000000000000000000000000000be7c4");
    let senders: Vec<_> = (0..transfers).map(|_| PrivateKeySigner::random()).collect();
    fund(&mut ctx, &senders).await?;
    ctx.fixture.seed_no_receive_policy(recipient)?;

    // Use every sender's first nonce up front so both measured paths pay the same gas.
    let warmup = submit_all(
        &ctx,
        &senders,
        concurrency,
        "eth_sendRawTransaction",
        0,
        recipient,
    )
    .await?;
    let head = ctx.zone.provider().get_block_number().await?;
    ctx.fixture.inject_empty_block(ctx.zone.deposit_queue());
    ctx.zone
        .wait_for_block_number(head + 1, DEFAULT_TIMEOUT)
        .await?;
    for (tx_hash, _, _) in &warmup.results {
        assert!(
            ctx.zone
                .provider()
                .get_transaction_receipt(*tx_hash)
                .await?
                .is_some(),
            "warm-up transfer {tx_hash} was not included"
        );
    }

    let blocks = BlockTicker::start(&mut ctx, block_interval);
    let included = submit_all(
        &ctx,
        &senders,
        concurrency,
        "eth_sendRawTransactionSync",
        1,
        recipient,
    )
    .await?;
    let preconfirmed = submit_all(
        &ctx,
        &senders,
        concurrency,
        "zone_preconfirmTransaction",
        2,
        recipient,
    )
    .await?;

    // Every promise is kept by the block it names.
    let provider = ctx.zone.provider();
    let mut kept = 0;
    let deadline = Instant::now() + DEFAULT_TIMEOUT;
    for (_, response, _) in &preconfirmed.results {
        let preconfirmation: SignedPreconfirmation =
            serde_json::from_value(response["result"].clone())?;
        let receipt = loop {
            if let Some(receipt) = provider
                .get_transaction_receipt(preconfirmation.tx_hash)
                .await?
            {
                break receipt;
            }
            eyre::ensure!(
                Instant::now() < deadline,
                "preconfirmed transfer {} was not included",
                preconfirmation.tx_hash
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(receipt.status());
        if receipt
            .block_number()
            .is_some_and(|number| number <= preconfirmation.include_by)
        {
            kept += 1;
        }
    }
    blocks.stop(&mut ctx).await?;

    let today = LatencySummary::new(&included);
    let preconf = LatencySummary::new(&preconfirmed);
    println!(
        "\n{transfers} TIP-20 transfers, {concurrency} concurrent senders, Zone block every {block_interval:?}"
    );
    println!(
        "{:<38} {:>10} {:>10} {:>10} {:>12} {:>12}",
        "path", "p50", "p99", "max", "wall clock", "transfers/s"
    );
    for (name, summary) in [
        ("today: eth_sendRawTransactionSync", &today),
        ("preconfirmation: zone_preconfirmTx", &preconf),
    ] {
        println!(
            "{name:<38} {:>10.2?} {:>10.2?} {:>10.2?} {:>12.2?} {:>12.0}",
            summary.p50,
            summary.p99,
            summary.max,
            summary.wall_clock,
            transfers as f64 / summary.wall_clock.as_secs_f64(),
        );
    }
    println!(
        "speedup: p50 {:.0}x, p99 {:.0}x; promises kept: {kept}/{transfers}\n",
        today.p50.as_secs_f64() / preconf.p50.as_secs_f64(),
        today.p99.as_secs_f64() / preconf.p99.as_secs_f64(),
    );
    assert_eq!(kept, transfers);

    Ok(())
}

/// Builds a signed Tempo transaction from `sender` with a single pathUSD call.
fn signed_transaction(
    sender: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    input: Vec<u8>,
) -> eyre::Result<(B256, Bytes)> {
    let transaction = TempoTransaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
        max_fee_per_gas: u128::from(TEMPO_T0_BASE_FEE),
        gas_limit,
        calls: vec![Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        }],
        fee_token: Some(PATH_USD_ADDRESS),
        ..Default::default()
    };
    let signature = sender.sign_hash_sync(&transaction.signature_hash())?;
    let envelope: TempoTxEnvelope = transaction.into_signed(signature.into()).into();
    Ok((*envelope.tx_hash(), envelope.encoded_2718().into()))
}

/// The first use of a nonce also pays for creating the account.
fn transfer_gas(nonce: u64) -> u64 {
    if nonce == 0 {
        TIP20_TX_GAS
    } else {
        TRANSFER_GAS
    }
}

fn signed_transfer(
    sender: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    to: Address,
    amount: u64,
) -> eyre::Result<(B256, Bytes)> {
    signed_transaction(
        sender,
        chain_id,
        nonce,
        transfer_gas(nonce),
        ITIP20::transferCall {
            to,
            amount: U256::from(amount),
        }
        .abi_encode(),
    )
}

async fn preconfirm(
    ctx: &RedactedRpcTestCtx,
    sender: &PrivateKeySigner,
    raw: &Bytes,
) -> eyre::Result<SignedPreconfirmation> {
    let response = ctx
        .call_as_user("zone_preconfirmTransaction", json!([raw]), sender)
        .await?;
    serde_json::from_value(response["result"].clone())
        .map_err(|err| eyre::eyre!("expected a preconfirmation ({err}): {response}"))
}

/// Returns the message of a rejected preconfirmation, which must be an invalid-params error.
async fn preconfirm_error(
    ctx: &RedactedRpcTestCtx,
    sender: &PrivateKeySigner,
    raw: &Bytes,
) -> eyre::Result<String> {
    let response = ctx
        .call_as_user("zone_preconfirmTransaction", json!([raw]), sender)
        .await?;
    eyre::ensure!(response["error"]["code"] == -32602, "{response}");
    Ok(response["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

/// Deposits [`SENDER_BALANCE`] pathUSD to every sender and waits until the last deposit lands.
async fn fund(ctx: &mut RedactedRpcTestCtx, senders: &[PrivateKeySigner]) -> eyre::Result<()> {
    for chunk in senders.chunks(MAX_UNPROCESSED_DEPOSITS) {
        let deposits = chunk
            .iter()
            .map(|sender| {
                ctx.fixture.make_deposit(
                    PATH_USD_ADDRESS,
                    sender.address(),
                    sender.address(),
                    SENDER_BALANCE,
                )
            })
            .collect();
        ctx.fixture
            .inject_deposits(ctx.zone.deposit_queue(), deposits);
        let last = chunk.last().expect("chunks are nonempty").address();
        ctx.zone
            .wait_for_balance(
                PATH_USD_ADDRESS,
                last,
                U256::from(SENDER_BALANCE),
                DEFAULT_TIMEOUT,
            )
            .await?;
    }
    Ok(())
}

/// Sends one transfer per sender through `method` with up to `concurrency` requests in flight.
///
/// Returns each transaction hash, its JSON-RPC response, and the request latency, plus the wall
/// clock time until the last response. Fails on the first JSON-RPC error.
async fn submit_all(
    ctx: &RedactedRpcTestCtx,
    senders: &[PrivateKeySigner],
    concurrency: usize,
    method: &str,
    nonce: u64,
    recipient: Address,
) -> eyre::Result<Submitted> {
    let client = reqwest::Client::new();
    let requests = senders
        .iter()
        .map(|sender| {
            let (tx_hash, raw) = signed_transfer(sender, ctx.config.chain_id, nonce, recipient, 1)?;
            Ok((tx_hash, raw, ctx.user_token(sender)))
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    let started = Instant::now();
    let results: Vec<_> = stream::iter(requests)
        .map(|(tx_hash, raw, token)| {
            let client = &client;
            async move {
                let started = Instant::now();
                let response: Value = client
                    .post(ctx.redacted_rpc_url.as_str())
                    .header("x-authorization-token", token)
                    .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": [raw]}))
                    .send()
                    .await?
                    .json()
                    .await?;
                let latency = started.elapsed();
                eyre::ensure!(response.get("error").is_none(), "{method}: {response}");
                Ok((tx_hash, response, latency))
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    Ok(Submitted {
        wall_clock: started.elapsed(),
        results: results.into_iter().collect::<eyre::Result<_>>()?,
    })
}

struct Submitted {
    results: Vec<(B256, Value, Duration)>,
    wall_clock: Duration,
}

/// Injects an empty Tempo block at a fixed interval so the Zone produces blocks like a live
/// sequencer.
///
/// A tick is skipped while the previous block is still queued. Otherwise a build that overruns
/// the interval leaves several Tempo blocks queued and the engine imports them as checkpoint-only
/// blocks, which carry no transactions; the benchmark measures transfers, not catch-up.
struct BlockTicker {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<crate::utils::L1Fixture>,
}

impl BlockTicker {
    fn start(ctx: &mut RedactedRpcTestCtx, interval: Duration) -> Self {
        let stop = CancellationToken::new();
        let mut fixture = core::mem::replace(&mut ctx.fixture, crate::utils::L1Fixture::new());
        let queue = ctx.zone.deposit_queue().clone();
        let cancelled = stop.clone();
        let task = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = cancelled.cancelled() => return fixture,
                    _ = ticks.tick() => {
                        if queue.peek().is_none() {
                            fixture.inject_empty_block(&queue);
                        }
                    }
                }
            }
        });
        Self { stop, task }
    }

    async fn stop(self, ctx: &mut RedactedRpcTestCtx) -> eyre::Result<()> {
        self.stop.cancel();
        ctx.fixture = self.task.await?;
        Ok(())
    }
}

struct LatencySummary {
    p50: Duration,
    p99: Duration,
    max: Duration,
    wall_clock: Duration,
}

impl LatencySummary {
    fn new(submitted: &Submitted) -> Self {
        let mut latencies: Vec<_> = submitted
            .results
            .iter()
            .map(|(_, _, latency)| *latency)
            .collect();
        latencies.sort();
        let percentile = |p: usize| latencies[(latencies.len() * p / 100).min(latencies.len() - 1)];
        Self {
            p50: percentile(50),
            p99: percentile(99),
            max: *latencies.last().expect("at least one transfer"),
            wall_clock: submitted.wall_clock,
        }
    }
}

fn env_or(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
