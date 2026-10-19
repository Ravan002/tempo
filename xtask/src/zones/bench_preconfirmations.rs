//! Benchmarks sequencer preconfirmations against today's transfer path on a running Zone.
//!
//! Every measured transfer is a pathUSD transfer submitted through the leader's redacted RPC.
//! Today a sender learns its transfer is final from `eth_sendRawTransactionSync`, which returns
//! once the transfer is in a block. With preconfirmations it gets a signed inclusion promise from
//! `zone_preconfirmTransaction`, after the other sequencers stored the transfer.
//!
//! The funding account must already hold pathUSD on the Zone (see `deposit`). It funds one fresh
//! account per transfer, every sender uses its first nonce in a warm-up so both paths pay the
//! same gas, and then each concurrency level runs both paths back to back.

use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy::{
    consensus::BlockHeader as _,
    network::ReceiptResponse as _,
    primitives::{Address, B256, Bytes, TxKind, U256, address},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{SignerSync as _, local::PrivateKeySigner},
    sol_types::SolCall as _,
};
use alloy_consensus::transaction::TxHashRef as _;
use alloy_eips::eip2718::Encodable2718 as _;
use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use serde::Serialize;
use serde_json::{Value, json};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{Call, TempoTransaction},
};
use zone_payload::SignedPreconfirmation;
use zone_rpc::auth::{X_AUTHORIZATION_TOKEN, build_token_fields};

use crate::zone_utils::parse_private_key;

/// Gas limit for the first transaction of an account, which also pays for creating it.
const FIRST_TX_GAS: u64 = 500_000;
/// Gas limit for a transfer from an account whose nonce is already in use.
const TRANSFER_GAS: u64 = 200_000;
/// pathUSD sent to every sender; enough for its transfers and their fees.
const SENDER_BALANCE: u64 = 1_000_000;
/// Receives every measured transfer.
const RECIPIENT: Address = address!("0x00000000000000000000000000000000000be7c4");
/// How long to wait for a transfer to land before failing the run.
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, clap::Parser)]
pub(crate) struct BenchPreconfirmations {
    /// Leader operator JSON-RPC URL, used for setup and receipts.
    #[arg(long)]
    zone_rpc_url: String,

    /// Leader redacted RPC URL. Both measured paths are submitted here.
    #[arg(long)]
    redacted_rpc_url: String,

    /// Operator JSON-RPC URLs of the other sequencers; every promised transfer must land there too.
    #[arg(long = "follower-rpc-url")]
    follower_rpc_urls: Vec<String>,

    /// Zone account that funds the senders. It must hold pathUSD on the Zone.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Largest number of transfers per path and concurrency level, and the number of senders.
    #[arg(long, default_value_t = 2000)]
    transfers: usize,

    /// Comma-separated numbers of requests in flight. Each level sends
    /// `min(transfers, 16 * concurrency)` transfers through each path.
    #[arg(long, value_delimiter = ',', default_value = "1,16,64,256")]
    concurrency: Vec<usize>,

    /// Writes the results as JSON.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl BenchPreconfirmations {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let funder = parse_private_key(&self.private_key)?;
        let zone = connect(&self.zone_rpc_url).await?;
        let followers =
            futures::future::try_join_all(self.follower_rpc_urls.iter().map(|url| connect(url)))
                .await?;
        let chain_id = zone.get_chain_id().await?;
        let ctx = Ctx {
            zone,
            chain_id,
            redacted_rpc_url: self.redacted_rpc_url,
            client: reqwest::Client::new(),
        };
        ensure!(
            self.concurrency.iter().all(|&level| level > 0),
            "--concurrency levels must be positive"
        );

        let mut senders: Vec<_> = (0..self.transfers)
            .map(|_| Sender {
                signer: PrivateKeySigner::random(),
                nonce: 0,
            })
            .collect();
        println!(
            "funding {} senders from {} on Zone chain {chain_id}",
            senders.len(),
            funder.address()
        );
        ctx.fund(&funder, &senders).await?;

        println!("warming up: every sender uses its first nonce");
        let warmup = ctx
            .submit(&mut senders, 256, "eth_sendRawTransaction")
            .await?;
        ctx.wait_for_receipts(warmup.results.iter().map(|result| result.tx_hash))
            .await?;

        let mut levels = Vec::new();
        for &concurrency in &self.concurrency {
            let senders = &mut senders[..self.transfers.min(16 * concurrency)];
            println!(
                "{} transfers, {concurrency} in flight: eth_sendRawTransactionSync",
                senders.len()
            );
            let today = ctx
                .submit(senders, concurrency, "eth_sendRawTransactionSync")
                .await?;
            println!(
                "{} transfers, {concurrency} in flight: zone_preconfirmTransaction",
                senders.len()
            );
            let preconfirmed = ctx
                .submit(senders, concurrency, "zone_preconfirmTransaction")
                .await?;
            let promises = ctx.check_promises(&preconfirmed, &followers).await?;
            levels.push(Level {
                transfers: senders.len(),
                concurrency,
                today: Summary::new(&today),
                preconfirmation: Summary::new(&preconfirmed),
                promises,
            });
        }

        print_table(&levels);
        if let Some(path) = self.output {
            std::fs::write(&path, serde_json::to_string_pretty(&levels)?)
                .wrap_err_with(|| format!("failed to write {}", path.display()))?;
        }
        Ok(())
    }
}

struct Ctx {
    zone: DynProvider<TempoNetwork>,
    chain_id: u64,
    redacted_rpc_url: String,
    client: reqwest::Client,
}

impl Ctx {
    /// Sends [`SENDER_BALANCE`] to every sender from `funder` and waits for every transfer.
    async fn fund(&self, funder: &PrivateKeySigner, senders: &[Sender]) -> eyre::Result<()> {
        let needed = U256::from(SENDER_BALANCE) * U256::from(senders.len() + 1);
        let balance = ITIP20::new(PATH_USD_ADDRESS, &self.zone)
            .balanceOf(funder.address())
            // Zone balances are private; only the holder may read its own.
            .from(funder.address())
            .call()
            .await?;
        ensure!(
            balance >= needed,
            "funder {} holds {balance} pathUSD on the Zone, needs at least {needed}",
            funder.address()
        );
        let first_nonce = self.zone.get_transaction_count(funder.address()).await?;
        let tx_hashes: Vec<_> = stream::iter(senders.iter().enumerate())
            .map(|(index, sender)| {
                let (_, raw) = transfer(
                    funder,
                    self.chain_id,
                    first_nonce + index as u64,
                    FIRST_TX_GAS,
                    sender.signer.address(),
                    SENDER_BALANCE,
                )?;
                Ok::<_, eyre::Report>(async move {
                    Ok(*self.zone.send_raw_transaction(&raw).await?.tx_hash())
                })
            })
            .try_buffered(64)
            .try_collect()
            .await?;
        self.wait_for_receipts(tx_hashes).await
    }

    /// Sends one transfer of 1 pathUSD unit from every sender with its next nonce through `method`
    /// on the redacted RPC, with up to `concurrency` requests in flight. Fails on any JSON-RPC
    /// error.
    async fn submit(
        &self,
        senders: &mut [Sender],
        concurrency: usize,
        method: &str,
    ) -> eyre::Result<Submitted> {
        let requests = senders
            .iter_mut()
            .map(|sender| {
                let gas = if sender.nonce == 0 {
                    FIRST_TX_GAS
                } else {
                    TRANSFER_GAS
                };
                let (tx_hash, raw) = transfer(
                    &sender.signer,
                    self.chain_id,
                    sender.nonce,
                    gas,
                    RECIPIENT,
                    1,
                )?;
                sender.nonce += 1;
                Ok((tx_hash, raw, auth_token(&sender.signer, self.chain_id)?))
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        let started = Instant::now();
        let results = stream::iter(requests)
            .map(|(tx_hash, raw, token)| async move {
                let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": [raw]});
                let started = Instant::now();
                let response = self
                    .client
                    .post(&self.redacted_rpc_url)
                    .header(X_AUTHORIZATION_TOKEN, token)
                    .header("content-type", "application/json")
                    .body(body.to_string())
                    .send()
                    .await?
                    .bytes()
                    .await?;
                let latency = started.elapsed();
                let mut response: Value = serde_json::from_slice(&response)?;
                ensure!(response.get("error").is_none(), "{method}: {response}");
                Ok(Response {
                    tx_hash,
                    result: response["result"].take(),
                    latency,
                })
            })
            .buffer_unordered(concurrency)
            .try_collect()
            .await?;
        Ok(Submitted {
            results,
            wall_clock: started.elapsed(),
        })
    }

    /// Checks that every promise was signed by the sequencer that built the block containing the
    /// transfer, and that the block is no later than the promised one, on the leader and on every
    /// follower.
    async fn check_promises(
        &self,
        preconfirmed: &Submitted,
        followers: &[DynProvider<TempoNetwork>],
    ) -> eyre::Result<Promises> {
        let mut promises = Promises::default();
        let promised: Vec<SignedPreconfirmation> = preconfirmed
            .results
            .iter()
            .map(|response| serde_json::from_value(response.result.clone()))
            .collect::<Result<_, _>>()?;
        self.wait_for_receipts(promised.iter().map(|promise| promise.tx_hash))
            .await?;
        for promise in &promised {
            let receipt = self
                .zone
                .get_transaction_receipt(promise.tx_hash)
                .await?
                .ok_or_eyre("receipt disappeared")?;
            ensure!(
                receipt.status(),
                "promised transfer {} reverted",
                promise.tx_hash
            );
            let block_number = receipt.block_number().ok_or_eyre("receipt has no block")?;
            let builder = self
                .zone
                .get_block_by_number(block_number.into())
                .await?
                .ok_or_eyre("block disappeared")?
                .header
                .beneficiary();
            ensure!(
                promise.recover_signer(self.chain_id)? == builder,
                "promise for {} was not signed by the sequencer {builder} that built block \
                 {block_number}",
                promise.tx_hash
            );
            if block_number <= promise.include_by {
                promises.kept += 1;
            }
            for follower in followers {
                let receipt = follower
                    .get_transaction_receipt(promise.tx_hash)
                    .await?
                    .ok_or_else(|| eyre!("follower is missing {}", promise.tx_hash))?;
                ensure!(receipt.block_number() == Some(block_number));
            }
        }
        promises.checked = promised.len();
        ensure!(
            promises.kept == promises.checked,
            "only {} of {} promises were kept",
            promises.kept,
            promises.checked
        );
        Ok(promises)
    }

    async fn wait_for_receipts(
        &self,
        tx_hashes: impl IntoIterator<Item = B256>,
    ) -> eyre::Result<()> {
        let deadline = Instant::now() + INCLUSION_TIMEOUT;
        for tx_hash in tx_hashes {
            loop {
                if let Some(receipt) = self.zone.get_transaction_receipt(tx_hash).await? {
                    ensure!(receipt.status(), "transfer {tx_hash} reverted");
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "transfer {tx_hash} was not included"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        Ok(())
    }
}

async fn connect(url: &str) -> eyre::Result<DynProvider<TempoNetwork>> {
    Ok(ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(url)
        .await
        .wrap_err_with(|| format!("failed to connect to {url}"))?
        .erased())
}

/// Builds a signed pathUSD transfer.
fn transfer(
    sender: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    to: Address,
    amount: u64,
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
            input: ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            }
            .abi_encode()
            .into(),
        }],
        fee_token: Some(PATH_USD_ADDRESS),
        ..Default::default()
    };
    let signature = sender.sign_hash_sync(&transaction.signature_hash())?;
    let envelope: TempoTxEnvelope = transaction.into_signed(signature.into()).into();
    Ok((*envelope.tx_hash(), envelope.encoded_2718().into()))
}

/// Builds a redacted RPC authorization token for `signer`, valid for ten minutes on any Zone.
fn auth_token(signer: &PrivateKeySigner, chain_id: u64) -> eyre::Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (fields, digest) = build_token_fields(0, chain_id, now, now + 600);
    let signature = signer.sign_hash_sync(&digest)?;
    Ok(const_hex::encode(
        [signature.as_rsy().as_slice(), &fields].concat(),
    ))
}

struct Sender {
    signer: PrivateKeySigner,
    /// Next nonce to use.
    nonce: u64,
}

struct Response {
    tx_hash: B256,
    result: Value,
    latency: Duration,
}

struct Submitted {
    results: Vec<Response>,
    wall_clock: Duration,
}

#[derive(Debug, Serialize)]
struct Level {
    transfers: usize,
    concurrency: usize,
    today: Summary,
    preconfirmation: Summary,
    promises: Promises,
}

/// Latencies in milliseconds.
#[derive(Debug, Serialize)]
struct Summary {
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    wall_clock_ms: f64,
    transfers_per_second: f64,
}

impl Summary {
    fn new(submitted: &Submitted) -> Self {
        let mut latencies: Vec<_> = submitted
            .results
            .iter()
            .map(|response| response.latency)
            .collect();
        latencies.sort();
        let percentile = |p: usize| latencies[(latencies.len() * p / 100).min(latencies.len() - 1)];
        let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
        Self {
            p50_ms: ms(percentile(50)),
            p99_ms: ms(percentile(99)),
            max_ms: ms(*latencies.last().expect("at least one transfer")),
            wall_clock_ms: ms(submitted.wall_clock),
            transfers_per_second: latencies.len() as f64 / submitted.wall_clock.as_secs_f64(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct Promises {
    checked: usize,
    kept: usize,
}

fn print_table(levels: &[Level]) {
    println!(
        "\n{:>9} {:>9}  {:<12} {:>10} {:>10} {:>10} {:>12}  {:>8}",
        "transfers", "in flight", "path", "p50 ms", "p99 ms", "max ms", "transfers/s", "kept"
    );
    for level in levels {
        for (path, summary, kept) in [
            ("today", &level.today, String::new()),
            (
                "preconfirm",
                &level.preconfirmation,
                format!("{}/{}", level.promises.kept, level.promises.checked),
            ),
        ] {
            println!(
                "{:>9} {:>9}  {path:<12} {:>10.2} {:>10.2} {:>10.2} {:>12.0}  {kept:>8}",
                level.transfers,
                level.concurrency,
                summary.p50_ms,
                summary.p99_ms,
                summary.max_ms,
                summary.transfers_per_second,
            );
        }
        println!(
            "{:>21}  p50 speedup {:.0}x, p99 speedup {:.0}x",
            "",
            level.today.p50_ms / level.preconfirmation.p50_ms,
            level.today.p99_ms / level.preconfirmation.p99_ms,
        );
    }
}
