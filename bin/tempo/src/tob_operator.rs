//! Demo top-of-block operator.
//!
//! Connects to the validators as an authenticated secondary peer, streams
//! replaceable maker transactions straight to each round's leader, verifies the
//! resulting blocks over RPC, and serves a live dashboard.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use alloy::providers::{Provider as _, ProviderBuilder, RootProvider};
use alloy_consensus::{SignableTransaction as _, TxEip1559, transaction::TxHashRef as _};
use alloy_eips::eip2718::Encodable2718 as _;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address};
use alloy_rlp::Encodable as _;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use clap::Parser;
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_p2p::{Receiver as _, Recipients};
use commonware_runtime::Runner as _;
use eyre::WrapErr as _;
use parking_lot::Mutex;
use serde::Serialize;
use tempo_consensus::top_of_block::{
    self, OperatorNetwork,
    wire::{AckStatus, Message, Submit},
};
use tempo_primitives::TempoTxEnvelope;

/// Makers send their quotes here; the address has no code.
const BOOK: Address = address!("0x000000000000000000000000000000000000b00c");
/// Stop streaming to a leader this long before its lane closes.
const CUTOFF_MARGIN: Duration = Duration::from_millis(5);
const ROUNDS_KEPT: usize = 40;

#[derive(Debug, Parser)]
#[command(name = "tempo-tob-operator", about = "Demo top-of-block operator")]
struct Args {
    /// Seed of the operator's ed25519 identity.
    #[arg(long)]
    seed: u64,
    /// Print the operator's public key and exit.
    #[arg(long)]
    print_public_key: bool,
    /// Consensus p2p listen address. Validators never dial it.
    #[arg(long, default_value = "127.0.0.1:9900")]
    listen: SocketAddr,
    /// Validators as `<public key>@<consensus ip:port>`, in the order of `--rpc`.
    #[arg(long = "validator")]
    validators: Vec<String>,
    /// JSON-RPC endpoints of the validators, in the order of `--validator`.
    #[arg(long = "rpc")]
    rpcs: Vec<String>,
    /// Number of makers streaming quotes.
    #[arg(long, default_value_t = 20)]
    makers: u32,
    /// Maker transactions generated per second, across all makers.
    #[arg(long, default_value_t = 1000)]
    rate: u64,
    /// Public transactions per second sent to the mempool with a high tip.
    #[arg(long, default_value_t = 20)]
    public_rate: u64,
    /// Dashboard address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    http: SocketAddr,
    #[arg(
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,
    /// Mnemonic index of the first maker account.
    #[arg(long, default_value_t = 10)]
    maker_offset: u32,
    /// Mnemonic index of the first public-flow account.
    #[arg(long, default_value_t = 200)]
    public_offset: u32,
    /// Must be at least the validators' `--consensus.max-message-size-bytes`.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_message_size: u32,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let signer = PrivateKey::from_seed(args.seed);
    if args.print_public_key {
        println!("{}", signer.public_key());
        return Ok(());
    }

    eyre::ensure!(
        args.validators.len() == args.rpcs.len() && !args.rpcs.is_empty(),
        "pass one --rpc per --validator"
    );
    let validators = args
        .validators
        .iter()
        .map(|value| top_of_block::parse_peer(value))
        .collect::<eyre::Result<Vec<_>>>()?;

    let storage = tempfile::tempdir()?;
    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(4)
            .with_storage_directory(storage.path()),
    );
    runner.start(async move |context| run(context, args, signer, validators).await)
}

#[derive(Clone, Debug, Serialize)]
struct ValidatorView {
    index: usize,
    public_key: String,
    rpc: String,
    rounds_led: u64,
    tob_txs_received: u64,
    last_ack_rtt_us: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct RoundView {
    epoch: u64,
    view: u64,
    height: u64,
    leader: usize,
    window_ms: u64,
    /// Unix ms when the announcement arrived.
    announced_at_ms: u64,
    /// Transactions streamed to the leader for this round.
    sent: u64,
    accepted: u64,
    replaced: u64,
    rejected: u64,
    late: u64,
    /// Round trip of the first submission.
    first_ack_rtt_us: Option<u64>,
    /// Time between the leader opening its lane and receiving our first submission.
    first_since_open_us: Option<u64>,
    built: Option<BuiltView>,
    verification: Option<Verification>,
}

#[derive(Clone, Debug, Serialize)]
struct BuiltView {
    block_hash: B256,
    tx_count: u32,
    top_of_block: Vec<B256>,
}

#[derive(Clone, Debug, Serialize)]
struct Verification {
    /// Validator whose RPC served the block.
    checked_on: usize,
    canonical: bool,
    /// The first transactions of the canonical block are the lane transactions.
    prefix_ok: bool,
    /// Kind of every transaction in the block, in order: `t` top of block,
    /// `p` public high-tip transaction, `o` other.
    layout: String,
    public_positions: Vec<usize>,
}

#[derive(Default, Serialize)]
struct Dashboard {
    operator: String,
    makers: u32,
    rate: u64,
    public_rate: u64,
    maker_tip_wei: u128,
    public_tip_wei: u128,
    validators: Vec<ValidatorView>,
    current: Option<RoundView>,
    rounds: VecDeque<RoundView>,
    generated: u64,
    streamed: u64,
    public_sent: u64,
    public_failed: u64,
}

/// A maker's account. Its quotes are signed on its own thread; all quotes of
/// a maker share its nonce, so at most one of them lands.
struct Maker {
    signer: PrivateKeySigner,
    nonce: AtomicU64,
    /// Unix ms of the last local nonce bump.
    bumped_at_ms: AtomicU64,
}

/// A freshly signed maker quote.
struct Quote {
    maker: usize,
    nonce: u64,
    hash: B256,
    raw: Bytes,
}

struct Target {
    leader: usize,
    epoch: u64,
    view: u64,
    cutoff: Instant,
}

async fn run(
    context: commonware_runtime::tokio::Context,
    args: Args,
    signer: PrivateKey,
    validators: Vec<(commonware_cryptography::ed25519::PublicKey, SocketAddr)>,
) -> eyre::Result<()> {
    let providers: Vec<RootProvider> = args
        .rpcs
        .iter()
        .map(|url| Ok(ProviderBuilder::default().connect_http(url.parse()?)))
        .collect::<eyre::Result<_>>()?;
    let chain_id = providers[0].get_chain_id().await?;
    let gas_price = providers[0].get_gas_price().await?;
    // Makers pay no tip; the public flow outbids them by far. Pool ordering
    // alone would put the public flow first.
    let maker_tip = 0u128;
    let public_tip = gas_price.max(1) * 50;
    let max_fee = gas_price * 2 + public_tip;

    let mut makers = Vec::new();
    for i in 0..args.makers {
        let signer = MnemonicBuilder::from_phrase_nth(&args.mnemonic, args.maker_offset + i);
        let nonce = providers[0].get_transaction_count(signer.address()).await?;
        makers.push(Maker {
            signer,
            nonce: AtomicU64::new(nonce),
            bumped_at_ms: AtomicU64::new(0),
        });
    }
    let makers = Arc::new(makers);

    let dashboard = Arc::new(Mutex::new(Dashboard {
        operator: signer.public_key().to_string(),
        makers: args.makers,
        rate: args.rate,
        public_rate: args.public_rate,
        maker_tip_wei: maker_tip,
        public_tip_wei: public_tip,
        validators: validators
            .iter()
            .zip(&args.rpcs)
            .enumerate()
            .map(|(index, ((key, _), rpc))| ValidatorView {
                index,
                public_key: key.to_string(),
                rpc: rpc.clone(),
                rounds_led: 0,
                tob_txs_received: 0,
                last_ack_rtt_us: None,
            })
            .collect(),
        ..Default::default()
    }));
    let public_hashes = Arc::new(Mutex::new(HashSet::<B256>::new()));

    let index_of: HashMap<_, _> = validators
        .iter()
        .enumerate()
        .map(|(index, (key, _))| (key.clone(), index))
        .collect();
    let keys: Vec<_> = validators.iter().map(|(key, _)| key.clone()).collect();

    let (mut sender, mut receiver) = top_of_block::start_operator_network(
        &context,
        OperatorNetwork {
            signer,
            listen: args.listen,
            validators,
            max_message_size: args.max_message_size,
        },
    )?;

    tokio::spawn(serve_dashboard(args.http, dashboard.clone()));
    tokio::spawn(public_flow(
        args.clone_public(),
        providers.clone(),
        chain_id,
        max_fee,
        public_tip,
        dashboard.clone(),
        public_hashes.clone(),
    ));
    tokio::spawn(resync_nonces(providers[0].clone(), makers.clone()));
    let (verify_tx, verify_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(verify_blocks(
        providers.clone(),
        verify_rx,
        dashboard.clone(),
        public_hashes,
    ));

    let (quotes_tx, mut quotes_rx) = tokio::sync::mpsc::unbounded_channel();
    let per_maker = Duration::from_secs_f64(f64::from(args.makers) / args.rate.max(1) as f64);
    for index in 0..makers.len() {
        let (makers, quotes_tx) = (makers.clone(), quotes_tx.clone());
        let template = TxTemplate {
            chain_id,
            max_fee,
            maker_tip,
        };
        std::thread::spawn(move || {
            // Stagger makers so the stream is smooth.
            std::thread::sleep(per_maker.mul_f64(index as f64 / makers.len() as f64));
            let mut next = Instant::now();
            let mut seq = 0u64;
            loop {
                seq += 1;
                let maker = &makers[index];
                let nonce = maker.nonce.load(Ordering::Relaxed);
                let Ok((hash, raw)) = template.sign(maker, nonce, seq) else {
                    continue;
                };
                if quotes_tx
                    .send(Quote {
                        maker: index,
                        nonce,
                        hash,
                        raw,
                    })
                    .is_err()
                {
                    return;
                }
                next += per_maker;
                std::thread::sleep(next.saturating_duration_since(Instant::now()));
            }
        });
    }

    let mut target: Option<Target> = None;
    let mut seq = 0u64;
    let mut in_flight: HashMap<u64, Instant> = HashMap::new();
    let mut latest: Vec<Option<(B256, Bytes)>> = vec![None; makers.len()];
    // Recently signed quotes, to map included hashes back to makers.
    let mut signed: HashMap<B256, (usize, u64)> = HashMap::new();
    let mut signed_order: VecDeque<B256> = VecDeque::new();

    println!(
        "operator up: {} makers at {} tx/s, public flow {} tx/s, dashboard on http://{}",
        args.makers, args.rate, args.public_rate, args.http
    );

    loop {
        tokio::select! {
            message = receiver.recv() => {
                let (peer, mut bytes) = message.map_err(|error| eyre::eyre!("{error}"))?;
                let Some(&leader) = index_of.get(&peer) else { continue };
                let Ok(message) = Message::read(&mut bytes) else { continue };
                match message {
                    Message::Leader(announcement) => {
                        let now = Instant::now();
                        let window = top_of_block::window(&announcement);
                        target = Some(Target {
                            leader,
                            epoch: announcement.epoch,
                            view: announcement.view,
                            cutoff: now + window.saturating_sub(CUTOFF_MARGIN),
                        });
                        // Flush the latest quote of every maker at once.
                        let txs: Vec<_> = latest
                            .iter()
                            .filter_map(|quote| quote.as_ref().map(|(_, raw)| raw.clone()))
                            .collect();
                        if !txs.is_empty() {
                            seq += 1;
                            in_flight.insert(seq, now);
                            submit(&mut sender, &keys[leader], announcement.epoch, announcement.view, seq, txs.clone());
                        }
                        let mut dashboard = dashboard.lock();
                        if let Some(previous) = dashboard.current.take() {
                            push_round(&mut dashboard.rounds, previous);
                        }
                        dashboard.validators[leader].rounds_led += 1;
                        dashboard.streamed += txs.len() as u64;
                        dashboard.current = Some(RoundView {
                            epoch: announcement.epoch,
                            view: announcement.view,
                            height: announcement.height,
                            leader,
                            window_ms: announcement.window_ms,
                            announced_at_ms: unix_ms(),
                            sent: txs.len() as u64,
                            ..Default::default()
                        });
                    }
                    Message::Ack(ack) => {
                        let rtt = in_flight.remove(&ack.seq).map(|sent| sent.elapsed().as_micros() as u64);
                        let mut dashboard = dashboard.lock();
                        let dashboard = &mut *dashboard;
                        let validator = &mut dashboard.validators[leader];
                        validator.last_ack_rtt_us = rtt.or(validator.last_ack_rtt_us);
                        validator.tob_txs_received += u64::from(ack.accepted + ack.replaced);
                        if let Some(round) = find_round(dashboard, ack.epoch, ack.view) {
                            if ack.status == AckStatus::Ok {
                                round.accepted += u64::from(ack.accepted);
                                round.replaced += u64::from(ack.replaced);
                                round.rejected += u64::from(ack.rejected);
                                if round.first_ack_rtt_us.is_none() {
                                    round.first_ack_rtt_us = rtt;
                                    round.first_since_open_us = Some(ack.since_open_us);
                                }
                            } else {
                                round.late += 1;
                            }
                        }
                    }
                    Message::Built(built) => {
                        for hash in &built.top_of_block {
                            let Some(&(maker, nonce)) = signed.get(hash) else { continue };
                            let state = &makers[maker];
                            if state.nonce.fetch_max(nonce + 1, Ordering::Relaxed) <= nonce {
                                state.bumped_at_ms.store(unix_ms(), Ordering::Relaxed);
                            }
                            latest[maker] = None;
                        }
                        let mut dashboard = dashboard.lock();
                        if let Some(round) = find_round(&mut dashboard, built.epoch, built.view) {
                            round.built = Some(BuiltView {
                                block_hash: built.block_hash,
                                tx_count: built.tx_count,
                                top_of_block: built.top_of_block.clone(),
                            });
                        }
                        let _ = verify_tx.send((leader, built));
                    }
                    Message::Submit(_) => {}
                }
            }

            Some(quote) = quotes_rx.recv() => {
                let mut fresh = vec![quote];
                while let Ok(quote) = quotes_rx.try_recv() {
                    fresh.push(quote);
                }
                let generated = fresh.len() as u64;
                let mut txs = Vec::with_capacity(fresh.len());
                for Quote { maker, nonce, hash, raw } in fresh {
                    // Quotes signed before a nonce bump are already stale.
                    if nonce < makers[maker].nonce.load(Ordering::Relaxed) {
                        continue;
                    }
                    signed.insert(hash, (maker, nonce));
                    signed_order.push_back(hash);
                    latest[maker] = Some((hash, raw.clone()));
                    txs.push(raw);
                }
                while signed_order.len() > 50_000 {
                    if let Some(hash) = signed_order.pop_front() {
                        signed.remove(&hash);
                    }
                }
                let mut streamed = 0;
                if let Some(target) = target.as_ref().filter(|target| Instant::now() < target.cutoff)
                    && !txs.is_empty()
                {
                    // Stream fresh quotes to the leader immediately.
                    streamed = txs.len() as u64;
                    seq += 1;
                    in_flight.insert(seq, Instant::now());
                    in_flight.retain(|_, sent| sent.elapsed() < Duration::from_secs(5));
                    submit(&mut sender, &keys[target.leader], target.epoch, target.view, seq, txs);
                }
                let mut dashboard = dashboard.lock();
                dashboard.generated += generated;
                dashboard.streamed += streamed;
                if let Some(current) = dashboard.current.as_mut() {
                    current.sent += streamed;
                }
            }
        }
    }
}

fn find_round(dashboard: &mut Dashboard, epoch: u64, view: u64) -> Option<&mut RoundView> {
    dashboard
        .current
        .iter_mut()
        .chain(dashboard.rounds.iter_mut())
        .find(|round| round.epoch == epoch && round.view == view)
}

/// Proposals that never finalize leave a maker's nonce ahead of the chain;
/// fall back to the chain after a grace period.
async fn resync_nonces(provider: RootProvider, makers: Arc<Vec<Maker>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for maker in makers.iter() {
            let Ok(chain) = provider
                .get_transaction_count(maker.signer.address())
                .latest()
                .await
            else {
                continue;
            };
            let local = maker.nonce.load(Ordering::Relaxed);
            let stale =
                unix_ms().saturating_sub(maker.bumped_at_ms.load(Ordering::Relaxed)) > 4_000;
            if chain > local || (chain < local && stale) {
                maker.nonce.store(chain, Ordering::Relaxed);
            }
        }
    }
}

fn submit(
    sender: &mut impl commonware_p2p::Sender<PublicKey = commonware_cryptography::ed25519::PublicKey>,
    leader: &commonware_cryptography::ed25519::PublicKey,
    epoch: u64,
    view: u64,
    seq: u64,
    txs: Vec<Bytes>,
) {
    let message = Message::Submit(Submit {
        epoch,
        view,
        seq,
        txs: txs.into_iter().map(|tx| tx.0).collect(),
    });
    sender.send(Recipients::One(leader.clone()), message.encode(), true);
}

fn push_round(rounds: &mut VecDeque<RoundView>, round: RoundView) {
    rounds.push_front(round);
    rounds.truncate(ROUNDS_KEPT);
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy)]
struct TxTemplate {
    chain_id: u64,
    max_fee: u128,
    maker_tip: u128,
}

impl TxTemplate {
    fn sign(&self, maker: &Maker, nonce: u64, seq: u64) -> eyre::Result<(B256, Bytes)> {
        let tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit: 300_000,
            max_fee_per_gas: self.max_fee,
            max_priority_fee_per_gas: self.maker_tip,
            to: TxKind::Call(BOOK),
            value: U256::ZERO,
            input: U256::from(seq).to_be_bytes::<32>().to_vec().into(),
            access_list: Default::default(),
        };
        sign(&maker.signer, tx)
    }
}

fn sign(signer: &PrivateKeySigner, tx: TxEip1559) -> eyre::Result<(B256, Bytes)> {
    use alloy::signers::SignerSync as _;
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope = TempoTxEnvelope::Eip1559(tx.into_signed(signature));
    let mut raw = Vec::with_capacity(envelope.length());
    envelope.encode_2718(&mut raw);
    Ok((*envelope.tx_hash(), raw.into()))
}

#[derive(Clone)]
struct PublicFlow {
    mnemonic: String,
    offset: u32,
    rate: u64,
}

impl Args {
    fn clone_public(&self) -> PublicFlow {
        PublicFlow {
            mnemonic: self.mnemonic.clone(),
            offset: self.public_offset,
            rate: self.public_rate,
        }
    }
}

/// Sends high-tip transactions to the public mempool of random validators.
async fn public_flow(
    flow: PublicFlow,
    providers: Vec<RootProvider>,
    chain_id: u64,
    max_fee: u128,
    tip: u128,
    dashboard: Arc<Mutex<Dashboard>>,
    hashes: Arc<Mutex<HashSet<B256>>>,
) {
    if flow.rate == 0 {
        return;
    }
    const ACCOUNTS: u32 = 8;
    let mut accounts = Vec::new();
    for i in 0..ACCOUNTS {
        let signer = MnemonicBuilder::from_phrase_nth(&flow.mnemonic, flow.offset + i);
        let nonce = providers[0]
            .get_transaction_count(signer.address())
            .await
            .unwrap_or_default();
        accounts.push((signer, nonce));
    }
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / flow.rate as f64));
    let mut resync = Instant::now();
    let mut i = 0u64;
    loop {
        i += 1;
        ticker.tick().await;
        if resync.elapsed() > Duration::from_secs(3) {
            resync = Instant::now();
            for (signer, nonce) in &mut accounts {
                if let Ok(chain) = providers[0].get_transaction_count(signer.address()).await
                    && chain > *nonce
                {
                    *nonce = chain;
                }
            }
        }
        let (signer, nonce) = &mut accounts[(i % u64::from(ACCOUNTS)) as usize];
        let tx = TxEip1559 {
            chain_id,
            nonce: *nonce,
            gas_limit: 300_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip,
            to: TxKind::Call(BOOK),
            value: U256::ZERO,
            input: Bytes::from_static(b"public"),
            access_list: Default::default(),
        };
        let Ok((hash, raw)) = sign(signer, tx) else {
            continue;
        };
        let provider = &providers[(i as usize) % providers.len()];
        match provider.send_raw_transaction(&raw).await {
            Ok(_) => {
                *nonce += 1;
                hashes.lock().insert(hash);
                dashboard.lock().public_sent += 1;
            }
            Err(_) => {
                dashboard.lock().public_failed += 1;
                if let Ok(chain) = provider.get_transaction_count(signer.address()).await {
                    *nonce = chain;
                }
            }
        }
    }
}

/// Checks each built proposal against a different validator's view of the chain.
async fn verify_blocks(
    providers: Vec<RootProvider>,
    mut built_rx: tokio::sync::mpsc::UnboundedReceiver<(usize, top_of_block::wire::Built)>,
    dashboard: Arc<Mutex<Dashboard>>,
    public_hashes: Arc<Mutex<HashSet<B256>>>,
) {
    while let Some((leader, built)) = built_rx.recv().await {
        let providers = providers.clone();
        let dashboard = dashboard.clone();
        let public_hashes = public_hashes.clone();
        tokio::spawn(async move {
            let checked_on = (leader + 1) % providers.len();
            let mut block = None;
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Ok(Some(found)) = providers[checked_on]
                    .raw_request::<_, Option<serde_json::Value>>(
                        "eth_getBlockByNumber".into(),
                        (format!("{:#x}", built.height), false),
                    )
                    .await
                {
                    block = Some(found);
                    break;
                }
            }
            let Some(block) = block else { return };
            let hash: Option<B256> = block["hash"].as_str().and_then(|hash| hash.parse().ok());
            let txs: Vec<B256> = block["transactions"]
                .as_array()
                .map(|txs| {
                    txs.iter()
                        .filter_map(|tx| tx.as_str()?.parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            let canonical = hash == Some(built.block_hash);
            let public = public_hashes.lock();
            let top: HashSet<_> = built.top_of_block.iter().collect();
            let layout: String = txs
                .iter()
                .map(|tx| {
                    if top.contains(tx) {
                        't'
                    } else if public.contains(tx) {
                        'p'
                    } else {
                        'o'
                    }
                })
                .collect();
            let public_positions = layout
                .char_indices()
                .filter(|(_, kind)| *kind == 'p')
                .map(|(i, _)| i)
                .collect();
            drop(public);
            let prefix_ok = canonical
                && txs.len() >= built.top_of_block.len()
                && txs[..built.top_of_block.len()] == built.top_of_block[..];
            let mut dashboard = dashboard.lock();
            let dashboard = &mut *dashboard;
            if let Some(round) = dashboard
                .current
                .iter_mut()
                .chain(dashboard.rounds.iter_mut())
                .find(|round| round.epoch == built.epoch && round.view == built.view)
            {
                round.verification = Some(Verification {
                    checked_on,
                    canonical,
                    prefix_ok,
                    layout,
                    public_positions,
                });
            }
        });
    }
}

async fn serve_dashboard(
    address: SocketAddr,
    dashboard: Arc<Mutex<Dashboard>>,
) -> eyre::Result<()> {
    use axum::{Json, Router, response::Html, routing::get};
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("tob_operator.html")) }),
        )
        .route(
            "/state",
            get(move || {
                let dashboard = dashboard.clone();
                async move {
                    let dashboard = dashboard.lock();
                    Json(serde_json::to_value(&*dashboard).unwrap_or_default())
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .wrap_err_with(|| format!("failed binding dashboard to {address}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}
