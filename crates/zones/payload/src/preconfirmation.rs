//! Sequencer preconfirmations for TIP-20 transfers.
//!
//! A preconfirmation is the sequencer's signed promise that a transaction will be included in a
//! Zone block numbered at most `includeBy`. The sequencer keeps an ordered queue of preconfirmed
//! transactions and the state they produce on top of the block the next build extends (the tip).
//! A transfer is preconfirmed only after it executes successfully on that state, so preconfirmed
//! transactions can never conflict with each other. One issuer thread executes submissions in
//! batches, each in one EVM, and requests sign their own promises in parallel.
//!
//! The payload builder holds the queue for the whole build and executes it, in order, right after
//! `advanceTempo` and before any pool transaction. Holding the queue prevents a preconfirmation
//! from being checked against state that a concurrently built block is about to change. When the
//! build finishes, the built block becomes the new tip and its state becomes the base for the next
//! preconfirmations, before the block is even canonical.
//!
//! The promise covers inclusion, not the transfer outcome. Inclusion can still fail if Tempo policy
//! imported by the next block's `advanceTempo` forbids the fee payment, and a checkpoint-only block
//! during catch-up carries no transactions, which delays inclusion past `includeBy`. The queue lives
//! in memory, so it does not survive a restart or a leadership handoff.

use crate::builder::POOL_TX_SIZE_BUDGET;
use alloy_consensus::{BlockHeader as _, Transaction as _, transaction::TxHashRef as _};
use alloy_eips::eip2718::Encodable2718 as _;
use alloy_evm::Evm as _;
use alloy_primitives::{Address, B256, Signature, SignatureError};
use alloy_signer::SignerSync as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall as _, SolStruct as _, eip712_domain, sol};
use reth_chainspec::EthChainSpec as _;
use reth_errors::ProviderError;
use reth_evm::{ConfigureEvm as _, NextBlockEnvAttributes};
use reth_primitives_traits::{Recovered, SealedHeader};
use reth_revm::{
    State,
    context::result::EVMError,
    database::StateProviderDatabase,
    database_interface::bal::EvmDatabaseError,
    db::{CacheState, DatabaseCommit as _},
};
use reth_storage_api::{BlockHashReader, BlockNumReader, StateProvider as _, StateProviderFactory};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::TempoNextBlockEnvAttributes;
use tempo_primitives::{TempoAddressExt as _, TempoHeader, TempoTxEnvelope};
use tempo_revm::TempoInvalidTransaction;
use tracing::warn;
use zone_evm::ZoneEvmConfig;
use zone_precompiles::L1StorageReader;

sol! {
    /// EIP-712 message the sequencer signs to promise inclusion of `txHash` in a Zone block
    /// numbered at most `includeBy`.
    struct Preconfirmation {
        bytes32 txHash;
        uint64 includeBy;
    }
}

/// A sequencer-signed inclusion promise, returned by `zone_preconfirmTransaction`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreconfirmation {
    /// Hash of the preconfirmed transaction.
    pub tx_hash: B256,
    /// Highest Zone block number that will contain the transaction.
    #[serde(with = "alloy_serde::quantity")]
    pub include_by: u64,
    /// Sequencer signature over the EIP-712 [`Preconfirmation`] message.
    pub signature: Signature,
}

impl SignedPreconfirmation {
    /// Returns the EIP-712 digest signed by the sequencer for the Zone with `chain_id`.
    pub fn signing_hash(&self, chain_id: u64) -> B256 {
        signing_hash(self.tx_hash, self.include_by, chain_id)
    }

    /// Recovers the address that signed this preconfirmation for the Zone with `chain_id`.
    ///
    /// Callers must compare the result with the Zone's sequencer.
    pub fn recover_signer(&self, chain_id: u64) -> Result<Address, SignatureError> {
        self.signature
            .recover_address_from_prehash(&self.signing_hash(chain_id))
    }
}

/// Reason a transaction cannot be preconfirmed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PreconfirmationError {
    /// Only transactions whose every call is a TIP-20 `transfer` or `transferWithMemo` qualify.
    #[error("only TIP-20 transfers can be preconfirmed")]
    Unsupported,
    /// This node did not build the block its next build extends, so it cannot promise inclusion.
    #[error("this node is not producing the next Zone block")]
    NotSequencing,
    /// The queue already fills the next block's gas or size budget.
    #[error("preconfirmation capacity for the next block is exhausted")]
    CapacityExhausted,
    /// The transfer executes but reverts on top of the already preconfirmed transactions.
    #[error("transaction reverts")]
    Reverted,
    /// The transaction is invalid on top of the already preconfirmed transactions.
    #[error("transaction is invalid: {0}")]
    Invalid(#[from] EVMError<EvmDatabaseError<ProviderError>, TempoInvalidTransaction>),
    /// State could not be read.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The sequencer key failed to sign.
    #[error(transparent)]
    Signing(Arc<alloy_signer::Error>),
    /// The issuer thread is gone because the node is shutting down.
    #[error("preconfirmation issuer stopped")]
    Stopped,
}

/// Shared queue of preconfirmed transactions, filled by a [`PreconfirmationIssuer`] and drained
/// by the payload builder.
#[derive(Clone)]
pub struct Preconfirmations {
    signer: PrivateKeySigner,
    queue: Arc<Mutex<Queue>>,
}

impl std::fmt::Debug for Preconfirmations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Preconfirmations")
            .field("sequencer", &self.signer.address())
            .finish_non_exhaustive()
    }
}

impl Preconfirmations {
    /// Creates an empty queue whose preconfirmations are signed by the sequencer `signer`.
    ///
    /// Preconfirmations are refused until the payload builder has built a block with this queue.
    pub fn new(signer: PrivateKeySigner) -> Self {
        Self {
            signer,
            queue: Arc::default(),
        }
    }

    /// Starts the thread that appends transactions to the queue and returns a handle to submit
    /// them. The thread stops once every handle is dropped.
    ///
    /// The thread drains every waiting submission into one batch and executes it in one EVM
    /// under one lock acquisition, so throughput grows with load instead of being bounded by
    /// lock handoffs between request threads, and a waiting build is delayed by one batch at most.
    pub fn spawn_issuer<P, L1>(
        &self,
        provider: P,
        evm_config: ZoneEvmConfig<L1>,
    ) -> PreconfirmationIssuer
    where
        P: StateProviderFactory + BlockNumReader + BlockHashReader + Send + 'static,
        L1: L1StorageReader + Unpin + Send + Sync + 'static,
    {
        let (submissions, received) = std::sync::mpsc::channel::<Submission>();
        let chain_id = evm_config.chain_spec().chain_id();
        let queue = self.queue.clone();
        std::thread::Builder::new()
            .name("zone-preconfirmations".into())
            .spawn(move || {
                while let Ok(first) = received.recv() {
                    let batch: Vec<_> = core::iter::once(first)
                        .chain(received.try_iter().take(MAX_ISSUE_BATCH - 1))
                        .collect();
                    let (txs, responders): (Vec<_>, Vec<_>) = batch
                        .into_iter()
                        .map(|submission| (submission.tx, submission.respond))
                        .unzip();
                    let outcomes = queue
                        .lock()
                        .expect("preconfirmation queue poisoned")
                        .enqueue(&provider, &evm_config, txs);
                    for (respond, outcome) in responders.into_iter().zip(outcomes) {
                        let _ = respond.send(outcome);
                    }
                }
            })
            .expect("failed to spawn the preconfirmation issuer");
        PreconfirmationIssuer {
            signer: self.signer.clone(),
            chain_id,
            submissions,
        }
    }

    /// Locks the queue for a build on top of `parent` and returns the transactions to include
    /// first, in order.
    ///
    /// If `parent` is not the current tip, the transactions of the abandoned tip and the queue are
    /// re-executed on `parent`, and those that no longer succeed are dropped.
    pub(crate) fn begin_block<P, L1>(
        &self,
        provider: &P,
        evm_config: &ZoneEvmConfig<L1>,
        parent: &SealedHeader<TempoHeader>,
    ) -> PreconfirmationBuild<'_>
    where
        P: StateProviderFactory,
        L1: L1StorageReader + Unpin,
    {
        let mut queue = self.lock();
        if queue.tip.as_ref().map(|tip| tip.header.hash()) != Some(parent.hash()) {
            let mut requeued = queue
                .tip
                .take()
                .map(|tip| tip.preconfirmed)
                .unwrap_or_default();
            requeued.append(&mut queue.pending);
            let tip = Tip {
                header: parent.clone(),
                state_base: parent.hash(),
                preconfirmed: Vec::new(),
            };
            queue.rebase(provider, evm_config, tip, CacheState::default(), requeued);
        }

        PreconfirmationBuild { queue }
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().expect("preconfirmation queue poisoned")
    }
}

/// Most submissions executed under one lock acquisition, which bounds how long a block build
/// waits for the issuer.
const MAX_ISSUE_BATCH: usize = 256;

/// Handle that submits transactions to the preconfirmation issuer thread.
#[derive(Debug, Clone)]
pub struct PreconfirmationIssuer {
    signer: PrivateKeySigner,
    chain_id: u64,
    submissions: std::sync::mpsc::Sender<Submission>,
}

impl PreconfirmationIssuer {
    /// Executes `tx` on top of the queue and, if it succeeds, appends it and returns the signed
    /// promise to include it in the next block. Resubmitting a queued transaction returns its
    /// existing preconfirmation.
    pub async fn preconfirm(
        &self,
        tx: Recovered<TempoTxEnvelope>,
    ) -> Result<SignedPreconfirmation, PreconfirmationError> {
        if !is_preconfirmable(&tx) {
            return Err(PreconfirmationError::Unsupported);
        }

        let tx_hash = *tx.tx_hash();
        let (respond, outcome) = tokio::sync::oneshot::channel();
        self.submissions
            .send(Submission { tx, respond })
            .map_err(|_| PreconfirmationError::Stopped)?;
        let include_by = outcome.await.map_err(|_| PreconfirmationError::Stopped)??;

        // Signing is deterministic, so a resubmission gets the same signature, and it happens
        // off the issuer thread because it does not depend on the queue.
        let digest = signing_hash(tx_hash, include_by, self.chain_id);
        let signature = self
            .signer
            .sign_hash_sync(&digest)
            .map_err(|err| PreconfirmationError::Signing(Arc::new(err)))?;
        Ok(SignedPreconfirmation {
            tx_hash,
            include_by,
            signature,
        })
    }
}

struct Submission {
    tx: Recovered<TempoTxEnvelope>,
    respond: tokio::sync::oneshot::Sender<Result<u64, PreconfirmationError>>,
}

/// Exclusive access to the queue for the duration of one block build.
pub(crate) struct PreconfirmationBuild<'a> {
    queue: MutexGuard<'a, Queue>,
}

impl PreconfirmationBuild<'_> {
    /// Returns the preconfirmed transactions to execute first, in preconfirmation order.
    pub(crate) fn transactions(&self) -> Vec<Recovered<TempoTxEnvelope>> {
        self.queue
            .pending
            .iter()
            .map(|queued| queued.tx.clone())
            .collect()
    }

    /// Makes a built checkpoint-only block, which carries no transactions, the tip and re-executes
    /// the queue on top of it. Transactions that no longer succeed are dropped, and the rest miss
    /// their `includeBy` by one block.
    pub(crate) fn finish_without_transactions<P, L1>(
        mut self,
        provider: &P,
        evm_config: &ZoneEvmConfig<L1>,
        header: SealedHeader<TempoHeader>,
        state: CacheState,
    ) where
        P: StateProviderFactory,
        L1: L1StorageReader + Unpin,
    {
        let pending = core::mem::take(&mut self.queue.pending);
        let tip = Tip {
            state_base: header.parent_hash(),
            header,
            preconfirmed: Vec::new(),
        };
        self.queue.rebase(provider, evm_config, tip, state, pending);
    }

    /// Makes the built block the tip with `state` (the build's cached state on top of its
    /// parent) as the base for new preconfirmations.
    ///
    /// Queued transactions not in `included` broke their promise and are dropped.
    pub(crate) fn finish(
        mut self,
        header: SealedHeader<TempoHeader>,
        state: CacheState,
        included: &HashSet<B256>,
    ) {
        let (preconfirmed, broken): (Vec<_>, Vec<_>) = core::mem::take(&mut self.queue.pending)
            .into_iter()
            .partition(|queued| included.contains(queued.tx.tx_hash()));
        for queued in &broken {
            drop_preconfirmation(queued, &"invalid in the built block");
        }
        metrics::counter!("zone_preconfirmations_included_total")
            .increment(preconfirmed.len() as u64);

        self.queue.reset(
            Tip {
                state_base: header.parent_hash(),
                header,
                preconfirmed,
            },
            state,
        );
    }
}

#[derive(Default)]
struct Queue {
    /// Block the next build extends; `None` until this node builds a block.
    tip: Option<Tip>,
    /// Preconfirmed transactions not yet in the tip, in preconfirmation order.
    pending: Vec<Queued>,
    /// `includeBy` of every transaction in `pending`, by hash.
    promised: HashMap<B256, u64>,
    /// State changes of the tip (when it was built here) and of `pending`, on top of the
    /// tip's `state_base`.
    cache: CacheState,
    /// Sum of `pending` gas limits.
    gas: u64,
    /// Sum of `pending` encoded lengths.
    bytes: usize,
}

impl Queue {
    /// Executes `txs` in order on top of the queue, appends those that succeed, and returns the
    /// block number promised to each. Resubmitting a queued transaction returns its promise.
    fn enqueue<P, L1>(
        &mut self,
        provider: &P,
        evm_config: &ZoneEvmConfig<L1>,
        txs: Vec<Recovered<TempoTxEnvelope>>,
    ) -> Vec<Result<u64, PreconfirmationError>>
    where
        P: StateProviderFactory + BlockNumReader + BlockHashReader,
        L1: L1StorageReader + Unpin,
    {
        let include_by = match self.next_block(provider) {
            Ok(number) => number,
            Err(err) => return vec![Err(err); txs.len()],
        };
        let gas_limit = self
            .tip
            .as_ref()
            .expect("checked by next_block")
            .header
            .gas_limit();

        // Resolve resubmissions and capacity up front so the rest of the batch executes in one
        // EVM. A transaction that then fails still counted toward capacity, which can only refuse
        // a later transaction of the same batch early.
        let mut outcomes = vec![None; txs.len()];
        let mut first_in_batch = HashMap::new();
        let mut duplicates = Vec::new();
        let mut executed = Vec::new();
        let (mut gas, mut bytes) = (self.gas, self.bytes);
        for (index, tx) in txs.iter().enumerate() {
            let tx_hash = *tx.tx_hash();
            if let Some(&promised) = self.promised.get(&tx_hash) {
                outcomes[index] = Some(Ok(promised));
            } else if let Some(&first) = first_in_batch.get(&tx_hash) {
                duplicates.push((index, first));
            } else {
                let next_gas = gas.saturating_add(tx.gas_limit());
                let next_bytes = bytes.saturating_add(tx.encode_2718_len());
                if next_gas > gas_limit || next_bytes > POOL_TX_SIZE_BUDGET {
                    outcomes[index] = Some(Err(PreconfirmationError::CapacityExhausted));
                } else {
                    (gas, bytes) = (next_gas, next_bytes);
                    first_in_batch.insert(tx_hash, index);
                    executed.push(index);
                }
            }
        }

        let results = self.execute(
            provider,
            evm_config,
            executed.iter().map(|&index| &txs[index]),
        );
        let mut txs: Vec<_> = txs.into_iter().map(Some).collect();
        let mut issued = 0;
        for (index, result) in executed.into_iter().zip(results) {
            if result.is_ok() {
                let tx = txs[index].take().expect("each transaction executes once");
                self.push(Queued { tx, include_by });
                issued += 1;
            }
            outcomes[index] = Some(result.map(|()| include_by));
        }
        for (index, first) in duplicates {
            outcomes[index] = outcomes[first].clone();
        }
        metrics::counter!("zone_preconfirmations_issued_total").increment(issued);
        outcomes
            .into_iter()
            .map(|outcome| outcome.expect("every transaction has an outcome"))
            .collect()
    }

    /// Returns the number of the block the next build produces, if this node builds it.
    fn next_block<P>(&self, provider: &P) -> Result<u64, PreconfirmationError>
    where
        P: BlockNumReader + BlockHashReader,
    {
        let tip = self
            .tip
            .as_ref()
            .ok_or(PreconfirmationError::NotSequencing)?;
        // A block this node built extends the canonical head until the engine imports it.
        let latest = provider.block_hash(provider.best_block_number()?)?;
        if latest != Some(tip.header.hash()) && latest != Some(tip.header.parent_hash()) {
            return Err(PreconfirmationError::NotSequencing);
        }
        Ok(tip.header.number() + 1)
    }

    /// Appends an executed transaction.
    fn push(&mut self, queued: Queued) {
        self.gas = self.gas.saturating_add(queued.tx.gas_limit());
        self.bytes = self.bytes.saturating_add(queued.tx.encode_2718_len());
        self.promised
            .insert(*queued.tx.tx_hash(), queued.include_by);
        self.pending.push(queued);
    }

    /// Moves the empty queue onto `tip`, whose changes on top of its `state_base` are `state`.
    fn reset(&mut self, tip: Tip, state: CacheState) {
        debug_assert!(self.pending.is_empty());
        self.tip = Some(tip);
        self.cache = state;
        self.promised.clear();
        self.gas = 0;
        self.bytes = 0;
    }

    /// Moves the queue onto `tip` and re-executes `requeued` in order, dropping transactions that
    /// no longer succeed.
    fn rebase<P, L1>(
        &mut self,
        provider: &P,
        evm_config: &ZoneEvmConfig<L1>,
        tip: Tip,
        state: CacheState,
        requeued: Vec<Queued>,
    ) where
        P: StateProviderFactory,
        L1: L1StorageReader + Unpin,
    {
        self.reset(tip, state);
        let outcomes = self.execute(
            provider,
            evm_config,
            requeued.iter().map(|queued| &queued.tx),
        );
        for (queued, outcome) in requeued.into_iter().zip(outcomes) {
            match outcome {
                Ok(()) => self.push(queued),
                Err(err) => drop_preconfirmation(&queued, &err),
            }
        }
    }

    /// Executes `txs` in order on the queue state in one EVM, commits the changes of each one
    /// that succeeds, and returns one outcome per transaction. Once state cannot be read, the
    /// remaining transactions are not executed and fail with that error.
    fn execute<'a, P, L1>(
        &mut self,
        provider: &P,
        evm_config: &ZoneEvmConfig<L1>,
        txs: impl IntoIterator<Item = &'a Recovered<TempoTxEnvelope>>,
    ) -> Vec<Result<(), PreconfirmationError>>
    where
        P: StateProviderFactory,
        L1: L1StorageReader + Unpin,
    {
        let tip = self.tip.as_ref().expect("queue state requires a tip");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let env = evm_config
            .next_evm_env(
                &tip.header,
                &TempoNextBlockEnvAttributes {
                    inner: NextBlockEnvAttributes {
                        timestamp: now.max(tip.header.timestamp()),
                        suggested_fee_recipient: tip.header.beneficiary(),
                        prev_randao: B256::ZERO,
                        gas_limit: tip.header.gas_limit(),
                        parent_beacon_block_root: None,
                        withdrawals: None,
                        extra_data: Default::default(),
                        slot_number: None,
                    },
                    general_gas_limit: 0,
                    shared_gas_limit: 0,
                    timestamp_millis_part: 0,
                    consensus_context: None,
                },
            )
            .map_err(ProviderError::other);
        let state = env.and_then(|env| Ok((env, provider.state_by_block_hash(tip.state_base)?)));
        let (env, state) = match state {
            Ok(state) => state,
            Err(err) => return txs.into_iter().map(|_| Err(err.clone().into())).collect(),
        };
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(state.into_evm_state_provider()))
            .with_cached_prestate(core::mem::take(&mut self.cache))
            .build();

        let mut evm = evm_config.evm_with_env(&mut db, env);
        let mut failure: Option<ProviderError> = None;
        let outcomes = txs
            .into_iter()
            .map(|tx| {
                if let Some(err) = &failure {
                    return Err(err.clone().into());
                }
                match evm.transact(tx) {
                    Ok(result) if result.result.is_success() => {
                        evm.db_mut().commit(result.state);
                        Ok(())
                    }
                    Ok(_) => Err(PreconfirmationError::Reverted),
                    Err(EVMError::Database(EvmDatabaseError::Database(err))) => {
                        failure = Some(err.clone());
                        Err(err.into())
                    }
                    Err(err) => Err(err.into()),
                }
            })
            .collect();
        drop(evm);
        self.cache = db.cache;
        outcomes
    }
}

struct Tip {
    header: SealedHeader<TempoHeader>,
    /// Block whose state the queue cache is layered on: the parent of a block built here, or the
    /// tip itself when it was adopted from the canonical chain.
    state_base: B256,
    /// Preconfirmed transactions included in the tip, requeued if the tip is abandoned.
    preconfirmed: Vec<Queued>,
}

struct Queued {
    tx: Recovered<TempoTxEnvelope>,
    /// Block number promised when the transaction was first preconfirmed.
    include_by: u64,
}

fn signing_hash(tx_hash: B256, include_by: u64, chain_id: u64) -> B256 {
    Preconfirmation {
        txHash: tx_hash,
        includeBy: include_by,
    }
    .eip712_signing_hash(&eip712_domain! {
        name: "TempoZonePreconfirmation",
        version: "1",
        chain_id: chain_id,
    })
}

/// Returns whether every call of `tx` is a TIP-20 `transfer` or `transferWithMemo`.
fn is_preconfirmable(tx: &TempoTxEnvelope) -> bool {
    tx.is_payment_v2()
        && tx.calls().all(|(kind, input)| {
            kind.to().is_some_and(|to| to.is_tip20())
                && input.get(..4).is_some_and(|selector| {
                    selector == ITIP20::transferCall::SELECTOR
                        || selector == ITIP20::transferWithMemoCall::SELECTOR
                })
        })
}

fn drop_preconfirmation(queued: &Queued, reason: &dyn std::fmt::Display) {
    metrics::counter!("zone_preconfirmations_dropped_total").increment(1);
    warn!(
        target: "zone::preconfirmation",
        tx_hash = %queued.tx.tx_hash(),
        include_by = queued.include_by,
        %reason,
        "dropping preconfirmed transaction"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, TxKind, U256, b256, keccak256};
    use alloy_sol_types::SolValue as _;
    use tempo_contracts::precompiles::PATH_USD_ADDRESS;
    use tempo_primitives::transaction::{Call, TempoTransaction};

    fn transaction(calls: Vec<(Address, Vec<u8>)>) -> TempoTxEnvelope {
        let transaction = TempoTransaction {
            calls: calls
                .into_iter()
                .map(|(to, input)| Call {
                    to: TxKind::Call(to),
                    value: U256::ZERO,
                    input: Bytes::from(input),
                })
                .collect(),
            ..Default::default()
        };
        transaction
            .into_signed(Signature::test_signature().into())
            .into()
    }

    #[test]
    fn only_tip20_transfers_are_preconfirmable() {
        let recipient = Address::repeat_byte(0x22);
        let transfer = ITIP20::transferCall {
            to: recipient,
            amount: U256::ONE,
        }
        .abi_encode();
        let transfer_with_memo = ITIP20::transferWithMemoCall {
            to: recipient,
            amount: U256::ONE,
            memo: B256::repeat_byte(0x33),
        }
        .abi_encode();
        let approve = ITIP20::approveCall {
            spender: recipient,
            amount: U256::ONE,
        }
        .abi_encode();

        for (calls, expected) in [
            (vec![(PATH_USD_ADDRESS, transfer.clone())], true),
            (
                vec![
                    (PATH_USD_ADDRESS, transfer.clone()),
                    (PATH_USD_ADDRESS, transfer_with_memo),
                ],
                true,
            ),
            (vec![(PATH_USD_ADDRESS, approve.clone())], false),
            (
                vec![
                    (PATH_USD_ADDRESS, transfer.clone()),
                    (PATH_USD_ADDRESS, approve),
                ],
                false,
            ),
            (vec![(recipient, transfer)], false),
        ] {
            assert_eq!(
                is_preconfirmable(&transaction(calls.clone())),
                expected,
                "{calls:?}"
            );
        }
    }

    /// Clients verify preconfirmations without this crate, so the signed digest is pinned to an
    /// independently computed EIP-712 encoding.
    #[test]
    fn preconfirmation_signs_the_eip712_digest() {
        let signer = PrivateKeySigner::random();
        let chain_id = 4_217_000_031;
        let tx_hash = b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
        let include_by = 42u64;

        let domain_separator = keccak256(
            (
                keccak256("EIP712Domain(string name,string version,uint256 chainId)"),
                keccak256("TempoZonePreconfirmation"),
                keccak256("1"),
                U256::from(chain_id),
            )
                .abi_encode(),
        );
        let struct_hash = keccak256(
            (
                keccak256("Preconfirmation(bytes32 txHash,uint64 includeBy)"),
                tx_hash,
                U256::from(include_by),
            )
                .abi_encode(),
        );
        let digest = keccak256(
            [
                &[0x19, 0x01][..],
                domain_separator.as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        );

        let preconfirmation = SignedPreconfirmation {
            tx_hash,
            include_by,
            signature: signer.sign_hash_sync(&digest).unwrap(),
        };
        assert_eq!(preconfirmation.signing_hash(chain_id), digest);
        assert_eq!(
            preconfirmation.recover_signer(chain_id).unwrap(),
            signer.address()
        );
        assert_ne!(
            preconfirmation.recover_signer(chain_id + 1).unwrap(),
            signer.address()
        );

        let json = serde_json::to_value(&preconfirmation).unwrap();
        assert_eq!(json["txHash"], serde_json::json!(tx_hash));
        assert_eq!(json["includeBy"], serde_json::json!("0x2a"));
        assert_eq!(
            serde_json::from_value::<SignedPreconfirmation>(json).unwrap(),
            preconfirmation
        );
    }
}
