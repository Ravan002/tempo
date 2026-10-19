//! Tempo adapter for executing frozen eras with their historical binaries.
//!
//! See `tempo_metabinary` for the routing rules and worker lifecycle.

use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::{Decodable as _, Header as RlpHeader};
use alloy_rpc_types_eth::BlockId;
use eyre::{OptionExt as _, WrapErr as _};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::BoxStream};
use jsonrpsee::{
    core::RpcResult,
    types::{
        ErrorObjectOwned,
        error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    },
};
use reth_chainspec::EthChainSpec as _;
use reth_ethereum::rpc::{
    builder::{TransportRpcModules, auth::AuthRpcModule},
    eth::{EthApiError, EthConfig, TransactionSource},
};
use reth_provider::{BlockReaderIdExt as _, ExecutionOutcome};
use reth_rpc_eth_api::{
    RpcNodeCore,
    helpers::{EthBlocks, LoadTransaction, SpawnBlocking},
};
use serde_json::{Value, value::RawValue};
use std::{io, path::PathBuf, sync::Arc};
use tempo_chainspec::spec::{MODERATO, PRESTO, TempoChainSpec};
use tempo_metabinary::{
    catalog::{Catalog, ChainEras},
    decorate::{RpcApi, decorate},
    routing::{Backend, BlockMetadata, Router, RpcParams, UNKNOWN_BLOCK_CODE},
    workers::{DEFAULT_STARTUP_TIMEOUT, HistoricalWorkers, WorkerContext},
};
use tempo_primitives::{TempoHeader, TempoReceipt};
use tracing::warn;

/// Era catalog embedded in this release.
const BUILT_IN_CATALOG: &str = include_str!("../eras.json");

/// Packaged catalog beside the executable, which supersedes the built-in one.
const PACKAGED_CATALOG: &str = "tempo-eras.json";

/// Returns the release's era catalog with binaries resolved against the executable's directory.
pub(crate) fn release_catalog() -> eyre::Result<Catalog> {
    let exe = std::env::current_exe().wrap_err("failed to locate the tempo executable")?;
    let dir = exe
        .parent()
        .ok_or_eyre("tempo executable has no parent directory")?;
    let packaged = dir.join(PACKAGED_CATALOG);
    match std::fs::metadata(&packaged) {
        Ok(_) => Catalog::load(&packaged),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut catalog: Catalog = BUILT_IN_CATALOG
                .parse()
                .wrap_err("invalid built-in era catalog")?;
            catalog.resolve_binaries(dir);
            Ok(catalog)
        }
        Err(err) => Err(err).wrap_err_with(|| format!("failed to inspect {}", packaged.display())),
    }
}

/// Returns the frozen eras of `chain`, or `None` when it runs natively.
///
/// Only the built-in mainnet and Moderato specifications have frozen eras; custom genesis files,
/// fork schedules, and dev chains always execute in-process.
pub(crate) fn release_schedule(chain: &TempoChainSpec) -> eyre::Result<Option<ChainEras>> {
    if !supports_release_catalog(chain) {
        return Ok(None);
    }
    Ok(release_catalog()?
        .for_chain(chain.chain_id())
        .filter(|schedule| !schedule.eras.is_empty())
        .cloned())
}

/// Whether `chain` is exactly a built-in chain whose fork schedule the catalog describes.
///
/// A custom genesis can keep the built-in genesis hash while changing fork times, so the
/// configuration and hardforks are compared too.
fn supports_release_catalog(chain: &TempoChainSpec) -> bool {
    [&**PRESTO, &**MODERATO].into_iter().any(|built_in| {
        chain.chain_id() == built_in.chain_id()
            && chain.genesis_hash() == built_in.genesis_hash()
            && chain.genesis().config == built_in.genesis().config
            && chain.inner.hardforks == built_in.inner.hardforks
            && chain.info == built_in.info
    })
}

/// Frozen-era workers and routing for one node.
pub(crate) struct EraRuntime {
    workers: Arc<HistoricalWorkers>,
    boundaries: Vec<u64>,
    max_trace_filter_blocks: u64,
    /// Files workers read; they live as long as the runtime.
    _genesis: tempfile::NamedTempFile,
    _rpc_config: tempfile::NamedTempFile,
}

impl EraRuntime {
    /// Prepares dormant workers for `schedule` that inherit the node's chain, storage paths, and
    /// RPC configuration. Must be called within a Tokio runtime.
    pub(crate) fn new(
        schedule: ChainEras,
        chain: &TempoChainSpec,
        datadir: PathBuf,
        static_files_path: Option<PathBuf>,
        rocksdb_path: Option<PathBuf>,
        eth_config: &EthConfig,
    ) -> eyre::Result<Self> {
        let boundaries = schedule.boundaries()?;
        let genesis = write_json_tempfile(chain.genesis())?;
        let rpc_config = write_json_tempfile(eth_config)?;
        let context = WorkerContext {
            chain: genesis.path().display().to_string(),
            datadir,
            static_files_path,
            rocksdb_path,
            rpc_config: rpc_config.path().to_path_buf(),
            chain_id: alloy_primitives::U64::from(chain.chain_id()),
            genesis_hash: chain.genesis_hash(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        };
        Ok(Self {
            workers: HistoricalWorkers::new(context, schedule.eras)?,
            boundaries,
            max_trace_filter_blocks: eth_config.max_trace_filter_blocks,
            _genesis: genesis,
            _rpc_config: rpc_config,
        })
    }

    /// Routes the execution methods of every configured transport through the eras.
    pub(crate) fn install<EthApi>(
        &self,
        modules: &mut TransportRpcModules,
        auth: &mut AuthRpcModule,
        eth_api: EthApi,
    ) -> eyre::Result<()>
    where
        EthApi: NativeEthApi,
    {
        let router = Arc::new(Router::new(
            self.boundaries.clone(),
            self.max_trace_filter_blocks,
            Arc::new(NativeBackend {
                eth_api,
                workers: self.workers.clone(),
            }),
        ));
        if let Some(methods) = modules.http_methods(|_| true) {
            modules.replace_http(decorate(methods, router.clone(), RpcApi::Eth)?)?;
        }
        if let Some(methods) = modules.ws_methods(|_| true) {
            modules.replace_ws(decorate(methods, router.clone(), RpcApi::Eth)?)?;
        }
        if let Some(methods) = modules.ipc_methods(|_| true) {
            modules.replace_ipc(decorate(methods, router.clone(), RpcApi::Eth)?)?;
        }
        let engine = auth.module_mut().clone().remove_context();
        auth.replace_auth_methods(decorate(engine.into(), router, RpcApi::Engine)?)?;
        Ok(())
    }

    /// Stops the workers. Failures are logged.
    pub(crate) async fn shutdown(&self) {
        if let Err(err) = self.workers.shutdown().await {
            warn!(%err, "failed to stop historical workers");
        }
    }
}

/// The eth API capabilities the native backend uses.
pub(crate) trait NativeEthApi:
    EthBlocks
    + LoadTransaction
    + SpawnBlocking
    + RpcNodeCore<Provider: reth_provider::BlockReaderIdExt<Header = TempoHeader>>
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> NativeEthApi for T where
    T: EthBlocks
        + LoadTransaction
        + SpawnBlocking
        + RpcNodeCore<Provider: reth_provider::BlockReaderIdExt<Header = TempoHeader>>
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Resolves blocks in-process and forwards frozen-era requests to workers.
struct NativeBackend<EthApi> {
    eth_api: EthApi,
    workers: Arc<HistoricalWorkers>,
}

impl<EthApi: NativeEthApi> Backend for NativeBackend<EthApi> {
    fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>> {
        async move {
            let id: BlockId = serde_json::from_value(selector.clone())
                .map_err(|err| invalid_params(format!("invalid block selector: {err}")))?;
            let metadata = if id.is_pending() {
                self.eth_api
                    .recovered_block(id)
                    .await
                    .map_err(Into::into)?
                    .map(|block| metadata(block.hash(), block.header()))
            } else {
                // Canonicality is enforced by the original params.
                self.eth_api
                    .spawn_blocking_io(move |this| {
                        Ok(this
                            .provider()
                            .sealed_header_by_id(id)
                            .map_err(EthApiError::from)?)
                    })
                    .await
                    .map_err(Into::into)?
                    .map(|header| metadata(header.hash(), header.header()))
            };
            metadata.ok_or_else(|| {
                ErrorObjectOwned::owned(UNKNOWN_BLOCK_CODE, "unknown block", None::<()>)
            })
        }
        .boxed()
    }

    fn transaction_timestamp<'a>(
        &'a self,
        hash: &'a Value,
    ) -> BoxFuture<'a, RpcResult<Option<u64>>> {
        async move {
            let hash: B256 = serde_json::from_value(hash.clone())
                .map_err(|err| invalid_params(format!("invalid transaction hash: {err}")))?;
            Ok(
                match LoadTransaction::transaction_by_hash(&self.eth_api, hash)
                    .await
                    .map_err(Into::into)?
                {
                    Some(TransactionSource::Block {
                        block_timestamp, ..
                    }) => Some(block_timestamp),
                    Some(TransactionSource::Pool(_)) | None => None,
                },
            )
        }
        .boxed()
    }

    fn forward<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>> {
        self.workers.request(era, method, params).boxed()
    }

    fn subscribe<'a>(
        &'a self,
        era: usize,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<BoxStream<'static, Box<RawValue>>>> {
        async move { Ok(self.workers.subscribe(era, params).await?.boxed()) }.boxed()
    }

    fn raw_block_timestamp(&self, params: &RpcParams) -> RpcResult<u64> {
        raw_block_timestamp(params)
    }

    fn merge_execution_outcomes(&self, parts: Vec<Box<RawValue>>) -> RpcResult<Box<RawValue>> {
        merge_execution_outcomes(&parts).map_err(|err| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                format!("cannot merge execution outcomes across eras: {err:#}"),
                None::<()>,
            )
        })
    }
}

/// Returns the header timestamp of the RLP block in `debug_traceBlock` params.
fn raw_block_timestamp(params: &RpcParams) -> RpcResult<u64> {
    let raw = params
        .get(0, &["rlp_block", "rlpBlock"])
        .ok_or_else(|| invalid_params("missing raw block"))?;
    let raw: Bytes = serde_json::from_value(raw.clone())
        .map_err(|err| invalid_params(format!("invalid raw block: {err}")))?;
    raw_block_header(&raw)
        .map(|header| header.timestamp())
        .map_err(|err| invalid_params(format!("invalid raw block: {err}")))
}

/// Decodes only the header of an RLP block, leaving the body to the selected era's codec.
fn raw_block_header(raw: &[u8]) -> eyre::Result<TempoHeader> {
    let mut buf = raw;
    let list = RlpHeader::decode(&mut buf)?;
    eyre::ensure!(list.list, "raw block must be an RLP list");
    eyre::ensure!(buf.len() >= list.payload_length, "truncated raw block data");
    eyre::ensure!(buf.len() == list.payload_length, "trailing raw block data");
    Ok(TempoHeader::decode(&mut buf)?)
}

/// Merges consecutive outcomes into the outcome of one execution over their combined range.
fn merge_execution_outcomes(parts: &[Box<RawValue>]) -> eyre::Result<Box<RawValue>> {
    let mut merged: Option<ExecutionOutcome<TempoReceipt>> = None;
    for part in parts {
        let value: Value = serde_json::from_str(part.get())?;
        let outcome: ExecutionOutcome<TempoReceipt> = serde_json::from_value(value.clone())?;
        // Rejects unknown fields and any encoding the live codec would not reproduce.
        eyre::ensure!(
            serde_json::to_value(&outcome)? == value,
            "execution outcome encoding differs from this release"
        );
        match &mut merged {
            None => merged = Some(outcome),
            Some(merged) => {
                let next = merged
                    .first_block
                    .checked_add(u64::try_from(merged.receipts.len())?)
                    .ok_or_eyre("block range overflows")?;
                eyre::ensure!(
                    outcome.first_block == next,
                    "outcome starting at block {} does not follow block {}",
                    outcome.first_block,
                    next - 1
                );
                merged.extend(outcome);
            }
        }
    }
    let merged = merged.ok_or_eyre("no execution outcomes to merge")?;
    Ok(serde_json::value::to_raw_value(&merged)?)
}

fn metadata(hash: B256, header: &impl BlockHeader) -> BlockMetadata {
    BlockMetadata {
        number: header.number(),
        hash,
        timestamp: header.timestamp(),
    }
}

fn write_json_tempfile(value: &impl serde::Serialize) -> eyre::Result<tempfile::NamedTempFile> {
    let file = tempfile::Builder::new()
        .prefix("tempo-era-")
        .suffix(".json")
        .tempfile()?;
    serde_json::to_writer(file.as_file(), value)?;
    Ok(file)
}

fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, message.into(), None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use revm::{
        DatabaseCommit as _,
        database::{EmptyDB, State, states::bundle_state::BundleRetention},
        state::{Account, EvmState, EvmStorageSlot},
    };
    use serde_json::json;
    use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
    use tempo_primitives::{Block, BlockBody, TempoTxType};

    fn receipt(cumulative_gas_used: u64) -> TempoReceipt {
        TempoReceipt {
            tx_type: TempoTxType::Legacy,
            success: true,
            cumulative_gas_used,
            logs: Vec::new(),
        }
    }

    /// Account and storage changes made by block `block`.
    fn changes(block: u64) -> EvmState {
        let mut account = Account::default();
        account.info.balance = U256::from(block);
        account.info.nonce = block;
        account.storage.insert(
            U256::from(1),
            EvmStorageSlot::new_changed(
                U256::from(block - 1),
                U256::from(block),
                Default::default(),
            ),
        );
        account.mark_touch();
        [(Address::repeat_byte(1), account)].into_iter().collect()
    }

    fn execute(state: &mut State<EmptyDB>, block: u64) {
        state.commit(changes(block));
        state.merge_transitions(BundleRetention::Reverts);
    }

    fn raw(value: &impl serde::Serialize) -> Box<RawValue> {
        serde_json::value::to_raw_value(value).unwrap()
    }

    #[test]
    fn merged_outcomes_equal_one_execution_over_both_ranges() {
        let mut split = State::builder().with_bundle_update().build();
        execute(&mut split, 1);
        let first = ExecutionOutcome::new(split.take_bundle(), vec![vec![receipt(1)]], 1, vec![]);
        execute(&mut split, 2);
        let second = ExecutionOutcome::new(split.take_bundle(), vec![vec![receipt(2)]], 2, vec![]);

        let mut whole = State::builder().with_bundle_update().build();
        execute(&mut whole, 1);
        execute(&mut whole, 2);
        let expected = ExecutionOutcome::new(
            whole.take_bundle(),
            vec![vec![receipt(1)], vec![receipt(2)]],
            1,
            vec![],
        );

        let merged = merge_execution_outcomes(&[raw(&first), raw(&second)]).unwrap();
        let merged: ExecutionOutcome<TempoReceipt> = serde_json::from_str(merged.get()).unwrap();
        assert_eq!(merged, expected);

        let err = merge_execution_outcomes(&[raw(&second), raw(&first)]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "outcome starting at block 1 does not follow block 2"
        );
        let err =
            merge_execution_outcomes(&[raw(&first), raw(&json!({"bundle": {}}))]).unwrap_err();
        assert!(err.to_string().contains("missing field"), "{err}");
        let mut unknown = serde_json::to_value(&second).unwrap();
        unknown["extra"] = json!(1);
        let err = merge_execution_outcomes(&[raw(&first), raw(&unknown)]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "execution outcome encoding differs from this release"
        );
    }

    #[test]
    fn built_in_catalog_matches_the_built_in_chains() {
        let catalog: Catalog = BUILT_IN_CATALOG.parse().unwrap();
        for schedule in &catalog.chains {
            let chain = [&**PRESTO, &**MODERATO]
                .into_iter()
                .find(|chain| schedule.chain_id.to::<u64>() == chain.chain_id())
                .expect("catalog chains are built in");
            let [era] = schedule.eras.as_slice() else {
                panic!("{} must have one frozen era", schedule.chain_id);
            };
            assert_eq!(era.binary, PathBuf::from("eras/tempo-genesis-t11"));
            assert!(era.until >= TempoHardfork::MINIMUM_SUPPORTED);
            assert_eq!(
                schedule.boundaries().unwrap(),
                [era.until.activation_timestamp(chain.chain_id()).unwrap()]
            );
        }
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        for era in release_catalog()
            .unwrap()
            .chains
            .iter()
            .flat_map(|c| &c.eras)
        {
            assert!(era.binary.starts_with(&exe_dir));
        }
    }

    #[test]
    fn only_unmodified_built_in_chains_use_the_catalog() {
        assert!(supports_release_catalog(&PRESTO));
        assert!(supports_release_catalog(&MODERATO));
        assert!(!supports_release_catalog(&DEV));

        let mut genesis = PRESTO.genesis().clone();
        genesis
            .config
            .extra_fields
            .insert("t12Time".to_owned(), json!(1));
        let custom_forks = TempoChainSpec::from_genesis(genesis);
        assert_eq!(custom_forks.genesis_hash(), PRESTO.genesis_hash());
        assert!(!supports_release_catalog(&custom_forks));

        let mut genesis = MODERATO.genesis().clone();
        genesis.timestamp += 1;
        assert!(!supports_release_catalog(&TempoChainSpec::from_genesis(
            genesis
        )));
    }

    #[test]
    fn raw_blocks_decode_only_their_header() {
        let block = Block {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    timestamp: 77,
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody::default(),
        };
        let encoded = alloy_rlp::encode(&block);
        let params = |raw: &[u8]| RpcParams(json!([Bytes::copy_from_slice(raw)]));
        assert_eq!(raw_block_timestamp(&params(&encoded)), Ok(77));
        assert_eq!(
            raw_block_timestamp(&RpcParams(
                json!({"rlpBlock": Bytes::from(encoded.clone())})
            )),
            Ok(77)
        );

        // Bodies are left to the era's codec.
        let header_len = alloy_rlp::encode(&block.header).len();
        let mut corrupted = encoded.clone();
        let list_header = encoded.len()
            - alloy_rlp::Header::decode(&mut &encoded[..])
                .unwrap()
                .payload_length;
        for byte in &mut corrupted[list_header + header_len..] {
            *byte = 0xff;
        }
        assert_eq!(raw_block_timestamp(&params(&corrupted)), Ok(77));

        let mut trailing = encoded;
        trailing.push(0);
        for (raw, expected) in [
            (
                params(&trailing),
                "invalid raw block: trailing raw block data",
            ),
            (
                params(&[0x01]),
                "invalid raw block: raw block must be an RLP list",
            ),
            (RpcParams(json!([])), "missing raw block"),
        ] {
            let err = raw_block_timestamp(&raw).unwrap_err();
            assert_eq!((err.code(), err.message()), (INVALID_PARAMS_CODE, expected));
        }
    }
}
