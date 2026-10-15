//! Wire/capability tests with real generated proof evidence, not devnet acceptance tests.
#![cfg(feature = "rpc-server")]

mod common;
use jsonrpsee::{RpcModule, server::Server, types::ErrorObjectOwned};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempo_light::{
    HeadTracker,
    config::Limits,
    transport::{Error, Upstreams},
};
use tempo_state_proof::ProofLimits;

#[tokio::test]
async fn standard_fallback_is_hash_pinned_verified_and_remembers_capability() {
    let checkpoint = common::checkpoint();
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/mpt-finality-v1.json")).unwrap();
    let responses: Vec<alloy_rpc_types_eth::EIP1186AccountProofResponse> =
        serde_json::from_value(fixture["responses"].clone()).unwrap();
    let targets = serde_json::from_value(fixture["targets"].clone()).unwrap();
    let hash = checkpoint.head.digest;
    let multi = Arc::new(AtomicUsize::new(0));
    let standard = Arc::new(AtomicUsize::new(0));
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new(());
    let count = multi.clone();
    module
        .register_method("eth_getMultiProof", move |_, _, _| {
            count.fetch_add(1, Ordering::Relaxed);
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32601,
                "method not found",
                None::<()>,
            ))
        })
        .unwrap();
    let count = standard.clone();
    let response = responses[0].clone();
    module
        .register_method("eth_getProof", move |params, _, _| {
            let params: Vec<Value> = params.parse().unwrap();
            assert_eq!(
                params[2],
                json!({"blockHash":hash, "requireCanonical":true})
            );
            assert_eq!(params[0], json!(response.address));
            count.fetch_add(1, Ordering::Relaxed);
            Ok::<_, ErrorObjectOwned>(response.clone())
        })
        .unwrap();
    let handle = server.start(module);
    let transport = Upstreams::new(
        vec![format!("http://{address}").parse().unwrap()],
        &Limits::default(),
    )
    .unwrap();
    let mut tracker = HeadTracker::new(checkpoint.network.anchor, checkpoint.network.epoch_length);
    let mut rng: rand::rngs::StdRng = rand::make_rng();
    let snapshot = tracker.accept(&mut rng, checkpoint.head).unwrap();
    for _ in 0..2 {
        let response = transport.proofs(0, hash, &targets).await.unwrap();
        snapshot
            .verify(&targets, &response, ProofLimits::default())
            .unwrap();
    }
    assert_eq!(multi.load(Ordering::Relaxed), 1);
    assert_eq!(standard.load(Ordering::Relaxed), 2);
    assert!(matches!(
        transport.proofs(99, hash, &targets).await,
        Err(Error::Configuration)
    ));
    let limits = Limits {
        max_response_bytes: 10,
        ..Default::default()
    };
    let bounded =
        Upstreams::new(vec![format!("http://{address}").parse().unwrap()], &limits).unwrap();
    assert!(matches!(
        bounded.proofs(0, hash, &targets).await,
        Err(Error::ResponseSize(_))
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn critical_publication_failure_pauses_reads_and_successful_refresh_recovers() {
    use tempo_light::{
        client::{Client, Error as ClientError, FailureKind},
        token::ReadRequest,
    };
    let checkpoint = common::checkpoint();
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("checkpoint.tmp")).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new(());
    let head = checkpoint.head.clone();
    module
        .register_method("consensus_getFinalizedHeader", move |_, _, _| {
            Ok::<_, ErrorObjectOwned>(head.clone())
        })
        .unwrap();
    let handle = server.start(module);
    let client = Client::open(
        checkpoint.network.clone(),
        vec![
            format!("http://{address}").parse().unwrap(),
            "http://127.0.0.1:1".parse().unwrap(),
        ],
        directory.path(),
        Limits::default(),
    )
    .unwrap();
    assert!(matches!(
        client.refresh().await,
        Err(ClientError::Checkpoint(_))
    ));
    let status = client.status().await;
    assert!(status.head.is_none());
    assert!(!status.durable);
    assert!(matches!(
        status.last_failure,
        Some(FailureKind::Persistence)
    ));
    let request = ReadRequest::TotalSupply {
        token: "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap(),
    };
    assert!(matches!(
        client.read(vec![request]).await.unwrap_err().as_ref(),
        ClientError::PersistencePaused
    ));
    std::fs::remove_dir(directory.path().join("checkpoint.tmp")).unwrap();
    client.refresh().await.unwrap();
    assert!(client.status().await.durable);
    // An available provider confirming retained evidence is a successful refresh, even when
    // another endpoint is down. Head age, not endpoint agreement, expresses freshness.
    client.refresh().await.unwrap();
    assert!(client.status().await.last_failure.is_none());
    drop(client);
    let store = tempo_light::checkpoint::Store::open(directory.path()).unwrap();
    assert_eq!(
        store.load(&checkpoint.network).unwrap().unwrap().head,
        checkpoint.head
    );
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn standard_proofs_use_a_provider_wide_concurrency_budget() {
    use alloy_primitives::{Address, B256, keccak256};
    use alloy_trie::{HashBuilder, Nibbles, TrieAccount, proof::ProofRetainer};
    use std::collections::{BTreeMap, BTreeSet};
    use tempo_state_proof::{ProofTargets, test_utils::fixture, verify_multi_proof};
    use tokio::sync::{Semaphore, mpsc};

    // Genuine account-only proofs for four accounts under one root.
    let mut responses = (0..4)
        .map(|index| {
            let (_, _, mut response) = fixture(1, 42);
            response.address = Address::with_last_byte(index);
            response.storage_proof.clear();
            response
        })
        .collect::<Vec<_>>();
    let leaves = responses
        .iter()
        .map(|response| {
            let account = TrieAccount {
                nonce: response.nonce,
                balance: response.balance,
                storage_root: response.storage_hash,
                code_hash: response.code_hash,
            };
            (
                Nibbles::unpack(keccak256(response.address)),
                alloy_rlp::encode(account),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut root = B256::ZERO;
    for response in &mut responses {
        let path = Nibbles::unpack(keccak256(response.address));
        let mut builder =
            HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![path]));
        for (path, value) in &leaves {
            builder.add_leaf(*path, value);
        }
        root = builder.root();
        response.account_proof = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node)
            .collect();
    }
    let targets = responses
        .iter()
        .map(|response| (response.address, BTreeSet::new()))
        .collect::<ProofTargets>();
    verify_multi_proof(root, &targets, &responses, ProofLimits::default()).unwrap();

    let (started_tx, mut started) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new((
        responses,
        started_tx,
        release.clone(),
        active.clone(),
        peak.clone(),
    ));
    module
        .register_method("eth_getMultiProof", |_, _, _| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32601,
                "method not found",
                None::<()>,
            ))
        })
        .unwrap();
    module
        .register_async_method("eth_getProof", |params, context, _| async move {
            let (responses, started, release, active, peak) = context.as_ref();
            let (account, slots, selector): (Address, Vec<B256>, Value) = params.parse()?;
            assert!(slots.is_empty());
            assert_eq!(
                selector,
                json!({"blockHash": B256::ZERO, "requireCanonical": true})
            );
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            started.send(account).unwrap();
            release.acquire().await.unwrap().forget();
            active.fetch_sub(1, Ordering::SeqCst);
            Ok::<_, ErrorObjectOwned>(
                responses
                    .iter()
                    .find(|response| response.address == account)
                    .unwrap()
                    .clone(),
            )
        })
        .unwrap();
    let handle = server.start(module);
    let transport = Upstreams::new(
        vec![format!("http://{address}").parse().unwrap()],
        &Limits {
            proof_concurrency: 4,
            ..Default::default()
        },
    )
    .unwrap();
    let transport = Arc::new(transport);
    let spawn = || {
        let transport = transport.clone();
        let targets = targets.clone();
        tokio::spawn(async move { transport.proofs(0, B256::ZERO, &targets).await })
    };
    let first = spawn();
    for _ in 0..4 {
        tokio::time::timeout(std::time::Duration::from_secs(5), started.recv())
            .await
            .unwrap()
            .unwrap();
    }
    // One fallback batch can use all four permits; another batch cannot multiply the budget.
    let second = spawn();
    tokio::task::yield_now().await;
    assert!(started.try_recv().is_err());
    release.add_permits(8);
    let (first, second) = tokio::join!(first, second);
    for responses in [first.unwrap().unwrap(), second.unwrap().unwrap()] {
        verify_multi_proof(root, &targets, &responses, ProofLimits::default()).unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 4);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn proof_window_expiry_is_availability_not_selector_capability() {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/mpt-finality-v1.json")).unwrap();
    let targets = serde_json::from_value(fixture["targets"].clone()).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new(());
    module
        .register_method("eth_getMultiProof", |_, _, _| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32602,
                "distance to target block exceeds maximum proof window",
                None::<()>,
            ))
        })
        .unwrap();
    let handle = server.start(module);
    let transport = Upstreams::new(
        vec![format!("http://{address}").parse().unwrap()],
        &Limits::default(),
    )
    .unwrap();
    assert!(matches!(
        transport
            .proofs(0, common::checkpoint().head.digest, &targets)
            .await,
        Err(Error::RpcUnavailable { code: -32602, .. })
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}
