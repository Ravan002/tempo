use alloy_primitives::{Address, B256, Bytes};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use eyre::Result;
use serde_json::json;
use sqlx::{PgPool, Row, types::Json};

use zone_auth::{AccessOp, AccountSet, Change, Domain, Principal, Registry, Scope, SignedOp};
use zone_gateway::{
    chain::VerifiedOperation,
    clock,
    store::{DeliveryEvent, LogRecord, Registration, Store},
};

fn proof(
    domain: &Domain,
    signer: &PrivateKeySigner,
    admin: Address,
    client: Address,
    coordinates: (u64, u64, u64),
    change: Change,
) -> Result<VerifiedOperation> {
    let (seq, generation, signer_generation) = coordinates;
    let now = clock::unix_seconds()?;
    let op = AccessOp {
        domain: domain.clone(),
        client,
        seq,
        generation,
        signer: signer.address(),
        signer_generation,
        change,
        issued_at: now,
        expires_at: now + 600,
    };
    let signature = Bytes::copy_from_slice(&signer.sign_hash_sync(&op.digest())?.as_bytes());
    Ok(VerifiedOperation {
        signed: SignedOp { op, signature },
        zone_admin: admin,
        observed_at: clock::continuous_seconds(),
        tempo_hash: B256::repeat_byte(0x77),
    })
}
fn admit(scopes: &[Scope]) -> Change {
    Change::Admit {
        name: "fixture client".into(),
        scopes: scopes.iter().copied().collect(),
        accounts: AccountSet::All,
    }
}
fn principal(address: Address, generation: u64, token_id: B256) -> Principal {
    Principal::Client {
        address,
        generation,
        token_id,
        label: "fixture".into(),
    }
}

#[tokio::test]
async fn postgres_serializes_history_archive_recovery_logs_and_delivery() -> Result<()> {
    let Some(url) = std::env::var("ZONES_GATEWAY_TEST_DATABASE_URL").ok() else {
        eprintln!("PostgreSQL test requires ZONES_GATEWAY_TEST_DATABASE_URL");
        return Ok(());
    };
    let domain = Domain {
        tempo_chain_id: 42431,
        portal: Address::random(),
        zone_id: 7,
        zone_chain_id: 42432,
    };
    let archive = tempfile::tempdir()?;
    let store = Store::open(&url, domain.clone(), archive.path()).await?;
    let peer = Store::open(&url, domain.clone(), archive.path()).await?;
    let pool = PgPool::connect(&url).await?;
    let admin = PrivateKeySigner::random();
    let delegate = PrivateKeySigner::random();
    let target = Address::random();
    let admission = proof(
        &domain,
        &admin,
        admin.address(),
        delegate.address(),
        (1, 0, 0),
        admit(&[Scope::Admin]),
    )?;
    let (left, right) = tokio::join!(store.commit(&admission), peer.commit(&admission));
    let receipt = left?;
    assert_eq!(receipt, right?);
    assert_eq!(receipt.offset, 1);
    assert_eq!(receipt.generation, 1);
    let mut stale = VerifiedOperation {
        signed: admission.signed.clone(),
        zone_admin: Address::ZERO,
        observed_at: 0.0,
        tempo_hash: B256::ZERO,
    };
    assert_eq!(
        store.commit(&stale).await?,
        receipt,
        "exact digest retry precedes fresh proof and signer authority"
    );
    assert_eq!(store.receipt(receipt.digest).await?, Some(receipt.clone()));
    assert_eq!(
        store.retry_signed(&admission.signed).await?,
        Some(receipt.clone())
    );
    let mut changed_signature = admission.signed.clone();
    changed_signature.signature = Bytes::from(vec![1, 2, 3]);
    assert_eq!(
        store.retry_signed(&changed_signature).await?,
        None,
        "alternate signatures must still pass current verification"
    );
    let mut changed_payload = admission.signed.clone();
    changed_payload.op.seq = 2;
    assert_eq!(store.retry_signed(&changed_payload).await?, None);

    let grant = proof(
        &domain,
        &delegate,
        admin.address(),
        target,
        (1, 0, 1),
        admit(&[Scope::RpcRead]),
    )?;
    let removal = proof(
        &domain,
        &admin,
        admin.address(),
        delegate.address(),
        (2, 1, 0),
        Change::Remove,
    )?;
    let (grant_result, remove_result) = tokio::join!(store.commit(&grant), peer.commit(&removal));
    let removed = remove_result?;
    let state = store.snapshot().await?;
    assert!(!state.clients[&delegate.address()].active);
    if grant_result.is_ok() {
        assert!(state.clients[&target].active);
        assert_eq!(state.offset, 3);
    } else {
        assert!(!state.clients.contains_key(&target));
        assert_eq!(state.offset, 2);
    }
    stale.observed_at = 0.0;
    assert_eq!(
        peer.commit(&stale).await?,
        receipt,
        "removed signer does not invalidate applied digest receipt"
    );
    assert!(
        store.commit(&grant).await.is_err() || grant_result.is_ok(),
        "grant cannot be newly applied after admin removal"
    );

    let owner = Address::random();
    let other = Address::random();
    let token = B256::repeat_byte(0x33);
    let own = store
        .record(LogRecord {
            principal: Some(principal(owner, 1, token)),
            token_id: Some(token),
            label: Some("fixture".into()),
            account: Some(owner),
            tempo_hash: Some(B256::repeat_byte(0x77)),
            zone_hash: Some(B256::repeat_byte(0x88)),
            method: "eth_getBalance".into(),
            decision: "allow".into(),
            offset: state.offset,
        })
        .await?;
    store.complete(own, "released").await?;
    store
        .record(LogRecord {
            principal: Some(principal(other, 1, token)),
            token_id: Some(token),
            label: None,
            account: Some(other),
            tempo_hash: None,
            zone_hash: None,
            method: "credential-content-must-not-appear".into(),
            decision: "deny".into(),
            offset: state.offset,
        })
        .await?;
    assert_eq!(
        store
            .logs(&principal(owner, 1, token), false, 0, 100)
            .await?
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .logs(&principal(owner, 2, token), false, 0, 100)
            .await?,
        json!([])
    );
    assert!(
        store
            .logs(&principal(owner, 1, token), true, 0, 100)
            .await
            .is_err()
    );
    assert!(
        store
            .logs(&principal(delegate.address(), 1, token), true, 0, 100)
            .await
            .is_err(),
        "removed admin cannot read all logs"
    );
    let all = store
        .logs(&Principal::ZoneAdmin(admin.address()), true, 0, 100)
        .await?;
    let entries = all.as_array().unwrap();
    assert!(entries.iter().any(|entry| entry["method"] == "unknown"));
    assert!(
        entries
            .iter()
            .any(|entry| entry["method"] == "zone_applyAccessOp"
                && entry["decision"] == "applied"
                && entry["offset"] == 1)
    );
    assert!(
        entries.iter().any(
            |entry| entry["method"] == "zone_applyAccessOp" && entry["decision"] == "duplicate"
        )
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.get("signature").is_none() && entry.get("params").is_none())
    );

    let directory = archive
        .path()
        .join(alloy_primitives::hex::encode(domain.key()));
    let watermark: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("watermark.json"))?)?;
    assert_eq!(watermark["offset"], json!(state.offset));
    std::fs::write(
        directory.join(".event.crashed-staging"),
        b"incomplete temporary bytes",
    )?;
    store.sync_archive().await?;
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM gateway_events WHERE domain=$1")
        .bind(domain.key().as_slice())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE gateway_heads SET head=0,archived_head=0,event_hash=$2,registry=$3 WHERE domain=$1",
    )
    .bind(domain.key().as_slice())
    .bind(B256::ZERO.as_slice())
    .bind(Json(serde_json::to_value(Registry::default())?))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    store.recover().await?;
    assert_eq!(store.snapshot().await?, state);
    assert_eq!(store.receipt(receipt.digest).await?, Some(receipt));
    assert_eq!(store.receipt(removed.digest).await?, Some(removed));

    let final_client = Address::random();
    let next = state.offset + 1;
    let final_path = directory.join(format!("{next:020}.json"));
    std::fs::write(&final_path, b"corrupt final object")?;
    let last = proof(
        &domain,
        &admin,
        admin.address(),
        final_client,
        (1, 0, 0),
        admit(&[]),
    )?;
    let error = store.commit(&last).await.unwrap_err();
    assert!(format!("{error:?}").contains("unknown outcome"));
    assert!(
        store.snapshot().await?.clients.contains_key(&final_client),
        "archive failure does not undo database commit"
    );
    assert!(
        store.receipt(last.signed.op.digest()).await.is_err(),
        "receipt is not acknowledged during archive corruption"
    );
    std::fs::remove_file(final_path)?;
    store.sync_archive().await?;
    assert_eq!(
        store
            .receipt(last.signed.op.digest())
            .await?
            .unwrap()
            .offset,
        next
    );
    let bytes = std::fs::read(directory.join("watermark.json"))?;
    std::fs::write(
        directory.join("watermark.json"),
        serde_json::to_vec(&json!({"offset":0,"hash":B256::ZERO,"domain":domain.key()}))?,
    )?;
    assert!(
        store.recover().await.is_err(),
        "independently recorded archive head may not regress"
    );
    std::fs::write(directory.join("watermark.json"), bytes)?;

    let registration = Registration {
        id: "delivery-fixture".into(),
        owner,
        generation: 1,
        encrypted_credential: vec![0x41; 32],
        endpoint: "https://receiver.example/events".into(),
        cursor: 0,
        paused: false,
    };
    store.put_registration(&registration).await?;
    let mut stolen = registration.clone();
    stolen.owner = other;
    assert!(store.put_registration(&stolen).await.is_err());
    let events = [
        DeliveryEvent {
            event_id: "event-1".into(),
            cursor: 1,
            payload: json!({"event":1}),
        },
        DeliveryEvent {
            event_id: "event-2".into(),
            cursor: 2,
            payload: json!({"event":2}),
        },
    ];
    store.ingest(&registration.id, 0, &events, 2).await?;
    assert!(
        store.ingest(&registration.id, 0, &events, 2).await.is_err(),
        "cursor must compare and advance atomically"
    );
    let first = store.claim_delivery("worker-one").await?.unwrap();
    assert_eq!(first.attempts, 1);
    assert_eq!(first.event_id, "event-1");
    assert!(
        peer.claim_delivery("worker-two").await?.is_none(),
        "only first unacknowledged cursor can be delivered"
    );
    sqlx::query("UPDATE gateway_delivery_jobs SET lease_until=NOW()-INTERVAL '1 second' WHERE domain=$1 AND registration_id=$2 AND event_id=$3").bind(domain.key().as_slice()).bind(&registration.id).bind(&first.event_id).execute(&pool).await?;
    let mut reclaimed = peer.claim_delivery("worker-two").await?.unwrap();
    assert_eq!(reclaimed.event_id, first.event_id);
    assert_eq!(reclaimed.fence, first.fence + 1);
    assert_eq!(reclaimed.attempts, 2);
    assert!(
        store.acknowledge_delivery(&first).await.is_err(),
        "old worker cannot acknowledge after re-lease"
    );
    reclaimed.cursor = u64::MAX;
    peer.acknowledge_delivery(&reclaimed).await?;
    let ack: String = sqlx::query_scalar(
        "SELECT ack_cursor::text FROM gateway_registrations WHERE domain=$1 AND id=$2",
    )
    .bind(domain.key().as_slice())
    .bind(&registration.id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(ack, "1");
    let second = store.claim_delivery("worker-one").await?.unwrap();
    assert_eq!(second.event_id, "event-2");
    store.retry_delivery(&second, 0).await?;
    let retry = peer.claim_delivery("worker-two").await?.unwrap();
    assert_eq!(retry.event_id, second.event_id);
    assert_eq!(retry.fence, second.fence + 1);
    peer.acknowledge_delivery(&retry).await?;
    assert!(store.claim_delivery("worker-one").await?.is_none());
    assert!(
        store
            .delete_registration(&registration.id, other, 1)
            .await
            .is_err()
    );
    store
        .delete_registration(&registration.id, owner, 1)
        .await?;
    assert!(store.get_registration(&registration.id).await?.is_none());

    let empty = Address::random();
    let mut expired = proof(
        &domain,
        &admin,
        admin.address(),
        empty,
        (1, 0, 0),
        admit(&[]),
    )?;
    expired.signed.op.issued_at = clock::unix_seconds()?.saturating_sub(601);
    expired.signed.op.expires_at = clock::unix_seconds()?.saturating_sub(1);
    assert!(store.commit(&expired).await.is_err());
    assert!(!store.snapshot().await?.clients.contains_key(&empty));
    let rejected: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM gateway_rejections WHERE domain=$1")
            .bind(domain.key().as_slice())
            .fetch_one(&pool)
            .await?;
    assert!(rejected >= 1);
    let _: i64 = sqlx::query("SELECT head FROM gateway_heads WHERE domain=$1")
        .bind(domain.key().as_slice())
        .fetch_one(&pool)
        .await?
        .try_get("head")?;
    let overflow_owner = Address::random();
    let old_id = store
        .record(LogRecord {
            principal: Some(principal(overflow_owner, u64::MAX, token)),
            token_id: Some(token),
            label: None,
            account: None,
            tempo_hash: None,
            zone_hash: None,
            method: "indexer.register".into(),
            decision: "allow".into(),
            offset: next,
        })
        .await?;
    store.complete(old_id, "registered").await?;
    let logged = store
        .logs(&principal(overflow_owner, u64::MAX, token), false, 0, 100)
        .await?;
    assert_eq!(logged[0]["generation"], json!(u64::MAX));
    assert_eq!(logged[0]["method"], "indexer.register");
    assert_eq!(logged[0]["completions"][0]["outcome"], "registered");
    sqlx::query("UPDATE gateway_decisions SET created_at=NOW()-INTERVAL '2 hours' WHERE domain=$1 AND id=$2")
        .bind(domain.key().as_slice()).bind(old_id).execute(&pool).await?;
    assert_eq!(store.retain_logs(3600).await?, 1);
    assert_eq!(
        store
            .logs(&principal(overflow_owner, u64::MAX, token), false, 0, 100)
            .await?,
        json!([])
    );
    assert!(
        store.receipt(last.signed.op.digest()).await?.is_some(),
        "request retention must not remove signed history"
    );
    assert!(store.retain_logs(0).await.is_err());

    let conflicting_client = Address::random();
    let first_change = proof(
        &domain,
        &admin,
        admin.address(),
        conflicting_client,
        (1, 0, 0),
        admit(&[Scope::RpcRead]),
    )?;
    let second_change = proof(
        &domain,
        &admin,
        admin.address(),
        conflicting_client,
        (1, 0, 0),
        admit(&[Scope::RpcWrite]),
    )?;
    let (a, b) = tokio::join!(store.commit(&first_change), peer.commit(&second_change));
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "only one digest can win a target sequence"
    );
    let registry = store.snapshot().await?;
    assert_eq!(registry.clients[&conflicting_client].seq, 1);
    assert!(
        registry.clients[&conflicting_client].scopes == [Scope::RpcRead].into_iter().collect()
            || registry.clients[&conflicting_client].scopes
                == [Scope::RpcWrite].into_iter().collect()
    );

    let expires_client = Address::random();
    let mut short = proof(
        &domain,
        &admin,
        admin.address(),
        expires_client,
        (1, 0, 0),
        admit(&[]),
    )?;
    short.signed.op.expires_at = short.signed.op.issued_at + 2;
    short.signed.signature =
        Bytes::copy_from_slice(&admin.sign_hash_sync(&short.signed.op.digest())?.as_bytes());
    let original = store.commit(&short).await?;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    short.observed_at = 0.0;
    assert_eq!(
        peer.commit(&short).await?,
        original,
        "an expired operation's exact retry returns its durable original receipt"
    );
    assert_eq!(
        store.retry_signed(&short.signed).await?,
        Some(original),
        "historical exact signature retry needs no current contract or chain proof"
    );

    Ok(())
}
