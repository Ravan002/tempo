//! The PostgreSQL Zone head is the serialization point for all registry mutations.
use crate::{archive::DirectoryArchive, chain::VerifiedOperation, clock};
use alloy_primitives::{Address, B256, keccak256};
use eyre::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{
    PgPool, Row,
    postgres::{PgPoolOptions, PgRow},
    types::Json,
};
use std::{path::Path, sync::Arc, time::Duration};
use zone_auth::{Domain, Principal, Receipt, Registry, Scope, SignedOp};

const DEADLINE: Duration = Duration::from_secs(2);
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    domain: Domain,
    archive: Arc<DirectoryArchive>,
}
enum CommitOutcome {
    Applied(Receipt),
    Duplicate(Receipt),
    Rejected(eyre::Report),
}
fn operation_metric(change: &zone_auth::Change, outcome: &'static str) {
    let kind = match change {
        zone_auth::Change::Admit { .. } => "admit",
        zone_auth::Change::Rename { .. } => "rename",
        zone_auth::Change::SetScopes { .. } => "set_scopes",
        zone_auth::Change::ReplaceAccounts { .. } => "replace_accounts",
        zone_auth::Change::AddAccounts { .. } => "add_accounts",
        zone_auth::Change::RemoveAccounts { .. } => "remove_accounts",
        zone_auth::Change::RevokeToken { .. } => "revoke_token",
        zone_auth::Change::Remove => "remove",
    };
    metrics::counter!("zone_access_op_total", "change_kind" => kind, "outcome" => outcome)
        .increment(1);
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchivedEvent {
    pub version: u32,
    pub domain_key: B256,
    pub offset: u64,
    pub previous_hash: B256,
    pub digest: B256,
    pub signed: SignedOp,
    pub zone_admin: Address,
    pub tempo_hash: B256,
    pub hash: B256,
}
impl ArchivedEvent {
    fn calculated_hash(&self) -> Result<B256> {
        #[derive(Serialize)]
        struct Content<'a> {
            version: u32,
            domain_key: B256,
            offset: u64,
            previous_hash: B256,
            digest: B256,
            signed: &'a SignedOp,
            zone_admin: Address,
            tempo_hash: B256,
        }
        Ok(keccak256(serde_json::to_vec(&Content {
            version: self.version,
            domain_key: self.domain_key,
            offset: self.offset,
            previous_hash: self.previous_hash,
            digest: self.digest,
            signed: &self.signed,
            zone_admin: self.zone_admin,
            tempo_hash: self.tempo_hash,
        })?))
    }
    pub(crate) fn validate_hash(&self) -> Result<()> {
        if self.version != 1
            || self.hash != self.calculated_hash()?
            || self.digest != self.signed.op.digest()
        {
            bail!("invalid registry event version, digest, or hash");
        }
        Ok(())
    }
}

pub struct LogRecord {
    pub principal: Option<Principal>,
    pub token_id: Option<B256>,
    pub label: Option<String>,
    pub account: Option<Address>,
    pub tempo_hash: Option<B256>,
    pub zone_hash: Option<B256>,
    pub method: String,
    pub decision: String,
    pub offset: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub id: String,
    pub owner: Address,
    pub generation: u64,
    pub encrypted_credential: Vec<u8>,
    pub endpoint: String,
    pub cursor: u64,
    pub paused: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEvent {
    pub event_id: String,
    pub cursor: u64,
    pub payload: Value,
}
pub struct DeliveryJob {
    pub registration_id: String,
    pub event_id: String,
    pub cursor: u64,
    pub payload: Value,
    pub fence: i64,
    pub attempts: u64,
}
fn db_offset(value: u64) -> Result<i64> {
    i64::try_from(value).wrap_err("database offset exceeds signed range")
}
fn wire_offset(value: i64) -> Result<u64> {
    u64::try_from(value).wrap_err("negative database offset")
}
fn domain_bytes(domain: &Domain) -> Vec<u8> {
    domain.key().as_slice().to_vec()
}
fn receipt_for(event: &ArchivedEvent, registry: &Registry) -> Result<Receipt> {
    let client = registry
        .clients
        .get(&event.signed.op.client)
        .ok_or_else(|| eyre::eyre!("event client absent after replay"))?;
    Ok(Receipt {
        digest: event.digest,
        client: client.address,
        seq: client.seq,
        generation: client.generation,
        offset: event.offset,
    })
}
fn replay(domain: &Domain, events: &[ArchivedEvent]) -> Result<Registry> {
    let started = clock::continuous_seconds();
    let result = replay_checked(domain, events);
    metrics::histogram!("zone_access_replay_seconds").record(clock::continuous_seconds() - started);
    result
}
fn replay_checked(domain: &Domain, events: &[ArchivedEvent]) -> Result<Registry> {
    let mut registry = Registry::default();
    let mut hash = B256::ZERO;
    for event in events {
        event.validate_hash()?;
        if event.domain_key != domain.key()
            || &event.signed.op.domain != domain
            || event.offset
                != registry
                    .offset
                    .checked_add(1)
                    .ok_or_else(|| eyre::eyre!("registry offset overflow"))?
            || event.previous_hash != hash
        {
            bail!("registry domain, offset or hash-chain mismatch");
        }
        registry
            .apply(&event.signed.op, event.zone_admin)
            .wrap_err("historical registry reducer rejected event")?;
        if registry.offset != event.offset {
            bail!("registry reducer offset mismatch");
        }
        hash = event.hash;
    }
    Ok(registry)
}
fn new_op_time(signed: &SignedOp) -> Result<()> {
    let now = clock::unix_seconds()?;
    let op = &signed.op;
    let ttl = op
        .expires_at
        .checked_sub(op.issued_at)
        .ok_or_else(|| eyre::eyre!("operation expiry precedes issuance"))?;
    if ttl > 600
        || op.expires_at <= now
        || op.issued_at
            > now
                .checked_add(60)
                .ok_or_else(|| eyre::eyre!("UTC overflow"))?
    {
        bail!("operation expired or outside issuance window");
    }
    Ok(())
}

impl Store {
    pub async fn open(database_url: &str, domain: Domain, archive_dir: &Path) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(DEADLINE)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET statement_timeout = '2s'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET lock_timeout = '2s'")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await?;
        let mut migration = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(724619801645041)")
            .execute(&mut *migration)
            .await?;
        for statement in include_str!("../migrations/0001_gateway.sql").split(';') {
            if !statement.trim().is_empty() {
                sqlx::query(statement).execute(&mut *migration).await?;
            }
        }
        migration.commit().await?;
        let archive = Arc::new(DirectoryArchive::new(archive_dir, domain.key())?);
        sqlx::query("INSERT INTO gateway_heads(domain,event_hash,registry) VALUES($1,$2,$3) ON CONFLICT(domain) DO NOTHING")
   .bind(domain_bytes(&domain)).bind(B256::ZERO.as_slice()).bind(Json(serde_json::to_value(Registry::default())?)).execute(&pool).await?;
        let store = Self {
            pool,
            domain,
            archive,
        };
        store.recover().await?;
        Ok(store)
    }
    pub async fn snapshot(&self) -> Result<Registry> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT head,event_hash,registry FROM gateway_heads WHERE domain=$1 FOR SHARE",
        )
        .bind(domain_bytes(&self.domain))
        .fetch_one(&mut *tx)
        .await?;
        let rows = sqlx::query(
            "SELECT log_offset,event,receipt FROM gateway_events WHERE domain=$1 ORDER BY log_offset",
        )
        .bind(domain_bytes(&self.domain))
        .fetch_all(&mut *tx)
        .await?;
        let mut events = Vec::with_capacity(rows.len());
        for row in &rows {
            let event: ArchivedEvent =
                serde_json::from_value(row.try_get::<Json<Value>, _>("event")?.0)?;
            if event.offset != wire_offset(row.try_get("log_offset")?)? {
                bail!("event row offset mismatch");
            }
            events.push(event);
        }
        let registry = replay(&self.domain, &events)?;
        let expected_hash = events.last().map(|e| e.hash).unwrap_or(B256::ZERO);
        if registry.offset != wire_offset(row.try_get("head")?)?
            || row.try_get::<Vec<u8>, _>("event_hash")? != expected_hash.as_slice()
            || row.try_get::<Json<Value>, _>("registry")?.0 != serde_json::to_value(&registry)?
        {
            bail!("materialized registry diverges from signed history");
        }
        let mut partial = Registry::default();
        for (event, row) in events.iter().zip(&rows) {
            partial.apply(&event.signed.op, event.zone_admin)?;
            if row.try_get::<Json<Value>, _>("receipt")?.0
                != serde_json::to_value(receipt_for(event, &partial)?)?
            {
                bail!("stored receipt diverges from signed history");
            }
        }
        tx.commit().await?;
        Ok(registry)
    }
    pub async fn commit(&self, proof: &VerifiedOperation) -> Result<Receipt> {
        let digest = proof.signed.op.digest();
        let started = clock::continuous_seconds();
        let attempt = tokio::time::timeout(DEADLINE, self.commit_database(proof)).await;
        metrics::histogram!("zone_access_log_commit_seconds", "stage" => "mutation")
            .record(clock::continuous_seconds() - started);
        let (receipt, outcome) = match attempt {
            Ok(Ok(CommitOutcome::Applied(receipt))) => (receipt, "applied"),
            Ok(Ok(CommitOutcome::Duplicate(receipt))) => (receipt, "duplicate"),
            Ok(Ok(CommitOutcome::Rejected(error))) => {
                operation_metric(&proof.signed.op.change, "rejected");
                return Err(error);
            }
            Ok(Err(error)) => {
                operation_metric(&proof.signed.op.change, "unknown");
                return Err(error);
            }
            Err(_) => {
                operation_metric(&proof.signed.op.change, "unknown");
                bail!("unknown outcome for operation {digest}: database deadline");
            }
        };
        if let Err(error) = self.archive_receipt(&receipt).await {
            operation_metric(&proof.signed.op.change, "unknown");
            return Err(error);
        }
        operation_metric(&proof.signed.op.change, outcome);
        Ok(receipt)
    }
    async fn commit_database(&self, proof: &VerifiedOperation) -> Result<CommitOutcome> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT head,event_hash,registry FROM gateway_heads WHERE domain=$1 FOR UPDATE",
        )
        .bind(domain_bytes(&self.domain))
        .fetch_one(&mut *tx)
        .await?;
        let digest = proof.signed.op.digest();
        if let Some(receipt) =
            sqlx::query("SELECT receipt FROM gateway_events WHERE domain=$1 AND digest=$2")
                .bind(domain_bytes(&self.domain))
                .bind(digest.as_slice())
                .fetch_optional(&mut *tx)
                .await?
        {
            let receipt: Receipt =
                serde_json::from_value(receipt.try_get::<Json<Value>, _>("receipt")?.0)?;
            self.mutation_log(
                &mut tx,
                &proof.signed.op,
                (proof.zone_admin, proof.tempo_hash),
                "duplicate",
                receipt.offset,
            )
            .await?;
            tx.commit().await?;
            return Ok(CommitOutcome::Duplicate(receipt));
        }
        let mut registry: Registry =
            serde_json::from_value(row.try_get::<Json<Value>, _>("registry")?.0)?;
        let validation = (|| -> Result<()> {
            if proof.signed.op.domain != self.domain {
                bail!("operation domain mismatch");
            }
            if !proof.fresh() {
                bail!("operation verification evidence expired");
            }
            new_op_time(&proof.signed)?;
            if registry.offset != wire_offset(row.try_get("head")?)? {
                bail!("materialized head mismatch");
            }
            registry.apply(&proof.signed.op, proof.zone_admin)?;
            Ok(())
        })();
        if let Err(error) = validation {
            let reason = format!("{error}");
            sqlx::query("INSERT INTO gateway_rejections(domain,digest,reason) VALUES($1,$2,$3)")
                .bind(domain_bytes(&self.domain))
                .bind(digest.as_slice())
                .bind(reason.chars().take(512).collect::<String>())
                .execute(&mut *tx)
                .await?;
            self.mutation_log(
                &mut tx,
                &proof.signed.op,
                (proof.zone_admin, proof.tempo_hash),
                "rejected",
                wire_offset(row.try_get("head")?)?,
            )
            .await?;
            tx.commit().await?;
            return Ok(CommitOutcome::Rejected(error));
        }
        let previous_bytes: Vec<u8> = row.try_get("event_hash")?;
        let mut event = ArchivedEvent {
            version: 1,
            domain_key: self.domain.key(),
            offset: registry.offset,
            previous_hash: B256::try_from(previous_bytes.as_slice())?,
            digest,
            signed: proof.signed.clone(),
            zone_admin: proof.zone_admin,
            tempo_hash: proof.tempo_hash,
            hash: B256::ZERO,
        };
        event.hash = event.calculated_hash()?;
        let receipt = receipt_for(&event, &registry)?;
        sqlx::query("INSERT INTO gateway_events(domain,log_offset,digest,client,sequence,event,receipt) VALUES($1,$2,$3,$4,$5::text::numeric,$6,$7)")
   .bind(domain_bytes(&self.domain)).bind(db_offset(event.offset)?).bind(digest.as_slice()).bind(receipt.client.as_slice()).bind(receipt.seq.to_string()).bind(Json(serde_json::to_value(&event)?)).bind(Json(serde_json::to_value(&receipt)?)).execute(&mut *tx).await?;
        sqlx::query("UPDATE gateway_heads SET head=$2,event_hash=$3,registry=$4 WHERE domain=$1")
            .bind(domain_bytes(&self.domain))
            .bind(db_offset(registry.offset)?)
            .bind(event.hash.as_slice())
            .bind(Json(serde_json::to_value(registry)?))
            .execute(&mut *tx)
            .await?;
        self.mutation_log(
            &mut tx,
            &proof.signed.op,
            (proof.zone_admin, proof.tempo_hash),
            "applied",
            receipt.offset,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| eyre::eyre!("unknown outcome for operation {digest}: {e}"))?;
        Ok(CommitOutcome::Applied(receipt))
    }
    async fn mutation_log(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        op: &zone_auth::AccessOp,
        (zone_admin, tempo_hash): (Address, B256),
        decision: &str,
        offset: u64,
    ) -> Result<()> {
        let is_admin = op.signer == zone_admin && op.signer_generation == 0;
        let kind = if is_admin { "admin" } else { "client" };
        let generation = (!is_admin).then(|| op.signer_generation.to_string());
        sqlx::query("INSERT INTO gateway_decisions(domain,principal_kind,principal,generation,method,decision,log_offset,tempo_hash) VALUES($1,$2,$3,$4::text::numeric,'zone_applyAccessOp',$5,$6,$7)")
            .bind(domain_bytes(&self.domain)).bind(kind).bind(op.signer.as_slice())
            .bind(generation).bind(decision).bind(db_offset(offset)?).bind(tempo_hash.as_slice())
            .execute(&mut **tx).await?;
        Ok(())
    }
    async fn archive_receipt(&self, receipt: &Receipt) -> Result<()> {
        tokio::time::timeout(DEADLINE, async {
            self.sync_archive().await?;
            let archive = self.archive.clone();
            let (mark, _) = tokio::task::spawn_blocking(move || archive.covered()).await??;
            if mark.offset < receipt.offset {
                bail!("receipt is not covered by the archive watermark");
            }
            Ok::<(), eyre::Report>(())
        })
        .await
        .map_err(|_| {
            eyre::eyre!(
                "unknown outcome for operation {}: archive deadline",
                receipt.digest
            )
        })?
        .wrap_err_with(|| {
            format!(
                "unknown outcome for operation {}: archive unavailable",
                receipt.digest
            )
        })
    }
    /// Resolve an exact authenticated historical submission without requiring today's contract validator.
    pub async fn retry_signed(&self, signed: &SignedOp) -> Result<Option<Receipt>> {
        if signed.op.domain != self.domain {
            bail!("operation domain mismatch");
        }
        let receipt = match tokio::time::timeout(DEADLINE, self.retry_signed_database(signed)).await
        {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => {
                operation_metric(&signed.op.change, "unknown");
                return Err(error);
            }
            Err(_) => {
                operation_metric(&signed.op.change, "unknown");
                bail!("receipt lookup database deadline");
            }
        };
        if let Some(receipt) = &receipt {
            if let Err(error) = self.archive_receipt(receipt).await {
                operation_metric(&signed.op.change, "unknown");
                return Err(error);
            }
            operation_metric(&signed.op.change, "duplicate");
        }
        Ok(receipt)
    }
    async fn retry_signed_database(&self, signed: &SignedOp) -> Result<Option<Receipt>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT head FROM gateway_heads WHERE domain=$1 FOR UPDATE")
            .bind(domain_bytes(&self.domain))
            .fetch_one(&mut *tx)
            .await?;
        let row =
            sqlx::query("SELECT event,receipt FROM gateway_events WHERE domain=$1 AND digest=$2")
                .bind(domain_bytes(&self.domain))
                .bind(signed.op.digest().as_slice())
                .fetch_optional(&mut *tx)
                .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let event: ArchivedEvent =
            serde_json::from_value(row.try_get::<Json<Value>, _>("event")?.0)?;
        event.validate_hash()?;
        if event.domain_key != self.domain.key() || event.signed.op.domain != self.domain {
            bail!("historical event domain mismatch");
        }
        if event.signed != *signed {
            tx.commit().await?;
            return Ok(None);
        }
        let receipt: Receipt = serde_json::from_value(row.try_get::<Json<Value>, _>("receipt")?.0)?;
        let generation = if matches!(signed.op.change, zone_auth::Change::Admit { .. }) {
            signed
                .op
                .generation
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("historical generation overflow"))?
        } else {
            signed.op.generation
        };
        if receipt.digest != event.digest
            || receipt.client != signed.op.client
            || receipt.seq != signed.op.seq
            || receipt.generation != generation
            || receipt.offset != event.offset
        {
            bail!("historical receipt mismatch");
        }
        self.mutation_log(
            &mut tx,
            &event.signed.op,
            (event.zone_admin, event.tempo_hash),
            "duplicate",
            receipt.offset,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(receipt))
    }
    pub async fn receipt(&self, digest: B256) -> Result<Option<Receipt>> {
        let row = sqlx::query("SELECT receipt FROM gateway_events WHERE domain=$1 AND digest=$2")
            .bind(domain_bytes(&self.domain))
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            let receipt: Receipt =
                serde_json::from_value(row.try_get::<Json<Value>, _>("receipt")?.0)?;
            self.archive_receipt(&receipt).await?;
            Ok(Some(receipt))
        } else {
            Ok(None)
        }
    }
    pub async fn sync_archive(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let row =
            sqlx::query("SELECT head,archived_head FROM gateway_heads WHERE domain=$1 FOR UPDATE")
                .bind(domain_bytes(&self.domain))
                .fetch_one(&mut *tx)
                .await?;
        let archive = self.archive.clone();
        let (old_mark, _) = tokio::task::spawn_blocking(move || archive.covered()).await??;
        if old_mark.offset < wire_offset(row.try_get("archived_head")?)? {
            bail!("independent archive watermark regressed");
        }
        let head = wire_offset(row.try_get("head")?)?;
        if let Some(pending) = head.checked_sub(old_mark.offset) {
            metrics::gauge!("zone_access_archive_pending_events").set(pending as f64);
        }
        let rows = sqlx::query(
            "SELECT log_offset,event FROM gateway_events WHERE domain=$1 ORDER BY log_offset",
        )
        .bind(domain_bytes(&self.domain))
        .fetch_all(&mut *tx)
        .await?;
        let events: Vec<ArchivedEvent> = rows
            .into_iter()
            .map(|row| -> Result<_> {
                let event: ArchivedEvent =
                    serde_json::from_value(row.try_get::<Json<Value>, _>("event")?.0)?;
                if event.offset != wire_offset(row.try_get("log_offset")?)? {
                    bail!("event row offset mismatch");
                }
                Ok(event)
            })
            .collect::<Result<_>>()?;
        let registry = replay(&self.domain, &events)?;
        if registry.offset != wire_offset(row.try_get("head")?)? {
            bail!("database history missing below committed head");
        }
        let archive = self.archive.clone();
        let mark = tokio::task::spawn_blocking(move || archive.publish(&events)).await??;
        if mark.offset != registry.offset {
            bail!("archive contains history missing from the database; recovery required");
        }
        sqlx::query("UPDATE gateway_heads SET archived_head=$2 WHERE domain=$1")
            .bind(domain_bytes(&self.domain))
            .bind(db_offset(mark.offset)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        metrics::gauge!("zone_access_archive_pending_events").set(0.0);
        Ok(())
    }
    pub async fn recover(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let row =
            sqlx::query("SELECT head,archived_head FROM gateway_heads WHERE domain=$1 FOR UPDATE")
                .bind(domain_bytes(&self.domain))
                .fetch_one(&mut *tx)
                .await?;
        let archive = self.archive.clone();
        let (mark, archive_events) =
            tokio::task::spawn_blocking(move || archive.covered()).await??;
        replay(&self.domain, &archive_events)?;
        let head = wire_offset(row.try_get("head")?)?;
        if mark.offset < wire_offset(row.try_get("archived_head")?)? {
            bail!("independent archive watermark regressed");
        }
        let rows =
            sqlx::query("SELECT event FROM gateway_events WHERE domain=$1 ORDER BY log_offset")
                .bind(domain_bytes(&self.domain))
                .fetch_all(&mut *tx)
                .await?;
        let events: Vec<ArchivedEvent> = rows
            .into_iter()
            .map(|r| {
                serde_json::from_value(r.try_get::<Json<Value>, _>("event")?.0).map_err(Into::into)
            })
            .collect::<Result<_>>()?;
        let mut registry = replay(&self.domain, &events)?;
        if registry.offset != head {
            bail!("database history missing below committed head");
        }
        for (db, archived) in events.iter().zip(&archive_events) {
            if db.hash != archived.hash {
                bail!("database and independent archive diverge");
            }
        }
        for event in archive_events.iter().filter(|e| e.offset > head) {
            registry.apply(&event.signed.op, event.zone_admin)?;
            let receipt = receipt_for(event, &registry)?;
            sqlx::query("INSERT INTO gateway_events(domain,log_offset,digest,client,sequence,event,receipt) VALUES($1,$2,$3,$4,$5::text::numeric,$6,$7)")
    .bind(domain_bytes(&self.domain)).bind(db_offset(event.offset)?).bind(event.digest.as_slice()).bind(receipt.client.as_slice()).bind(receipt.seq.to_string()).bind(Json(serde_json::to_value(event)?)).bind(Json(serde_json::to_value(&receipt)?)).execute(&mut *tx).await?;
        }
        let hash = if mark.offset > head {
            mark.hash
        } else {
            events.last().map(|e| e.hash).unwrap_or(B256::ZERO)
        };
        sqlx::query("UPDATE gateway_heads SET head=$2,event_hash=$3,archived_head=$4,registry=$5 WHERE domain=$1").bind(domain_bytes(&self.domain)).bind(db_offset(registry.offset)?).bind(hash.as_slice()).bind(db_offset(mark.offset)?).bind(Json(serde_json::to_value(registry)?)).execute(&mut *tx).await?;
        tx.commit().await?;
        self.snapshot().await?;
        self.sync_archive().await
    }
    pub async fn record(&self, record: LogRecord) -> Result<i64> {
        if record.label.as_ref().is_some_and(|s| s.len() > 64)
            || record.decision.len() > 64
            || !record.decision.is_ascii()
        {
            bail!("log field exceeds bound");
        }
        let (kind, address, generation) = match record.principal.as_ref() {
            Some(Principal::Account(address)) => {
                ("account", Some(address.as_slice().to_vec()), None)
            }
            Some(Principal::Client {
                address,
                generation,
                ..
            }) => (
                "client",
                Some(address.as_slice().to_vec()),
                Some(generation.to_string()),
            ),
            Some(Principal::ZoneAdmin(address)) => {
                ("admin", Some(address.as_slice().to_vec()), None)
            }
            None => ("unverified", None, None),
        };
        let method = if zone_auth::RpcMethod::from_name(&record.method).is_some()
            || matches!(
                record.method.as_str(),
                "eth_subscribe"
                    | "eth_unsubscribe"
                    | "zone_applyAccessOp"
                    | "zone_getClient"
                    | "zone_listAccess"
                    | "zone_getAccessReceipt"
                    | "zone_registerDelivery"
                    | "zone_removeDelivery"
                    | "zone_renewDelivery"
                    | "indexer.query"
                    | "indexer.stream"
                    | "indexer.delivery"
                    | "indexer.register"
                    | "indexer.renew"
                    | "indexer.remove"
            ) {
            record.method.as_str()
        } else {
            "unknown"
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let row=sqlx::query("INSERT INTO gateway_decisions(domain,principal_kind,principal,generation,token_id,label,account,method,decision,log_offset,tempo_hash,zone_hash) VALUES($1,$2,$3,$4::text::numeric,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id")
   .bind(domain_bytes(&self.domain)).bind(kind).bind(address).bind(generation).bind(record.token_id.map(|id|id.as_slice().to_vec())).bind(record.label).bind(record.account.map(|a|a.as_slice().to_vec())).bind(method).bind(record.decision).bind(db_offset(record.offset)?).bind(record.tempo_hash.map(|h|h.as_slice().to_vec())).bind(record.zone_hash.map(|h|h.as_slice().to_vec())).fetch_one(&mut *tx).await?;
        let id = row.try_get("id")?;
        tx.commit().await?;
        Ok(id)
    }
    pub async fn complete(&self, id: i64, outcome: &str) -> Result<()> {
        let started = clock::continuous_seconds();
        let result = self.complete_database(id, outcome).await;
        metrics::histogram!("zone_access_log_commit_seconds", "stage" => "completion")
            .record(clock::continuous_seconds() - started);
        result
    }
    async fn complete_database(&self, id: i64, outcome: &str) -> Result<()> {
        if outcome.len() > 64 || !outcome.is_ascii() {
            bail!("completion outcome exceeds bound");
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let result=sqlx::query("INSERT INTO gateway_completions(decision_id,outcome) SELECT id,$3 FROM gateway_decisions WHERE domain=$1 AND id=$2 ON CONFLICT DO NOTHING")
   .bind(domain_bytes(&self.domain)).bind(id).bind(outcome).execute(&mut *tx).await?;
        if result.rows_affected() == 0 {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gateway_decisions WHERE domain=$1 AND id=$2)",
            )
            .bind(domain_bytes(&self.domain))
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if !exists {
                bail!("decision not found");
            }
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn logs(
        &self,
        viewer: &Principal,
        all: bool,
        after: i64,
        limit: u32,
    ) -> Result<Value> {
        if after < 0 || limit == 0 || limit > 1000 {
            bail!("invalid log pagination");
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT registry FROM gateway_heads WHERE domain=$1 FOR SHARE")
            .bind(domain_bytes(&self.domain))
            .fetch_one(&mut *tx)
            .await?;
        let registry: Registry =
            serde_json::from_value(row.try_get::<Json<Value>, _>("registry")?.0)?;
        if all
            && !match viewer {
                Principal::ZoneAdmin(_) => true,
                Principal::Client {
                    address,
                    generation,
                    token_id,
                    ..
                } => {
                    registry.clients.get(address).is_some_and(|c| {
                        c.active && c.generation == *generation && c.scopes.contains(&Scope::Admin)
                    }) && !registry.revoked.contains(&zone_auth::RevocationKey {
                        client: *address,
                        generation: *generation,
                        token_id: *token_id,
                    })
                }
                Principal::Account(_) => false,
            }
        {
            bail!("all log access requires current admin authority");
        }
        let (kind, address, generation) = match viewer {
            Principal::Account(a) => ("account", a, None),
            Principal::Client {
                address,
                generation,
                ..
            } => ("client", address, Some(generation.to_string())),
            Principal::ZoneAdmin(a) => ("admin", a, None),
        };
        let rows=sqlx::query("SELECT id,principal_kind,principal,generation::text AS generation,token_id,label,account,tempo_hash,zone_hash,method,decision,log_offset,created_at::text AS created_at,COALESCE((SELECT jsonb_agg(jsonb_build_object('outcome',c.outcome,'created_at',c.created_at::text) ORDER BY c.created_at,c.outcome) FROM gateway_completions c WHERE c.decision_id=gateway_decisions.id),'[]'::jsonb) AS completions FROM gateway_decisions WHERE domain=$1 AND id>$2 AND ($3 OR (principal_kind=$4 AND principal=$5 AND generation IS NOT DISTINCT FROM $6::text::numeric)) ORDER BY id LIMIT $7")
   .bind(domain_bytes(&self.domain)).bind(after).bind(all).bind(kind).bind(address.as_slice()).bind(generation).bind(i64::from(limit)).fetch_all(&mut *tx).await?;
        let values=rows.into_iter().map(|row|->Result<Value>{
   let hex_column=|name:&str|->Result<Option<String>>{ Ok(row.try_get::<Option<Vec<u8>>,_>(name)?.map(|bytes|format!("0x{}",alloy_primitives::hex::encode(bytes)))) };
   let generation=row.try_get::<Option<String>,_>("generation")?.map(|g|g.parse::<u64>()).transpose()?;
   Ok(json!({"id":row.try_get::<i64,_>("id")?,"principal_kind":row.try_get::<String,_>("principal_kind")?,"principal":hex_column("principal")?,"generation":generation,"token_id":hex_column("token_id")?,"label":row.try_get::<Option<String>,_>("label")?,"account":hex_column("account")?,"tempo_hash":hex_column("tempo_hash")?,"zone_hash":hex_column("zone_hash")?,"method":row.try_get::<String,_>("method")?,"decision":row.try_get::<String,_>("decision")?,"offset":wire_offset(row.try_get("log_offset")?)?,"created_at":row.try_get::<String,_>("created_at")?,"completions":row.try_get::<Json<Value>,_>("completions")?.0}))
  }).collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(Value::Array(values))
    }
    /// Delete bounded batches of expired request logs; signed history is retained independently.
    pub async fn retain_logs(&self, retention_seconds: u64) -> Result<u64> {
        if retention_seconds == 0 {
            bail!("log retention must be positive");
        }
        let retention = i64::try_from(retention_seconds)
            .wrap_err("log retention exceeds PostgreSQL interval range")?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM gateway_decisions WHERE domain=$1 AND created_at < NOW()-($2::text || ' seconds')::interval ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1000")
            .bind(domain_bytes(&self.domain)).bind(retention.to_string()).fetch_all(&mut *tx).await?;
        sqlx::query("DELETE FROM gateway_completions WHERE decision_id=ANY($1)")
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM gateway_decisions WHERE domain=$1 AND id=ANY($2)")
            .bind(domain_bytes(&self.domain))
            .bind(&ids)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }
    pub async fn put_registration(&self, registration: &Registration) -> Result<()> {
        if registration.id.is_empty()
            || registration.id.len() > 128
            || registration.endpoint.len() > 2048
            || registration.encrypted_credential.is_empty()
            || registration.encrypted_credential.len() > 16384
        {
            bail!("invalid registration bounds");
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let result=sqlx::query("INSERT INTO gateway_registrations(domain,id,owner,generation,encrypted_credential,endpoint,ingest_cursor,ack_cursor,paused) VALUES($1,$2,$3,$4::text::numeric,$5,$6,$7::text::numeric,$7::text::numeric,$8) ON CONFLICT(domain,id) DO UPDATE SET encrypted_credential=EXCLUDED.encrypted_credential,endpoint=EXCLUDED.endpoint,paused=EXCLUDED.paused WHERE gateway_registrations.owner=EXCLUDED.owner AND gateway_registrations.generation=EXCLUDED.generation")
   .bind(domain_bytes(&self.domain)).bind(&registration.id).bind(registration.owner.as_slice()).bind(registration.generation.to_string()).bind(&registration.encrypted_credential).bind(&registration.endpoint).bind(registration.cursor.to_string()).bind(registration.paused).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            bail!("registration belongs to another owner or admission generation");
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn registrations(&self) -> Result<Vec<Registration>> {
        let rows=sqlx::query("SELECT id,owner,generation::text AS generation,encrypted_credential,endpoint,ingest_cursor::text AS cursor,paused FROM gateway_registrations WHERE domain=$1 ORDER BY id").bind(domain_bytes(&self.domain)).fetch_all(&self.pool).await?;
        rows.into_iter().map(registration_row).collect()
    }
    pub async fn get_registration(&self, id: &str) -> Result<Option<Registration>> {
        let row=sqlx::query("SELECT id,owner,generation::text AS generation,encrypted_credential,endpoint,ingest_cursor::text AS cursor,paused FROM gateway_registrations WHERE domain=$1 AND id=$2").bind(domain_bytes(&self.domain)).bind(id).fetch_optional(&self.pool).await?;
        row.map(registration_row).transpose()
    }
    pub async fn delete_registration(
        &self,
        id: &str,
        owner: Address,
        generation: u64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let exists=sqlx::query("SELECT id FROM gateway_registrations WHERE domain=$1 AND id=$2 AND owner=$3 AND generation=$4::text::numeric FOR UPDATE").bind(domain_bytes(&self.domain)).bind(id).bind(owner.as_slice()).bind(generation.to_string()).fetch_optional(&mut *tx).await?;
        if exists.is_none() {
            bail!("registration not found for this owner");
        }
        sqlx::query("DELETE FROM gateway_delivery_jobs WHERE domain=$1 AND registration_id=$2")
            .bind(domain_bytes(&self.domain))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM gateway_registrations WHERE domain=$1 AND id=$2")
            .bind(domain_bytes(&self.domain))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn pause_registration(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE gateway_registrations SET paused=TRUE WHERE domain=$1 AND id=$2")
            .bind(domain_bytes(&self.domain))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn ingest(
        &self,
        id: &str,
        expected_cursor: u64,
        events: &[DeliveryEvent],
        next_cursor: u64,
    ) -> Result<()> {
        if events.len() > 1000 || next_cursor < expected_cursor {
            bail!("invalid ingestion bounds");
        }
        let mut previous = expected_cursor;
        for event in events {
            if event.cursor <= previous
                || event.cursor > next_cursor
                || event.event_id.is_empty()
                || event.event_id.len() > 256
                || serde_json::to_vec(&event.payload)?.len() > 1024 * 1024
            {
                bail!("invalid event cursor, identity, or payload bound");
            }
            previous = event.cursor;
        }
        if next_cursor != previous {
            bail!("ingestion cursor must cover exactly the supplied events");
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let cursor:String=sqlx::query_scalar("SELECT ingest_cursor::text FROM gateway_registrations WHERE domain=$1 AND id=$2 FOR UPDATE").bind(domain_bytes(&self.domain)).bind(id).fetch_one(&mut *tx).await?;
        if cursor.parse::<u64>()? != expected_cursor {
            bail!("ingestion cursor changed concurrently");
        }
        for event in events {
            let existing=sqlx::query("SELECT cursor::text AS cursor,payload FROM gateway_delivery_jobs WHERE domain=$1 AND registration_id=$2 AND event_id=$3").bind(domain_bytes(&self.domain)).bind(id).bind(&event.event_id).fetch_optional(&mut *tx).await?;
            if let Some(row) = existing {
                if row.try_get::<String, _>("cursor")?.parse::<u64>()? != event.cursor
                    || row.try_get::<Json<Value>, _>("payload")?.0 != event.payload
                {
                    bail!("event ID reused with conflicting content");
                }
            } else {
                sqlx::query("INSERT INTO gateway_delivery_jobs(domain,registration_id,event_id,cursor,payload) VALUES($1,$2,$3,$4::text::numeric,$5)").bind(domain_bytes(&self.domain)).bind(id).bind(&event.event_id).bind(event.cursor.to_string()).bind(Json(&event.payload)).execute(&mut *tx).await?;
            }
        }
        sqlx::query("UPDATE gateway_registrations SET ingest_cursor=$3::text::numeric WHERE domain=$1 AND id=$2").bind(domain_bytes(&self.domain)).bind(id).bind(next_cursor.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn claim_delivery(&self, worker: &str) -> Result<Option<DeliveryJob>> {
        if worker.is_empty() || worker.len() > 128 {
            bail!("invalid worker identity");
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT j.registration_id,j.event_id,j.cursor::text AS cursor,j.payload,j.fence,j.attempts FROM gateway_delivery_jobs j JOIN gateway_registrations r ON r.domain=j.domain AND r.id=j.registration_id WHERE j.domain=$1 AND NOT r.paused AND NOT j.acknowledged AND j.next_attempt<=NOW() AND (j.lease_until IS NULL OR j.lease_until<NOW()) AND NOT EXISTS(SELECT 1 FROM gateway_delivery_jobs prior WHERE prior.domain=j.domain AND prior.registration_id=j.registration_id AND prior.cursor<j.cursor AND NOT prior.acknowledged) ORDER BY j.next_attempt,j.cursor FOR UPDATE OF j SKIP LOCKED LIMIT 1")
   .bind(domain_bytes(&self.domain)).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let fence = row
            .try_get::<i64, _>("fence")?
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("delivery fence overflow"))?;
        let attempts = row
            .try_get::<i64, _>("attempts")?
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("delivery attempt counter exhausted"))?;
        let job = DeliveryJob {
            registration_id: row.try_get("registration_id")?,
            event_id: row.try_get("event_id")?,
            cursor: row.try_get::<String, _>("cursor")?.parse()?,
            payload: row.try_get::<Json<Value>, _>("payload")?.0,
            fence,
            attempts: wire_offset(attempts)?,
        };
        sqlx::query("UPDATE gateway_delivery_jobs SET fence=$4,lease_owner=$5,lease_until=NOW()+INTERVAL '30 seconds',attempts=$6 WHERE domain=$1 AND registration_id=$2 AND event_id=$3")
   .bind(domain_bytes(&self.domain)).bind(&job.registration_id).bind(&job.event_id).bind(fence).bind(worker).bind(attempts).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(job))
    }
    pub async fn acknowledge_delivery(&self, job: &DeliveryJob) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT id FROM gateway_registrations WHERE domain=$1 AND id=$2 FOR UPDATE")
            .bind(domain_bytes(&self.domain))
            .bind(&job.registration_id)
            .fetch_one(&mut *tx)
            .await?;
        let row = sqlx::query("UPDATE gateway_delivery_jobs SET acknowledged=TRUE,lease_until=NULL WHERE domain=$1 AND registration_id=$2 AND event_id=$3 AND fence=$4 AND lease_until>=NOW() AND NOT acknowledged RETURNING cursor::text AS cursor")
            .bind(domain_bytes(&self.domain)).bind(&job.registration_id).bind(&job.event_id).bind(job.fence).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            bail!("delivery lease expired or fence changed");
        };
        let cursor = row.try_get::<String, _>("cursor")?.parse::<u64>()?;
        sqlx::query("UPDATE gateway_registrations SET ack_cursor=GREATEST(ack_cursor,$3::text::numeric) WHERE domain=$1 AND id=$2")
            .bind(domain_bytes(&self.domain)).bind(&job.registration_id).bind(cursor.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn retry_delivery(&self, job: &DeliveryJob, delay_secs: u64) -> Result<()> {
        let delay = i32::try_from(delay_secs.min(60))?;
        let result=sqlx::query("UPDATE gateway_delivery_jobs SET lease_until=NULL,next_attempt=NOW()+($5::double precision*INTERVAL '1 second') WHERE domain=$1 AND registration_id=$2 AND event_id=$3 AND fence=$4 AND NOT acknowledged")
   .bind(domain_bytes(&self.domain)).bind(&job.registration_id).bind(&job.event_id).bind(job.fence).bind(f64::from(delay)).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            bail!("delivery fence changed");
        }
        Ok(())
    }
}
fn registration_row(row: PgRow) -> Result<Registration> {
    Ok(Registration {
        id: row.try_get("id")?,
        owner: Address::try_from(row.try_get::<Vec<u8>, _>("owner")?.as_slice())?,
        generation: row.try_get::<String, _>("generation")?.parse()?,
        encrypted_credential: row.try_get("encrypted_credential")?,
        endpoint: row.try_get("endpoint")?,
        cursor: row.try_get::<String, _>("cursor")?.parse()?,
        paused: row.try_get("paused")?,
    })
}
