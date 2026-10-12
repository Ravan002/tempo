use crate::{
    chain::{ChainVerifier, VerificationError, VerifiedCredential},
    clock,
    config::Config,
    store::{LogRecord, Store},
    tls,
};
use alloy_primitives::{Address, B256};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eyre::{Result, ensure, eyre};
use futures::{SinkExt, StreamExt};
use rustls::ClientConfig;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock, Semaphore, watch},
};
use tokio_tungstenite::{
    Connector,
    tungstenite::{Message as UpstreamMessage, client::IntoClientRequest},
};
use uuid::Uuid;
use zone_auth::{Credential, Permission, Principal, Registry, Scope, SignedOp, rpc_permission};

pub struct Gateway;
#[derive(Debug, thiserror::Error)]
#[error("access denied")]
pub(crate) struct AccessDenied;
pub(crate) struct StateData {
    pub config: Config,
    pub store: Store,
    pub verifier: ChainVerifier,
    pub http: reqwest::Client,
    pub(crate) backend_tls: Arc<ClientConfig>,
    snapshot: RwLock<Option<(Registry, f64)>>,
    healthy_at: RwLock<Option<f64>>,
    stopping: AtomicBool,
    pub(crate) streams: Arc<Semaphore>,
    budgets: Mutex<Budget>,
    handles: Mutex<HashMap<String, Handle>>,
}
struct Budget {
    second: u64,
    calls: u32,
    bytes: u64,
}
#[derive(Clone)]
struct Handle {
    backend: Value,
    owner: Principal,
    account: Address,
    created_at: f64,
}
pub(crate) struct Admission {
    pub(crate) credential: Credential,
    pub(crate) proof: VerifiedCredential,
    pub(crate) account: Option<Address>,
    pub(crate) permission: Permission,
    pub(crate) log_id: i64,
    requires_admin: bool,
}

impl Gateway {
    pub async fn migrate(config: Config) -> Result<()> {
        config.validate()?;
        Store::open(&config.database_url, config.domain, &config.archive_dir).await?;
        Ok(())
    }
    pub async fn archive(config: Config) -> Result<()> {
        let store = Store::open(&config.database_url, config.domain, &config.archive_dir).await?;
        loop {
            tokio::select! { _ = tokio::signal::ctrl_c() => return Ok(()), _ = tokio::time::sleep(Duration::from_secs(1)) => store.sync_archive().await? }
        }
    }
    pub async fn verify_history(config: Config) -> Result<()> {
        let store = Store::open(&config.database_url, config.domain, &config.archive_dir).await?;
        store.recover().await?;
        let snapshot = store.snapshot().await?;
        println!(
            "Verified registry and archive through offset {}",
            snapshot.offset
        );
        Ok(())
    }
    pub async fn serve(config: Config) -> Result<()> {
        let listener = TcpListener::bind(config.listen).await?;
        Self::serve_on(config, listener, async {
            #[cfg(unix)]
            {
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(mut term) => {
                        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                    }
                    Err(_) => {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        })
        .await
    }
    pub async fn serve_on(
        config: Config,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> Result<()> {
        ensure!(
            listener.local_addr()?.ip().is_loopback() || config.frontend_tls.is_some(),
            "non-loopback listener requires frontend TLS"
        );
        let (router, state) = Self::build(config.clone()).await?;
        tokio::pin!(shutdown);
        tracing::info!(address = %listener.local_addr()?, "zones gateway listening");
        let (stop_tx, stop_rx) = watch::channel(false);
        let refresh_state = state.clone();
        let mut workers = tokio::task::JoinSet::new();
        let mut stopped = stop_rx.clone();
        workers.spawn(async move {
            loop {
                tokio::select! {
                    _ = stopped.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        if let Err(error) = refresh_state.refresh().await { tracing::warn!(error = %error, "registry refresh unavailable"); }

                    }
                }
            }
        });
        let health_state = state.clone();
        let mut health_stop = stop_rx.clone();
        workers.spawn(async move {
            loop {
                tokio::select! {
                    _ = health_stop.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        let started = clock::continuous_seconds();
                        let check = async {
                            health_state.verifier.health().await?;
                            let response = health_state.http.get(health_state.config.rpc_backend.join("/gateway/context")?).send().await?;
                            ensure!(response.status().is_success(), "backend unavailable");
                            let bytes = limited_response(response, 1024).await?;
                            ensure!(serde_json::from_slice::<Value>(&bytes)?.get("protocol") == Some(&json!(1)), "backend protocol unavailable");
                            Ok::<(), eyre::Report>(())
                        };
                        let healthy = matches!(tokio::time::timeout(Duration::from_secs(2), check).await, Ok(Ok(())));
                        *health_state.healthy_at.write().await = healthy.then_some(started);
                    }
                }
            }
        });
        let retention_state = state.clone();
        let mut retention_stop = stop_rx.clone();
        workers.spawn(async move {
            loop {
                tokio::select! {
                    _ = retention_stop.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        if let Err(error) = retention_state.store.retain_logs(retention_state.config.log_retention_seconds).await {
                            tracing::warn!(error = %error, "request log retention deferred");
                        }
                    }
                }
            }
        });
        let server = tls::serve_public(listener, router, config.frontend_tls.clone(), stop_rx);
        tokio::pin!(server);
        let (result, finished) = tokio::select! {
            result = &mut server => (result, true),
            _ = &mut shutdown => (Ok(()), false),
            result = workers.join_next() => (Err(eyre!("gateway worker stopped unexpectedly: {result:?}")), false),
        };
        state.stopping.store(true, Ordering::Release);
        let _ = stop_tx.send(true);
        if !finished {
            let _ = tokio::time::timeout(Duration::from_secs(10), &mut server).await;
        }
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        result
    }
    /// Build the real service listener, also used by external-protocol tests.
    async fn build(config: Config) -> Result<(Router, Arc<StateData>)> {
        config.validate()?;
        let (http, backend_tls) = tls::backend_client(&config.backend_tls).await?;
        let probe = http
            .get(config.rpc_backend.join("/gateway/context")?)
            .send()
            .await?;
        ensure!(
            probe.status().is_success(),
            "private RPC workload probe rejected"
        );
        let body = limited_response(probe, 1_024).await?;
        ensure!(
            serde_json::from_slice::<Value>(&body)?.get("protocol") == Some(&json!(1)),
            "RPC gateway context protocol unavailable"
        );
        let store = Store::open(
            &config.database_url,
            config.domain.clone(),
            &config.archive_dir,
        )
        .await?;
        let verifier = ChainVerifier::new(
            config.domain.clone(),
            config.tempo_rpc.clone(),
            config.zone_rpc.clone(),
        )?;
        let state = Arc::new(StateData {
            config,
            store,
            verifier,
            http,
            backend_tls,
            snapshot: RwLock::new(None),
            healthy_at: RwLock::new(None),
            stopping: AtomicBool::new(false),
            streams: Arc::new(Semaphore::new(1_000)),
            budgets: Mutex::new(Budget {
                second: 0,
                calls: 0,
                bytes: 0,
            }),
            handles: Mutex::new(HashMap::new()),
        });
        state.refresh().await?;
        let router = Router::new()
            .route("/", post(http_rpc).get(ws_rpc))
            .route("/rpc", post(http_rpc).get(ws_rpc))
            .route("/health/live", get(live))
            .route("/health/ready", get(ready))
            .layer(DefaultBodyLimit::max(1 << 20))
            .layer(tower::limit::ConcurrencyLimitLayer::new(1_000))
            .with_state(state.clone());
        Ok((router, state))
    }
}

impl StateData {
    async fn refresh(&self) -> Result<()> {
        let started = clock::continuous_seconds();
        self.store.sync_archive().await?;
        let registry = self.store.snapshot().await?;
        ensure!(
            clock::continuous_seconds() - started < 5.0,
            "registry refresh expired"
        );
        let mut previous = self.snapshot.write().await;
        if previous
            .as_ref()
            .is_some_and(|(old, _)| old.offset > registry.offset)
        {
            return Err(eyre!("registry head regressed"));
        }
        metrics::gauge!("zone_access_evidence_age_seconds", "source" => "registry")
            .set(clock::continuous_seconds() - started);
        *previous = Some((registry, started));
        Ok(())
    }
    async fn registry(&self) -> Result<Registry> {
        let snapshot = self.snapshot.read().await;
        let (registry, since) = snapshot
            .as_ref()
            .ok_or_else(|| eyre!("registry unavailable"))?;
        ensure!(clock::continuous_seconds() - since < 5.0, "registry stale");
        Ok(registry.clone())
    }
    pub(crate) async fn budget(&self, bytes: usize) -> Result<()> {
        let second = clock::continuous_seconds() as u64;
        let mut b = self.budgets.lock().await;
        if b.second != second {
            *b = Budget {
                second,
                calls: 0,
                bytes: 0,
            };
        }
        if bytes == 0 {
            b.calls = b.calls.saturating_add(1);
            ensure!(b.calls <= self.config.requests_per_second, "rate limited");
        } else {
            b.bytes = b.bytes.saturating_add(bytes as u64);
            ensure!(
                b.bytes <= self.config.egress_bytes_per_second,
                "egress limited"
            );
        }
        Ok(())
    }
    pub(crate) async fn authorize(
        &self,
        header: &str,
        account: Option<Address>,
        permission: Permission,
        method: &str,
    ) -> Result<Admission> {
        self.budget(0).await?;
        self.authorize_unmetered(header, account, permission, method)
            .await
    }
    async fn authorize_unmetered(
        &self,
        header: &str,
        account: Option<Address>,
        permission: Permission,
        method: &str,
    ) -> Result<Admission> {
        ensure!(!self.stopping.load(Ordering::Acquire), "gateway stopping");
        let credential = Credential::parse(header, &self.config.domain, clock::unix_seconds()?)?;
        let proof = self
            .verifier
            .verify(&credential, account, permission == Permission::Logs)
            .await?;
        metrics::gauge!("zone_access_evidence_age_seconds", "source" => "tempo")
            .set(clock::continuous_seconds() - proof.observed_at);
        if proof.zone_hash.is_some() {
            metrics::gauge!("zone_access_evidence_age_seconds", "source" => "zone")
                .set(clock::continuous_seconds() - proof.observed_at);
        }
        let account = match &proof.principal {
            Principal::Account(address) => Some(*address),
            _ => account,
        };
        let registry = match &proof.principal {
            Principal::Account(_) | Principal::ZoneAdmin(_) => self
                .snapshot
                .read()
                .await
                .as_ref()
                .map(|(s, _)| s.clone())
                .unwrap_or_default(),
            Principal::Client { .. } => self.registry().await?,
        };
        let allowed = registry.allows(&proof.principal, account, permission);
        let kind = match proof.principal {
            Principal::Account(_) => "account",
            Principal::Client { .. } => "client",
            Principal::ZoneAdmin(_) => "admin",
        };
        let scope = match permission {
            Permission::Metadata => "metadata",
            Permission::RpcRead => "rpc.read",
            Permission::RpcWrite => "rpc.write",
            Permission::IndexerRead => "indexer.read",
            Permission::Logs => "logs",
        };
        metrics::counter!("zone_access_decisions_total", "principal_kind" => kind, "scope" => scope, "decision" => if allowed { "allow" } else { "deny" }).increment(1);
        let log_started = clock::continuous_seconds();
        let (token_id, label) = token_identity(&credential);
        let log_id = self
            .store
            .record(LogRecord {
                principal: Some(proof.principal.clone()),
                token_id,
                label,
                account,
                method: bounded_method(method).into(),
                decision: if allowed { "allow" } else { "deny" }.into(),
                offset: registry.offset,
                tempo_hash: Some(proof.tempo_hash),
                zone_hash: proof.zone_hash,
            })
            .await?;
        metrics::histogram!("zone_access_log_commit_seconds", "stage" => "decision")
            .record(clock::continuous_seconds() - log_started);
        if !allowed {
            return Err(AccessDenied.into());
        }
        ensure!(proof.fresh(), "authority evidence expired");
        Ok(Admission {
            credential,
            proof,
            account,
            permission,
            log_id,
            requires_admin: false,
        })
    }
    pub(crate) async fn recheck(&self, admission: &Admission) -> Result<()> {
        self.recheck_permission(admission, admission.permission)
            .await
            .map(|_| ())
    }
    async fn recheck_permission(
        &self,
        admission: &Admission,
        permission: Permission,
    ) -> Result<VerifiedCredential> {
        ensure!(!self.stopping.load(Ordering::Acquire), "gateway stopping");
        let proof = self
            .verifier
            .verify(
                &admission.credential,
                admission.account,
                permission == Permission::Logs,
            )
            .await?;
        let registry = match &proof.principal {
            Principal::Account(_) | Principal::ZoneAdmin(_) => self
                .snapshot
                .read()
                .await
                .as_ref()
                .map(|(r, _)| r.clone())
                .unwrap_or_default(),
            Principal::Client { .. } => self.registry().await?,
        };
        ensure!(proof.fresh(), "authority evidence expired");
        if proof.principal != admission.proof.principal
            || !registry.allows(&proof.principal, admission.account, permission)
            || (admission.requires_admin && !registry_admin(&registry, &proof.principal))
        {
            return Err(AccessDenied.into());
        }
        Ok(proof)
    }
    async fn recheck_all(&self, admissions: &[Admission]) -> Result<()> {
        let started = clock::continuous_seconds();
        let mut proofs = Vec::with_capacity(admissions.len());
        for admission in admissions {
            proofs.push(
                self.recheck_permission(admission, admission.permission)
                    .await?,
            );
        }
        let now = clock::unix_seconds()?;
        let delegated = admissions
            .iter()
            .any(|a| matches!(a.proof.principal, Principal::Client { .. }));
        let registry = if delegated {
            self.registry().await?
        } else {
            Registry::default()
        };
        for admission in admissions {
            ensure!(
                admission.credential.expires_at() > now,
                "credential expired before release"
            );
            if matches!(admission.proof.principal, Principal::Client { .. }) {
                ensure!(
                    registry.allows(
                        &admission.proof.principal,
                        admission.account,
                        admission.permission
                    ),
                    "access removed before release"
                );
                if admission.requires_admin {
                    ensure!(
                        registry_admin(&registry, &admission.proof.principal),
                        "admin access removed before release"
                    );
                }
            }
        }
        ensure!(
            proofs.iter().all(VerifiedCredential::fresh),
            "authority expired before release"
        );
        ensure!(
            clock::continuous_seconds() - started < 4.9,
            "batch evidence expired before release"
        );
        Ok(())
    }
    pub(crate) async fn deny_log(&self, method: &str, account: Option<Address>) -> Result<()> {
        self.store
            .record(LogRecord {
                principal: None,
                token_id: None,
                label: None,
                account,
                method: bounded_method(method).into(),
                decision: "deny".into(),
                offset: 0,
                tempo_hash: None,
                zone_hash: None,
            })
            .await?;
        Ok(())
    }
}

fn bounded_method(method: &str) -> &str {
    if zone_auth::RpcMethod::from_name(method).is_some() {
        method
    } else {
        match method {
            "zone_applyAccessOp"
            | "zone_getClient"
            | "zone_listAccess"
            | "zone_getAccessReceipt"
            | "indexer.query"
            | "indexer.delivery"
            | "indexer.register"
            | "indexer.stream"
            | "indexer.renew"
            | "indexer.remove" => method,
            _ => "unknown",
        }
    }
}
fn token_identity(c: &Credential) -> (Option<B256>, Option<String>) {
    match c {
        Credential::Legacy(t) => (Some(t.digest), Some("legacy".into())),
        Credential::V1(t) => (Some(t.token.token_id), Some(t.token.label.clone())),
    }
}
fn token_hint(c: &Credential) -> Option<Address> {
    match c {
        Credential::V1(t) => Some(t.token.principal),
        _ => None,
    }
}
pub(crate) fn header(headers: &HeaderMap) -> Result<&str> {
    ensure!(
        headers.get_all("x-authorization-token").iter().count() == 1,
        "exactly one credential required"
    );
    headers
        .get("x-authorization-token")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| eyre!("credential required"))
}
fn account(headers: &HeaderMap) -> Result<Option<Address>> {
    ensure!(
        headers.get_all("x-zone-account").iter().count() <= 1,
        "ambiguous account context"
    );
    headers
        .get("x-zone-account")
        .map(|h| h.to_str()?.parse().map_err(Into::into))
        .transpose()
}
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn denied(id: Value) -> Value {
    rpc_error(id, -32001, "Access denied")
}
fn unavailable(id: Value) -> Value {
    rpc_error(id, -32002, "Service unavailable")
}

async fn http_rpc(
    State(state): State<Arc<StateData>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let within_limit = state.budget(0).await.is_ok();
            let _ = state.deny_log("unknown", None).await;
            return (
                if within_limit {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                },
                axum::Json(rpc_error(Value::Null, -32700, "Invalid request")),
            )
                .into_response();
        }
    };
    let receipts: Vec<bool> = parsed
        .as_array()
        .map(|calls| {
            calls
                .iter()
                .map(|call| {
                    call.get("method").and_then(Value::as_str) == Some("zone_applyAccessOp")
                })
                .collect()
        })
        .unwrap_or_default();
    let mut releases = Vec::new();
    let response = if let Some(calls) = parsed.as_array() {
        if calls.is_empty() || calls.len() > 100 {
            let _ = state.budget(0).await;
            let _ = state.deny_log("unknown", None).await;
            rpc_error(Value::Null, -32600, "Invalid batch")
        } else {
            let mut out = Vec::with_capacity(calls.len());
            let mut buffered = 2usize;
            for call in calls {
                let value =
                    process_call(&state, &headers, call.clone(), false, &mut releases).await;
                buffered = buffered
                    .saturating_add(value.to_string().len())
                    .saturating_add(1);
                if buffered > state.config.max_response_bytes {
                    return axum::Json(rpc_error(
                        Value::Null,
                        -32003,
                        "Response too large; earlier calls may have completed",
                    ))
                    .into_response();
                }
                out.push(value);
            }
            Value::Array(out)
        }
    } else {
        process_call(&state, &headers, parsed, false, &mut releases).await
    };
    let bytes = serde_json::to_vec(&response).unwrap_or_default();
    if bytes.len() > state.config.max_response_bytes {
        return axum::Json(rpc_error(Value::Null, -32003, "Response too large")).into_response();
    }
    if state.budget(bytes.len()).await.is_err() {
        return axum::Json(unavailable(
            response.get("id").cloned().unwrap_or(Value::Null),
        ))
        .into_response();
    }
    for admission in &releases {
        if state
            .store
            .complete(admission.log_id, "release_intent")
            .await
            .is_err()
        {
            return axum::Json(unavailable(Value::Null)).into_response();
        }
    }
    let body = futures::stream::unfold(
        Some((false, state, releases, response, receipts, bytes)),
        |pending| async move {
            let (released, state, releases, response, receipts, bytes) = pending?;
            if released {
                for admission in &releases {
                    if let Err(error) = state
                        .store
                        .complete(admission.log_id, "release_admitted")
                        .await
                    {
                        tracing::warn!(%error, "release completion logging failed");
                    }
                }
                return None;
            }
            if state.recheck_all(&releases).await.is_err() {
                let suppressed = match response {
                    Value::Array(values) => Value::Array(
                        values
                            .into_iter()
                            .enumerate()
                            .map(|(index, value)| {
                                if receipts.get(index) == Some(&true)
                                    || value.get("error").is_some()
                                {
                                    value
                                } else {
                                    denied(value.get("id").cloned().unwrap_or(Value::Null))
                                }
                            })
                            .collect(),
                    ),
                    value => denied(value.get("id").cloned().unwrap_or(Value::Null)),
                };
                return Some((
                    Ok::<_, std::convert::Infallible>(Bytes::from(suppressed.to_string())),
                    None,
                ));
            }
            // One bounded frame is admitted immediately after the final gate. If the
            // body is dropped before its next poll, the completion remains unknown.
            Some((
                Ok(Bytes::from(bytes)),
                Some((true, state, releases, response, receipts, Vec::new())),
            ))
        },
    );
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        Body::from_stream(body),
    )
        .into_response()
}

async fn process_call(
    state: &Arc<StateData>,
    headers: &HeaderMap,
    mut call: Value,
    websocket: bool,
    releases: &mut Vec<Admission>,
) -> Value {
    let id = call.get("id").cloned().unwrap_or(Value::Null);
    if state.budget(0).await.is_err() {
        let _ = state.deny_log("unknown", None).await;
        return unavailable(id);
    }
    let Some(method) = call
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        let _ = state.deny_log("unknown", None).await;
        return denied(id);
    };
    if call.get("jsonrpc") != Some(&json!("2.0")) || call.get("id").is_none() {
        let _ = state.deny_log(&method, None).await;
        return rpc_error(id, -32600, "Invalid request");
    }
    let params = call.get("params").cloned().unwrap_or(json!([]));
    if method == "zone_applyAccessOp" {
        let signed: SignedOp = match params
            .get(0)
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
        {
            Some(s) => s,
            None => {
                let _ = state.deny_log(&method, None).await;
                return denied(id);
            }
        };
        match state.store.retry_signed(&signed).await {
            Ok(Some(receipt)) => return json!({"jsonrpc":"2.0","id":id,"result":receipt}),
            Ok(None) => {}
            Err(_) => return unavailable(id),
        }
        let proof = match state.verifier.verify_operation(&signed).await {
            Ok(p) => p,
            Err(_) => {
                let _ = state.deny_log(&method, None).await;
                return denied(id);
            }
        };
        match state.store.commit(&proof).await {
            Ok(receipt) => {
                let _ = state.refresh().await;
                return json!({"jsonrpc":"2.0","id":id,"result":receipt});
            }
            Err(error) => {
                tracing::warn!(digest=%signed.op.digest(),"access operation did not return a receipt");
                if error.to_string().contains("unknown outcome") {
                    return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32002,"message":"Outcome unknown; retry the same signed operation","data":{"digest":signed.op.digest()}}});
                }
                return denied(id);
            }
        }
    }
    let token = match header(headers) {
        Ok(t) => t,
        Err(_) => {
            let _ = state.deny_log(&method, None).await;
            return denied(id);
        }
    };
    let parsed = match Credential::parse(
        token,
        &state.config.domain,
        match clock::unix_seconds() {
            Ok(n) => n,
            Err(_) => return unavailable(id),
        },
    ) {
        Ok(c) => c,
        Err(_) => {
            let _ = state.deny_log(&method, None).await;
            return denied(id);
        }
    };
    let mut target = match account(headers) {
        Ok(a) => a,
        Err(_) => return denied(id),
    };
    if target.is_none() {
        target = token_hint(&parsed);
    }
    if ["zone_getClient", "zone_listAccess", "zone_getAccessReceipt"].contains(&method.as_str()) {
        let mut admission = match state
            .authorize_unmetered(token, None, Permission::Logs, &method)
            .await
        {
            Ok(a) => a,
            Err(_) => {
                let _ = state.deny_log(&method, None).await;
                return denied(id);
            }
        };
        let result: Result<Value> = async {
            if method == "zone_listAccess" {
                let q = params.get(0).cloned().unwrap_or(json!({}));
                let all = match admission.proof.principal {
                    Principal::ZoneAdmin(_) => true,
                    Principal::Account(_) => false,
                    Principal::Client { .. } => {
                        registry_admin(&state.registry().await?, &admission.proof.principal)
                    }
                };
                admission.requires_admin = all;
                state
                    .store
                    .logs(
                        &admission.proof.principal,
                        all,
                        q.get("after").and_then(Value::as_i64).unwrap_or(0),
                        q.get("limit")
                            .and_then(Value::as_u64)
                            .unwrap_or(100)
                            .min(1000) as u32,
                    )
                    .await
            } else {
                let registry = state.registry().await?;
                let is_admin = registry_admin(&registry, &admission.proof.principal);
                ensure!(is_admin, "access denied");
                admission.requires_admin = true;
                if method == "zone_getClient" {
                    let target: Address =
                        serde_json::from_value(params.get(0).cloned().unwrap_or(Value::Null))?;
                    Ok(serde_json::to_value(registry.clients.get(&target))?)
                } else {
                    let digest: B256 =
                        serde_json::from_value(params.get(0).cloned().unwrap_or(Value::Null))?;
                    Ok(serde_json::to_value(state.store.receipt(digest).await?)?)
                }
            }
        }
        .await;
        return match result {
            Ok(v) => {
                if state.recheck(&admission).await.is_err() {
                    return denied(id);
                }
                if state
                    .store
                    .complete(admission.log_id, "backend_success")
                    .await
                    .is_err()
                {
                    return unavailable(id);
                }
                releases.push(admission);
                json!({"jsonrpc":"2.0","id":id,"result":v})
            }
            Err(_) => denied(id),
        };
    }
    let Some(permission) = rpc_permission(&method, &params) else {
        let _ = state.deny_log(&method, target).await;
        return denied(id);
    };
    if !websocket && (method == "eth_subscribe" || method == "eth_unsubscribe") {
        let _ = state.deny_log(&method, target).await;
        return denied(id);
    }
    let admission = match state
        .authorize_unmetered(token, target, permission, &method)
        .await
    {
        Ok(a) => a,
        Err(error) => {
            let _ = state.deny_log(&method, target).await;
            if error
                .downcast_ref::<VerificationError>()
                .is_some_and(|e| matches!(e, VerificationError::Unavailable))
            {
                return unavailable(id);
            }
            return denied(id);
        }
    };
    let target = match admission.account.or(match admission.proof.principal {
        Principal::Account(a) => Some(a),
        _ => None,
    }) {
        Some(a) => a,
        None => return denied(id),
    };
    let filters = [
        "eth_getFilterLogs",
        "eth_getFilterChanges",
        "eth_uninstallFilter",
    ];
    if filters.contains(&method.as_str()) {
        let Some(alias) = params.get(0).and_then(Value::as_str) else {
            return denied(id);
        };
        let handles = state.handles.lock().await;
        let Some(handle) = handles.get(alias).filter(|h| {
            h.owner == admission.proof.principal
                && h.account == target
                && clock::continuous_seconds() - h.created_at < 600.0
        }) else {
            return denied(id);
        };
        call["params"][0] = handle.backend.clone();
    }
    if state.recheck(&admission).await.is_err() {
        return denied(id);
    }
    let result: Result<Value> = async {
        let response = state
            .http
            .post(state.config.rpc_backend.clone())
            .header("x-zone-account", target.to_string())
            .header("x-zone-expires-at", admission.proof.expires_at.to_string())
            .header("x-zone-context-version", "1")
            .json(&call)
            .send()
            .await?;
        ensure!(response.status().is_success(), "backend unavailable");
        let body = limited_response(response, state.config.max_response_bytes).await?;
        let value: Value = serde_json::from_slice(&body)?;
        ensure!(
            value.get("id") == Some(&id),
            "backend response identity mismatch"
        );
        Ok(value)
    }
    .await;
    let mut result = match result {
        Ok(v) => v,
        Err(_) => {
            let _ = state
                .store
                .complete(admission.log_id, "backend_unknown")
                .await;
            return unavailable(id);
        }
    };
    if ["eth_newFilter", "eth_newBlockFilter"].contains(&method.as_str())
        && result.get("error").is_none()
    {
        let alias = format!("0x{}", Uuid::new_v4().simple());
        let mut handles = state.handles.lock().await;
        handles.retain(|_, h| clock::continuous_seconds() - h.created_at < 600.0);
        if handles.len() >= 10_000 {
            return unavailable(id);
        }
        handles.insert(
            alias.clone(),
            Handle {
                backend: result["result"].clone(),
                owner: admission.proof.principal.clone(),
                account: target,
                created_at: clock::continuous_seconds(),
            },
        );
        result["result"] = json!(alias);
    }
    if method == "eth_uninstallFilter"
        && result.get("result") == Some(&Value::Bool(true))
        && let Some(alias) = params.get(0).and_then(Value::as_str)
    {
        state.handles.lock().await.remove(alias);
    }
    if state.recheck(&admission).await.is_err() {
        let _ = state
            .store
            .complete(admission.log_id, "release_denied")
            .await;
        return denied(id);
    }
    if state
        .store
        .complete(admission.log_id, "backend_success")
        .await
        .is_err()
    {
        return unavailable(id);
    }
    releases.push(admission);
    result
}

fn registry_admin(registry: &Registry, principal: &Principal) -> bool {
    match principal {
        Principal::ZoneAdmin(_) => true,
        Principal::Account(_) => false,
        Principal::Client { address, .. } => {
            registry.allows(principal, None, Permission::Logs)
                && registry
                    .clients
                    .get(address)
                    .is_some_and(|client| client.scopes.contains(&Scope::Admin))
        }
    }
}

pub(crate) async fn limited_response(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "response too large"
    );
    let mut stream = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            out.len().saturating_add(chunk.len()) <= limit,
            "response too large"
        );
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
async fn live() -> StatusCode {
    StatusCode::OK
}
async fn ready(State(s): State<Arc<StateData>>) -> StatusCode {
    if s.registry().await.is_ok()
        && s.healthy_at
            .read()
            .await
            .is_some_and(|since| clock::continuous_seconds() - since < 5.0)
        && !s.stopping.load(Ordering::Acquire)
    {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn ws_rpc(
    State(s): State<Arc<StateData>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if s.budget(0).await.is_err() {
        let _ = s.deny_log("eth_subscribe", None).await;
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let token = match header(&headers) {
        Ok(h) => h.to_owned(),
        Err(_) => {
            let _ = s.deny_log("eth_subscribe", None).await;
            return StatusCode::FORBIDDEN.into_response();
        }
    };
    let target = match account(&headers) {
        Ok(a) => a,
        Err(_) => {
            let _ = s.deny_log("eth_subscribe", None).await;
            return StatusCode::FORBIDDEN.into_response();
        }
    };
    let admission = match s
        .authorize_unmetered(&token, target, Permission::Metadata, "eth_subscribe")
        .await
    {
        Ok(a) => a,
        Err(_) => {
            let _ = s.deny_log("eth_subscribe", target).await;
            return StatusCode::FORBIDDEN.into_response();
        }
    };
    let Ok(permit) = s.streams.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    ws.max_message_size(1 << 20)
        .max_frame_size(1 << 20)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let _session = SessionMetric::rpc();
            if let Err(error) = proxy_ws(socket, s, token, target, admission).await {
                tracing::debug!(error=%error,"gateway websocket closed");
            }
        })
        .into_response()
}

struct SessionMetric;
impl SessionMetric {
    fn rpc() -> Self {
        metrics::gauge!("zone_access_sessions", "transport" => "rpc").increment(1.0);
        Self
    }
}
impl Drop for SessionMetric {
    fn drop(&mut self) {
        metrics::gauge!("zone_access_sessions", "transport" => "rpc").decrement(1.0);
    }
}

struct PendingCall {
    group: String,
    index: usize,
    id: Value,
    admission: Admission,
    subscribe: bool,
    remove: Option<String>,
}
struct ResponseGroup {
    batch: bool,
    values: Vec<Option<Value>>,
    admissions: Vec<Admission>,
    remaining: std::collections::VecDeque<(usize, Value)>,
    bytes: usize,
}
impl ResponseGroup {
    fn put(&mut self, index: usize, value: Value, limit: usize) -> Result<()> {
        let length = value.to_string().len().saturating_add(1);
        self.bytes = self.bytes.saturating_add(length);
        ensure!(self.bytes <= limit, "batch response too large");
        self.values[index] = Some(value);
        Ok(())
    }
}
type UpstreamSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct WsRequests {
    pending: HashMap<String, PendingCall>,
    groups: HashMap<String, ResponseGroup>,
    subscriptions: HashMap<String, (Value, Permission)>,
    backend_to_alias: HashMap<String, String>,
    headers: HeaderMap,
    token: String,
    acting: Address,
}
impl WsRequests {
    fn response_budget(&self, limit: usize) -> Result<()> {
        ensure!(
            self.groups.values().map(|g| g.bytes).sum::<usize>() <= limit,
            "pending response budget exhausted"
        );
        Ok(())
    }

    /// Run this batch only through its next asynchronous WS operation.
    /// Its remaining calls resume after that operation's backend response arrives.
    async fn advance(
        &mut self,
        state: &Arc<StateData>,
        upstream: &mut UpstreamSocket,
        key: &str,
    ) -> Result<()> {
        loop {
            let group = self
                .groups
                .get_mut(key)
                .ok_or_else(|| eyre!("missing response group"))?;
            let Some((index, mut call)) = group.remaining.pop_front() else {
                break;
            };
            let id = call.get("id").cloned().unwrap_or(Value::Null);
            let method = call
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            if !matches!(method.as_str(), "eth_subscribe" | "eth_unsubscribe") {
                let value =
                    process_call(state, &self.headers, call, false, &mut group.admissions).await;
                group.put(index, value, state.config.max_response_bytes)?;
                self.response_budget(state.config.max_response_bytes)?;
                continue;
            }
            if state.budget(0).await.is_err() {
                state.deny_log(&method, Some(self.acting)).await?;
                group.put(index, denied(id), state.config.max_response_bytes)?;
                continue;
            }
            if call.get("jsonrpc") != Some(&json!("2.0")) || call.get("id").is_none() {
                state.deny_log(&method, Some(self.acting)).await?;
                group.put(
                    index,
                    rpc_error(id, -32600, "Invalid request"),
                    state.config.max_response_bytes,
                )?;
                continue;
            }
            let params = call.get("params").cloned().unwrap_or(json!([]));
            let Some(permission) = rpc_permission(&method, &params) else {
                state.deny_log(&method, Some(self.acting)).await?;
                group.put(index, denied(id), state.config.max_response_bytes)?;
                continue;
            };
            let remove = if method == "eth_unsubscribe" {
                params.get(0).and_then(Value::as_str).map(str::to_owned)
            } else {
                None
            };
            if method == "eth_unsubscribe" {
                let Some((backend, _)) = remove
                    .as_ref()
                    .and_then(|alias| self.subscriptions.get(alias))
                else {
                    state.deny_log(&method, Some(self.acting)).await?;
                    group.put(index, denied(id), state.config.max_response_bytes)?;
                    continue;
                };
                call["params"][0] = backend.clone();
            }
            let admission = match state
                .authorize_unmetered(&self.token, Some(self.acting), permission, &method)
                .await
            {
                Ok(admission) => admission,
                Err(_) => {
                    state.deny_log(&method, Some(self.acting)).await?;
                    group.put(index, denied(id), state.config.max_response_bytes)?;
                    continue;
                }
            };
            ensure!(self.pending.len() < 100, "too many pending calls");
            let internal = Uuid::new_v4().to_string();
            call["id"] = json!(internal);
            state.recheck(&admission).await?;
            upstream
                .send(UpstreamMessage::Text(call.to_string().into()))
                .await?;
            self.pending.insert(
                internal,
                PendingCall {
                    group: key.to_owned(),
                    index,
                    id,
                    admission,
                    subscribe: method == "eth_subscribe",
                    remove,
                },
            );
            // Sending a frame is not completion. No later batch call runs until this
            // response is processed, including calls sent over the HTTP upstream.
            break;
        }
        self.response_budget(state.config.max_response_bytes)
    }
}

async fn flush_group(
    socket: &mut WebSocket,
    state: &StateData,
    groups: &mut HashMap<String, ResponseGroup>,
    key: &str,
) -> Result<()> {
    if !groups
        .get(key)
        .is_some_and(|g| g.values.iter().all(Option::is_some))
    {
        return Ok(());
    }
    let group = groups
        .remove(key)
        .ok_or_else(|| eyre!("missing response group"))?;
    let values: Vec<Value> = group.values.into_iter().flatten().collect();
    let response = if group.batch {
        Value::Array(values)
    } else {
        values
            .into_iter()
            .next()
            .ok_or_else(|| eyre!("empty response"))?
    };
    let text = response.to_string();
    ensure!(
        text.len() <= state.config.max_response_bytes,
        "response too large"
    );
    state.budget(text.len()).await?;
    for admission in &group.admissions {
        state
            .store
            .complete(admission.log_id, "release_intent")
            .await?;
    }
    state.recheck_all(&group.admissions).await?;
    socket.send(Message::Text(text.into())).await?;
    for admission in &group.admissions {
        if let Err(error) = state
            .store
            .complete(admission.log_id, "release_admitted")
            .await
        {
            tracing::warn!(error=%error, "websocket transport completion unavailable");
        }
    }
    Ok(())
}

async fn proxy_ws(
    mut downstream: WebSocket,
    s: Arc<StateData>,
    token: String,
    target: Option<Address>,
    opening: Admission,
) -> Result<()> {
    let acting = opening
        .account
        .or(target)
        .ok_or_else(|| eyre!("acting account required"))?;
    let mut url = s.config.rpc_backend.clone();
    url.set_scheme("wss")
        .map_err(|_| eyre!("invalid websocket URL"))?;
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("x-zone-account", acting.to_string().parse()?);
    request.headers_mut().insert(
        "x-zone-expires-at",
        opening.proof.expires_at.to_string().parse()?,
    );
    request
        .headers_mut()
        .insert("x-zone-context-version", "1".parse()?);
    let (mut upstream, _) = tokio::time::timeout(
        Duration::from_secs(2),
        tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(
                tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                    .max_message_size(Some(1 << 20))
                    .max_frame_size(Some(1 << 20)),
            ),
            false,
            Some(Connector::Rustls(s.backend_tls.clone())),
        ),
    )
    .await??;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut headers = HeaderMap::new();
    headers.insert("x-authorization-token", token.parse()?);
    headers.insert("x-zone-account", acting.to_string().parse()?);
    let mut requests = WsRequests {
        pending: HashMap::new(),
        groups: HashMap::new(),
        subscriptions: HashMap::new(),
        backend_to_alias: HashMap::new(),
        headers,
        token,
        acting,
    };
    loop {
        tokio::select! {
            biased;
            _ = tick.tick() => {
                s.recheck(&opening).await?;
                for (_, permission) in requests.subscriptions.values() { s.recheck_permission(&opening,*permission).await?; }
            }
            input = downstream.recv() => {
                let text = match input {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(data))) => { downstream.send(Message::Pong(data)).await?; continue; }
                    Some(Ok(Message::Pong(_))) => continue,
                    _ => break,
                };
                let parsed: Value = match serde_json::from_str(&text) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        let _ = s.budget(0).await;
                        s.deny_log("unknown", Some(acting)).await?;
                        return Err(error.into());
                    }
                };
                let batch = parsed.is_array();
                let calls = parsed.as_array().cloned().unwrap_or_else(|| vec![parsed]);
                if calls.is_empty() || calls.len() > 100 {
                    let _ = s.budget(0).await;
                    s.deny_log("unknown", Some(acting)).await?;
                    return Err(eyre!("invalid batch"));
                }
                ensure!(requests.groups.len() < 100, "too many pending batches");
                let queued = requests.groups.values().map(|g| g.remaining.len()).sum::<usize>();
                ensure!(queued + requests.pending.len() + calls.len() <= 100, "too many pending calls");
                let group_id = Uuid::new_v4().to_string();
                requests.groups.insert(group_id.clone(), ResponseGroup { batch,values:vec![None;calls.len()],
                    admissions:Vec::new(),remaining:calls.into_iter().enumerate().collect(),bytes:2 });
                requests.advance(&s,&mut upstream,&group_id).await?;
                flush_group(&mut downstream,&s,&mut requests.groups,&group_id).await?;
            }
            input = upstream.next() => {
                let text = match input {
                    Some(Ok(UpstreamMessage::Text(text))) => text,
                    Some(Ok(UpstreamMessage::Ping(data))) => { upstream.send(UpstreamMessage::Pong(data)).await?; continue; }
                    Some(Ok(UpstreamMessage::Pong(_))) => continue,
                    _ => break,
                };
                ensure!(text.len() <= s.config.max_response_bytes,"response too large");
                let mut value: Value = serde_json::from_str(&text)?;
                if let Some(internal) = value.get("id").and_then(Value::as_str).map(str::to_owned) {
                    let Some(PendingCall {group:group_id,index,id,admission,subscribe,remove}) = requests.pending.remove(&internal) else { continue; };
                    value["id"] = id;
                    if subscribe && value.get("error").is_none() {
                        ensure!(requests.subscriptions.len() < 32,"too many subscriptions");
                        let backend = value["result"].clone();
                        let alias = Uuid::new_v4().to_string();
                        requests.backend_to_alias.insert(backend.to_string(),alias.clone());
                        requests.subscriptions.insert(alias.clone(),(backend,admission.permission));
                        value["result"] = json!(alias);
                    }
                    if value.get("result") == Some(&Value::Bool(true)) && let Some(alias) = remove
                        && let Some((backend,_)) = requests.subscriptions.remove(&alias) {
                        requests.backend_to_alias.remove(&backend.to_string());
                    }
                    let outcome = if value.get("error").is_some() {"backend_rejected"} else {"backend_success"};
                    s.store.complete(admission.log_id,outcome).await?;
                    let group = requests.groups.get_mut(&group_id).ok_or_else(|| eyre!("missing response group"))?;
                    group.put(index,value,s.config.max_response_bytes)?;
                    group.admissions.push(admission);
                    requests.advance(&s,&mut upstream,&group_id).await?;
                    flush_group(&mut downstream,&s,&mut requests.groups,&group_id).await?;
                } else {
                    let backend = value.pointer("/params/subscription").cloned().ok_or_else(|| eyre!("invalid upstream notification"))?;
                    let Some(alias) = requests.backend_to_alias.get(&backend.to_string()).cloned() else { continue; };
                    let (_,permission) = requests.subscriptions.get(&alias).ok_or_else(|| eyre!("unknown subscription"))?;
                    let admission = s.authorize(&requests.token,Some(acting),*permission,"eth_subscribe").await?;
                    value["params"]["subscription"] = json!(alias);
                    let text = value.to_string();
                    s.budget(text.len()).await?;
                    s.store.complete(admission.log_id,"backend_success").await?;
                    s.store.complete(admission.log_id,"release_intent").await?;
                    s.recheck(&admission).await?;
                    downstream.send(Message::Text(text.into())).await?;
                    if let Err(error) = s.store.complete(admission.log_id,"release_admitted").await {
                        tracing::warn!(error=%error,"websocket transport completion unavailable");
                    }
                }
            }
        }
    }
    let _ = upstream.close(None).await;
    let _ = downstream.close().await;
    Ok(())
}
