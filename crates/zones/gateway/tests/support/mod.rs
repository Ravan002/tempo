#![allow(dead_code)]
use alloy_primitives::{Address, B256, Bytes};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use axum::{
    Json, Router,
    body::Bytes as BodyBytes,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use eyre::{Result, ensure, eyre};
use futures::StreamExt;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tempo_contracts::{precompiles::signature_verifier::ISignatureVerifier, zones::ZonePortal};
use tempo_primitives::transaction::tt_signature::TempoSignature;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::client::IntoClientRequest};
use zone_auth::{
    AccessOp, AccountSet, Change, CredentialKind, Domain, Scope, SignedOp, SignedToken, TokenClaims,
};
use zone_gateway::{Config, Gateway, config::TlsFiles, store::Store};

#[derive(Clone)]
pub(crate) struct ObservedCall {
    pub(crate) method: String,
    pub(crate) params: Value,
    pub(crate) account: Address,
    pub(crate) headers: HeaderMap,
}
#[derive(Clone, Default)]
pub(crate) struct BackendState {
    pub(crate) calls: Arc<Mutex<Vec<ObservedCall>>>,
    pub(crate) subscription_delay_ms: Arc<AtomicU64>,
}
async fn backend_rpc(
    State(state): State<BackendState>,
    headers: HeaderMap,
    body: BodyBytes,
) -> Response {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let account: Address = headers
        .get("x-zone-account")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(headers.get("x-zone-context-version").unwrap(), "1");
    assert!(headers.get("x-authorization-token").is_none());
    assert!(headers.get("x-zone-principal").is_none());
    let method = request["method"].as_str().unwrap();
    let params = request["params"].clone();
    state.calls.lock().unwrap().push(ObservedCall {
        method: method.into(),
        params: params.clone(),
        account,
        headers,
    });
    let result = match method {
        "eth_getBalance" => {
            let requested: Address = serde_json::from_value(params[0].clone()).unwrap();
            json!(if requested == account {
                "0x1234"
            } else {
                "0x0"
            })
        }
        "eth_chainId" => json!("0x65"),
        "eth_blockNumber" => json!("0x7"),
        "eth_newFilter" | "eth_newBlockFilter" => json!("0xbeef"),
        "eth_getFilterChanges" | "eth_getFilterLogs" => {
            assert_eq!(params[0], "0xbeef");
            json!([{"visible":"private"}])
        }
        "eth_uninstallFilter" => {
            assert_eq!(params[0], "0xbeef");
            json!(true)
        }
        _ => panic!("unexpected allowed backend RPC method {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})).into_response()
}
async fn backend_upgrade(
    State(state): State<BackendState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let account: Address = headers
        .get("x-zone-account")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    state.calls.lock().unwrap().push(ObservedCall {
        method: "ws_upgrade".into(),
        params: Value::Null,
        account,
        headers,
    });
    ws.on_upgrade(move |socket| backend_socket(socket, state, account))
        .into_response()
}
async fn backend_socket(mut socket: WebSocket, state: BackendState, account: Address) {
    while let Some(Ok(Message::Text(text))) = socket.recv().await {
        let call: Value = serde_json::from_str(&text).unwrap();
        if call["method"] == "eth_subscribe" {
            tokio::time::sleep(Duration::from_millis(
                state.subscription_delay_ms.load(Ordering::Acquire),
            ))
            .await;
        }
        state.calls.lock().unwrap().push(ObservedCall {
            method: call["method"].as_str().unwrap().into(),
            params: call["params"].clone(),
            account,
            headers: HeaderMap::new(),
        });
        let result = match call["method"].as_str().unwrap() {
            "eth_subscribe" => json!("0x100"),
            "eth_unsubscribe" => json!(true),
            _ => panic!("unexpected WS passthrough"),
        };
        if socket
            .send(Message::Text(
                json!({"jsonrpc":"2.0","id":call["id"],"result":result})
                    .to_string()
                    .into(),
            ))
            .await
            .is_err()
        {
            break;
        }
    }
}
#[derive(Clone)]
struct ChainState {
    chain_id: u64,
    hash: B256,
    admin: Address,
    healthy: Arc<AtomicBool>,
}
async fn chain_rpc(State(state): State<ChainState>, Json(call): Json<Value>) -> Json<Value> {
    if !state.healthy.load(Ordering::Acquire) {
        return Json(
            json!({"jsonrpc":"2.0","id":call["id"],"error":{"code":-32000,"message":"fixture provider unavailable"}}),
        );
    }
    let result = match call["method"].as_str().unwrap() {
        "eth_chainId" => json!(format!("0x{:x}", state.chain_id)),
        "eth_getBlockByNumber" => json!({"hash":state.hash}),
        "eth_getCode" => {
            assert_eq!(
                call["params"][1],
                json!({"blockHash":state.hash,"requireCanonical":true})
            );
            json!("0x")
        }
        "eth_call" => {
            assert_eq!(
                call["params"][1],
                json!({"blockHash":state.hash,"requireCanonical":true})
            );
            let data: Bytes = serde_json::from_value(call["params"][0]["data"].clone()).unwrap();
            let result = if data.starts_with(&ZonePortal::adminCall::SELECTOR) {
                ZonePortal::adminCall::abi_encode_returns(&state.admin)
            } else if data.starts_with(&ZonePortal::isAccessEnforcedCall::SELECTOR) {
                ZonePortal::isAccessEnforcedCall::abi_encode_returns(&true)
            } else if data.starts_with(&ZonePortal::hasRoleCall::SELECTOR) {
                let args = ZonePortal::hasRoleCall::abi_decode(&data).unwrap();
                assert_eq!(args.role, ZonePortal::Role::Account);
                ZonePortal::hasRoleCall::abi_encode_returns(&true)
            } else if data.starts_with(&ISignatureVerifier::verifyCall::SELECTOR) {
                let args = ISignatureVerifier::verifyCall::abi_decode(&data).unwrap();
                let recovered = TempoSignature::from_bytes(&args.signature)
                    .ok()
                    .and_then(|s| s.recover_signer(&args.hash).ok());
                ISignatureVerifier::verifyCall::abi_encode_returns(
                    &(recovered == Some(args.signer)),
                )
            } else {
                panic!("unexpected chain ABI selector");
            };
            json!(Bytes::from(result))
        }
        _ => panic!("unexpected chain method {}", call["method"]),
    };
    Json(json!({"jsonrpc":"2.0","id":call["id"],"result":result}))
}
async fn serve_chain(
    chain_id: u64,
    admin: Address,
    healthy: Arc<AtomicBool>,
) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let state = ChainState {
        chain_id,
        hash: B256::with_last_byte(u8::try_from(chain_id)?),
        admin,
        healthy,
    };
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(chain_rpc)).with_state(state),
        )
        .await
        .unwrap();
    });
    Ok((endpoint, task))
}

pub(crate) struct Fixture {
    pub(crate) config: Config,
    pub(crate) root: PrivateKeySigner,
    pub(crate) admin: PrivateKeySigner,
    pub(crate) client: PrivateKeySigner,
    pub(crate) other: PrivateKeySigner,
    pub(crate) backend: BackendState,
    pub(crate) providers_healthy: Arc<AtomicBool>,
    pub(crate) store: Store,
    pub(crate) http: reqwest::Client,
    pub(crate) base: url::Url,
    pub(crate) temp: tempfile::TempDir,
    listener: Option<TcpListener>,
    tasks: Vec<JoinHandle<()>>,
    gateway: Option<JoinHandle<Result<()>>>,
    shutdown: Option<oneshot::Sender<()>>,
}
impl Fixture {
    pub(crate) async fn prepare(extra: Router) -> Result<Option<Self>> {
        let Some(database_url) = std::env::var("ZONES_GATEWAY_TEST_DATABASE_URL").ok() else {
            eprintln!("external gateway test requires ZONES_GATEWAY_TEST_DATABASE_URL");
            return Ok(None);
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp = tempfile::tempdir()?;
        let root = PrivateKeySigner::random();
        let admin = PrivateKeySigner::random();
        let client = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let domain = Domain {
            tempo_chain_id: 100,
            portal: Address::random(),
            zone_id: 7,
            zone_chain_id: 101,
        };
        let providers_healthy = Arc::new(AtomicBool::new(true));
        let (tempo_rpc, tempo_task) =
            serve_chain(100, admin.address(), providers_healthy.clone()).await?;
        let (zone_rpc, zone_task) =
            serve_chain(101, admin.address(), providers_healthy.clone()).await?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate()?;
        let mut server_params = CertificateParams::new(vec!["localhost".into()])?;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.signed_by(&server_key, &issuer)?;
        let client_key = KeyPair::generate()?;
        let mut client_params = CertificateParams::new(vec!["zones-gateway.fixture".into()])?;
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &issuer)?;
        let ca_path = temp.path().join("ca.pem");
        let cert_path = temp.path().join("client.pem");
        let key_path = temp.path().join("client.key");
        std::fs::write(&ca_path, ca.pem())?;
        std::fs::write(&cert_path, client_cert.pem())?;
        std::fs::write(&key_path, client_key.serialize_pem())?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone())?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                ),
            )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let accepted_client = client_cert.der().clone();
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_url = format!(
            "https://localhost:{}/",
            backend_listener.local_addr()?.port()
        );
        let backend = BackendState::default();
        let router = Router::new()
            .route("/", post(backend_rpc).get(backend_upgrade))
            .route(
                "/gateway/context",
                get(|| async { Json(json!({"protocol":1})) }),
            )
            .with_state(backend.clone())
            .merge(extra);
        let backend_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                 accepted=backend_listener.accept()=>{
                  let Ok((stream,_))=accepted else {break;};let acceptor=acceptor.clone();let router=router.clone();let accepted_client=accepted_client.clone();
                  connections.spawn(async move {
                   let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(2),acceptor.accept(stream)).await else{return;};
                   if stream.get_ref().1.peer_certificates().and_then(|certs|certs.first())!=Some(&accepted_client){return;}
                   let builder=hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                   let _=builder.serve_connection_with_upgrades(TokioIo::new(stream),TowerToHyperService::new(router)).await;
                  });
                 },
                 _=connections.join_next(),if !connections.is_empty()=>{},
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = url::Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let archive_dir = temp.path().join("archive");
        let config = Config {
            domain: domain.clone(),
            listen: listener.local_addr()?,
            database_url: database_url.clone(),
            archive_dir: archive_dir.clone(),
            tempo_rpc,
            zone_rpc,
            rpc_backend: url::Url::parse(&backend_url)?,
            backend_tls: TlsFiles {
                ca: ca_path,
                cert: cert_path,
                key: key_path,
            },
            frontend_tls: None,
            indexer_backend: None,
            indexer_paths: vec![],
            indexer_stream_paths: vec![],
            indexer_events_path: None,
            requests_per_second: 1000,
            egress_bytes_per_second: 1024 * 1024,
            log_retention_seconds: 3600,
            max_response_bytes: 1024 * 1024,
            delivery_key_env: None,
        };
        let store = Store::open(&database_url, domain, &archive_dir).await?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Some(Self {
            config,
            root,
            admin,
            client,
            other,
            backend,
            providers_healthy,
            store,
            http,
            base,
            temp,
            listener: Some(listener),
            tasks: vec![tempo_task, zone_task, backend_task],
            gateway: None,
            shutdown: None,
        }))
    }
    pub(crate) async fn start(&mut self) -> Result<()> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| eyre!("fixture already started"))?;
        let (tx, rx) = oneshot::channel();
        self.shutdown = Some(tx);
        let config = self.config.clone();
        self.gateway = Some(tokio::spawn(async move {
            Gateway::serve_on(config, listener, async {
                let _ = rx.await;
            })
            .await
        }));
        for _ in 0..200 {
            if self.gateway.as_ref().is_some_and(|t| t.is_finished()) {
                let result = self.gateway.take().unwrap().await?;
                return Err(eyre!("gateway stopped before readiness: {result:?}"));
            }
            if let Ok(response) = self.http.get(self.base.join("health/ready")?).send().await
                && response.status().is_success()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(eyre!("gateway fixture did not become ready"))
    }
    pub(crate) fn token(
        &self,
        signer: &PrivateKeySigner,
        kind: CredentialKind,
        generation: u64,
    ) -> SignedToken {
        let now = zone_gateway::clock::unix_seconds().unwrap();
        let token = TokenClaims {
            domain: self.config.domain.clone(),
            principal: signer.address(),
            kind,
            generation,
            token_id: B256::random(),
            label: "external-fixture".into(),
            issued_at: now,
            expires_at: now + 60,
        };
        let signature = signer
            .sign_hash_sync(&token.digest())
            .unwrap()
            .as_bytes()
            .to_vec()
            .into();
        SignedToken { token, signature }
    }
    pub(crate) fn signed_op(
        &self,
        target: Address,
        seq: u64,
        generation: u64,
        change: Change,
    ) -> SignedOp {
        let now = zone_gateway::clock::unix_seconds().unwrap();
        let op = AccessOp {
            domain: self.config.domain.clone(),
            client: target,
            seq,
            generation,
            signer: self.admin.address(),
            signer_generation: 0,
            change,
            issued_at: now,
            expires_at: now + 600,
        };
        let signature = self
            .admin
            .sign_hash_sync(&op.digest())
            .unwrap()
            .as_bytes()
            .to_vec()
            .into();
        SignedOp { op, signature }
    }
    pub(crate) async fn apply(&self, op: &SignedOp) -> Result<Value> {
        self.post(
            None,
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"zone_applyAccessOp","params":[op]}),
        )
        .await
    }
    pub(crate) async fn admit(&self, signer: &PrivateKeySigner, scopes: &[Scope]) -> Result<()> {
        let op = self.signed_op(
            signer.address(),
            1,
            0,
            Change::Admit {
                name: "external fixture".into(),
                scopes: scopes.iter().copied().collect(),
                accounts: AccountSet::Listed([self.root.address()].into_iter().collect()),
            },
        );
        let response = self.apply(&op).await?;
        ensure!(
            response.get("result").is_some(),
            "fixture admission rejected: {response}"
        );
        Ok(())
    }
    pub(crate) async fn post(
        &self,
        token: Option<&str>,
        account: Option<Address>,
        body: Value,
    ) -> Result<Value> {
        let mut request = self.http.post(self.base.join("rpc")?).json(&body);
        if let Some(token) = token {
            request = request.header("x-authorization-token", token);
        }
        if let Some(account) = account {
            request = request.header("x-zone-account", account.to_string());
        }
        Ok(request.send().await?.error_for_status()?.json().await?)
    }
    pub(crate) async fn connect_ws(
        &self,
        token: &str,
        account: Option<Address>,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let mut url = self.base.join("rpc")?;
        url.set_scheme("ws").unwrap();
        let mut request = url.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert("x-authorization-token", token.parse()?);
        if let Some(account) = account {
            request
                .headers_mut()
                .insert("x-zone-account", account.to_string().parse()?);
        }
        Ok(tokio_tungstenite::connect_async(request).await?.0)
    }
    pub(crate) async fn crash_and_restart(&mut self) -> Result<()> {
        let task = self
            .gateway
            .take()
            .ok_or_else(|| eyre!("fixture is not running"))?;
        task.abort();
        let error = task
            .await
            .expect_err("aborted gateway unexpectedly completed");
        ensure!(
            error.is_cancelled(),
            "gateway task panicked instead of stopping"
        );
        self.shutdown.take();
        self.http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        self.listener = Some(TcpListener::bind(self.config.listen).await?);
        self.start().await
    }
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.gateway.take() {
            tokio::time::timeout(Duration::from_secs(10), task).await???;
        }
        for task in &self.tasks {
            task.abort();
        }
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.gateway.take() {
            task.abort();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}
pub(crate) async fn ws_response(
    socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Result<Value> {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await?
            .ok_or_else(|| eyre!("WS closed before response"))??;
        if message.is_text() {
            return Ok(serde_json::from_str(message.to_text()?)?);
        }
    }
}
