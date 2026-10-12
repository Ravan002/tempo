mod support;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use alloy_signer::SignerSync;
use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use eyre::{Result, ensure};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use support::Fixture;
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use zone_auth::{Change, CredentialKind, Scope};
use zone_gateway::store::Registration;

#[derive(Clone, Default)]
struct IndexerState {
    seen: Arc<Mutex<Vec<HeaderMap>>>,
    started: Arc<Notify>,
    release: Arc<Notify>,
    unavailable: Arc<AtomicBool>,
}
fn context(headers: &HeaderMap) {
    assert_eq!(headers.get("x-zone-context-version").unwrap(), "1");
    assert!(headers.get("x-authorization-token").is_none());
    assert!(headers.get("x-zone-account").is_none());
    assert!(headers.get("x-zone-principal").is_none());
    let expires = headers
        .get("x-zone-expires-at")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(expires > zone_gateway::clock::unix_seconds().unwrap());
}
async fn query(
    State(state): State<IndexerState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    context(&headers);
    assert_eq!(params.get("chainId").unwrap(), "101");
    state.seen.lock().unwrap().push(headers);
    if params.get("delay").is_some_and(|value| value == "true") {
        state.started.notify_one();
        state.release.notified().await;
    }
    if params.get("live").is_some_and(|value| value == "true") {
        let stream = futures::stream::unfold(0u64, |offset| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Some((
                Ok::<_, std::io::Error>(format!(
                    "event: result\ndata: {{\"offset\":{offset},\"visible\":\"whole-zone\"}}\n\n"
                )),
                offset + 1,
            ))
        });
        return (
            [("content-type", "text/event-stream")],
            Body::from_stream(stream),
        )
            .into_response();
    }
    Json(json!({"visible":"whole-zone"})).into_response()
}
async fn socket(headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    context(&headers);
    ws.on_upgrade(|mut socket| async move {
        while let Some(Ok(Message::Text(text))) = socket.recv().await {
            if socket.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    })
    .into_response()
}
async fn events(
    State(state): State<IndexerState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    context(&headers);
    assert_eq!(params.get("chainId").unwrap(), "101");
    state.seen.lock().unwrap().push(headers);
    if state.unavailable.load(Ordering::Acquire) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(json!({"events":[],"next_cursor":params.get("after").unwrap().parse::<u64>().unwrap()}))
        .into_response()
}
fn routes(state: IndexerState) -> Router {
    Router::new()
        .route(
            "/query",
            get(query).post(|headers: HeaderMap, Json(body): Json<Value>| async move {
                context(&headers);
                Json(body)
            }),
        )
        .route("/socket", get(socket))
        .route("/events", get(events))
        .with_state(state)
}
async fn prepare(state: IndexerState) -> Result<Option<Fixture>> {
    let Some(mut fixture) = Fixture::prepare(routes(state)).await? else {
        return Ok(None);
    };
    fixture.config.indexer_backend = Some(fixture.config.rpc_backend.clone());
    fixture.config.indexer_paths = vec!["/query".into()];
    fixture.config.indexer_stream_paths = vec!["/query".into(), "/socket".into()];
    Ok(Some(fixture))
}

#[tokio::test]
async fn queries_bind_zone_context_and_discard_results_revoked_in_flight() -> Result<()> {
    let state = IndexerState::default();
    let Some(mut fixture) = prepare(state.clone()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    fixture
        .admit(&fixture.client, &[Scope::IndexerRead])
        .await?;
    let token = fixture
        .token(&fixture.client, CredentialKind::Client, 1)
        .header()?;
    let direct = fixture
        .token(&fixture.root, CredentialKind::AccountRoot, 0)
        .header()?;
    let route = fixture.base.join("indexer/query")?;
    assert_eq!(
        fixture
            .http
            .get(route.clone())
            .header("x-authorization-token", direct)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(state.seen.lock().unwrap().is_empty());
    let response = fixture
        .http
        .get(route.clone())
        .header("x-authorization-token", &token)
        .header("x-zone-account", fixture.other.address().to_string())
        .header("x-zone-context-version", "999")
        .header("x-zone-expires-at", "1")
        .header("x-zone-principal", "forged")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await?,
        json!({"visible":"whole-zone"})
    );
    let response = fixture
        .http
        .post(route.clone())
        .header("x-authorization-token", &token)
        .json(&json!({"sql":"SELECT 1"}))
        .send()
        .await?;
    assert_eq!(response.json::<Value>().await?, json!({"sql":"SELECT 1"}));
    let before = state.seen.lock().unwrap().len();
    assert_eq!(
        fixture
            .http
            .get(fixture.base.join("indexer/secret")?)
            .header("x-authorization-token", &token)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .http
            .get(fixture.base.join("indexer/query?chainId=102")?)
            .header("x-authorization-token", &token)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(state.seen.lock().unwrap().len(), before);
    let http = fixture.http.clone();
    let token_copy = token.clone();
    let delayed = fixture.base.join("indexer/query?delay=true")?;
    let pending = tokio::spawn(async move {
        http.get(delayed)
            .header("x-authorization-token", token_copy)
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), state.started.notified()).await?;
    let removal = fixture.signed_op(
        fixture.client.address(),
        2,
        1,
        Change::SetScopes {
            scopes: Default::default(),
        },
    );
    ensure!(
        fixture.apply(&removal).await?.get("result").is_some(),
        "scope change failed"
    );
    state.release.notify_one();
    let response = pending.await??;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.text().await?.contains("whole-zone"));
    fixture.shutdown().await
}

#[tokio::test]
async fn sse_and_websocket_streams_stop_after_permission_removal() -> Result<()> {
    let Some(mut fixture) = prepare(IndexerState::default()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    fixture
        .admit(&fixture.client, &[Scope::IndexerRead])
        .await?;
    let token = fixture
        .token(&fixture.client, CredentialKind::Client, 1)
        .header()?;
    let response = fixture
        .http
        .get(fixture.base.join("indexer/query?live=true")?)
        .header("x-authorization-token", &token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let mut sse = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(3), sse.next())
        .await?
        .unwrap()?;
    ensure!(
        String::from_utf8_lossy(&first).contains("whole-zone"),
        "missing SSE data"
    );
    let mut url = fixture.base.join("indexer/socket")?;
    url.set_scheme("ws").unwrap();
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("x-authorization-token", token.parse()?);
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "whole-zone".into(),
        ))
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await?
            .unwrap()?
            .to_text()?,
        "whole-zone"
    );
    let removal = fixture.signed_op(
        fixture.client.address(),
        2,
        1,
        Change::SetScopes {
            scopes: Default::default(),
        },
    );
    ensure!(
        fixture.apply(&removal).await?.get("result").is_some(),
        "scope change failed"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(_)) = sse.next().await {}
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(message)) = socket.next().await {
            if message.is_close() {
                break;
            }
        }
    })
    .await?;
    fixture.shutdown().await
}

fn encrypt_registration(fixture: &Fixture, id: &str, token: &str) -> Result<Vec<u8>> {
    let key = alloy_primitives::hex::decode(std::env::var("ZONES_GATEWAY_TEST_DELIVERY_KEY")?)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| eyre::eyre!("bad test key"))?;
    let nonce: [u8; 12] = rand::random();
    let aad = format!(
        "{}:{id}:{}:1",
        fixture.config.domain.key(),
        fixture.client.address()
    );
    let payload = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: token.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| eyre::eyre!("test encryption failed"))?;
    let mut result = nonce.to_vec();
    result.extend(payload);
    Ok(result)
}

#[tokio::test]
async fn registration_renewal_preserves_owner_and_outages_do_not_permanently_pause() -> Result<()> {
    if std::env::var("ZONES_GATEWAY_TEST_DELIVERY_KEY").is_err() {
        eprintln!("delivery lifecycle test requires ZONES_GATEWAY_TEST_DELIVERY_KEY");
        return Ok(());
    }
    let state = IndexerState::default();
    state.unavailable.store(true, Ordering::Release);
    let Some(mut fixture) = prepare(state.clone()).await? else {
        return Ok(());
    };
    fixture.config.indexer_events_path = Some("/events".into());
    fixture.config.delivery_key_env = Some("ZONES_GATEWAY_TEST_DELIVERY_KEY".into());
    fixture.start().await?;
    fixture
        .admit(&fixture.client, &[Scope::IndexerRead])
        .await?;
    fixture.admit(&fixture.other, &[Scope::IndexerRead]).await?;
    let token = fixture
        .token(&fixture.client, CredentialKind::Client, 1)
        .header()?;
    let registration = Registration {
        id: "owned-registration".into(),
        owner: fixture.client.address(),
        generation: 1,
        encrypted_credential: encrypt_registration(&fixture, "owned-registration", &token)?,
        endpoint: "https://receiver.example/events".into(),
        cursor: 17,
        paused: true,
    };
    fixture.store.put_registration(&registration).await?;
    let renew = fixture
        .base
        .join("indexer/registrations/owned-registration/renew")?;
    let other = fixture
        .token(&fixture.other, CredentialKind::Client, 1)
        .header()?;
    assert_eq!(
        fixture
            .http
            .post(renew.clone())
            .header("x-authorization-token", other)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        fixture
            .store
            .get_registration(&registration.id)
            .await?
            .unwrap()
            .paused
    );
    assert_eq!(
        fixture
            .http
            .post(renew)
            .header("x-authorization-token", &token)
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let persisted = fixture
        .store
        .get_registration(&registration.id)
        .await?
        .unwrap();
    assert!(
        !persisted.paused,
        "transient Indexer outage must not require token renewal"
    );
    assert_eq!(persisted.cursor, 17);
    state.unavailable.store(false, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        !fixture
            .store
            .get_registration(&registration.id)
            .await?
            .unwrap()
            .paused
    );
    let now = zone_gateway::clock::unix_seconds()?;
    let mut expired = fixture.token(&fixture.client, CredentialKind::Client, 1);
    expired.token.issued_at = now - 100;
    expired.token.expires_at = now - 1;
    expired.signature = fixture
        .client
        .sign_hash_sync(&expired.token.digest())?
        .as_bytes()
        .to_vec()
        .into();
    let mut persisted = fixture
        .store
        .get_registration(&registration.id)
        .await?
        .unwrap();
    persisted.encrypted_credential =
        encrypt_registration(&fixture, &registration.id, &expired.header()?)?;
    fixture.store.put_registration(&persisted).await?;
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if fixture
                .store
                .get_registration(&registration.id)
                .await
                .unwrap()
                .unwrap()
                .paused
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    let renew = fixture
        .base
        .join("indexer/registrations/owned-registration/renew")?;
    assert_eq!(
        fixture
            .http
            .post(renew)
            .header("x-authorization-token", &token)
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .store
            .get_registration(&registration.id)
            .await?
            .unwrap()
            .cursor,
        17
    );
    let private = fixture
        .http
        .post(fixture.base.join("indexer/register")?)
        .header("x-authorization-token", &token)
        .json(&json!({"endpoint":"https://127.0.0.1/private"}))
        .send()
        .await?;
    assert_eq!(private.status(), StatusCode::FORBIDDEN);
    let remove = fixture
        .base
        .join("indexer/registrations/owned-registration")?;
    assert_eq!(
        fixture
            .http
            .delete(remove)
            .header("x-authorization-token", token)
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    assert!(
        fixture
            .store
            .get_registration(&registration.id)
            .await?
            .is_none()
    );
    fixture.shutdown().await
}
