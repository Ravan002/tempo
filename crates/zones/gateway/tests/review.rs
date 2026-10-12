mod support;

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolCall, sol};
use axum::{Json, Router, extract::State, routing::post};
use eyre::Result;
use futures::SinkExt;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use support::Fixture;
use zone_auth::{AccountSet, Change, CredentialKind, Scope};

sol! { interface ReviewValidator { function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4); } }

#[tokio::test]
async fn websocket_batch_waits_for_subscription_before_following_rpc_dispatch() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture
        .backend
        .subscription_delay_ms
        .store(300, Ordering::Release);
    fixture.start().await?;
    fixture.admit(&fixture.client, &[]).await?;
    let token = fixture
        .token(&fixture.client, CredentialKind::Client, 1)
        .header()?;
    let mut socket = fixture
        .connect_ws(&token, Some(fixture.root.address()))
        .await?;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!([
                {"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]},
                {"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}
            ])
            .to_string()
            .into(),
        ))
        .await?;
    let response = support::ws_response(&mut socket).await?;
    let methods: Vec<String> = fixture
        .backend
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.method != "ws_upgrade")
        .map(|call| call.method.clone())
        .collect();
    fixture.shutdown().await?;
    assert_eq!(methods, ["eth_subscribe", "eth_chainId"]);
    assert_eq!(response[0]["id"], json!(1));
    assert_eq!(response[1]["id"], json!(2));
    assert_eq!(response[1]["result"], json!("0x65"));
    Ok(())
}

#[tokio::test]
async fn websocket_data_is_withheld_if_release_intent_cannot_commit() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    let pool = sqlx::PgPool::connect(&fixture.config.database_url).await?;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("review_release_{suffix}");
    let domain = format!("{:x}", fixture.config.domain.key());
    let function = format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome = 'release_intent' AND EXISTS (SELECT 1 FROM gateway_decisions WHERE id=NEW.decision_id AND domain=decode('{domain}','hex')) THEN RAISE EXCEPTION 'review release logging unavailable'; END IF; RETURN NEW; END $$"
    );
    sqlx::query(&function).execute(&pool).await?;
    sqlx::query(&format!("CREATE TRIGGER {name} BEFORE INSERT ON gateway_completions FOR EACH ROW EXECUTE FUNCTION {name}()")).execute(&pool).await?;
    let token = fixture
        .token(&fixture.root, CredentialKind::AccountRoot, 0)
        .header()?;
    let mut socket = fixture.connect_ws(&token, None).await?;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]})
                .to_string()
                .into(),
        ))
        .await?;
    let response = support::ws_response(&mut socket).await;
    let calls = fixture
        .backend
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| call.method == "eth_chainId")
        .count();
    fixture.shutdown().await?;
    sqlx::query(&format!("DROP TRIGGER {name} ON gateway_completions"))
        .execute(&pool)
        .await?;
    sqlx::query(&format!("DROP FUNCTION {name}()"))
        .execute(&pool)
        .await?;
    assert_eq!(
        calls, 1,
        "The fixture must reach backend dispatch before the release-log failure"
    );
    assert!(
        response.is_err(),
        "Data was released without a durable release intent: {response:?}"
    );
    Ok(())
}

#[derive(Clone)]
struct RotatingValidator {
    upstream: String,
    http: reqwest::Client,
    account: Address,
    active: Arc<AtomicBool>,
}

async fn validator_rpc(
    State(state): State<RotatingValidator>,
    Json(call): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if call["method"] == "eth_getCode" && call["params"][0] == json!(state.account) {
        return Json(json!({"jsonrpc":"2.0","id":call["id"],"result":"0x6000"}));
    }
    if call["method"] == "eth_call" && call["params"][0]["to"] == json!(state.account) {
        let bytes: Bytes = serde_json::from_value(call["params"][0]["data"].clone()).unwrap();
        let verification = ReviewValidator::isValidSignatureCall::abi_decode(&bytes).unwrap();
        let signer = tempo_primitives::transaction::tt_signature::TempoSignature::from_bytes(
            &verification.signature,
        )
        .unwrap()
        .recover_signer(&verification.hash)
        .unwrap();
        let mut result = [0u8; 32];
        if signer == state.account && state.active.load(Ordering::Acquire) {
            result[..4].copy_from_slice(&[0x16, 0x26, 0xba, 0x7e]);
        }
        return Json(
            json!({"jsonrpc":"2.0","id":call["id"],"result":Bytes::copy_from_slice(&result)}),
        );
    }
    Json(
        state
            .http
            .post(&state.upstream)
            .json(&call)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn committed_digest_retry_survives_contract_validator_rotation() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    let active = Arc::new(AtomicBool::new(true));
    let state = RotatingValidator {
        upstream: fixture.config.tempo_rpc.clone(),
        http: fixture.http.clone(),
        account: fixture.admin.address(),
        active: active.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    fixture.config.tempo_rpc = format!("http://{}", listener.local_addr()?);
    let provider = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", post(validator_rpc))
                .with_state(state),
        )
        .await
        .unwrap();
    });
    fixture.start().await?;
    let op = fixture.signed_op(
        fixture.client.address(),
        1,
        0,
        Change::Admit {
            name: "validator rotation".into(),
            scopes: [Scope::RpcRead].into_iter().collect(),
            accounts: AccountSet::All,
        },
    );
    let original = fixture.apply(&op).await?;
    assert!(
        original.get("result").is_some(),
        "fixture operation was not applied: {original}"
    );
    active.store(false, Ordering::Release);
    let repeated = fixture.apply(&op).await?;
    fixture.shutdown().await?;
    provider.abort();
    assert_eq!(
        repeated.get("result"),
        original.get("result"),
        "an already committed digest lost its receipt when current contract validation changed: {repeated}"
    );
    Ok(())
}

#[tokio::test]
async fn account_self_authority_does_not_inherit_admin_client_permissions() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    fixture.admit(&fixture.client, &[Scope::Admin]).await?;
    let account_token = fixture
        .token(&fixture.client, CredentialKind::AccountRoot, 0)
        .header()?;
    let denied = fixture.post(Some(&account_token), None,
        json!({"jsonrpc":"2.0","id":1,"method":"zone_getClient","params":[fixture.client.address()]})).await?;
    let own_logs = fixture
        .post(
            Some(&account_token),
            None,
            json!({"jsonrpc":"2.0","id":2,"method":"zone_listAccess","params":[{"limit":100}]}),
        )
        .await?;
    fixture.shutdown().await?;
    assert!(
        denied.get("error").is_some(),
        "Account self authority disclosed an admin-only Client record: {denied}"
    );
    assert!(
        own_logs.get("result").is_some(),
        "The overlapping Client record removed valid Account own-log access: {own_logs}"
    );
    Ok(())
}

#[tokio::test]
async fn http_access_logs_respect_the_configured_egress_limit() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.config.egress_bytes_per_second = 1;
    fixture.start().await?;
    let token = fixture
        .token(&fixture.admin, CredentialKind::ZoneAdmin, 0)
        .header()?;
    let response = fixture
        .post(
            Some(&token),
            None,
            json!({"jsonrpc":"2.0","id":1,"method":"zone_listAccess","params":[{"limit":100}]}),
        )
        .await?;
    fixture.shutdown().await?;
    assert!(
        response.get("error").is_some(),
        "HTTP access-log data bypassed the one-byte Zone egress limit: {response}"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_and_unknown_requests_consume_the_request_budget() -> Result<()> {
    for malformed in [false, true] {
        let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
            return Ok(());
        };
        fixture.config.requests_per_second = 1;
        fixture.start().await?;
        // Start near the beginning of a fixed rate window so the pair cannot straddle it.
        while zone_gateway::clock::continuous_seconds().fract() > 0.1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        if malformed {
            let rejected = fixture
                .http
                .post(fixture.base.join("rpc")?)
                .body("{")
                .send()
                .await?;
            assert_eq!(rejected.status(), reqwest::StatusCode::BAD_REQUEST);
        } else {
            fixture
                .post(
                    None,
                    None,
                    json!({"jsonrpc":"2.0","id":1,"method":"unknown_method","params":[]}),
                )
                .await?;
        }
        let token = fixture
            .token(&fixture.root, CredentialKind::AccountRoot, 0)
            .header()?;
        let response = fixture
            .post(
                Some(&token),
                None,
                json!({"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}),
            )
            .await?;
        let calls = fixture.backend.calls.lock().unwrap().len();
        fixture.shutdown().await?;
        assert!(
            response.get("error").is_some(),
            "Pre-authentication request did not consume the Zone request limit: {response}"
        );
        assert_eq!(calls, 0, "A call after rate exhaustion reached the backend");
    }
    Ok(())
}
