mod support;
use alloy_primitives::{Address, keccak256};
use alloy_signer::SignerSync;
use axum::Router;
use eyre::Result;
use futures::SinkExt;
use serde_json::{Value, json};
use support::{Fixture, ws_response};
use tokio_tungstenite::tungstenite::Message;
use zone_auth::{Change, CredentialKind, Scope};

fn call(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}
fn legacy(f: &Fixture, ttl: u64) -> String {
    let now = zone_gateway::clock::unix_seconds().unwrap();
    let mut fields = Vec::new();
    fields.push(0);
    fields.extend_from_slice(&0u32.to_be_bytes());
    fields.extend_from_slice(&f.config.domain.zone_chain_id.to_be_bytes());
    fields.extend_from_slice(&now.to_be_bytes());
    fields.extend_from_slice(&(now + ttl).to_be_bytes());
    let mut message = vec![0u8; 32];
    message[..12].copy_from_slice(b"TempoZoneRPC");
    message.extend_from_slice(&fields);
    let mut bytes = f
        .root
        .sign_hash_sync(&keccak256(message))
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes.extend(fields);
    format!("0x{}", alloy_primitives::hex::encode(bytes))
}

#[tokio::test]
async fn real_listener_preserves_self_access_scope_order_and_private_context() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    let root = fixture
        .token(&fixture.root, CredentialKind::AccountRoot, 0)
        .header()?;
    let own = fixture
        .post(
            Some(&root),
            None,
            call(
                1,
                "eth_getBalance",
                json!([fixture.root.address(), "latest"]),
            ),
        )
        .await?;
    assert_eq!(own, json!({"jsonrpc":"2.0","id":1,"result":"0x1234"}));
    let other = fixture
        .post(
            Some(&root),
            None,
            call(
                2,
                "eth_getBalance",
                json!([Address::repeat_byte(0xa2), "latest"]),
            ),
        )
        .await?;
    assert_eq!(other["result"], "0x0");
    let legacy_token = legacy(&fixture, 600);
    assert_eq!(
        fixture
            .post(
                Some(&legacy_token),
                None,
                call(
                    3,
                    "eth_getBalance",
                    json!([fixture.root.address(), "latest"])
                )
            )
            .await?["result"],
        "0x1234"
    );
    let long_legacy = legacy(&fixture, 601);
    let before = fixture.backend.calls.lock().unwrap().len();
    assert!(
        fixture
            .post(
                Some(&long_legacy),
                None,
                call(
                    4,
                    "eth_getBalance",
                    json!([fixture.root.address(), "latest"])
                )
            )
            .await?
            .get("error")
            .is_some()
    );
    assert!(
        fixture
            .post(None, None, call(5, "eth_chainId", json!([])))
            .await?
            .get("error")
            .is_some()
    );
    assert!(
        fixture
            .post(
                Some(&root),
                Some(fixture.other.address()),
                call(
                    6,
                    "eth_getBalance",
                    json!([fixture.other.address(), "latest"])
                )
            )
            .await?
            .get("error")
            .is_some()
    );
    assert_eq!(
        fixture.backend.calls.lock().unwrap().len(),
        before,
        "invalid or mismatching credentials never dispatch"
    );

    fixture.admit(&fixture.client, &[Scope::RpcRead]).await?;
    let client = fixture
        .token(&fixture.client, CredentialKind::Client, 1)
        .header()?;
    let requests = json!([
        call(
            10,
            "eth_getBalance",
            json!([fixture.root.address(), "latest"])
        ),
        call(11, "eth_sendRawTransaction", json!(["0x00"])),
        call(12, "credential-shaped-unknown-method", json!([])),
        call(13, "eth_chainId", json!([]))
    ]);
    let before = fixture.backend.calls.lock().unwrap().len();
    let response = fixture
        .post(Some(&client), Some(fixture.root.address()), requests)
        .await?;
    assert_eq!(
        response
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![10, 11, 12, 13]
    );
    assert_eq!(response[0]["result"], "0x1234");
    assert_eq!(response[3]["result"], "0x65");
    assert_eq!(response[1]["error"]["code"], -32001);
    assert_eq!(response[2]["error"]["code"], -32001);
    let observed = fixture.backend.calls.lock().unwrap().clone();
    assert_eq!(observed.len() - before, 2);
    assert_eq!(
        observed[before..]
            .iter()
            .map(|r| r.method.as_str())
            .collect::<Vec<_>>(),
        vec!["eth_getBalance", "eth_chainId"]
    );
    assert!(
        observed[before..]
            .iter()
            .all(|r| r.account == fixture.root.address())
    );

    let forged = fixture
        .http
        .post(fixture.base.join("rpc")?)
        .header("x-authorization-token", &client)
        .header("x-zone-account", fixture.root.address().to_string())
        .header("x-zone-expires-at", u64::MAX.to_string())
        .header("x-zone-context-version", "999")
        .header("x-zone-principal", fixture.admin.address().to_string())
        .json(&call(
            14,
            "eth_getBalance",
            json!([fixture.root.address(), "latest"]),
        ))
        .send()
        .await?
        .json::<Value>()
        .await?;
    assert_eq!(forged["result"], "0x1234");
    let last = fixture
        .backend
        .calls
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last.headers["x-zone-context-version"], "1");
    assert_ne!(last.headers["x-zone-expires-at"], u64::MAX.to_string());
    assert!(last.headers.get("x-zone-principal").is_none());

    let ca = reqwest::Certificate::from_pem(&std::fs::read(&fixture.config.backend_tls.ca)?)?;
    let direct = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .timeout(std::time::Duration::from_secs(2))
        .build()?;
    let before = fixture.backend.calls.lock().unwrap().len();
    assert!(
        direct
            .post(fixture.config.rpc_backend.clone())
            .header("x-zone-account", fixture.root.address().to_string())
            .json(&call(
                15,
                "eth_getBalance",
                json!([fixture.root.address(), "latest"])
            ))
            .send()
            .await
            .is_err(),
        "forged account headers cannot replace backend client authentication"
    );
    assert_eq!(fixture.backend.calls.lock().unwrap().len(), before);
    let logs = fixture
        .post(
            Some(&client),
            None,
            call(
                16,
                "zone_listAccess",
                json!([{"owner":fixture.admin.address(),"all":true}]),
            ),
        )
        .await?;
    assert!(
        logs["result"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["principal"] == json!(fixture.client.address()))
    );
    assert!(
        logs["result"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("tempo_hash").is_some())
    );
    fixture.shutdown().await
}

#[tokio::test]
async fn http_final_batch_gate_and_websocket_handles_bind_to_verified_owner() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    fixture.admit(&fixture.client, &[Scope::RpcRead]).await?;
    fixture.admit(&fixture.other, &[Scope::RpcRead]).await?;
    let signed_token = fixture.token(&fixture.client, CredentialKind::Client, 1);
    let client = signed_token.header()?;
    let other = fixture
        .token(&fixture.other, CredentialKind::Client, 1)
        .header()?;
    let acting = fixture.root.address();
    let filter = fixture
        .post(
            Some(&client),
            Some(acting),
            call(20, "eth_newFilter", json!([{}])),
        )
        .await?;
    let alias = filter["result"].as_str().unwrap();
    assert_ne!(alias, "0xbeef");
    let before = fixture.backend.calls.lock().unwrap().len();
    let stolen = fixture
        .post(
            Some(&other),
            Some(acting),
            call(21, "eth_getFilterChanges", json!([alias])),
        )
        .await?;
    assert_eq!(stolen["error"]["code"], -32001);
    assert_eq!(fixture.backend.calls.lock().unwrap().len(), before);
    let owned = fixture
        .post(
            Some(&client),
            Some(acting),
            call(22, "eth_getFilterChanges", json!([alias])),
        )
        .await?;
    assert_eq!(owned["result"], json!([{"visible":"private"}]));

    let mut ws = fixture.connect_ws(&client, Some(acting)).await?;
    ws.send(Message::Text(
        json!([
            call(30, "eth_chainId", json!([])),
            call(31, "eth_getFilterChanges", json!([alias])),
            call(32, "eth_sendRawTransaction", json!(["0x00"])),
            call(33, "eth_subscribe", json!(["newHeads"]))
        ])
        .to_string()
        .into(),
    ))
    .await?;
    let response = ws_response(&mut ws).await?;
    assert!(
        response.is_array(),
        "WebSocket batches return one ordered response array"
    );
    assert_eq!(
        response
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![30, 31, 32, 33]
    );
    assert_eq!(response[0]["result"], "0x65");
    assert_eq!(response[1]["result"], json!([{"visible":"private"}]));
    assert_eq!(response[2]["error"]["code"], -32001);
    let subscription = response[3]["result"].as_str().unwrap().to_owned();
    assert_ne!(subscription, "0x100");
    let mut thief = fixture.connect_ws(&other, Some(acting)).await?;
    thief
        .send(Message::Text(
            json!([
                call(34, "eth_getFilterChanges", json!([alias])),
                call(35, "eth_unsubscribe", json!([subscription]))
            ])
            .to_string()
            .into(),
        ))
        .await?;
    let response = ws_response(&mut thief).await?;
    assert_eq!(response[0]["error"]["code"], -32001);
    assert_eq!(response[1]["error"]["code"], -32001);
    ws.send(Message::Text(
        call(36, "eth_unsubscribe", json!([subscription]))
            .to_string()
            .into(),
    ))
    .await?;
    assert_eq!(ws_response(&mut ws).await?["result"], true);
    ws.close(None).await?;
    thief.close(None).await?;

    let revoke = fixture.signed_op(
        fixture.client.address(),
        2,
        1,
        Change::RevokeToken {
            generation: 1,
            token_id: signed_token.token.token_id,
        },
    );
    let batch = json!([
        call(40, "eth_getBalance", json!([acting, "latest"])),
        call(41, "zone_applyAccessOp", json!([revoke]))
    ]);
    let before = fixture.backend.calls.lock().unwrap().len();
    let response = fixture.post(Some(&client), Some(acting), batch).await?;
    assert_eq!(response[0]["id"], 40);
    assert_eq!(response[0]["error"]["code"], -32001);
    assert!(
        response[0].get("result").is_none(),
        "a private result buffered before revocation must not be released"
    );
    assert_eq!(response[1]["id"], 41);
    assert_eq!(response[1]["result"]["digest"], json!(revoke.op.digest()));
    assert_eq!(
        fixture.backend.calls.lock().unwrap().len() - before,
        1,
        "allowed earlier work remains dispatched despite later revocation"
    );
    let logs = fixture
        .store
        .logs(
            &zone_auth::Principal::ZoneAdmin(fixture.admin.address()),
            true,
            0,
            1000,
        )
        .await?;
    let suppressed = logs
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|record| {
            record["method"] == "eth_getBalance"
                && record["principal"] == json!(fixture.client.address())
        })
        .unwrap();
    assert!(
        suppressed["completions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["outcome"] == "backend_success")
    );
    assert!(
        !suppressed["completions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["outcome"] == "release_admitted"),
        "a batch result suppressed by revocation cannot be logged as admitted"
    );
    assert!(
        fixture
            .post(
                Some(&client),
                Some(acting),
                call(42, "eth_getBalance", json!([acting, "latest"]))
            )
            .await?
            .get("error")
            .is_some()
    );
    let self_result = fixture
        .post(
            Some(&client),
            None,
            call(
                43,
                "eth_getBalance",
                json!([fixture.client.address(), "latest"]),
            ),
        )
        .await?;
    assert_eq!(
        self_result["result"], "0x1234",
        "registry token revocation cannot remove valid self-account proof"
    );
    fixture.shutdown().await
}

#[tokio::test]
async fn abrupt_restart_preserves_revocation_and_original_receipt() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    let admission = fixture.signed_op(
        fixture.client.address(),
        1,
        0,
        Change::Admit {
            name: "restart fixture".into(),
            scopes: [Scope::RpcRead].into_iter().collect(),
            accounts: zone_auth::AccountSet::Listed([fixture.root.address()].into_iter().collect()),
        },
    );
    let original_admission = fixture.apply(&admission).await?["result"].clone();
    assert_eq!(original_admission["offset"], 1);
    fixture.crash_and_restart().await?;
    assert_eq!(
        fixture.apply(&admission).await?["result"],
        original_admission,
        "retry after losing the request process must resolve the exact original receipt"
    );
    let token = fixture.token(&fixture.client, CredentialKind::Client, 1);
    let header = token.header()?;
    assert_eq!(
        fixture
            .post(
                Some(&header),
                Some(fixture.root.address()),
                call(
                    50,
                    "eth_getBalance",
                    json!([fixture.root.address(), "latest"])
                )
            )
            .await?["result"],
        "0x1234"
    );
    let revoke = fixture.signed_op(
        fixture.client.address(),
        2,
        1,
        Change::RevokeToken {
            generation: 1,
            token_id: token.token.token_id,
        },
    );
    let original_revocation = fixture.apply(&revoke).await?["result"].clone();
    assert_eq!(original_revocation["offset"], 2);
    fixture.crash_and_restart().await?;
    let before = fixture.backend.calls.lock().unwrap().len();
    assert_eq!(
        fixture
            .post(
                Some(&header),
                Some(fixture.root.address()),
                call(
                    51,
                    "eth_getBalance",
                    json!([fixture.root.address(), "latest"])
                )
            )
            .await?["error"]["code"],
        -32001
    );
    assert_eq!(
        fixture.backend.calls.lock().unwrap().len(),
        before,
        "revoked authority must not dispatch after an empty runtime cache restart"
    );
    assert_eq!(fixture.apply(&revoke).await?["result"], original_revocation);
    assert_eq!(
        fixture.apply(&admission).await?["result"],
        original_admission
    );
    fixture.shutdown().await
}

#[tokio::test]
async fn idle_websocket_revocation_closes_within_five_seconds() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    fixture.admit(&fixture.client, &[Scope::RpcRead]).await?;
    let token = fixture.token(&fixture.client, CredentialKind::Client, 1);
    let header = token.header()?;
    let mut socket = fixture
        .connect_ws(&header, Some(fixture.root.address()))
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !fixture
            .backend
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.method == "ws_upgrade")
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    let revoke = fixture.signed_op(
        fixture.client.address(),
        2,
        1,
        Change::RevokeToken {
            generation: 1,
            token_id: token.token.token_id,
        },
    );
    assert!(fixture.apply(&revoke).await?.get("result").is_some());
    let committed = std::time::Instant::now();
    use futures::StreamExt;
    let closure = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await?;
    assert!(
        matches!(closure, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
        "idle revoked socket must close without requiring another client frame"
    );
    assert!(committed.elapsed() < std::time::Duration::from_secs(5));
    fixture.shutdown().await
}

async fn wait_readiness(fixture: &Fixture, status: reqwest::StatusCode, bound: u64) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(bound), async {
        loop {
            if fixture
                .http
                .get(fixture.base.join("health/ready")?)
                .send()
                .await?
                .status()
                == status
            {
                return Ok::<(), eyre::Report>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn provider_outage_closes_readiness_and_healing_resumes_service() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    let admitted = fixture.signed_op(
        fixture.client.address(),
        1,
        0,
        Change::Admit {
            name: "outage receipt fixture".into(),
            scopes: [Scope::RpcRead].into_iter().collect(),
            accounts: zone_auth::AccountSet::All,
        },
    );
    let original_receipt = fixture.apply(&admitted).await?["result"].clone();
    let root = fixture
        .token(&fixture.root, CredentialKind::AccountRoot, 0)
        .header()?;
    fixture
        .providers_healthy
        .store(false, std::sync::atomic::Ordering::Release);
    wait_readiness(&fixture, reqwest::StatusCode::SERVICE_UNAVAILABLE, 5).await?;
    assert!(
        fixture
            .http
            .get(fixture.base.join("health/live")?)
            .send()
            .await?
            .status()
            .is_success()
    );
    let before = fixture.backend.calls.lock().unwrap().len();
    let response = fixture
        .post(
            Some(&root),
            None,
            call(
                60,
                "eth_getBalance",
                json!([fixture.root.address(), "latest"]),
            ),
        )
        .await?;
    assert_eq!(response["error"]["code"], -32002);
    assert_eq!(fixture.backend.calls.lock().unwrap().len(), before);
    assert_eq!(
        fixture.apply(&admitted).await?["result"],
        original_receipt,
        "exact historical signed retry must survive unavailable current signature validators"
    );
    fixture
        .providers_healthy
        .store(true, std::sync::atomic::Ordering::Release);
    wait_readiness(&fixture, reqwest::StatusCode::OK, 10).await?;
    assert_eq!(
        fixture
            .post(
                Some(&root),
                None,
                call(
                    61,
                    "eth_getBalance",
                    json!([fixture.root.address(), "latest"])
                )
            )
            .await?["result"],
        "0x1234"
    );
    fixture.shutdown().await
}

#[tokio::test]
async fn durable_completion_failure_suppresses_private_response() -> Result<()> {
    let Some(mut fixture) = Fixture::prepare(Router::new()).await? else {
        return Ok(());
    };
    fixture.start().await?;
    let token = fixture
        .token(&fixture.root, CredentialKind::AccountRoot, 0)
        .header()?;
    let pool = sqlx::PgPool::connect(&fixture.config.database_url).await?;
    let suffix = alloy_primitives::hex::encode(fixture.config.domain.key());
    let function = format!("fixture_log_fail_{suffix}");
    let trigger = format!("fixture_log_trigger_{suffix}");
    let definition = format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='release_intent' AND EXISTS(SELECT 1 FROM gateway_decisions WHERE id=NEW.decision_id AND domain=decode('{suffix}','hex')) THEN RAISE EXCEPTION 'fixture completion storage unavailable'; END IF; RETURN NEW; END $$"
    );
    sqlx::query(&definition).execute(&pool).await?;
    sqlx::query(&format!("CREATE TRIGGER {trigger} BEFORE INSERT ON gateway_completions FOR EACH ROW EXECUTE FUNCTION {function}()" )).execute(&pool).await?;
    let before = fixture.backend.calls.lock().unwrap().len();
    let failed = fixture
        .post(
            Some(&token),
            None,
            call(
                70,
                "eth_getBalance",
                json!([fixture.root.address(), "latest"]),
            ),
        )
        .await;
    // Remove the domain-scoped fault before assertions so another fixture remains unaffected on failure.
    sqlx::query(&format!("DROP TRIGGER {trigger} ON gateway_completions"))
        .execute(&pool)
        .await?;
    sqlx::query(&format!("DROP FUNCTION {function}()"))
        .execute(&pool)
        .await?;
    let response = failed?;
    assert!(response.get("error").is_some());
    assert!(response.get("result").is_none());
    assert_eq!(
        fixture.backend.calls.lock().unwrap().len() - before,
        1,
        "the failure happens after the actual backend result"
    );
    let logs = fixture
        .store
        .logs(
            &zone_auth::Principal::Account(fixture.root.address()),
            false,
            0,
            100,
        )
        .await?;
    let record = logs
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["method"] == "eth_getBalance")
        .unwrap();
    assert!(
        record["completions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["outcome"] == "backend_success")
    );
    assert!(
        !record["completions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["outcome"] == "release_admitted")
    );
    assert_eq!(
        fixture
            .post(
                Some(&token),
                None,
                call(
                    71,
                    "eth_getBalance",
                    json!([fixture.root.address(), "latest"])
                )
            )
            .await?["result"],
        "0x1234",
        "healed completion storage permits private release"
    );
    fixture.shutdown().await
}
