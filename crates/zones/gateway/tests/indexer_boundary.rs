use alloy_primitives::{B256, keccak256};
use axum::{
    Json, Router, body::Body, extract::Query, http::StatusCode, response::IntoResponse,
    routing::get,
};
use eyre::{Result, ensure};
use futures::StreamExt;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot};
use zone_gateway::indexer_boundary::{BoundaryConfig, BoundaryTls, IndexerBoundary};

#[derive(Deserialize)]
struct TidxQuery {
    #[serde(rename = "chainId")]
    chain_id: u64,
    sql: String,
    #[serde(default)]
    live: bool,
}

fn raw_tidx(observed: Arc<Mutex<Vec<String>>>) -> Router {
    Router::new().route("/query",get(move |Query(query):Query<TidxQuery>| {
        let observed=observed.clone();
        async move {
            assert_eq!(query.chain_id,101);
            observed.lock().unwrap().push(query.sql.clone());
            if query.live {
                let stream=futures::stream::iter([Ok::<_, std::io::Error>("event: result\ndata: {\"ok\":true,\"columns\":[\"num\"],\"rows\":[[17]],\"row_count\":1}\n\n")])
                    .chain(futures::stream::pending());
                return ([ ("content-type","text/event-stream") ],Body::from_stream(stream)).into_response();
            }
            if query.sql.starts_with("SELECT event_id, cursor, payload FROM (") {
                assert!(query.sql.contains("WHERE cursor > 16 ORDER BY cursor ASC LIMIT 100"));
                Json(json!({"ok":true,"columns":["event_id","cursor","payload"],"rows":[["block-hash-17","17","0x17"]],"row_count":1})).into_response()
            } else {
                assert_eq!(query.sql,"SELECT num FROM blocks LIMIT 1");
                Json(json!({"ok":true,"columns":["num"],"rows":[[17]],"row_count":1})).into_response()
            }
        }
    }))
}

fn certificates(
    temp: &tempfile::TempDir,
) -> Result<(BoundaryTls, reqwest::Client, reqwest::Client)> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate()?;
    let mut parameters = CertificateParams::new(vec!["localhost".into()])?;
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = parameters.signed_by(&key, &issuer)?;
    let mut clients = Vec::new();
    let mut pin = B256::ZERO;
    for index in 0..2 {
        let key = KeyPair::generate()?;
        let mut parameters = CertificateParams::new(vec![format!("gateway-{index}.fixture")])?;
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = parameters.signed_by(&key, &issuer)?;
        if index == 0 {
            pin = keccak256(certificate.der().as_ref());
        }
        let identity = reqwest::Identity::from_pem(
            format!("{}{}", certificate.pem(), key.serialize_pem()).as_bytes(),
        )?;
        clients.push(
            reqwest::Client::builder()
                .identity(identity)
                .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes())?)
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()?,
        );
    }
    let tls = BoundaryTls {
        certificate: temp.path().join("server.pem"),
        private_key: temp.path().join("server.key"),
        gateway_ca: temp.path().join("ca.pem"),
        gateway_certificate_hash: pin,
    };
    std::fs::write(&tls.certificate, server.pem())?;
    std::fs::write(&tls.private_key, key.serialize_pem())?;
    std::fs::write(&tls.gateway_ca, ca.pem())?;
    Ok((tls, clients.remove(0), clients.remove(0)))
}

#[tokio::test]
async fn executable_boundary_uses_actual_tidx_query_sse_and_event_shapes() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let raw = TcpListener::bind("127.0.0.1:0").await?;
    let tidx_backend = url::Url::parse(&format!("http://{}/", raw.local_addr()?))?;
    let raw_router = raw_tidx(observed.clone());
    let raw_task = tokio::spawn(async move {
        axum::serve(raw, raw_router).await.unwrap();
    });
    let temp = tempfile::tempdir()?;
    let (tls, http, wrong_identity) = certificates(&temp)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let base = url::Url::parse(&format!(
        "https://localhost:{}/",
        listener.local_addr()?.port()
    ))?;
    let config=BoundaryConfig{listen:listener.local_addr()?,zone_chain_id:101,tidx_backend,tls,
        event_sql:"SELECT encode(hash, 'hex') AS event_id, num AS cursor, encode(hash, 'hex') AS payload FROM blocks".into(),max_response_bytes:1024*1024};
    let (stop_tx, stop_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        IndexerBoundary::serve_on(config, listener, async {
            let _ = stop_rx.await;
        })
        .await
    });
    let expires = zone_gateway::clock::unix_seconds()? + 30;
    let request = |url: url::Url| {
        http.get(url)
            .header("x-zone-context-version", "1")
            .header("x-zone-expires-at", expires.to_string())
    };
    let mut query = base.join("query")?;
    query
        .query_pairs_mut()
        .append_pair("sql", "SELECT num FROM blocks LIMIT 1");
    let response = request(query.clone()).send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await?,
        json!({"ok":true,"columns":["num"],"rows":[[17]],"row_count":1})
    );
    let response = request(base.join("events?after=16&limit=100")?)
        .send()
        .await?;
    assert_eq!(
        response.json::<Value>().await?,
        json!({"events":[{"event_id":"block-hash-17","cursor":17,"payload":"0x17"}],"next_cursor":17})
    );
    query.query_pairs_mut().append_pair("live", "true");
    let response = request(query.clone()).send().await?;
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let mut stream = response.bytes_stream();
    let frame = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await?
        .unwrap()?;
    ensure!(String::from_utf8_lossy(&frame).contains("event: result"));
    drop(stream);
    let soon = zone_gateway::clock::unix_seconds()? + 2;
    let response = http
        .get(query.clone())
        .header("x-zone-context-version", "1")
        .header("x-zone-expires-at", soon.to_string())
        .send()
        .await?;
    let mut short_stream = response.bytes_stream();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), short_stream.next())
            .await?
            .unwrap()
            .is_ok()
    );
    tokio::time::timeout(Duration::from_secs(4), async {
        while let Some(Ok(_)) = short_stream.next().await {}
    })
    .await?;
    let before = observed.lock().unwrap().len();
    let mut wrong_engine = query.clone();
    wrong_engine
        .query_pairs_mut()
        .append_pair("engine", "clickhouse");
    assert_eq!(
        request(wrong_engine).send().await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    query.query_pairs_mut().append_pair("chainId", "102");
    assert_eq!(
        request(query).send().await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        http.get(base.join("query?sql=SELECT+1")?)
            .header("x-zone-context-version", "1")
            .header("x-zone-expires-at", "1")
            .send()
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let mut duplicate_context = reqwest::header::HeaderMap::new();
    duplicate_context.append("x-zone-context-version", "1".parse()?);
    duplicate_context.append("x-zone-context-version", "1".parse()?);
    duplicate_context.insert("x-zone-expires-at", expires.to_string().parse()?);
    assert_eq!(
        http.get(base.join("query?sql=SELECT+1")?)
            .headers(duplicate_context)
            .send()
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        http.get(base.join("query?sql=SELECT+1")?)
            .send()
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        observed.lock().unwrap().len(),
        before,
        "invalid context never reaches raw TIDX"
    );
    assert!(
        wrong_identity
            .get(base.join("gateway/context")?)
            .send()
            .await
            .is_err(),
        "same CA is insufficient without the gateway certificate pin"
    );
    let _ = stop_tx.send(());
    tokio::time::timeout(Duration::from_secs(10), task).await???;
    raw_task.abort();
    Ok(())
}

#[tokio::test]
async fn deployment_reader_role_cannot_query_another_zone_through_a_qualified_cte() -> Result<()> {
    let Some(url) = std::env::var("ZONES_GATEWAY_TEST_DATABASE_URL").ok() else {
        eprintln!("role isolation test requires ZONES_GATEWAY_TEST_DATABASE_URL");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&url).await?;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let own = format!("zone_own_{suffix}");
    let other = format!("zone_other_{suffix}");
    let reader = format!("zone_reader_{suffix}");
    sqlx::raw_sql(&format!("CREATE SCHEMA {own}; CREATE SCHEMA {other}; CREATE TABLE {own}.blocks(num BIGINT); INSERT INTO {own}.blocks VALUES(17); CREATE TABLE {own}.txs(id BIGINT); CREATE TABLE {own}.logs(id BIGINT); CREATE TABLE {own}.receipts(id BIGINT); CREATE TABLE {other}.blocks(num BIGINT); INSERT INTO {other}.blocks VALUES(99)"))
        .execute(&pool).await?;
    let deployment = include_str!("../../../../deploy/zones-gateway/reader-role.sql")
        .replace("zone_indexer_reader", &reader)
        .replace("public", &own);
    sqlx::raw_sql(&deployment).execute(&pool).await?;
    // Even granting the unrelated schema's visibility must not grant its data.
    sqlx::raw_sql(&format!("GRANT USAGE ON SCHEMA {other} TO {reader}"))
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::raw_sql(&format!(
        "SET LOCAL ROLE {reader}; SET LOCAL search_path TO {own}"
    ))
    .execute(&mut *tx)
    .await?;
    let number: i64 = sqlx::query_scalar("SELECT num FROM blocks")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(number, 17);
    let failure = sqlx::query_scalar::<_, i64>(&format!(
        "WITH selected AS (SELECT num FROM {other}.blocks) SELECT num FROM selected"
    ))
    .fetch_one(&mut *tx)
    .await
    .unwrap_err();
    assert_eq!(
        failure
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("42501")
    );
    tx.rollback().await?;
    sqlx::raw_sql(&format!("DROP OWNED BY {reader}; DROP SCHEMA {own} CASCADE; DROP SCHEMA {other} CASCADE; DROP ROLE {reader}"))
        .execute(&pool).await?;
    pool.close().await;
    Ok(())
}
