//! Private, authenticated adapter for the concrete TIDX GET query and SSE protocol.
use crate::{clock, gateway::limited_response, store::DeliveryEvent};
use alloy_primitives::B256;
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use eyre::{Result, ensure, eyre};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch};
use zone_auth::transport::{GatewayTlsConfig, VerifiedGatewayPeer, serve_gateway};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryTls {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub gateway_ca: PathBuf,
    pub gateway_certificate_hash: B256,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryConfig {
    pub listen: SocketAddr,
    pub zone_chain_id: u64,
    pub tidx_backend: url::Url,
    pub tls: BoundaryTls,
    /// Fixed deployment SELECT projection with event_id, cursor and payload columns.
    pub event_sql: String,
    pub max_response_bytes: usize,
}

impl BoundaryConfig {
    pub async fn load(path: &Path) -> Result<Self> {
        let bytes = tokio::fs::read(path).await?;
        ensure!(bytes.len() <= 64 * 1024, "boundary configuration too large");
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    fn transport(&self) -> GatewayTlsConfig {
        GatewayTlsConfig {
            certificate: self.tls.certificate.clone(),
            private_key: self.tls.private_key.clone(),
            gateway_ca: self.tls.gateway_ca.clone(),
            gateway_certificate_hash: self.tls.gateway_certificate_hash,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.zone_chain_id > 0, "Zone chain ID required");
        ensure!(
            (1024..=64 * 1024 * 1024).contains(&self.max_response_bytes),
            "invalid boundary response budget"
        );
        ensure!(
            !self.event_sql.trim().is_empty()
                && self.event_sql.len() <= 8192
                && !self.event_sql.contains(';'),
            "fixed event projection required"
        );
        let url = &self.tidx_backend;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "TIDX origin may not contain credentials or query"
        );
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        ensure!(
            url.scheme() == "https" || url.scheme() == "http" && loopback,
            "plaintext TIDX must use loopback"
        );
        self.transport().validate()
    }
}

pub struct IndexerBoundary;
#[derive(Clone)]
struct BoundaryState {
    config: BoundaryConfig,
    http: reqwest::Client,
}

impl IndexerBoundary {
    pub async fn serve(config: BoundaryConfig) -> Result<()> {
        let listener = TcpListener::bind(config.listen).await?;
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Self::serve_on(config, listener, async move {
            #[cfg(unix)]
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        })
        .await
    }

    pub async fn serve_on(
        config: BoundaryConfig,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> Result<()> {
        config.validate()?;
        let transport = config.transport();
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(35))
            .build()?;
        let state = Arc::new(BoundaryState { config, http });
        let router = Router::new()
            .route("/query", get(query))
            .route("/events", get(events))
            .route("/gateway/context", get(probe))
            .with_state(state);
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = serve_gateway(listener, router, transport, stop_rx);
        tokio::pin!(server);
        tokio::pin!(shutdown);
        tokio::select! {
            result = &mut server => result,
            _ = &mut shutdown => {
                let _ = stop_tx.send(true);
                tokio::time::timeout(Duration::from_secs(10), &mut server).await??;
                Ok(())
            }
        }
    }
}

async fn probe(Extension(_peer): Extension<VerifiedGatewayPeer>) -> Json<Value> {
    Json(json!({"protocol":1,"backend":"tidx","query":"/query","events":"/events"}))
}

fn expiry(headers: &HeaderMap) -> Result<u64> {
    ensure!(
        headers.get_all("x-zone-context-version").iter().count() == 1
            && headers.get_all("x-zone-expires-at").iter().count() == 1,
        "ambiguous context headers"
    );
    ensure!(
        headers
            .get("x-zone-context-version")
            .and_then(|h| h.to_str().ok())
            == Some("1"),
        "context version required"
    );
    let expires = headers
        .get("x-zone-expires-at")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| eyre!("context expiry required"))?
        .parse::<u64>()?;
    ensure!(expires > clock::unix_seconds()?, "context expired");
    Ok(expires)
}

pub(crate) fn pin_chain(url: &mut url::Url, expected: u64) -> Result<()> {
    let mut parameters = Vec::new();
    for (key, value) in url.query_pairs() {
        if key == "chainId" || key == "chain_id" {
            ensure!(
                value.parse::<u64>()? == expected,
                "another chain was requested"
            );
        } else {
            parameters.push((key.into_owned(), value.into_owned()));
        }
    }
    url.set_query(None);
    let mut query = url.query_pairs_mut();
    query.extend_pairs(parameters);
    query.append_pair("chainId", &expected.to_string());
    Ok(())
}

fn constrain_engine(url: &mut url::Url) -> Result<()> {
    for (key, value) in url.query_pairs() {
        if key == "engine" || key == "source" {
            ensure!(value == "postgres", "Indexer engine override denied");
        }
    }
    let parameters: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key != "engine" && key != "source")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(parameters)
        .append_pair("engine", "postgres")
        .append_pair("source", "postgres");
    Ok(())
}

async fn query(
    State(state): State<Arc<BoundaryState>>,
    Extension(_peer): Extension<VerifiedGatewayPeer>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let result: Result<Response> = async {
        let expires_at = expiry(&headers)?;
        let mut url =
            crate::indexer::upstream_url(&state.config.tidx_backend, "/query", uri.query())?;
        pin_chain(&mut url, state.config.zone_chain_id)?;
        constrain_engine(&mut url)?;
        let live = url
            .query_pairs()
            .any(|(key, value)| key == "live" && value == "true");
        let request = state.http.get(url);
        let request = if live {
            request.timeout(Duration::from_secs(
                expires_at
                    .saturating_sub(clock::unix_seconds()?)
                    .min(2_592_060),
            ))
        } else {
            request
        };
        expiry(&headers)?;
        let response = tokio::time::timeout(Duration::from_secs(35), request.send()).await??;
        let status = response.status();
        let content_type = response.headers().get("content-type").cloned();
        if live && status.is_success() {
            ensure!(
                content_type
                    .as_ref()
                    .and_then(|h| h.to_str().ok())
                    .is_some_and(|h| h.starts_with("text/event-stream")),
                "TIDX live response is not SSE"
            );
            let stream = futures::stream::try_unfold(
                (response.bytes_stream(), state.clone(), headers),
                |(mut stream, state, headers)| async move {
                    loop {
                        expiry(&headers)?;
                        match tokio::time::timeout(Duration::from_secs(1), stream.next()).await {
                            Err(_) => continue,
                            Ok(None) => return Ok::<_, eyre::Report>(None),
                            Ok(Some(chunk)) => {
                                let chunk = chunk?;
                                ensure!(
                                    chunk.len() <= state.config.max_response_bytes,
                                    "TIDX stream chunk too large"
                                );
                                expiry(&headers)?;
                                return Ok(Some((chunk, (stream, state, headers))));
                            }
                        }
                    }
                },
            );
            return Ok((
                status,
                [(
                    axum::http::header::CONTENT_TYPE,
                    content_type.expect("checked content type"),
                )],
                Body::from_stream(stream),
            )
                .into_response());
        }
        let bytes = limited_response(response, state.config.max_response_bytes).await?;
        expiry(&headers)?;
        let mut response = (status, bytes).into_response();
        if let Some(value) = content_type {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_TYPE, value);
        }
        Ok(response)
    }
    .await;
    match result {
        Ok(response) => response,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventQuery {
    after: u64,
    #[serde(default = "page_limit")]
    limit: u32,
    #[serde(rename = "chainId")]
    chain_id: Option<u64>,
}
fn page_limit() -> u32 {
    100
}

#[derive(Deserialize)]
struct TidxResult {
    ok: bool,
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
    row_count: usize,
}

fn event_page(result: TidxResult, after: u64, limit: usize) -> Result<Value> {
    ensure!(
        result.ok
            && result.columns == ["event_id", "cursor", "payload"]
            && result.row_count == result.rows.len()
            && result.rows.len() <= limit,
        "invalid TIDX event response"
    );
    let mut previous = after;
    let mut events = Vec::with_capacity(result.rows.len());
    for row in result.rows {
        ensure!(row.len() == 3, "invalid TIDX event row");
        let event_id = row[0]
            .as_str()
            .ok_or_else(|| eyre!("event ID is not text"))?
            .to_owned();
        let cursor = match &row[1] {
            Value::String(value) => value.parse::<u64>()?,
            value => value.as_u64().ok_or_else(|| eyre!("cursor is not u64"))?,
        };
        ensure!(
            !event_id.is_empty() && event_id.len() <= 256 && cursor > previous,
            "unstable event identity or cursor"
        );
        previous = cursor;
        events.push(DeliveryEvent {
            event_id,
            cursor,
            payload: row[2].clone(),
        });
    }
    Ok(json!({"events":events,"next_cursor":previous}))
}

async fn events(
    State(state): State<Arc<BoundaryState>>,
    Extension(_peer): Extension<VerifiedGatewayPeer>,
    headers: HeaderMap,
    Query(input): Query<EventQuery>,
) -> Response {
    let result: Result<Value> = async {
        expiry(&headers)?;
        ensure!((1..=100).contains(&input.limit) && input.chain_id.is_none_or(|id|id==state.config.zone_chain_id), "invalid event page selection");
        // Both interpolation values are validated integers; the projection is infrastructure configuration.
        let sql = format!("SELECT event_id, cursor, payload FROM ({}) AS gateway_events WHERE cursor > {} ORDER BY cursor ASC LIMIT {}", state.config.event_sql, input.after, input.limit);
        let mut url = crate::indexer::upstream_url(&state.config.tidx_backend, "/query", None)?;
        url.query_pairs_mut().append_pair("sql", &sql).append_pair("chainId", &state.config.zone_chain_id.to_string())
            .append_pair("engine", "postgres").append_pair("source", "postgres").append_pair("limit", &input.limit.to_string()).append_pair("timeout_ms", "2000");
        let response = state.http.get(url).timeout(Duration::from_secs(2)).send().await?;
        ensure!(response.status().is_success(), "TIDX event query unavailable");
        let bytes = limited_response(response, state.config.max_response_bytes).await?;
        let page = event_page(serde_json::from_slice(&bytes)?, input.after, input.limit as usize)?;
        expiry(&headers)?;
        Ok(page)
    }.await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multi_chain_tidx_cannot_expand_one_zone_permission() {
        let mut url = url::Url::parse(
            "https://tidx.internal/query?sql=SELECT+1&chainId=101&signature=A&signature=B",
        )
        .unwrap();
        pin_chain(&mut url, 101).unwrap();
        assert_eq!(
            url.query_pairs()
                .filter(|(key, _)| key == "signature")
                .count(),
            2
        );
        for query in [
            "chainId=102",
            "chain_id=102",
            "chainId=101&chainId=102",
            "chainId=abc",
        ] {
            let mut bad = url::Url::parse(&format!("https://tidx.internal/query?{query}")).unwrap();
            assert!(pin_chain(&mut bad, 101).is_err());
        }
    }
    #[test]
    fn concrete_tidx_rows_become_stable_delivery_events() {
        let result:TidxResult=serde_json::from_value(json!({"ok":true,"columns":["event_id","cursor","payload"],"rows":[["hash-17","17",{"number":17}],["hash-18",18,{"number":18}]],"row_count":2})).unwrap();
        assert_eq!(
            event_page(result, 16, 100).unwrap(),
            json!({"events":[{"event_id":"hash-17","cursor":17,"payload":{"number":17}},{"event_id":"hash-18","cursor":18,"payload":{"number":18}}],"next_cursor":18})
        );
        let bad:TidxResult=serde_json::from_value(json!({"ok":true,"columns":["event_id","cursor","payload"],"rows":[["bad","16",{}]],"row_count":1})).unwrap();
        assert!(event_page(bad, 16, 100).is_err());
    }
}
