//! Explicitly inventoried Indexer routes. Upstream credentials and context are never copied.
use crate::{
    chain::VerificationError,
    gateway::{AccessDenied, StateData, header, limited_response},
};
use axum::{
    body::{Body, Bytes},
    extract::{
        OriginalUri, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use eyre::{Result, ensure, eyre};
use futures::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use tokio_tungstenite::{
    Connector,
    tungstenite::{Message as UpstreamMessage, client::IntoClientRequest},
};
use zone_auth::{CodecError, Permission};

struct StreamMetrics {
    transport: &'static str,
    reason: &'static str,
}
impl StreamMetrics {
    fn new(transport: &'static str) -> Self {
        metrics::gauge!("zone_access_sessions", "transport" => "indexer").increment(1.0);
        metrics::gauge!("zone_access_indexer_streams_active","transport"=>transport).increment(1.0);
        metrics::counter!("zone_access_indexer_streams_opened_total","transport"=>transport)
            .increment(1);
        Self {
            transport,
            reason: "cancelled_or_error",
        }
    }
}
impl Drop for StreamMetrics {
    fn drop(&mut self) {
        metrics::gauge!("zone_access_sessions", "transport" => "indexer").decrement(1.0);
        metrics::gauge!("zone_access_indexer_streams_active","transport"=>self.transport)
            .decrement(1.0);
        metrics::counter!("zone_access_indexer_streams_closed_total","transport"=>self.transport,"reason"=>self.reason).increment(1);
    }
}

fn path(uri: &Uri) -> &str {
    uri.path().strip_prefix("/indexer").unwrap_or("")
}

/// Set the approved path on a fixed origin instead of resolving a URL reference.
/// A leading double slash must never select another host.
pub(crate) fn upstream_url(base: &url::Url, route: &str, query: Option<&str>) -> Result<url::Url> {
    ensure!(
        route.starts_with('/')
            && !route.starts_with("//")
            && !route.contains('%')
            && !route.contains("..")
            && !route.contains(['?', '#', '\\']),
        "invalid Indexer route"
    );
    let mut url = base.clone();
    url.set_path(route);
    url.set_query(query);
    Ok(url)
}

async fn denied(s: &StateData, method: &str) -> Response {
    match s.deny_log(method, None).await {
        Ok(()) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn failed(s: &StateData, method: &str, error: eyre::Report) -> Response {
    let access_denied = error.downcast_ref::<AccessDenied>().is_some()
        || error.downcast_ref::<CodecError>().is_some()
        || matches!(
            error.downcast_ref::<VerificationError>(),
            Some(VerificationError::Invalid)
        )
        || error.to_string() == "access denied";
    if access_denied {
        return denied(s, method).await;
    }
    let _ = s.deny_log(method, None).await;
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

pub(crate) async fn query(
    State(s): State<Arc<StateData>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Response {
    if !s.config.indexer_paths.iter().any(|p| p == path(&uri)) || header(&headers).is_err() {
        let _ = s.budget(0).await;
        return denied(&s, "indexer.query").await;
    }
    let result: Result<Response> = async {
        let upstream = s
            .config
            .indexer_backend
            .as_ref()
            .ok_or_else(|| eyre!("Indexer unavailable"))?;
        let token = header(&headers).map_err(|_| AccessDenied)?;
        let admission = s
            .authorize(token, None, Permission::IndexerRead, "indexer.query")
            .await?;
        let mut url = upstream_url(upstream, path(&uri), uri.query())?;
        crate::indexer_boundary::pin_chain(&mut url, s.config.domain.zone_chain_id)
            .map_err(|_| AccessDenied)?;
        let mut request = s
            .http
            .request(method, url)
            .header("x-zone-context-version", "1")
            .header("x-zone-expires-at", admission.proof.expires_at.to_string())
            .body(body);
        // Content type describes the bounded body. All identity/context headers are regenerated or absent.
        if let Some(value) = headers.get(axum::http::header::CONTENT_TYPE) {
            request = request.header(axum::http::header::CONTENT_TYPE, value);
        }
        s.recheck(&admission).await?;
        let response = request.send().await?;
        ensure!(response.status().is_success(), "Indexer unavailable");
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .cloned();
        let bytes = limited_response(response, s.config.max_response_bytes).await?;
        s.store
            .complete(admission.log_id, "backend_success")
            .await?;
        s.budget(bytes.len()).await?;
        s.store.complete(admission.log_id, "release_intent").await?;
        s.recheck(&admission).await?;
        let stream = futures::stream::try_unfold(
            (Some(Bytes::from(bytes)), s.clone(), admission),
            |(bytes, s, admission)| async move {
                match bytes {
                    Some(bytes) => {
                        s.recheck(&admission).await?;
                        Ok::<_, eyre::Report>(Some((bytes, (None, s, admission))))
                    }
                    None => {
                        let _ = s.store.complete(admission.log_id, "release_admitted").await;
                        Ok(None)
                    }
                }
            },
        );
        let mut response = Body::from_stream(stream).into_response();
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
        Err(error) => failed(&s, "indexer.query", error).await,
    }
}

pub(crate) async fn get(
    State(s): State<Arc<StateData>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    websocket: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let live = uri.query().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .any(|(key, value)| key == "live" && value == "true")
    });
    let stream_requested = websocket.is_ok()
        || live
        || headers
            .get("accept")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("text/event-stream"));
    let shared_query = s
        .config
        .indexer_paths
        .iter()
        .any(|route| route == path(&uri));
    if !s
        .config
        .indexer_stream_paths
        .iter()
        .any(|route| route == path(&uri))
        || (shared_query && !stream_requested)
    {
        return query(
            State(s),
            OriginalUri(uri),
            headers,
            Method::GET,
            Bytes::new(),
        )
        .await;
    }
    let token = match header(&headers) {
        Ok(token) => token.to_owned(),
        Err(_) => {
            let _ = s.budget(0).await;
            return denied(&s, "indexer.stream").await;
        }
    };
    let opening = match s
        .authorize(&token, None, Permission::IndexerRead, "indexer.stream")
        .await
    {
        Ok(value) => value,
        Err(error) => return failed(&s, "indexer.stream", error).await,
    };
    let Ok(permit) = s.streams.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    if let Ok(websocket) = websocket {
        return websocket
            .max_message_size(1 << 20)
            .max_frame_size(1 << 20)
            .on_upgrade(move |socket| async move {
                let _permit = permit;
                let mut metrics = StreamMetrics::new("websocket");
                if let Err(error) = websocket_stream(socket, s, uri, token).await {
                    tracing::debug!(error = %error, "Indexer websocket closed");
                } else {
                    metrics.reason = "peer_closed";
                }
            })
            .into_response();
    }
    let result: Result<Response> = async {
        let upstream = s
            .config
            .indexer_backend
            .as_ref()
            .ok_or_else(|| eyre!("Indexer unavailable"))?;
        let mut url = upstream_url(upstream, path(&uri), uri.query())?;
        crate::indexer_boundary::pin_chain(&mut url, s.config.domain.zone_chain_id)
            .map_err(|_| AccessDenied)?;
        s.recheck(&opening).await?;
        let response = s
            .http
            .get(url)
            .timeout(Duration::from_secs(2_592_060))
            .header("accept", "text/event-stream")
            .header("x-zone-context-version", "1")
            .header("x-zone-expires-at", opening.proof.expires_at.to_string())
            .send()
            .await?;
        ensure!(response.status().is_success(), "Indexer stream unavailable");
        let content_type = response
            .headers()
            .get("content-type")
            .cloned()
            .ok_or_else(|| eyre!("missing stream content type"))?;
        ensure!(
            content_type.to_str()?.starts_with("text/event-stream"),
            "Indexer did not return an event stream"
        );
        s.store.complete(opening.log_id, "backend_success").await?;
        let upstream = response.bytes_stream();
        let stream = futures::stream::try_unfold(
            (
                upstream,
                s.clone(),
                token,
                permit,
                None::<i64>,
                StreamMetrics::new("sse"),
            ),
            |(mut upstream, s, token, permit, previous, mut metrics)| async move {
                if let Some(id) = previous {
                    let _ = s.store.complete(id, "release_admitted").await;
                }
                loop {
                    // An idle connection loses authorization too, even without new upstream bytes.
                    let item = match tokio::time::timeout(Duration::from_secs(1), upstream.next())
                        .await
                    {
                        Ok(item) => item,
                        Err(_) => {
                            let proof = s
                                .authorize(&token, None, Permission::IndexerRead, "indexer.stream")
                                .await?;
                            s.recheck(&proof).await?;
                            continue;
                        }
                    };
                    let Some(chunk) = item else {
                        metrics.reason = "upstream_closed";
                        drop(metrics);
                        return Ok::<_, eyre::Report>(None);
                    };
                    let chunk = chunk?;
                    ensure!(
                        chunk.len() <= s.config.max_response_bytes,
                        "Indexer frame too large"
                    );
                    let admission = s
                        .authorize(&token, None, Permission::IndexerRead, "indexer.stream")
                        .await?;
                    s.budget(chunk.len()).await?;
                    s.store.complete(admission.log_id, "release_intent").await?;
                    s.recheck(&admission).await?;
                    return Ok(Some((
                        chunk,
                        (upstream, s, token, permit, Some(admission.log_id), metrics),
                    )));
                }
            },
        );
        Ok((
            [(axum::http::header::CONTENT_TYPE, content_type)],
            Body::from_stream(stream),
        )
            .into_response())
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => failed(&s, "indexer.stream", error).await,
    }
}

async fn websocket_stream(
    mut downstream: WebSocket,
    s: Arc<StateData>,
    uri: Uri,
    token: String,
) -> Result<()> {
    let base = s
        .config
        .indexer_backend
        .as_ref()
        .ok_or_else(|| eyre!("Indexer unavailable"))?;
    let mut url = upstream_url(base, path(&uri), uri.query())?;
    crate::indexer_boundary::pin_chain(&mut url, s.config.domain.zone_chain_id)
        .map_err(|_| AccessDenied)?;
    url.set_scheme("wss")
        .map_err(|_| eyre!("invalid Indexer websocket URL"))?;
    let opening = s
        .authorize(&token, None, Permission::IndexerRead, "indexer.stream")
        .await?;
    let mut request = url.as_str().into_client_request()?;
    request
        .headers_mut()
        .insert("x-zone-context-version", "1".parse()?);
    request.headers_mut().insert(
        "x-zone-expires-at",
        opening.proof.expires_at.to_string().parse()?,
    );
    s.recheck(&opening).await?;
    let (mut upstream, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(
            tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(1 << 20))
                .max_frame_size(Some(1 << 20)),
        ),
        false,
        Some(Connector::Rustls(s.backend_tls.clone())),
    )
    .await?;
    let mut idle = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = idle.tick() => {
                let admission = s.authorize(&token, None, Permission::IndexerRead, "indexer.stream").await?;
                s.recheck(&admission).await?;
            }
            message = downstream.next() => {
                let Some(message) = message else { break; };
                let message = message?;
                let message = match message {
                    Message::Text(text) => UpstreamMessage::Text(text.as_str().into()),
                    Message::Binary(bytes) => UpstreamMessage::Binary(bytes),
                    Message::Close(_) => break,
                    Message::Ping(bytes) => { downstream.send(Message::Pong(bytes)).await?; continue; }
                    Message::Pong(_) => continue,
                };
                let admission = s.authorize(&token, None, Permission::IndexerRead, "indexer.stream").await?;
                s.recheck(&admission).await?;
                tokio::time::timeout(Duration::from_secs(2), upstream.send(message)).await??;
                s.store.complete(admission.log_id, "backend_success").await?;
            }
            message = upstream.next() => {
                let Some(message) = message else { break; };
                let message = message?;
                let message = match message {
                    UpstreamMessage::Text(text) => Message::Text(text.as_str().into()),
                    UpstreamMessage::Binary(bytes) => Message::Binary(bytes),
                    UpstreamMessage::Close(_) => break,
                    UpstreamMessage::Ping(bytes) => { upstream.send(UpstreamMessage::Pong(bytes)).await?; continue; }
                    UpstreamMessage::Pong(_) | UpstreamMessage::Frame(_) => continue,
                };
                let bytes = match &message { Message::Text(text) => text.len(), Message::Binary(bytes) => bytes.len(), _ => 0 };
                ensure!(bytes <= s.config.max_response_bytes, "Indexer frame too large");
                let admission = s.authorize(&token, None, Permission::IndexerRead, "indexer.stream").await?;
                s.budget(bytes).await?;
                s.store.complete(admission.log_id, "release_intent").await?;
                s.recheck(&admission).await?;
                tokio::time::timeout(Duration::from_millis(100), downstream.send(message)).await??;
                let _=s.store.complete(admission.log_id,"release_admitted").await;
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_millis(100), upstream.close(None)).await;
    let _ = tokio::time::timeout(Duration::from_millis(100), downstream.close()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indexer_routes_cannot_change_upstream_origin() {
        let base = url::Url::parse("https://indexer.example/base").unwrap();
        let url = upstream_url(&base, "/events", Some("after=7")).unwrap();
        assert_eq!(url.as_str(), "https://indexer.example/events?after=7");
        for path in [
            "//attacker.example/events",
            "/%2e%2e/hidden",
            "/a/../hidden",
            "/events?secret=1",
            "/events#fragment",
            "/events\\hidden",
        ] {
            assert!(upstream_url(&base, path, None).is_err(), "{path}");
        }
    }
}
