use crate::{
    chain::VerificationError,
    clock,
    gateway::{
        AccessDenied, StateData, header, limited_response, principal_address, principal_generation,
    },
    store::{DeliveryEvent, Registration},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use eyre::{Result, ensure, eyre};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
use zone_auth::{CodecError, Permission, Principal};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationRequest {
    endpoint: String,
    #[serde(default)]
    id: Option<String>,
}

fn encryption_key(s: &StateData) -> Result<Aes256Gcm> {
    let name = s
        .config
        .delivery_key_env
        .as_ref()
        .ok_or_else(|| eyre!("delivery encryption key not configured"))?;
    let key = alloy_primitives::hex::decode(std::env::var(name)?)?;
    ensure!(key.len() == 32, "delivery storage key must be 32 bytes");
    Aes256Gcm::new_from_slice(&key).map_err(|_| eyre!("invalid delivery storage key"))
}
fn aad(s: &StateData, id: &str, owner: alloy_primitives::Address, generation: u64) -> Vec<u8> {
    format!("{}:{id}:{owner}:{generation}", s.config.domain.key()).into_bytes()
}
fn encrypt(
    s: &StateData,
    id: &str,
    owner: alloy_primitives::Address,
    generation: u64,
    token: &str,
) -> Result<Vec<u8>> {
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = &nonce_bytes;
    let payload = encryption_key(s)?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: token.as_bytes(),
                aad: &aad(s, id, owner, generation),
            },
        )
        .map_err(|_| eyre!("credential encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend(payload);
    Ok(out)
}
fn decrypt(s: &StateData, r: &Registration) -> Result<String> {
    ensure!(
        r.encrypted_credential.len() >= 28,
        "invalid credential ciphertext"
    );
    let token = encryption_key(s)?
        .decrypt(
            Nonce::from_slice(&r.encrypted_credential[..12]),
            Payload {
                msg: &r.encrypted_credential[12..],
                aad: &aad(s, &r.id, r.owner, r.generation),
            },
        )
        .map_err(|_| eyre!("credential decryption failed"))?;
    Ok(String::from_utf8(token)?)
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0
        || a >= 240
        || a == 100 && (64..=127).contains(&b)
        || a == 127
        || a == 169 && b == 254
        || a == 192 && b == 0
        || a == 192 && b == 0 && c == 2
        || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
        || a == 203 && b == 0 && c == 113)
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return public_v4(mapped);
            }
            let seg = v.segments();
            (seg[0] & 0xe000) == 0x2000
                && !(seg[0] == 0x2001 && (seg[1] == 0x0db8 || seg[1] < 0x0200))
        }
    }
}
async fn destination(endpoint: &str) -> Result<(url::Url, reqwest::Client)> {
    ensure!(endpoint.len() <= 2048, "endpoint too long");
    let url = url::Url::parse(endpoint)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "delivery requires public HTTPS"
    );
    let host = url
        .host_str()
        .ok_or_else(|| eyre!("delivery host missing"))?;
    let addresses: Vec<_> = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443))),
    )
    .await??
    .collect();
    ensure!(
        !addresses.is_empty()
            && addresses.len() <= 32
            && addresses.iter().all(|a| public_ip(a.ip())),
        "delivery address is not public"
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .resolve(host, addresses[0])
        .build()?;
    Ok((url, client))
}

async fn credential_header<'a>(s: &StateData, headers: &'a HeaderMap) -> Result<&'a str> {
    match header(headers) {
        Ok(token) => Ok(token),
        Err(error) => {
            let _ = s.budget(0).await;
            Err(error)
        }
    }
}

pub(crate) async fn register(
    State(s): State<Arc<StateData>>,
    headers: HeaderMap,
    Json(input): Json<RegistrationRequest>,
) -> Response {
    let result: Result<Value> = async {
        let token = credential_header(&s, &headers).await?;
        let admission = s
            .authorize(token, None, Permission::IndexerRead, "indexer.register")
            .await?;
        ensure!(
            matches!(admission.proof.principal, Principal::Client { .. }),
            "Client credential required"
        );
        let owner = principal_address(&admission.proof.principal);
        let generation = principal_generation(&admission.proof.principal);
        let id = input
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        ensure!(id.len() <= 128 && !id.is_empty(), "invalid registration ID");
        let existing = s.store.get_registration(&id).await?;
        if let Some(existing) = &existing {
            ensure!(
                existing.owner == owner && existing.generation == generation,
                "registration belongs to another Client"
            );
        }
        let (mut endpoint, client) = destination(&input.endpoint).await?;
        let challenge = Uuid::new_v4().to_string();
        endpoint
            .query_pairs_mut()
            .append_pair("zone_challenge", &challenge);
        s.recheck(&admission).await?;
        let response = client.get(endpoint).send().await?;
        ensure!(
            response.status().is_success(),
            "receiver challenge rejected"
        );
        ensure!(
            limited_response(response, 1024).await? == challenge.as_bytes(),
            "receiver challenge mismatch"
        );
        let encrypted_credential = encrypt(&s, &id, owner, generation, token)?;
        s.recheck(&admission).await?;
        s.store
            .put_registration(&Registration {
                id: id.clone(),
                owner,
                generation,
                encrypted_credential,
                endpoint: input.endpoint,
                cursor: existing.map_or(0, |e| e.cursor),
                paused: false,
            })
            .await?;
        s.store.complete(admission.log_id, "registered").await?;
        Ok(json!({"id":id,"delivery":"at_least_once"}))
    }
    .await;
    lifecycle_response(&s, "indexer.register", result).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventPage {
    events: Vec<DeliveryEvent>,
    next_cursor: u64,
}

fn permanent_authority_failure(error: &eyre::Report) -> bool {
    error.downcast_ref::<AccessDenied>().is_some()
        || matches!(
            error.downcast_ref::<VerificationError>(),
            Some(VerificationError::Invalid)
        )
        || error.downcast_ref::<CodecError>().is_some()
}

pub(crate) async fn renew(
    State(s): State<Arc<StateData>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result: Result<Value> = async {
        let token = credential_header(&s, &headers).await?;
        let admission = s
            .authorize(token, None, Permission::IndexerRead, "indexer.renew")
            .await?;
        ensure!(
            matches!(admission.proof.principal, Principal::Client { .. }),
            "Client credential required"
        );
        let owner = principal_address(&admission.proof.principal);
        let generation = principal_generation(&admission.proof.principal);
        let mut registration = s
            .store
            .get_registration(&id)
            .await?
            .ok_or_else(|| eyre!("registration absent"))?;
        ensure!(
            registration.owner == owner && registration.generation == generation,
            "registration belongs to another Client"
        );
        registration.encrypted_credential = encrypt(&s, &id, owner, generation, token)?;
        registration.paused = false;
        s.recheck(&admission).await?;
        s.store.put_registration(&registration).await?;
        s.store
            .complete(admission.log_id, "registration_renewed")
            .await?;
        Ok(json!({"id":id,"paused":false}))
    }
    .await;
    lifecycle_response(&s, "indexer.renew", result).await
}

pub(crate) async fn remove(
    State(s): State<Arc<StateData>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result: Result<Value> = async {
        let admission = s
            .authorize(
                credential_header(&s, &headers).await?,
                None,
                Permission::Logs,
                "indexer.remove",
            )
            .await?;
        ensure!(
            matches!(admission.proof.principal, Principal::Client { .. }),
            "Client credential required"
        );
        s.recheck(&admission).await?;
        s.store
            .delete_registration(
                &id,
                principal_address(&admission.proof.principal),
                principal_generation(&admission.proof.principal),
            )
            .await?;
        s.store
            .complete(admission.log_id, "registration_removed")
            .await?;
        Ok(json!({"id":id,"removed":true}))
    }
    .await;
    lifecycle_response(&s, "indexer.remove", result).await
}

async fn lifecycle_response(s: &StateData, method: &str, result: Result<Value>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(_) => match s.deny_log(method, None).await {
            Ok(()) => (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"Access denied"})),
            )
                .into_response(),
            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        },
    }
}

fn retry_delay(attempts: u64) -> u64 {
    1u64.checked_shl(attempts.saturating_sub(1).min(6) as u32)
        .unwrap_or(60)
        .min(60)
}

async fn ingest_registration(s: &Arc<StateData>, registration: &Registration) -> Result<()> {
    let token = match decrypt(s, registration) {
        Ok(token) => token,
        Err(error) => {
            s.store.pause_registration(&registration.id).await?;
            return Err(error);
        }
    };
    let admission = match s
        .authorize(&token, None, Permission::IndexerRead, "indexer.delivery")
        .await
    {
        Ok(value) => value,
        Err(error) => {
            if permanent_authority_failure(&error) {
                s.store.pause_registration(&registration.id).await?;
            }
            return Err(error);
        }
    };
    ensure!(
        principal_address(&admission.proof.principal) == registration.owner
            && principal_generation(&admission.proof.principal) == registration.generation,
        "registration authority changed"
    );
    let base = s
        .config
        .indexer_backend
        .as_ref()
        .ok_or_else(|| eyre!("Indexer absent"))?;
    let path = s
        .config
        .indexer_events_path
        .as_ref()
        .ok_or_else(|| eyre!("Indexer event route absent"))?;
    let mut url = crate::indexer::upstream_url(base, path, None)?;
    crate::indexer_boundary::pin_chain(&mut url, s.config.domain.zone_chain_id)?;
    url.query_pairs_mut()
        .append_pair("after", &registration.cursor.to_string())
        .append_pair("limit", "100");
    s.recheck(&admission).await?;
    let response = s
        .http
        .get(url)
        .header("x-zone-context-version", "1")
        .header("x-zone-expires-at", admission.proof.expires_at.to_string())
        .send()
        .await?;
    ensure!(response.status().is_success(), "Indexer events unavailable");
    let page: EventPage =
        serde_json::from_slice(&limited_response(response, s.config.max_response_bytes).await?)?;
    ensure!(
        page.events.len() <= 100 && page.next_cursor >= registration.cursor,
        "invalid event page"
    );
    s.recheck(&admission).await?;
    s.store
        .ingest(
            &registration.id,
            registration.cursor,
            &page.events,
            page.next_cursor,
        )
        .await?;
    s.store
        .complete(admission.log_id, "events_ingested")
        .await?;
    Ok(())
}

async fn deliver_job(s: &Arc<StateData>, job: &crate::store::DeliveryJob) -> Result<()> {
    let registration = s
        .store
        .get_registration(&job.registration_id)
        .await?
        .ok_or_else(|| eyre!("registration removed"))?;
    ensure!(!registration.paused, "registration paused");
    let token = decrypt(s, &registration)?;
    let admission = match s
        .authorize(&token, None, Permission::IndexerRead, "indexer.delivery")
        .await
    {
        Ok(value) => value,
        Err(error) => {
            if permanent_authority_failure(&error) {
                s.store.pause_registration(&registration.id).await?;
            }
            return Err(error);
        }
    };
    ensure!(
        principal_address(&admission.proof.principal) == registration.owner
            && principal_generation(&admission.proof.principal) == registration.generation,
        "registration authority changed"
    );
    let (url, client) = destination(&registration.endpoint).await?;
    let bytes =
        serde_json::to_vec(&json!({"id":job.event_id,"cursor":job.cursor,"payload":job.payload}))?;
    ensure!(
        bytes.len() <= s.config.max_response_bytes,
        "delivery too large"
    );
    s.budget(bytes.len()).await?;
    s.store.complete(admission.log_id, "release_intent").await?;
    s.recheck(&admission).await?;
    let response = client
        .post(url)
        .header("x-zone-event-id", &job.event_id)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await?;
    let _ = s.store.complete(admission.log_id, "release_admitted").await;
    ensure!(
        response.status().is_success(),
        "receiver did not acknowledge"
    );
    // Do not recheck authority after receiver acceptance: bytes were already admitted.
    s.store.acknowledge_delivery(job).await?;
    s.store
        .complete(admission.log_id, "receiver_acknowledged")
        .await?;
    Ok(())
}

pub(crate) async fn tick(s: &Arc<StateData>) -> Result<()> {
    if s.config.indexer_backend.is_none() || s.config.indexer_events_path.is_none() {
        return Ok(());
    }
    let ingestion = async {
        let registrations = s.store.registrations().await?;
        futures::stream::iter(registrations.into_iter().filter(|r| !r.paused))
            .for_each_concurrent(16, |registration| async move {
                if let Err(error) = ingest_registration(s, &registration).await {
                    tracing::debug!(registration=%registration.id,error=%error,"Indexer ingestion deferred");
                }
            }).await;
        Ok::<_, eyre::Report>(())
    };
    let delivery = async {
        let worker = Uuid::new_v4().to_string();
        let attempts = futures::stream::iter(0..100).map(|_| {
            let worker = worker.clone();
            async move {
                let Some(job) = s.store.claim_delivery(&worker).await? else { return Ok::<_, eyre::Report>(()); };
                let result=deliver_job(s,&job).await;
                metrics::counter!("zone_access_delivery_attempts_total","outcome"=>if result.is_ok(){"acknowledged"}else{"retry"}).increment(1);
                if let Err(error) = result {
                    tracing::debug!(registration=%job.registration_id,event=%job.event_id,error=%error,"delivery attempt deferred");
                    if let Err(error) = s.store.retry_delivery(&job, retry_delay(job.attempts)).await {
                        tracing::debug!(error=%error,"delivery retry was fenced");
                    }
                }
                Ok(())
            }
        }).buffer_unordered(16);
        futures::pin_mut!(attempts);
        while let Some(result) = attempts.next().await {
            result?;
        }
        Ok::<_, eyre::Report>(())
    };
    // Ingestion and delivery do not share a scheduling queue. A stalled source cannot starve saved jobs.
    let (ingestion, delivery) = tokio::join!(ingestion, delivery);
    ingestion?;
    delivery?;
    let _ = clock::unix_seconds()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transient_dependencies_remain_eligible_but_revocations_pause() {
        assert!(!permanent_authority_failure(&eyre!(
            VerificationError::Unavailable
        )));
        assert!(!permanent_authority_failure(&eyre!("registry stale")));
        assert!(!permanent_authority_failure(&eyre!("rate limited")));
        assert!(permanent_authority_failure(&eyre!(
            VerificationError::Invalid
        )));
        assert!(permanent_authority_failure(&eyre!(CodecError::Expired)));
        assert!(permanent_authority_failure(&eyre!(AccessDenied)));
    }

    #[test]
    fn retries_back_off_exponentially_without_exceeding_sixty_seconds() {
        let delays: Vec<_> = (1..=9).map(retry_delay).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(retry_delay(u64::MAX), 60);
    }

    #[test]
    fn excludes_internal_and_rebinding_destinations() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
