//! Shares sequencer preconfirmations with the other quorum members over zone P2P.
//!
//! The issuing sequencer sends every issuance batch to each other quorum member and promises the
//! batch only after each peer that admitted the frame acknowledged storing it. A peer refuses a
//! batch for a block it has already built, so the issuer never promises a block that cannot
//! contain the batch. Whichever sequencer builds the next block includes the stored transactions
//! first.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_eips::eip2718::Decodable2718 as _;
use alloy_primitives::Bytes;
use futures::{FutureExt as _, future::BoxFuture};
use reth_primitives_traits::SignerRecoverable as _;
use reth_storage_api::BlockNumReader;
use tempo_primitives::TempoTxEnvelope;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};
use zone_p2p::{P2pCommand, P2pEvent, P2pPeerId};
use zone_payload::{PreconfirmationReplicator, Preconfirmations};

/// How long the issuer waits for every admitting peer to acknowledge a batch.
const REPLICATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Capacity of the event sink fed by the P2P event router.
pub(crate) const PRECONFIRMATION_EVENT_BACKLOG: usize = 16_384;

const REPLICATE_FRAME: u8 = 0;
const ACK_FRAME: u8 = 1;

/// One preconfirmation replication message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    /// Transactions promised for block `include_by`, in issuance order.
    Replicate {
        id: u64,
        include_by: u64,
        transactions: Vec<Bytes>,
    },
    /// Whether the receiver stored the batch `id` and will include it if it builds the block.
    Ack { id: u64, accepted: bool },
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Replicate {
                id,
                include_by,
                transactions,
            } => {
                let len = transactions.iter().map(|tx| 4 + tx.len()).sum::<usize>();
                let mut encoded = Vec::with_capacity(17 + len);
                encoded.push(REPLICATE_FRAME);
                encoded.extend_from_slice(&id.to_be_bytes());
                encoded.extend_from_slice(&include_by.to_be_bytes());
                for tx in transactions {
                    encoded.extend_from_slice(&(tx.len() as u32).to_be_bytes());
                    encoded.extend_from_slice(tx);
                }
                encoded
            }
            Self::Ack { id, accepted } => {
                let mut encoded = Vec::with_capacity(10);
                encoded.push(ACK_FRAME);
                encoded.extend_from_slice(&id.to_be_bytes());
                encoded.push(u8::from(*accepted));
                encoded
            }
        }
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let (id, rest) = rest.split_at_checked(8)?;
        let id = u64::from_be_bytes(id.try_into().ok()?);
        match tag {
            REPLICATE_FRAME => {
                let (include_by, mut rest) = rest.split_at_checked(8)?;
                let include_by = u64::from_be_bytes(include_by.try_into().ok()?);
                let mut transactions = Vec::new();
                while !rest.is_empty() {
                    let (len, body) = rest.split_at_checked(4)?;
                    let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
                    let (tx, next) = body.split_at_checked(len)?;
                    transactions.push(Bytes::copy_from_slice(tx));
                    rest = next;
                }
                Some(Self::Replicate {
                    id,
                    include_by,
                    transactions,
                })
            }
            ACK_FRAME => match rest {
                [accepted @ (0 | 1)] => Some(Self::Ack {
                    id,
                    accepted: *accepted == 1,
                }),
                _ => None,
            },
            _ => None,
        }
    }
}

struct ReplicationRequest {
    include_by: u64,
    transactions: Vec<Bytes>,
    done: oneshot::Sender<Result<(), String>>,
}

/// [`PreconfirmationReplicator`] backed by the zone P2P network.
pub(crate) struct P2pReplicator {
    requests: mpsc::UnboundedSender<ReplicationRequest>,
}

impl PreconfirmationReplicator for P2pReplicator {
    fn replicate(
        &self,
        include_by: u64,
        transactions: Vec<Bytes>,
    ) -> BoxFuture<'static, Result<(), String>> {
        let (done, result) = oneshot::channel();
        let sent = self.requests.send(ReplicationRequest {
            include_by,
            transactions,
            done,
        });
        async move {
            sent.map_err(|_| "replication stopped".to_owned())?;
            result
                .await
                .unwrap_or_else(|_| Err("replication stopped".to_owned()))
        }
        .boxed()
    }
}

struct Pending {
    /// Peers that admitted the frame; `None` until the P2P runtime reports admission.
    awaiting: Option<HashSet<P2pPeerId>>,
    acked: HashSet<P2pPeerId>,
    deadline: Instant,
    done: oneshot::Sender<Result<(), String>>,
}

/// Starts replication for `preconfirmations` and installs its replicator.
///
/// `events` must carry every preconfirmation P2P event for the process lifetime.
pub(crate) fn spawn_preconfirmation_replication<P>(
    preconfirmations: Preconfirmations,
    provider: P,
    commands: mpsc::Sender<P2pCommand>,
    events: mpsc::Receiver<P2pEvent>,
    task_executor: &reth_tasks::TaskExecutor,
) where
    P: BlockNumReader + Clone + Send + Sync + 'static,
{
    let (requests, request_rx) = mpsc::unbounded_channel();
    preconfirmations.set_replicator(Arc::new(P2pReplicator { requests }));
    task_executor.spawn_critical_task(
        "zone-preconfirmation-replication",
        run(preconfirmations, provider, commands, events, request_rx),
    );
}

async fn run<P>(
    preconfirmations: Preconfirmations,
    provider: P,
    commands: mpsc::Sender<P2pCommand>,
    mut events: mpsc::Receiver<P2pEvent>,
    mut requests: mpsc::UnboundedReceiver<ReplicationRequest>,
) where
    P: BlockNumReader + Clone + Send + Sync + 'static,
{
    // Received batches are stored in arrival order by one worker: a later batch can spend a nonce
    // that an earlier one reserved.
    let (stores, store_rx) = mpsc::unbounded_channel();
    tokio::spawn(store_replicas(
        preconfirmations,
        provider,
        commands.clone(),
        store_rx,
    ));

    let mut next_id = 1u64;
    let mut pending = HashMap::<u64, Pending>::new();
    let mut sweep = tokio::time::interval(REPLICATION_TIMEOUT / 4);
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(ReplicationRequest { include_by, transactions, done }) = request else {
                    return;
                };
                let id = next_id;
                next_id += 1;
                let frame = Frame::Replicate { id, include_by, transactions }.encode();
                pending.insert(id, Pending {
                    awaiting: None,
                    acked: HashSet::new(),
                    deadline: Instant::now() + REPLICATION_TIMEOUT,
                    done,
                });
                let command = P2pCommand::SendPreconfirmationFrame { id, recipient: None, frame };
                if commands.send(command).await.is_err() {
                    return;
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    return;
                };
                match event {
                    P2pEvent::PreconfirmationFrameSent { id, admitted } => {
                        let Some(entry) = pending.get_mut(&id) else {
                            continue;
                        };
                        if admitted.is_empty() {
                            finish(&mut pending, id, Err("no other sequencer is connected".to_owned()));
                            continue;
                        }
                        entry.awaiting = Some(admitted.into_iter().collect());
                        settle(&mut pending, id);
                    }
                    P2pEvent::PreconfirmationFrameReceived { peer, frame } => match Frame::decode(&frame) {
                        Some(Frame::Replicate { id, include_by, transactions }) => {
                            let _ = stores.send((peer, id, include_by, transactions));
                        }
                        Some(Frame::Ack { id, accepted }) => {
                            let Some(entry) = pending.get_mut(&id) else {
                                continue;
                            };
                            if !accepted {
                                finish(&mut pending, id, Err(format!("sequencer {peer} already built the promised block")));
                                continue;
                            }
                            entry.acked.insert(peer);
                            settle(&mut pending, id);
                        }
                        None => {
                            warn!(target: "zone::preconfirmation", %peer, "Ignoring malformed preconfirmation frame");
                        }
                    },
                    _ => {}
                }
            }
            _ = sweep.tick() => {
                let now = Instant::now();
                let expired: Vec<_> = pending
                    .iter()
                    .filter(|(_, entry)| entry.deadline <= now)
                    .map(|(id, _)| *id)
                    .collect();
                for id in expired {
                    finish(&mut pending, id, Err("timed out waiting for sequencers to store the batch".to_owned()));
                }
            }
        }
    }
}

/// Resolves batch `id` once every admitting peer acknowledged it.
fn settle(pending: &mut HashMap<u64, Pending>, id: u64) {
    let complete = pending.get(&id).is_some_and(|entry| {
        entry
            .awaiting
            .as_ref()
            .is_some_and(|awaiting| awaiting.is_subset(&entry.acked))
    });
    if complete {
        finish(pending, id, Ok(()));
    }
}

fn finish(pending: &mut HashMap<u64, Pending>, id: u64, result: Result<(), String>) {
    if let Some(entry) = pending.remove(&id) {
        if let Err(err) = &result {
            metrics::counter!("zone_preconfirmation_replication_failures_total").increment(1);
            debug!(target: "zone::preconfirmation", id, %err, "preconfirmation batch was not replicated");
        }
        let _ = entry.done.send(result);
    }
}

async fn store_replicas<P>(
    preconfirmations: Preconfirmations,
    provider: P,
    commands: mpsc::Sender<P2pCommand>,
    mut batches: mpsc::UnboundedReceiver<(P2pPeerId, u64, u64, Vec<Bytes>)>,
) where
    P: BlockNumReader + Clone + Send + Sync + 'static,
{
    while let Some((peer, id, include_by, transactions)) = batches.recv().await {
        let preconfirmations = preconfirmations.clone();
        let provider = provider.clone();
        let sender = peer.clone();
        let accepted = tokio::task::spawn_blocking(move || {
            let recovered = transactions
                .iter()
                .map(|raw| {
                    TempoTxEnvelope::decode_2718_exact(raw)
                        .ok()?
                        .try_into_recovered()
                        .ok()
                })
                .collect::<Option<Vec<_>>>();
            let Some(recovered) = recovered else {
                warn!(target: "zone::preconfirmation", peer = %sender, "Refusing a preconfirmation batch with an invalid transaction");
                return false;
            };
            let canonical_head = provider.best_block_number().unwrap_or_default();
            preconfirmations.store_replicas(canonical_head, include_by, recovered)
        })
        .await
        .unwrap_or(false);
        let frame = Frame::Ack { id, accepted }.encode();
        let command = P2pCommand::SendPreconfirmationFrame {
            id: 0,
            recipient: Some(peer),
            frame,
        };
        if commands.send(command).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_reject_truncation() {
        let replicate = Frame::Replicate {
            id: 7,
            include_by: 42,
            transactions: vec![Bytes::from_static(b"ab"), Bytes::from_static(b"")],
        };
        let encoded = replicate.encode();
        assert_eq!(
            encoded,
            [
                &[0][..],
                &7u64.to_be_bytes(),
                &42u64.to_be_bytes(),
                &2u32.to_be_bytes(),
                b"ab",
                &0u32.to_be_bytes(),
            ]
            .concat()
        );
        assert_eq!(Frame::decode(&encoded), Some(replicate));
        assert_eq!(Frame::decode(&encoded[..encoded.len() - 1]), None);

        for accepted in [false, true] {
            let ack = Frame::Ack { id: 9, accepted };
            assert_eq!(Frame::decode(&ack.encode()), Some(ack));
        }
        assert_eq!(Frame::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 9, 2]), None);
    }
}
