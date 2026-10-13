//! The privileged top-of-block lane.
//!
//! Consensus opens the lane for a round when this node starts proposing it.
//! Authenticated top-of-block operators then submit signed transactions for
//! that round until the lane's window elapses. The payload builder takes the
//! lane after its start-of-block system work and executes the taken
//! transactions before any transaction from the pool.
//!
//! Each maker (the recovered transaction signer) holds at most one slot per
//! round: a newer transaction from the same maker replaces the older one and
//! keeps its position in the prefix. Slots are ordered by the time the maker
//! first appeared in the round.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_consensus::{Transaction as _, transaction::TxHashRef as _};
use alloy_primitives::{Address, B256};
use reth_primitives_traits::Recovered;
use tempo_primitives::TempoTxEnvelope;

/// Limits an operator is held to within one round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopOfBlockLimits {
    /// Maximum number of maker slots the operator may hold.
    pub max_txs: usize,
    /// Maximum sum of gas limits over the operator's slots.
    pub max_gas: u64,
}

/// Result of a submission to an open round.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TopOfBlockSubmitOutcome {
    /// Transactions that took a new maker slot.
    pub accepted: u32,
    /// Transactions that replaced the previous transaction of their maker.
    pub replaced: u32,
    /// Transactions dropped because of the operator's limits or because another
    /// operator holds the maker's slot.
    pub rejected: u32,
    /// Time since the round was opened.
    pub since_open: Duration,
}

/// Why a submission was refused as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TopOfBlockSubmitError {
    /// This node is not building the round.
    #[error("the lane is not open for this round")]
    NotOpen,
    /// The builder already took the lane for this round.
    #[error("the lane was already taken by the builder")]
    Closed,
}

/// Handle to the lane, shared by consensus and the payload builder.
///
/// A default lane is never opened, so the builder takes nothing from it.
#[derive(Debug, Clone, Default)]
pub struct TopOfBlockLane {
    inner: Arc<Mutex<Option<LaneRound>>>,
}

#[derive(Debug)]
struct LaneRound {
    epoch: u64,
    view: u64,
    opened_at: Instant,
    deadline: Instant,
    /// The hashes the builder took, in prefix order; `None` while open.
    taken: Option<Vec<B256>>,
    slots: Vec<Slot>,
    slot_by_maker: HashMap<Address, usize>,
    usage_by_operator: HashMap<B256, (usize, u64)>,
}

#[derive(Debug)]
struct Slot {
    operator: B256,
    tx: Recovered<TempoTxEnvelope>,
}

impl TopOfBlockLane {
    /// Opens the lane for `(epoch, view)`, discarding any previous round.
    ///
    /// Submissions are accepted until the builder takes the lane. The builder
    /// waits for `window` after opening before it takes the lane.
    pub fn open(&self, epoch: u64, view: u64, window: Duration) {
        let now = Instant::now();
        *self.lock() = Some(LaneRound {
            epoch,
            view,
            opened_at: now,
            deadline: now + window,
            taken: None,
            slots: Vec::new(),
            slot_by_maker: HashMap::new(),
            usage_by_operator: HashMap::new(),
        });
    }

    /// Adds `txs` from `operator` to the open round `(epoch, view)`.
    pub fn submit(
        &self,
        epoch: u64,
        view: u64,
        operator: B256,
        limits: TopOfBlockLimits,
        txs: impl IntoIterator<Item = Recovered<TempoTxEnvelope>>,
    ) -> Result<TopOfBlockSubmitOutcome, TopOfBlockSubmitError> {
        let mut guard = self.lock();
        let round = guard
            .as_mut()
            .filter(|round| round.epoch == epoch && round.view == view)
            .ok_or(TopOfBlockSubmitError::NotOpen)?;
        if round.taken.is_some() {
            return Err(TopOfBlockSubmitError::Closed);
        }

        let mut outcome = TopOfBlockSubmitOutcome {
            since_open: round.opened_at.elapsed(),
            ..Default::default()
        };
        for tx in txs {
            let maker = tx.signer();
            let gas = tx.gas_limit();
            let (slots, used_gas) = round
                .usage_by_operator
                .get(&operator)
                .copied()
                .unwrap_or_default();
            match round.slot_by_maker.get(&maker).copied() {
                Some(index) => {
                    let slot = &mut round.slots[index];
                    let old_gas = slot.tx.gas_limit();
                    if slot.operator != operator || used_gas - old_gas + gas > limits.max_gas {
                        outcome.rejected += 1;
                        continue;
                    }
                    slot.tx = tx;
                    round
                        .usage_by_operator
                        .insert(operator, (slots, used_gas - old_gas + gas));
                    outcome.replaced += 1;
                }
                None => {
                    if slots >= limits.max_txs || used_gas + gas > limits.max_gas {
                        outcome.rejected += 1;
                        continue;
                    }
                    round.slot_by_maker.insert(maker, round.slots.len());
                    round.slots.push(Slot { operator, tx });
                    round
                        .usage_by_operator
                        .insert(operator, (slots + 1, used_gas + gas));
                    outcome.accepted += 1;
                }
            }
        }
        Ok(outcome)
    }

    /// Waits until the window of round `(epoch, view)` elapses, then closes the
    /// round and returns its transactions in prefix order.
    ///
    /// Returns nothing if the lane is not open for this round.
    pub fn take(&self, epoch: u64, view: u64) -> Vec<Recovered<TempoTxEnvelope>> {
        let deadline = match self.lock().as_ref() {
            Some(round) if round.epoch == epoch && round.view == view && round.taken.is_none() => {
                round.deadline
            }
            _ => return Vec::new(),
        };
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));

        let mut guard = self.lock();
        let Some(round) = guard
            .as_mut()
            .filter(|round| round.epoch == epoch && round.view == view && round.taken.is_none())
        else {
            return Vec::new();
        };
        let txs: Vec<_> = round.slots.drain(..).map(|slot| slot.tx).collect();
        round.taken = Some(txs.iter().map(|tx| *tx.tx_hash()).collect());
        txs
    }

    /// Returns the hashes the builder took for round `(epoch, view)`, in
    /// prefix order.
    pub fn taken(&self, epoch: u64, view: u64) -> Option<Vec<B256>> {
        self.lock()
            .as_ref()
            .filter(|round| round.epoch == epoch && round.view == view)
            .and_then(|round| round.taken.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<LaneRound>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_primitives::{Signature, U256};

    const LIMITS: TopOfBlockLimits = TopOfBlockLimits {
        max_txs: 2,
        max_gas: 100_000,
    };

    fn tx(maker: u8, nonce: u64, gas: u64) -> Recovered<TempoTxEnvelope> {
        let tx = TxLegacy {
            nonce,
            gas_limit: gas,
            value: U256::from(nonce),
            ..Default::default()
        };
        Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature())),
            Address::repeat_byte(maker),
        )
    }

    #[test]
    fn newest_transaction_of_a_maker_keeps_the_makers_first_position() {
        let lane = TopOfBlockLane::default();
        let operator = B256::repeat_byte(1);
        lane.open(0, 7, Duration::ZERO);

        lane.submit(0, 7, operator, LIMITS, [tx(1, 0, 21_000), tx(2, 0, 21_000)])
            .unwrap();
        let outcome = lane
            .submit(0, 7, operator, LIMITS, [tx(1, 5, 21_000), tx(3, 0, 21_000)])
            .unwrap();
        assert_eq!(
            (outcome.accepted, outcome.replaced, outcome.rejected),
            (0, 1, 1)
        );

        let taken = lane.take(0, 7);
        let got: Vec<_> = taken.iter().map(|tx| (tx.signer(), tx.nonce())).collect();
        assert_eq!(
            got,
            [(Address::repeat_byte(1), 5), (Address::repeat_byte(2), 0)]
        );
        assert_eq!(
            lane.taken(0, 7).unwrap(),
            taken.iter().map(|tx| *tx.tx_hash()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn lane_only_accepts_its_round_until_taken() {
        let lane = TopOfBlockLane::default();
        let (operator, other) = (B256::repeat_byte(1), B256::repeat_byte(2));
        assert_eq!(
            lane.submit(0, 7, operator, LIMITS, [tx(1, 0, 21_000)]),
            Err(TopOfBlockSubmitError::NotOpen)
        );
        assert!(lane.take(0, 7).is_empty());

        lane.open(0, 7, Duration::ZERO);
        assert_eq!(
            lane.submit(0, 6, operator, LIMITS, [tx(1, 0, 21_000)]),
            Err(TopOfBlockSubmitError::NotOpen)
        );
        // Gas is limited per operator, and a maker slot belongs to the operator
        // that took it.
        let outcome = lane
            .submit(0, 7, operator, LIMITS, [tx(1, 0, 90_000), tx(2, 0, 21_000)])
            .unwrap();
        assert_eq!((outcome.accepted, outcome.rejected), (1, 1));
        let outcome = lane
            .submit(0, 7, other, LIMITS, [tx(1, 1, 21_000)])
            .unwrap();
        assert_eq!((outcome.replaced, outcome.rejected), (0, 1));

        assert_eq!(lane.take(0, 7).len(), 1);
        assert_eq!(
            lane.submit(0, 7, operator, LIMITS, [tx(3, 0, 21_000)]),
            Err(TopOfBlockSubmitError::Closed)
        );
        assert!(lane.take(0, 7).is_empty(), "a round is taken once");
    }
}
