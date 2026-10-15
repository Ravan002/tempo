//! Explicit, network-bound trust and resource configuration.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;
#[cfg(feature = "client")]
use std::{num::NonZeroU32, time::Duration};
use tempo_finality::NetworkIdentity;

/// Configured locally, never filled from upstream discovery. Persisted checkpoints bind all fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub anchor: NetworkIdentity,
    pub epoch_length: NonZeroU64,
    /// Version-one TIP-20 layout through T14. Unknown layout versions fail deserialization.
    pub layout: Layout,
    /// First configured activation requiring a layout this implementation does not support.
    pub unsupported_layout_from: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Layout {
    V1,
}

impl Network {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.epoch_length.get() < 3 {
            return Err("Tempo epoch length must be at least three blocks");
        }
        Ok(())
    }
}

/// Provisional safety ceilings, not measured performance guarantees.
#[cfg(feature = "client")]
#[derive(Clone, Debug)]
pub struct Limits {
    pub request_timeout: Duration,
    pub read_timeout: Duration,
    pub poll_interval: Duration,
    pub max_response_bytes: usize,
    pub max_reads: usize,
    /// Maximum owned proof jobs, including CPU workers whose waiters have expired.
    pub read_concurrency: usize,
    /// Maximum concurrent callers, including callers sharing existing proof work.
    pub max_read_waiters: usize,
    /// Maximum simultaneous proof RPCs per provider, shared across all proof jobs.
    pub proof_concurrency: usize,
    pub max_transition_search: u64,
    pub account_cache: NonZeroU32,
    pub slot_cache: NonZeroU32,
    pub proofs: tempo_state_proof::ProofLimits,
}

#[cfg(feature = "client")]
impl Default for Limits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(15),
            poll_interval: Duration::from_millis(500),
            max_response_bytes: 8 * 1024 * 1024,
            max_reads: 128,
            read_concurrency: 8,
            max_read_waiters: 64,
            proof_concurrency: 8,
            max_transition_search: 32,
            account_cache: NonZeroU32::new(4096).unwrap(),
            slot_cache: NonZeroU32::new(16_384).unwrap(),
            proofs: Default::default(),
        }
    }
}

#[cfg(feature = "client")]
impl Limits {
    /// Upper bound on concurrent callers, independent of proof-job admission.
    pub const MAX_READ_WAITERS: usize = 1024;
    /// Upper bound on simultaneous proof RPCs per provider.
    pub const MAX_PROOF_CONCURRENCY: usize = 64;

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.request_timeout.is_zero()
            || self.read_timeout.is_zero()
            || self.poll_interval.is_zero()
            || self.max_response_bytes == 0
            || self.max_reads == 0
            || self.max_reads > self.proofs.max_slots
            || self.read_concurrency == 0
            || self.read_concurrency > 64
            || self.max_read_waiters == 0
            || self.max_read_waiters > Self::MAX_READ_WAITERS
            || self.proof_concurrency == 0
            || self.proof_concurrency > Self::MAX_PROOF_CONCURRENCY
            || self.proofs.max_accounts == 0
            || self.max_transition_search == 0
            || self.max_transition_search > 1024
        {
            return Err("invalid light-client resource limits");
        }
        self.cache_limits()?;
        Ok(())
    }

    /// A read can join at most `read_concurrency` jobs, each with at most `max_reads` keys.
    /// Publication charges their input occurrences independently of resident cache capacities.
    pub(crate) fn cache_limits(&self) -> Result<tempo_state_proof::CacheLimits, &'static str> {
        let nonzero = |count: usize| {
            u32::try_from(count)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or("invalid light-client publication budget")
        };
        let entries = nonzero(
            self.max_reads
                .checked_mul(self.read_concurrency)
                .ok_or("invalid light-client publication budget")?,
        )?;
        Ok(tempo_state_proof::CacheLimits {
            max_publication_batches: nonzero(self.read_concurrency)?,
            max_publication_accounts: entries,
            max_publication_words: entries,
            ..tempo_state_proof::CacheLimits::new(self.account_cache, self.slot_cache)
        })
    }
}
