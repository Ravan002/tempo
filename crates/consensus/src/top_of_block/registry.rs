//! The registry of top-of-block operators.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime},
};

use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Address;
use commonware_utils::ordered;
use eyre::{WrapErr as _, ensure};
use serde::Deserialize;
use tempo_payload_types::TopOfBlockLimits;

/// Operators allowed to submit to the top-of-block lane, and the lane window.
///
/// Read from a JSON file:
///
/// ```json
/// {
///   "window_ms": 150,
///   "operators": [{
///     "public_key": "<hex ed25519 public key>",
///     "address": "203.0.113.7:0",
///     "expires_at": 1767225600,
///     "max_txs_per_block": 1000,
///     "max_gas_per_block": 100000000
///   }]
/// }
/// ```
///
/// `address` is the IP operators connect from; the port is ignored.
/// `expires_at` is optional unix time in seconds.
#[derive(Clone, Debug)]
pub struct Registry {
    /// Time the builder waits for operators after opening the lane.
    pub window: Duration,
    operators: HashMap<PublicKey, OperatorPolicy>,
}

/// What an operator may do.
#[derive(Clone, Debug)]
pub struct OperatorPolicy {
    pub address: SocketAddr,
    pub expires_at: Option<SystemTime>,
    pub limits: TopOfBlockLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    window_ms: u64,
    operators: Vec<OperatorEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorEntry {
    public_key: String,
    address: SocketAddr,
    #[serde(default)]
    expires_at: Option<u64>,
    max_txs_per_block: usize,
    max_gas_per_block: u64,
}

impl Registry {
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("failed reading `{}`", path.display()))?;
        Self::parse(&contents)
            .wrap_err_with(|| format!("invalid top-of-block registry `{}`", path.display()))
    }

    fn parse(contents: &str) -> eyre::Result<Self> {
        let file: RegistryFile = serde_json::from_str(contents)?;
        ensure!(file.window_ms > 0, "`window_ms` must be positive");
        let mut operators = HashMap::new();
        for entry in file.operators {
            ensure!(
                entry.max_txs_per_block > 0 && entry.max_gas_per_block > 0,
                "operator `{}` has a zero limit",
                entry.public_key,
            );
            let key = parse_public_key(&entry.public_key)?;
            let policy = OperatorPolicy {
                address: entry.address,
                expires_at: entry
                    .expires_at
                    .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
                limits: TopOfBlockLimits {
                    max_txs: entry.max_txs_per_block,
                    max_gas: entry.max_gas_per_block,
                },
            };
            ensure!(
                operators.insert(key, policy).is_none(),
                "operator `{}` is listed twice",
                entry.public_key,
            );
        }
        Ok(Self {
            window: Duration::from_millis(file.window_ms),
            operators,
        })
    }

    /// Returns the policy of `operator` if its access has not expired at `now`.
    pub(crate) fn authorize(
        &self,
        operator: &PublicKey,
        now: SystemTime,
    ) -> Option<&OperatorPolicy> {
        self.operators
            .get(operator)
            .filter(|policy| policy.expires_at.is_none_or(|expiry| now < expiry))
    }

    /// Operators whose access has not expired at `now`.
    pub(crate) fn active(&self, now: SystemTime) -> Vec<PublicKey> {
        self.operators
            .keys()
            .filter(|key| self.authorize(key, now).is_some())
            .cloned()
            .collect()
    }

    /// All operators with the addresses they connect from.
    pub(crate) fn peers(&self) -> ordered::Map<PublicKey, Address> {
        ordered::Map::from_iter_dedup(
            self.operators
                .iter()
                .map(|(key, policy)| (key.clone(), Address::Symmetric(policy.address))),
        )
    }
}

pub(super) fn parse_public_key(value: &str) -> eyre::Result<PublicKey> {
    let bytes = alloy_primitives::hex::decode(value.trim()).wrap_err("public key is not hex")?;
    PublicKey::decode(bytes.as_slice()).wrap_err("not an ed25519 public key")
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::*;

    #[test]
    fn expired_operators_are_not_authorized() {
        let key = PrivateKey::from_seed(1).public_key();
        let registry = Registry::parse(&format!(
            r#"{{"window_ms": 100, "operators": [{{
                "public_key": "{key}", "address": "127.0.0.1:0", "expires_at": 1000,
                "max_txs_per_block": 10, "max_gas_per_block": 1000000
            }}]}}"#
        ))
        .unwrap();
        let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        assert!(registry.authorize(&key, at(999)).is_some());
        assert!(registry.authorize(&key, at(1000)).is_none());
        assert_eq!(registry.active(at(1000)), Vec::<PublicKey>::new());
        assert_eq!(registry.peers().len(), 1, "expired operators stay peers");
    }
}
