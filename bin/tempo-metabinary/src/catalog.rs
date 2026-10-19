//! Release metadata describing the frozen eras of each built-in chain.
//!
//! ```json
//! {"chains":[{"chain_id":"0x1079","eras":[
//!   {"until":"T12","binary":"eras/tempo-genesis-t11",
//!    "checkpoint":{"number":43957544,"hash":"0x6c85…e452"}}]}]}
//! ```

use alloy_eips::BlockNumHash;
use alloy_primitives::U64;
use eyre::{OptionExt as _, WrapErr as _, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use tempo_hardfork::TempoHardfork;

/// Frozen eras of every chain a release serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Per-chain era schedules. Chain IDs are unique.
    pub chains: Vec<ChainEras>,
}

impl Catalog {
    /// Reads, validates, and resolves the catalog at `path`.
    ///
    /// Relative era binaries are resolved against the catalog's canonical parent directory.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let json = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("failed to read era catalog {}", path.display()))?;
        let mut catalog: Self = json
            .parse()
            .wrap_err_with(|| format!("invalid era catalog {}", path.display()))?;
        let canonical = path
            .canonicalize()
            .wrap_err_with(|| format!("failed to resolve {}", path.display()))?;
        let parent = canonical
            .parent()
            .ok_or_eyre("era catalog has no parent directory")?;
        catalog.resolve_binaries(parent);
        Ok(catalog)
    }

    /// Checks that every chain has a valid schedule, that checkpoints strictly increase, and that
    /// chain IDs are unique by value.
    pub fn validate(&self) -> eyre::Result<()> {
        let mut chain_ids = HashSet::new();
        for chain in &self.chains {
            ensure!(
                chain_ids.insert(chain.chain_id),
                "duplicate chain ID in era catalog"
            );
            chain.boundaries()?;
            ensure!(
                chain
                    .eras
                    .windows(2)
                    .all(|pair| pair[0].checkpoint.number < pair[1].checkpoint.number),
                "era checkpoints must strictly increase"
            );
        }
        Ok(())
    }

    /// Joins every relative era binary onto `parent`.
    pub fn resolve_binaries(&mut self, parent: &Path) {
        for era in self.chains.iter_mut().flat_map(|chain| &mut chain.eras) {
            if era.binary.is_relative() {
                era.binary = parent.join(&era.binary);
            }
        }
    }

    /// Returns the schedule of `chain_id`, or `None` if the catalog doesn't list it.
    pub fn for_chain(&self, chain_id: u64) -> Option<&ChainEras> {
        self.chains
            .iter()
            .find(|chain| chain.chain_id == U64::from(chain_id))
    }
}

impl FromStr for Catalog {
    type Err = eyre::Report;

    /// Parses and validates a catalog. Era binaries are left unresolved.
    fn from_str(json: &str) -> eyre::Result<Self> {
        let catalog: Self = serde_json::from_str(json)?;
        catalog.validate()?;
        Ok(catalog)
    }
}

/// The frozen eras of one chain, ordered by activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainEras {
    /// Chain the eras belong to.
    pub chain_id: U64,
    /// Frozen eras, oldest first. Everything after the last era is the live era.
    pub eras: Vec<FrozenEra>,
}

impl ChainEras {
    /// Returns the first timestamp outside each era, in era order.
    ///
    /// Block `b` belongs to era `i` when `boundaries[i-1] <= b.timestamp < boundaries[i]`; era
    /// index `boundaries.len()` is the live era.
    pub fn boundaries(&self) -> eyre::Result<Vec<u64>> {
        let chain_id = self.chain_id.to::<u64>();
        let mut boundaries: Vec<u64> = Vec::with_capacity(self.eras.len());
        for era in &self.eras {
            ensure!(
                !era.binary.as_os_str().is_empty(),
                "era {era} requires an executable"
            );
            let Some(boundary) = era.until.activation_timestamp(chain_id) else {
                bail!("{} has no activation on chain {chain_id}", era.until);
            };
            ensure!(
                boundary > boundaries.last().copied().unwrap_or_default(),
                "era {era} must activate after its predecessor"
            );
            boundaries.push(boundary);
        }
        Ok(boundaries)
    }
}

/// A contiguous range of blocks executed by one historical binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenEra {
    /// First hardfork this era does not execute; its activation timestamp ends the era.
    pub until: TempoHardfork,
    /// Executable serving the era. Relative paths resolve against the catalog's directory.
    pub binary: PathBuf,
    /// The era's last canonical block, used for the sync handoff.
    pub checkpoint: BlockNumHash,
}

impl fmt::Display for FrozenEra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pre-{}", self.until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;
    use tempo_hardfork::constants::mainnet::{MAINNET_T1_TIMESTAMP, MAINNET_T12_TIMESTAMP};

    fn era(until: &str, number: u64) -> serde_json::Value {
        serde_json::json!({
            "until": until,
            "binary": "eras/worker",
            "checkpoint": {"number": number, "hash": B256_ONE},
        })
    }

    const B256_ONE: alloy_primitives::B256 =
        b256!("0x0000000000000000000000000000000000000000000000000000000000000001");

    fn parse(chains: serde_json::Value) -> eyre::Result<Catalog> {
        serde_json::json!({ "chains": chains }).to_string().parse()
    }

    fn error(chains: serde_json::Value) -> String {
        format!("{:#}", parse(chains).unwrap_err())
    }

    #[test]
    fn boundaries_follow_fork_activations() {
        let catalog = parse(serde_json::json!([
            {"chain_id": "0x1079", "eras": [era("T1", 1), era("T12", 2)]}
        ]))
        .unwrap();
        let chain = catalog.for_chain(4217).unwrap();
        assert_eq!(
            chain.boundaries().unwrap(),
            vec![MAINNET_T1_TIMESTAMP, MAINNET_T12_TIMESTAMP]
        );
        assert_eq!(chain.eras[1].to_string(), "pre-T12");
        assert!(catalog.for_chain(42431).is_none());
    }

    #[test]
    fn rejects_invalid_schedules() {
        let mut no_binary = era("T12", 1);
        no_binary["binary"] = "".into();
        assert_eq!(
            error(serde_json::json!([{"chain_id": "0x1079", "eras": [no_binary]}])),
            "era pre-T12 requires an executable"
        );
        assert_eq!(
            error(serde_json::json!([{"chain_id": "0x1079", "eras": [era("T14", 1)]}])),
            "T14 has no activation on chain 4217"
        );
        assert_eq!(
            error(serde_json::json!([{"chain_id": "0x1", "eras": [era("T12", 1)]}])),
            "T12 has no activation on chain 1"
        );
        assert_eq!(
            error(serde_json::json!([{"chain_id": "0x1079", "eras": [era("T0", 1)]}])),
            "era pre-T0 must activate after its predecessor"
        );
        assert_eq!(
            error(serde_json::json!([
                {"chain_id": "0x1079", "eras": [era("T12", 1), era("T12", 2)]}
            ])),
            "era pre-T12 must activate after its predecessor"
        );
        assert_eq!(
            error(serde_json::json!([
                {"chain_id": "0x1079", "eras": [era("T1", 2), era("T12", 2)]}
            ])),
            "era checkpoints must strictly increase"
        );
        assert_eq!(
            error(serde_json::json!([
                {"chain_id": "0x1079", "eras": [era("T12", 1)]},
                {"chain_id": "0x01079", "eras": []}
            ])),
            "duplicate chain ID in era catalog"
        );
    }

    #[test]
    fn rejects_malformed_entries() {
        let mut missing = era("T12", 1);
        missing.as_object_mut().unwrap().remove("checkpoint");
        assert!(
            error(serde_json::json!([{"chain_id": "0x1079", "eras": [missing]}]))
                .contains("missing field `checkpoint`")
        );

        let mut unknown = era("T12", 1);
        unknown["extra"] = true.into();
        assert!(
            error(serde_json::json!([{"chain_id": "0x1079", "eras": [unknown]}]))
                .contains("unknown field `extra`")
        );
    }

    #[test]
    fn load_resolves_relative_binaries_against_the_catalog_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tempo-eras.json");
        let mut absolute = era("T12", 1);
        absolute["binary"] = "/opt/worker".into();
        std::fs::write(
            &path,
            serde_json::json!({"chains": [
                {"chain_id": "0x1079", "eras": [era("T1", 1)]},
                {"chain_id": "0xa5bf", "eras": [absolute]},
            ]})
            .to_string(),
        )
        .unwrap();

        let catalog = Catalog::load(&path).unwrap();
        let parent = dir.path().canonicalize().unwrap();
        assert_eq!(
            catalog.for_chain(4217).unwrap().eras[0].binary,
            parent.join("eras/worker")
        );
        assert_eq!(
            catalog.for_chain(42431).unwrap().eras[0].binary,
            PathBuf::from("/opt/worker")
        );
    }
}
