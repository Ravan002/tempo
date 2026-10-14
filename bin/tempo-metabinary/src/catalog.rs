//! Release metadata. Runtime node options remain owned by Tempo's ordinary CLI.

use crate::manifest::resolve_path;
use alloy_eips::BlockNumHash;
use alloy_primitives::U64;
use eyre::{Context, OptionExt, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};
use tempo_hardfork::TempoHardfork;

/// Release era schedules and frozen executables indexed by chain ID.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub chains: Vec<ChainEras>,
}

impl Catalog {
    /// Executable paths resolve relative to the catalog.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let mut catalog: Self = serde_json::from_slice(&std::fs::read(path)?)
            .wrap_err_with(|| format!("invalid era catalog {}", path.display()))?;
        catalog.validate()?;
        let parent = path.canonicalize()?.with_file_name("");
        catalog.resolve_binaries(&parent);
        Ok(catalog)
    }

    pub fn resolve_binaries(&mut self, parent: &Path) {
        for era in self.chains.iter_mut().flat_map(|chain| &mut chain.eras) {
            resolve_path(parent, &mut era.binary);
        }
    }

    pub fn validate(&self) -> eyre::Result<()> {
        let mut chain_ids = HashSet::new();
        for chain in &self.chains {
            chain.boundaries()?;
            ensure!(
                chain_ids.insert(chain.chain_id),
                "duplicate chain ID in era catalog"
            );
        }
        Ok(())
    }

    /// `None` means the chain executes natively.
    pub fn for_chain(&self, chain_id: u64) -> Option<&ChainEras> {
        let chain_id = U64::from(chain_id);
        self.chains.iter().find(|chain| chain.chain_id == chain_id)
    }
}

/// A chain's frozen eras, in activation order. The running binary executes everything after the
/// last one.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainEras {
    pub chain_id: U64,
    pub eras: Vec<FrozenEra>,
}

impl ChainEras {
    /// Validates the eras and returns each one's exclusive end timestamp.
    pub fn boundaries(&self) -> eyre::Result<Vec<u64>> {
        era_boundaries(self.chain_id, &self.eras)
    }
}

/// A frozen executable for blocks before its `until` hardfork activates.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenEra {
    /// First hardfork this era does not execute.
    pub until: TempoHardfork,
    /// Frozen executable, resolved relative to the release catalog or manifest.
    pub binary: PathBuf,
    /// Last canonical block to execute before handing storage to the next era.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<BlockNumHash>,
}

impl fmt::Display for FrozenEra {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pre-{}", self.until)
    }
}

/// Validates ordered frozen eras and returns their `until` activation timestamps on `chain_id`.
/// Each era must be non-empty and scheduled in [`tempo_hardfork::constants`].
pub(crate) fn era_boundaries<'a>(
    chain_id: U64,
    eras: impl IntoIterator<Item = &'a FrozenEra>,
) -> eyre::Result<Vec<u64>> {
    let mut boundaries: Vec<u64> = Vec::new();
    for era in eras {
        ensure!(
            !era.binary.as_os_str().is_empty(),
            "era {era} requires an executable"
        );
        let end = era
            .until
            .activation_timestamp(chain_id.to())
            .ok_or_eyre(format!(
                "{} has no activation on chain {chain_id}",
                era.until
            ))?;
        ensure!(
            boundaries
                .last()
                .map_or(end > 0, |previous| *previous < end),
            "era {era} must activate after its predecessor"
        );
        boundaries.push(end);
    }
    Ok(boundaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_hardfork::constants::mainnet::*;

    #[test]
    fn boundaries_come_from_hardfork_constants() {
        let mut catalog: Catalog = serde_json::from_value(serde_json::json!({
            "chains":[{"chain_id":"0x1079", "eras":[
                {"until":"T1", "binary":"t0-tempo"},
                {"until":"T11", "binary":"t10-tempo"}
            ]}]
        }))
        .unwrap();
        catalog.validate().unwrap();
        assert!(catalog.for_chain(1).is_none());
        let chain = catalog.for_chain(MAINNET_CHAIN_ID).unwrap();
        assert_eq!(
            chain.boundaries().unwrap(),
            [MAINNET_T1_TIMESTAMP, MAINNET_T11_TIMESTAMP]
        );
        assert_eq!(chain.eras[1].to_string(), "pre-T11");

        let invalid = |chain: &ChainEras| chain.boundaries().unwrap_err().to_string();
        let mut chain = chain.clone();
        chain.eras[1].until = TempoHardfork::T1A;
        assert_eq!(
            invalid(&chain),
            "era pre-T1A must activate after its predecessor"
        );
        chain.eras[1].until = TempoHardfork::T14;
        assert_eq!(invalid(&chain), "T14 has no activation on chain 4217");
        chain.eras[1].binary = PathBuf::new();
        assert_eq!(invalid(&chain), "era pre-T14 requires an executable");
        chain.eras.truncate(1);
        chain.eras[0].until = TempoHardfork::T0;
        assert_eq!(
            invalid(&chain),
            "era pre-T0 must activate after its predecessor"
        );
        chain.chain_id = U64::from(1);
        assert_eq!(invalid(&chain), "T0 has no activation on chain 1");

        let mut duplicate = serde_json::to_value(&catalog.chains[0]).unwrap();
        duplicate["chain_id"] = serde_json::json!("0x01079");
        catalog
            .chains
            .push(serde_json::from_value(duplicate).unwrap());
        assert_eq!(
            catalog.validate().unwrap_err().to_string(),
            "duplicate chain ID in era catalog"
        );
    }
}
