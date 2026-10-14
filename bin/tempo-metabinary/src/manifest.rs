//! Ordered binaries and bounded imports for bootstrapping shared execution storage.

use crate::catalog::{FrozenEra, era_boundaries};
use alloy_primitives::{B256, U64};
use eyre::{Context, OptionExt, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Ordered frozen era executables and bounded imports for a chain's shared storage.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Built-in chain name or chain specification path.
    pub chain: String,
    /// Shared data directory. Binary and datadir paths are manifest-relative.
    pub datadir: PathBuf,
    /// Expected identity, checked against each era's storage before advancing.
    pub chain_id: U64,
    pub genesis_hash: B256,
    /// Frozen eras in activation order. The live era is started afterwards with `tempo node`.
    pub eras: Vec<Bootstrap>,
}

impl Manifest {
    /// Paths resolve relative to the manifest.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .wrap_err_with(|| format!("cannot read manifest {}", path.display()))?;
        let mut manifest: Self = serde_json::from_slice(&bytes)
            .wrap_err_with(|| format!("invalid manifest {}", path.display()))?;
        manifest.validate()?;
        let parent = path.canonicalize()?.with_file_name("");
        resolve_path(&parent, &mut manifest.datadir);
        for bootstrap in &mut manifest.eras {
            resolve_path(&parent, &mut bootstrap.era.binary);
        }
        // Built-in names have no path separator. Explicit spec paths are manifest-relative.
        if manifest.chain.contains(std::path::MAIN_SEPARATOR) || manifest.chain.ends_with(".json") {
            let mut chain_path = PathBuf::from(&manifest.chain);
            resolve_path(&parent, &mut chain_path);
            manifest.chain = chain_path.to_string_lossy().into_owned();
        }
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.chain.is_empty(), "chain must not be empty");
        ensure!(
            !self.datadir.as_os_str().is_empty(),
            "datadir must not be empty"
        );
        ensure!(!self.eras.is_empty(), "manifest needs a frozen era");
        self.boundaries()?;
        let mut previous_checkpoint = None;
        for bootstrap in &self.eras {
            let era = &bootstrap.era;
            let checkpoint = era
                .checkpoint
                .ok_or_eyre(format!("era {era} needs a bootstrap checkpoint"))?;
            bootstrap
                .validate()
                .wrap_err_with(|| format!("invalid bootstrap for {era}"))?;
            ensure!(
                previous_checkpoint.is_none_or(|previous| previous < checkpoint.number),
                "bootstrap checkpoint numbers must strictly increase"
            );
            previous_checkpoint = Some(checkpoint.number);
        }
        Ok(())
    }

    /// Each era's exclusive end timestamp, from its `until` hardfork activation.
    pub fn boundaries(&self) -> Result<Vec<u64>> {
        era_boundaries(
            self.chain_id,
            self.eras.iter().map(|bootstrap| &bootstrap.era),
        )
    }
}

/// A frozen era and the finite import command that must reach its required checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub era: FrozenEra,
    /// Starts with `import`. The wrapper adds shared storage and validation flags.
    pub args: Vec<String>,
}

impl Bootstrap {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.args.first().map(String::as_str) == Some("import"),
            "bootstrap args must start with import"
        );
        // Import must execute state, validate blocks, and stop at the pinned file boundary.
        for arg in &self.args[1..] {
            let key = arg.split('=').next().unwrap_or(arg);
            ensure!(
                !matches!(
                    key,
                    "--" | "--chain"
                        | "--datadir"
                        | "--debug.max-block"
                        | "--debug.terminate"
                        | "--fail-on-invalid-block"
                ) && !key.starts_with("--datadir."),
                "bootstrap owns flag {key}"
            );
            ensure!(key != "--no-state", "bootstrap import must execute state");
        }
        Ok(())
    }
}

pub(crate) fn resolve_path(parent: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = parent.join(&*path);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn manifest() -> Manifest {
        serde_json::from_str(include_str!("../examples/eras-manifest.json")).unwrap()
    }

    #[test]
    fn rejects_invalid_eras_and_bootstrap_options() {
        let mut manifest = manifest();
        let error = |manifest: &Manifest| manifest.validate().unwrap_err().to_string();
        let mut invalid = manifest.clone();
        invalid.eras.clear();
        assert_eq!(error(&invalid), "manifest needs a frozen era");
        invalid.eras.push(manifest.eras[0].clone());
        invalid.eras[0].era.checkpoint = None;
        assert_eq!(error(&invalid), "era pre-T11 needs a bootstrap checkpoint");
        let mut invalid = manifest.clone();
        invalid.eras.insert(0, manifest.eras[0].clone());
        invalid.eras[0].era.until = tempo_hardfork::TempoHardfork::T10;
        assert_eq!(
            error(&invalid),
            "bootstrap checkpoint numbers must strictly increase"
        );
        invalid.eras[0].era.checkpoint.as_mut().unwrap().number -= 1;
        invalid.validate().unwrap();
        for args in [
            "node",
            "import --chain=other blocks.rlp",
            "import --datadir blocks.rlp",
            "import --datadir.static-files=other blocks.rlp",
            "import -- blocks.rlp",
            "import --no-state blocks.rlp",
            "import --no-state=true blocks.rlp",
            "import --no-state=false blocks.rlp",
            "import --debug.max-block=42 blocks.rlp",
            "import --fail-on-invalid-block=false blocks.rlp",
        ] {
            manifest.eras[0].args = args.split_whitespace().map(str::to_owned).collect();
            assert!(manifest.validate().is_err(), "accepted {args}");
        }
        manifest.eras[0].args = vec![
            "import".into(),
            "--chunk-len=67108864".into(),
            "--db.max-size=8TB".into(),
            "blocks.rlp".into(),
        ];
        manifest.validate().unwrap();
        let value = serde_json::to_value(&manifest).unwrap();
        for (field, malformed) in [
            ("chain_id", "0x10000000000000000"),
            ("genesis_hash", "0x01"),
        ] {
            let mut invalid = value.clone();
            invalid[field] = serde_json::json!(malformed);
            assert!(serde_json::from_value::<Manifest>(invalid).is_err());
        }
    }

    #[test]
    fn paths_are_relative_to_manifest_not_working_directory() {
        let temp = tempfile::tempdir().unwrap();
        let mut manifest = manifest();
        manifest.datadir = "data".into();
        manifest.chain = "./chain.json".into();
        manifest.eras[0].era.binary = "frozen".into();
        let path = temp.path().join("eras.json");
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let loaded = Manifest::load(path).unwrap();
        let directory = temp.path().canonicalize().unwrap();
        assert_eq!(loaded.datadir, directory.join("data"));
        assert_eq!(loaded.eras[0].era.binary, directory.join("frozen"));
        assert_eq!(PathBuf::from(loaded.chain), directory.join("./chain.json"));
    }
}
