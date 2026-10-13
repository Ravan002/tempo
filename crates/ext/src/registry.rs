//! Persistent registry of installed extensions (versions, update check timestamps).
//!
//! Writers hold [`Registry::lock`] across load-modify-save, and across any
//! install or removal whose result they record, so concurrent `tempo`
//! invocations and background updates never interleave. Saves go through a
//! unique temp file and an atomic rename, so readers never need the lock.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const UPDATE_CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours

/// Exclusive advisory lock on the registry, released on drop.
#[derive(Debug)]
pub(crate) struct RegistryLock {
    _file: Option<fs::File>,
}

/// On-disk state for all known extensions, keyed by extension name.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Registry {
    /// Map from extension name (e.g. `"wallet"`) to its recorded state.
    #[serde(default)]
    pub(crate) extensions: HashMap<String, ExtensionState>,
}

/// Persisted metadata for a single extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtensionState {
    /// Unix timestamp (seconds) of the last update check.
    pub(crate) checked_at: u64,
    /// Version string recorded at install time (e.g. `"1.0.0"`).
    pub(crate) installed_version: String,
    /// When true, auto-update will not install newer versions — only
    /// log that an update is available. Set when the user installs a
    /// specific version via `tempo add <ext> <version>`.
    #[serde(default)]
    pub(crate) pinned: bool,
    /// Short description from the release manifest.
    #[serde(default)]
    pub(crate) description: String,
    /// Message left by a background update check, shown and cleared on the
    /// next invocation whose stderr is a terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) notice: Option<String>,
}

impl Registry {
    /// Loads the registry from disk.
    ///
    /// Returns `Ok(Self::default())` when the file does not exist or no data
    /// directory can be determined. Returns an error if the file exists but
    /// cannot be read or parsed — the caller should surface this to the user.
    pub(crate) fn load() -> Result<Self, String> {
        let Some(path) = state_path() else {
            return Ok(Self::default());
        };
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(_) => {
                return Err(format!(
                    "registry corrupt; to reset, run:\n  rm \"{}\"",
                    path.display()
                ));
            }
        };
        serde_json::from_str(&content).map_err(|_| {
            format!(
                "registry corrupt; to reset, run:\n  rm \"{}\"",
                path.display()
            )
        })
    }

    /// Persists the registry to disk via atomic rename.
    pub(crate) fn save(&self) {
        let path = match state_path() {
            Some(p) => p,
            None => return,
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(err) => {
                tracing::warn!("registry serialize failed: {err}");
                return;
            }
        };
        let dir = path.parent().unwrap_or(Path::new("."));
        let result = tempfile::NamedTempFile::new_in(dir).and_then(|mut tmp| {
            tmp.write_all(format!("{json}\n").as_bytes())?;
            tmp.persist(&path).map_err(|err| err.error)?;
            Ok(())
        });
        if let Err(err) = result {
            tracing::warn!("registry write failed: {}: {err}", path.display());
        }
    }

    /// Blocks until this process holds the registry lock. Runs unlocked
    /// (with a warning) if the lock file cannot be opened or locked.
    pub(crate) fn lock() -> RegistryLock {
        let file = open_lock_file().filter(|file| match file.lock() {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!("registry lock failed: {err}");
                false
            }
        });
        RegistryLock { _file: file }
    }

    /// Like [`Self::lock`], but returns `None` instead of waiting when
    /// another process holds the lock.
    pub(crate) fn try_lock() -> Option<RegistryLock> {
        let Some(file) = open_lock_file() else {
            return Some(RegistryLock { _file: None });
        };
        match file.try_lock() {
            Ok(()) => Some(RegistryLock { _file: Some(file) }),
            Err(fs::TryLockError::WouldBlock) => None,
            Err(fs::TryLockError::Error(err)) => {
                tracing::warn!("registry lock failed: {err}");
                Some(RegistryLock { _file: None })
            }
        }
    }

    /// Returns `true` if the extension has never been checked or the last
    /// check was more than 6 hours ago.
    pub(crate) fn needs_update_check(&self, extension: &str) -> bool {
        let now = now_secs();
        match self.extensions.get(extension) {
            Some(ext) => now.saturating_sub(ext.checked_at) >= UPDATE_CHECK_INTERVAL_SECS,
            None => true,
        }
    }

    /// Records a successful install or update check for an extension.
    pub(crate) fn record_check(
        &mut self,
        extension: &str,
        version: &str,
        pinned: bool,
        description: &str,
    ) {
        self.extensions.insert(
            extension.to_string(),
            ExtensionState {
                checked_at: now_secs(),
                installed_version: version.to_string(),
                pinned,
                description: description.to_string(),
                notice: None,
            },
        );
    }

    /// Bumps the check timestamp without changing the recorded version.
    /// Used on network failure to avoid retrying every invocation.
    pub(crate) fn touch_check(&mut self, extension: &str) {
        if let Some(ext) = self.extensions.get_mut(extension) {
            ext.checked_at = now_secs();
        } else {
            // No record at all — record with empty version so we don't
            // keep retrying on every launch during an outage.
            self.extensions.insert(
                extension.to_string(),
                ExtensionState {
                    checked_at: now_secs(),
                    installed_version: String::new(),
                    pinned: false,
                    description: String::new(),
                    notice: None,
                },
            );
        }
    }

    /// Returns `true` if a background update check left a notice to show.
    pub(crate) fn has_notice(&self, extension: &str) -> bool {
        self.extensions
            .get(extension)
            .is_some_and(|e| e.notice.is_some())
    }

    /// Stores a notice for the next interactive invocation of an extension.
    pub(crate) fn set_notice(&mut self, extension: &str, notice: String) {
        if let Some(ext) = self.extensions.get_mut(extension) {
            ext.notice = Some(notice);
        }
    }

    /// Removes and returns the pending notice for an extension.
    pub(crate) fn take_notice(&mut self, extension: &str) -> Option<String> {
        self.extensions.get_mut(extension)?.notice.take()
    }
}

/// Opens (creating if needed) the lock file next to the registry.
fn open_lock_file() -> Option<fs::File> {
    let path = state_path()?.with_extension("lock");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .inspect_err(|err| tracing::warn!("registry lock open failed: {}: {err}", path.display()))
        .ok()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolves the path to the registry file.
///
/// Uses `TEMPO_HOME/extensions.json` if set, otherwise the platform data
/// directory via `dirs_next` (e.g. `~/Library/Application Support/tempo` on
/// macOS, `$XDG_DATA_HOME/tempo` on Linux).
fn state_path() -> Option<PathBuf> {
    if let Some(home) = env::var_os("TEMPO_HOME") {
        Some(PathBuf::from(home).join("extensions.json"))
    } else {
        dirs_next::data_dir().map(|data| data.join("tempo").join("extensions.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::ENV_MUTEX;

    /// RAII guard that sets `TEMPO_HOME` to a temp directory and restores it
    /// on drop. Must be held alongside `ENV_MUTEX`.
    struct TempHome {
        prev: Option<String>,
        _tmp: tempfile::TempDir,
    }

    impl TempHome {
        fn new() -> Self {
            let tmp = tempfile::TempDir::new().unwrap();
            let prev = std::env::var("TEMPO_HOME").ok();
            unsafe { std::env::set_var("TEMPO_HOME", tmp.path()) };
            Self { prev, _tmp: tmp }
        }

        fn registry_path(&self) -> PathBuf {
            self._tmp.path().join("extensions.json")
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var("TEMPO_HOME", v) },
                None => unsafe { std::env::remove_var("TEMPO_HOME") },
            }
        }
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _home = TempHome::new();
        let reg = Registry::load().unwrap();
        assert!(reg.extensions.is_empty());
    }

    #[test]
    fn load_returns_ok_for_valid_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0","pinned":false,"description":"test"}}}"#;
        fs::write(home.registry_path(), json).unwrap();
        let reg = Registry::load().unwrap();
        assert_eq!(reg.extensions["wallet"].installed_version, "1.0.0");
        assert_eq!(reg.extensions["wallet"].description, "test");
    }

    #[test]
    fn load_returns_error_for_invalid_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), "NOT VALID JSON {{{").unwrap();
        let err = Registry::load().unwrap_err();
        assert!(
            err.contains("registry corrupt"),
            "expected 'registry corrupt', got: {err}"
        );
        assert!(err.contains("rm \""), "expected rm command, got: {err}");
    }

    #[test]
    fn load_returns_error_for_unreadable_path() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        // Create a directory where the file is expected — read_to_string
        // will fail with a non-NotFound IO error.
        fs::create_dir_all(home.registry_path()).unwrap();
        let err = Registry::load().unwrap_err();
        assert!(
            err.contains("registry corrupt"),
            "expected 'registry corrupt', got: {err}"
        );
    }

    #[test]
    fn load_error_message_contains_path() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), "garbage").unwrap();
        let err = Registry::load().unwrap_err();
        let expected_path = home.registry_path().display().to_string();
        assert!(
            err.contains(&expected_path),
            "error should contain path '{expected_path}', got: {err}"
        );
    }

    #[test]
    fn save_then_load_roundtrip_on_disk() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _home = TempHome::new();
        let mut reg = Registry::default();
        reg.record_check("wallet", "2.0.0", true, "Tempo wallet");
        reg.save();
        let loaded = Registry::load().unwrap();
        assert_eq!(loaded.extensions["wallet"].installed_version, "2.0.0");
        assert!(loaded.extensions["wallet"].pinned);
        assert_eq!(loaded.extensions["wallet"].description, "Tempo wallet");
    }

    #[test]
    fn load_empty_file_returns_error() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), "").unwrap();
        let err = Registry::load().unwrap_err();
        assert!(
            err.contains("registry corrupt"),
            "empty file should be corrupt, got: {err}"
        );
    }

    #[test]
    fn load_partial_json_returns_error() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), r#"{"extensions":{"#).unwrap();
        let err = Registry::load().unwrap_err();
        assert!(err.contains("registry corrupt"));
    }

    #[test]
    fn needs_check_when_no_record() {
        let reg = Registry::default();
        assert!(reg.needs_update_check("wallet"));
    }

    #[test]
    fn no_check_needed_after_recent_record() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false, "");
        assert!(!reg.needs_update_check("wallet"));
    }

    #[test]
    fn check_needed_after_stale_record() {
        let mut reg = Registry::default();
        reg.extensions.insert(
            "wallet".to_string(),
            ExtensionState {
                checked_at: now_secs() - UPDATE_CHECK_INTERVAL_SECS - 1,
                installed_version: "v1.0.0".to_string(),
                pinned: false,
                description: String::new(),
                notice: None,
            },
        );
        assert!(reg.needs_update_check("wallet"));
    }

    #[test]
    fn touch_preserves_version() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false, "");
        reg.extensions.get_mut("wallet").unwrap().checked_at = 0;
        reg.touch_check("wallet");
        assert_eq!(reg.extensions["wallet"].installed_version, "v1.0.0");
        assert!(!reg.needs_update_check("wallet"));
    }

    #[test]
    fn touch_creates_record_if_missing() {
        let mut reg = Registry::default();
        reg.touch_check("wallet");
        assert!(!reg.needs_update_check("wallet"));
        assert_eq!(reg.extensions["wallet"].installed_version, "");
    }

    #[test]
    fn roundtrip_serialize() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false, "");
        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.extensions["wallet"].installed_version, "v1.0.0");
    }

    #[test]
    fn pinned_flag_recorded() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true, "");
        assert!(reg.extensions["wallet"].pinned);
    }

    #[test]
    fn not_pinned_by_default() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false, "");
        assert!(!reg.extensions["wallet"].pinned);
    }

    #[test]
    fn update_unpins() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true, "");
        assert!(reg.extensions["wallet"].pinned);
        reg.record_check("wallet", "2.0.0", false, "");
        assert!(!reg.extensions["wallet"].pinned);
    }

    #[test]
    fn roundtrip_serialize_pinned() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true, "");
        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert!(loaded.extensions["wallet"].pinned);
    }

    #[test]
    fn description_recorded() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false, "Tempo wallet");
        assert_eq!(reg.extensions["wallet"].description, "Tempo wallet");
    }

    #[test]
    fn deserialize_without_description_defaults_empty() {
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0","pinned":false}}}"#;
        let reg: Registry = serde_json::from_str(json).unwrap();
        assert_eq!(reg.extensions["wallet"].description, "");
    }

    #[test]
    fn lock_excludes_other_holders() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _home = TempHome::new();

        let held = Registry::lock();
        assert!(Registry::try_lock().is_none(), "lock is exclusive");
        drop(held);

        let held = Registry::try_lock().expect("lock is free after drop");
        assert!(Registry::try_lock().is_none(), "try_lock is exclusive too");
        drop(held);
    }

    #[test]
    fn save_leaves_no_temp_files() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false, "");
        reg.save();
        reg.save();

        let names: Vec<_> = fs::read_dir(home._tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["extensions.json"]);
    }

    #[test]
    fn notice_lifecycle() {
        let mut reg = Registry::default();
        reg.set_notice("wallet", "ignored".to_string());
        assert!(!reg.has_notice("wallet"), "no notice without a record");

        reg.record_check("wallet", "1.0.0", false, "");
        reg.set_notice("wallet", "updated".to_string());
        reg.touch_check("wallet");
        assert!(reg.has_notice("wallet"), "touch keeps the notice");

        assert_eq!(reg.take_notice("wallet").as_deref(), Some("updated"));
        assert!(
            reg.take_notice("wallet").is_none(),
            "take clears the notice"
        );

        reg.set_notice("wallet", "stale".to_string());
        reg.record_check("wallet", "2.0.0", false, "");
        assert!(!reg.has_notice("wallet"), "a new install clears the notice");
    }

    #[test]
    fn notice_omitted_from_json_when_absent() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false, "");
        assert!(!serde_json::to_string(&reg).unwrap().contains("notice"));
    }

    #[test]
    fn deserialize_without_pinned_defaults_false() {
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0"}}}"#;
        let reg: Registry = serde_json::from_str(json).unwrap();
        assert!(!reg.extensions["wallet"].pinned);
    }
}
