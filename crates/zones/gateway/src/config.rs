use eyre::{Result, ensure};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use url::Url;
use zone_auth::Domain;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub domain: Domain,
    pub listen: SocketAddr,
    pub database_url: String,
    pub archive_dir: PathBuf,
    pub tempo_rpc: String,
    pub zone_rpc: String,
    pub rpc_backend: Url,
    pub backend_tls: TlsFiles,
    pub frontend_tls: Option<ServerTls>,
    pub indexer_backend: Option<Url>,
    #[serde(default)]
    pub indexer_paths: Vec<String>,
    #[serde(default)]
    pub indexer_stream_paths: Vec<String>,
    pub indexer_events_path: Option<String>,
    pub requests_per_second: u32,
    pub egress_bytes_per_second: u64,
    pub log_retention_seconds: u64,
    pub max_response_bytes: usize,
    pub delivery_key_env: Option<String>,
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        let source = tokio::fs::read(path).await?;
        ensure!(source.len() <= 64 * 1024, "configuration too large");
        let mut config: Self = serde_json::from_slice(&source)?;
        if let Some(name) = config.database_url.strip_prefix("env:") {
            config.database_url = std::env::var(name)?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.requests_per_second > 0 && self.requests_per_second <= 100_000,
            "request rate must be 1..100000"
        );
        ensure!(
            self.egress_bytes_per_second > 0,
            "egress rate must be positive"
        );
        ensure!(
            self.log_retention_seconds > 0,
            "log retention must be positive"
        );
        ensure!(
            (1024..=64 * 1024 * 1024).contains(&self.max_response_bytes),
            "response limit must be 1 KiB..64 MiB"
        );
        ensure!(
            !self.archive_dir.as_os_str().is_empty(),
            "archive directory required"
        );
        ensure!(
            self.listen.ip().is_loopback() || self.frontend_tls.is_some(),
            "non-loopback listener requires frontend TLS"
        );
        for url in std::iter::once(&self.rpc_backend).chain(self.indexer_backend.iter()) {
            ensure!(
                url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "backend must use HTTPS workload authentication without URL credentials or query"
            );
        }
        for path in self
            .indexer_paths
            .iter()
            .chain(self.indexer_stream_paths.iter())
            .chain(self.indexer_events_path.iter())
        {
            ensure!(
                path.starts_with('/')
                    && !path.starts_with("//")
                    && !path.contains('%')
                    && !path.contains("..")
                    && !path.contains('?')
                    && !path.contains('#')
                    && !path.contains('\\')
                    && path.len() <= 256,
                "invalid Indexer route"
            );
        }
        ensure!(
            self.indexer_paths.len() + self.indexer_stream_paths.len() <= 64,
            "too many Indexer routes"
        );
        ensure!(
            self.indexer_backend.is_some()
                || (self.indexer_paths.is_empty()
                    && self.indexer_stream_paths.is_empty()
                    && self.indexer_events_path.is_none()),
            "Indexer routes require an upstream"
        );
        ensure!(
            self.indexer_events_path.is_none() || self.delivery_key_env.is_some(),
            "Indexer deliveries require an encryption key"
        );
        Ok(())
    }
}
