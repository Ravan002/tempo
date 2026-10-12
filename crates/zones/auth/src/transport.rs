//! Private mTLS listener. Only this module can construct the peer request extension.

use alloy_primitives::{B256, keccak256};
use axum::{Extension, Router};
use eyre::{Result, ensure};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

/// Request identity created only after a validated, explicitly pinned TLS handshake.
#[derive(Clone)]
pub struct VerifiedGatewayPeer {
    certificate_hash: B256,
}
impl VerifiedGatewayPeer {
    pub fn certificate_hash(&self) -> B256 {
        self.certificate_hash
    }
}

#[derive(Clone, Debug)]
pub struct GatewayTlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub gateway_ca: PathBuf,
    pub gateway_certificate_hash: B256,
}

impl GatewayTlsConfig {
    pub fn validate(&self) -> Result<()> {
        self.server_config().map(|_| ())
    }

    fn server_config(&self) -> Result<ServerConfig> {
        ensure!(
            self.gateway_certificate_hash != B256::ZERO,
            "gateway certificate pin is required"
        );
        let certificates = CertificateDer::pem_file_iter(&self.certificate)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(&self.private_key)?;
        let authorities = CertificateDer::pem_file_iter(&self.gateway_ca)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(!authorities.is_empty(), "gateway CA is empty");
        let mut roots = RootCertStore::empty();
        for authority in authorities {
            roots.add(authority)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Serve only mutually authenticated connections; no plaintext account context entrance exists.
pub async fn serve_gateway(
    listener: TcpListener,
    router: Router,
    config: GatewayTlsConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config.server_config()?));
    let permits = Arc::new(Semaphore::new(1024));
    let mut connections = JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                // A connection failure never authorizes a subsequent plaintext retry.
                if let Err(error) = result { tracing::debug!(%error, "private RPC connection ended"); }
            }
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { drop(socket); continue; };
                let acceptor = acceptor.clone();
                let router = router.clone();
                let pin = config.gateway_certificate_hash;
                let mut stop = shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let stream = match tokio::time::timeout(Duration::from_secs(2), acceptor.accept(socket)).await {
                        Ok(Ok(stream)) => stream,
                        _ => return,
                    };
                    let Some(certificate) = stream.get_ref().1.peer_certificates().and_then(|chain| chain.first()) else { return; };
                    let certificate_hash = keccak256(certificate.as_ref());
                    if certificate_hash != pin { return; }
                    let router = router.layer(Extension(VerifiedGatewayPeer { certificate_hash }));
                    let service = TowerToHyperService::new(router);
                    let builder = Builder::new(TokioExecutor::new());
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stop.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(Duration::from_secs(10), &mut connection).await;
                        }
                    }
                });
            }
        }
    }
    // Upgraded sessions are separately owned by the RPC; dropping their task/transport closes them.
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_err()
    {
        connections.abort_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use rustls::{ClientConfig, pki_types::ServerName};
    use std::{path::Path, process::Command};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn openssl(directory: &Path, args: &[&str]) {
        let result = Command::new("openssl")
            .current_dir(directory)
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fn certificates() -> Scratch {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("zone-gateway-tls-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        openssl(
            &directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "1",
                "-subj",
                "/CN=Gateway Test CA",
            ],
        );
        std::fs::write(
            directory.join("server.ext"),
            "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
        )
        .unwrap();
        std::fs::write(
            directory.join("client.ext"),
            "extendedKeyUsage=clientAuth\n",
        )
        .unwrap();
        for name in ["server", "client", "other"] {
            openssl(
                &directory,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN={name}"),
                ],
            );
            openssl(
                &directory,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{name}.pem"),
                    "-days",
                    "1",
                    "-extfile",
                    if name == "server" {
                        "server.ext"
                    } else {
                        "client.ext"
                    },
                ],
            );
        }
        Scratch(directory)
    }

    async fn request(
        address: std::net::SocketAddr,
        directory: &Path,
        client: Option<&str>,
    ) -> Result<String> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(directory.join("ca.pem"))? {
            roots.add(cert?)?;
        }
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots);
        let config = if let Some(client) = client {
            let certs = CertificateDer::pem_file_iter(directory.join(format!("{client}.pem")))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(directory.join(format!("{client}.key")))?;
            builder.with_client_auth_cert(certs, key)?
        } else {
            builder.with_no_client_auth()
        };
        let stream = tokio::net::TcpStream::connect(address).await?;
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost")?, stream)
            .await?;
        tls.write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nx-zone-account: forged\r\n\r\n").await?;
        let mut response = Vec::new();
        let read = tls.read_to_end(&mut response).await;
        if response.is_empty() {
            read?;
        }
        Ok(String::from_utf8(response)?)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_pinned_mutually_authenticated_peer_receives_extension() {
        let directory = certificates();
        let cert = CertificateDer::from_pem_file(directory.0.join("client.pem")).unwrap();
        let config = GatewayTlsConfig {
            certificate: directory.0.join("server.pem"),
            private_key: directory.0.join("server.key"),
            gateway_ca: directory.0.join("ca.pem"),
            gateway_certificate_hash: keccak256(cert.as_ref()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/probe",
            get(|Extension(_): Extension<VerifiedGatewayPeer>| async { "authenticated" }),
        );
        let (shutdown, stop) = watch::channel(false);
        let task = tokio::spawn(serve_gateway(listener, router, config, stop));
        let response = request(address, &directory.0, Some("client"))
            .await
            .unwrap();
        assert!(response.contains("200 OK"));
        assert!(response.ends_with("authenticated"));
        assert!(request(address, &directory.0, None).await.is_err());
        let unpinned = request(address, &directory.0, Some("other")).await;
        assert!(unpinned.is_err() || !unpinned.unwrap().contains("200 OK"));
        shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }
}
