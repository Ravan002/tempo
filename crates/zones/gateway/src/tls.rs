use crate::config::{ServerTls, TlsFiles};
use axum::Router;
use eyre::Result;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};

pub(crate) async fn backend_client(
    files: &TlsFiles,
) -> Result<(reqwest::Client, Arc<ClientConfig>)> {
    let ca = tokio::fs::read(&files.ca).await?;
    let cert = tokio::fs::read(&files.cert).await?;
    let key = tokio::fs::read(&files.key).await?;
    eyre::ensure!(
        ca.len() <= 64 * 1024 && cert.len() <= 64 * 1024 && key.len() <= 64 * 1024,
        "TLS material too large"
    );
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&ca) {
        roots.add(certificate?)?;
    }
    let certs =
        CertificateDer::pem_slice_iter(&cert).collect::<std::result::Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&key)?;
    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let http = reqwest::Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(30))
        .build()?;
    Ok((http, tls))
}

pub(crate) async fn serve_public(
    listener: TcpListener,
    router: Router,
    tls: Option<ServerTls>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let Some(files) = tls else {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stop.changed().await;
            })
            .await?;
        return Ok(());
    };
    let certs = tokio::fs::read(files.cert).await?;
    let key = tokio::fs::read(files.key).await?;
    let certs =
        CertificateDer::pem_slice_iter(&certs).collect::<std::result::Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ));
    let capacity = Arc::new(Semaphore::new(1_024));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                let router = router.clone();
                let acceptor = acceptor.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream)).await else { return; };
                    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let _ = builder.serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(router)).await;
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.shutdown().await;
    Ok(())
}
