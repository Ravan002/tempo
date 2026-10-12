use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};
use zone_gateway::{Config, Gateway};

#[derive(Parser)]
#[command(
    name = "zones-gateway",
    about = "Authenticate and forward Zone RPC and Indexer requests"
)]
struct Args {
    #[arg(long, env = "ZONES_GATEWAY_CONFIG")]
    config: PathBuf,
    #[arg(long, default_value = "127.0.0.1:9099")]
    metrics_listen: SocketAddr,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Migrate,
    Archive,
    VerifyHistory,
    IndexerBoundary,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if matches!(args.command, Command::IndexerBoundary) {
        let config = zone_gateway::indexer_boundary::BoundaryConfig::load(&args.config).await?;
        return zone_gateway::indexer_boundary::IndexerBoundary::serve(config).await;
    }
    let config = Config::load(&args.config).await?;
    match args.command {
        Command::Serve => {
            eyre::ensure!(
                args.metrics_listen.ip().is_loopback(),
                "metrics listener must bind loopback"
            );
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .with_http_listener(args.metrics_listen)
                .install()?;
            Gateway::serve(config).await
        }
        Command::Migrate => Gateway::migrate(config).await,
        Command::Archive => Gateway::archive(config).await,
        Command::VerifyHistory => Gateway::verify_history(config).await,
        Command::IndexerBoundary => unreachable!("handled before gateway configuration"),
    }
}
