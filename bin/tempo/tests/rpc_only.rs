//! `tempo rpc-only` serving a datadir that a running dev node keeps writing.

use jsonrpsee::{
    core::client::{ClientT as _, SubscriptionClientT as _},
    http_client::HttpClientBuilder,
    rpc_params,
    ws_client::WsClientBuilder,
};
use serde_json::Value;
use std::{
    net::{Ipv4Addr, TcpListener},
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

const WAIT: Duration = Duration::from_secs(120);

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tempo(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tempo"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn block_number(url: &str) -> Option<u64> {
    let client = HttpClientBuilder::default().build(url).ok()?;
    let number: String = client
        .request("eth_blockNumber", rpc_params![])
        .await
        .ok()?;
    u64::from_str_radix(number.trim_start_matches("0x"), 16).ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn trace_chain_streams_stored_blocks_over_ws() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().to_str().unwrap();
    let node_port = free_port().to_string();
    let _node = tempo(&[
        "node",
        "--dev",
        "--dev.block-time",
        "100ms",
        "--datadir",
        datadir,
        "--tempo.bootnodes-endpoint",
        "none",
        "--disable-discovery",
        "--no-persist-peers",
        "--port",
        "0",
        "--authrpc.port",
        "0",
        "--http",
        "--http.port",
        &node_port,
        "--engine.persistence-threshold",
        "0",
        "--engine.memory-block-buffer-target",
        "0",
    ]);
    let node_url = format!("http://127.0.0.1:{node_port}");
    tokio::time::timeout(WAIT, async {
        while block_number(&node_url)
            .await
            .is_none_or(|number| number < 5)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("dev node did not produce blocks");

    let worker_port = free_port().to_string();
    let _worker = tempo(&[
        "rpc-only",
        "--chain",
        "dev",
        "--datadir",
        datadir,
        "--port",
        &worker_port,
    ]);
    let worker_url = format!("http://127.0.0.1:{worker_port}");
    tokio::time::timeout(WAIT, async {
        while block_number(&worker_url)
            .await
            .is_none_or(|number| number < 3)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("worker did not serve stored blocks");

    let ws = WsClientBuilder::default()
        .build(format!("ws://127.0.0.1:{worker_port}"))
        .await
        .unwrap();
    let mut subscription = ws
        .subscribe::<Value, _>(
            "debug_subscribe",
            rpc_params!["traceChain", "0x1", "0x3"],
            "debug_unsubscribe",
        )
        .await
        .unwrap();
    // Blocks without traces are skipped, except the end block.
    let mut blocks = Vec::new();
    while blocks.last() != Some(&Value::from("0x3")) {
        let item = tokio::time::timeout(WAIT, subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        blocks.push(item["block"].clone());
        assert!(blocks.len() <= 2, "{blocks:?}");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(500), subscription.next())
            .await
            .is_err(),
        "the stream ends after the end block"
    );
}
