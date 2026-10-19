//! Lifecycle tests against a fixture worker: this test binary re-executed by a shell script that
//! records each start and creates the worker's RocksDB secondary, like Reth does.

use super::*;
use crate::handshake::{EXECUTION_INFO_METHOD, EXECUTION_INFO_PROTOCOL_VERSION, ExecutionInfo};
use alloy_eips::BlockNumHash;
use futures::StreamExt as _;
use jsonrpsee::{
    RpcModule,
    server::{Server, ServerConfig},
    types::ErrorObject,
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt as _};
use tempo_hardfork::TempoHardfork;

const MODE_ENV: &str = "TEMPO_METABINARY_FIXTURE_MODE";
const ARGS_ENV: &str = "TEMPO_METABINARY_FIXTURE_ARGS";
const DIR_ENV: &str = "TEMPO_METABINARY_FIXTURE_DIR";
const CHAIN_ID: u64 = 4217;
const GENESIS: B256 = B256::repeat_byte(7);
/// Bounds every real-time wait in these tests.
const WAIT: Duration = Duration::from_secs(20);

/// The worker process. Does nothing unless re-executed by the fixture script.
#[test]
fn fixture_worker() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return;
    };
    let args: Vec<String> = std::env::var(ARGS_ENV)
        .unwrap()
        .split(' ')
        .map(str::to_owned)
        .collect();
    let port: u16 = args[args.iter().position(|arg| arg == "--port").unwrap() + 1]
        .parse()
        .unwrap();
    let dir = PathBuf::from(std::env::var(DIR_ENV).unwrap());
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(serve_fixture(&mode, port, dir));
}

async fn serve_fixture(mode: &str, port: u16, dir: PathBuf) {
    match mode {
        "stalled" => std::future::pending().await,
        "exit" => std::process::exit(3),
        "slow" => tokio::time::sleep(Duration::from_secs(2)).await,
        _ => {}
    }
    let mut info = ExecutionInfo {
        protocol_version: EXECUTION_INFO_PROTOCOL_VERSION,
        chain_id: U64::from(CHAIN_ID),
        genesis_hash: GENESIS,
        read_only: true,
        process_id: std::process::id(),
    };
    match mode {
        "wrong-pid" => info.process_id += 1,
        "wrong-chain" => info.chain_id = U64::from(1),
        "wrong-genesis" => info.genesis_hash = B256::ZERO,
        "writer" => info.read_only = false,
        "wrong-protocol" => info.protocol_version += 1,
        _ => {}
    }

    let mut module = RpcModule::new(());
    if mode != "missing-protocol" {
        module
            .register_method(EXECUTION_INFO_METHOD, move |_, _, _| {
                RpcResult::Ok(info.clone())
            })
            .unwrap();
    }
    module
        .register_method("echo", |params, _, _| {
            params.parse::<Value>().unwrap_or(Value::Null)
        })
        .unwrap();
    module
        .register_method("revert", |_, _, _| {
            Err::<(), _>(ErrorObject::owned(-32000, "execution reverted", None::<()>))
        })
        .unwrap();
    module
        .register_async_method("stall", |_, _, _| std::future::pending::<Value>())
        .unwrap();
    module
        .register_method("crash", |_, _, _| -> Value { std::process::exit(1) })
        .unwrap();
    module
        .register_subscription(
            "debug_subscribe",
            "debug_subscription",
            "debug_unsubscribe",
            move |_, pending, _, _| {
                let dir = dir.clone();
                async move {
                    let sink = pending.accept().await?;
                    for block in 1..=3u64 {
                        let item = json!({"block": format!("{block:#x}"), "traces": []});
                        sink.send(serde_json::value::to_raw_value(&item)?).await?;
                    }
                    sink.closed().await;
                    fs::write(dir.join("unsubscribed"), "")?;
                    Ok(())
                }
            },
        )
        .unwrap();
    let server = Server::builder()
        .set_config(ServerConfig::builder().build())
        .build((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let handle = server.start(module);
    handle.stopped().await;
}

struct Fixture {
    dir: tempfile::TempDir,
    workers: Arc<HistoricalWorkers>,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        Self::with_timeout(mode, Duration::from_secs(10))
    }

    fn with_timeout(mode: &str, startup_timeout: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("worker.sh");
        let exe = std::env::current_exe().unwrap();
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 echo $$ >> '{dir}/starts'\n\
                 mkdir -p '{dir}/rocksdb-secondary-tmp-'$$\n\
                 export {MODE_ENV}='{mode}' {ARGS_ENV}=\"$*\" {DIR_ENV}='{dir}'\n\
                 exec '{exe}' workers::tests::fixture_worker --exact --nocapture --test-threads=1\n",
                dir = dir.path().display(),
                exe = exe.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let context = WorkerContext {
            chain: "genesis.json".into(),
            datadir: dir.path().to_path_buf(),
            static_files_path: None,
            rocksdb_path: None,
            rpc_config: dir.path().join("rpc.json"),
            chain_id: U64::from(CHAIN_ID),
            genesis_hash: GENESIS,
            startup_timeout,
        };
        let era = FrozenEra {
            until: TempoHardfork::T12,
            binary: script,
            checkpoint: BlockNumHash::default(),
        };
        let workers = HistoricalWorkers::new(context, vec![era]).unwrap();
        Self { dir, workers }
    }

    fn starts(&self) -> Vec<u32> {
        fs::read_to_string(self.dir.path().join("starts"))
            .unwrap_or_default()
            .lines()
            .map(|pid| pid.parse().unwrap())
            .collect()
    }

    fn secondary(&self, pid: u32) -> PathBuf {
        self.dir.path().join(format!("rocksdb-secondary-tmp-{pid}"))
    }

    async fn request(&self, method: &str, params: Value) -> RpcResult<Value> {
        let raw = tokio::time::timeout(WAIT, self.workers.request(0, method, RpcParams(params)))
            .await
            .expect("request timed out")?;
        Ok(serde_json::from_str(raw.get()).unwrap())
    }

    /// Asserts that `pid` was reaped and its secondary removed, waiting for background stops.
    async fn assert_stopped(&self, pid: u32) {
        tokio::time::timeout(WAIT, async {
            while !is_reaped(pid) || self.secondary(pid).exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("worker {pid} was not stopped"));
    }

    async fn ready_handles(&self) -> Option<usize> {
        match &*self.workers.eras[0].state.lock().await {
            State::Running(process) => process.ready.as_ref().map(Arc::strong_count),
            _ => None,
        }
    }

    async fn is_dormant(&self) -> bool {
        matches!(*self.workers.eras[0].state.lock().await, State::Dormant)
    }
}

fn is_reaped(pid: u32) -> bool {
    // SAFETY: probing with signal 0 has no side effects.
    let rc = unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), 0) };
    rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Moves paused time forward far enough for the idle reaper to stop an unused worker.
async fn idle_out() {
    tokio::time::pause();
    for _ in 0..12 {
        tokio::time::advance(IDLE_CHECK_INTERVAL).await;
        tokio::task::yield_now().await;
    }
    tokio::time::resume();
}

#[tokio::test]
async fn starts_lazily_and_coalesces_concurrent_callers() {
    let fixture = Fixture::new("ok");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(fixture.starts().is_empty());

    let calls = (0..4).map(|i| fixture.request("echo", json!([i])));
    for (i, result) in futures::future::join_all(calls)
        .await
        .into_iter()
        .enumerate()
    {
        assert_eq!(result.unwrap(), json!([i]));
    }
    assert_eq!(fixture.starts().len(), 1);
    fixture.workers.shutdown().await.unwrap();
}

#[tokio::test]
async fn forwards_params_and_maps_errors() {
    let fixture = Fixture::new("ok");
    let named = json!({"blockNumber": "0x1", "request": {"to": null}});
    assert_eq!(fixture.request("echo", named.clone()).await.unwrap(), named);
    assert_eq!(
        fixture.request("echo", Value::Null).await.unwrap(),
        Value::Null
    );

    let err = fixture.request("eth_missing", json!([])).await.unwrap_err();
    assert_eq!(err.code(), UNSUPPORTED_CODE);
    assert_eq!(
        err.message(),
        "eth_missing is unavailable in historical era pre-T12"
    );

    let err = fixture.request("revert", json!([])).await.unwrap_err();
    assert_eq!((err.code(), err.message()), (-32000, "execution reverted"));
    fixture.workers.shutdown().await.unwrap();
}

#[tokio::test]
async fn held_handles_prevent_idle_reaping() {
    let fixture = Fixture::new("ok");
    let worker = tokio::time::timeout(WAIT, fixture.workers.get(0))
        .await
        .unwrap()
        .unwrap();
    let pid = fixture.starts()[0];

    idle_out().await;
    assert_eq!(fixture.ready_handles().await, Some(2));

    drop(worker);
    idle_out().await;
    fixture.assert_stopped(pid).await;
    assert!(fixture.is_dormant().await);

    fixture.request("echo", json!([])).await.unwrap();
    let starts = fixture.starts();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[1], pid);
    fixture.workers.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelled_calls_release_the_worker() {
    let fixture = Fixture::new("ok");
    fixture.request("echo", json!([])).await.unwrap();
    let stalled = tokio::time::timeout(
        Duration::from_millis(200),
        fixture.workers.request(0, "stall", RpcParams(json!([]))),
    )
    .await;
    assert!(stalled.is_err(), "stall must not answer");
    assert_eq!(fixture.ready_handles().await, Some(1));

    idle_out().await;
    fixture.assert_stopped(fixture.starts()[0]).await;
    fixture.workers.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_reaps_workers_and_rejects_requests() {
    let fixture = Fixture::new("ok");
    fixture.request("echo", json!([])).await.unwrap();
    let pid = fixture.starts()[0];

    tokio::time::timeout(WAIT, fixture.workers.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(is_reaped(pid));
    assert!(!fixture.secondary(pid).exists());
    assert!(fixture.is_dormant().await);

    let err = fixture.request("echo", json!([])).await.unwrap_err();
    assert_eq!(err.code(), CALL_EXECUTION_FAILED_CODE);
    assert_eq!(err.message(), "historical workers are shutting down");
}

#[tokio::test]
async fn failed_startups_are_reaped_and_cooled_down() {
    for (mode, expected) in [
        ("wrong-pid", "private endpoint belongs to another process"),
        ("wrong-chain", "worker chain ID mismatch"),
        ("wrong-genesis", "worker genesis mismatch"),
        ("writer", "worker is not read-only"),
        ("wrong-protocol", "unsupported worker protocol"),
        (
            "missing-protocol",
            "executable lacks tempo_executionInfo; it needs the private RPC worker protocol",
        ),
        ("stalled", "worker startup timed out"),
        ("exit", "exited with exit status: 3"),
    ] {
        let fixture = Fixture::with_timeout(mode, Duration::from_secs(2));
        let err = fixture.request("echo", json!([])).await.unwrap_err();
        assert_eq!(err.code(), CALL_EXECUTION_FAILED_CODE, "{mode}");
        assert!(
            err.message()
                .starts_with("historical era pre-T12 unavailable: ")
                && err.message().ends_with(expected),
            "{mode}: {}",
            err.message()
        );
        let pid = fixture.starts()[0];
        fixture.assert_stopped(pid).await;

        let again = fixture.request("echo", json!([])).await.unwrap_err();
        assert_eq!(again.message(), err.message(), "{mode}");
        assert_eq!(
            fixture.starts().len(),
            1,
            "{mode} respawned during cooldown"
        );
        fixture.workers.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn aborted_startup_resumes_the_same_worker() {
    let fixture = Fixture::new("slow");
    let aborted = tokio::time::timeout(Duration::from_millis(300), fixture.workers.get(0)).await;
    assert!(aborted.is_err());

    fixture.request("echo", json!([])).await.unwrap();
    assert_eq!(fixture.starts().len(), 1);
    fixture.workers.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_during_startup_reaps_the_worker() {
    let fixture = Fixture::new("slow");
    let workers = fixture.workers.clone();
    let startup = tokio::spawn(async move { workers.get(0).await.map(drop) });
    tokio::time::timeout(WAIT, async {
        while fixture.starts().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    tokio::time::timeout(WAIT, fixture.workers.shutdown())
        .await
        .unwrap()
        .unwrap();
    let err = startup.await.unwrap().unwrap_err();
    assert!(
        format!("{err:#}").ends_with("historical workers are shutting down"),
        "{err:#}"
    );
    let pid = fixture.starts()[0];
    assert!(is_reaped(pid));
    assert!(!fixture.secondary(pid).exists());
}

#[tokio::test]
async fn crashed_workers_recover_after_the_cooldown() {
    let fixture = Fixture::new("ok");
    fixture.request("echo", json!([])).await.unwrap();
    let pid = fixture.starts()[0];

    let err = fixture.request("crash", json!([])).await.unwrap_err();
    assert_eq!(err.code(), CALL_EXECUTION_FAILED_CODE);
    assert!(
        err.message().starts_with("era RPC unavailable: "),
        "{}",
        err.message()
    );
    // The connection can close just before the exited child becomes waitable.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let failed = fixture.request("echo", json!([])).await.unwrap_err();
    assert!(
        failed
            .message()
            .starts_with("historical era pre-T12 unavailable: historical era pre-T12 exited with"),
        "{}",
        failed.message()
    );
    fixture.assert_stopped(pid).await;
    let cooling = fixture.request("echo", json!([])).await.unwrap_err();
    assert_eq!(cooling.message(), failed.message());
    assert_eq!(fixture.starts().len(), 1);

    tokio::time::pause();
    tokio::time::advance(FAILURE_COOLDOWN).await;
    tokio::time::resume();
    fixture.request("echo", json!([])).await.unwrap();
    assert_eq!(fixture.starts().len(), 2);
    fixture.workers.shutdown().await.unwrap();
}

#[tokio::test]
async fn subscriptions_relay_notifications_and_hold_the_worker() {
    let fixture = Fixture::new("ok");
    let mut subscription = tokio::time::timeout(
        WAIT,
        fixture
            .workers
            .subscribe(0, RpcParams(json!(["traceChain", "0x0", "0x3"]))),
    )
    .await
    .unwrap()
    .unwrap();
    for block in 1..=3u64 {
        let item = tokio::time::timeout(WAIT, subscription.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(item.get()).unwrap(),
            json!({"block": format!("{block:#x}"), "traces": []})
        );
    }
    let pid = fixture.starts()[0];
    idle_out().await;
    assert_eq!(fixture.ready_handles().await, Some(2));

    drop(subscription);
    tokio::time::timeout(WAIT, async {
        while !fixture.dir.path().join("unsubscribed").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    idle_out().await;
    fixture.assert_stopped(pid).await;
    fixture.workers.shutdown().await.unwrap();
}
