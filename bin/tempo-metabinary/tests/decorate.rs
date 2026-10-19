//! Transport decoration tests: native callbacks are fakes that record what reached them, and
//! frozen eras are served by the fake backend. Block `n` has timestamp `n`.

mod common;

use common::{FakeBackend, hash, hex};
use futures::FutureExt as _;
use jsonrpsee::{
    RpcModule,
    core::server::{ConnectionId, Extensions, MethodCallback, MethodResponse, Methods},
    types::{ErrorObjectOwned, Id, Params},
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempo_metabinary::{
    decorate::{RpcApi, decorate},
    routing::Router,
};
use tokio::sync::mpsc::Receiver;

const WAIT: Duration = Duration::from_secs(10);

/// What a native call callback received.
#[derive(Debug, Clone, PartialEq)]
struct Received {
    id: Id<'static>,
    params: Option<String>,
    conn_id: Option<ConnectionId>,
    max: usize,
    marker: Option<u32>,
}

#[derive(Default)]
struct Natives {
    received: Mutex<Vec<(&'static str, Received)>>,
    trace_filter_calls: AtomicUsize,
    /// `reth_getBlockExecutionOutcome` answers `null` when set.
    missing_outcome: bool,
}

impl Natives {
    fn received(&self) -> Vec<(&'static str, Received)> {
        self.received.lock().unwrap().clone()
    }
}

/// `[{"block": n, "i": 0}, {"block": n, "i": 1}]` for every block in the range.
fn traces(from: u64, to: u64) -> Vec<Value> {
    (from..=to)
        .flat_map(|block| {
            [
                json!({"block": block, "i": 0}),
                json!({"block": block, "i": 1}),
            ]
        })
        .collect()
}

fn filter_bounds(params: &Value) -> (u64, u64) {
    let bound =
        |name: &str| u64::from_str_radix(&params[0][name].as_str().unwrap()[2..], 16).unwrap();
    (bound("fromBlock"), bound("toBlock"))
}

fn native_methods(natives: Arc<Natives>) -> Methods {
    let mut methods = Methods::new();
    let record = |natives: &Arc<Natives>, name, received| {
        natives.received.lock().unwrap().push((name, received));
    };
    {
        let natives = natives.clone();
        methods
            .verify_and_insert(
                "eth_call",
                MethodCallback::Sync(Arc::new(move |id, params, max, ext| {
                    let received = Received {
                        id: id.clone().into_owned(),
                        params: params.as_str().map(str::to_owned),
                        conn_id: None,
                        max,
                        marker: ext.get::<u32>().copied(),
                    };
                    record(&natives, "eth_call", received);
                    MethodResponse::response(
                        id,
                        jsonrpsee::core::server::ResponsePayload::success("native"),
                        max,
                    )
                    .with_extensions(ext)
                })),
            )
            .unwrap();
    }
    for name in [
        "trace_call",
        "trace_filter",
        "reth_getBlockExecutionOutcome",
    ] {
        let natives = natives.clone();
        methods
            .verify_and_insert(
                name,
                MethodCallback::Async(Arc::new(move |id, params, conn_id, max, ext| {
                    let natives = natives.clone();
                    async move {
                        let received = Received {
                            id: id.clone(),
                            params: params.as_str().map(str::to_owned),
                            conn_id: Some(conn_id),
                            max,
                            marker: ext.get::<u32>().copied(),
                        };
                        record(&natives, name, received);
                        let parsed: Value = params.parse().unwrap_or(Value::Null);
                        let result = match name {
                            "trace_filter" => {
                                natives.trace_filter_calls.fetch_add(1, Ordering::SeqCst);
                                let (from, to) = filter_bounds(&parsed);
                                json!(traces(from, to))
                            }
                            "reth_getBlockExecutionOutcome" if natives.missing_outcome => {
                                Value::Null
                            }
                            "reth_getBlockExecutionOutcome" => {
                                json!({"part": parsed, "era": "live"})
                            }
                            _ => json!("native"),
                        };
                        MethodResponse::response(
                            id,
                            jsonrpsee::core::server::ResponsePayload::success(result),
                            max,
                        )
                        .with_extensions(ext)
                    }
                    .boxed()
                })),
            )
            .unwrap();
    }
    let mut module = RpcModule::new(());
    module
        .register_method("eth_blockNumber", |_, _, _| "0x1")
        .unwrap();
    module
        .register_async_method("engine_forkchoiceUpdatedV3", |_, _, _| async { "fcu" })
        .unwrap();
    module
        .register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            |_, pending, _, _| async move {
                pending.accept().await?;
                Ok(())
            },
        )
        .unwrap();
    // Like native `traceChain`: skips empty blocks except the end block, then stays open.
    module
        .register_subscription(
            "debug_subscribe",
            "debug_subscription",
            "debug_unsubscribe",
            |params, pending, _, _| async move {
                let params: Value = params.parse()?;
                let block =
                    |i: usize| u64::from_str_radix(&params[i].as_str().unwrap()[2..], 16).unwrap();
                let (start, end) = (block(1), block(2));
                let sink = pending.accept().await?;
                for number in start + 1..=end {
                    let traces = if number % 2 == 1 {
                        json!([1])
                    } else {
                        json!([])
                    };
                    if number % 2 == 0 && number != end {
                        continue;
                    }
                    let item =
                        json!({"block": hex(number), "hash": hash(number), "traces": traces});
                    sink.send(serde_json::value::to_raw_value(&item)?).await?;
                }
                sink.closed().await;
                Ok(())
            },
        )
        .unwrap();
    methods.merge(module).unwrap();
    methods
}

struct Fixture {
    natives: Arc<Natives>,
    backend: Arc<FakeBackend>,
    original: Methods,
    methods: Methods,
}

impl Fixture {
    fn new(boundaries: Vec<u64>, backend: FakeBackend, natives: Natives, api: RpcApi) -> Self {
        let natives = Arc::new(natives);
        let backend = Arc::new(backend);
        let original = native_methods(natives.clone());
        let router = Arc::new(Router::new(boundaries, 1000, backend.clone()));
        let methods = decorate(original.clone(), router, api).unwrap();
        Self {
            natives,
            backend,
            original,
            methods,
        }
    }

    /// Eras: frozen `0` below timestamp 100, live above.
    fn two_eras() -> Self {
        Self::new(
            vec![100],
            FakeBackend::default(),
            Natives::default(),
            RpcApi::Eth,
        )
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ErrorObjectOwned> {
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let (response, _) = tokio::time::timeout(
            WAIT,
            self.methods.raw_json_request(&request.to_string(), 16),
        )
        .await
        .unwrap()
        .unwrap();
        envelope(response.get())
    }

    async fn subscribe(
        &self,
        params: Value,
    ) -> (Value, Receiver<Box<serde_json::value::RawValue>>) {
        let request =
            json!({"jsonrpc": "2.0", "id": 1, "method": "debug_subscribe", "params": params});
        let (response, rx) = tokio::time::timeout(
            WAIT,
            self.methods.raw_json_request(&request.to_string(), 64),
        )
        .await
        .unwrap()
        .unwrap();
        (envelope(response.get()).unwrap(), rx)
    }

    async fn invoke(
        &self,
        method: &str,
        params: &str,
        conn_id: usize,
        max: usize,
        marker: u32,
    ) -> MethodResponse {
        let mut ext = Extensions::new();
        ext.insert(marker);
        let params = Params::new(Some(params)).into_owned();
        let id = Id::Number(7);
        match self.methods.method(method).unwrap() {
            MethodCallback::Async(callback) => {
                callback(id, params, ConnectionId(conn_id), max, ext).await
            }
            other => panic!("{method} is {other:?}"),
        }
    }
}

fn envelope(json: &str) -> Result<Value, ErrorObjectOwned> {
    let mut response: Value = serde_json::from_str(json).unwrap();
    match response.get("error") {
        Some(error) => Err(serde_json::from_value(error.clone()).unwrap()),
        None => Ok(response["result"].take()),
    }
}

async fn next_notification(rx: &mut Receiver<Box<serde_json::value::RawValue>>) -> Value {
    let item = tokio::time::timeout(WAIT, rx.recv())
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(item.get()).unwrap()
}

fn same_callback(a: &MethodCallback, b: &MethodCallback) -> bool {
    match (a, b) {
        (MethodCallback::Sync(a), MethodCallback::Sync(b)) => Arc::ptr_eq(a, b),
        (MethodCallback::Async(a), MethodCallback::Async(b)) => Arc::ptr_eq(a, b),
        (MethodCallback::Subscription(a), MethodCallback::Subscription(b)) => Arc::ptr_eq(a, b),
        (MethodCallback::Unsubscription(a), MethodCallback::Unsubscription(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

#[tokio::test]
async fn only_execution_callbacks_are_replaced() {
    let fixture = Fixture::two_eras();
    let mut names: Vec<_> = fixture.methods.method_names().collect();
    let mut original: Vec<_> = fixture.original.method_names().collect();
    names.sort_unstable();
    original.sort_unstable();
    assert_eq!(names, original);
    for name in names {
        let replaced = matches!(
            name,
            "eth_call"
                | "trace_call"
                | "trace_filter"
                | "reth_getBlockExecutionOutcome"
                | "debug_subscribe"
                | "debug_unsubscribe"
        );
        assert_eq!(
            !same_callback(
                fixture.methods.method(name).unwrap(),
                fixture.original.method(name).unwrap()
            ),
            replaced,
            "{name}"
        );
    }
}

#[tokio::test]
async fn live_calls_reach_native_unchanged() {
    let fixture = Fixture::two_eras();
    let params = r#"[{"to":null}, "latest"]"#;
    for method in ["eth_call", "trace_call"] {
        let response = fixture.invoke(method, params, 3, 1234, 42).await;
        assert_eq!(response.extensions().get::<u32>(), Some(&42));
        assert_eq!(envelope(response.as_json().get()).unwrap(), json!("native"));
    }
    let expected = |conn_id| Received {
        id: Id::Number(7),
        params: Some(params.to_owned()),
        conn_id,
        max: 1234,
        marker: Some(42),
    };
    assert_eq!(
        fixture.natives.received(),
        [
            ("eth_call", expected(None)),
            ("trace_call", expected(Some(ConnectionId(3))))
        ]
    );
    assert!(fixture.backend.forwarded().is_empty());
}

#[tokio::test]
async fn historical_calls_forward_raw_results() {
    let backend = FakeBackend {
        forward: Box::new(|_, _, params| match params.get(2) {
            None => Ok(r#"{"b": 1,   "a":[ 2 ]}"#.to_owned()),
            Some(_) => Err(ErrorObjectOwned::owned(
                -32000,
                "execution reverted",
                Some("0xdead"),
            )),
        }),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);

    let response = fixture
        .invoke("eth_call", r#"[{}, "0x32"]"#, 0, 1000, 9)
        .await;
    assert_eq!(response.extensions().get::<u32>(), Some(&9));
    assert_eq!(
        response.as_json().get(),
        r#"{"jsonrpc":"2.0","id":7,"result":{"b": 1,   "a":[ 2 ]}}"#
    );
    assert_eq!(
        fixture.backend.forwarded(),
        [(
            0,
            "eth_call".to_owned(),
            json!([{}, {"blockHash": hash(50)}])
        )]
    );

    let oversized = fixture
        .invoke("eth_call", r#"[{}, "0x32"]"#, 0, 10, 9)
        .await;
    assert_eq!(oversized.as_error_code(), Some(-32008));

    let reverted = fixture
        .invoke(
            "eth_call",
            r#"[{}, {"blockNumber": "0x32"}, {"x": 1}]"#,
            0,
            1000,
            9,
        )
        .await;
    assert_eq!(reverted.extensions().get::<u32>(), Some(&9));
    let err = envelope(reverted.as_json().get()).unwrap_err();
    assert_eq!(
        (err.code(), err.message(), err.data().map(|d| d.get())),
        (-32000, "execution reverted", Some(r#""0xdead""#))
    );
    assert!(fixture.natives.received().is_empty());

    let err = fixture
        .call("eth_call", json!([{}, "0x5000"]))
        .await
        .unwrap_err();
    assert_eq!((err.code(), err.message()), (-32001, "unknown block"));
}

#[tokio::test]
async fn engine_eth_call_uses_the_public_selector_name() {
    let fixture = Fixture::new(
        vec![100],
        FakeBackend::default(),
        Natives::default(),
        RpcApi::Engine,
    );
    for (params, expected) in [
        (
            json!({"request": {}, "block_id": "0x32"}),
            json!({"request": {}, "block_number": {"blockHash": hash(50)}}),
        ),
        (
            json!({"request": {}, "blockId": "0x32", "block_number": "0x99"}),
            json!({"request": {}, "blockNumber": {"blockHash": hash(50)}}),
        ),
        (
            json!({"request": {}, "block_id": "0x32", "blockNumber": "0x3e8", "block_overrides": {"time": "0x3e8"}}),
            json!({"request": {}, "block_number": {"blockHash": hash(50)}, "block_overrides": {"time": "0x3e8"}}),
        ),
        (json!([{}, "0x32"]), json!([{}, {"blockHash": hash(50)}])),
    ] {
        fixture.call("eth_call", params).await.unwrap();
        assert_eq!(
            fixture.backend.forwarded.lock().unwrap().pop().unwrap(),
            (0, "eth_call".to_owned(), expected)
        );
    }

    let pending = r#"{"request":{},"block_id":"pending"}"#;
    let response = fixture.invoke("eth_call", pending, 0, 100, 1).await;
    assert_eq!(envelope(response.as_json().get()).unwrap(), json!("native"));
    assert_eq!(
        fixture.natives.received()[0].1.params.as_deref(),
        Some(pending)
    );
}

fn frozen_traces() -> Box<common::ForwardFn> {
    Box::new(|_, method, params| {
        assert_eq!(method, "trace_filter");
        assert!(params[0].get("after").is_none() && params[0].get("count").is_none());
        let (from, to) = filter_bounds(params);
        Ok(json!(traces(from, to)).to_string())
    })
}

#[tokio::test]
async fn split_trace_filters_paginate_like_one_call() {
    // Blocks 95..=104 hold 20 traces; 95..=99 are frozen.
    let all = traces(95, 104);
    let backend = FakeBackend {
        forward: frozen_traces(),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);
    let filter = |pagination: Value| {
        let mut filter = json!({"fromBlock": "0x5f", "toBlock": "0x68", "mode": "union"});
        filter
            .as_object_mut()
            .unwrap()
            .extend(pagination.as_object().unwrap().clone());
        json!([filter])
    };

    assert_eq!(
        fixture
            .call("trace_filter", filter(json!({})))
            .await
            .unwrap(),
        json!(all)
    );
    assert_eq!(
        fixture
            .call("trace_filter", filter(json!({"after": 12, "count": 3})))
            .await
            .unwrap(),
        json!(all[12..15])
    );
    assert_eq!(
        fixture
            .call("trace_filter", filter(json!({"after": 20})))
            .await
            .unwrap(),
        json!([])
    );
    assert_eq!(fixture.natives.trace_filter_calls.load(Ordering::SeqCst), 3);

    // A full page from the frozen segment never calls the live tail.
    assert_eq!(
        fixture
            .call("trace_filter", filter(json!({"after": 3, "count": 4})))
            .await
            .unwrap(),
        json!(all[3..7])
    );
    assert_eq!(fixture.natives.trace_filter_calls.load(Ordering::SeqCst), 3);

    // The merged response is limited by the caller's size limit.
    let response = fixture
        .invoke("trace_filter", &filter(json!({})).to_string(), 0, 100, 1)
        .await;
    assert_eq!(response.as_error_code(), Some(-32008));
}

#[tokio::test]
async fn split_trace_filters_stop_before_frozen_tails_and_propagate_errors() {
    let backend = FakeBackend {
        forward: frozen_traces(),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100, 200], backend, Natives::default(), RpcApi::Eth);
    let result = fixture
        .call(
            "trace_filter",
            json!([{"fromBlock": "0x5f", "toBlock": "0x68", "count": 2}]),
        )
        .await
        .unwrap();
    assert_eq!(result, json!(traces(95, 95)));
    assert_eq!(fixture.backend.forwarded().len(), 1);

    let backend = FakeBackend {
        forward: Box::new(|_, _, _| {
            Err(ErrorObjectOwned::owned(
                -32000,
                "tracing failed",
                None::<()>,
            ))
        }),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);
    let err = fixture
        .call(
            "trace_filter",
            json!([{"fromBlock": "0x5f", "toBlock": "0x68"}]),
        )
        .await
        .unwrap_err();
    assert_eq!((err.code(), err.message()), (-32000, "tracing failed"));
    assert_eq!(fixture.natives.trace_filter_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn split_execution_outcomes_merge_in_block_order() {
    let frozen = || -> Box<common::ForwardFn> {
        Box::new(|_, _, params| Ok(json!({"part": params, "era": "frozen"}).to_string()))
    };
    let request = json!(["0x5f", "0xa"]);
    let frozen_part = json!({"part": ["0x5f", "0x5"], "era": "frozen"});
    let live_part = json!({"part": ["0x64", "0x5"], "era": "live"});

    let backend = FakeBackend {
        forward: frozen(),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);
    assert_eq!(
        fixture
            .call("reth_getBlockExecutionOutcome", request.clone())
            .await
            .unwrap(),
        json!({"merged": [frozen_part, live_part]})
    );

    // A missing tail truncates the merge.
    let backend = FakeBackend {
        forward: frozen(),
        ..Default::default()
    };
    let natives = Natives {
        missing_outcome: true,
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, natives, RpcApi::Eth);
    assert_eq!(
        fixture
            .call("reth_getBlockExecutionOutcome", request.clone())
            .await
            .unwrap(),
        json!({"merged": [frozen_part]})
    );

    // A missing first part is `null`.
    let backend = FakeBackend {
        forward: Box::new(|_, _, _| Ok("null".to_owned())),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);
    assert_eq!(
        fixture
            .call("reth_getBlockExecutionOutcome", request)
            .await
            .unwrap(),
        Value::Null
    );
    assert!(fixture.backend.merged.lock().unwrap().is_empty());
    assert!(fixture.natives.received().is_empty());
}

#[tokio::test]
async fn engine_callbacks_stay_native() {
    let fixture = Fixture::new(
        vec![100],
        FakeBackend::default(),
        Natives::default(),
        RpcApi::Engine,
    );
    assert!(same_callback(
        fixture
            .methods
            .method("engine_forkchoiceUpdatedV3")
            .unwrap(),
        fixture
            .original
            .method("engine_forkchoiceUpdatedV3")
            .unwrap()
    ));
    assert_eq!(
        fixture
            .call("engine_forkchoiceUpdatedV3", json!([]))
            .await
            .unwrap(),
        json!("fcu")
    );
}

#[tokio::test]
async fn live_trace_chains_delegate_with_the_allocated_id() {
    let fixture = Fixture::two_eras();
    let (id, mut rx) = fixture
        .subscribe(json!(["traceChain", "0x3e0", "0x3e3"]))
        .await;
    for block in [993u64, 995] {
        let notification = next_notification(&mut rx).await;
        assert_eq!(notification["params"]["subscription"], id);
        assert_eq!(notification["params"]["result"]["block"], hex(block));
    }
    assert!(fixture.backend.subscribed.lock().unwrap().is_empty());
}

fn frozen_chain() -> FakeBackend {
    FakeBackend {
        notifications: [(
            0,
            vec![
                json!({"block": hex(91), "traces": [1]}),
                json!({"block": hex(99), "traces": []}),
            ],
        )]
        .into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn relayed_trace_chains_stream_both_eras_in_order() {
    let fixture = Fixture::new(vec![100], frozen_chain(), Natives::default(), RpcApi::Eth);
    let (id, mut rx) = fixture
        .subscribe(json!(["traceChain", "0x5a", "0x6e"]))
        .await;
    // The frozen end block's empty notification is dropped; the final end block's is kept.
    let mut blocks = Vec::new();
    for _ in 0..7 {
        let notification = next_notification(&mut rx).await;
        assert_eq!(notification["method"], "debug_subscription");
        assert_eq!(notification["params"]["subscription"], id);
        blocks.push(notification["params"]["result"]["block"].clone());
    }
    assert_eq!(blocks, [91, 101, 103, 105, 107, 109, 110].map(hex));
    assert_eq!(
        *fixture.backend.subscribed.lock().unwrap(),
        [(0, json!(["traceChain", "0x5a", "0x63"]))]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err(),
        "the finished relay stays open without notifications"
    );
}

#[tokio::test]
async fn relays_stop_when_a_segment_ends_early() {
    let backend = FakeBackend {
        notifications: [(0, vec![json!({"block": hex(91), "traces": [1]})])].into(),
        end_streams: true,
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);
    let (_, mut rx) = fixture
        .subscribe(json!(["traceChain", "0x5a", "0x6e"]))
        .await;
    assert_eq!(
        next_notification(&mut rx).await["params"]["result"]["block"],
        hex(91)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err()
    );
    assert_eq!(fixture.backend.subscribed.lock().unwrap().len(), 1);
}

async fn wait_for_closed_streams(backend: &FakeBackend) {
    tokio::time::timeout(WAIT, async {
        while backend.open_streams.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("upstream subscription was not dropped");
}

#[tokio::test]
async fn relays_end_on_unsubscribe_or_disconnect() {
    // Frozen-only relays keep their upstream open until the client leaves.
    let backend = FakeBackend {
        notifications: [(0, vec![json!({"block": hex(15), "traces": [1]})])].into(),
        ..Default::default()
    };
    let fixture = Fixture::new(vec![100], backend, Natives::default(), RpcApi::Eth);
    let params = json!(["traceChain", "0xa", "0x14"]);

    let (id, mut rx) = fixture.subscribe(params.clone()).await;
    next_notification(&mut rx).await;
    assert_eq!(fixture.backend.open_streams.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .call("debug_unsubscribe", json!([id]))
            .await
            .unwrap(),
        json!(true)
    );
    wait_for_closed_streams(&fixture.backend).await;

    let (_, mut rx) = fixture.subscribe(params).await;
    next_notification(&mut rx).await;
    drop(rx);
    wait_for_closed_streams(&fixture.backend).await;

    // Unknown subscriptions are the native callback's.
    let unknown = json!(["0x1234"]);
    let request =
        json!({"jsonrpc": "2.0", "id": 1, "method": "debug_unsubscribe", "params": unknown});
    let (native, _) = fixture
        .original
        .raw_json_request(&request.to_string(), 1)
        .await
        .unwrap();
    assert_eq!(
        fixture.call("debug_unsubscribe", unknown).await,
        envelope(native.get())
    );
}
