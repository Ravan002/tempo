//! Routing policy tests against a fake chain where block `n` has timestamp `n` and eras end at
//! timestamps 100 and 200, so the live era is 2.

mod common;

use common::{FakeBackend, hash, hex};
use jsonrpsee::core::RpcResult;
use serde_json::{Value, json};
use std::sync::Arc;
use tempo_metabinary::routing::{
    Merge, RelaySegment, Route, Router, RpcParams, first_block_at, is_execution_method,
};

const LIVE: usize = 2;
const TX: Value = Value::Null;

fn router_with(boundaries: Vec<u64>, backend: FakeBackend) -> (Router, Arc<FakeBackend>) {
    let backend = Arc::new(backend);
    (Router::new(boundaries, 100, backend.clone()), backend)
}

fn default_router() -> (Router, Arc<FakeBackend>) {
    router_with(vec![100, 200], FakeBackend::default())
}

async fn route(method: &str, params: Value) -> RpcResult<Route> {
    default_router().0.route(method, RpcParams(params)).await
}

fn era(era: usize, params: Value) -> Route {
    Route::Era(era, RpcParams(params))
}

fn named(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
    )
}

fn pinned(number: u64) -> Value {
    json!({ "blockHash": hash(number) })
}

#[tokio::test]
async fn block_methods_route_by_their_selector() {
    // (method, selector index, names, number_only)
    let cases: &[(&str, usize, &[&str], bool)] = &[
        ("eth_call", 1, &["block_number", "blockNumber"], false),
        (
            "eth_estimateGas",
            1,
            &["block_number", "blockNumber"],
            false,
        ),
        (
            "eth_createAccessList",
            1,
            &["block_number", "blockNumber"],
            false,
        ),
        ("debug_traceCall", 1, &["block_id", "blockId"], false),
        ("trace_call", 2, &["block_id", "blockId"], false),
        ("trace_rawTransaction", 2, &["block_id", "blockId"], false),
        ("trace_callMany", 1, &["block_id", "blockId"], false),
        ("debug_traceBlockByNumber", 0, &["block"], true),
        ("debug_traceBlockByHash", 0, &["block"], false),
        ("eth_getBlockAccessListByBlockHash", 0, &["hash"], false),
        ("eth_getBlockAccessListByBlockNumber", 0, &["number"], true),
        ("eth_getBlockAccessList", 0, &["block_id", "blockId"], false),
        (
            "eth_getBlockAccessListRaw",
            0,
            &["block", "block_id", "blockId"],
            false,
        ),
        (
            "debug_getRawBlockAccessList",
            0,
            &["block", "block_id", "blockId"],
            false,
        ),
        ("debug_executionWitnessByBlockHash", 0, &["hash"], false),
        (
            "debug_intermediateRoots",
            0,
            &["block_hash", "blockHash"],
            false,
        ),
        ("debug_executionWitness", 0, &["block"], false),
        ("debug_accountAt", 0, &["block_id", "blockId"], false),
        ("debug_accountInfoAt", 0, &["block_id", "blockId"], false),
        ("trace_block", 0, &["block_id", "blockId"], false),
        (
            "trace_replayBlockTransactions",
            0,
            &["block_id", "blockId"],
            false,
        ),
        ("trace_blockOpcodeGas", 0, &["block_id", "blockId"], false),
    ];
    for (method, index, names, number_only) in cases {
        let expected = if *number_only { hex(150) } else { pinned(150) };

        let mut positional = vec![TX; *index];
        positional.push(hex(150));
        let mut pinned_positional = vec![TX; *index];
        pinned_positional.push(expected.clone());
        assert_eq!(
            route(method, json!(positional)).await.unwrap(),
            era(1, json!(pinned_positional)),
            "{method}"
        );

        for name in *names {
            let pin = if *number_only { hex(50) } else { pinned(50) };
            assert_eq!(
                route(method, named(&[("other", json!(1)), (name, hex(50))]))
                    .await
                    .unwrap(),
                era(0, named(&[("other", json!(1)), (name, pin)])),
                "{method} {name}"
            );
        }
    }
}

#[tokio::test]
async fn selectors_pin_hashes_verbatim_and_default_by_method() {
    let hash_selector = json!(hash(50));
    assert_eq!(
        route("eth_call", json!([TX, hash_selector])).await.unwrap(),
        era(0, json!([TX, hash_selector]))
    );
    let canonical = json!({"blockHash": hash(50), "requireCanonical": true});
    assert_eq!(
        route("eth_call", json!([TX, canonical])).await.unwrap(),
        era(0, json!([TX, canonical]))
    );
    assert_eq!(
        route("eth_call", json!([TX, {"blockNumber": "0x32"}]))
            .await
            .unwrap(),
        era(0, json!([TX, pinned(50)]))
    );
    assert_eq!(
        route("debug_traceBlockByNumber", json!(["earliest"]))
            .await
            .unwrap(),
        era(0, json!(["0x0"]))
    );

    // Missing selectors: `latest`, except `pending` for gas estimation.
    assert_eq!(
        route("eth_call", json!([TX])).await.unwrap(),
        era(LIVE, json!([TX, pinned(1000)]))
    );
    let (router, backend) = default_router();
    assert_eq!(
        router
            .route("eth_estimateGas", RpcParams(json!([TX])))
            .await
            .unwrap(),
        era(LIVE, json!([TX]))
    );
    assert_eq!(
        router
            .route(
                "eth_call",
                RpcParams(json!({"request": TX, "blockNumber": "pending"}))
            )
            .await
            .unwrap(),
        era(LIVE, json!({"request": TX, "blockNumber": "pending"}))
    );
    assert_eq!(backend.resolutions(), 0);
}

#[tokio::test]
async fn params_must_be_arrays_or_objects() {
    let err = route("eth_call", json!("0x1")).await.unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (-32602, "params must be an array or an object")
    );
}

#[tokio::test]
async fn block_overrides_never_change_the_era() {
    let live_time = json!({"time": "0x3e8"});
    for (method, params) in [
        ("eth_call", json!([TX, "0x32", null, live_time])),
        (
            "debug_traceCall",
            json!([TX, "0x32", {"blockOverrides": live_time}]),
        ),
        (
            "trace_call",
            json!([TX, ["trace"], "0x32", null, live_time]),
        ),
        (
            "eth_callMany",
            json!([[{"transactions": [], "blockOverride": live_time}], {"blockNumber": "0x32"}]),
        ),
        (
            "eth_callBundle",
            json!([{"txs": [], "stateBlockNumber": "0x32", "timestamp": 1000}]),
        ),
    ] {
        assert!(
            matches!(route(method, params).await.unwrap(), Route::Era(0, _)),
            "{method}"
        );
    }

    let historical_time = json!({"time": "0x32"});
    for (method, params) in [
        ("eth_call", json!([TX, "latest", null, historical_time])),
        (
            "eth_callMany",
            json!([[{"transactions": [], "blockOverride": historical_time}], {"blockNumber": "latest"}]),
        ),
        (
            "eth_callBundle",
            json!([{"txs": [], "stateBlockNumber": "latest", "timestamp": 50}]),
        ),
    ] {
        assert!(
            matches!(route(method, params).await.unwrap(), Route::Era(LIVE, _)),
            "{method}"
        );
    }
}

#[tokio::test]
async fn base_block_methods_pin_their_base() {
    assert_eq!(
        route(
            "eth_callBundle",
            json!([{"txs": [], "stateBlockNumber": "latest"}])
        )
        .await
        .unwrap(),
        era(LIVE, json!([{"txs": [], "stateBlockNumber": hex(1000)}]))
    );
    assert_eq!(
        route(
            "debug_traceCallMany",
            json!({"bundles": [], "stateContext": {"blockNumber": "0x96", "transactionIndex": 1}})
        )
        .await
        .unwrap(),
        era(
            1,
            json!({"bundles": [], "stateContext": {"blockNumber": pinned(150), "transactionIndex": 1}})
        )
    );
    for params in [
        json!([[]]),
        json!([[], {"blockNumber": "pending"}]),
        json!([[], {"transactionIndex": 1}]),
    ] {
        assert_eq!(
            route("eth_callMany", params.clone()).await.unwrap(),
            era(LIVE, params)
        );
    }
}

#[tokio::test]
async fn fee_history_routes_by_its_newest_block() {
    assert_eq!(
        route("eth_feeHistory", json!(["0x4", "0x96", [25]]))
            .await
            .unwrap(),
        era(1, json!(["0x4", "0x96", [25]]))
    );
    assert_eq!(
        route(
            "eth_feeHistory",
            json!({"blockCount": 4, "newestBlock": "pending"})
        )
        .await
        .unwrap(),
        era(LIVE, json!({"blockCount": 4, "newestBlock": hex(1000)}))
    );
    let (router, backend) = default_router();
    for params in [
        json!(["0x0", "0x32"]),
        json!(["bogus", "0x32"]),
        json!(["0x4", {"blockHash": hash(50)}]),
        json!(["0x4"]),
    ] {
        assert_eq!(
            router
                .route("eth_feeHistory", RpcParams(params.clone()))
                .await
                .unwrap(),
            era(LIVE, params)
        );
    }
    assert_eq!(backend.resolutions(), 0);
}

#[tokio::test]
async fn transactions_route_by_their_block() {
    let historical = hash(9000);
    let backend = FakeBackend {
        transactions: [(historical, 150)].into(),
        ..Default::default()
    };
    let (router, _) = router_with(vec![100, 200], backend);
    for method in [
        "debug_traceTransaction",
        "trace_transaction",
        "trace_get",
        "trace_replayTransaction",
        "trace_transactionOpcodeGas",
        "ots_getInternalOperations",
        "ots_getTransactionError",
        "ots_traceTransaction",
    ] {
        assert!(matches!(
            router
                .route(method, RpcParams(json!([historical])))
                .await
                .unwrap(),
            Route::Era(1, _)
        ));
        for name in ["tx_hash", "txHash", "hash", "transaction"] {
            assert!(matches!(
                router
                    .route(method, RpcParams(named(&[(name, json!(historical))])))
                    .await
                    .unwrap(),
                Route::Era(1, _)
            ));
        }
        // Pooled or unknown transactions run live.
        assert!(matches!(
            router
                .route(method, RpcParams(json!([hash(1)])))
                .await
                .unwrap(),
            Route::Era(LIVE, _)
        ));
        let err = router
            .route(method, RpcParams(json!([])))
            .await
            .unwrap_err();
        assert_eq!(err.code(), -32602);
    }
}

#[tokio::test]
async fn simulations_route_by_generated_block_times() {
    let calls = |times: &[u64]| {
        json!({"blockStateCalls": times
            .iter()
            .map(|time| json!({"blockOverrides": {"time": hex(*time)}}))
            .chain([json!({})])
            .collect::<Vec<_>>()})
    };
    // No explicit times: the base era.
    assert_eq!(
        route("eth_simulateV1", json!([calls(&[]), "0x32"]))
            .await
            .unwrap(),
        era(0, json!([calls(&[]), pinned(50)]))
    );
    // Historical base with live times.
    assert!(matches!(
        route("eth_simulateV1", json!([calls(&[900, 950]), "0x32"]))
            .await
            .unwrap(),
        Route::Era(LIVE, _)
    ));
    // Times older than the base use the base era.
    assert!(matches!(
        route("eth_simulateV1", json!([calls(&[50]), "0x96"]))
            .await
            .unwrap(),
        Route::Era(1, _)
    ));
    let err = route("eth_simulateV1", json!([calls(&[50, 150]), "0x32"]))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (-32004, "simulated blocks span multiple eras")
    );
    for base in [json!("pending"), Value::Null] {
        let params = json!({"payload": calls(&[]), "block": base});
        assert_eq!(
            route("tempo_simulateV1", params.clone()).await.unwrap(),
            era(LIVE, params)
        );
    }
    assert_eq!(
        route(
            "tempo_simulateV1",
            json!({"payload": calls(&[]), "block": "0x96"})
        )
        .await
        .unwrap(),
        era(1, json!({"payload": calls(&[]), "block": pinned(150)}))
    );
}

#[tokio::test]
async fn sim_bundles_route_by_override_time_then_parent() {
    let bundle = json!({"bundle": []});
    assert_eq!(
        route("mev_simBundle", json!([bundle, {"parentBlock": "0x32"}]))
            .await
            .unwrap(),
        era(0, json!([bundle, {"parentBlock": pinned(50)}]))
    );
    assert_eq!(
        route(
            "mev_simBundle",
            json!([bundle, {"parentBlock": "0x32", "timestamp": 150}])
        )
        .await
        .unwrap(),
        era(
            1,
            json!([bundle, {"parentBlock": pinned(50), "timestamp": 150}])
        )
    );
    assert_eq!(
        route("mev_simBundle", json!({"bundle": bundle}))
            .await
            .unwrap(),
        era(
            LIVE,
            json!({"bundle": bundle, "sim_overrides": {"parentBlock": pinned(1000)}})
        )
    );
    let pending = json!([bundle, {"parentBlock": "pending"}]);
    assert_eq!(
        route("mev_simBundle", pending.clone()).await.unwrap(),
        era(LIVE, pending)
    );
}

#[tokio::test]
async fn execution_outcomes_split_at_boundaries() {
    assert_eq!(
        route("reth_getBlockExecutionOutcome", json!(["0x32", "0x2"]))
            .await
            .unwrap(),
        era(0, json!([pinned(50), "0x2"]))
    );
    assert_eq!(
        route(
            "reth_getBlockExecutionOutcome",
            json!({"blockId": "0x5f", "count": 10})
        )
        .await
        .unwrap(),
        Route::Split {
            segments: vec![
                (0, RpcParams(json!({"blockId": "0x5f", "count": "0x5"}))),
                (1, RpcParams(json!({"blockId": "0x64", "count": "0x5"}))),
            ],
            merge: Merge::ExecutionOutcome,
        }
    );
    // A hash re-resolves by canonical height.
    assert_eq!(
        route("reth_getBlockExecutionOutcome", json!([hash(95), "0xa"]))
            .await
            .unwrap(),
        route("reth_getBlockExecutionOutcome", json!(["0x5f", "0xa"]))
            .await
            .unwrap(),
    );

    // Clamped at the head.
    let (router, _) = router_with(vec![100, 995], FakeBackend::default());
    assert_eq!(
        router
            .route(
                "reth_getBlockExecutionOutcome",
                RpcParams(json!(["0x3e0", "0x80"]))
            )
            .await
            .unwrap(),
        Route::Split {
            segments: vec![
                (1, RpcParams(json!(["0x3e0", "0x3"]))),
                (2, RpcParams(json!(["0x3e3", "0x6"]))),
            ],
            merge: Merge::ExecutionOutcome,
        }
    );

    for params in [json!(["0x0"]), json!(["pending", 3])] {
        assert_eq!(
            route("reth_getBlockExecutionOutcome", params.clone())
                .await
                .unwrap(),
            era(LIVE, params)
        );
    }
    for count in [json!(0), json!("0x81")] {
        let err = route("reth_getBlockExecutionOutcome", json!(["0x1", count]))
            .await
            .unwrap_err();
        assert_eq!(
            (err.code(), err.message()),
            (-32602, "block count must be between 1 and 128")
        );
    }
}

#[tokio::test]
async fn trace_filters_split_at_boundaries() {
    let filter = json!({
        "fromBlock": "0x5a",
        "toBlock": "0x6e",
        "fromAddress": ["0x0000000000000000000000000000000000000001"],
        "mode": "union",
        "after": 2,
        "count": "0x3",
    });
    let segment = |from: u64, to: u64| {
        let mut filter = filter.clone();
        filter["fromBlock"] = hex(from);
        filter["toBlock"] = hex(to);
        let filter = filter.as_object_mut().unwrap();
        filter.remove("after");
        filter.remove("count");
        RpcParams(json!([filter]))
    };
    assert_eq!(
        route("trace_filter", json!([filter])).await.unwrap(),
        Route::Split {
            segments: vec![(0, segment(90, 99)), (1, segment(100, 110))],
            merge: Merge::TraceFilter {
                after: Some(2),
                count: Some(3),
            },
        }
    );

    // Two boundaries: three eras.
    let mut three = filter.clone();
    three["fromBlock"] = hex(150);
    three["toBlock"] = hex(210);
    let (router, _) = router_with(vec![100, 160, 200], FakeBackend::default());
    let Route::Split { segments, .. } = router
        .route("trace_filter", RpcParams(json!([three])))
        .await
        .unwrap()
    else {
        panic!("expected a split")
    };
    let bounds: Vec<_> = segments
        .iter()
        .map(|(era, params)| {
            (
                *era,
                params.0[0]["fromBlock"].clone(),
                params.0[0]["toBlock"].clone(),
            )
        })
        .collect();
    assert_eq!(
        bounds,
        [
            (1, hex(150), hex(159)),
            (2, hex(160), hex(199)),
            (3, hex(200), hex(210))
        ]
    );

    // One era keeps pagination and pins both bounds.
    assert_eq!(
        route(
            "trace_filter",
            json!([{"fromBlock": "0x1", "toBlock": "0x2", "after": 1}])
        )
        .await
        .unwrap(),
        era(
            0,
            json!([{"fromBlock": "0x1", "toBlock": "0x2", "after": 1}])
        )
    );
    let (router, backend) = default_router();
    assert_eq!(
        router
            .route("trace_filter", RpcParams(json!([{"toBlock": null}])))
            .await
            .unwrap(),
        era(
            LIVE,
            json!([{"fromBlock": hex(1000), "toBlock": hex(1000)}])
        )
    );
    assert_eq!(backend.resolutions(), 1);

    let err = route(
        "trace_filter",
        json!([{"fromBlock": "0x6e", "toBlock": "0x5a"}]),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (
            -32602,
            "invalid parameters: fromBlock cannot be greater than toBlock"
        )
    );
    let err = route(
        "trace_filter",
        json!([{"fromBlock": "0x0", "toBlock": "0x65"}]),
    )
    .await
    .unwrap_err();
    assert_eq!(
        (err.code(), err.message()),
        (
            -32602,
            "Block range too large; currently limited to 100 blocks"
        )
    );
}

#[tokio::test]
async fn split_points_follow_era_selection() {
    // Blocks `n` at timestamp `3n`: the boundary 100 falls between blocks 33 and 34, and the era
    // ending at 101 holds no block at all.
    let backend = FakeBackend {
        timestamp: |number| 3 * number,
        ..Default::default()
    };
    let (router, _) = router_with(vec![100, 101], backend);
    let Route::Split { segments, .. } = router
        .route(
            "trace_filter",
            RpcParams(json!([{"fromBlock": "0x1e", "toBlock": "0x28"}])),
        )
        .await
        .unwrap()
    else {
        panic!("expected a split")
    };
    assert_eq!(
        segments
            .iter()
            .map(|(era, params)| (*era, params.0[0]["fromBlock"].clone()))
            .collect::<Vec<_>>(),
        [(0, hex(30)), (2, hex(34))]
    );

    // Boundaries at the first and last block of the range.
    let (router, _) = default_router();
    for (from, to, expected) in [
        (99, 100, vec![(0, 99, 99), (1, 100, 100)]),
        (100, 200, vec![(1, 100, 199), (2, 200, 200)]),
    ] {
        let Route::Split { segments, .. } = router
            .route(
                "trace_filter",
                RpcParams(json!([{"fromBlock": hex(from), "toBlock": hex(to)}])),
            )
            .await
            .unwrap()
        else {
            panic!("expected a split")
        };
        let bounds: Vec<_> = segments
            .iter()
            .map(|(era, params)| {
                let bound = |name: &str| {
                    u64::from_str_radix(&params.0[0][name].as_str().unwrap()[2..], 16).unwrap()
                };
                (*era, bound("fromBlock"), bound("toBlock"))
            })
            .collect();
        assert_eq!(bounds, expected);
    }

    // Logarithmic header reads.
    let backend = FakeBackend {
        head: 1 << 20,
        ..Default::default()
    };
    let backend = Arc::new(backend);
    let router = Router::new(vec![1 << 19], u64::MAX, backend.clone());
    router
        .route(
            "trace_filter",
            RpcParams(json!([{"fromBlock": "0x0", "toBlock": hex(1 << 20)}])),
        )
        .await
        .unwrap();
    assert!(backend.resolutions() <= 2 + 21, "{}", backend.resolutions());
}

#[tokio::test]
async fn first_block_at_is_a_binary_search() {
    let timestamp = async |number: u64| Ok::<_, ()>(number * 10);
    assert_eq!(first_block_at(0, 10, 0, timestamp).await, Ok(0));
    assert_eq!(first_block_at(0, 10, 41, timestamp).await, Ok(5));
    assert_eq!(first_block_at(0, 10, 50, timestamp).await, Ok(5));
    assert_eq!(first_block_at(3, 10, 0, timestamp).await, Ok(3));
    assert_eq!(first_block_at(0, 10, 1000, timestamp).await, Ok(10));
}

#[tokio::test]
async fn trace_chain_relays_historical_segments() {
    let params = json!(["traceChain", "0x5a", "0x6e", {"tracer": "callTracer"}]);
    let segment = |era, start: u64, end: u64, is_last| RelaySegment {
        era,
        params: RpcParams(json!(["traceChain", hex(start), hex(end), {"tracer": "callTracer"}])),
        last_block: end,
        is_last,
    };
    assert_eq!(
        route("debug_subscribe", params).await.unwrap(),
        Route::Relay {
            segments: vec![segment(0, 90, 99, false), segment(1, 99, 110, true)],
        }
    );
    assert_eq!(
        route(
            "debug_subscribe",
            json!(["traceChain", "0xa", "0x14", null])
        )
        .await
        .unwrap(),
        Route::Relay {
            segments: vec![RelaySegment {
                era: 0,
                params: RpcParams(json!(["traceChain", "0xa", "0x14", null])),
                last_block: 20,
                is_last: true,
            }],
        }
    );
    assert!(matches!(
        route(
            "debug_subscribe",
            json!({"subscription": "traceChain", "startExclusive": "0x5a", "endInclusive": "0xc8"})
        )
        .await
        .unwrap(),
        Route::Relay { segments } if segments.len() == 3
    ));

    // Live-only, empty, and other subscriptions stay native and untouched.
    for params in [
        json!(["traceChain", "0x3e0", "0x3e8"]),
        json!(["traceChain", "0x6e", "0x5a"]),
        json!(["traceChain", "0x5a", "0x5a"]),
        json!(["newHeads"]),
    ] {
        assert_eq!(
            route("debug_subscribe", params.clone()).await.unwrap(),
            era(LIVE, params)
        );
    }
}

#[tokio::test]
async fn raw_blocks_route_by_their_header() {
    assert!(matches!(
        route("debug_traceBlock", json!(["0x96"])).await.unwrap(),
        Route::Era(1, _)
    ));
}

#[tokio::test]
async fn unknown_methods_fail_closed() {
    for method in [
        "testing_buildBlockV1",
        "flashbots_validateBuilderSubmissionV3",
        "foo_bar",
    ] {
        let err = route(method, json!([])).await.unwrap_err();
        assert_eq!(
            (err.code(), err.message().to_owned()),
            (-32004, format!("{method} has no era routing policy"))
        );
        assert!(is_execution_method(method));
    }
    for method in [
        "eth_getBalance",
        "eth_getLogs",
        "engine_newPayloadV4",
        "reth_newPayload",
        "consensus_getFinalization",
        "tempo_forkSchedule",
        "debug_getRawBlock",
        "ots_getBlockDetails",
        "debug_subscribe",
    ] {
        assert!(!is_execution_method(method), "{method}");
    }
}
