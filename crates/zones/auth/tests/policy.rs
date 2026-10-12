use alloy_primitives::{Address, B256, Bytes, b256, hex};
use std::collections::BTreeSet;
use zone_auth::*;

const NOW: u64 = 1_700_000_000;
fn a(byte: u8) -> Address {
    Address::repeat_byte(byte)
}
fn domain() -> Domain {
    Domain {
        tempo_chain_id: 42431,
        portal: a(0x11),
        zone_id: 42,
        zone_chain_id: 1337,
    }
}
fn scopes(values: &[Scope]) -> BTreeSet<Scope> {
    values.iter().copied().collect()
}
fn token() -> TokenClaims {
    TokenClaims {
        domain: domain(),
        principal: a(0x22),
        kind: CredentialKind::Client,
        generation: 7,
        token_id: B256::repeat_byte(0x33),
        label: "audit".into(),
        issued_at: NOW,
        expires_at: NOW + 600,
    }
}
fn op(
    client: Address,
    seq: u64,
    generation: u64,
    signer: Address,
    signer_generation: u64,
    change: Change,
) -> AccessOp {
    AccessOp {
        domain: domain(),
        client,
        seq,
        generation,
        signer,
        signer_generation,
        change,
        issued_at: NOW,
        expires_at: NOW + 600,
    }
}
fn admit(client: Address, scopes: &[Scope]) -> AccessOp {
    op(
        client,
        1,
        0,
        a(0x66),
        0,
        Change::Admit {
            name: "auditor".into(),
            scopes: self::scopes(scopes),
            accounts: AccountSet::All,
        },
    )
}
fn principal(client: Address, generation: u64) -> Principal {
    Principal::Client {
        address: client,
        generation,
        token_id: B256::repeat_byte(0x77),
        label: "audit".into(),
    }
}

#[test]
fn canonical_vectors_generated_by_independent_python_encoder() {
    assert_eq!(
        token().digest(),
        b256!("0d210d99f68d9993066e081a8405aca930f16b2a93668e4cfd58c976e9439e79")
    );
    let signed = op(
        a(0x22),
        1,
        0,
        a(0x66),
        0,
        Change::Admit {
            name: "auditor".into(),
            scopes: scopes(&[Scope::RpcRead, Scope::IndexerRead]),
            accounts: AccountSet::Listed([a(0x44), a(0x55)].into_iter().collect()),
        },
    );
    assert_eq!(
        signed.digest(),
        b256!("771b6eed948871e6228276b15c7ed88c638d21a2be6bde7202d557e061791101")
    );
    let baseline = signed.digest();
    let mut variants = vec![];
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut changed = signed.clone();
            changed.$field = $value;
            variants.push(changed);
        }};
    }
    changed!(client, a(0x23));
    changed!(seq, 2);
    changed!(generation, 1);
    changed!(signer, a(0x67));
    changed!(signer_generation, 1);
    changed!(issued_at, NOW + 1);
    changed!(expires_at, NOW + 599);
    changed!(change, Change::Remove);
    for mut changed in variants {
        assert_ne!(changed.digest(), baseline);
        changed.domain.portal = a(0x12);
        assert_ne!(changed.digest(), baseline);
    }
    for mutate in [0, 1, 2, 3] {
        let mut changed = token();
        match mutate {
            0 => changed.domain.tempo_chain_id += 1,
            1 => changed.domain.zone_chain_id += 1,
            2 => changed.domain.zone_id += 1,
            _ => changed.domain.portal = a(0x12),
        }
        assert_ne!(changed.digest(), token().digest());
    }
}

#[test]
fn legacy_bytes_and_digest_are_preserved() {
    let mut bytes = vec![0xab; 65];
    bytes
        .extend(hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c").unwrap());
    let parsed = LegacyToken::parse(&bytes).unwrap();
    assert_eq!(parsed.signature, Bytes::from(vec![0xab; 65]));
    assert_eq!(parsed.zone_id, 0x01020304);
    assert_eq!(parsed.chain_id, 0x05060708090a0b0c);
    assert_eq!(
        parsed.digest,
        b256!("f827387a933f40dfedece81ba4933feaef89e98a269f52f4f54dda2f1dac4171")
    );
}

#[test]
fn strict_wire_time_and_direct_root_cutover() {
    let signed = SignedToken {
        token: token(),
        signature: Bytes::from(vec![1; 65]),
    };
    let header = signed.header().unwrap();
    assert!(Credential::parse(&header, &domain(), NOW).is_ok());
    assert!(Credential::parse(&header, &domain(), NOW + 600).is_err());
    assert!(Credential::parse(&header, &domain(), u64::MAX).is_err());
    let mut claims = token();
    claims.issued_at = NOW + 60;
    claims.expires_at = NOW + 61;
    assert!(claims.validate(&domain(), NOW).is_ok());
    claims.issued_at += 1;
    assert!(claims.validate(&domain(), NOW).is_err());
    claims = token();
    claims.expires_at = NOW - 1;
    assert!(claims.validate(&domain(), NOW).is_err());
    claims = token();
    claims.expires_at = NOW + 601;
    let credential = Credential::V1(SignedToken {
        token: claims.clone(),
        signature: signed.signature.clone(),
    });
    assert!(claims.validate(&domain(), NOW).is_ok());
    assert!(credential.validate_direct_root_ttl().is_err());
    claims.kind = CredentialKind::AccountRoot;
    claims.generation = 0;
    assert!(claims.validate(&domain(), NOW).is_err());

    let json = serde_json::to_string(&signed).unwrap();
    let duplicate = json.replacen(
        "\"token\":",
        &format!(
            "\"token\":{},\"token\":",
            serde_json::to_string(&signed.token).unwrap()
        ),
        1,
    );
    let extra = json.replacen("{", "{\"unknown\":1,", 1);
    for raw in [duplicate, extra] {
        assert!(Credential::parse(&format!("v1:{}", hex::encode(raw)), &domain(), NOW).is_err());
    }
    assert!(
        serde_json::from_str::<AccountSet>(&format!(
            "{{\"kind\":\"listed\",\"accounts\":[\"{}\",\"{}\"]}}",
            a(1),
            a(1)
        ))
        .is_err()
    );
    assert!(Credential::parse(&"a".repeat(8193), &domain(), NOW).is_err());
}

#[test]
fn self_access_never_depends_on_registry_and_never_grants_indexer() {
    let registry = Registry::default();
    let account = Principal::Account(a(1));
    for permission in [
        Permission::Metadata,
        Permission::RpcRead,
        Permission::RpcWrite,
    ] {
        assert!(registry.allows(&account, Some(a(1)), permission));
        assert!(!registry.allows(&account, Some(a(2)), permission));
    }
    assert!(!registry.allows(&account, None, Permission::IndexerRead));
    assert!(registry.allows(&Principal::ZoneAdmin(a(9)), None, Permission::Logs));
    assert!(!registry.allows(&Principal::ZoneAdmin(a(9)), Some(a(9)), Permission::RpcRead));
}

#[test]
fn remove_readmit_preserves_sequences_generations_and_revocations() {
    let mut registry = Registry::default();
    let admin = a(0x66);
    let client = a(1);
    registry
        .apply(&admit(client, &[Scope::RpcRead]), admin)
        .unwrap();
    assert!(registry.allows(&principal(client, 1), Some(a(2)), Permission::RpcRead));
    registry
        .apply(
            &op(
                client,
                2,
                1,
                client,
                1,
                Change::RevokeToken {
                    generation: 1,
                    token_id: B256::repeat_byte(0x77),
                },
            ),
            admin,
        )
        .unwrap();
    assert!(!registry.allows(&principal(client, 1), Some(a(2)), Permission::RpcRead));
    registry
        .apply(&op(client, 3, 1, admin, 0, Change::Remove), admin)
        .unwrap();
    let mut admission = admit(client, &[]);
    admission.seq = 4;
    admission.generation = 1;
    let new_client = registry.apply(&admission, admin).unwrap();
    assert_eq!((new_client.generation, new_client.seq), (2, 4));
    assert!(new_client.scopes.is_empty());
    assert_eq!(registry.revoked.len(), 1);
    assert!(!registry.allows(&principal(client, 1), Some(a(2)), Permission::Metadata));
    assert!(!registry.allows(&principal(client, 2), Some(a(2)), Permission::RpcRead));
    let before = registry.clone();
    assert_eq!(
        registry.apply(&admission, admin),
        Err(PolicyError::Sequence)
    );
    assert_eq!(registry, before);
}

#[test]
fn independent_authority_table_covers_admin_before_and_after_state() {
    let admin = a(0x66);
    let admin_client = a(1);
    let ordinary = a(2);
    let target = a(3);
    for target_admin in [false, true] {
        for signer in [admin, admin_client, ordinary, target] {
            for operation in 0..7 {
                let mut registry = Registry::default();
                registry
                    .apply(&admit(admin_client, &[Scope::Admin]), admin)
                    .unwrap();
                registry.apply(&admit(ordinary, &[]), admin).unwrap();
                registry
                    .apply(
                        &admit(
                            target,
                            if target_admin {
                                &[Scope::Admin]
                            } else {
                                &[Scope::RpcRead]
                            },
                        ),
                        admin,
                    )
                    .unwrap();
                let change = match operation {
                    0 => Change::Rename {
                        name: "new name".into(),
                    },
                    1 => Change::Remove,
                    2 => Change::SetScopes {
                        scopes: scopes(&[Scope::Admin]),
                    },
                    3 => Change::SetScopes {
                        scopes: BTreeSet::new(),
                    },
                    4 => Change::ReplaceAccounts {
                        accounts: AccountSet::Listed(BTreeSet::new()),
                    },
                    5 => Change::RevokeToken {
                        generation: 1,
                        token_id: B256::repeat_byte(8),
                    },
                    _ => Change::SetScopes {
                        scopes: scopes(&[Scope::RpcWrite]),
                    },
                };
                // This literal table is independent of reducer control flow.
                let expected = signer == admin
                    || (operation == 5 && signer == target)
                    || (signer == admin_client && !target_admin && operation != 2);
                let before = registry.clone();
                let result = registry.apply(
                    &op(
                        target,
                        2,
                        1,
                        signer,
                        if signer == admin { 0 } else { 1 },
                        change,
                    ),
                    admin,
                );
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "admin={target_admin} signer={signer} operation={operation}"
                );
                if !expected {
                    assert_eq!(registry, before);
                }
            }
        }
    }
}

#[test]
fn replay_is_deterministic_and_counters_never_wrap() {
    let admin = a(0x66);
    let client = a(1);
    let history = [
        admit(client, &[Scope::RpcRead]),
        op(client, 2, 1, admin, 0, Change::Remove),
        op(
            client,
            3,
            1,
            admin,
            0,
            Change::Admit {
                name: "new".into(),
                scopes: scopes(&[Scope::IndexerRead]),
                accounts: AccountSet::Listed(BTreeSet::new()),
            },
        ),
    ];
    let mut left = Registry::default();
    let mut right = Registry::default();
    for operation in &history {
        left.apply(operation, admin).unwrap();
    }
    for operation in &history {
        right
            .apply(
                &serde_json::from_str(&serde_json::to_string(operation).unwrap()).unwrap(),
                admin,
            )
            .unwrap();
    }
    assert_eq!(left, right);
    assert_eq!(left.offset, 3);
    left.offset = u64::MAX;
    let before = left.clone();
    assert_eq!(
        left.apply(&op(client, 4, 2, admin, 0, Change::Remove), admin),
        Err(PolicyError::Exhausted)
    );
    assert_eq!(left, before);
}

#[test]
fn method_permission_oracle_is_literal_and_complete() {
    let read = [
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_call",
        "eth_estimateGas",
        "eth_fillTransaction",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_getLogs",
        "eth_getFilterLogs",
        "eth_getFilterChanges",
        "eth_newFilter",
        "eth_newBlockFilter",
        "eth_uninstallFilter",
    ];
    let write = ["eth_sendRawTransaction", "eth_sendRawTransactionSync"];
    let metadata = [
        "eth_chainId",
        "eth_blockNumber",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_feeHistory",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_syncing",
        "eth_coinbase",
        "net_version",
        "net_listening",
        "web3_clientVersion",
        "web3_sha3",
        "zone_getAuthorizationTokenInfo",
        "zone_getZoneInfo",
        "zone_getEncryptionKey",
        "eth_unsubscribe",
    ];
    assert_eq!(
        RpcMethod::ALL.len(),
        read.len() + write.len() + metadata.len() + 1
    );
    for (names, permission) in [
        (read.as_slice(), Permission::RpcRead),
        (write.as_slice(), Permission::RpcWrite),
        (metadata.as_slice(), Permission::Metadata),
    ] {
        for name in names {
            assert_eq!(
                rpc_permission(name, &serde_json::json!([])),
                Some(permission),
                "{name}"
            );
        }
    }
    assert_eq!(
        rpc_permission("eth_subscribe", &serde_json::json!(["newHeads"])),
        Some(Permission::Metadata)
    );
    assert_eq!(
        rpc_permission("eth_subscribe", &serde_json::json!(["logs", {}])),
        Some(Permission::RpcRead)
    );
    for params in [
        serde_json::json!(["pendingTransactions"]),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        assert_eq!(rpc_permission("eth_subscribe", &params), None);
    }
    assert_eq!(
        rpc_permission("debug_traceTransaction", &serde_json::json!([])),
        None
    );
    assert_eq!(rpc_permission("made_up", &serde_json::json!([])), None);
}
