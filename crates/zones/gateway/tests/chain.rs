use alloy_primitives::{Address, B256, Bytes, hex};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tempo_contracts::{
    precompiles::{account_keychain::IAccountKeychain, signature_verifier::ISignatureVerifier},
    zones::ZonePortal,
};
use tempo_primitives::transaction::tt_signature::{
    KeychainSignature, PrimitiveSignature, TempoSignature,
};
use zone_auth::{
    AccessOp, AccountSet, Change, Credential, CredentialKind, Domain, Principal, SignedOp,
    SignedToken, TokenClaims,
};
use zone_gateway::chain::{ChainVerifier, VerificationError};

#[derive(Clone)]
struct Fixture {
    chain_id: u64,
    hash: B256,
    calls: Arc<Mutex<Vec<Value>>>,
    unavailable: bool,
    admin: Address,
    contract: Option<Address>,
    membership: bool,
    key_info: Option<IAccountKeychain::KeyInfo>,
}

#[tokio::test]
async fn expired_signed_operation_can_resolve_retry_but_tampered_payload_cannot() {
    let signer: PrivateKeySigner =
        "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
    let now = zone_gateway::clock::unix_seconds().unwrap();
    let op = AccessOp {
        domain: domain(),
        client: Address::repeat_byte(0x66),
        seq: 1,
        generation: 0,
        signer: signer.address(),
        signer_generation: 0,
        change: Change::Admit {
            name: "auditor".into(),
            scopes: Default::default(),
            accounts: AccountSet::All,
        },
        issued_at: now - 10,
        expires_at: now - 1,
    };
    let signature = signer
        .sign_hash_sync(&op.digest())
        .unwrap()
        .as_bytes()
        .to_vec()
        .into();
    let signed = SignedOp { op, signature };
    let mut tempo = fixture(100);
    tempo.admin = signer.address();
    let (tempo_url, tempo_task) = serve(tempo).await;
    let (zone_url, zone_task) = serve(fixture(101)).await;
    let verifier = ChainVerifier::new(domain(), tempo_url, zone_url).unwrap();
    let verified = verifier.verify_operation(&signed).await.unwrap();
    assert!(verified.fresh());
    assert_eq!(verified.zone_admin, signer.address());
    let mut tampered = signed.clone();
    tampered.op.client = Address::repeat_byte(0x77);
    let error = verifier.verify_operation(&tampered).await.err().unwrap();
    assert!(matches!(
        error.downcast_ref::<VerificationError>(),
        Some(VerificationError::Invalid)
    ));
    tempo_task.abort();
    zone_task.abort();
}

async fn rpc(State(fixture): State<Fixture>, Json(request): Json<Value>) -> Json<Value> {
    fixture.calls.lock().unwrap().push(request.clone());
    let method = request["method"].as_str().unwrap();
    if fixture.unavailable && method == "eth_getCode" {
        return Json(
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unavailable"}}),
        );
    }
    let params = &request["params"];
    let result = match method {
        "eth_chainId" => json!(format!("0x{:x}", fixture.chain_id)),
        "eth_getBlockByNumber" => json!({"hash":fixture.hash}),
        "eth_getCode" => {
            assert_eq!(
                params[1],
                json!({"blockHash":fixture.hash,"requireCanonical":true})
            );
            let account: Address = serde_json::from_value(params[0].clone()).unwrap();
            json!(if fixture.contract == Some(account) {
                "0x6000"
            } else {
                "0x"
            })
        }
        "eth_call" => {
            assert_eq!(
                params[1],
                json!({"blockHash":fixture.hash,"requireCanonical":true})
            );
            let data: Bytes = serde_json::from_value(params[0]["data"].clone()).unwrap();
            let bytes = if data.starts_with(&ZonePortal::adminCall::SELECTOR) {
                ZonePortal::adminCall::abi_encode_returns(&fixture.admin)
            } else if data.starts_with(&ZonePortal::isAccessEnforcedCall::SELECTOR) {
                ZonePortal::isAccessEnforcedCall::abi_encode_returns(&true)
            } else if data.starts_with(&ZonePortal::hasRoleCall::SELECTOR) {
                let call = ZonePortal::hasRoleCall::abi_decode(&data).unwrap();
                assert_eq!(call.role, ZonePortal::Role::Account);
                ZonePortal::hasRoleCall::abi_encode_returns(&fixture.membership)
            } else if data.starts_with(&ISignatureVerifier::verifyCall::SELECTOR) {
                let call = ISignatureVerifier::verifyCall::abi_decode(&data).unwrap();
                let recovered = TempoSignature::from_bytes(&call.signature)
                    .unwrap()
                    .recover_signer(&call.hash)
                    .unwrap();
                ISignatureVerifier::verifyCall::abi_encode_returns(&(recovered == call.signer))
            } else if data.starts_with(&IAccountKeychain::getKeyCall::SELECTOR) {
                IAccountKeychain::getKeyCall::abi_encode_returns(fixture.key_info.as_ref().unwrap())
            } else if data.starts_with(&[0x16, 0x26, 0xba, 0x7e]) {
                // Literal ERC-1271 ABI result, independent of the verifier's decoder.
                hex::decode("1626ba7e0000000000000000000000000000000000000000000000000000000000")
                    .unwrap()
            } else {
                panic!("unexpected ABI call");
            };
            json!(Bytes::from(bytes))
        }
        _ => panic!("unexpected RPC method"),
    };
    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
}

async fn serve(fixture: Fixture) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", post(rpc)).with_state(fixture),
        )
        .await
        .unwrap();
    });
    (url, task)
}

fn domain() -> Domain {
    Domain {
        tempo_chain_id: 100,
        portal: Address::repeat_byte(0x11),
        zone_id: 7,
        zone_chain_id: 101,
    }
}

fn fixture(chain_id: u64) -> Fixture {
    Fixture {
        chain_id,
        hash: B256::with_last_byte(chain_id as u8),
        calls: Arc::default(),
        unavailable: false,
        admin: Address::repeat_byte(0x44),
        contract: None,
        membership: true,
        key_info: None,
    }
}

#[tokio::test]
async fn zone_keychain_requires_active_key_and_exact_signature_type() {
    let signer: PrivateKeySigner =
        "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
    let account = Address::repeat_byte(0x55);
    let now = zone_gateway::clock::unix_seconds().unwrap();
    let claims = TokenClaims {
        domain: domain(),
        principal: account,
        kind: CredentialKind::AccountKey,
        generation: 0,
        token_id: B256::repeat_byte(0x22),
        label: "key".into(),
        issued_at: now,
        expires_at: now + 3_600,
    };
    let digest = KeychainSignature::signing_hash(claims.digest(), account);
    let signature = signer.sign_hash_sync(&digest).unwrap();
    let primitive = PrimitiveSignature::from_bytes(&signature.as_bytes()).unwrap();
    let signature = TempoSignature::Keychain(KeychainSignature::new(account, primitive)).to_bytes();
    let credential = Credential::V1(SignedToken {
        token: claims,
        signature,
    });
    for (revoked, wrong_type, expected) in [
        (false, false, true),
        (true, false, false),
        (false, true, false),
    ] {
        let tempo = fixture(100);
        let mut zone = fixture(101);
        zone.key_info = Some(IAccountKeychain::KeyInfo {
            keyId: signer.address(),
            expiry: now + 3_600,
            isRevoked: revoked,
            enforceLimits: false,
            signatureType: if wrong_type {
                IAccountKeychain::SignatureType::P256
            } else {
                IAccountKeychain::SignatureType::Secp256k1
            },
        });
        let (tempo_url, tempo_task) = serve(tempo).await;
        let (zone_url, zone_task) = serve(zone).await;
        let verifier = ChainVerifier::new(domain(), tempo_url, zone_url).unwrap();
        assert_eq!(
            verifier
                .verify(&credential, Some(account), false)
                .await
                .is_ok(),
            expected
        );
        tempo_task.abort();
        zone_task.abort();
    }
}

fn token(signer: &PrivateKeySigner, kind: CredentialKind) -> Credential {
    let now = zone_gateway::clock::unix_seconds().unwrap();
    let token = TokenClaims {
        domain: domain(),
        principal: signer.address(),
        kind,
        generation: 1,
        token_id: B256::repeat_byte(0x22),
        label: "audit".into(),
        issued_at: now,
        expires_at: now + 600,
    };
    let signature = signer
        .sign_hash_sync(&token.digest())
        .unwrap()
        .as_bytes()
        .to_vec()
        .into();
    Credential::V1(SignedToken { token, signature })
}

#[tokio::test]
async fn direct_first_and_delegated_chain_calls_use_real_signatures_and_pinned_hashes() {
    let signer: PrivateKeySigner =
        "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
    let tempo = fixture(100);
    let tempo_calls = tempo.calls.clone();
    let zone = fixture(101);
    let zone_calls = zone.calls.clone();
    let (tempo_url, tempo_task) = serve(tempo).await;
    let (zone_url, zone_task) = serve(zone).await;
    let verifier = ChainVerifier::new(domain(), tempo_url, zone_url).unwrap();
    let credential = token(&signer, CredentialKind::Client);
    let direct = verifier
        .verify(&credential, Some(signer.address()), false)
        .await
        .unwrap();
    assert!(matches!(direct.principal, Principal::Account(address) if address == signer.address()));
    assert!(direct.fresh());
    assert!(
        zone_calls
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_call")
    );
    assert!(
        !tempo_calls
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_getCode")
    );
    let delegated = verifier
        .verify(&credential, Some(Address::repeat_byte(0x33)), false)
        .await
        .unwrap();
    assert!(
        matches!(delegated.principal, Principal::Client {address,generation:1,..} if address == signer.address())
    );
    assert!(
        tempo_calls
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_getCode")
    );
    tempo_task.abort();
    zone_task.abort();
}

#[tokio::test]
async fn unavailable_direct_verification_never_falls_back_to_client() {
    let signer: PrivateKeySigner =
        "0x0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
    let tempo = fixture(100);
    let calls = tempo.calls.clone();
    let mut zone = fixture(101);
    zone.unavailable = true;
    let (tempo_url, tempo_task) = serve(tempo).await;
    let (zone_url, zone_task) = serve(zone).await;
    let verifier = ChainVerifier::new(domain(), tempo_url, zone_url).unwrap();
    let error = verifier
        .verify(
            &token(&signer, CredentialKind::Client),
            Some(signer.address()),
            false,
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error.downcast_ref::<VerificationError>(),
        Some(VerificationError::Unavailable)
    ));
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "eth_getCode")
    );
    tempo_task.abort();
    zone_task.abort();
}

#[tokio::test]
async fn contract_portal_admin_is_verified_on_tempo_without_zone_membership() {
    let admin = Address::repeat_byte(0x44);
    let mut tempo = fixture(100);
    tempo.contract = Some(admin);
    tempo.membership = false;
    let calls = tempo.calls.clone();
    let zone = fixture(101);
    let zone_calls = zone.calls.clone();
    let (tempo_url, tempo_task) = serve(tempo).await;
    let (zone_url, zone_task) = serve(zone).await;
    let verifier = ChainVerifier::new(domain(), tempo_url, zone_url).unwrap();
    let now = zone_gateway::clock::unix_seconds().unwrap();
    let claims = TokenClaims {
        domain: domain(),
        principal: admin,
        kind: CredentialKind::ZoneAdmin,
        generation: 0,
        token_id: B256::ZERO,
        label: "admin".into(),
        issued_at: now,
        expires_at: now + 600,
    };
    let credential = Credential::V1(SignedToken {
        token: claims,
        signature: Bytes::from(vec![1, 2, 3]),
    });
    let verified = verifier.verify(&credential, None, true).await.unwrap();
    assert!(matches!(verified.principal, Principal::ZoneAdmin(address) if address == admin));
    assert!(zone_calls.lock().unwrap().is_empty());
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .all(|r| !r["params"][0]["data"]
                .as_str()
                .is_some_and(|data| data.starts_with(&format!(
                    "0x{}",
                    hex::encode(ZonePortal::hasRoleCall::SELECTOR)
                ))))
    );
    tempo_task.abort();
    zone_task.abort();
}
