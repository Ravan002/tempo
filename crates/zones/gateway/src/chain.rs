//! Read-only, hash-pinned authority verification. Trusted proofs are never deserialized.

use alloy_primitives::{Address, B256, Bytes, hex};
use alloy_sol_types::{SolCall, sol};
use eyre::Result;
use serde_json::{Value, json};
use std::time::Duration;
use tempo_contracts::{
    precompiles::{
        ACCOUNT_KEYCHAIN_ADDRESS, SIGNATURE_VERIFIER_ADDRESS, account_keychain::IAccountKeychain,
        signature_verifier::ISignatureVerifier,
    },
    zones::ZonePortal,
};
use tempo_primitives::transaction::{
    SignatureType,
    tt_signature::{KeychainSignature, TempoSignature},
};
use zone_auth::{Credential, CredentialKind, Domain, Principal, SignedOp};

use crate::clock;

sol! {
    interface IERC1271 {
        function isValidSignature(bytes32 digest, bytes signature) external view returns (bytes4);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid credential")]
    Invalid,
    #[error("authority dependency unavailable")]
    Unavailable,
}

pub struct VerifiedCredential {
    pub principal: Principal,
    pub expires_at: u64,
    pub observed_at: f64,
    pub tempo_hash: B256,
    pub zone_hash: Option<B256>,
}

pub struct VerifiedOperation {
    pub signed: SignedOp,
    pub zone_admin: Address,
    pub observed_at: f64,
    pub tempo_hash: B256,
}

fn fresh(observed_at: f64) -> bool {
    let age = clock::continuous_seconds() - observed_at;
    age.is_finite() && (0.0..5.0).contains(&age) && clock::unix_seconds().is_ok()
}

impl VerifiedCredential {
    pub fn fresh(&self) -> bool {
        fresh(self.observed_at) && clock::unix_seconds().is_ok_and(|now| self.expires_at > now)
    }
}
impl VerifiedOperation {
    pub fn fresh(&self) -> bool {
        fresh(self.observed_at)
    }
}

#[derive(Clone)]
pub struct ChainVerifier {
    domain: Domain,
    tempo_url: String,
    zone_url: String,
    http: reqwest::Client,
}

impl ChainVerifier {
    pub async fn health(&self) -> Result<()> {
        let observed_at = clock::continuous_seconds();
        clock::unix_seconds()?;
        self.pin(&self.tempo_url, self.domain.tempo_chain_id, "finalized")
            .await?;
        self.pin(&self.zone_url, self.domain.zone_chain_id, "latest")
            .await?;
        if !fresh(observed_at) {
            return Err(VerificationError::Unavailable.into());
        }
        Ok(())
    }

    pub fn new(domain: Domain, tempo_url: String, zone_url: String) -> Result<Self> {
        // reqwest's rustls-no-provider feature requires an explicit process provider.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        for endpoint in [&tempo_url, &zone_url] {
            let url = reqwest::Url::parse(endpoint)?;
            eyre::ensure!(
                matches!(url.scheme(), "http" | "https"),
                "invalid chain endpoint"
            );
            eyre::ensure!(
                url.username().is_empty() && url.password().is_none(),
                "URL credentials unsupported"
            );
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            domain,
            tempo_url,
            zone_url,
            http,
        })
    }

    async fn rpc(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let response = self
            .http
            .post(url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| VerificationError::Unavailable)?;
        if !response.status().is_success() {
            return Err(VerificationError::Unavailable.into());
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| VerificationError::Unavailable)?;
        if bytes.len() > 1 << 20 {
            return Err(VerificationError::Unavailable.into());
        }
        let body: Value =
            serde_json::from_slice(&bytes).map_err(|_| VerificationError::Unavailable)?;
        if body.get("id") != Some(&json!(1)) {
            return Err(VerificationError::Unavailable.into());
        }
        if let Some(error) = body.get("error") {
            // Only execution reverts definitively disprove the particular signature.
            // Missing methods, pruned state, timeout and malformed replies are dependency failures.
            if error.get("code").and_then(Value::as_i64) == Some(3) {
                return Err(VerificationError::Invalid.into());
            }
            return Err(VerificationError::Unavailable.into());
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| VerificationError::Unavailable.into())
    }

    async fn pin(&self, url: &str, chain_id: u64, tag: &str) -> Result<B256> {
        let actual = self.rpc(url, "eth_chainId", json!([])).await?;
        let parsed = actual
            .as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .and_then(|v| u64::from_str_radix(v, 16).ok());
        if parsed != Some(chain_id) {
            return Err(VerificationError::Unavailable.into());
        }
        let block = self
            .rpc(url, "eth_getBlockByNumber", json!([tag, false]))
            .await?;
        serde_json::from_value(block.get("hash").cloned().unwrap_or(Value::Null))
            .map_err(|_| VerificationError::Unavailable.into())
    }

    async fn call<C: SolCall>(
        &self,
        url: &str,
        hash: B256,
        to: Address,
        call: C,
    ) -> Result<C::Return> {
        let value = self
            .rpc(
                url,
                "eth_call",
                json!([
                    {"to":to,"data":format!("0x{}", hex::encode(call.abi_encode()))},
                    {"blockHash":hash,"requireCanonical":true}
                ]),
            )
            .await?;
        let bytes: Bytes =
            serde_json::from_value(value).map_err(|_| VerificationError::Unavailable)?;
        C::abi_decode_returns(&bytes).map_err(|_| VerificationError::Unavailable.into())
    }

    async fn membership(&self, account: Address, hash: B256) -> Result<()> {
        let enforced = self
            .call(
                &self.tempo_url,
                hash,
                self.domain.portal,
                ZonePortal::isAccessEnforcedCall {},
            )
            .await?;
        if !enforced {
            return Ok(());
        }
        // hasRole uses exact equality; a Sequencer is not automatically an Account.
        if self
            .call(
                &self.tempo_url,
                hash,
                self.domain.portal,
                ZonePortal::hasRoleCall {
                    account,
                    role: ZonePortal::Role::Account,
                },
            )
            .await?
        {
            return Ok(());
        }
        Err(VerificationError::Invalid.into())
    }

    async fn signature(
        &self,
        url: &str,
        hash: B256,
        signer: Address,
        digest: B256,
        signature: &Bytes,
        allow_keychain: bool,
    ) -> Result<(bool, Option<u64>)> {
        let code = self
            .rpc(
                url,
                "eth_getCode",
                json!([signer,{"blockHash":hash,"requireCanonical":true}]),
            )
            .await?;
        let code: Bytes =
            serde_json::from_value(code).map_err(|_| VerificationError::Unavailable)?;
        if !code.is_empty() {
            let magic = self
                .call(
                    url,
                    hash,
                    signer,
                    IERC1271::isValidSignatureCall {
                        digest,
                        signature: signature.clone(),
                    },
                )
                .await?;
            if magic.as_slice() != [0x16, 0x26, 0xba, 0x7e] {
                return Err(VerificationError::Invalid.into());
            }
            return Ok((false, None));
        }
        let parsed =
            TempoSignature::from_bytes(signature).map_err(|_| VerificationError::Invalid)?;
        if let TempoSignature::Keychain(key) = parsed {
            if !allow_keychain || key.user_address != signer {
                return Err(VerificationError::Invalid.into());
            }
            let key_id = key
                .key_id(&digest)
                .map_err(|_| VerificationError::Invalid)?;
            let info = self
                .call(
                    url,
                    hash,
                    ACCOUNT_KEYCHAIN_ADDRESS,
                    IAccountKeychain::getKeyCall {
                        account: signer,
                        keyId: key_id,
                    },
                )
                .await?;
            let expected = match key.signature.signature_type() {
                SignatureType::Secp256k1 => IAccountKeychain::SignatureType::Secp256k1,
                SignatureType::P256 => IAccountKeychain::SignatureType::P256,
                SignatureType::WebAuthn => IAccountKeychain::SignatureType::WebAuthn,
            };
            if info.keyId != key_id
                || info.isRevoked
                || info.expiry <= clock::unix_seconds()?
                || info.signatureType != expected
            {
                return Err(VerificationError::Invalid.into());
            }
            // This account-bound path works before T6 and with legacy encodings.
            // Verify the actual inner primitive remotely; never omit getKey's type comparison.
            let signing_hash = if key.is_legacy() {
                digest
            } else {
                KeychainSignature::signing_hash(digest, signer)
            };
            if !self
                .call(
                    url,
                    hash,
                    SIGNATURE_VERIFIER_ADDRESS,
                    ISignatureVerifier::verifyCall {
                        signer: key_id,
                        hash: signing_hash,
                        signature: key.signature.to_bytes(),
                    },
                )
                .await?
            {
                return Err(VerificationError::Invalid.into());
            }
            return Ok((true, Some(info.expiry)));
        }
        if !self
            .call(
                url,
                hash,
                SIGNATURE_VERIFIER_ADDRESS,
                ISignatureVerifier::verifyCall {
                    signer,
                    hash: digest,
                    signature: signature.clone(),
                },
            )
            .await?
        {
            return Err(VerificationError::Invalid.into());
        }
        Ok((false, None))
    }

    pub async fn verify(
        &self,
        credential: &Credential,
        account: Option<Address>,
        logs: bool,
    ) -> Result<VerifiedCredential> {
        let observed_at = clock::continuous_seconds();
        let now = clock::unix_seconds()?;
        let (signer, digest, signature, issued_at, expires_at) = match credential {
            Credential::Legacy(token) => {
                if token.zone_id != 0 && token.zone_id != self.domain.zone_id
                    || token.chain_id != self.domain.zone_chain_id
                {
                    return Err(VerificationError::Invalid.into());
                }
                let parsed = TempoSignature::from_bytes(&token.signature)
                    .map_err(|_| VerificationError::Invalid)?;
                (
                    parsed
                        .recover_signer(&token.digest)
                        .map_err(|_| VerificationError::Invalid)?,
                    token.digest,
                    Bytes::copy_from_slice(&token.signature),
                    token.issued_at,
                    token.expires_at,
                )
            }
            Credential::V1(signed) => {
                signed
                    .token
                    .validate(&self.domain, now)
                    .map_err(|_| VerificationError::Invalid)?;
                (
                    signed.token.principal,
                    signed.token.digest(),
                    signed.signature.clone(),
                    signed.token.issued_at,
                    signed.token.expires_at,
                )
            }
        };
        validate_time(issued_at, expires_at, now, 2_592_000)?;
        let tempo_hash = self
            .pin(&self.tempo_url, self.domain.tempo_chain_id, "finalized")
            .await?;
        if logs {
            let admin = self
                .call(
                    &self.tempo_url,
                    tempo_hash,
                    self.domain.portal,
                    ZonePortal::adminCall {},
                )
                .await?;
            if signer == admin {
                self.signature(
                    &self.tempo_url,
                    tempo_hash,
                    signer,
                    digest,
                    &signature,
                    false,
                )
                .await?;
                let proof = VerifiedCredential {
                    principal: Principal::ZoneAdmin(admin),
                    expires_at,
                    observed_at,
                    tempo_hash,
                    zone_hash: None,
                };
                if !proof.fresh() {
                    return Err(VerificationError::Unavailable.into());
                }
                return Ok(proof);
            }
        }
        let acting = account.or(match credential {
            Credential::Legacy(_) => Some(signer),
            Credential::V1(signed)
                if matches!(
                    signed.token.kind,
                    CredentialKind::AccountRoot | CredentialKind::AccountKey
                ) =>
            {
                Some(signer)
            }
            _ => None,
        });
        if acting == Some(signer) {
            let zone_hash = self
                .pin(&self.zone_url, self.domain.zone_chain_id, "latest")
                .await?;
            let direct = self
                .signature(&self.zone_url, zone_hash, signer, digest, &signature, true)
                .await;
            match direct {
                Ok((access_key, key_expiry))
                    if access_key || credential.validate_direct_root_ttl().is_ok() =>
                {
                    if let Credential::V1(signed) = credential
                        && matches!(
                            (signed.token.kind, access_key),
                            (CredentialKind::AccountKey, false)
                                | (CredentialKind::AccountRoot, true)
                        )
                    {
                        return Err(VerificationError::Invalid.into());
                    }
                    self.membership(signer, tempo_hash).await?;
                    let expires_at =
                        key_expiry.map_or(expires_at, |key_expiry| key_expiry.min(expires_at));
                    let proof = VerifiedCredential {
                        principal: Principal::Account(signer),
                        expires_at,
                        observed_at,
                        tempo_hash,
                        zone_hash: Some(zone_hash),
                    };
                    if !proof.fresh() {
                        return Err(VerificationError::Unavailable.into());
                    }
                    return Ok(proof);
                }
                Ok(_) => {}
                Err(error)
                    if error
                        .downcast_ref::<VerificationError>()
                        .is_some_and(|e| matches!(e, VerificationError::Invalid)) => {}
                Err(error) => return Err(error),
            }
        }
        let Credential::V1(signed) = credential else {
            return Err(VerificationError::Invalid.into());
        };
        if signed.token.kind != CredentialKind::Client {
            return Err(VerificationError::Invalid.into());
        }
        self.signature(
            &self.tempo_url,
            tempo_hash,
            signer,
            digest,
            &signature,
            false,
        )
        .await?;
        if let Some(account) = account {
            self.membership(account, tempo_hash).await?;
        }
        let proof = VerifiedCredential {
            principal: Principal::Client {
                address: signer,
                generation: signed.token.generation,
                token_id: signed.token.token_id,
                label: signed.token.label.clone(),
            },
            expires_at,
            observed_at,
            tempo_hash,
            zone_hash: None,
        };
        if !proof.fresh() {
            return Err(VerificationError::Unavailable.into());
        }
        Ok(proof)
    }

    pub async fn verify_operation(&self, signed: &SignedOp) -> Result<VerifiedOperation> {
        let observed_at = clock::continuous_seconds();
        if signed.op.domain != self.domain {
            return Err(VerificationError::Invalid.into());
        }
        // Expired signed operations still need cryptographic verification so the store can
        // return a prior receipt. The locked commit path rejects expired unapplied changes.
        let now = clock::unix_seconds()?;
        signed
            .op
            .change
            .validate()
            .map_err(|_| VerificationError::Invalid)?;
        if signed.op.client.is_zero()
            || signed.op.signer.is_zero()
            || signed.op.seq == 0
            || signed.signature.is_empty()
            || signed
                .op
                .expires_at
                .checked_sub(signed.op.issued_at)
                .is_none_or(|ttl| ttl > 600)
            || now
                .checked_add(60)
                .is_none_or(|limit| signed.op.issued_at > limit)
        {
            return Err(VerificationError::Invalid.into());
        }
        let tempo_hash = self
            .pin(&self.tempo_url, self.domain.tempo_chain_id, "finalized")
            .await?;
        let zone_admin = self
            .call(
                &self.tempo_url,
                tempo_hash,
                self.domain.portal,
                ZonePortal::adminCall {},
            )
            .await?;
        self.signature(
            &self.tempo_url,
            tempo_hash,
            signed.op.signer,
            signed.op.digest(),
            &signed.signature,
            false,
        )
        .await?;
        let proof = VerifiedOperation {
            signed: signed.clone(),
            zone_admin,
            observed_at,
            tempo_hash,
        };
        if !proof.fresh() {
            return Err(VerificationError::Unavailable.into());
        }
        Ok(proof)
    }
}

fn validate_time(issued: u64, expires: u64, now: u64, max_ttl: u64) -> Result<()> {
    let valid = expires
        .checked_sub(issued)
        .is_some_and(|ttl| ttl <= max_ttl)
        && expires > now
        && now.checked_add(60).is_some_and(|limit| issued <= limit);
    if !valid {
        return Err(VerificationError::Invalid.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_boundaries_are_exclusive_and_checked() {
        assert!(validate_time(100, 700, 100, 600).is_ok());
        assert!(validate_time(160, 161, 100, 600).is_ok());
        assert!(validate_time(161, 162, 100, 600).is_err());
        assert!(validate_time(100, 700, 700, 600).is_err());
        assert!(validate_time(101, 100, 100, 600).is_err());
        assert!(validate_time(0, u64::MAX, 100, 600).is_err());
        assert!(!fresh(clock::continuous_seconds() - 5.0));
        let proof = VerifiedCredential {
            principal: Principal::Account(Address::repeat_byte(1)),
            expires_at: clock::unix_seconds().unwrap(),
            observed_at: clock::continuous_seconds(),
            tempo_hash: B256::ZERO,
            zone_hash: None,
        };
        assert!(!proof.fresh());
    }
}
