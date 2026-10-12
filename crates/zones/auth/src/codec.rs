use crate::{
    AccessOp, AccountSet, Change, Credential, CredentialKind, Domain, Scope, SignedToken,
    TokenClaims,
};
use alloy_primitives::{Address, B256, Bytes, hex, keccak256};
use alloy_sol_types::{SolStruct, eip712_domain, sol};
use std::collections::BTreeSet;

pub const MAX_TOKEN_WIRE_BYTES: usize = 8_192;
pub const ROOT_TTL: u64 = 600;
pub const LONG_TTL: u64 = 2_592_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("invalid credential encoding")]
    Encoding,
    #[error("credential exceeds size limit")]
    TooLarge,
    #[error("wrong signed domain")]
    Domain,
    #[error("invalid time window")]
    Time,
    #[error("credential expired")]
    Expired,
    #[error("invalid credential field")]
    Fields,
}

#[derive(Clone)]
pub struct LegacyToken {
    pub signature: Bytes,
    pub digest: B256,
    pub zone_id: u32,
    pub chain_id: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

// These exact Solidity type names and field names are the signed protocol.
sol! {
    struct ZoneDomain { uint64 tempoChainId; address portal; uint32 zoneId; uint64 zoneChainId; }
    struct AccessToken {
        uint32 zoneId; uint64 zoneChainId; address principal; uint8 credentialKind;
        uint64 clientGeneration; bytes32 tokenId; string label; uint64 issuedAt; uint64 expiresAt;
    }
    struct AccessOperation {
        uint32 zoneId; uint64 zoneChainId; address client; uint64 sequence; uint64 generation;
        address signer; uint64 signerGeneration; uint8 changeTag; bytes32 changeHash;
        uint64 issuedAt; uint64 expiresAt;
    }
    struct Admission { string name; uint8 scopes; bool allAccounts; address[] accounts; }
    struct Rename { string name; }
    struct SetScopes { uint8 scopes; }
    struct ReplaceAccounts { bool allAccounts; address[] accounts; }
    struct AddAccounts { address[] accounts; }
    struct RemoveAccounts { address[] accounts; }
    struct RevokeToken { uint64 generation; bytes32 tokenId; }
    struct Remove { bool removed; }
}

impl Domain {
    pub fn key(&self) -> B256 {
        ZoneDomain {
            tempoChainId: self.tempo_chain_id,
            portal: self.portal,
            zoneId: self.zone_id,
            zoneChainId: self.zone_chain_id,
        }
        .eip712_hash_struct()
    }

    fn eip712(&self) -> alloy_sol_types::Eip712Domain {
        eip712_domain! { name: "TempoZoneAccess", version: "1",
        chain_id: self.tempo_chain_id, verifying_contract: self.portal, }
    }
}

impl CredentialKind {
    pub const fn tag(self) -> u8 {
        match self {
            Self::AccountRoot => 0,
            Self::AccountKey => 1,
            Self::Client => 2,
            Self::ZoneAdmin => 3,
        }
    }

    pub const fn max_ttl(self) -> u64 {
        match self {
            Self::AccountRoot | Self::ZoneAdmin => ROOT_TTL,
            Self::AccountKey | Self::Client => LONG_TTL,
        }
    }
}

pub fn validate_time(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    max_ttl: u64,
) -> Result<(), CodecError> {
    let ttl = expires_at.checked_sub(issued_at).ok_or(CodecError::Time)?;
    if ttl > max_ttl || issued_at > now.checked_add(60).ok_or(CodecError::Time)? {
        return Err(CodecError::Time);
    }
    if expires_at <= now {
        return Err(CodecError::Expired);
    }
    Ok(())
}

impl TokenClaims {
    pub fn digest(&self) -> B256 {
        AccessToken {
            zoneId: self.domain.zone_id,
            zoneChainId: self.domain.zone_chain_id,
            principal: self.principal,
            credentialKind: self.kind.tag(),
            clientGeneration: self.generation,
            tokenId: self.token_id,
            label: self.label.clone(),
            issuedAt: self.issued_at,
            expiresAt: self.expires_at,
        }
        .eip712_signing_hash(&self.domain.eip712())
    }

    pub fn validate(&self, domain: &Domain, now: u64) -> Result<(), CodecError> {
        if &self.domain != domain {
            return Err(CodecError::Domain);
        }
        if self.principal.is_zero()
            || self.label.is_empty()
            || self.label.len() > 64
            || self.kind == CredentialKind::Client && self.generation == 0
            || self.kind != CredentialKind::Client && self.generation != 0
        {
            return Err(CodecError::Fields);
        }
        validate_time(self.issued_at, self.expires_at, now, self.kind.max_ttl())
    }
}

impl SignedToken {
    pub fn header(&self) -> Result<String, CodecError> {
        let bytes = serde_json::to_vec(self).map_err(|_| CodecError::Encoding)?;
        if bytes
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(3))
            .is_none_or(|n| n > MAX_TOKEN_WIRE_BYTES)
        {
            return Err(CodecError::TooLarge);
        }
        Ok(format!("v1:{}", hex::encode(bytes)))
    }
}

impl Credential {
    pub fn parse(header: &str, domain: &Domain, now: u64) -> Result<Self, CodecError> {
        if header.len() > MAX_TOKEN_WIRE_BYTES {
            return Err(CodecError::TooLarge);
        }
        if let Some(value) = header.strip_prefix("v1:") {
            let bytes = hex::decode(value).map_err(|_| CodecError::Encoding)?;
            let signed: SignedToken =
                serde_json::from_slice(&bytes).map_err(|_| CodecError::Encoding)?;
            if signed.signature.is_empty() {
                return Err(CodecError::Fields);
            }
            signed.token.validate(domain, now)?;
            Ok(Self::V1(signed))
        } else {
            let bytes = hex::decode(header.strip_prefix("0x").unwrap_or(header))
                .map_err(|_| CodecError::Encoding)?;
            let token = LegacyToken::parse(&bytes)?;
            if token.chain_id != domain.zone_chain_id
                || token.zone_id != 0 && token.zone_id != domain.zone_id
            {
                return Err(CodecError::Domain);
            }
            // Legacy signatures may prove an access key, determined only by the verifier.
            validate_time(token.issued_at, token.expires_at, now, LONG_TTL)?;
            Ok(Self::Legacy(token))
        }
    }

    /// Must be called after proving root self-account authority, including Client-framed tokens.
    /// The signed kind is never rewritten to obtain a different TTL.
    pub fn validate_direct_root_ttl(&self) -> Result<(), CodecError> {
        let (issued, expires) = match self {
            Self::Legacy(t) => (t.issued_at, t.expires_at),
            Self::V1(t) => (t.token.issued_at, t.token.expires_at),
        };
        if expires.checked_sub(issued).is_none_or(|ttl| ttl > ROOT_TTL) {
            Err(CodecError::Time)
        } else {
            Ok(())
        }
    }

    pub fn expires_at(&self) -> u64 {
        match self {
            Self::Legacy(t) => t.expires_at,
            Self::V1(t) => t.token.expires_at,
        }
    }
}

impl LegacyToken {
    pub fn parse(blob: &[u8]) -> Result<Self, CodecError> {
        if blob.len() < 30 || blob.len() > MAX_TOKEN_WIRE_BYTES {
            return Err(CodecError::Encoding);
        }
        let start = blob.len() - 29;
        let fields = &blob[start..];
        if fields[0] != 0 {
            return Err(CodecError::Encoding);
        }
        let mut packed = [0u8; 61];
        packed[..12].copy_from_slice(b"TempoZoneRPC");
        packed[32..].copy_from_slice(fields);
        let u64_at = |index| {
            u64::from_be_bytes(
                fields[index..index + 8]
                    .try_into()
                    .expect("fixed legacy suffix"),
            )
        };
        Ok(Self {
            signature: Bytes::copy_from_slice(&blob[..start]),
            digest: keccak256(packed),
            zone_id: u32::from_be_bytes(fields[1..5].try_into().expect("fixed legacy suffix")),
            chain_id: u64_at(5),
            issued_at: u64_at(13),
            expires_at: u64_at(21),
        })
    }
}

impl AccessOp {
    pub fn validate(&self, domain: &Domain, now: u64) -> Result<(), CodecError> {
        if &self.domain != domain {
            return Err(CodecError::Domain);
        }
        if self.client.is_zero() || self.signer.is_zero() || self.seq == 0 {
            return Err(CodecError::Fields);
        }
        self.change.validate().map_err(|_| CodecError::Fields)?;
        validate_time(self.issued_at, self.expires_at, now, ROOT_TTL)
    }

    pub fn digest(&self) -> B256 {
        let (tag, hash) = self.change.signed_hash();
        AccessOperation {
            zoneId: self.domain.zone_id,
            zoneChainId: self.domain.zone_chain_id,
            client: self.client,
            sequence: self.seq,
            generation: self.generation,
            signer: self.signer,
            signerGeneration: self.signer_generation,
            changeTag: tag,
            changeHash: hash,
            issuedAt: self.issued_at,
            expiresAt: self.expires_at,
        }
        .eip712_signing_hash(&self.domain.eip712())
    }
}

fn scope_bits(scopes: &BTreeSet<Scope>) -> u8 {
    scopes.iter().fold(0, |bits, scope| {
        bits | match scope {
            Scope::RpcRead => 1,
            Scope::RpcWrite => 2,
            Scope::IndexerRead => 4,
            Scope::Admin => 8,
        }
    })
}

fn coverage(accounts: &AccountSet) -> (bool, Vec<Address>) {
    match accounts {
        AccountSet::All => (true, vec![]),
        AccountSet::Listed(accounts) => (false, accounts.iter().copied().collect()),
    }
}

impl Change {
    fn signed_hash(&self) -> (u8, B256) {
        match self {
            Self::Admit {
                name,
                scopes,
                accounts,
            } => {
                let (all, accounts) = coverage(accounts);
                (
                    0,
                    Admission {
                        name: name.clone(),
                        scopes: scope_bits(scopes),
                        allAccounts: all,
                        accounts,
                    }
                    .eip712_hash_struct(),
                )
            }
            Self::Rename { name } => (1, Rename { name: name.clone() }.eip712_hash_struct()),
            Self::SetScopes { scopes } => (
                2,
                SetScopes {
                    scopes: scope_bits(scopes),
                }
                .eip712_hash_struct(),
            ),
            Self::ReplaceAccounts { accounts } => {
                let (all, accounts) = coverage(accounts);
                (
                    3,
                    ReplaceAccounts {
                        allAccounts: all,
                        accounts,
                    }
                    .eip712_hash_struct(),
                )
            }
            Self::AddAccounts { accounts } => (
                4,
                AddAccounts {
                    accounts: accounts.iter().copied().collect(),
                }
                .eip712_hash_struct(),
            ),
            Self::RemoveAccounts { accounts } => (
                5,
                RemoveAccounts {
                    accounts: accounts.iter().copied().collect(),
                }
                .eip712_hash_struct(),
            ),
            Self::RevokeToken {
                generation,
                token_id,
            } => (
                6,
                RevokeToken {
                    generation: *generation,
                    tokenId: *token_id,
                }
                .eip712_hash_struct(),
            ),
            Self::Remove => (7, Remove { removed: true }.eip712_hash_struct()),
        }
    }
}
