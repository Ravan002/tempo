use alloy_primitives::{Address, B256, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub tempo_chain_id: u64,
    pub portal: Address,
    pub zone_id: u32,
    pub zone_chain_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "rpc.read")]
    RpcRead,
    #[serde(rename = "rpc.write")]
    RpcWrite,
    #[serde(rename = "indexer.read")]
    IndexerRead,
    #[serde(rename = "admin")]
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "accounts",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AccountSet {
    All,
    Listed(#[serde(deserialize_with = "unique_set")] BTreeSet<Address>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub address: Address,
    pub name: String,
    #[serde(deserialize_with = "unique_set")]
    pub scopes: BTreeSet<Scope>,
    pub accounts: AccountSet,
    pub generation: u64,
    pub seq: u64,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationKey {
    pub client: Address,
    pub generation: u64,
    pub token_id: B256,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub offset: u64,
    pub clients: BTreeMap<Address, Client>,
    #[serde(deserialize_with = "unique_set")]
    pub revoked: BTreeSet<RevocationKey>,
}

/// Only constructed after the runtime verifies a credential. Never deserializable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "identity", rename_all = "snake_case")]
pub enum Principal {
    Account(Address),
    Client {
        address: Address,
        generation: u64,
        token_id: B256,
        label: String,
    },
    ZoneAdmin(Address),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    Metadata,
    RpcRead,
    RpcWrite,
    IndexerRead,
    Logs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Admit {
        name: String,
        #[serde(deserialize_with = "unique_set")]
        scopes: BTreeSet<Scope>,
        accounts: AccountSet,
    },
    Rename {
        name: String,
    },
    SetScopes {
        #[serde(deserialize_with = "unique_set")]
        scopes: BTreeSet<Scope>,
    },
    ReplaceAccounts {
        accounts: AccountSet,
    },
    AddAccounts {
        #[serde(deserialize_with = "unique_set")]
        accounts: BTreeSet<Address>,
    },
    RemoveAccounts {
        #[serde(deserialize_with = "unique_set")]
        accounts: BTreeSet<Address>,
    },
    RevokeToken {
        generation: u64,
        token_id: B256,
    },
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessOp {
    pub domain: Domain,
    pub client: Address,
    pub seq: u64,
    pub generation: u64,
    pub signer: Address,
    pub signer_generation: u64,
    pub change: Change,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOp {
    pub op: AccessOp,
    pub signature: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub digest: B256,
    pub client: Address,
    pub seq: u64,
    pub generation: u64,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    AccountRoot,
    AccountKey,
    Client,
    ZoneAdmin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenClaims {
    pub domain: Domain,
    pub principal: Address,
    pub kind: CredentialKind,
    pub generation: u64,
    pub token_id: B256,
    pub label: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedToken {
    pub token: TokenClaims,
    pub signature: Bytes,
}

#[derive(Clone)]
pub enum Credential {
    Legacy(crate::LegacyToken),
    V1(SignedToken),
}

fn unique_set<'de, D, T>(deserializer: D) -> Result<BTreeSet<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    let count = values.len();
    let set: BTreeSet<T> = values.into_iter().collect();
    if set.len() != count {
        return Err(serde::de::Error::custom("duplicate set member"));
    }
    Ok(set)
}
