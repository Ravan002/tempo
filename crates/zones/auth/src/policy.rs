use crate::{
    AccessOp, AccountSet, Change, Client, Permission, Principal, Registry, RevocationKey, Scope,
};
use alloy_primitives::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("unauthorized operation")]
    Unauthorized,
    #[error("incorrect client sequence")]
    Sequence,
    #[error("incorrect admission generation")]
    Generation,
    #[error("client status does not permit operation")]
    Status,
    #[error("operation exceeds bounds")]
    Bounds,
    #[error("account changes require listed coverage")]
    Coverage,
    #[error("registry counter exhausted")]
    Exhausted,
}

impl AccountSet {
    pub fn contains(&self, address: Address) -> bool {
        match self {
            Self::All => true,
            Self::Listed(accounts) => accounts.contains(&address),
        }
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if matches!(self, Self::Listed(a) if a.len() > 1_000) {
            Err(PolicyError::Bounds)
        } else {
            Ok(())
        }
    }
}

impl Change {
    pub fn validate(&self) -> Result<(), PolicyError> {
        match self {
            Self::Admit { name, accounts, .. } => {
                validate_name(name)?;
                accounts.validate()
            }
            Self::Rename { name } => validate_name(name),
            Self::ReplaceAccounts { accounts } => accounts.validate(),
            Self::AddAccounts { accounts } | Self::RemoveAccounts { accounts } => {
                if accounts.is_empty() || accounts.len() > 1_000 {
                    Err(PolicyError::Bounds)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

fn validate_name(name: &str) -> Result<(), PolicyError> {
    if name.trim().is_empty() || name.len() > 128 {
        Err(PolicyError::Bounds)
    } else {
        Ok(())
    }
}

impl Registry {
    /// Chain membership, time validity and direct signature authority are checked by the verifier.
    pub fn allows(
        &self,
        principal: &Principal,
        account: Option<Address>,
        permission: Permission,
    ) -> bool {
        match principal {
            Principal::Account(address) => match permission {
                Permission::Metadata => account.is_none_or(|a| a == *address),
                Permission::RpcRead | Permission::RpcWrite => account == Some(*address),
                Permission::Logs => true,
                Permission::IndexerRead => false,
            },
            Principal::ZoneAdmin(_) => permission == Permission::Logs,
            Principal::Client {
                address,
                generation,
                token_id,
                ..
            } => {
                let Some(client) = self.clients.get(address) else {
                    return false;
                };
                if !client.active
                    || client.generation != *generation
                    || self.revoked.contains(&RevocationKey {
                        client: *address,
                        generation: *generation,
                        token_id: *token_id,
                    })
                {
                    return false;
                }
                let admin = client.scopes.contains(&Scope::Admin);
                match permission {
                    Permission::Logs => true,
                    Permission::IndexerRead => admin || client.scopes.contains(&Scope::IndexerRead),
                    Permission::Metadata => {
                        account.is_none()
                            || admin
                            || account.is_some_and(|a| client.accounts.contains(a))
                    }
                    Permission::RpcRead | Permission::RpcWrite => {
                        let scope = if permission == Permission::RpcRead {
                            Scope::RpcRead
                        } else {
                            Scope::RpcWrite
                        };
                        account.is_some_and(|a| {
                            admin || client.scopes.contains(&scope) && client.accounts.contains(a)
                        })
                    }
                }
            }
        }
    }

    /// Applies one authenticated signed operation. Storage handles digest idempotency before this call.
    /// On rejection no registry field changes, including sequence and head.
    pub fn apply(&mut self, op: &AccessOp, zone_admin: Address) -> Result<Client, PolicyError> {
        op.change.validate()?;
        let existing = self.clients.get(&op.client);
        let sequence = existing
            .map_or(0, |c| c.seq)
            .checked_add(1)
            .ok_or(PolicyError::Exhausted)?;
        if op.seq != sequence {
            return Err(PolicyError::Sequence);
        }
        if op.generation != existing.map_or(0, |c| c.generation) {
            return Err(PolicyError::Generation);
        }
        let offset = self.offset.checked_add(1).ok_or(PolicyError::Exhausted)?;

        let mut next = match &op.change {
            Change::Admit {
                name,
                scopes,
                accounts,
            } => {
                if existing.is_some_and(|c| c.active) {
                    return Err(PolicyError::Status);
                }
                Client {
                    address: op.client,
                    name: name.clone(),
                    scopes: scopes.clone(),
                    accounts: accounts.clone(),
                    generation: op.generation.checked_add(1).ok_or(PolicyError::Exhausted)?,
                    seq: op.seq,
                    active: true,
                }
            }
            _ => {
                let mut client = existing
                    .filter(|c| c.active)
                    .cloned()
                    .ok_or(PolicyError::Status)?;
                match &op.change {
                    Change::Rename { name } => client.name = name.clone(),
                    Change::SetScopes { scopes } => client.scopes = scopes.clone(),
                    Change::ReplaceAccounts { accounts } => client.accounts = accounts.clone(),
                    Change::AddAccounts { accounts } => match &mut client.accounts {
                        AccountSet::Listed(list) => {
                            list.extend(accounts);
                        }
                        AccountSet::All => return Err(PolicyError::Coverage),
                    },
                    Change::RemoveAccounts { accounts } => match &mut client.accounts {
                        AccountSet::Listed(list) => list.retain(|a| !accounts.contains(a)),
                        AccountSet::All => return Err(PolicyError::Coverage),
                    },
                    Change::RevokeToken { generation, .. } => {
                        if *generation == 0 || *generation > client.generation {
                            return Err(PolicyError::Generation);
                        }
                    }
                    Change::Remove => client.active = false,
                    Change::Admit { .. } => unreachable!("admissions handled above"),
                }
                client
            }
        };
        let is_admin = op.signer == zone_admin && op.signer_generation == 0;
        if !is_admin {
            let signer = self
                .clients
                .get(&op.signer)
                .filter(|c| c.active && c.generation == op.signer_generation)
                .ok_or(PolicyError::Unauthorized)?;
            let self_revoke =
                op.signer == op.client && matches!(op.change, Change::RevokeToken { .. });
            let changes_admin = existing.is_some_and(|c| c.scopes.contains(&Scope::Admin))
                || next.scopes.contains(&Scope::Admin);
            if !self_revoke && (!signer.scopes.contains(&Scope::Admin) || changes_admin) {
                return Err(PolicyError::Unauthorized);
            }
        }
        next.seq = op.seq;
        if let Change::RevokeToken {
            generation,
            token_id,
        } = &op.change
        {
            self.revoked.insert(RevocationKey {
                client: op.client,
                generation: *generation,
                token_id: *token_id,
            });
        }
        self.clients.insert(op.client, next.clone());
        self.offset = offset;
        Ok(next)
    }
}
