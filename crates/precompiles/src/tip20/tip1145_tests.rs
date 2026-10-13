//! TIP-1145 integration tests: token-specific policies, packed storage, receive configs, and
//! storage conversion.

use super::*;
use crate::{
    PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS,
    error::TempoPrecompileError,
    receive_policy_guard::{BLOCKED_RECEIPT_VERSION, IReceivePolicyGuard, InboundKind},
    storage::{StorageCtx, StorageKey, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
    tip403_registry::{
        MINT_RECIPIENT_FLAG, RECEIVE_CONFIG_KIND, RECEIVE_TOKEN_FLAG, RECIPIENT_FLAG,
        REJECT_ALL_POLICY_ID, SENDER_FLAG, tip403_registry_slots,
    },
};
use alloy::{primitives::LogData, sol_types::SolEvent};
use tempo_contracts::precompiles::ITIP403Registry::{
    AuthRole as Role, BlockedReason, MembershipKind, PolicyMode,
};
use tempo_primitives::{MasterId, UserTag};

const MODE_ALLOW: PolicyMode = PolicyMode::ALLOW;
const MODE_DENY: PolicyMode = PolicyMode::DENY;
const MODE_WHITELIST: PolicyMode = PolicyMode::WHITELIST;
const MODE_BLACKLIST: PolicyMode = PolicyMode::BLACKLIST;

fn t14() -> HashMapStorageProvider {
    HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
}

fn word(address: Address, slot: U256) -> U256 {
    StorageCtx.sload(address, slot).unwrap()
}

fn registry_events() -> Vec<LogData> {
    StorageCtx.get_events(TIP403_REGISTRY_ADDRESS).clone()
}

fn set_modes(
    admin: Address,
    token: Address,
    sender: PolicyMode,
    recipient: PolicyMode,
    mint_recipient: PolicyMode,
) -> Result<()> {
    TIP403Registry::new().set_token_policy_modes(
        admin,
        ITIP403Registry::setTokenPolicyModesCall {
            token,
            senderMode: sender,
            recipientMode: recipient,
            mintRecipientMode: mint_recipient,
        },
    )
}

fn add_members(admin: Address, token: Address, accounts: &[Address], role: Role) -> Result<()> {
    TIP403Registry::new().modify_token_members(admin, token, accounts, role, true)
}

fn flags(token: Address, account: Address) -> u8 {
    TIP403Registry::new()
        .token_user_flags(ITIP403Registry::tokenUserFlagsCall { token, account })
        .unwrap()
}

fn transfer(token: &mut TIP20Token, from: Address, to: Address, amount: u64) -> Result<bool> {
    token.transfer(
        from,
        ITIP20::transferCall {
            to,
            amount: U256::from(amount),
        },
    )
}

fn mint(token: &mut TIP20Token, issuer: Address, to: Address, amount: u64) -> Result<()> {
    token.mint(
        issuer,
        ITIP20::mintCall {
            to,
            amount: U256::from(amount),
        },
    )
}

fn forbids() -> TempoPrecompileError {
    TIP20Error::policy_forbids().into()
}

#[test]
fn new_tokens_use_packed_layout_and_allow_all_policy() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Test", "TST", admin).apply()?;
        let address = token.address;

        assert!(token.is_packed()?);
        assert_eq!(token.transfer_policy_id()?, TOKEN_POLICY_ID);
        assert_eq!(
            token.transfer_policy()?,
            ITIP20::transferPolicyReturn {
                senderMode: 0,
                recipientMode: 0,
                mintRecipientMode: 0
            }
        );
        let policy = TIP403Registry::new()
            .token_policy(ITIP403Registry::tokenPolicyCall { token: address })?;
        assert!(policy.isSet);
        assert_eq!(
            TIP403Registry::new()
                .token_transfer_policy_id(ITIP403Registry::tokenTransferPolicyIdCall {
                    token: address
                })?
                .policyId,
            TOKEN_POLICY_ID
        );

        // Logical metadata is preserved.
        assert_eq!(token.currency()?, "USD");
        assert!(token.is_usd()?);
        assert_eq!(token.quote_token()?, PATH_USD_ADDRESS);
        assert_eq!(token.next_quote_token()?, PATH_USD_ADDRESS);
        assert_eq!(token.total_supply()?, U256::ZERO);
        assert_eq!(token.supply_cap()?, U128_MAX);
        assert!(!token.paused()?);

        // Obsolete legacy words stay empty; supply and cap share slot 8.
        for slot in [
            slots::CURRENCY,
            slots::QUOTE_TOKEN,
            slots::NEXT_QUOTE_TOKEN,
            slots::SUPPLY_CAP,
        ] {
            assert_eq!(word(address, slot), U256::ZERO);
        }
        assert_eq!(word(address, slots::TOTAL_SUPPLY), U128_MAX << 128);

        // pathUSD itself is packed and reports no quote token.
        let path_usd = TIP20Token::from_address(PATH_USD_ADDRESS)?;
        assert!(path_usd.is_packed()?);
        assert_eq!(path_usd.quote_token()?, Address::ZERO);

        // Creation emits `TransferPolicyUpdated` with three `ALLOW` modes.
        let expected = ITIP403Registry::TransferPolicyUpdated {
            token: address,
            senderMode: MODE_ALLOW,
            recipientMode: MODE_ALLOW,
            mintRecipientMode: MODE_ALLOW,
        }
        .encode_log_data();
        assert!(registry_events().contains(&expected));
        Ok(())
    })
}

#[test]
fn long_currencies_stay_external() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();

    StorageCtx::enter(&mut storage, || {
        let long = "A_CURRENCY_LONGER_THAN_14";
        let token = TIP20Setup::create("Test", "TST", admin)
            .currency(long)
            .apply()?;
        assert!(token.is_packed()?);
        assert_eq!(token.currency()?, long);
        assert!(!token.is_usd()?);
        assert_ne!(word(token.address, slots::CURRENCY), U256::ZERO);

        let short = TIP20Setup::create("Test", "TST", admin)
            .currency("EUR")
            .apply()?;
        assert_eq!(short.currency()?, "EUR");
        assert!(!short.is_usd()?);
        assert_eq!(word(short.address, slots::CURRENCY), U256::ZERO);
        Ok(())
    })
}

#[test]
fn packed_admin_operations_preserve_unrelated_fields() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();
    let user = Address::random();

    StorageCtx::enter(&mut storage, || {
        let quote = TIP20Setup::create("Quote", "QT", admin).apply()?;
        let mut token = TIP20Setup::create("Test", "TST", admin)
            .with_issuer(admin)
            .with_role(admin, PAUSE_ROLE)
            .with_role(admin, UNPAUSE_ROLE)
            .apply()?;

        mint(&mut token, admin, user, 1_000)?;
        assert_eq!(token.total_supply()?, U256::from(1_000));
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: user })?,
            U256::from(1_000)
        );

        token.set_supply_cap(
            admin,
            ITIP20::setSupplyCapCall {
                newSupplyCap: U256::from(5_000),
            },
        )?;
        assert_eq!(token.supply_cap()?, U256::from(5_000));
        assert_eq!(token.total_supply()?, U256::from(1_000));
        assert_eq!(
            token
                .set_supply_cap(
                    admin,
                    ITIP20::setSupplyCapCall {
                        newSupplyCap: U256::from(999),
                    },
                )
                .unwrap_err(),
            TIP20Error::invalid_supply_cap().into()
        );
        assert_eq!(
            mint(&mut token, admin, user, 4_001).unwrap_err(),
            TIP20Error::supply_cap_exceeded().into()
        );

        token.burn(admin, ITIP20::burnCall { amount: U256::ZERO })?;
        token.transfer(
            user,
            ITIP20::transferCall {
                to: admin,
                amount: U256::from(100),
            },
        )?;
        token.burn(
            admin,
            ITIP20::burnCall {
                amount: U256::from(100),
            },
        )?;
        assert_eq!(token.total_supply()?, U256::from(900));
        assert_eq!(token.supply_cap()?, U256::from(5_000));

        token.set_next_quote_token(
            admin,
            ITIP20::setNextQuoteTokenCall {
                newQuoteToken: quote.address,
            },
        )?;
        assert_eq!(token.next_quote_token()?, quote.address);
        assert_eq!(token.quote_token()?, PATH_USD_ADDRESS);
        token.complete_quote_token_update(admin, ITIP20::completeQuoteTokenUpdateCall {})?;
        assert_eq!(token.quote_token()?, quote.address);

        token.pause(admin, ITIP20::pauseCall {})?;
        assert!(token.paused()?);
        assert_eq!(
            transfer(&mut token, user, admin, 1).unwrap_err(),
            TIP20Error::contract_paused().into()
        );
        // Metadata remains readable while paused.
        assert_eq!(token.quote_token()?, quote.address);
        assert_eq!(token.currency()?, "USD");
        token.unpause(admin, ITIP20::unpauseCall {})?;
        assert!(!token.paused()?);
        assert_eq!(token.quote_token()?, quote.address);
        assert_eq!(token.transfer_policy_id()?, TOKEN_POLICY_ID);
        Ok(())
    })
}

#[test]
fn issuer_modes_and_memberships() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();
    let (alice, bob, carol) = (Address::random(), Address::random(), Address::random());

    StorageCtx::enter(&mut storage, || {
        let mut token = TIP20Setup::create("Test", "TST", admin)
            .with_issuer(admin)
            .with_mint(alice, U256::from(1_000))
            .apply()?;
        let address = token.address;

        // Only the token admin may edit the policy.
        assert_eq!(
            set_modes(alice, address, MODE_DENY, MODE_ALLOW, MODE_ALLOW).unwrap_err(),
            TIP403RegistryError::unauthorized().into()
        );
        assert_eq!(
            add_members(alice, address, &[], Role::SENDER).unwrap_err(),
            TIP403RegistryError::unauthorized().into()
        );

        // Sender blacklist and recipient whitelist.
        set_modes(admin, address, MODE_BLACKLIST, MODE_WHITELIST, MODE_ALLOW)?;
        assert_eq!(token.transfer_policy()?.senderMode, MODE_BLACKLIST as u8);
        assert_eq!(
            transfer(&mut token, alice, bob, 10).unwrap_err(),
            forbids(),
            "bob is not whitelisted"
        );
        add_members(admin, address, &[bob], Role::RECIPIENT)?;
        assert!(transfer(&mut token, alice, bob, 10)?);

        add_members(admin, address, &[alice], Role::SENDER)?;
        assert_eq!(transfer(&mut token, alice, bob, 10).unwrap_err(), forbids());
        TIP403Registry::new().modify_token_members(
            admin,
            address,
            &[alice],
            Role::SENDER,
            false,
        )?;
        assert!(transfer(&mut token, alice, bob, 10)?);

        // `ALL` edits all three lists without touching the receive-token bit.
        TIP403Registry::new().modify_receive_tokens(carol, &[address], true)?;
        add_members(admin, address, &[carol], Role::ALL)?;
        assert_eq!(
            flags(address, carol),
            SENDER_FLAG | RECIPIENT_FLAG | MINT_RECIPIENT_FLAG | RECEIVE_TOKEN_FLAG
        );
        TIP403Registry::new().modify_token_members(
            admin,
            address,
            &[carol],
            Role::TRANSFER,
            false,
        )?;
        assert_eq!(
            flags(address, carol),
            MINT_RECIPIENT_FLAG | RECEIVE_TOKEN_FLAG
        );

        // Mint-recipient rules are independent.
        set_modes(admin, address, MODE_ALLOW, MODE_ALLOW, MODE_WHITELIST)?;
        assert_eq!(mint(&mut token, admin, bob, 1).unwrap_err(), forbids());
        mint(&mut token, admin, carol, 1)?;
        set_modes(admin, address, MODE_ALLOW, MODE_ALLOW, MODE_DENY)?;
        assert_eq!(mint(&mut token, admin, carol, 1).unwrap_err(), forbids());

        // The registry view checks every selected role.
        let is_authorized = |account, role| {
            TIP403Registry::new().is_token_authorized(ITIP403Registry::isTokenAuthorizedCall {
                token: address,
                account,
                role,
            })
        };
        assert!(is_authorized(carol, Role::TRANSFER)?);
        assert!(!is_authorized(carol, Role::ALL)?);
        assert!(!is_authorized(carol, Role::MINT_RECIPIENT)?);

        // Virtual members and non-TIP-20 tokens are rejected.
        let virtual_addr = Address::new_virtual(MasterId::ZERO, UserTag::ZERO);
        assert_eq!(
            add_members(admin, address, &[virtual_addr], Role::SENDER).unwrap_err(),
            TIP403RegistryError::virtual_address_not_allowed().into()
        );
        assert_eq!(
            add_members(admin, Address::random(), &[bob], Role::SENDER).unwrap_err(),
            TIP403RegistryError::invalid_token().into()
        );
        let undeployed = Address::new_tip20(u64::from_be_bytes([9; 8]));
        assert_eq!(
            set_modes(admin, undeployed, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW).unwrap_err(),
            TIP403RegistryError::invalid_token().into()
        );
        assert_eq!(
            TIP403Registry::new()
                .is_token_authorized(ITIP403Registry::isTokenAuthorizedCall {
                    token: undeployed,
                    account: bob,
                    role: Role::SENDER,
                })
                .unwrap_err(),
            TIP403RegistryError::invalid_token().into(),
            "unregistered tokens are rejected"
        );
        Ok(())
    })
}

#[test]
fn mode_changes_sync_packed_cache_and_emit_events() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();
    let (alice, bob) = (Address::random(), Address::random());

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Test", "TST", admin).apply()?;
        let address = token.address;
        let before = word(address, slots::PAUSED);

        TIP403Registry::new().clear_emitted_events();
        set_modes(admin, address, MODE_DENY, MODE_BLACKLIST, MODE_WHITELIST)?;
        assert_ne!(word(address, slots::PAUSED), before);
        assert_eq!(
            token.token_control()?.unwrap().policy().unwrap(),
            TokenPolicy {
                is_set: true,
                sender: MODE_DENY,
                recipient: MODE_BLACKLIST,
                mint_recipient: MODE_WHITELIST,
            }
        );

        // No-op updates still emit, and batches emit per entry including duplicates.
        set_modes(admin, address, MODE_DENY, MODE_BLACKLIST, MODE_WHITELIST)?;
        add_members(admin, address, &[alice, bob, alice], Role::TRANSFER)?;
        add_members(admin, address, &[], Role::SENDER)?;

        let modes_event = ITIP403Registry::TransferPolicyUpdated {
            token: address,
            senderMode: MODE_DENY,
            recipientMode: MODE_BLACKLIST,
            mintRecipientMode: MODE_WHITELIST,
        }
        .encode_log_data();
        let member = |account| {
            ITIP403Registry::PolicyMembershipUpdated {
                kind: MembershipKind::ISSUER,
                owner: address,
                account,
                role: Role::TRANSFER,
                isMember: true,
            }
            .encode_log_data()
        };
        assert_eq!(
            registry_events(),
            vec![
                modes_event.clone(),
                modes_event,
                member(alice),
                member(bob),
                member(alice)
            ]
        );
        Ok(())
    })
}

#[test]
fn protocol_guard_is_always_authorized() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Test", "TST", admin).apply()?;
        set_modes(admin, token.address, MODE_DENY, MODE_DENY, MODE_DENY)?;
        assert!(token.is_authorized_as(RECEIVE_POLICY_GUARD_ADDRESS, AuthRole::Transfer)?);
        assert!(!token.is_authorized_as(admin, AuthRole::Sender)?);
        Ok(())
    })
}

#[test]
fn receive_configs_filter_tokens_then_senders() -> eyre::Result<()> {
    let mut storage = t14();
    storage.set_timestamp(U256::from(77));
    let admin = Address::random();
    let (sender, receiver, recovery) = (Address::random(), Address::random(), Address::random());

    StorageCtx::enter(&mut storage, || {
        let mut token = TIP20Setup::create("Test", "TST", admin)
            .with_issuer(admin)
            .with_mint(sender, U256::from(1_000))
            .apply()?;
        let address = token.address;
        let mut registry = TIP403Registry::new();

        // Opt into a token whitelist with third-party recovery.
        registry.set_receive_config(
            receiver,
            ITIP403Registry::setReceiveConfigCall {
                tokenMode: MODE_WHITELIST,
                senderMode: MODE_BLACKLIST,
                recoveryAuthority: recovery,
            },
        )?;
        assert_eq!(
            registry.receive_config(receiver)?,
            ITIP403Registry::receiveConfigReturn {
                hasReceivePolicy: true,
                tokenMode: MODE_WHITELIST,
                senderMode: MODE_BLACKLIST,
                recoveryAuthority: recovery,
            }
        );
        // The config replaces the legacy word: kind, modes, recovery mode, then the authority.
        let word = word(
            TIP403_REGISTRY_ADDRESS,
            receiver.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
        );
        assert_eq!(word.byte(0), RECEIVE_CONFIG_KIND);
        assert_eq!(word.byte(1), MODE_WHITELIST as u8);
        assert_eq!(word.byte(2), MODE_BLACKLIST as u8);
        assert_eq!(Address::from_word(B256::from(word >> 32)), recovery);

        // Legacy APIs are unsupported after opting in.
        assert_eq!(
            registry.receive_policy(receiver).unwrap_err(),
            TIP403RegistryError::receive_policy_ids_unsupported().into()
        );
        assert_eq!(
            registry
                .set_receive_policy(
                    receiver,
                    ITIP403Registry::setReceivePolicyCall {
                        senderPolicyId: 1,
                        tokenFilterId: 1,
                        recoveryAuthority: Address::ZERO,
                    },
                )
                .unwrap_err(),
            TIP403RegistryError::receive_policy_ids_unsupported().into()
        );

        // Token not whitelisted: blocked with the stored recovery authority.
        assert_eq!(
            registry.validate_receive_policy(address, sender, receiver)?,
            Some(BlockedReason::TOKEN_FILTER)
        );
        assert!(transfer(&mut token, sender, receiver, 10)?);
        let receipt = IReceivePolicyGuard::ClaimReceiptV1::new(
            address,
            recovery,
            sender,
            receiver,
            77,
            1,
            BlockedReason::TOKEN_FILTER as u8,
            InboundKind::TRANSFER,
            B256::ZERO,
        );
        assert_eq!(
            ReceivePolicyGuard::new().balance_of(receipt.abi_encode().into())?,
            U256::from(10)
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
            U256::ZERO
        );

        // Whitelisting the token (a future-token-capable list) lets the transfer through.
        registry.modify_receive_tokens(receiver, &[address], true)?;
        assert_eq!(flags(address, receiver), RECEIVE_TOKEN_FLAG);
        assert!(transfer(&mut token, sender, receiver, 10)?);
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
            U256::from(10)
        );

        // Blacklisting the sender blocks with `RECEIVE_POLICY`.
        registry.modify_receive_senders(receiver, &[sender], true)?;
        assert!(registry.receive_sender_membership(receiver, sender)?);
        assert_eq!(
            registry.validate_receive_policy(address, sender, receiver)?,
            Some(BlockedReason::RECEIVE_POLICY)
        );
        mint(&mut token, admin, receiver, 5)?;
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
            U256::from(15),
            "mints check `msg.sender`, which is not blacklisted"
        );
        assert!(transfer(&mut token, sender, receiver, 10)?);
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: receiver })?,
            U256::from(15)
        );
        ReceivePolicyGuard::new().assert_emitted_events(vec![
            IReceivePolicyGuard::IReceivePolicyGuardEvents::TransferBlocked(
                IReceivePolicyGuard::TransferBlocked {
                    token: address,
                    receiver,
                    blockedNonce: 1,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    amount: U256::from(10),
                    receipt: receipt.abi_encode().into(),
                },
            ),
            IReceivePolicyGuard::IReceivePolicyGuardEvents::TransferBlocked(
                IReceivePolicyGuard::TransferBlocked {
                    token: address,
                    receiver,
                    blockedNonce: 2,
                    receiptVersion: BLOCKED_RECEIPT_VERSION,
                    amount: U256::from(10),
                    receipt: IReceivePolicyGuard::ClaimReceiptV1::new(
                        address,
                        recovery,
                        sender,
                        receiver,
                        77,
                        2,
                        BlockedReason::RECEIVE_POLICY as u8,
                        InboundKind::TRANSFER,
                        B256::ZERO,
                    )
                    .abi_encode()
                    .into(),
                },
            ),
        ]);

        // Caller restrictions.
        assert_eq!(
            registry
                .modify_receive_tokens(RECEIVE_POLICY_GUARD_ADDRESS, &[], true)
                .unwrap_err(),
            TIP403RegistryError::address_reserved().into()
        );
        assert_eq!(
            registry
                .modify_receive_tokens(receiver, &[Address::random()], true)
                .unwrap_err(),
            TIP403RegistryError::invalid_token().into()
        );
        assert_eq!(
            registry
                .set_receive_config(
                    receiver,
                    ITIP403Registry::setReceiveConfigCall {
                        tokenMode: MODE_ALLOW,
                        senderMode: MODE_ALLOW,
                        recoveryAuthority: TIP403_REGISTRY_ADDRESS,
                    },
                )
                .unwrap_err(),
            TIP403RegistryError::invalid_recovery_authority().into()
        );
        Ok(())
    })
}

#[test]
fn unconfigured_receivers_report_allow_all() -> eyre::Result<()> {
    let mut storage = t14();
    StorageCtx::enter(&mut storage, || {
        let receiver = Address::random();
        assert_eq!(
            TIP403Registry::new().receive_config(receiver)?,
            ITIP403Registry::receiveConfigReturn {
                hasReceivePolicy: false,
                tokenMode: MODE_ALLOW,
                senderMode: MODE_ALLOW,
                recoveryAuthority: Address::ZERO,
            }
        );
        Ok(())
    })
}

/// Creates a legacy token before T14 with a generic blacklist, then switches to T14.
fn legacy_token(admin: Address, blocked: Address) -> Result<(TIP20Token, u64)> {
    StorageCtx.set_spec(TempoHardfork::T13);
    let mut token = TIP20Setup::create("Legacy", "LGC", admin)
        .with_issuer(admin)
        .apply()?;
    let policy_id = TIP403Registry::new().create_policy_with_accounts(
        admin,
        ITIP403Registry::createPolicyWithAccountsCall {
            admin,
            policyType: ITIP403Registry::PolicyType::BLACKLIST,
            accounts: vec![blocked],
        },
    )?;
    token.change_transfer_policy_id(
        admin,
        ITIP20::changeTransferPolicyIdCall {
            newPolicyId: policy_id,
        },
    )?;
    StorageCtx.set_spec(TempoHardfork::T14);
    Ok((token, policy_id))
}

#[test]
fn activation_converts_legacy_tokens() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();
    let (alice, blocked) = (Address::random(), Address::random());

    StorageCtx::enter(&mut storage, || {
        let (mut token, policy_id) = legacy_token(admin, blocked)?;
        let address = token.address;
        mint(&mut token, admin, alice, 1_000)?;
        assert!(!token.is_packed()?);
        assert_eq!(token.transfer_policy_id()?, policy_id);
        assert_eq!(
            transfer(&mut token, alice, blocked, 1).unwrap_err(),
            forbids()
        );

        // Preparing modes and memberships does not activate them.
        set_modes(admin, address, MODE_ALLOW, MODE_BLACKLIST, MODE_ALLOW)?;
        assert_eq!(word(address, slots::PAUSED), U256::ZERO);
        assert_eq!(token.transfer_policy_id()?, policy_id);
        assert_eq!(
            token.transfer_policy().unwrap_err(),
            TIP20Error::invalid_transfer_policy_id().into()
        );

        // Activation registers the prepared policy and packs storage, preserving logical values.
        let before = (
            token.currency()?,
            token.quote_token()?,
            token.next_quote_token()?,
            token.total_supply()?,
            token.supply_cap()?,
            token.paused()?,
        );
        TIP403Registry::new().clear_emitted_events();
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: TOKEN_POLICY_ID,
            },
        )?;
        assert_eq!(
            registry_events(),
            vec![
                ITIP403Registry::TransferPolicyUpdated {
                    token: address,
                    senderMode: MODE_ALLOW,
                    recipientMode: MODE_BLACKLIST,
                    mintRecipientMode: MODE_ALLOW,
                }
                .encode_log_data()
            ]
        );
        assert!(token.is_packed()?);
        assert_eq!(
            before,
            (
                token.currency()?,
                token.quote_token()?,
                token.next_quote_token()?,
                token.total_supply()?,
                token.supply_cap()?,
                token.paused()?,
            )
        );
        for slot in [
            slots::CURRENCY,
            slots::QUOTE_TOKEN,
            slots::NEXT_QUOTE_TOKEN,
            slots::SUPPLY_CAP,
        ] {
            assert_eq!(word(address, slot), U256::ZERO);
        }

        // Lists start empty, so `blocked` passes until it is listed.
        assert_eq!(token.transfer_policy_id()?, TOKEN_POLICY_ID);
        assert!(transfer(&mut token, alice, blocked, 1)?);
        add_members(admin, address, &[blocked], Role::RECIPIENT)?;
        assert_eq!(
            transfer(&mut token, alice, blocked, 1).unwrap_err(),
            forbids()
        );

        // Repeating activation is a no-op; generic IDs are unsupported afterwards.
        TIP403Registry::new().clear_emitted_events();
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: TOKEN_POLICY_ID,
            },
        )?;
        assert!(registry_events().is_empty());
        assert_eq!(
            token
                .change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: REJECT_ALL_POLICY_ID,
                    },
                )
                .unwrap_err(),
            TIP403RegistryError::token_policy_ids_unsupported().into()
        );

        // Activation clears the obsolete generic binding.
        assert_eq!(
            TIP403Registry::new().registered_token_transfer_policy_id(address)?,
            None
        );

        // Legacy binding migration skips token-specific tokens.
        assert_eq!(
            TIP403Registry::new().migrate_transfer_policy_ids(
                ITIP403Registry::migrateTransferPolicyIdsCall {
                    tokens: vec![address]
                }
            )?,
            U256::ZERO
        );

        // Mode changes stay in sync with the packed cache.
        set_modes(admin, address, MODE_ALLOW, MODE_ALLOW, MODE_ALLOW)?;
        assert!(transfer(&mut token, alice, blocked, 1)?);
        assert_eq!(
            token.token_control()?.unwrap().policy().unwrap(),
            TokenPolicy::ALLOW_ALL
        );
        Ok(())
    })
}

#[test]
fn activation_rejects_unpackable_tokens_and_malformed_words() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();

    StorageCtx::enter(&mut storage, || {
        let (mut token, policy_id) = legacy_token(admin, Address::random())?;
        let address = token.address;

        // A non-pathUSD null quote cannot be packed, so activation reverts atomically.
        StorageCtx.sstore(address, slots::QUOTE_TOKEN, U256::ZERO)?;
        let activate = ITIP20::changeTransferPolicyIdCall {
            newPolicyId: TOKEN_POLICY_ID,
        };
        assert_eq!(
            token
                .change_transfer_policy_id(admin, activate)
                .unwrap_err(),
            TIP20Error::invalid_quote_token().into()
        );
        assert_eq!(token.transfer_policy_id()?, policy_id);

        // Malformed control words revert reads.
        StorageCtx.sstore(address, slots::PAUSED, U256::from(4))?;
        assert!(matches!(
            token.paused().unwrap_err(),
            TempoPrecompileError::Fatal(_)
        ));
        Ok(())
    })
}

#[test]
fn registry_mirrors_resolve_token_specific_policies() -> eyre::Result<()> {
    let mut storage = t14();
    let admin = Address::random();
    let (alice, bob) = (Address::random(), Address::random());

    StorageCtx::enter(&mut storage, || {
        // A legacy-layout mirror (as zones create) without a registry binding.
        TIP20Setup::path_usd(admin).apply()?;
        let address = Address::new_tip20(0x1145);
        let mut token = TIP20Token::from_address(address)?;
        token.initialize_with_layout(
            admin,
            "Mirror",
            "MIR",
            "USD",
            PATH_USD_ADDRESS,
            admin,
            false,
        )?;
        token.grant_role_internal(admin, ISSUER_ROLE)?;
        token.resolve_policy_from_registry()?;
        let mut registry = TIP403Registry::new();
        registry.token_transfer_policies[address].delete()?;
        assert!(!token.is_packed()?);

        // No active token-specific policy: reject all.
        assert_eq!(mint(&mut token, admin, alice, 10).unwrap_err(), forbids());

        // The mirrored registry policy applies, including its lists.
        registry.register_token_policy(
            address,
            TokenPolicy {
                recipient: MODE_WHITELIST,
                ..TokenPolicy::ALLOW_ALL
            },
        )?;
        mint(&mut token, admin, alice, 10)?;
        assert_eq!(transfer(&mut token, alice, bob, 1).unwrap_err(), forbids());
        registry.token_user_flags[address][bob].write(RECIPIENT_FLAG)?;
        assert!(transfer(&mut token, alice, bob, 1)?);
        assert_eq!(token.transfer_policy_id()?, TOKEN_POLICY_ID);
        Ok(())
    })
}

#[test]
fn pre_t14_tokens_keep_the_legacy_layout() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    let admin = Address::random();

    StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::create("Test", "TST", admin).apply()?;
        assert!(!token.is_packed()?);
        assert_eq!(token.transfer_policy_id()?, ALLOW_ALL_POLICY_ID);
        assert_eq!(word(token.address, slots::SUPPLY_CAP), U128_MAX);
        assert!(
            TIP403Registry::new()
                .active_token_policy(token.address)?
                .is_none()
        );
        Ok(())
    })
}
