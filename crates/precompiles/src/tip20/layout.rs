//! [TIP-1145] packed TIP-20 control and supply storage.
//!
//! Converted ("packed") tokens store pause, layout, cached issuer modes, quote IDs, and short
//! currencies in the slot-12 control word, and total supply with the cap in slot 8. Legacy tokens
//! keep the original layout, whose slot-12 word is exactly `0`/`1`. Every accessor decodes the
//! actual layout and never converts implicitly.
//!
//! [TIP-1145]: <https://docs.tempo.xyz/protocol/tips/tip-1145>

use super::{TIP20Error, TIP20Token, U128_MAX, USD_CURRENCY, slots};
use crate::{
    PATH_USD_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Slot},
    tip20_factory::TIP20Factory,
    tip403_registry::{TIP403Registry, TokenPolicy},
};
use alloy::primitives::{Address, FixedBytes, U256};
use tempo_precompiles_macros::Storable;
use tempo_primitives::TempoAddressExt;

/// Control flag: transfers are paused (also the legacy `paused == true` word).
const PAUSED_FLAG: u8 = 0b01;
/// Control flag: the token uses the packed layout.
const PACKED_FLAG: u8 = 0b10;
/// Inline encoding of [`USD_CURRENCY`].
const INLINE_USD: FixedBytes<14> = FixedBytes(*b"USD\0\0\0\0\0\0\0\0\0\0\0");

/// Slot-12 control word. The legacy `bool paused` word decodes as `flags` 0 or 1 with every other
/// field zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct TokenControl {
    flags: u8,
    /// Cache of the token's canonical TIP-403 issuer modes (two bits per role).
    modes: u8,
    /// Active quote token suffix (zero is pathUSD).
    quote_id: u64,
    /// Staged quote token suffix (zero is pathUSD).
    next_quote_id: u64,
    /// Inline currency, right-padded with zeros. All zero when the currency is external.
    currency: FixedBytes<14>,
}

impl TokenControl {
    /// Builds a packed control word. The currency is stored inline if it is nonempty,
    /// NUL-free, and fits 14 bytes; otherwise the inline field stays zero and the currency is
    /// external.
    fn new(policy: &TokenPolicy, quote_id: u64, next_quote_id: u64, currency: &str) -> Self {
        let bytes = currency.as_bytes();
        let inline = (1..=14).contains(&bytes.len()) && !bytes.contains(&0);
        Self {
            flags: PACKED_FLAG,
            modes: policy.modes_byte(),
            quote_id,
            next_quote_id,
            currency: if inline {
                FixedBytes::right_padding_from(bytes)
            } else {
                FixedBytes::ZERO
            },
        }
    }

    /// Returns whether the currency lives in the external (slot 4) string.
    fn has_external_currency(&self) -> bool {
        self.currency.is_zero()
    }

    /// Rejects malformed words: unknown flags, nonzero legacy fields, invalid modes, non-canonical
    /// inline currencies, and quotes on pathUSD.
    fn validate(self, token: Address) -> Result<Self> {
        let valid = self.flags & !(PAUSED_FLAG | PACKED_FLAG) == 0
            && if !self.is_packed() {
                self == Self {
                    flags: self.flags,
                    ..Default::default()
                }
            } else {
                TokenPolicy::from_modes_byte(self.modes).is_some()
                    && (self.currency.is_zero() || self.inline_currency().is_some())
                    && (token != PATH_USD_ADDRESS
                        || (self.quote_id == 0 && self.next_quote_id == 0))
            };
        if !valid {
            return Err(invalid_state(token));
        }
        Ok(self)
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.flags & PAUSED_FLAG != 0
    }

    fn with_paused(self, paused: bool) -> Self {
        let flags = if paused {
            self.flags | PAUSED_FLAG
        } else {
            self.flags & !PAUSED_FLAG
        };
        Self { flags, ..self }
    }

    pub(crate) fn is_packed(&self) -> bool {
        self.flags & PACKED_FLAG != 0
    }

    /// Returns the cached issuer policy of a packed token.
    pub(crate) fn policy(&self) -> Option<TokenPolicy> {
        self.is_packed()
            .then(|| TokenPolicy::from_modes_byte(self.modes).expect("validated"))
    }

    /// Decodes a nonzero inline currency, returning `None` for non-canonical encodings.
    fn inline_currency(&self) -> Option<&str> {
        let len = self.currency.iter().rposition(|b| *b != 0)? + 1;
        let bytes = &self.currency[..len];
        if bytes.contains(&0) {
            return None;
        }
        core::str::from_utf8(bytes).ok()
    }
}

/// Packed slot-8 word: total supply (low 128 bits) and supply cap (high 128 bits).
#[derive(Debug, Clone, Copy, Default, Storable)]
struct PackedSupply {
    total_supply: u128,
    supply_cap: u128,
}

/// Decoded supply state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Supply {
    pub(crate) total: U256,
    /// Packed supply cap; `None` for the legacy layout, which stores it in slot 13.
    cap: Option<U256>,
}

fn invalid_state(token: Address) -> TempoPrecompileError {
    TempoPrecompileError::Fatal(format!("invalid TIP-1145 control word for token {token}"))
}

impl TIP20Token {
    fn control_slot(&self) -> Slot<TokenControl> {
        Slot::new(slots::PAUSED, self.address)
    }

    fn supply_slot(&self) -> Slot<PackedSupply> {
        Slot::new(slots::TOTAL_SUPPLY, self.address)
    }

    /// Loads the control word. Pre-T14 this is exactly the legacy `paused` read.
    pub(crate) fn load_control(&self) -> Result<TokenControl> {
        if !self.storage.spec().is_t14() {
            return Ok(TokenControl::default().with_paused(self.paused.read()?));
        }
        self.control_slot().read()?.validate(self.address)
    }

    /// Probes the layout, returning the control word of packed tokens. Pre-T14 every token is
    /// legacy, so no storage is read.
    pub(crate) fn token_control(&self) -> Result<Option<TokenControl>> {
        if !self.storage.spec().is_t14() {
            return Ok(None);
        }
        Ok(Some(self.load_control()?).filter(TokenControl::is_packed))
    }

    #[cfg(test)]
    pub(crate) fn is_packed(&self) -> Result<bool> {
        Ok(self.token_control()?.is_some())
    }

    /// Writes the pause state, preserving the packed fields.
    pub(crate) fn store_paused(&mut self, paused: bool) -> Result<()> {
        match self.token_control()? {
            Some(control) => self.control_slot().write(control.with_paused(paused)),
            None => self.paused.write(paused),
        }
    }

    /// Synchronizes the cached issuer modes of packed tokens. Legacy tokens and unchanged modes
    /// receive no write.
    pub(crate) fn sync_policy_modes(&mut self, policy: &TokenPolicy) -> Result<()> {
        match self.token_control()? {
            Some(control) if control.modes != policy.modes_byte() => {
                let modes = policy.modes_byte();
                self.control_slot().write(TokenControl { modes, ..control })
            }
            _ => Ok(()),
        }
    }

    // ----- supply -----------------------------------------------------------------------------

    /// Loads the total supply for the given layout.
    pub(crate) fn load_supply(&self, packed: bool) -> Result<Supply> {
        Ok(if packed {
            let supply = self.supply_slot().read()?;
            Supply {
                total: U256::from(supply.total_supply),
                cap: Some(U256::from(supply.supply_cap)),
            }
        } else {
            Supply {
                total: self.total_supply.read()?,
                cap: None,
            }
        })
    }

    /// Returns the supply cap, reading the legacy slot when not already loaded.
    pub(crate) fn supply_cap_of(&self, supply: &Supply) -> Result<U256> {
        supply.cap.map_or_else(|| self.supply_cap.read(), Ok)
    }

    /// Writes a new total supply, preserving the packed cap.
    ///
    /// Callers must bound packed totals by the cap (≤ `u128::MAX`).
    pub(crate) fn store_total_supply(&mut self, supply: &Supply, total: U256) -> Result<()> {
        match supply.cap {
            Some(cap) => self.store_packed_supply(total, cap),
            None => self.total_supply.write(total),
        }
    }

    /// Writes a new supply cap (≤ `u128::MAX`), preserving the packed total.
    pub(crate) fn store_supply_cap(&mut self, supply: &Supply, cap: U256) -> Result<()> {
        match supply.cap {
            Some(_) => self.store_packed_supply(supply.total, cap),
            None => self.supply_cap.write(cap),
        }
    }

    fn store_packed_supply(&mut self, total: U256, cap: U256) -> Result<()> {
        self.supply_slot().write(PackedSupply {
            total_supply: total.to(),
            supply_cap: cap.to(),
        })
    }

    /// Overwrites the total supply in either layout (test helper).
    #[cfg(test)]
    pub(crate) fn set_total_supply(&mut self, total: U256) -> Result<()> {
        let supply = self.load_supply(self.is_packed()?)?;
        self.store_total_supply(&supply, total)
    }

    // ----- quote tokens -----------------------------------------------------------------------

    /// Returns the active (`staged == false`) or staged quote token.
    pub(crate) fn load_quote(&self, staged: bool) -> Result<Address> {
        Ok(match self.token_control()? {
            // pathUSD itself has no quote token.
            Some(_) if self.address == PATH_USD_ADDRESS => Address::ZERO,
            Some(control) if staged => Address::new_tip20(control.next_quote_id),
            Some(control) => Address::new_tip20(control.quote_id),
            None if staged => self.next_quote_token.read()?,
            None => self.quote_token.read()?,
        })
    }

    /// Writes the active (`staged == false`) or staged quote token, a deployed TIP-20.
    pub(crate) fn store_quote(&mut self, staged: bool, quote: Address) -> Result<()> {
        match self.token_control()? {
            Some(mut control) => {
                *if staged {
                    &mut control.next_quote_id
                } else {
                    &mut control.quote_id
                } = quote.tip20_id().expect("quote tokens are TIP-20s");
                self.control_slot().write(control)
            }
            None if staged => self.next_quote_token.write(quote),
            None => self.quote_token.write(quote),
        }
    }

    // ----- currency ---------------------------------------------------------------------------

    /// Returns the inline currency of packed tokens, if any.
    pub fn load_currency(&self) -> Result<Option<String>> {
        Ok(self
            .token_control()?
            .and_then(|control| control.inline_currency().map(str::to_string)))
    }

    /// Returns the currency for diagnostics, eliding external strings longer than 31 bytes.
    pub fn currency_summary(&self) -> Result<String> {
        if let Some(currency) = self.load_currency()? {
            return Ok(currency);
        }
        match self.currency.len()? {
            len if len > 31 => Ok(format!("<{len} bytes>")),
            _ => self.currency.read(),
        }
    }

    /// Returns whether the currency is [`USD_CURRENCY`].
    pub fn is_usd(&self) -> Result<bool> {
        match self.packed_is_usd()? {
            Some(is_usd) => Ok(is_usd),
            None => Ok(self.currency.read()? == USD_CURRENCY),
        }
    }

    /// For packed tokens, returns whether the currency is [`USD_CURRENCY`] by comparing inline
    /// bytes without an external read, since `"USD"` always fits inline. Returns `None` for
    /// legacy tokens.
    pub fn packed_is_usd(&self) -> Result<Option<bool>> {
        Ok(self
            .token_control()?
            .map(|control| control.currency == INLINE_USD))
    }

    // ----- initialization and conversion ------------------------------------------------------

    /// Returns the packed quote ID for `quote`, or `None` if it cannot be represented (a
    /// non-pathUSD token with a null quote) or is not a deployed TIP-20.
    fn packable_quote_id(&self, quote: Address) -> Result<Option<u64>> {
        if self.address == PATH_USD_ADDRESS {
            return Ok(quote.is_zero().then_some(0));
        }
        if quote.is_zero() || !TIP20Factory::new().is_tip20(quote)? {
            return Ok(None);
        }
        Ok(quote.tip20_id())
    }

    /// Initializes packed metadata, supply, and an `ALLOW` token-specific policy for a new
    /// token. Returns `false`, writing nothing, when `quote_token` cannot be packed.
    pub(crate) fn try_initialize_packed(
        &mut self,
        currency: &str,
        quote_token: Address,
    ) -> Result<bool> {
        let Some(quote_id) = self.packable_quote_id(quote_token)? else {
            return Ok(false);
        };

        let policy = TokenPolicy::ALLOW_ALL;
        let control = TokenControl::new(&policy, quote_id, quote_id, currency);
        if control.has_external_currency() {
            self.currency.write(currency.to_string())?;
        }
        self.store_packed_supply(U256::ZERO, U128_MAX)?;
        self.control_slot().write(control)?;
        TIP403Registry::new().register_token_policy(self.address, policy)?;
        Ok(true)
    }

    /// Converts a legacy token to the packed layout when it activates its token-specific policy.
    ///
    /// Reads every source field first, then clears obsolete words and writes supply before the
    /// control word, skipping unchanged writes. Logical values are preserved exactly.
    ///
    /// # Errors
    /// - `InvalidQuoteToken` — a quote is null (non-pathUSD) or undeployed
    /// - `SupplyCapExceeded` — supply or cap exceeds 128 bits
    pub(crate) fn convert_to_packed(&mut self, paused: bool, policy: &TokenPolicy) -> Result<()> {
        let currency = self.currency.read()?;
        let quote_id = self
            .packable_quote_id(self.quote_token.read()?)?
            .ok_or_else(TIP20Error::invalid_quote_token)?;
        let next_quote_id = self
            .packable_quote_id(self.next_quote_token.read()?)?
            .ok_or_else(TIP20Error::invalid_quote_token)?;
        let total = self.total_supply.read()?;
        let cap = self.supply_cap.read()?;
        if total > U128_MAX || cap > U128_MAX {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        let control =
            TokenControl::new(policy, quote_id, next_quote_id, &currency).with_paused(paused);
        if !control.has_external_currency() {
            self.clear_word(slots::CURRENCY)?;
        }
        for slot in [
            slots::QUOTE_TOKEN,
            slots::NEXT_QUOTE_TOKEN,
            slots::SUPPLY_CAP,
        ] {
            self.clear_word(slot)?;
        }
        // A zero cap leaves the legacy supply word unchanged.
        if !cap.is_zero() {
            self.store_packed_supply(total, cap)?;
        }
        self.control_slot().write(control)
    }

    /// Zeroes an obsolete legacy word, skipping the write when already zero.
    fn clear_word(&mut self, slot: U256) -> Result<()> {
        let mut word = Slot::<U256>::new(slot, self.address);
        if !word.read()?.is_zero() {
            word.write(U256::ZERO)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use tempo_chainspec::hardfork::TempoHardfork;

    fn roundtrip(control: TokenControl) -> U256 {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let address = Address::repeat_byte(0x20);
        StorageCtx::enter(&mut storage, || {
            let mut slot = Slot::<TokenControl>::new(U256::ZERO, address);
            slot.write(control).unwrap();
            assert_eq!(slot.read().unwrap(), control);
            StorageCtx.sload(address, U256::ZERO).unwrap()
        })
    }

    #[test]
    fn control_word_layout_and_legacy_compat() {
        let token = Address::repeat_byte(0x20);
        for paused in [false, true] {
            let legacy = TokenControl::default().with_paused(paused);
            assert_eq!(roundtrip(legacy), U256::from(u8::from(paused)));
            assert!(!legacy.validate(token).unwrap().is_packed());
        }

        let control = TokenControl::new(&TokenPolicy::ALLOW_ALL, 1, 2, "USD").with_paused(true);
        let word = roundtrip(control);
        assert_eq!(
            word & U256::from(0xff),
            U256::from(PAUSED_FLAG | PACKED_FLAG)
        );
        assert_eq!((word >> 16) & U256::from(u64::MAX), U256::ONE);
        assert_eq!((word >> 80) & U256::from(u64::MAX), U256::from(2));
        assert_eq!(word >> 248, U256::from(b'U'));
        assert!(control.validate(token).unwrap().is_paused());

        // Legacy words other than 0/1, unknown flags, and high mode bits are malformed.
        for malformed in [
            TokenControl {
                flags: PAUSED_FLAG,
                quote_id: 1,
                ..Default::default()
            },
            TokenControl {
                flags: 4,
                ..Default::default()
            },
            TokenControl {
                modes: 0xC0,
                ..control
            },
            TokenControl {
                currency: FixedBytes::right_padding_from(b"A\0B"),
                ..control
            },
        ] {
            assert!(malformed.validate(token).is_err());
        }
        assert!(control.validate(PATH_USD_ADDRESS).is_err());
    }

    #[test]
    fn inline_currency_rules() {
        let inline = |currency| TokenControl::new(&TokenPolicy::ALLOW_ALL, 0, 0, currency);
        assert_eq!(inline("USD").currency, INLINE_USD);
        for external in ["", "A\0B", "FIFTEEN_BYTES__"] {
            assert!(inline(external).currency.is_zero());
        }
        for currency in ["FOURTEENBYTES!", "€"] {
            assert_eq!(inline(currency).inline_currency(), Some(currency));
        }
        let invalid_utf8 = TokenControl {
            currency: FixedBytes::right_padding_from(&[0xff]),
            ..inline("")
        };
        assert!(invalid_utf8.inline_currency().is_none());
    }
}
