//! What the ring reads of the pinned SPP account lists and public legs, pinned by `tests/spp.rs`.
//!
//! SPP reads its lists by position and folds its legs in one order. A wrong index or stride here
//! would verify the ring proof against accounts SPP does not settle.
//!
//! Read after `program-libs/interface/src/lib.rs`. Read before `program-libs/interface/src/instructions/withdrawals.rs`,
//! `programs/custom-ring/src/instructions/verification/public_legs.rs`.

use arrayvec::ArrayVec;
use solana_address::Address;
use spr_hasher::{
    primitives::{hash_bytes, right_align, BN254_SCALAR_MODULUS_BE},
    HasherError,
};
use spr_interface::{
    error::ShieldedPoolError, instruction::InterfaceTransfer, N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};
use thiserror::Error;

use crate::CoSignScope;

/// The fee payer in every SPP transact account list.
pub const TRANSACT_PAYER_INDEX: usize = 0;
/// The signed `RingConfig` in an SPP ring transact account list.
pub const RING_TRANSACT_RING_CONFIG_INDEX: usize = 4;
/// Accounts before the input trees in an SPP ring transact account list.
pub const RING_TRANSACT_ACCOUNT_PREFIX_LEN: usize = RING_TRANSACT_RING_CONFIG_INDEX + 1;
/// The signed `RingConfig` in an SPP ring merge account list.
pub const RING_MERGE_RING_CONFIG_INDEX: usize = 2;
/// The funding signer in an SPP ring merge account list.
pub const RING_MERGE_PAYER_INDEX: usize = 3;

/// SOL takes the zero asset address, whose asset field is [`SOL_ASSET_FIELD`].
pub const SOL_ASSET_ADDRESS: [u8; 32] = [0u8; 32];

pub const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

/// A refused fold, `asset` the zero address for SOL.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PublicSlotError {
    #[error("an asset needs a public slot past the last")]
    TooManyAssets { asset: [u8; 32] },
    #[error("the net public amount of an asset exceeds a u64 magnitude")]
    AmountOverflow { asset: [u8; 32] },
    #[error("the interface transfers of an asset net to zero")]
    ZeroNet { asset: [u8; 32] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicLeg {
    pub transfer: InterfaceTransfer,
    /// The raw mint address, never an asset field, `None` for SOL.
    pub mint: Option<[u8; 32]>,
}

/// Pinocchio's `MAX_CPI_ACCOUNTS`, the ring program's ceiling for the SPP call.
pub const MAX_SPP_CPI_ACCOUNTS: usize = 128;

/// Assets in first-seen leg order, the fold SPP's `assign_public_amounts_and_assets` runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicSlots {
    slots: ArrayVec<PublicSlot, N_PUBLIC_SLOTS>,
    classes: CoSignScope,
}

impl Default for PublicSlots {
    fn default() -> Self {
        Self {
            slots: ArrayVec::new(),
            classes: CoSignScope::NONE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PublicSlot {
    asset: [u8; 32],
    net: i128,
    /// Sum of the asset's withdrawal legs, deposits excluded.
    gross: u128,
}

impl PublicSlots {
    pub fn fold<E: From<PublicSlotError>>(
        legs: impl IntoIterator<Item = Result<PublicLeg, E>>,
    ) -> Result<Self, E> {
        let mut slots = Self::default();
        for leg in legs {
            let PublicLeg { transfer, mint } = leg?;
            slots.classes = slots.classes
                | match transfer.is_deposit() {
                    true => CoSignScope::DEPOSITS,
                    false => CoSignScope::WITHDRAWALS,
                };
            slots.add(mint.unwrap_or(SOL_ASSET_ADDRESS), signed_amount(transfer))?;
        }
        if let Some(slot) = slots.slots.iter().find(|slot| slot.net == 0) {
            return Err(PublicSlotError::ZeroNet { asset: slot.asset }.into());
        }
        Ok(slots)
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub const fn classes(&self) -> CoSignScope {
        self.classes
    }

    /// Zero past the used slots.
    pub fn asset_fields(&self) -> Result<[[u8; 32]; N_PUBLIC_SLOTS], HasherError> {
        let mut fields = [[0u8; 32]; N_PUBLIC_SLOTS];
        for (field, slot) in fields.iter_mut().zip(&self.slots) {
            *field = match slot.asset {
                SOL_ASSET_ADDRESS => SOL_ASSET_FIELD,
                mint => hash_bytes(&mint)?,
            };
        }
        Ok(fields)
    }

    /// Zero past the used slots.
    pub fn amounts(&self) -> [i128; N_PUBLIC_SLOTS] {
        core::array::from_fn(|index| self.slots.get(index).map_or(0, |slot| slot.net))
    }

    /// Zero past the used slots.
    pub fn gross(&self) -> [u128; N_PUBLIC_SLOTS] {
        core::array::from_fn(|index| self.slots.get(index).map_or(0, |slot| slot.gross))
    }

    pub fn gross_fields(&self) -> [[u8; 32]; N_PUBLIC_SLOTS] {
        self.gross().map(|gross| right_align(&gross.to_be_bytes()))
    }

    /// Zero past the used slots.
    pub fn amount_fields(&self) -> Result<[[u8; 32]; N_PUBLIC_SLOTS], PublicSlotError> {
        let mut fields = [[0u8; 32]; N_PUBLIC_SLOTS];
        for (field, slot) in fields.iter_mut().zip(&self.slots) {
            *field = amount_field(slot.net)
                .map_err(|_| PublicSlotError::AmountOverflow { asset: slot.asset })?;
        }
        Ok(fields)
    }

    fn add(&mut self, asset: [u8; 32], amount: i128) -> Result<(), PublicSlotError> {
        match self.slots.iter_mut().find(|slot| slot.asset == asset) {
            Some(slot) => *slot = slot.credit(amount)?,
            None => self
                .slots
                .try_push(
                    PublicSlot {
                        asset,
                        net: 0,
                        gross: 0,
                    }
                    .credit(amount)?,
                )
                .map_err(|_| PublicSlotError::TooManyAssets { asset })?,
        }
        Ok(())
    }
}

impl PublicSlot {
    fn credit(self, amount: i128) -> Result<Self, PublicSlotError> {
        // The circuit range-checks each public amount to a u64 magnitude.
        let net = self
            .net
            .checked_add(amount)
            .filter(|net| u64::try_from(net.unsigned_abs()).is_ok())
            .ok_or(PublicSlotError::AmountOverflow { asset: self.asset })?;
        // A u128 sum of u64 legs never overflows.
        let gross = match amount.is_negative() {
            true => self.gross + amount.unsigned_abs(),
            false => self.gross,
        };
        Ok(Self { net, gross, ..self })
    }
}

pub fn signed_amount(transfer: InterfaceTransfer) -> i128 {
    let amount = i128::from(transfer.amount());
    if transfer.is_deposit() {
        amount
    } else {
        -amount
    }
}

/// Low half of the BN254 scalar modulus, above every u64 magnitude.
const MODULUS_LOW: u128 = match BN254_SCALAR_MODULUS_BE.last_chunk() {
    Some(low) => u128::from_be_bytes(*low),
    None => 0,
};
const _: () = assert!(MODULUS_LOW > u64::MAX as u128);

/// A signed public amount as a field element, a withdrawal as `q - |amount|`.
pub fn amount_field(amount: i128) -> Result<[u8; 32], ShieldedPoolError> {
    let magnitude = u64::try_from(amount.unsigned_abs())
        .map_err(|_| ShieldedPoolError::PublicAssetAmountOverflow)?;
    if !amount.is_negative() {
        return Ok(right_align(&magnitude.to_be_bytes()));
    }
    let mut field = BN254_SCALAR_MODULUS_BE;
    field[16..].copy_from_slice(&(MODULUS_LOW - u128::from(magnitude)).to_be_bytes());
    Ok(field)
}

/// `groups` is the window `settlement_accounts` returns.
pub fn settlement_mints<'a, T>(
    transfers: &'a [InterfaceTransfer],
    groups: &'a [T],
) -> impl Iterator<Item = Result<Option<&'a T>, ShieldedPoolError>> + 'a {
    let mut start = 0usize;
    transfers.iter().map(move |transfer| {
        let group = start
            .checked_add(transfer.settlement_account_count())
            .and_then(|end| groups.get(start..end))
            .ok_or(ShieldedPoolError::InvalidSettlementAccounts)?;
        start += group.len();
        transfer
            .mint_account_position()
            .map(|position| {
                group
                    .get(position)
                    .ok_or(ShieldedPoolError::InvalidSettlementAccounts)
            })
            .transpose()
    })
}

/// Position of the signer a deposit moves funds from, `None` for a withdrawal.
pub const fn funder_account_position(transfer: &InterfaceTransfer) -> Option<usize> {
    match transfer {
        InterfaceTransfer::SolDeposit { .. } => Some(1),
        InterfaceTransfer::SplDeposit { .. } => Some(2),
        InterfaceTransfer::SolWithdrawal { .. } | InterfaceTransfer::SplWithdrawal { .. } => None,
    }
}
