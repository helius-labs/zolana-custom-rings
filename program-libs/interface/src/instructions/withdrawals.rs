//! Gross public payments the policy screens.
//!
//! A rule reads a withdrawal's real owner and mint, so each comes from the live settlement account
//! and the statement binds the result as `withdrawal_hash`. A frame's owner off its token account refuses.
//!
//! Read after `program-libs/interface/src/codec/spp.rs`. Read before `program-libs/interface/src/instructions/anonymous_exit.rs`,
//! `prover/circuits/policy/withdrawals.go`.

use crate::{CustomRingError, SettlementAccount};
use spr_hasher::{
    hash_chain::create_hash_chain_4,
    primitives::{hash_bytes, right_align, solana_owner_identity},
    HasherError,
};
use spr_interface::{
    instruction::InterfaceTransfer, SOL_ASSET_FIELD, SPL_TOKEN_2022_PROGRAM_ID,
    SPL_TOKEN_PROGRAM_ID,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolicyWithdrawal {
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

impl PolicyWithdrawal {
    pub fn new(
        owner: &[u8; 32],
        mint: Option<&[u8; 32]>,
        amount: u64,
    ) -> Result<Self, HasherError> {
        Ok(Self {
            owner: solana_owner_identity(owner)?,
            asset: match mint {
                Some(mint) => hash_bytes(mint)?,
                None => SOL_ASSET_FIELD,
            },
            amount,
        })
    }
}

/// Order and count matter, even when two legs pay the same owner and asset.
pub fn policy_withdrawal_hash(legs: &[PolicyWithdrawal]) -> Result<[u8; 32], HasherError> {
    let head = [
        crate::domain::field(crate::domain::WITHDRAWALS),
        right_align(&(legs.len() as u64).to_be_bytes()),
    ];
    let amounts: Vec<[u8; 32]> = legs
        .iter()
        .map(|leg| right_align(&leg.amount.to_be_bytes()))
        .collect();
    let fields = legs
        .iter()
        .zip(&amounts)
        .flat_map(|(leg, amount)| [&leg.owner, &leg.asset, amount]);
    create_hash_chain_4(head.iter().chain(fields))
}

pub fn spl_withdrawal_count(transfers: &[InterfaceTransfer]) -> usize {
    transfers
        .iter()
        .filter(|t| matches!(t, InterfaceTransfer::SplWithdrawal { .. }))
        .count()
}

/// Validate instruction metadata against live settlement accounts before proof verification.
/// Deposits are skipped; SPL screening names the token owner, not the token account.
pub fn policy_withdrawals<A: SettlementAccount>(
    transfers: &[InterfaceTransfer],
    groups: &[A],
    spl_owners: &[[u8; 32]],
) -> Result<Vec<PolicyWithdrawal>, CustomRingError> {
    if spl_owners.len() != spl_withdrawal_count(transfers) {
        return Err(CustomRingError::InvalidSettlementAccounts);
    }
    let mut result: Vec<PolicyWithdrawal> = Vec::with_capacity(transfers.len());
    // Index aligned with `result`, a repeated owner or mint reuses the identity its first leg derived.
    let mut keys: Vec<(&[u8; 32], Option<&[u8; 32]>)> = Vec::with_capacity(transfers.len());
    let mut groups = groups;
    let mut owners = spl_owners.iter();
    for transfer in transfers {
        let (group, rest) = groups
            .split_at_checked(transfer.settlement_account_count())
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        groups = rest;
        let (owner, mint, amount) = match transfer {
            InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => continue,
            InterfaceTransfer::SolWithdrawal { amount, .. } => {
                (group[1].address().as_array(), None, *amount)
            }
            InterfaceTransfer::SplWithdrawal { amount, .. } => {
                let account = &group[3];
                if ![SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID]
                    .contains(account.owner().as_array())
                {
                    return Err(CustomRingError::AnonymousExitTokenAccountInvalid);
                }
                let token = account.token_account()?;
                let mint = group[transfer
                    .mint_account_position()
                    .ok_or(CustomRingError::InvalidSettlementAccounts)?]
                .address()
                .as_array();
                let owner = owners
                    .next()
                    .ok_or(CustomRingError::InvalidSettlementAccounts)?;
                if &token.mint != mint || token.control.owner() != owner {
                    return Err(CustomRingError::InvalidSettlementAccounts);
                }
                (owner, Some(mint), *amount)
            }
        };
        if amount == 0 {
            return Err(CustomRingError::ZeroPublicLegAmount);
        }
        let identity = match keys.iter().position(|(seen, _)| *seen == owner) {
            Some(index) => result[index].owner,
            None => solana_owner_identity(owner)?,
        };
        let asset = match mint {
            None => SOL_ASSET_FIELD,
            Some(mint) => match keys.iter().position(|(_, seen)| *seen == Some(mint)) {
                Some(index) => result[index].asset,
                None => hash_bytes(mint)?,
            },
        };
        keys.push((owner, mint));
        result.push(PolicyWithdrawal {
            owner: identity,
            asset,
            amount,
        });
    }
    if !groups.is_empty() {
        return Err(CustomRingError::InvalidSettlementAccounts);
    }
    Ok(result)
}
