//! Gross public payments screened by policy version 4.
use crate::{CustomRingError, SettlementAccount};
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
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
    let mut fields = vec![
        crate::domain::field(crate::domain::WITHDRAWALS),
        right_align(&(legs.len() as u64).to_be_bytes()),
    ];
    for leg in legs {
        fields.extend([leg.owner, leg.asset, right_align(&leg.amount.to_be_bytes())]);
    }
    create_hash_chain_4_from_slice(&fields)
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
    let mut result = Vec::new();
    let mut groups = groups;
    let mut owners = spl_owners.iter();
    for transfer in transfers {
        let (group, rest) = groups
            .split_at_checked(transfer.settlement_account_count())
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        groups = rest;
        let payment = match transfer {
            InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => continue,
            InterfaceTransfer::SolWithdrawal { amount, .. } => {
                PolicyWithdrawal::new(group[1].address().as_array(), None, *amount)?
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
                PolicyWithdrawal::new(owner, Some(mint), *amount)?
            }
        };
        if payment.amount == 0 {
            return Err(CustomRingError::ZeroPublicLegAmount);
        }
        result.push(payment);
    }
    if !groups.is_empty() {
        return Err(CustomRingError::InvalidSettlementAccounts);
    }
    Ok(result)
}
