//! The anonymous rail's exit accounts and named parties, one reading for the program and the SDKs.
//!
//! A hidden sender's exit must name one key the proof can hold apart from the hidden owner. A SOL
//! destination with data or a program owner, or a token account with a second authority or a keypair
//! address, could name that owner behind another key, so each refuses.
//!
//! Read after `program-libs/interface/src/instructions/withdrawals.rs`. Read before `program-libs/interface/src/instructions/cosign.rs`,
//! `programs/custom-ring/src/instructions/transfer/accounts.rs`.

use solana_address::Address;
use spl_token_2022_interface::{extension::PodStateWithExtensions, pod::PodAccount};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{
    instruction::InterfaceTransfer, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_PROGRAM_ID,
};

use crate::{CustomRingError, SYSTEM_PROGRAM_ID};

pub const ANONYMOUS_PARTIES: usize = 2 + crate::cosign::MAX_CO_SIGNERS;

/// The recipient in a SOL withdrawal's settlement group.
const SOL_WITHDRAWAL_RECIPIENT: usize = 1;
/// The user token account in an SPL withdrawal's settlement group.
const SPL_WITHDRAWAL_TOKEN_ACCOUNT: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenAccountControl {
    SoleOwner([u8; 32]),
    /// A delegate or a close authority acts beside the owner.
    Shared([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccountState {
    pub mint: [u8; 32],
    pub control: TokenAccountControl,
}

#[derive(Clone, Copy, Debug)]
pub enum AnonymousExitDestination<'a> {
    Sol {
        recipient: &'a Address,
        owner: &'a Address,
        data_len: usize,
    },
    Spl {
        token_account: &'a Address,
        control: &'a TokenAccountControl,
    },
}

pub trait SettlementAccount {
    fn address(&self) -> &Address;
    fn owner(&self) -> &Address;
    fn data_len(&self) -> usize;
    fn token_account(&self) -> Result<TokenAccountState, CustomRingError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousParties<'a> {
    pub payer: &'a [u8; 32],
    pub co_signers: &'a [Address],
    /// In leg order, a key another party already names takes no cell.
    pub funders: &'a [[u8; 32]],
    pub exit_destination: Option<&'a [u8; 32]>,
}

impl TokenAccountState {
    pub fn unpack(data: &[u8]) -> Result<Self, CustomRingError> {
        let state = PodStateWithExtensions::<PodAccount>::unpack(data)
            .map_err(|_| CustomRingError::AnonymousExitTokenAccountInvalid)?;
        if state.base.state != SPL_TOKEN_ACCOUNT_INITIALIZED {
            return Err(CustomRingError::AnonymousExitTokenAccountInvalid);
        }
        let owner = state.base.owner.to_bytes();
        let control = if state.base.delegate.is_none() && state.base.close_authority.is_none() {
            TokenAccountControl::SoleOwner(owner)
        } else {
            TokenAccountControl::Shared(owner)
        };
        Ok(Self {
            mint: state.base.mint.to_bytes(),
            control,
        })
    }
}

impl TokenAccountControl {
    pub fn owner(&self) -> &[u8; 32] {
        match self {
            Self::SoleOwner(owner) | Self::Shared(owner) => owner,
        }
    }
}

impl<'a> AnonymousExitDestination<'a> {
    /// The key the anonymous audit proof proves apart from the hidden owner.
    pub fn named_key(self) -> Result<&'a [u8; 32], CustomRingError> {
        match self {
            // Data or a program owner could name a second key.
            Self::Sol {
                recipient,
                owner,
                data_len,
            } => {
                if *owner == SYSTEM_PROGRAM_ID && data_len == 0 {
                    Ok(recipient.as_array())
                } else {
                    Err(CustomRingError::AnonymousExitAccountHasData)
                }
            }
            // The proof binds the owner only, a keypair address could be the hidden owner's.
            Self::Spl { token_account, .. } if token_account.is_on_curve() => {
                Err(CustomRingError::AnonymousExitTokenAccountOnCurve)
            }
            Self::Spl {
                control: TokenAccountControl::SoleOwner(owner),
                ..
            } => Ok(owner),
            Self::Spl {
                control: TokenAccountControl::Shared(_),
                ..
            } => Err(CustomRingError::AnonymousExitTokenAccountShared),
        }
    }
}

/// The one key every withdrawal names, `None` without a withdrawal.
pub fn anonymous_exit_destination<A: SettlementAccount>(
    transfers: &[InterfaceTransfer],
    groups: &[A],
) -> Result<Option<[u8; 32]>, CustomRingError> {
    let mut start = 0usize;
    let mut exit: Option<[u8; 32]> = None;
    for transfer in transfers {
        let end = start
            .checked_add(transfer.settlement_account_count())
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        let group = groups
            .get(start..end)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        start = end;
        let named = match transfer {
            InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => continue,
            InterfaceTransfer::SolWithdrawal { .. } => {
                let recipient = settlement_at(group, SOL_WITHDRAWAL_RECIPIENT)?;
                *AnonymousExitDestination::Sol {
                    recipient: recipient.address(),
                    owner: recipient.owner(),
                    data_len: recipient.data_len(),
                }
                .named_key()?
            }
            InterfaceTransfer::SplWithdrawal { .. } => {
                let account = settlement_at(group, SPL_WITHDRAWAL_TOKEN_ACCOUNT)?;
                let token_program = account.owner().as_array();
                if *token_program != SPL_TOKEN_PROGRAM_ID
                    && *token_program != SPL_TOKEN_2022_PROGRAM_ID
                {
                    return Err(CustomRingError::AnonymousExitTokenAccountInvalid);
                }
                let control = account.token_account()?.control;
                *AnonymousExitDestination::Spl {
                    token_account: account.address(),
                    control: &control,
                }
                .named_key()?
            }
        };
        match exit {
            Some(seen) if seen != named => {
                return Err(CustomRingError::AnonymousExitDestinationsDiffer)
            }
            _ => exit = Some(named),
        }
    }
    Ok(exit)
}

impl AnonymousParties<'_> {
    /// Solana owner identities, zero for an absent party.
    ///
    /// The circuit holds the hidden owner apart from every nonzero cell, a public signature would
    /// name it otherwise. A funder signs in public like a co-signer and shares the same cells, the
    /// statement's layout stays fixed and a transfer pays for no cell it leaves empty. The payer
    /// funding its own leg leaves the cells as they were.
    pub fn identities(&self) -> Result<[[u8; 32]; ANONYMOUS_PARTIES], CustomRingError> {
        let identity = |party: &[u8; 32]| -> Result<[u8; 32], CustomRingError> {
            Ok(solana_owner_identity(party)?)
        };
        let mut identities = [[0u8; 32]; ANONYMOUS_PARTIES];
        identities[0] = identity(self.payer)?;
        let (shared, exit) = identities[1..].split_at_mut(crate::cosign::MAX_CO_SIGNERS);
        let mut named = 0;
        let mut seat = |party: [u8; 32]| -> Result<(), CustomRingError> {
            let cell = shared
                .get_mut(named)
                .ok_or(CustomRingError::TooManyAnonymousParties)?;
            *cell = party;
            named += 1;
            Ok(())
        };
        for co_signer in self.co_signers {
            seat(identity(co_signer.as_array())?)?;
        }
        for (position, funder) in self.funders.iter().enumerate() {
            let named_already = funder == self.payer
                || self
                    .co_signers
                    .iter()
                    .any(|signer| signer.as_array() == funder)
                || self.funders[..position].contains(funder);
            if !named_already {
                seat(identity(funder)?)?;
            }
        }
        if let (Some(cell), Some(destination)) = (exit.first_mut(), self.exit_destination) {
            *cell = identity(destination)?;
        }
        Ok(identities)
    }
}

fn settlement_at<A>(group: &[A], position: usize) -> Result<&A, CustomRingError> {
    group
        .get(position)
        .ok_or(CustomRingError::InvalidSettlementAccounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(party: &[u8; 32]) -> [u8; 32] {
        solana_owner_identity(party).unwrap()
    }

    #[test]
    fn a_funder_takes_a_free_cell_and_a_named_key_takes_none() {
        let (payer, co_signer, funder, exit) = ([1; 32], [2; 32], [3; 32], [4; 32]);
        let co_signers = [Address::new_from_array(co_signer)];
        let identities = AnonymousParties {
            payer: &payer,
            co_signers: &co_signers,
            funders: &[payer, funder, co_signer, funder],
            exit_destination: Some(&exit),
        }
        .identities()
        .unwrap();
        let mut expected = [[0; 32]; ANONYMOUS_PARTIES];
        expected[0] = cell(&payer);
        expected[1] = cell(&co_signer);
        expected[2] = cell(&funder);
        expected[ANONYMOUS_PARTIES - 1] = cell(&exit);
        assert_eq!(identities, expected);
    }

    #[test]
    fn parties_past_the_cells_are_refused() {
        let payer = [1; 32];
        let co_signers: Vec<Address> = (0..crate::cosign::MAX_CO_SIGNERS as u8)
            .map(|index| Address::new_from_array([10 + index; 32]))
            .collect();
        let parties = |funders: &[[u8; 32]]| {
            AnonymousParties {
                payer: &payer,
                co_signers: &co_signers,
                funders,
                exit_destination: None,
            }
            .identities()
        };
        assert!(parties(&[payer]).is_ok());
        assert_eq!(
            parties(&[[3; 32]]),
            Err(CustomRingError::TooManyAnonymousParties)
        );
    }
}
