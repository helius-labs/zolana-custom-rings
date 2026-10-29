//! The confidential rail.

use custom_ring_interface::{CustomRingError, RingMode, RingRail};
use spr_client::{AsyncRpc, OwnerAuthorization, SettlementAccountValidation};
use spr_interface::shape::Shape;
use spr_keypair::{NullifierKey, ShieldedAddress, SigningKey};
use spr_program::instruction::TransactInterfaceTransferAccounts;
use spr_transaction::instructions::transact::ConfidentialTransaction;
use zolana_ring_transaction::{RingDelivery, RingOutputRail};

use super::{
    canonical_shape, delivered, pad_under_rail, sealed, shape_keyed, transaction_key, Rail,
    RailKind, RingSender, RingTransfer, Spend, Staged, TransferAuthority,
};
use crate::{CustomRing, CustomRingConfig, RingError};

/// The sender's spends, it signs the assembled Solana transaction itself or inside the proof.
pub struct Owner<'a> {
    pub(super) sender: &'a dyn RingSender,
    pub(super) nullifier_key: Option<&'a NullifierKey>,
    pub(super) transaction: ConfidentialTransaction,
    pub(super) interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub(super) shape: Option<Shape>,
    pub(super) in_proof_owner: Option<&'a SigningKey>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    /// Only transaction keys and the address are read, the signing key may live elsewhere.
    pub sender: &'a dyn RingSender,
    /// Completes the real inputs, `None` only for an all-padding transfer.
    pub nullifier_key: Option<&'a NullifierKey>,
    pub transaction: ConfidentialTransaction,
}

pub type CustomRingTransfer<'a> = RingTransfer<Owner<'a>>;

impl sealed::Sealed for Owner<'_> {}

impl Rail for Owner<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Owner(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            co_signer: None,
            rail: Owner {
                sender: input.sender,
                nullifier_key: input.nullifier_key,
                transaction: input.transaction,
                interface_transfer_accounts: Vec::new(),
                shape: None,
                in_proof_owner: None,
            },
        }
    }

    /// The sender's signing key signs inside the proof, any fee payer sends the transaction.
    #[must_use = "use the updated transfer"]
    pub fn with_in_proof_owner(mut self, signer: &'a SigningKey) -> Self {
        self.rail.in_proof_owner = Some(signer);
        self
    }

    #[must_use = "use the updated transfer"]
    pub fn with_interface_transfer_accounts(
        mut self,
        accounts: Vec<TransactInterfaceTransferAccounts>,
    ) -> Self {
        self.rail.interface_transfer_accounts = accounts;
        self
    }

    /// Unset, staging pads to the smallest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        if !shape_keyed(RingRail::Confidential, shape) {
            return Err(RingError::ShapeUnkeyed {
                rail: RingRail::Confidential,
            });
        }
        self.rail.shape = Some(shape);
        Ok(self)
    }
}

impl Owner<'_> {
    /// The rail pads under its own blinding seed, a caller never pads.
    pub(super) fn shape(&self, sender: &ShieldedAddress) -> Result<Shape, RingError> {
        match self.shape {
            Some(shape) => Ok(shape),
            None => canonical_shape(&self.transaction, sender),
        }
    }

    pub(super) fn check_settlement_accounts(&self) -> Result<(), RingError> {
        let transfers: Vec<_> = self
            .transaction
            .interface_transfers()?
            .into_iter()
            .map(|transfer| transfer.interface_transfer())
            .collect();
        SettlementAccountValidation {
            transfers: &transfers,
            accounts: &self.interface_transfer_accounts,
        }
        .validate()?;
        Ok(())
    }

    /// The anonymous rail takes no SPP signer but the payer.
    pub(super) fn check_payer_funds_deposits(&self) -> Result<(), RingError> {
        let payer = self.transaction.payer();
        let transfers = self.transaction.interface_transfers()?;
        let mut funders = transfers
            .iter()
            .zip(&self.interface_transfer_accounts)
            .filter_map(|(transfer, accounts)| match accounts {
                TransactInterfaceTransferAccounts::Sol(sol) => {
                    transfer.is_deposit().then_some(sol.recipient)
                }
                TransactInterfaceTransferAccounts::SplDeposit(spl) => Some(spl.token_authority),
                TransactInterfaceTransferAccounts::SplWithdrawal(_) => None,
            });
        match funders.any(|funder| funder != payer) {
            true => Err(CustomRingError::InvalidAnonymousSigner.into()),
            false => Ok(()),
        }
    }

    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        _ring: CustomRing,
        _client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        if config.mode == RingMode::Anonymous {
            return Err(RingError::MissingAnonymousSigner);
        }
        let sender = self.sender.address()?;
        self.check_settlement_accounts()?;
        let shape = self.shape(&sender)?;
        let transaction = self.transaction.clone();
        let delivery = match (
            delivered(shape.n_outputs(), RingRail::Confidential)?,
            self.in_proof_owner,
        ) {
            (_, Some(_)) => RingDelivery::Owned,
            (delivery, None) => delivery,
        };
        let first_nullifier = *transaction.first_nullifier();
        let rail = RingOutputRail::new(transaction_key(self.sender, first_nullifier)?, delivery);
        let transaction = pad_under_rail(transaction, &rail, shape, &sender)?;
        let proof_inputs = rail.encrypt(transaction, &sender)?;
        let (owner_signers, spend) = match self.in_proof_owner {
            Some(signer) => {
                if signer.pubkey() != sender.signing_pubkey {
                    return Err(RingError::InProofOwnerMismatch);
                }
                (
                    Vec::new(),
                    Spend::InProofOwner(OwnerAuthorization::SigningKey(signer)),
                )
            }
            None => (proof_inputs.owner_signer_pubkeys()?, Spend::Owner),
        };
        if config.has_policy && self.in_proof_owner.is_none() && owner_signers.len() != 1 {
            return Err(CustomRingError::OwnerSignerCount.into());
        }
        Ok(Staged {
            owner_signers,
            proof_inputs,
            rail,
            sender,
            authority: TransferAuthority {
                owner: self.nullifier_key.cloned(),
            },
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            spend,
            presealed: None,
        })
    }
}
