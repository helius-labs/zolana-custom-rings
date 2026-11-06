//! A spend whose owners all sign the transaction, the one path that spends a wallet's zero-key note.

use custom_ring_interface::RingMode;
use solana_address::Address;
use spr_interface::shape::Shape;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::PublicKey;
use spr_transaction::{utxo::SppProofInputUtxo, TransactionError};
use zolana_ring_transaction::{RingDelivery, RingOutputRail};

use super::{
    anonymous::{
        anonymous_plan, check_payment_ring, payment_salts, AnonymousPayment, SenderChange,
    },
    canonical_shape,
    owner::Owner,
    pad_under_rail, sealed, transaction_key, Rail, RailKind, RingTransfer, Spend, Staged,
};
use crate::{CustomRing, CustomRingConfig, RingError};

/// The named wallet becomes public, recipients stay hidden on an anonymous ring.
pub struct PublicOwners<'a> {
    pub(super) owner: Owner<'a>,
    wallet: Address,
    /// An unenrolled wallet's only key on a tracking root.
    zero_key_change: bool,
    /// In declared order, the order of their ring outputs.
    payments: Vec<AnonymousPayment>,
}

pub type PublicOwnerTransfer<'a> = RingTransfer<PublicOwners<'a>>;

impl sealed::Sealed for PublicOwners<'_> {}

impl Rail for PublicOwners<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::PublicOwners(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    /// `wallet` signs in public and may spend its zero-key notes, nothing selects them for it.
    ///
    /// A program owner names its PDA here and CPI signs, any [`super::RingSender`] whose address
    /// carries `PublicKey::from_pda` holds its keys. The program requires the owner's signer flag on
    /// either key class, only hidden authorization needs an Ed25519 key.
    pub fn spend_public(self, wallet: Address) -> RingTransfer<PublicOwners<'a>> {
        RingTransfer {
            ring: self.ring,
            co_signers: self.co_signers,
            priority_fee: self.priority_fee,
            rail: PublicOwners {
                owner: self.rail,
                wallet,
                zero_key_change: false,
                payments: Vec::new(),
            },
            list_salts: self.list_salts,
            approval: self.approval,
            seal_row: self.seal_row,
        }
    }
}

impl RingTransfer<PublicOwners<'_>> {
    /// For a wallet with no tracking row, a keyed change refuses at the output check.
    #[must_use = "use the updated transfer"]
    pub fn with_zero_key_change(mut self) -> Self {
        self.rail.zero_key_change = true;
        self
    }

    /// Every ring output owner other than the wallet is paid here, before the transaction is padded.
    pub fn with_payment(mut self, payment: AnonymousPayment) -> Result<Self, RingError> {
        check_payment_ring(&payment, self.ring)?;
        payment.add_to(&mut self.rail.owner.transaction)?;
        self.rail.payments.push(payment);
        Ok(self)
    }

    /// Unset, staging pads to the smallest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        if !shape.is_supported() {
            return Err(TransactionError::UnsupportedShape {
                n_in: shape.n_inputs(),
                n_out: shape.n_outputs(),
            }
            .into());
        }
        self.rail.owner.shape = Some(shape);
        Ok(self)
    }
}

impl PublicOwners<'_> {
    pub(super) async fn stage(
        &self,
        ring: CustomRing,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        let keys = self.owner.sender;
        let mut sender = keys.address()?;
        if self.zero_key_change {
            sender.nullifier_pubkey = ZERO_NULLIFIER_PUBKEY;
        }
        let named = sender.solana_address()?;
        if named != self.wallet {
            return Err(RingError::PublicSpendWalletMismatch {
                named: self.wallet,
                sender: named,
            });
        }
        if self.owner.in_proof_owner.is_some() {
            return Err(RingError::PublicSpendInProofOwner);
        }
        if config.mode != RingMode::Anonymous {
            return self.owner.stage_signers(sender, config);
        }
        self.owner.check_settlement_accounts()?;
        let transaction = SenderChange {
            shape: self.owner.shape,
            sender: &sender,
            ring: ring.program_id(),
        }
        .ensure(self.owner.transaction.clone())?;
        let shape = match self.owner.shape {
            Some(shape) => shape,
            None => canonical_shape(&transaction, &sender)?,
        };
        let first_nullifier = *transaction.first_nullifier();
        let rail = RingOutputRail::new(
            transaction_key(keys, first_nullifier)?,
            config.auditor_pubkey,
            RingDelivery::Anonymous(Box::new(anonymous_plan(&self.payments))),
        );
        let transaction = pad_under_rail(transaction, &rail, shape, &sender)?;
        let proof_inputs = rail.encrypt(transaction, &sender)?;
        Ok(Staged {
            authority: self.owner.authority()?,
            owner_signers: proof_inputs.owner_signer_pubkeys()?,
            proof_inputs,
            rail,
            sender,
            interface_transfer_accounts: self.owner.interface_transfer_accounts.clone(),
            spend: Spend::PublicOwners,
            presealed: None,
            list_salts: payment_salts(&self.payments)?,
        })
    }
}

/// Only a spend that named its wallet takes a zero-key note of that wallet, an address slot spends no note.
pub(super) fn check_zero_key_inputs(
    inputs: &[SppProofInputUtxo],
    owner: &PublicKey,
) -> Result<(), RingError> {
    match inputs.iter().position(|input| {
        !input.is_dummy()
            && !input.is_address()
            && input.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY
            && input.utxo.owner == *owner
    }) {
        Some(index) => Err(RingError::ZeroKeyInputUnnamed { index }),
        None => Ok(()),
    }
}
