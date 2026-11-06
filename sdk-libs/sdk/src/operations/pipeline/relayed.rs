//! A transfer the wallet sealed and Ring RPC proves, pays and sends.

use custom_ring_interface::{CustomRingError, RingMode, RingRail};
use solana_address::Address;
use spr_client::{prover::transact::OwnerAuthorization, AsyncRpc, SettlementAccountValidation};
use spr_interface::shape::Shape;
use zolana_ring_client::rpc::{RelayProofInputs, RelayRail};
use zolana_ring_transaction::{RingDelivery, RingOutputRail};

use super::{
    anonymous::{
        check_anonymous_inputs, public_co_owners, AnonymousExits, AnonymousSpend, HiddenOwner,
        OwnerExposure,
    },
    audit::PresealedAudit,
    delegate::delegate_rail,
    public_owners::check_zero_key_inputs,
    sealed, shape_keyed, ApprovalDisclosure, CoOwner, CoOwnerKey, DeliveredRail, Rail, RailKind,
    RingTransfer, SealRow, Spend, Staged, TransferAuthority,
};
use crate::{CustomRing, CustomRingConfig, RingError};

pub struct Relayed<'a> {
    proof_inputs: &'a RelayProofInputs,
    fee_payer: Address,
    owner_signature: Option<[u8; 64]>,
}

pub struct RelayedTransferInput<'a> {
    pub ring: CustomRing,
    pub proof_inputs: &'a RelayProofInputs,
    /// The SPP payer.
    pub fee_payer: Address,
}

pub type RelayedTransfer<'a> = RingTransfer<Relayed<'a>>;

impl sealed::Sealed for Relayed<'_> {}

impl Rail for Relayed<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Relayed(self)
    }
}

impl<'a> RingTransfer<Relayed<'a>> {
    pub fn relayed(input: RelayedTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            co_signers: Vec::new(),
            priority_fee: None,
            rail: Relayed {
                proof_inputs: input.proof_inputs,
                fee_payer: input.fee_payer,
                owner_signature: None,
            },
            list_salts: Vec::new(),
            approval: ApprovalDisclosure::None,
            seal_row: None,
        }
    }

    /// The prepared owner signature over `SppProofInputs::message_hash`, the owner signs no transaction.
    #[must_use = "use the updated transfer"]
    pub fn with_owner_signature(mut self, signature: [u8; 64]) -> Self {
        self.rail.owner_signature = Some(signature);
        self
    }
}

impl Relayed<'_> {
    pub(super) fn approval_blinder(&self) -> Option<[u8; 32]> {
        self.proof_inputs.approval_blinder
    }

    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        ring: CustomRing,
        client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        let relayed = self.proof_inputs;
        if relayed.ring_program_id != ring.program_id() {
            return Err(RingError::ForeignRing(relayed.ring_program_id));
        }
        if relayed.nullifier_key.pubkey()? != relayed.sender.nullifier_pubkey {
            return Err(RingError::NullifierKeyMismatch);
        }
        if *relayed.tx_viewing_key.pubkey().as_bytes() != relayed.external_data.tx_viewing_pk {
            return Err(RingError::RelayViewingKeyMismatch);
        }
        let mut proof_inputs = relayed.spp_proof_inputs(self.fee_payer);
        let auditor_message = proof_inputs
            .external_data
            .messages
            .pop()
            .ok_or(RingError::RelayAuditorMessage)?;
        SettlementAccountValidation {
            transfers: &proof_inputs
                .external_data
                .interface_transfers
                .iter()
                .map(|transfer| transfer.interface_transfer())
                .collect::<Vec<_>>(),
            accounts: &relayed.interface_transfer_accounts,
        }
        .validate()?;
        // The fee payer signs whatever the relay sends, a leg naming it would fund the wallet's note
        // from the relay.
        if relayed
            .deposit_funders()
            .any(|funder| funder == self.fee_payer)
        {
            return Err(RingError::RelayFeePayerFundsDeposit);
        }
        let sender = relayed.sender;
        let rail = |delivery| {
            RingOutputRail::sealed(
                relayed.tx_viewing_key.clone(),
                proof_inputs.external_data.salt,
                config.auditor_pubkey,
                delivery,
            )
        };
        let n_outputs = proof_inputs.output_utxos.len();
        let (rail, owner_signers, spend) = match &relayed.rail {
            RelayRail::Anonymous {
                plan,
                exit_token_owner,
            } => {
                if config.mode != RingMode::Anonymous {
                    return Err(RingError::NotAnonymousRing);
                }
                let signature = self
                    .owner_signature
                    .ok_or(RingError::MissingAnonymousSigner)?;
                let owner = HiddenOwner::of(&sender.signing_pubkey)?;
                owner.check_signers([self.fee_payer])?;
                owner.check_signers(relayed.deposit_funders())?;
                check_anonymous_inputs(&proof_inputs, &sender, OwnerExposure::Refused)?;
                let exits = AnonymousExits {
                    transfers: &proof_inputs.external_data.interface_transfers,
                    hidden_owner: Some(owner.0),
                    named_owner: *exit_token_owner,
                };
                let exits = exits.owners(client).await?;
                let spend = AnonymousSpend {
                    token_owner: exits.token_owner,
                    signer: OwnerAuthorization::Prepared {
                        owner: sender.signing_pubkey,
                        signature,
                    },
                };
                (
                    rail(RingDelivery::Anonymous(plan.clone())),
                    public_co_owners(&proof_inputs, &sender)?,
                    Spend::Anonymous(Box::new(spend)),
                )
            }
            RelayRail::Confidential => {
                if config.mode == RingMode::Anonymous {
                    return Err(RingError::MissingAnonymousSigner);
                }
                check_zero_key_inputs(&proof_inputs.input_utxos, &sender.signing_pubkey)?;
                if !shape_keyed(
                    RingRail::Confidential,
                    Shape::new(proof_inputs.input_utxos.len(), n_outputs),
                ) {
                    return Err(RingError::ShapeUnkeyed {
                        rail: RingRail::Confidential,
                    });
                }
                let delivery = DeliveredRail {
                    outputs: n_outputs,
                    rail: RingRail::Confidential,
                }
                .delivery()?;
                let signature = self
                    .owner_signature
                    .ok_or(RingError::MissingInProofOwnerSignature)?;
                (
                    rail(delivery),
                    public_co_owners(&proof_inputs, &sender)?,
                    Spend::InProofOwner(OwnerAuthorization::Prepared {
                        owner: sender.signing_pubkey,
                        signature,
                    }),
                )
            }
            RelayRail::Deposit { plan } => {
                // No owner signs a deposit, a real input here would spend unauthorized.
                if !proof_inputs
                    .input_utxos
                    .iter()
                    .all(|input| input.is_dummy())
                {
                    return Err(RingError::DepositSpendsNote);
                }
                match (config.mode, plan) {
                    (RingMode::Anonymous, Some(plan)) => (
                        rail(RingDelivery::Anonymous(plan.clone())),
                        Vec::new(),
                        Spend::PublicOwners,
                    ),
                    (RingMode::Confidential, None) => {
                        let delivery = DeliveredRail {
                            outputs: n_outputs,
                            rail: RingRail::Confidential,
                        }
                        .delivery()?;
                        (rail(delivery), Vec::new(), Spend::Owner)
                    }
                    (RingMode::Anonymous, None) => return Err(RingError::AnonymousDepositUntagged),
                    (RingMode::Confidential, Some(_)) => return Err(RingError::NotAnonymousRing),
                }
            }
            RelayRail::Delegate { delegate, plan } => {
                match config.delegate {
                    None => return Err(RingError::MissingDelegate),
                    Some(stored) if stored != *delegate => {
                        return Err(CustomRingError::UnauthorizedDelegate.into())
                    }
                    Some(_) => {}
                }
                let ring_rail = delegate_rail(config.mode);
                if !Shape::new(proof_inputs.input_utxos.len(), n_outputs).is_ring_authority() {
                    return Err(RingError::ShapeUnkeyed { rail: ring_rail });
                }
                let delivery = match plan {
                    Some(plan) => RingDelivery::Anonymous(plan.clone()),
                    None => DeliveredRail {
                        outputs: n_outputs,
                        rail: ring_rail,
                    }
                    .delivery()?,
                };
                (
                    rail(delivery),
                    Vec::new(),
                    Spend::Delegate {
                        delegate: *delegate,
                        rail: ring_rail,
                    },
                )
            }
        };
        Ok(Staged {
            proof_inputs,
            rail,
            sender,
            authority: TransferAuthority {
                owner: Some(relayed.nullifier_key.clone()),
                co_owners: relayed
                    .co_owners
                    .iter()
                    .map(|co_owner| {
                        CoOwnerKey::of(&CoOwner {
                            owner: co_owner.owner,
                            nullifier_key: &co_owner.nullifier_key,
                        })
                    })
                    .collect::<Result<_, RingError>>()?,
            },
            owner_signers,
            interface_transfer_accounts: relayed.interface_transfer_accounts.clone(),
            spend,
            presealed: Some(PresealedAudit {
                message: auditor_message,
                row: SealRow::of(relayed.wide_owners),
            }),
            list_salts: relayed.list_salts.clone(),
        })
    }
}
