//! A transfer the wallet sealed and Ring RPC proves, pays and sends.

use custom_ring_interface::{CustomRingError, RingMode, RingRail};
use solana_address::Address;
use spr_client::{prover::transact::OwnerAuthorization, AsyncRpc, SettlementAccountValidation};
use spr_interface::shape::Shape;
use zolana_ring_client::rpc::{RelayProofInputs, RelayRail};
use zolana_ring_transaction::{RingDelivery, RingOutputRail};

use super::{
    anonymous::{check_anonymous_inputs, AnonymousExits, AnonymousSpend, HiddenOwner},
    audit::PresealedAudit,
    delivered, sealed, shape_keyed, Rail, RailKind, RingTransfer, Spend, Staged, TransferAuthority,
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
            rail: Relayed {
                proof_inputs: input.proof_inputs,
                fee_payer: input.fee_payer,
                owner_signature: None,
            },
        }
    }

    /// The anonymous rail's prepared owner signature over `SppProofInputs::message_hash`.
    #[must_use = "use the updated transfer"]
    pub fn with_owner_signature(mut self, signature: [u8; 64]) -> Self {
        self.rail.owner_signature = Some(signature);
        self
    }
}

impl Relayed<'_> {
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
        let sender = relayed.sender;
        let rail = |delivery| {
            RingOutputRail::sealed(
                relayed.tx_viewing_key.clone(),
                proof_inputs.external_data.salt,
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
                let co_signer = config.co_signer.as_ref().map(|co_signer| co_signer.signer);
                owner.check_signers(core::iter::once(self.fee_payer).chain(co_signer))?;
                check_anonymous_inputs(&proof_inputs, &sender)?;
                let exits = AnonymousExits {
                    transfers: &proof_inputs.external_data.interface_transfers,
                    hidden_owner: &owner.0,
                    named_owner: *exit_token_owner,
                };
                let parties = exits
                    .parties(client, self.fee_payer, co_signer.as_ref())
                    .await?;
                let spend = AnonymousSpend {
                    party_identities: parties.identities,
                    token_owner: parties.token_owner,
                    signer: OwnerAuthorization::Prepared {
                        owner: sender.signing_pubkey,
                        signature,
                    },
                    history: None,
                };
                (
                    rail(RingDelivery::Anonymous(plan.clone())),
                    Vec::new(),
                    Spend::Anonymous(Box::new(spend)),
                )
            }
            RelayRail::Confidential => {
                if config.mode == RingMode::Anonymous {
                    return Err(RingError::MissingAnonymousSigner);
                }
                if !shape_keyed(
                    RingRail::Confidential,
                    Shape::new(proof_inputs.input_utxos.len(), n_outputs),
                ) {
                    return Err(RingError::ShapeUnkeyed {
                        rail: RingRail::Confidential,
                    });
                }
                let owner_signers = proof_inputs.owner_signer_pubkeys()?;
                if config.has_policy && owner_signers.len() != 1 {
                    return Err(CustomRingError::OwnerSignerCount.into());
                }
                (
                    rail(delivered(n_outputs, RingRail::Confidential)?),
                    owner_signers,
                    Spend::Owner,
                )
            }
            RelayRail::Delegate { delegate } => {
                match config.delegate {
                    None => return Err(RingError::MissingDelegate),
                    Some(stored) if stored != *delegate => {
                        return Err(CustomRingError::UnauthorizedDelegate.into())
                    }
                    Some(_) => {}
                }
                if config.mode != RingMode::ConfidentialEscrow || !config.has_policy {
                    return Err(RingError::DelegateRequiresEscrow);
                }
                if !Shape::new(proof_inputs.input_utxos.len(), n_outputs).is_ring_authority() {
                    return Err(RingError::ShapeUnkeyed {
                        rail: RingRail::Delegate,
                    });
                }
                (
                    rail(delivered(n_outputs, RingRail::Delegate)?),
                    Vec::new(),
                    Spend::Delegate {
                        delegate: *delegate,
                    },
                )
            }
            RelayRail::Deposit | RelayRail::Merge => return Err(RingError::RelayRailUnserved),
        };
        Ok(Staged {
            proof_inputs,
            rail,
            sender,
            authority: TransferAuthority {
                owner: Some(relayed.nullifier_key.clone()),
            },
            owner_signers,
            interface_transfer_accounts: relayed.interface_transfer_accounts.clone(),
            spend,
            presealed: Some(PresealedAudit {
                message: auditor_message,
                eph_sk: relayed.audit_ephemeral_key.clone(),
            }),
        })
    }
}
