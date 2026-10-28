//! The anonymous rail's slots, the sender's change leading at output 0, one body per
//! recipient output and the sender bundle after them.

use rand::{rngs::OsRng, RngCore};
use solana_address::Address;
use spr_interface::MAX_OUTPUTS;
use spr_keypair::{
    random_blinding,
    viewing_key::{Salt, ViewTag},
    ShieldedAddress, ViewingKey, X25519Pubkey,
};
use spr_transaction::{
    instructions::transact::SppProofInputs, Data, Mint, SppProofOutputUtxo, TransactionError,
};

use crate::{
    anonymous_body::{OutputBlindings, DUMMY_RECIPIENT_VIEWING_PK, RECIPIENT_BODY_LEN},
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, RingRailError,
    UnverifiedRecipientPlaintext, UnverifiedSenderPlaintext, VerifiedRecipientPlaintext,
    VerifiedSenderPlaintext,
};

/// One recipient body, its tag picked by the spec view tag selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaggedPayment {
    /// The recipient's viewing key the body is sealed to.
    pub recipient: X25519Pubkey,
    pub tag: ViewTag,
}

/// The tags of one anonymous transfer, its payments in declared order.
#[must_use]
#[derive(Clone, Debug)]
pub struct AnonymousPlan {
    sender_tag: ViewTag,
    payments: Vec<TaggedPayment>,
    /// Drawn ahead, every encoding of a dummy slot publishes one tag.
    dummy_tags: [ViewTag; MAX_OUTPUTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousSlot {
    /// A sender change output, output 0 always one.
    Change {
        tag: ViewTag,
    },
    Payment(TaggedPayment),
    Exit,
    Dummy {
        tag: ViewTag,
    },
}

impl AnonymousPlan {
    pub fn new(sender_tag: ViewTag) -> Self {
        Self {
            sender_tag,
            payments: Vec::new(),
            // Distributed as every derived view tag.
            dummy_tags: core::array::from_fn(|_| random_blinding()),
        }
    }

    pub fn with_payment(mut self, payment: TaggedPayment) -> Self {
        self.payments.push(payment);
        self
    }

    pub fn sender_tag(&self) -> &ViewTag {
        &self.sender_tag
    }

    pub fn payments(&self) -> &[TaggedPayment] {
        &self.payments
    }

    /// Change leads, every other ring output takes the next payment in declared order.
    pub fn slots(
        &self,
        outputs: &[SppProofOutputUtxo],
        sender: &ShieldedAddress,
    ) -> Result<Vec<AnonymousSlot>, RingRailError> {
        let change = leading_change(outputs, sender);
        if change == 0 {
            return Err(RingRailError::MissingSenderChange);
        }
        let mut payments = self.payments.iter();
        let mut slots = Vec::with_capacity(outputs.len());
        for (slot_index, output) in outputs.iter().enumerate() {
            let dummy_tag = *self
                .dummy_tags
                .get(slot_index)
                .ok_or(TransactionError::TooManyOutputs)?;
            let slot = match output.owner_address {
                // Later change opens from the sender bundle, only output 0 takes the sender tag.
                _ if slot_index < change => AnonymousSlot::Change {
                    tag: match slot_index {
                        0 => self.sender_tag,
                        _ => dummy_tag,
                    },
                },
                None => AnonymousSlot::Dummy { tag: dummy_tag },
                Some(_) if is_change(output, sender) => {
                    return Err(RingRailError::AnonymousChange { slot_index })
                }
                Some(owner) if output.ring_program_id.is_none() => {
                    if owner.signing_pubkey == sender.signing_pubkey {
                        return Err(RingRailError::RingSenderExit { slot_index });
                    }
                    AnonymousSlot::Exit
                }
                Some(owner) => match payments.next() {
                    Some(payment) if payment.recipient == owner.viewing_pubkey => {
                        AnonymousSlot::Payment(*payment)
                    }
                    Some(_) => return Err(RingRailError::RingPaymentSlot { slot_index }),
                    None => return Err(RingRailError::UnplannedRingOutput { slot_index }),
                },
            };
            slots.push(slot);
        }
        match payments.next() {
            Some(_) => Err(RingRailError::RingPaymentSlot {
                slot_index: outputs.len(),
            }),
            None => Ok(slots),
        }
    }
}

impl AnonymousSlot {
    pub fn tag(&self) -> Option<&ViewTag> {
        match self {
            Self::Change { tag } | Self::Dummy { tag } => Some(tag),
            Self::Payment(payment) => Some(&payment.tag),
            Self::Exit => None,
        }
    }

    /// The sender bundle's entry, a dummy key where no anonymous recipient reads the output.
    fn listed_recipient(&self) -> Result<Option<X25519Pubkey>, RingRailError> {
        Ok(match self {
            Self::Change { .. } => None,
            Self::Payment(payment) => Some(payment.recipient),
            // An exit's owner reads no shared tag, listing it would mispair the next payment.
            Self::Exit | Self::Dummy { .. } => {
                Some(X25519Pubkey::from_bytes(DUMMY_RECIPIENT_VIEWING_PK)?)
            }
        })
    }
}

/// Moves the sender's change to the front, SPL before SOL, and rederives every blinding at its slot.
pub(crate) fn lead_change(
    inputs: &mut SppProofInputs,
    sender: &ShieldedAddress,
) -> Result<(), RingRailError> {
    let mut order: Vec<usize> = (0..inputs.output_utxos.len()).collect();
    order.sort_by_key(|index| {
        let output = &inputs.output_utxos[*index];
        match is_change(output, sender) {
            true if output.asset.asset != Mint::SOL.asset => 0,
            true => 1,
            false => 2,
        }
    });
    let outputs: Vec<SppProofOutputUtxo> = order
        .iter()
        .map(|index| inputs.output_utxos[*index].clone())
        .collect();
    let first_nullifier = inputs.first_nullifier()?;
    let blindings = OutputBlindings::new(&first_nullifier, &inputs.blinding_seed)?;
    inputs.output_utxos = outputs
        .into_iter()
        .zip(0u32..)
        .map(|(output, slot_index)| {
            Ok(SppProofOutputUtxo {
                blinding: blindings.at(slot_index)?,
                ..output
            })
        })
        .collect::<Result<_, RingRailError>>()?;
    Ok(())
}

pub(crate) struct AnonymousSeal<'a> {
    pub tx_viewing_key: &'a ViewingKey,
    pub salt: Salt,
    pub sender: &'a ShieldedAddress,
    pub outputs: &'a [SppProofOutputUtxo],
    pub slots: &'a [AnonymousSlot],
}

impl AnonymousSeal<'_> {
    /// The body of a tagged slot sealed at its output position, `None` on a change output.
    pub fn body(&self, slot_index: usize) -> Result<Option<Vec<u8>>, RingRailError> {
        let output = &self.outputs[slot_index];
        let payment = match self.slots[slot_index] {
            AnonymousSlot::Change { .. } => return Ok(None),
            AnonymousSlot::Payment(payment) => payment,
            AnonymousSlot::Dummy { .. } => {
                let mut body = vec![0u8; RECIPIENT_BODY_LEN];
                OsRng.fill_bytes(&mut body);
                return Ok(Some(body));
            }
            AnonymousSlot::Exit => return Err(RingRailError::RingOutputFraming { slot_index }),
        };
        let owner = output
            .owner_address
            .ok_or(TransactionError::OutputWithoutOwner { slot_index })?;
        let plaintext = AnonymousTransferRecipientPlaintext {
            verified: VerifiedRecipientPlaintext {
                owner_pubkey: owner.signing_pubkey,
                mint: output.asset.asset,
                amount: output.amount,
            },
            unverified: UnverifiedRecipientPlaintext {
                sender_pubkey: self.sender.viewing_pubkey,
                blinding: output.blinding,
                data: Data::default(),
            },
        }
        .serialize()?;
        Ok(Some(self.seal(
            &payment.recipient,
            &plaintext,
            slot_index,
        )?))
    }

    /// The change and the recipient list, sealed to the sender after every output.
    pub fn sender_bundle(&self, blindings: &OutputBlindings) -> Result<Vec<u8>, RingRailError> {
        let mut verified = VerifiedSenderPlaintext {
            owner_pubkey: self.sender.signing_pubkey,
            spl_mint: Address::default(),
            spl_amount: 0,
            sol_amount: 0,
            recipient_viewing_pks: self
                .slots
                .iter()
                .filter_map(|slot| slot.listed_recipient().transpose())
                .collect::<Result<_, _>>()?,
        };
        let change = self
            .slots
            .iter()
            .take_while(|slot| matches!(slot, AnonymousSlot::Change { .. }))
            .count();
        let change = &self.outputs[..change];
        // A zero amount reads back as absent and would shift the later change's position.
        if change.len() > 1 && change.iter().any(|output| output.amount == 0) {
            return Err(RingRailError::AnonymousChangeCount);
        }
        for output in change.iter().filter(|output| output.amount != 0) {
            let held = match output.asset.asset == Mint::SOL.asset {
                true => &mut verified.sol_amount,
                false => {
                    verified.spl_mint = output.asset.asset;
                    &mut verified.spl_amount
                }
            };
            if *held != 0 {
                return Err(RingRailError::AnonymousChangeCount);
            }
            *held = output.amount;
        }
        let plaintext = AnonymousTransferSenderPlaintext {
            verified,
            unverified: UnverifiedSenderPlaintext {
                blinding_seed: *blindings.output_seed(),
                spl_data: Data::default(),
                sol_data: Data::default(),
            },
        }
        .serialize()?;
        self.seal(&self.sender.viewing_pubkey, &plaintext, self.outputs.len())
    }

    fn seal(
        &self,
        recipient: &X25519Pubkey,
        plaintext: &[u8],
        slot_index: usize,
    ) -> Result<Vec<u8>, RingRailError> {
        let slot_index = u32::try_from(slot_index).map_err(|_| TransactionError::TooManyOutputs)?;
        Ok(self
            .tx_viewing_key
            .encrypt_slot(recipient, plaintext, self.salt, slot_index)?)
    }
}

fn leading_change(outputs: &[SppProofOutputUtxo], sender: &ShieldedAddress) -> usize {
    outputs
        .iter()
        .take_while(|output| is_change(output, sender))
        .count()
}

fn is_change(output: &SppProofOutputUtxo, sender: &ShieldedAddress) -> bool {
    output.owner_address == Some(*sender) && output.ring_program_id.is_some()
}
