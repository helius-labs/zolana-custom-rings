//! The anonymous rail's slots, the sender's change leading at output 0, one record body per
//! non-exit slot and the sender bundle after them.

use custom_ring_interface::{SenderBundle, MIN_REPLY_LEN};
use rand::{rngs::OsRng, RngCore};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_interface::MAX_OUTPUTS;
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    instructions::transact::SppProofInputs, SppProofOutputUtxo, TransactionError,
};

use crate::{
    recipient_delivery::{seal_reply, seal_sender_bundle},
    OutputBlindings, ReplyMetadata, RingRailError,
};

/// The recipients of one anonymous transfer in declared order, a live tag derives from its slot.
#[must_use]
#[derive(Clone, Debug)]
pub struct AnonymousPlan {
    recipients: Vec<X25519Pubkey>,
    /// One per payment, a frame without any carries no reply bytes.
    replies: Vec<Option<ReplyMetadata>>,
    /// Drawn ahead, every encoding of a dummy slot publishes one tag.
    dummy_preimages: [[u8; 32]; MAX_OUTPUTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousSlot {
    /// A live output at the sender's exact address, its tag zero, its record sealed to the sender.
    Change,
    Payment {
        recipient: X25519Pubkey,
    },
    Exit,
    /// The tag is `Poseidon(CRRT, preimage)`.
    Dummy {
        preimage: [u8; 32],
    },
}

impl AnonymousPlan {
    pub fn new() -> Self {
        Self {
            recipients: Vec::new(),
            replies: Vec::new(),
            dummy_preimages: core::array::from_fn(|_| random_tag_preimage()),
        }
    }

    /// `dummy_preimages` must be the ones the sealed outputs publish.
    pub fn from_parts(
        recipients: Vec<X25519Pubkey>,
        dummy_preimages: [[u8; 32]; MAX_OUTPUTS],
    ) -> Self {
        let replies = vec![None; recipients.len()];
        Self {
            recipients,
            replies,
            dummy_preimages,
        }
    }

    pub fn with_payment(mut self, recipient: X25519Pubkey) -> Self {
        self.recipients.push(recipient);
        self.replies.push(None);
        self
    }

    /// Attaches a reply to the latest payment, no other path sets one.
    pub fn with_reply(mut self, reply: ReplyMetadata) -> Self {
        if let Some(slot) = self.replies.last_mut() {
            *slot = Some(reply);
        }
        self
    }

    pub fn recipients(&self) -> &[X25519Pubkey] {
        &self.recipients
    }

    pub fn dummy_preimages(&self) -> &[[u8; 32]; MAX_OUTPUTS] {
        &self.dummy_preimages
    }

    /// One length per frame, a slot without a reply carries random bytes of it.
    pub fn reply_len(&self) -> Result<Option<usize>, RingRailError> {
        self.replies
            .iter()
            .flatten()
            .map(|reply| reply.encoded_len())
            .try_fold(None, |longest: Option<usize>, len| {
                Ok(Some(longest.unwrap_or(MIN_REPLY_LEN).max(len?)))
            })
    }

    /// Change leads, every other ring output takes the next payment in declared order.
    pub fn slots(
        &self,
        outputs: &[SppProofOutputUtxo],
        sender: &ShieldedAddress,
    ) -> Result<Vec<AnonymousSlot>, RingRailError> {
        let published = published(outputs);
        let change = leading_change(published, sender);
        let mut recipients = self.recipients.iter();
        let mut slots = Vec::with_capacity(published.len());
        for (slot_index, output) in published.iter().enumerate() {
            let preimage = *self
                .dummy_preimages
                .get(slot_index)
                .ok_or(TransactionError::TooManyOutputs)?;
            let slot = match output.owner_address {
                _ if slot_index < change => AnonymousSlot::Change,
                None => AnonymousSlot::Dummy { preimage },
                Some(_) if is_change(output, sender) => {
                    return Err(RingRailError::AnonymousChange { slot_index });
                }
                Some(owner) if output.ring_program_id.is_none() => {
                    if owner.signing_pubkey == sender.signing_pubkey {
                        return Err(RingRailError::RingSenderExit { slot_index });
                    }
                    AnonymousSlot::Exit
                }
                Some(owner) => match recipients.next() {
                    Some(recipient) if *recipient == owner.viewing_pubkey => {
                        AnonymousSlot::Payment {
                            recipient: *recipient,
                        }
                    }
                    Some(_) => return Err(RingRailError::RingPaymentSlot { slot_index }),
                    None => return Err(RingRailError::UnplannedRingOutput { slot_index }),
                },
            };
            slots.push(slot);
        }
        match recipients.next() {
            Some(_) => Err(RingRailError::RingPaymentSlot {
                slot_index: published.len(),
            }),
            None => Ok(slots),
        }
    }

    fn slot_replies(&self, slots: &[AnonymousSlot]) -> Vec<Option<&ReplyMetadata>> {
        let mut replies = self.replies.iter();
        slots
            .iter()
            .map(|slot| match slot {
                AnonymousSlot::Payment { .. } => replies.next().and_then(Option::as_ref),
                _ => None,
            })
            .collect()
    }
}

impl Default for AnonymousPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonymousSlot {
    pub const fn is_change(&self) -> bool {
        matches!(self, Self::Change)
    }

    /// The bundle's key of the slot, the sender's own on change, zero on exit and dummy.
    fn recipient_key(&self, sender: &ShieldedAddress) -> [u8; 32] {
        match self {
            Self::Payment { recipient } => recipient.u(),
            Self::Change => sender.viewing_pubkey.u(),
            Self::Exit | Self::Dummy { .. } => [0; 32],
        }
    }
}

/// Moves the sender's change to the front and rederives every blinding at its slot.
pub(crate) fn lead_change(
    inputs: &mut SppProofInputs,
    sender: &ShieldedAddress,
) -> Result<(), RingRailError> {
    let mut order: Vec<usize> = (0..inputs.output_utxos.len()).collect();
    order.sort_by_key(|index| !is_change(&inputs.output_utxos[*index], sender));
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
    pub rail: &'a crate::RingOutputRail,
    pub first_nullifier: [u8; 32],
    pub outputs: &'a [SppProofOutputUtxo],
    pub slots: &'a [AnonymousSlot],
    pub plan: &'a AnonymousPlan,
    /// The frame's payload width, `None` without data.
    pub width: Option<usize>,
}

/// One non-exit slot's bytes, its reply empty without reply metadata.
pub(crate) struct SealedBody {
    pub body: Vec<u8>,
    pub reply: Vec<u8>,
}

impl AnonymousSeal<'_> {
    /// The record body of a tagged slot sealed at its output position, an exit carries none.
    pub fn body(&self, slot_index: usize) -> Result<SealedBody, RingRailError> {
        let reply_len = self.plan.reply_len()?;
        if self.slots[slot_index] == AnonymousSlot::Exit {
            return Err(RingRailError::RingOutputFraming { slot_index });
        }
        let output = &self.outputs[slot_index];
        let body = self
            .rail
            .seal_body(output, &self.first_nullifier, slot_index, self.width)?;
        let replies = self.plan.slot_replies(self.slots);
        let reply = match (self.slots[slot_index], replies[slot_index], reply_len) {
            (AnonymousSlot::Payment { recipient }, Some(reply), Some(reply_len)) => {
                let index =
                    u32::try_from(slot_index).map_err(|_| TransactionError::TooManyOutputs)?;
                let secret = self
                    .rail
                    .slot_secret(&recipient, &self.first_nullifier, index)?;
                seal_reply(reply, reply_len, &secret)?
            }
            _ => random_bytes(reply_len.unwrap_or(0)),
        };
        Ok(SealedBody { body, reply })
    }

    /// The bundle at index `m` opens under a retained or reproducible sender viewing key and
    /// published values alone, its keys name each slot's recipient.
    pub fn sender_bundle(
        &self,
        blindings: &OutputBlindings,
        sender: &ShieldedAddress,
    ) -> Result<Vec<u8>, RingRailError> {
        let bundle = SenderBundle {
            output_seed: *blindings.output_seed(),
            recipient_keys: self
                .slots
                .iter()
                .map(|slot| slot.recipient_key(sender))
                .collect(),
        };
        let published =
            u32::try_from(self.slots.len()).map_err(|_| TransactionError::TooManyOutputs)?;
        let secret =
            self.rail
                .slot_secret(&sender.viewing_pubkey, &self.first_nullifier, published)?;
        seal_sender_bundle(&bundle, &secret)
    }
}

/// The outputs the frame publishes, compact padding is an omitted suffix.
pub fn published(outputs: &[SppProofOutputUtxo]) -> &[SppProofOutputUtxo] {
    let omitted = outputs
        .iter()
        .rev()
        .take_while(|output| output.is_compact())
        .count();
    &outputs[..outputs.len() - omitted]
}

/// Uniform below `q` by rejection, a live tag's preimage is a Poseidon output.
pub fn random_tag_preimage() -> [u8; 32] {
    loop {
        let mut value = [0u8; 32];
        OsRng.fill_bytes(&mut value);
        value[0] &= 0x3f;
        if is_canonical_bn254_scalar_be(&value) {
            return value;
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn leading_change(outputs: &[SppProofOutputUtxo], sender: &ShieldedAddress) -> usize {
    outputs
        .iter()
        .take_while(|output| is_change(output, sender))
        .count()
}

/// A bundle cell holds no data, a data note travels in its own body.
fn is_change(output: &SppProofOutputUtxo, sender: &ShieldedAddress) -> bool {
    let carries_data = [output.data_hash, output.ring_data_hash]
        .into_iter()
        .flatten()
        .any(|hash| hash != [0; 32]);
    output.owner_address == Some(*sender) && output.ring_program_id.is_some() && !carries_data
}
