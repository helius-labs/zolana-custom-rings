//! The slots a sealed ring transfer publishes, in the compact form the ring program expands, their
//! records stay in the auditor message.

use custom_ring_interface::{
    ring_body_output, ring_sender_bundle_output_body, FramedSenderBundle, RingOutput, SlotBody,
    DATA_TAIL_LEN,
};
use spr_event::confidential_encrypted_output_body;
use spr_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    instructions::transact::SppProofInputs, SppProofOutputUtxo, TransactionError,
};

use crate::{
    anonymous_rail::published as published_outputs, AnonymousSlot, RingDelivery, RingOutputRail,
    RingRailError, Slot, UNSEALED_RECORD,
};

#[derive(Clone, Copy, Debug)]
pub struct PublishedSlot<'a> {
    pub output: &'a SppProofOutputUtxo,
    pub hash: &'a [u8; 32],
    pub owner_tag: &'a [u8; 32],
    pub body: SlotBody<'a>,
    /// Set on the anonymous rail.
    pub anonymous: Option<AnonymousSlot>,
    /// The sealed reply beside a recipient body, empty without reply metadata.
    pub reply: &'a [u8],
}

impl<'a> PublishedSlot<'a> {
    /// The frame's slot once its record and tail sealed.
    pub fn wire<'r>(
        &self,
        record: &'r [u8],
        tail: Option<&'r [u8; DATA_TAIL_LEN]>,
    ) -> RingOutput<'r>
    where
        'a: 'r,
    {
        RingOutput {
            hash: self.hash,
            owner_tag: *self.owner_tag,
            body: self.body,
            record,
            tail,
        }
    }
}

impl RingOutputRail {
    /// Every published slot in order, compact padding omitted, each expanding to exactly the output the SPP proof binds.
    pub fn published_slots<'a>(
        &self,
        inputs: &'a SppProofInputs,
        sender: &ShieldedAddress,
    ) -> Result<Vec<PublishedSlot<'a>>, RingRailError> {
        let outputs = published_outputs(&inputs.output_utxos);
        let published = &inputs.external_data.outputs;
        if published.len() != outputs.len() {
            return Err(RingRailError::RingOutputFraming {
                slot_index: outputs.len().min(published.len()),
            });
        }
        let anonymous = match &self.delivery {
            RingDelivery::Anonymous(plan) => Some(plan.slots(outputs, sender)?),
            RingDelivery::Delivered => None,
        };
        outputs
            .iter()
            .zip(published)
            .enumerate()
            .map(|(index, (output, published))| {
                let anonymous = anonymous.as_ref().map(|slots| slots[index]);
                let (body, reply) = match anonymous {
                    Some(slot) => self.anonymous_body(slot, published, index, inputs)?,
                    None => (self.delivered_body(output, published, index)?, &[][..]),
                };
                let (hash, owner_tag) = inline(published, index)?;
                let slot = PublishedSlot {
                    output,
                    hash,
                    owner_tag,
                    body,
                    anonymous,
                    reply,
                };
                if slot.wire(&UNSEALED_RECORD, None).transact_output(reply)? != *published {
                    return Err(RingRailError::RingOutputFraming { slot_index: index });
                }
                Ok(slot)
            })
            .collect()
    }

    /// The anonymous rail's sender bundle, the first message.
    pub fn published_sender<'a>(
        &self,
        inputs: &'a SppProofInputs,
        sender_viewing_pubkey: &X25519Pubkey,
    ) -> Result<Option<FramedSenderBundle<'a>>, RingRailError> {
        if !matches!(self.delivery, RingDelivery::Anonymous(_)) {
            return Ok(None);
        }
        let message = inputs
            .external_data
            .messages
            .first()
            .ok_or(RingRailError::SenderBundleFraming)?;
        let frame_outputs = u32::try_from(published_outputs(&inputs.output_utxos).len())
            .map_err(|_| TransactionError::TooManyOutputs)?;
        let expected_tag = self.sender_bundle_tag(
            sender_viewing_pubkey,
            &inputs.first_nullifier()?,
            frame_outputs,
        )?;
        let body = ring_sender_bundle_output_body(&message.data)
            .filter(|_| message.view_tag == expected_tag)
            .ok_or(RingRailError::SenderBundleFraming)?;
        Ok(Some(FramedSenderBundle {
            tag: &message.view_tag,
            body,
        }))
    }

    /// The body kind and tag each anonymous slot publishes, any other is refused.
    fn anonymous_body<'a>(
        &self,
        slot: AnonymousSlot,
        published: &'a TransactOutput,
        slot_index: usize,
        inputs: &SppProofInputs,
    ) -> Result<(SlotBody<'a>, &'a [u8]), RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let (_, owner_tag) = inline(published, slot_index)?;
        let data = published.data.as_deref();
        let position = u32::try_from(slot_index).map_err(|_| TransactionError::TooManyOutputs)?;
        let Some(tag) = self.anonymous_tag(&slot, &inputs.first_nullifier()?, position)? else {
            let payload = data
                .and_then(confidential_encrypted_output_body)
                .ok_or_else(framing)?;
            return Ok((SlotBody::Exit(payload), &[]));
        };
        if tag != *owner_tag {
            return Err(framing());
        }
        match slot {
            AnonymousSlot::Change => match data {
                None => Ok((SlotBody::None, &[])),
                Some(_) => Err(framing()),
            },
            _ => {
                let (body, reply) = data.and_then(ring_body_output).ok_or_else(framing)?;
                Ok((SlotBody::Recipient(body), reply))
            }
        }
    }

    fn delivered_body<'a>(
        &self,
        output: &SppProofOutputUtxo,
        published: &'a TransactOutput,
        slot_index: usize,
    ) -> Result<SlotBody<'a>, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let data = published.data.as_deref().ok_or_else(framing)?;
        Ok(match self.slot(output) {
            Slot::Exit => {
                SlotBody::Exit(confidential_encrypted_output_body(data).ok_or_else(framing)?)
            }
            Slot::Ring { .. } | Slot::Dummy => {
                SlotBody::Recipient(ring_body_output(data).ok_or_else(framing)?.0)
            }
        })
    }
}

fn inline(
    published: &TransactOutput,
    slot_index: usize,
) -> Result<(&[u8; 32], &[u8; 32]), RingRailError> {
    match &published.owner_tag {
        OwnerTag::Inline(owner_tag) => Ok((&published.utxo_hash, owner_tag)),
        _ => Err(RingRailError::RingOutputFraming { slot_index }),
    }
}
