//! The slots a sealed ring transfer publishes, in the compact form the ring program expands.

use custom_ring_interface::{
    anonymous_recipient_output_body, anonymous_sender_output_body,
    ring_confidential_delivered_output_body, ring_owner_delivered_output, RingOutput, SenderBundle,
};
use spr_event::confidential_encrypted_output_body;
use spr_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use spr_keypair::ShieldedAddress;
use spr_transaction::{instructions::transact::SppProofInputs, SppProofOutputUtxo};

use crate::{AnonymousSlot, RingDelivery, RingOutputRail, RingRailError, Slot};

#[derive(Clone, Copy, Debug)]
pub struct PublishedSlot<'a> {
    pub output: &'a SppProofOutputUtxo,
    pub wire: RingOutput<'a>,
    /// Set on the anonymous rail.
    pub anonymous: Option<AnonymousSlot>,
}

impl RingOutputRail {
    /// Every published slot in order, each expanding to exactly the output the SPP proof binds.
    pub fn published_slots<'a>(
        &self,
        inputs: &'a SppProofInputs,
        sender: &ShieldedAddress,
    ) -> Result<Vec<PublishedSlot<'a>>, RingRailError> {
        let outputs = &inputs.output_utxos;
        let published = &inputs.external_data.outputs;
        if published.len() != outputs.len() {
            return Err(RingRailError::RingOutputFraming {
                slot_index: outputs.len().min(published.len()),
            });
        }
        let anonymous = match &self.delivery {
            RingDelivery::Anonymous(plan) => Some(plan.slots(outputs, sender)?),
            RingDelivery::Delivered | RingDelivery::Owned => None,
        };
        outputs
            .iter()
            .zip(published)
            .enumerate()
            .map(|(index, (output, published))| {
                let anonymous = anonymous.as_ref().map(|slots| slots[index]);
                let wire = match anonymous {
                    Some(slot) => anonymous_wire(slot, published, index)?,
                    None => self.delivered_wire(output, published, index)?,
                };
                if wire.transact_output()? != *published {
                    return Err(RingRailError::RingOutputFraming { slot_index: index });
                }
                Ok(PublishedSlot {
                    output,
                    wire,
                    anonymous,
                })
            })
            .collect()
    }

    /// The anonymous rail's sender bundle, the first message.
    pub fn published_sender<'a>(
        &self,
        inputs: &'a SppProofInputs,
    ) -> Result<Option<SenderBundle<'a>>, RingRailError> {
        let RingDelivery::Anonymous(plan) = &self.delivery else {
            return Ok(None);
        };
        let message = inputs
            .external_data
            .messages
            .first()
            .ok_or(RingRailError::SenderBundleFraming)?;
        let body = anonymous_sender_output_body(&message.data)
            .filter(|_| message.view_tag == *plan.sender_tag())
            .ok_or(RingRailError::SenderBundleFraming)?;
        Ok(Some(SenderBundle {
            tag: &message.view_tag,
            body,
        }))
    }

    fn delivered_wire<'a>(
        &self,
        output: &SppProofOutputUtxo,
        published: &'a TransactOutput,
        slot_index: usize,
    ) -> Result<RingOutput<'a>, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let (hash, owner_tag) = inline(published, slot_index)?;
        let data = published.data.as_deref().ok_or_else(framing)?;
        Ok(match self.slot(output, slot_index)? {
            Slot::Exit => RingOutput::Exit {
                hash,
                owner_tag,
                payload: confidential_encrypted_output_body(data).ok_or_else(framing)?,
            },
            Slot::Ring { .. } | Slot::Dummy if matches!(self.delivery, RingDelivery::Owned) => {
                let (u, body) = ring_owner_delivered_output(data).ok_or_else(framing)?;
                RingOutput::Owned {
                    hash,
                    owner: owner_tag,
                    u,
                    body,
                }
            }
            Slot::Ring { .. } | Slot::Dummy => RingOutput::Delivered {
                hash,
                u: owner_tag,
                body: ring_confidential_delivered_output_body(data).ok_or_else(framing)?,
            },
        })
    }
}

/// The body kind and tag each anonymous slot publishes, any other is refused.
fn anonymous_wire<'a>(
    slot: AnonymousSlot,
    published: &'a TransactOutput,
    slot_index: usize,
) -> Result<RingOutput<'a>, RingRailError> {
    let framing = || RingRailError::RingOutputFraming { slot_index };
    let (hash, owner_tag) = inline(published, slot_index)?;
    let data = published.data.as_deref();
    let Some(tag) = slot.tag() else {
        return Ok(RingOutput::Exit {
            hash,
            owner_tag,
            payload: data
                .and_then(confidential_encrypted_output_body)
                .ok_or_else(framing)?,
        });
    };
    let body = match slot {
        AnonymousSlot::Change { .. } => match data {
            None => None,
            Some(_) => return Err(framing()),
        },
        _ => Some(
            data.and_then(anonymous_recipient_output_body)
                .ok_or_else(framing)?,
        ),
    };
    match tag == owner_tag {
        true => Ok(RingOutput::Anonymous {
            hash,
            tag: owner_tag,
            body,
        }),
        false => Err(framing()),
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
