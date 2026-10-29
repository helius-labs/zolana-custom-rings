//! Ring output rails as the ring program expands them, mirrored by Go `prover/circuits/audit`.

mod anonymous_body;
mod anonymous_plaintext;
mod anonymous_rail;
mod assets;
mod error;
mod published;
mod ring_delivered;
mod ring_deposit;
#[cfg(test)]
mod tests;

use std::cell::RefCell;

use custom_ring_interface::{
    blinding::ring_blinding_seed,
    encode_anonymous_sender_output,
    stream::{DeliveredSlot, SlotSecret},
    RingOutput, RING_DELIVERED_BODY_LEN,
};
use rand::{rngs::OsRng, RngCore};
use spr_event::MessageData;
use spr_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use spr_keypair::{random_salt, viewing_key::Salt, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, OutputEncoder, OutputEncryption, ResolvedOwnerTag, SppProofInputs,
    },
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    SppProofOutputUtxo, TransactionError, UtxoSerialization,
};

pub use anonymous_body::{
    is_dummy_recipient, listed_recipients, AnonymousOutput, OutputBlindings,
    DUMMY_RECIPIENT_VIEWING_PK, RECIPIENT_BODY_LEN,
};
pub use anonymous_plaintext::{
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext,
    UnverifiedRecipientPlaintext, UnverifiedSenderPlaintext, VerifiedRecipientPlaintext,
    VerifiedSenderPlaintext,
};
use anonymous_rail::{lead_change, AnonymousSeal};
pub use anonymous_rail::{AnonymousPlan, AnonymousSlot, TaggedPayment};
pub use assets::RingAssets;
pub use error::RingRailError;
pub use published::PublishedSlot;
pub use ring_delivered::{
    is_contributory, RingDelivered, RingDeliveredBody, RingDeliveredNote, RingDeliveryOpening,
    RingUtxoOwner,
};
pub use ring_deposit::RingDepositPlaintext;

#[derive(Clone, Debug)]
pub enum RingDelivery {
    /// Scheme 10 delivered to the owner's viewing key, at `DELIVERED_AUDIT_CAPACITIES`.
    Delivered,
    /// Scheme 1 under view tags at each recipient output, scheme 2 in a message.
    Anonymous(Box<AnonymousPlan>),
}

#[must_use]
#[derive(Clone)]
pub struct RingOutputRail {
    tx_viewing_key: ViewingKey,
    salt: Salt,
    delivery: RingDelivery,
}

#[derive(Clone, Copy)]
enum Slot {
    Ring { recipient: X25519Pubkey },
    Exit,
    Dummy,
}

impl RingOutputRail {
    /// A fresh salt per rail, a resent attempt under the same first nullifier repeats no keystream.
    pub fn new(tx_viewing_key: ViewingKey, delivery: RingDelivery) -> Self {
        Self {
            tx_viewing_key,
            salt: random_salt(),
            delivery,
        }
    }

    /// The rail a wallet sealed under `salt`, proven again away from the wallet.
    pub fn sealed(tx_viewing_key: ViewingKey, salt: Salt, delivery: RingDelivery) -> Self {
        Self {
            tx_viewing_key,
            salt,
            delivery,
        }
    }

    /// SPP's encryption fixes the slots and blindings, the rail then re-encodes every slot.
    pub fn encrypt(
        &self,
        transaction: ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<SppProofInputs, RingRailError> {
        let blinding_seed = self.blinding_seed()?;
        let transaction = match transaction.blinding_seed() == &blinding_seed {
            true => transaction,
            false => transaction.with_blinding_seed(blinding_seed)?,
        };
        let mut inputs = match &self.delivery {
            RingDelivery::Delivered => self.spp_encrypt(transaction, sender)?,
            RingDelivery::Anonymous(_) => {
                let mut inputs = OutputEncryption {
                    sender,
                    tx_viewing_key: &self.tx_viewing_key,
                    encoder: &Confidential,
                }
                .encrypt(transaction)?;
                lead_change(&mut inputs, sender)?;
                inputs
            }
        };
        match &self.delivery {
            RingDelivery::Delivered => self.reencode_delivered(&mut inputs)?,
            RingDelivery::Anonymous(plan) => self.reencode_anonymous(plan, &mut inputs, sender)?,
        }
        inputs.external_data.salt = self.salt;
        Ok(inputs)
    }

    /// A transaction padded before [`Self::encrypt`] takes the seed before its padding.
    pub fn blinding_seed(&self) -> Result<[u8; 32], RingRailError> {
        Ok(ring_blinding_seed(
            &self.tx_viewing_key.secret_bytes(),
            &self.salt,
        )?)
    }

    pub fn tx_viewing_key(&self) -> &ViewingKey {
        &self.tx_viewing_key
    }

    pub fn salt(&self) -> Salt {
        self.salt
    }

    pub fn delivery(&self) -> &RingDelivery {
        &self.delivery
    }

    /// The body key of the delivered ring output at `slot_index`.
    pub fn slot_secret(
        &self,
        recipient: &X25519Pubkey,
        first_nullifier: &[u8; 32],
        slot_index: u32,
    ) -> Result<SlotSecret, RingRailError> {
        Ok(DeliveredSlot {
            agreement: &self.tx_viewing_key.ecdh(recipient)?,
            tx_viewing_pk: self.tx_viewing_key.pubkey().as_bytes(),
            recipient_viewing_pk: recipient.as_bytes(),
            salt: &self.salt,
            output_index: slot_index,
            first_nullifier,
        }
        .secret()?)
    }

    /// The pinned SPP encryption under the delivered owner tags.
    fn spp_encrypt(
        &self,
        transaction: ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<SppProofInputs, RingRailError> {
        let encoder = SppEncoder {
            rail: self,
            refusal: RefCell::new(None),
        };
        let encrypted = OutputEncryption {
            sender,
            tx_viewing_key: &self.tx_viewing_key,
            encoder: &encoder,
        }
        .encrypt(transaction);
        match (encrypted, encoder.refusal.into_inner()) {
            (Err(_), Some(refusal)) => Err(refusal),
            (encrypted, _) => Ok(encrypted?),
        }
    }

    /// Replaces every published slot with its scheme 10, scheme 3 or dummy encoding.
    fn reencode_delivered(&self, inputs: &mut SppProofInputs) -> Result<(), RingRailError> {
        let first_nullifier = inputs.first_nullifier()?;
        let mut published = inputs.external_data.outputs.iter_mut();
        let mut resolved = inputs.external_data.resolved_owner_tags.iter();
        for (index, output) in inputs.output_utxos.iter().enumerate() {
            let framing = RingRailError::RingOutputFraming { slot_index: index };
            let slot_index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let (transact_output, resolved) = published
                .next()
                .zip(resolved.next())
                .ok_or(RingRailError::RingOutputFraming { slot_index: index })?;
            let message = self.encode_delivered(&SlotEncode {
                output,
                slot_index,
                first_nullifier,
                owner_tag: ResolvedOwnerTag {
                    tag: transact_output.owner_tag,
                    resolved: *resolved,
                },
            })?;
            if message.view_tag != *resolved {
                return Err(framing);
            }
            transact_output.data = Some(message.data);
        }
        Ok(())
    }

    /// Rebuilds every published slot, each tagged body sealed at its output position.
    fn reencode_anonymous(
        &self,
        plan: &AnonymousPlan,
        inputs: &mut SppProofInputs,
        sender: &ShieldedAddress,
    ) -> Result<(), RingRailError> {
        for (slot_index, output) in inputs.output_utxos.iter().enumerate() {
            check_plain(output, slot_index)?;
        }
        let slots = plan.slots(&inputs.output_utxos, sender)?;
        let seal = AnonymousSeal {
            tx_viewing_key: &self.tx_viewing_key,
            salt: self.salt,
            sender,
            outputs: &inputs.output_utxos,
            slots: &slots,
        };
        let tree_id = inputs.output_tree_id;
        let blindings = OutputBlindings::new(&inputs.first_nullifier()?, &inputs.blinding_seed)?;
        let sender_bundle = seal.sender_bundle(&blindings)?;
        let mut outputs = Vec::with_capacity(slots.len());
        let mut resolved = Vec::with_capacity(slots.len());
        for (index, (output, slot)) in inputs.output_utxos.iter().zip(&slots).enumerate() {
            let hash = output.hash(tree_id)?;
            let (transact_output, owner_tag) = match slot.tag() {
                Some(tag) => {
                    let body = seal.body(index)?;
                    let wire = RingOutput::Anonymous {
                        hash: &hash,
                        tag,
                        body: body.as_deref(),
                    };
                    (wire.transact_output()?, *tag)
                }
                None => {
                    let owner_tag = output
                        .owner_address
                        .ok_or(TransactionError::OutputWithoutOwner { slot_index: index })?
                        .signing_pubkey
                        .confidential_view_tag()?;
                    let slot_index =
                        u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
                    let message = self.exit_slot(output, owner_tag, slot_index)?;
                    (
                        TransactOutput {
                            utxo_hash: hash,
                            owner_tag: OwnerTag::Inline(owner_tag),
                            data: Some(message.data),
                        },
                        owner_tag,
                    )
                }
            };
            outputs.push(transact_output);
            resolved.push(owner_tag);
        }
        inputs.external_data.outputs = outputs;
        inputs.external_data.resolved_owner_tags = resolved;
        inputs.external_data.messages = vec![MessageData {
            view_tag: *plan.sender_tag(),
            data: encode_anonymous_sender_output(&sender_bundle)?,
        }];
        Ok(())
    }

    fn slot(&self, output: &SppProofOutputUtxo, slot_index: usize) -> Result<Slot, RingRailError> {
        check_plain(output, slot_index)?;
        Ok(match output.owner_address {
            None => Slot::Dummy,
            Some(owner) if output.ring_program_id.is_some() => Slot::Ring {
                recipient: owner.viewing_pubkey,
            },
            Some(_) => Slot::Exit,
        })
    }

    /// The published bytes of a slot through the ring program's own expansion.
    fn framed(
        output: RingOutput<'_>,
        owner_tag: &ResolvedOwnerTag,
        slot_index: usize,
    ) -> Result<MessageData, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let expanded = output.transact_output()?;
        if expanded.owner_tag != owner_tag.tag {
            return Err(framing());
        }
        Ok(MessageData {
            view_tag: owner_tag.resolved,
            data: expanded.data.ok_or_else(framing)?,
        })
    }

    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, RingRailError> {
        let mut owner_tags = transaction.owner_tags(&sender.signing_pubkey)?;
        for (index, (output, owner_tag)) in transaction
            .outputs()
            .iter()
            .zip(&mut owner_tags)
            .enumerate()
        {
            let resolved = match self.slot(output, index)? {
                Slot::Exit => owner_tag.resolved,
                Slot::Ring { recipient } => recipient.u(),
                // A random key publishes as a real recipient's would.
                Slot::Dummy => ViewingKey::new().pubkey().u(),
            };
            *owner_tag = ResolvedOwnerTag {
                tag: OwnerTag::Inline(resolved),
                resolved,
            };
        }
        Ok(owner_tags)
    }

    /// Scheme 3 to the exit's owner at its slot, under the rail's salt.
    fn exit_slot(
        &self,
        output: &SppProofOutputUtxo,
        owner_tag: [u8; 32],
        slot_index: u32,
    ) -> Result<MessageData, RingRailError> {
        let owner = output
            .owner_address
            .ok_or(TransactionError::OutputWithoutOwner {
                slot_index: slot_index as usize,
            })?;
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: output.asset.asset_id,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            data: output.data.clone(),
        };
        Ok(Confidential::encode_plaintext(
            &plaintext,
            owner_tag,
            &ConfidentialEncode {
                tx: self.tx_viewing_key.clone(),
                recipient_pubkey: owner.viewing_pubkey,
                salt: self.salt,
                slot_index,
            },
        )?)
    }

    fn encode_delivered(&self, slot: &SlotEncode<'_>) -> Result<MessageData, RingRailError> {
        let slot_index = slot.slot_index as usize;
        // The expansion ignores the hash, only the published bytes are kept.
        let hash = [0; 32];
        let owner_tag = &slot.owner_tag;
        let body = match self.slot(slot.output, slot_index)? {
            Slot::Exit => return self.exit_slot(slot.output, owner_tag.resolved, slot.slot_index),
            Slot::Ring { recipient } => {
                let secret =
                    self.slot_secret(&recipient, &slot.first_nullifier, slot.slot_index)?;
                RingDeliveredBody {
                    blinding: slot.output.blinding,
                    amount: slot.output.amount,
                }
                .seal(&secret)?
            }
            Slot::Dummy => random_body(),
        };
        Self::framed(
            RingOutput::Delivered {
                hash: &hash,
                u: &owner_tag.resolved,
                body: &body,
            },
            owner_tag,
            slot_index,
        )
    }
}

/// The pinned SPP encryption under the rail's owner tags, every slot re-encoded after it.
struct SppEncoder<'a> {
    rail: &'a RingOutputRail,
    refusal: RefCell<Option<RingRailError>>,
}

impl OutputEncoder for SppEncoder<'_> {
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        self.rail
            .owner_tags(transaction, sender)
            .map_err(|refusal| match refusal {
                RingRailError::Transaction(error) => error,
                refusal => {
                    let slots = transaction.outputs().len();
                    self.refusal.replace(Some(refusal));
                    TransactionError::OwnerTagCountMismatch {
                        got: 0,
                        expected: slots,
                    }
                }
            })
    }

    fn encode_slot(
        &self,
        plaintext: &ConfidentialOutputPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError> {
        Confidential::encode_plaintext(plaintext, view_tag, cx)
    }
}

struct SlotEncode<'a> {
    output: &'a SppProofOutputUtxo,
    slot_index: u32,
    first_nullifier: [u8; 32],
    owner_tag: ResolvedOwnerTag,
}

/// A ring rail slot carries no data and is never compact padding.
fn check_plain(output: &SppProofOutputUtxo, slot_index: usize) -> Result<(), RingRailError> {
    if output.is_compact() {
        return Err(RingRailError::DeliveredCompactPadding { slot_index });
    }
    let carries_data =
        !output.data.is_empty() || output.data_hash.is_some() || output.ring_data_hash.is_some();
    match !output.is_dummy() && carries_data {
        true => Err(RingRailError::DeliveredOutputData { slot_index }),
        false => Ok(()),
    }
}

fn random_body() -> [u8; RING_DELIVERED_BODY_LEN] {
    let mut body = [0u8; RING_DELIVERED_BODY_LEN];
    OsRng.fill_bytes(&mut body);
    body
}
