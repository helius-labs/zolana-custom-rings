//! Ring output rails as the ring program expands them, mirrored by Go `prover/circuits/audit`.
//!
//! Every non-exit slot publishes its proven record under the slot's delivered secret, the record
//! then the payload in one stream. An exit keeps SPP's scheme 3 body and seals its record to the
//! auditor. Each slot's recipient key is the owner's viewing key, the auditor's on an exit, and a
//! key derived from the transaction viewing secret on a dummy.

mod anonymous_rail;
mod assets;
mod error;
mod input_map;
mod published;
mod recipient_delivery;

use std::cell::RefCell;

use custom_ring_interface::{
    blinding::ring_blinding_seed,
    encode_ring_sender_bundle_output,
    stream::{confidential_slot_tag, DeliveredSlot, SlotSecret},
    OutputRecord, RecipientPayload, RecordKind, RingOutput, SlotBody, OUTPUT_RECORD_LEN,
};
use rand::{rngs::OsRng, RngCore};
use spr_event::MessageData;
use spr_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use spr_keypair::{
    random_salt,
    viewing_key::{Salt, ViewTag},
    ShieldedAddress, ViewingKey, X25519Pubkey,
};
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, OutputEncoder, OutputEncryption, ResolvedOwnerTag, SppProofInputs,
    },
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    SppProofOutputUtxo, TransactionError, UtxoSerialization,
};
use zolana_ring_keys::dummy_recipient_key;

pub use anonymous_rail::published as published_outputs;
use anonymous_rail::{lead_change, AnonymousSeal};
pub use anonymous_rail::{random_tag_preimage, AnonymousPlan, AnonymousSlot};
pub use assets::RingAssets;
pub use error::RingRailError;
pub use input_map::{address_chain, note_count, ClassifiedInput, InputClass};
pub use published::PublishedSlot;
pub use recipient_delivery::{
    is_contributory, open_recipient_body, open_reply, open_sender_bundle, recipient_payload,
    seal_recipient_body, seal_reply, seal_sender_bundle, AnonymousOutput, OpenedBody, OpenedNote,
    OpenedRecipientBody, OutputBlindings, PayloadRead, ReplyClaim, ReplyMetadata,
};

#[derive(Clone, Debug)]
pub enum RingDelivery {
    /// A body under the owner's viewing key, the owner tag its `u`.
    Delivered,
    /// Ring body under view tags at each recipient output, sender bundle in a message.
    Anonymous(Box<AnonymousPlan>),
}

/// 31 random bytes, below the field for every draw.
pub fn random_field_element() -> [u8; 32] {
    let mut element = [0; 32];
    OsRng.fill_bytes(&mut element[1..]);
    element
}

#[must_use]
#[derive(Clone)]
pub struct RingOutputRail {
    tx_viewing_key: ViewingKey,
    salt: Salt,
    /// An exit's record and every unpublished capacity slot seal to it.
    auditor: X25519Pubkey,
    delivery: RingDelivery,
}

#[derive(Clone, Copy)]
enum Slot {
    Ring { owner: ShieldedAddress },
    Exit,
    Dummy,
}

impl RingOutputRail {
    /// A fresh salt per rail, a resent attempt under the same first nullifier repeats no keystream.
    pub fn new(tx_viewing_key: ViewingKey, auditor: X25519Pubkey, delivery: RingDelivery) -> Self {
        Self::sealed(tx_viewing_key, random_salt(), auditor, delivery)
    }

    /// The rail a wallet sealed under `salt`, proven again away from the wallet.
    pub fn sealed(
        tx_viewing_key: ViewingKey,
        salt: Salt,
        auditor: X25519Pubkey,
        delivery: RingDelivery,
    ) -> Self {
        Self {
            tx_viewing_key,
            salt,
            auditor,
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

    pub fn auditor(&self) -> &X25519Pubkey {
        &self.auditor
    }

    pub fn delivery(&self) -> &RingDelivery {
        &self.delivery
    }

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

    /// `V_i` of every slot of a key's `capacity`, a slot past the published outputs takes the
    /// auditor's.
    pub fn recipient_keys(
        &self,
        outputs: &[SppProofOutputUtxo],
        capacity: usize,
    ) -> Result<Vec<X25519Pubkey>, RingRailError> {
        let published = published_outputs(outputs);
        (0..capacity)
            .map(|slot_index| match published.get(slot_index) {
                Some(output) => self.recipient_key(output, slot_index),
                None => Ok(self.auditor),
            })
            .collect()
    }

    /// `V_i`, the owner's viewing key on a ring output, the auditor's on an exit, a derived key on a dummy.
    pub fn recipient_key(
        &self,
        output: &SppProofOutputUtxo,
        slot_index: usize,
    ) -> Result<X25519Pubkey, RingRailError> {
        Ok(match self.slot(output) {
            Slot::Ring { owner } => owner.viewing_pubkey,
            Slot::Exit => self.auditor,
            Slot::Dummy => dummy_recipient_key(
                &self.tx_viewing_key.secret_bytes(),
                u32::try_from(slot_index).map_err(|_| TransactionError::TooManyOutputs)?,
            )?,
        })
    }

    /// The record the proof holds to `output`, all zero on a dummy.
    pub fn output_record(output: &SppProofOutputUtxo) -> Result<OutputRecord, RingRailError> {
        let Some(owner) = output.owner_address else {
            return Ok(OutputRecord::default());
        };
        Ok(OutputRecord {
            kind: match output.ring_program_id {
                Some(_) => RecordKind::Ring,
                None => RecordKind::Exit,
            },
            amount: output.amount,
            owner_key: owner.signing_pubkey.confidential_view_tag()?,
            mint: output.asset.asset.to_bytes(),
            nullifier_pk: owner.nullifier_pubkey,
            blinding: output.blinding,
        })
    }

    /// An exit's record sealed to the auditor at its slot, the auditor message carries it.
    pub fn exit_record(
        &self,
        output: &SppProofOutputUtxo,
        first_nullifier: &[u8; 32],
        slot_index: usize,
    ) -> Result<[u8; OUTPUT_RECORD_LEN], RingRailError> {
        let position = u32::try_from(slot_index).map_err(|_| TransactionError::TooManyOutputs)?;
        let secret = self.slot_secret(&self.auditor, first_nullifier, position)?;
        let body = seal_recipient_body(&Self::output_record(output)?, None, &secret)?;
        body.try_into()
            .map_err(|_| RingRailError::RingOutputFraming { slot_index })
    }

    /// The tag slot `slot_index` publishes, `None` on an exit since its owner tag is no view tag.
    pub fn anonymous_tag(
        &self,
        slot: &AnonymousSlot,
        first_nullifier: &[u8; 32],
        slot_index: u32,
    ) -> Result<Option<ViewTag>, RingRailError> {
        Ok(match slot {
            AnonymousSlot::Exit => None,
            AnonymousSlot::Change => Some([0; 32]),
            AnonymousSlot::Dummy { preimage } => {
                Some(SlotSecret::new(*preimage)?.anonymous_slot_tag()?)
            }
            AnonymousSlot::Payment { recipient } => Some(
                self.slot_secret(recipient, first_nullifier, slot_index)?
                    .anonymous_slot_tag()?,
            ),
        })
    }

    /// The bundle's tag at index `m`, the frame's output count.
    pub fn sender_bundle_tag(
        &self,
        sender: &X25519Pubkey,
        first_nullifier: &[u8; 32],
        published: u32,
    ) -> Result<ViewTag, RingRailError> {
        Ok(self
            .slot_secret(sender, first_nullifier, published)?
            .sender_tag()?)
    }

    /// The record then, under `width`, the payload, sealed to the slot's recipient key.
    pub(crate) fn seal_body(
        &self,
        output: &SppProofOutputUtxo,
        first_nullifier: &[u8; 32],
        slot_index: usize,
        width: Option<usize>,
    ) -> Result<Vec<u8>, RingRailError> {
        let position = u32::try_from(slot_index).map_err(|_| TransactionError::TooManyOutputs)?;
        let recipient = self.recipient_key(output, slot_index)?;
        let secret = self.slot_secret(&recipient, first_nullifier, position)?;
        let payload = recipient_payload(output);
        seal_recipient_body(
            &Self::output_record(output)?,
            width.map(|width| (&payload, width)),
            &secret,
        )
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

    /// Replaces every published slot with its record body or its scheme 3 exit.
    fn reencode_delivered(&self, inputs: &mut SppProofInputs) -> Result<(), RingRailError> {
        let published = published_outputs(&inputs.output_utxos);
        check_carried(published)?;
        let first_nullifier = inputs.first_nullifier()?;
        let width = payload_width(published);
        let mut framed = inputs.external_data.outputs.iter_mut();
        let mut resolved = inputs.external_data.resolved_owner_tags.iter();
        for (index, output) in published.iter().enumerate() {
            let framing = RingRailError::RingOutputFraming { slot_index: index };
            let position = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let (transact_output, resolved) = framed
                .next()
                .zip(resolved.next())
                .ok_or(RingRailError::RingOutputFraming { slot_index: index })?;
            let owner_tag = ResolvedOwnerTag {
                tag: transact_output.owner_tag,
                resolved: *resolved,
            };
            let message = match self.slot(output) {
                Slot::Exit => self.exit_slot(output, owner_tag.resolved, position)?,
                Slot::Ring { .. } | Slot::Dummy => {
                    let body = self.seal_body(output, &first_nullifier, index, width)?;
                    Self::framed(&body, &owner_tag, index)?
                }
            };
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
        let published = published_outputs(&inputs.output_utxos);
        check_carried(published)?;
        let slots = plan.slots(&inputs.output_utxos, sender)?;
        let first_nullifier = inputs.first_nullifier()?;
        let seal = AnonymousSeal {
            rail: self,
            first_nullifier,
            outputs: published,
            slots: &slots,
            plan,
            width: payload_width(published),
        };
        let tree_id = inputs.output_tree_id;
        let blindings = OutputBlindings::new(&first_nullifier, &inputs.blinding_seed)?;
        let sender_bundle = seal.sender_bundle(&blindings, sender)?;
        let mut outputs = Vec::with_capacity(slots.len());
        let mut resolved = Vec::with_capacity(slots.len());
        for (index, (output, slot)) in published.iter().zip(&slots).enumerate() {
            let hash = output.hash(tree_id)?;
            let position = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let (transact_output, owner_tag) =
                match self.anonymous_tag(slot, &first_nullifier, position)? {
                    Some(tag) => {
                        let sealed = seal.body(index)?;
                        let record = record_of(&sealed.body, index)?;
                        let wire = RingOutput {
                            hash: &hash,
                            owner_tag: tag,
                            body: SlotBody::Recipient(&sealed.body),
                            record,
                        };
                        (wire.transact_output(&sealed.reply)?, tag)
                    }
                    None => {
                        let owner_tag = output
                            .owner_address
                            .ok_or(TransactionError::OutputWithoutOwner { slot_index: index })?
                            .signing_pubkey
                            .confidential_view_tag()?;
                        let message = self.exit_slot(output, owner_tag, position)?;
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
        let frame_outputs =
            u32::try_from(slots.len()).map_err(|_| TransactionError::TooManyOutputs)?;
        inputs.external_data.messages = vec![MessageData {
            view_tag: self.sender_bundle_tag(
                &sender.viewing_pubkey,
                &first_nullifier,
                frame_outputs,
            )?,
            data: encode_ring_sender_bundle_output(&sender_bundle)?,
        }];
        Ok(())
    }

    fn slot(&self, output: &SppProofOutputUtxo) -> Slot {
        match output.owner_address {
            None => Slot::Dummy,
            Some(owner) if output.ring_program_id.is_some() => Slot::Ring { owner },
            Some(_) => Slot::Exit,
        }
    }

    /// The published bytes of a recipient body through the ring program's own expansion.
    fn framed(
        body: &[u8],
        owner_tag: &ResolvedOwnerTag,
        slot_index: usize,
    ) -> Result<MessageData, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        // The expansion ignores the hash, only the published bytes are kept.
        let expanded = RingOutput {
            hash: &[0; 32],
            owner_tag: owner_tag.resolved,
            body: SlotBody::Recipient(body),
            record: record_of(body, slot_index)?,
        }
        .transact_output(&[])?;
        if expanded.owner_tag != owner_tag.tag {
            return Err(framing());
        }
        Ok(MessageData {
            view_tag: owner_tag.resolved,
            data: expanded.data.ok_or_else(framing)?,
        })
    }

    /// A dummy's tag names its derived recipient key as a real recipient's names its viewing key.
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
            // An omitted slot publishes no tag.
            if output.is_compact() {
                continue;
            }
            let resolved = match self.slot(output) {
                Slot::Exit => owner_tag.resolved,
                Slot::Ring { .. } | Slot::Dummy => {
                    confidential_slot_tag(self.recipient_key(output, index)?.u())
                }
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

/// A recipient body leads with its record ciphertext.
pub(crate) fn record_of(
    body: &[u8],
    slot_index: usize,
) -> Result<&[u8; OUTPUT_RECORD_LEN], RingRailError> {
    body.first_chunk()
        .ok_or(RingRailError::RingOutputFraming { slot_index })
}

/// A ring body holds the hashes and application data alone, nothing else may vanish from a note.
fn check_carried(outputs: &[SppProofOutputUtxo]) -> Result<(), RingRailError> {
    let refused = outputs.iter().position(|output| {
        let unbound_data = output.data.utxo_data().is_some()
            && output.data_hash.is_none_or(|hash| hash == [0; 32]);
        output.ring_program_id.is_some()
            && !output.is_dummy()
            && (unbound_data || output.data.memo().is_some() || output.data.ring_data().is_some())
    });
    match refused {
        Some(slot_index) => Err(RingRailError::OutputDataNotCarried { slot_index }),
        None => Ok(()),
    }
}

/// `None` while no published output carries data, else every recipient payload takes the widest
/// one's length.
pub fn payload_width(outputs: &[SppProofOutputUtxo]) -> Option<usize> {
    let carries = |output: &SppProofOutputUtxo| {
        !output.is_dummy()
            && (output.data.utxo_data().is_some()
                || [output.data_hash, output.ring_data_hash]
                    .into_iter()
                    .flatten()
                    .any(|hash| hash != [0; 32]))
    };
    if !published_outputs(outputs).iter().any(carries) {
        return None;
    }
    let widest = published_outputs(outputs)
        .iter()
        .filter(|output| output.ring_program_id.is_some() || output.is_dummy())
        .map(|output| recipient_payload(output).encoded_len())
        .max();
    Some(widest.unwrap_or_else(|| RecipientPayload::default().encoded_len()))
}
