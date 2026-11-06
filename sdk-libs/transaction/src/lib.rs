//! Ring output rails as the ring program expands them, mirrored by Go `prover/circuits/audit`.

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
    CompactRecipientBody, DisclosureFormat, RingOutput, SlotBody, AUDIT_RECORD_LEN,
    RECIPIENT_BODY_LEN, SINGLE_ASSET_PAYOUT_OUTPUTS,
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

pub use anonymous_rail::published as published_outputs;
use anonymous_rail::{lead_change, AnonymousSeal};
pub use anonymous_rail::{random_tag_preimage, AnonymousPlan, AnonymousSlot};
pub use assets::RingAssets;
pub use error::RingRailError;
pub use input_map::{published_input_map, ClassifiedInput};
pub use published::PublishedSlot;
pub use recipient_delivery::{
    is_contributory, open_compact_recipient_body, open_recipient_body, open_reply,
    open_sender_bundle, recipient_body, seal_compact_recipient_body, seal_recipient_body,
    seal_reply, seal_sender_bundle, AnonymousOutput, OpenedBody, OpenedNote, OutputBlindings,
    ReplyClaim, ReplyMetadata,
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

/// `transact_output` drops the record, every SPP output encodes before its record seals.
pub(crate) const UNSEALED_RECORD: [u8; AUDIT_RECORD_LEN] = [0; AUDIT_RECORD_LEN];

#[must_use]
#[derive(Clone)]
pub struct RingOutputRail {
    tx_viewing_key: ViewingKey,
    salt: Salt,
    delivery: RingDelivery,
    format: DisclosureFormat,
}

#[derive(Clone, Copy)]
enum Slot {
    Ring { owner: ShieldedAddress },
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
            format: DisclosureFormat::Standard,
        }
    }

    /// The rail a wallet sealed under `salt`, proven again away from the wallet.
    pub fn sealed(tx_viewing_key: ViewingKey, salt: Salt, delivery: RingDelivery) -> Self {
        Self {
            tx_viewing_key,
            salt,
            delivery,
            format: DisclosureFormat::Standard,
        }
    }

    pub fn with_format(mut self, format: DisclosureFormat) -> Self {
        self.format = format;
        self
    }

    pub fn format(&self) -> DisclosureFormat {
        self.format
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
        if self.format == DisclosureFormat::SingleAssetPayout
            && !matches!(self.delivery, RingDelivery::Delivered)
        {
            return Err(RingRailError::PayoutProfile);
        }
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
        self.check_format(&inputs)?;
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

    /// Replaces every published slot with its body, scheme 3 or dummy encoding.
    fn reencode_delivered(&self, inputs: &mut SppProofInputs) -> Result<(), RingRailError> {
        check_carried(published_outputs(&inputs.output_utxos))?;
        let first_nullifier = inputs.first_nullifier()?;
        let body_width = recipient_body_width(&inputs.output_utxos);
        let mut published = inputs.external_data.outputs.iter_mut();
        let mut resolved = inputs.external_data.resolved_owner_tags.iter();
        for (index, output) in published_outputs(&inputs.output_utxos).iter().enumerate() {
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
                body_width,
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
        let published = published_outputs(&inputs.output_utxos);
        check_carried(published)?;
        let slots = plan.slots(&inputs.output_utxos, sender)?;
        let first_nullifier = inputs.first_nullifier()?;
        let seal = AnonymousSeal {
            rail: self,
            first_nullifier,
            sender,
            outputs: published,
            slots: &slots,
            plan,
            body_width: recipient_body_width(published),
        };
        let tree_id = inputs.output_tree_id;
        let blindings = OutputBlindings::new(&first_nullifier, &inputs.blinding_seed)?;
        let sender_bundle = seal.sender_bundle(&blindings)?;
        let mut outputs = Vec::with_capacity(slots.len());
        let mut resolved = Vec::with_capacity(slots.len());
        for (index, (output, slot)) in published.iter().zip(&slots).enumerate() {
            let hash = output.hash(tree_id)?;
            let position = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let (transact_output, owner_tag) =
                match self.anonymous_tag(slot, &first_nullifier, position)? {
                    Some(tag) => {
                        let sealed = seal.body(index)?;
                        let wire = RingOutput {
                            hash: &hash,
                            owner_tag: tag,
                            body: sealed
                                .as_ref()
                                .map_or(SlotBody::None, |sealed| SlotBody::Recipient(&sealed.body)),
                            record: &UNSEALED_RECORD,
                            tail: None,
                        };
                        let reply = sealed.as_ref().map_or(&[][..], |sealed| &sealed.reply);
                        (wire.transact_output(reply)?, tag)
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

    /// The published bytes of a slot through the ring program's own expansion.
    fn framed(
        output: RingOutput<'_>,
        owner_tag: &ResolvedOwnerTag,
        slot_index: usize,
    ) -> Result<MessageData, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let expanded = output.transact_output(&[])?;
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
        for (output, owner_tag) in transaction.outputs().iter().zip(&mut owner_tags) {
            // An omitted slot publishes no tag.
            if output.is_compact() {
                continue;
            }
            let resolved = match self.slot(output) {
                Slot::Exit => owner_tag.resolved,
                Slot::Ring { owner } => confidential_slot_tag(owner.viewing_pubkey.u()),
                // A random key publishes as a real recipient's would.
                Slot::Dummy => confidential_slot_tag(ViewingKey::new().pubkey().u()),
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

    pub fn check_format(&self, inputs: &SppProofInputs) -> Result<(), RingRailError> {
        if self.format == DisclosureFormat::Standard {
            return Ok(());
        }
        let valid = match inputs.input_utxos.as_slice() {
            [input] if input.is_note() && input.utxo.ring_program_id.is_some() => {
                inputs.output_utxos.len() == SINGLE_ASSET_PAYOUT_OUTPUTS
                    && inputs.output_utxos.iter().all(|output| {
                        !output.is_dummy()
                            && output.ring_program_id == input.utxo.ring_program_id
                            && output.asset == input.utxo.asset
                            && output.data_hash.is_none_or(|hash| hash == [0; 32])
                            && output.ring_data_hash.is_none_or(|hash| hash == [0; 32])
                            && output.data.is_empty()
                    })
                    && inputs.external_data.interface_transfers.is_empty()
                    && inputs.external_data.messages.is_empty()
                    && inputs.external_data.data_hash.is_none()
                    && inputs.external_data.ring_data_hash.is_none()
            }
            _ => false,
        };
        match valid {
            true => Ok(()),
            false => Err(RingRailError::PayoutProfile),
        }
    }

    fn encode_delivered(&self, slot: &SlotEncode<'_>) -> Result<MessageData, RingRailError> {
        let slot_index = slot.slot_index as usize;
        // The expansion ignores the hash, only the published bytes are kept.
        let hash = [0; 32];
        let owner_tag = &slot.owner_tag;
        let body = match self.slot(slot.output) {
            Slot::Exit => return self.exit_slot(slot.output, owner_tag.resolved, slot.slot_index),
            Slot::Ring { owner } => {
                let secret = self.slot_secret(
                    &owner.viewing_pubkey,
                    &slot.first_nullifier,
                    slot.slot_index,
                )?;
                match self.format {
                    DisclosureFormat::SingleAssetPayout => seal_compact_recipient_body(
                        &CompactRecipientBody {
                            blinding: slot.output.blinding,
                            amount: slot.output.amount,
                            asset_id: slot.output.asset.asset_id,
                        },
                        &secret,
                    )?,
                    DisclosureFormat::Standard => recipient_delivery::PaddedRecipientBody {
                        body: &recipient_body(slot.output),
                        slot_secret: &secret,
                        width: slot.body_width,
                    }
                    .seal()?,
                }
            }
            Slot::Dummy => random_body(slot.body_width),
        };
        Self::framed(
            RingOutput {
                hash: &hash,
                owner_tag: owner_tag.resolved,
                body: SlotBody::Recipient(&body),
                record: &UNSEALED_RECORD,
                tail: None,
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
    body_width: usize,
    owner_tag: ResolvedOwnerTag,
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

fn random_body(len: usize) -> Vec<u8> {
    let mut body = vec![0u8; len];
    OsRng.fill_bytes(&mut body);
    body
}

pub(crate) fn recipient_body_width(outputs: &[SppProofOutputUtxo]) -> usize {
    let minimum = RECIPIENT_BODY_LEN
        + if outputs.iter().any(|output| {
            !output.is_dummy()
                && [output.data_hash, output.ring_data_hash]
                    .into_iter()
                    .flatten()
                    .any(|hash| hash != [0; 32])
        }) {
            custom_ring_interface::RECIPIENT_BODY_LENGTH_LEN
        } else {
            0
        };
    outputs
        .iter()
        .filter(|output| !output.is_dummy() && output.ring_program_id.is_some())
        .map(|output| recipient_body(output).encoded_len())
        .max()
        .unwrap_or(minimum)
        .max(minimum)
}
