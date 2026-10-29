//! The audit half of a ring transfer, its disclosure sealed to the auditor.

use custom_ring_interface::{
    key_catalog::RingCircuit, AnonymousAuditKey, AuditLayout, AuditorMessage, DisclosureLayout,
    RingOutput, RING_DELIVERED_BODY_LEN,
};
use serde::Serialize;
use spr_client::AsyncRpc;
use spr_event::MessageData;
use spr_hasher::primitives::hash_bytes;
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    derive_output_blinding_seed, instructions::transact::SppProofInputs, SppProofOutputUtxo,
    TransactionError,
};
use zeroize::Zeroizing;
use zolana_ring_client::{
    AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
    AuditDisclosure, AuditEnvelope, DeliveredOutputOpening, DisclosurePad,
};
use zolana_ring_transaction::{PublishedSlot, RingOutputRail};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    request::{
        owner_key, AnonymousAudit, AnonymousOutput, AuditParams, DeliveredAudit, DeliveredOutput,
        Opening,
    },
    RingError,
};

pub(crate) struct SealedAudit {
    pub layout: DisclosureLayout,
    pub flags: AuditLayout,
    pub eph_u: [u8; 32],
    pub sealed: [u8; 32],
    eph_sk: Zeroizing<[u8; 32]>,
    /// The published fields.
    pub fields: Vec<[u8; 32]>,
}

pub(crate) struct PresealedAudit {
    pub message: MessageData,
    pub eph_sk: Zeroizing<[u8; 32]>,
}

pub(super) struct AuditSeal<'a> {
    pub rail: &'a RingOutputRail,
    pub layout: DisclosureLayout,
    pub flags: AuditLayout,
    pub published: &'a [PublishedSlot<'a>],
    pub inputs: &'a SppProofInputs,
    pub sender: &'a ShieldedAddress,
    pub auditor: &'a X25519Pubkey,
}

impl SealedAudit {
    /// Opens `sealed` with the auditor public key alone.
    pub(crate) fn ephemeral_secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.eph_sk
    }
}

impl AuditSeal<'_> {
    pub fn seal(self) -> Result<SealedAudit, RingError> {
        let first_nullifier = self
            .inputs
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier();
        let seed_out = derive_output_blinding_seed(&first_nullifier, &self.inputs.blinding_seed)?;
        let disclosure = self.disclosure(seed_out)?;
        let envelope = AuditEnvelope::seal(self.rail.tx_viewing_key(), self.auditor)?;
        let pad = DisclosurePad::new(self.rail.tx_viewing_key(), &self.rail.salt())?;
        Ok(SealedAudit {
            layout: self.layout,
            flags: self.flags,
            eph_u: envelope.envelope.eph_u,
            sealed: envelope.envelope.sealed,
            eph_sk: envelope.ephemeral_sk,
            fields: pad.encrypt(&disclosure.fields()?)?,
        })
    }

    fn disclosure(&self, seed_out: [u8; 32]) -> Result<AuditDisclosure, RingError> {
        Ok(match self.layout {
            DisclosureLayout::Delivered(layout) => AuditDisclosure::Delivered {
                layout,
                seed_out: layout.exits.then_some(seed_out),
                outputs: self
                    .published
                    .iter()
                    .map(|slot| delivered_opening(slot, layout.key_escrow))
                    .collect::<Result<_, _>>()?,
            },
            DisclosureLayout::Anonymous(layout) => {
                AuditDisclosure::Anonymous(AnonymousDisclosure {
                    layout,
                    seed_out: layout.exits.then_some(seed_out),
                    outputs: self
                        .published
                        .iter()
                        .map(anonymous_opening)
                        .collect::<Result<_, _>>()?,
                    inputs: self.spent(layout.key)?,
                })
            }
        })
    }

    fn spent(&self, key: AnonymousAuditKey) -> Result<AnonymousInputs, RingError> {
        let published = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact());
        Ok(match key {
            AnonymousAuditKey::Commitment { .. } => AnonymousInputs::commitments(
                &published
                    .map(|input| (!input.is_dummy()).then(|| input.private_tx_input_hash()))
                    .collect::<Vec<_>>(),
            )?,
            AnonymousAuditKey::Entry => AnonymousInputs::Openings {
                sender_key: owner_key(&self.sender.signing_pubkey)?,
                sender_nullifier_pk: self.sender.nullifier_pubkey,
                inputs: published
                    .map(|input| match input.is_dummy() {
                        true => Ok(None),
                        false => Ok(Some(AnonymousInputOpening {
                            asset: hash_bytes(input.utxo.asset.asset.as_array())?,
                            amount: input.utxo.amount,
                            blinding: input.utxo.blinding,
                        })),
                    })
                    .collect::<Result<_, RingError>>()?,
            },
        })
    }
}

impl PresealedAudit {
    /// Refused unless the message sits under the ring auditor's tag in the layout of the transfer.
    pub fn open(
        self,
        layout: DisclosureLayout,
        flags: AuditLayout,
        auditor: &X25519Pubkey,
    ) -> Result<SealedAudit, RingError> {
        let message = AuditorMessage::parse(&self.message.data, layout)
            .filter(|_| self.message.view_tag == auditor.u())
            .ok_or(RingError::RelayAuditorMessage)?;
        let eph_u = message.eph_pk[1..]
            .try_into()
            .map_err(|_| RingError::RelayAuditorMessage)?;
        Ok(SealedAudit {
            layout,
            flags,
            eph_u,
            sealed: *message.sealed,
            eph_sk: self.eph_sk,
            fields: message.disclosure.to_vec(),
        })
    }
}

impl SealedAudit {
    /// The message the program expands under the auditor's view tag.
    pub fn message(&self, auditor: &X25519Pubkey) -> MessageData {
        MessageData {
            view_tag: auditor.u(),
            data: AuditorMessage::data(&self.eph_u, &self.sealed, &self.fields),
        }
    }
}

pub(crate) struct AuditProving<'a> {
    pub rail: &'a RingOutputRail,
    pub sealed: &'a SealedAudit,
    pub published: Vec<PublishedSlot<'a>>,
    pub inputs: &'a SppProofInputs,
    pub n_out: u8,
    pub sender: &'a ShieldedAddress,
    pub auditor: &'a X25519Pubkey,
    pub ring_id: [u8; 32],
    pub public_input_hash: [u8; 32],
    /// `None` outside the anonymous rail.
    pub anonymous: Option<&'a AnonymousStatement>,
}

pub(crate) struct AuditRequest {
    pub circuit: RingCircuit,
    pub body: AuditBody,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum AuditBody {
    Delivered(Box<DeliveredAudit>),
    Anonymous(Box<AnonymousAudit>),
}

pub(crate) struct AnonymousStatement {
    pub party_identities: [[u8; 32]; 3],
    pub private_tx_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub sender_commitment: [u8; 32],
}

impl AuditProving<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<custom_ring_interface::CustomRingProof, RingError> {
        let request = self.request()?;
        let proof = RingRequest::new(request.circuit, &request.body)?
            .prove(client, self.public_input_hash)
            .await?;
        to_instruction_proof(proof)
    }

    /// The circuit the sealed layout selects and the body it proves.
    pub fn request(&self) -> Result<AuditRequest, RingError> {
        let inputs = self.inputs;
        let n_out = self.n_out;
        let circuit = RingCircuit::audit(self.sealed.layout, n_out);
        let first_nullifier = inputs
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier();
        let audit = AuditParams {
            first_nullifier,
            ring_id: self.ring_id,
            tx_viewing_sk: self.rail.tx_viewing_key().secret_bytes(),
            eph_sk: self.sealed.eph_sk.clone(),
            auditor_pk: *self.auditor,
            salt: self.rail.salt(),
            layout: self.sealed.flags.value(),
        };
        let tree = inputs.output_tree_id;
        let body = match (self.sealed.layout, self.anonymous) {
            (DisclosureLayout::Delivered(_), _) => AuditBody::Delivered(Box::new(DeliveredAudit {
                public_input_hash: self.public_input_hash,
                audit,
                outputs: self
                    .published
                    .iter()
                    .map(|slot| delivered_output(slot, tree))
                    .collect::<Result<_, _>>()?,
            })),
            (DisclosureLayout::Anonymous(layout), Some(statement)) => {
                let (class, count) = (layout.key.class(), layout.inputs);
                let mut openings = inputs
                    .input_utxos
                    .iter()
                    .filter(|input| !input.is_compact())
                    .map(Opening::input)
                    .collect::<Result<Vec<_>, _>>()?;
                openings.resize(class, Opening::default());
                AuditBody::Anonymous(Box::new(AnonymousAudit {
                    party_identities: statement.party_identities,
                    public_input_hash: self.public_input_hash,
                    audit,
                    outputs: self
                        .published
                        .iter()
                        .map(|slot| anonymous_output(slot, tree))
                        .collect::<Result<_, _>>()?,
                    private_tx_hash: statement.private_tx_hash,
                    private_tx_blinding: statement.private_tx_blinding,
                    sender_key: (layout.key == AnonymousAuditKey::Entry)
                        .then(|| owner_key(&self.sender.signing_pubkey))
                        .transpose()?,
                    input_count: u8::try_from(count).map_err(|_| {
                        TransactionError::TooManyInputs {
                            got: count,
                            max: usize::from(u8::MAX),
                        }
                    })?,
                    inputs: openings,
                    sender_commitment: statement.sender_commitment,
                }))
            }
            (DisclosureLayout::Anonymous(_), None) => {
                return Err(RingError::MissingAnonymousSigner)
            }
        };
        Ok(AuditRequest { circuit, body })
    }
}

fn slot_owner_key(output: &SppProofOutputUtxo) -> Result<[u8; 32], RingError> {
    output
        .owner_address
        .map(|owner| owner_key(&owner.signing_pubkey))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn disclosed_key(owner: &ShieldedAddress, key_escrow: bool) -> Option<[u8; 32]> {
    (!key_escrow).then_some(owner.nullifier_pubkey)
}

fn delivered_opening(
    slot: &PublishedSlot<'_>,
    key_escrow: bool,
) -> Result<DeliveredOutputOpening, RingError> {
    let output = slot.output;
    let Some(owner) = output.owner_address else {
        return Ok(DeliveredOutputOpening::Dummy);
    };
    Ok(match slot.wire.is_exit() {
        true => DeliveredOutputOpening::Exit {
            nullifier_pk: disclosed_key(&owner, key_escrow),
            asset: hash_bytes(output.asset.asset.as_array())?,
            amount: output.amount,
        },
        false => DeliveredOutputOpening::Ring {
            owner_key: owner_key(&owner.signing_pubkey)?,
            nullifier_pk: disclosed_key(&owner, key_escrow),
        },
    })
}

fn anonymous_opening(slot: &PublishedSlot<'_>) -> Result<AnonymousOutputOpening, RingError> {
    let output = slot.output;
    let Some(owner) = output.owner_address else {
        return Ok(AnonymousOutputOpening::Dummy);
    };
    let asset = hash_bytes(output.asset.asset.as_array())?;
    Ok(match slot.wire.is_exit() {
        true => AnonymousOutputOpening::Exit {
            nullifier_pk: owner.nullifier_pubkey,
            asset,
            amount: output.amount,
        },
        false => AnonymousOutputOpening::Ring {
            owner_key: owner_key(&owner.signing_pubkey)?,
            nullifier_pk: owner.nullifier_pubkey,
            asset,
            amount: output.amount,
        },
    })
}

/// A ring output opens its body for its recipient, padding binds its published key and body.
fn delivered_output(slot: &PublishedSlot<'_>, tree: u16) -> Result<DeliveredOutput, RingError> {
    let output = slot.output;
    let (recipient_key, body) = match slot.wire {
        RingOutput::Delivered { u, body, .. } => (*u, *body),
        RingOutput::Anonymous { .. } | RingOutput::Exit { .. } => {
            ([0; 32], [0; RING_DELIVERED_BODY_LEN])
        }
    };
    let ring = !output.is_dummy() && !slot.wire.is_exit();
    Ok(DeliveredOutput {
        output: Opening::output(output, tree)?,
        recipient_key,
        owner_key: match ring {
            true => slot_owner_key(output)?,
            false => [0; 32],
        },
        body,
    })
}

/// An exit's owner key is masked out of the disclosure, a dummy names none.
fn anonymous_output(slot: &PublishedSlot<'_>, tree: u16) -> Result<AnonymousOutput, RingError> {
    let output = slot.output;
    Ok(AnonymousOutput {
        output: Opening::output(output, tree)?,
        owner_key: slot_owner_key(output)?,
    })
}
