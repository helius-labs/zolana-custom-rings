//! The audit half of a ring transfer, its stream sealed to the auditor.
//!
//! The stream seals the viewing secret, `R`, the entry records in note order and each published
//! slot's recipient key. A non-exit slot's record travels in its body, an exit's in the message.

use custom_ring_interface::{
    disclosure::AuditLayout, AuditEvidence, AuditStreamLayout, AuditorMessage, EntryRecord,
    RecordKind, OUTPUT_RECORD_LEN,
};
use spr_event::MessageData;
use spr_hasher::primitives::pack_be;
use spr_keypair::X25519Pubkey;
use spr_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, Mint, TransactionError,
};
use zolana_ring_client::AuditStreamSeal;
use zolana_ring_transaction::{
    address_chain, note_count, published_outputs, ClassifiedInput, RingOutputRail,
};

use super::SealRow;
use crate::{
    request::{owner_key, AuditParams, EntryOpening, Opening, OutputOpening},
    RingError,
};

pub(crate) struct SealedAudit {
    pub flags: AuditLayout,
    pub eph_u: [u8; 32],
    pub envelope: Vec<u8>,
    /// One sealed recipient key per published slot.
    pub keys: Vec<u8>,
    /// One record per exit in slot order.
    pub exit_records: Vec<[u8; OUTPUT_RECORD_LEN]>,
}

pub(crate) struct PresealedAudit {
    pub message: MessageData,
    /// The row the owner sealed under, a read keeps the seal only where its stream opens alike.
    pub row: SealRow,
}

pub(super) struct AuditSeal<'a> {
    pub rail: &'a RingOutputRail,
    pub layout: AuditStreamLayout,
    pub flags: AuditLayout,
    pub inputs: &'a SppProofInputs,
    pub auditor: &'a X25519Pubkey,
}

impl AuditSeal<'_> {
    pub fn seal(self) -> Result<SealedAudit, RingError> {
        let slots = &self.inputs.output_utxos[..self.layout.outputs];
        let recipient_keys = self
            .rail
            .recipient_keys(&self.inputs.output_utxos, self.layout.outputs)?
            .iter()
            .map(X25519Pubkey::u)
            .collect();
        let sealed = AuditStreamSeal {
            layout: self.layout,
            tx_viewing_key: self.rail.tx_viewing_key(),
            salt: &self.rail.salt(),
            real_inputs: note_count(&self.inputs.input_utxos)?,
            evidence: self.evidence()?,
            recipient_keys,
        }
        .seal(self.auditor)?;
        let first_nullifier = self.inputs.first_nullifier()?;
        let exit_records = slots
            .iter()
            .enumerate()
            .filter(|(_, output)| {
                output.owner_address.is_some() && output.ring_program_id.is_none()
            })
            .map(|(slot, output)| self.rail.exit_record(output, &first_nullifier, slot))
            .collect::<Result<_, _>>()?;
        Ok(SealedAudit {
            flags: self.flags,
            eph_u: sealed.eph_u,
            envelope: sealed.envelope,
            keys: sealed.keys,
            exit_records,
        })
    }

    /// Bit `k` names note `k`, record `k` the same note, zero past `R` and on a ring note.
    fn evidence(&self) -> Result<AuditEvidence, RingError> {
        if !self.layout.key.entry {
            return Ok(AuditEvidence::None);
        }
        let mut default_note_bits = 0;
        let mut inputs = vec![EntryRecord::default(); self.layout.inputs];
        for (note, input) in spent_notes(self.inputs).enumerate() {
            if is_default_ring(input) {
                default_note_bits |= 1 << note;
                *inputs.get_mut(note).ok_or(RingError::RelayAuditorMessage)? = entry_record(input)?;
            }
        }
        Ok(AuditEvidence::Entry {
            default_note_bits,
            inputs,
        })
    }
}

/// SPP's spent notes in slot order, the ring's input wires in note order.
fn spent_notes(inputs: &SppProofInputs) -> impl Iterator<Item = &SppProofInputUtxo> {
    inputs.input_utxos.iter().filter(|input| input.is_note())
}

pub(super) fn is_default_ring(input: &SppProofInputUtxo) -> bool {
    input.is_note() && input.utxo.ring_program_id.is_none()
}

/// `input_commitment` is the spent hash the proof reads into `private_tx_hash`.
fn entry_record(input: &SppProofInputUtxo) -> Result<EntryRecord, RingError> {
    Ok(EntryRecord {
        owner_key: owner_key(&input.utxo.owner)?,
        nullifier_pk: input.nullifier_pubkey,
        amount: input.utxo.amount,
        mint: input.utxo.asset.asset.to_bytes(),
        input_commitment: input.utxo_hash,
    })
}

impl PresealedAudit {
    /// Refused unless the message sits under the ring auditor's tag in the layout of the transfer.
    pub fn open(
        self,
        layout: AuditStreamLayout,
        flags: AuditLayout,
        auditor: &X25519Pubkey,
        exits: usize,
    ) -> Result<SealedAudit, RingError> {
        let message = AuditorMessage::parse(&self.message.data, layout, exits)
            .filter(|_| self.message.view_tag == auditor.u())
            .ok_or(RingError::RelayAuditorMessage)?;
        let eph_u = message.eph_pk[1..]
            .try_into()
            .map_err(|_| RingError::RelayAuditorMessage)?;
        let exit_records = (0..exits)
            .map(|exit| message.exit_record(exit).copied())
            .collect::<Option<_>>()
            .ok_or(RingError::RelayAuditorMessage)?;
        Ok(SealedAudit {
            flags,
            eph_u,
            envelope: message.envelope.to_vec(),
            keys: message.recipient_keys.to_vec(),
            exit_records,
        })
    }
}

impl SealedAudit {
    /// The message the program expands under the auditor's view tag.
    pub fn message(&self, auditor: &X25519Pubkey) -> MessageData {
        MessageData {
            view_tag: auditor.u(),
            data: AuditorMessage::data(
                &self.eph_u,
                [self.envelope.as_slice(), self.keys.as_slice()]
                    .into_iter()
                    .chain(
                        self.exit_records
                            .iter()
                            .map(<[u8; OUTPUT_RECORD_LEN]>::as_slice),
                    ),
            ),
        }
    }
}

pub(super) struct AuditSection<'a> {
    pub rail: &'a RingOutputRail,
    pub sealed: &'a SealedAudit,
    pub inputs: &'a SppProofInputs,
    pub auditor: &'a X25519Pubkey,
}

impl AuditSection<'_> {
    pub fn params(&self) -> Result<AuditParams, RingError> {
        Ok(AuditParams {
            first_nullifier: self
                .inputs
                .input_utxos
                .first()
                .ok_or(TransactionError::NoInputs)?
                .nullifier(),
            tx_viewing_sk: self.rail.tx_viewing_key().secret_bytes(),
            auditor_pk: *self.auditor,
            salt: self.rail.salt(),
            layout: self.sealed.flags.value(),
        })
    }

    /// The key's `N` slots, a dummy and a slot past the published ones name no owner, the second
    /// seals to the auditor.
    pub fn output_openings(&self, capacity: usize) -> Result<Vec<OutputOpening>, RingError> {
        let tree = self.inputs.output_tree_id;
        let keys = self
            .rail
            .recipient_keys(&self.inputs.output_utxos, capacity)?;
        let published = published_outputs(&self.inputs.output_utxos);
        keys.iter()
            .enumerate()
            .map(|(slot, key)| {
                let Some(output) = published.get(slot) else {
                    return Ok(OutputOpening {
                        output: Opening::padding(),
                        owner_key: [0; 32],
                        mint_chunks: [[0; 32]; 2],
                        recipient_key: key.u(),
                    });
                };
                let record = RingOutputRail::output_record(output)?;
                Ok(OutputOpening {
                    output: Opening::output(output, tree)?,
                    owner_key: record.owner_key,
                    mint_chunks: match record.kind {
                        RecordKind::Dummy => [[0; 32]; 2],
                        RecordKind::Ring | RecordKind::Exit => mint_chunks(&output.asset),
                    },
                    recipient_key: key.u(),
                })
            })
            .collect()
    }

    /// Spent notes in note order then dummies, an address reaches the proof through `address_chain`
    /// alone.
    pub fn input_openings(&self, class: usize) -> Result<Vec<Opening>, RingError> {
        let mut openings = spent_notes(self.inputs)
            .map(Opening::input)
            .collect::<Result<Vec<_>, _>>()?;
        openings.resize(class, Opening::padding());
        Ok(openings)
    }

    /// SPP's address chain the proof reopens inside `private_tx_hash`.
    pub fn address_chain(&self) -> Result<[u8; 32], RingError> {
        Ok(address_chain(&self.inputs.input_utxos)?)
    }

    /// One per input class slot on an entry key in note order, zero off a default-ring note.
    pub fn entry_openings(&self, class: usize) -> Result<Vec<EntryOpening>, RingError> {
        let mut openings = spent_notes(self.inputs)
            .map(|input| match is_default_ring(input) {
                true => owner_key(&input.utxo.owner).map(|key| EntryOpening {
                    owner_key: key,
                    mint_chunks: mint_chunks(&input.utxo.asset),
                }),
                false => Ok(EntryOpening::default()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        openings.resize(class, EntryOpening::default());
        Ok(openings)
    }
}

fn mint_chunks(asset: &Mint) -> [[u8; 32]; 2] {
    pack_be::<32, 2>(asset.asset.as_array())
}
