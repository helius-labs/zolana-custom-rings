//! The audit half of a ring transfer, its stream sealed to the auditor.

use custom_ring_interface::{
    disclosure::AuditLayout, AuditEvidence, AuditRecord, AuditStreamLayout, AuditorMessage,
    DataTail, DisclosureFormat, EntryRecord, RecordKind, DATA_TAIL_LEN,
};
use spr_event::MessageData;
use spr_hasher::primitives::pack_be;
use spr_keypair::X25519Pubkey;
use spr_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, Mint, SppProofOutputUtxo,
    TransactionError,
};
use zolana_ring_client::AuditStreamSeal;
use zolana_ring_transaction::{published_input_map, ClassifiedInput, RingOutputRail};

use super::SealRow;
use crate::{
    request::{owner_key, AuditParams, EntryOpening, Opening, OutputOpening},
    RingError,
};

pub(crate) struct SealedAudit {
    pub flags: AuditLayout,
    pub eph_u: [u8; 32],
    pub envelope: Vec<u8>,
    /// One per slot.
    pub records: Vec<Vec<u8>>,
    /// One per slot under `has_data`, else none.
    pub tails: Vec<[u8; DATA_TAIL_LEN]>,
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
        let records = slots
            .iter()
            .map(audit_record)
            .collect::<Result<_, RingError>>()?;
        let tails = match self.layout.has_data {
            true => slots.iter().map(data_tail).collect(),
            false => Vec::new(),
        };
        let inputs = published_input_map(&self.inputs.input_utxos, self.layout.key.class())?;
        let sealed = AuditStreamSeal {
            layout: self.layout,
            tx_viewing_key: self.rail.tx_viewing_key(),
            salt: &self.rail.salt(),
            inputs,
            evidence: self.evidence()?,
            records,
            tails,
        }
        .seal(self.auditor)?;
        Ok(SealedAudit {
            flags: self.flags,
            eph_u: sealed.eph_u,
            envelope: sealed.envelope,
            records: sealed.records,
            tails: sealed.tails,
        })
    }

    /// Bit `i` names absolute position `i`, an address or a dummy never sets one.
    fn evidence(&self) -> Result<AuditEvidence, RingError> {
        if self.layout.key.format == DisclosureFormat::SingleAssetPayout {
            let mint = self
                .inputs
                .output_utxos
                .first()
                .ok_or(RingError::RelayAuditorMessage)?
                .asset
                .asset
                .to_bytes();
            return Ok(AuditEvidence::SingleAssetPayout { mint });
        }
        if !self.layout.key.entry {
            return Ok(AuditEvidence::None);
        }
        let published = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact());
        let mut default_input_bits = 0;
        let mut inputs = Vec::with_capacity(self.layout.inputs);
        for (index, input) in published.enumerate() {
            let default_ring = is_default_ring(input);
            if default_ring {
                default_input_bits |= 1 << index;
            }
            inputs.push(match default_ring {
                true => entry_record(input)?,
                false => EntryRecord::default(),
            });
        }
        Ok(AuditEvidence::Entry {
            default_input_bits,
            inputs,
        })
    }
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

/// The proof holds a dummy's plaintext to zero.
pub(super) fn audit_record(output: &SppProofOutputUtxo) -> Result<AuditRecord, RingError> {
    let owner = match output.owner_address {
        Some(owner) if !output.is_dummy() => owner,
        _ => return Ok(AuditRecord::default()),
    };
    Ok(AuditRecord {
        kind: match output.ring_program_id {
            Some(_) => RecordKind::Ring,
            None => RecordKind::Exit,
        },
        amount: output.amount,
        owner_key: owner_key(&owner.signing_pubkey)?,
        mint: output.asset.asset.to_bytes(),
        nullifier_pk: owner.nullifier_pubkey,
    })
}

fn data_tail(output: &SppProofOutputUtxo) -> DataTail {
    match output.is_dummy() {
        true => DataTail::default(),
        false => DataTail {
            data_hash: output.data_hash.unwrap_or_default(),
            ring_data_hash: output.ring_data_hash.unwrap_or_default(),
        },
    }
}

impl PresealedAudit {
    /// Refused unless the message sits under the ring auditor's tag in the layout of the transfer.
    pub fn open(
        self,
        layout: AuditStreamLayout,
        flags: AuditLayout,
        auditor: &X25519Pubkey,
    ) -> Result<SealedAudit, RingError> {
        let message = AuditorMessage::parse(&self.message.data, layout)
            .filter(|_| self.message.view_tag == auditor.u())
            .ok_or(RingError::RelayAuditorMessage)?;
        let eph_u = message.eph_pk[1..]
            .try_into()
            .map_err(|_| RingError::RelayAuditorMessage)?;
        let records = (0..layout.outputs)
            .map(|slot| message.record(slot).map(<[u8]>::to_vec))
            .collect::<Option<_>>()
            .ok_or(RingError::RelayAuditorMessage)?;
        let tails = match layout.has_data {
            true => (0..layout.outputs)
                .map(|slot| message.tail(slot).copied())
                .collect::<Option<_>>()
                .ok_or(RingError::RelayAuditorMessage)?,
            false => Vec::new(),
        };
        Ok(SealedAudit {
            flags,
            eph_u,
            envelope: message.envelope.to_vec(),
            records,
            tails,
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
                core::iter::once(self.envelope.as_slice())
                    .chain(self.records.iter().map(Vec::as_slice))
                    .chain(self.tails.iter().map(<[u8; DATA_TAIL_LEN]>::as_slice)),
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

    /// The key's `N` slots, a dummy and a slot past the SPP shape name no owner.
    pub fn output_openings(&self, capacity: usize) -> Result<Vec<OutputOpening>, RingError> {
        let tree = self.inputs.output_tree_id;
        let mut openings = self
            .inputs
            .output_utxos
            .iter()
            .map(|output| {
                let record = audit_record(output)?;
                Ok(OutputOpening {
                    output: Opening::output(output, tree)?,
                    owner_key: record.owner_key,
                    mint_chunks: match record.kind {
                        RecordKind::Dummy => [[0; 32]; 2],
                        RecordKind::Ring | RecordKind::Exit => mint_chunks(&output.asset),
                    },
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        openings.resize_with(capacity, OutputOpening::default);
        Ok(openings)
    }

    /// The spent notes' openings in SPP order, dummies past them to the key's input class.
    pub fn input_openings(&self, class: usize) -> Result<Vec<Opening>, RingError> {
        let mut openings = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .map(Opening::input)
            .collect::<Result<Vec<_>, _>>()?;
        openings.resize(class, Opening::input_padding());
        Ok(openings)
    }

    /// One per input class slot on an entry key, zero off a default-ring note.
    pub fn entry_openings(&self, class: usize) -> Result<Vec<EntryOpening>, RingError> {
        let mut openings = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
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
