use custom_ring_interface::{
    blinding::ring_blinding_seed, AuditEvidence, AuditRecord, AuditStreamLayout, AuditorMessage,
    DataTail, EntryInput, InputClass, InputMap, ParsedTransact, RecordKind,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::ProofInputUtxo;
use spr_event::MessageData;
use spr_hasher::primitives::{hash_bytes, right_align};
use spr_interface::{instruction::instruction_data::OwnerTag, tree_slot::tree_id_field};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, DUMMY_DOMAIN},
    OutputContext, OutputSlot, ShieldedTransaction,
};

use crate::{
    disclosure::{canonical, AuditEnvelope},
    encryption::auditor_view_tag,
    types::{
        AuditedDefaultInput, AuditedInput, AuditedOutput, AuditedTransaction, AuditedUtxo,
        InputOpening, OutputOpening, OutputPayloadError, OutputPayloadErrorKind, RingOwnerTag,
    },
    AuditError,
};

/// Only [`crate::RingScan::audit`] binds the transaction to its confirmed event.
#[must_use = "run the audit explicitly"]
pub struct TransactionAudit<'a> {
    transaction: &'a ShieldedTransaction,
    layout: AuditStreamLayout,
    input_trees: Option<&'a [Option<u16>]>,
}

/// The row a frame's event publishes, the co-signer audits its own message before it lands.
#[must_use]
pub struct FramedRow<'a, 'f> {
    pub parsed: &'a ParsedTransact<'f>,
    pub ring: Address,
    pub auditor: &'a X25519Pubkey,
    pub output_tree_id: u16,
}

impl FramedRow<'_, '_> {
    pub fn row(self) -> Result<ShieldedTransaction, AuditError> {
        let data = self.parsed.data();
        let output_slots = data
            .outputs
            .iter()
            .zip(data.slot_replies())
            .map(|(output, reply)| {
                let published = output
                    .transact_output(reply)
                    .map_err(|_| AuditError::DisclosureField)?;
                let OwnerTag::Inline(view_tag) = published.owner_tag else {
                    return Err(AuditError::DisclosureField);
                };
                Ok(OutputSlot {
                    view_tag,
                    output_context: OutputContext {
                        hash: published.utxo_hash,
                        tree_id: self.output_tree_id,
                        leaf_index: 0,
                    },
                    payload: published.data.unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, AuditError>>()?;
        Ok(ShieldedTransaction {
            slot: 0,
            tx_signature: Signature::default(),
            event_index: None,
            tx_viewing_pk: Some(X25519Pubkey::from_u(*data.tx_viewing_u)?),
            salt: Some(*data.salt),
            output_slots,
            messages: vec![MessageData {
                view_tag: auditor_view_tag(self.auditor),
                data: data.auditor_message(),
            }],
            nullifiers: data.nullifiers.to_vec(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(self.ring),
        })
    }
}

impl<'a> TransactionAudit<'a> {
    pub fn new(transaction: &'a ShieldedTransaction, layout: AuditStreamLayout) -> Self {
        Self {
            transaction,
            layout,
            input_trees: None,
        }
    }

    /// Every input commitment binds its tree id.
    pub fn with_input_trees(mut self, trees: &'a [Option<u16>]) -> Result<Self, AuditError> {
        let inputs = self.transaction.nullifiers.len();
        if trees.len() != inputs {
            return Err(AuditError::InputTreeCount {
                trees: trees.len(),
                inputs,
            });
        }
        self.input_trees = Some(trees);
        Ok(self)
    }

    /// Reads no mint registry or earlier note.
    pub fn run(self, auditor: &X25519Keypair) -> Result<AuditedTransaction, AuditError> {
        let tx = self.transaction;
        let layout = self.layout;
        let tx_viewing_pk = tx.tx_viewing_pk.ok_or(AuditError::MissingTxViewingPk)?;
        let salt = tx.salt.ok_or(AuditError::MissingSalt)?;
        let ring = tx.ring_program_id.ok_or(AuditError::MissingRingProgram)?;
        let first_nullifier = *tx.nullifiers.first().ok_or(AuditError::MissingNullifier)?;
        let data = auditor_message(tx, &auditor.pubkey())?;
        check_published(layout, tx)?;
        let message = AuditorMessage::parse(data, layout)
            .ok_or(AuditError::AuditorMessageLength(data.len()))?;
        let opened = AuditEnvelope {
            eph_u: X25519Pubkey::from_bytes(*message.eph_pk)?.u(),
            salt: &salt,
            ciphertext: message.envelope,
        }
        .open(auditor, layout)?;
        let tx_key = &opened.tx_viewing_key;
        // The audit proof binds the envelope to the published key.
        if tx_key.pubkey() != tx_viewing_pk {
            return Err(AuditError::TxViewingKeyMismatch);
        }
        let transfer = Transfer::new(ring, first_nullifier, tx_key, &salt)?;
        let mut audited = AuditedTransaction {
            tx_signature: tx.tx_signature,
            slot: tx.slot,
            tx_viewing_pk,
            real_inputs: opened.inputs.note_count(),
            outputs: Vec::new(),
            payload_errors: Vec::new(),
            inputs: Vec::new(),
        };
        for (index, output) in (0u32..).zip(&tx.output_slots) {
            let slot = Slot { index, output };
            let position = index as usize;
            let truncated = || AuditError::AuditorMessageLength(data.len());
            let record =
                opened.record(position, message.record(position).ok_or_else(truncated)?)?;
            let tail = match layout.has_data {
                true => opened.tail(position, message.tail(position).ok_or_else(truncated)?)?,
                false => DataTail::default(),
            };
            audited.place(
                index,
                output.output_context.clone(),
                transfer.slot(slot, record, tail)?,
            );
        }
        audited.inputs = transfer.inputs(SpentInputs {
            map: opened.inputs,
            evidence: &opened.evidence,
            nullifiers: &tx.nullifiers,
            trees: self.input_trees,
        })?;
        Ok(audited)
    }
}

fn check_published(layout: AuditStreamLayout, tx: &ShieldedTransaction) -> Result<(), AuditError> {
    let consistent =
        layout.outputs == tx.output_slots.len() && layout.inputs == tx.nullifiers.len();
    match consistent {
        true => Ok(()),
        false => Err(AuditError::DisclosureLayout),
    }
}

/// The program keeps the auditor message last, the tag of any earlier message is free frame bytes.
fn auditor_message<'a>(
    tx: &'a ShieldedTransaction,
    auditor_pk: &X25519Pubkey,
) -> Result<&'a [u8], AuditError> {
    tx.messages
        .last()
        .filter(|message| message.view_tag == auditor_view_tag(auditor_pk))
        .map(|message| message.data.as_slice())
        .ok_or(AuditError::MissingAuditorMessage)
}

#[derive(Clone, Copy)]
struct Slot<'a> {
    index: u32,
    output: &'a OutputSlot,
}

impl Slot<'_> {
    fn owner_tag(self) -> [u8; 32] {
        self.output.view_tag
    }

    fn tree_id(self) -> u16 {
        self.output.output_context.tree_id
    }

    fn rebuilt(self, commitment: [u8; 32], opening: OutputOpening) -> SlotOpening {
        match commitment == self.output.output_context.hash {
            true => Ok(opening),
            false => Err(OutputPayloadErrorKind::Commitment),
        }
    }
}

type SlotOpening = Result<OutputOpening, OutputPayloadErrorKind>;

struct Transfer {
    ring: Address,
    first_nullifier: [u8; 32],
    seed_out: [u8; 32],
}

struct SpentInputs<'a> {
    map: InputMap,
    evidence: &'a AuditEvidence,
    nullifiers: &'a [[u8; 32]],
    trees: Option<&'a [Option<u16>]>,
}

impl Transfer {
    fn new(
        ring: Address,
        first_nullifier: [u8; 32],
        tx_key: &ViewingKey,
        salt: &[u8; 16],
    ) -> Result<Self, AuditError> {
        Ok(Self {
            ring,
            first_nullifier,
            seed_out: derive_output_blinding_seed(
                &first_nullifier,
                &ring_blinding_seed(&tx_key.secret_bytes(), salt)?,
            )?,
        })
    }

    fn slot(
        &self,
        slot: Slot<'_>,
        record: AuditRecord,
        tail: DataTail,
    ) -> Result<SlotOpening, AuditError> {
        let ring = match record.kind {
            RecordKind::Dummy => return self.verify_dummy(slot),
            RecordKind::Ring => Some(self.ring),
            RecordKind::Exit => None,
        };
        let AuditRecord {
            owner_key,
            mint,
            amount,
            nullifier_pk,
            ..
        } = record;
        if canonical(nullifier_pk).is_err()
            || canonical(tail.data_hash).is_err()
            || canonical(tail.ring_data_hash).is_err()
        {
            return Ok(Err(OutputPayloadErrorKind::Disclosure));
        }
        let utxo = AuditedUtxo {
            owner_key,
            nullifier_pk,
            asset: hash_bytes(&mint)?,
            mint: Some(Address::new_from_array(mint)),
            amount,
            blinding: self.blinding(slot)?,
            data_hash: tail.data_hash,
            ring_data_hash: tail.ring_data_hash,
        };
        let commitment = utxo.commitment(slot.tree_id(), ring)?;
        Ok(slot.rebuilt(
            commitment,
            match ring {
                Some(_) => OutputOpening::Ring {
                    utxo,
                    owner_tag: RingOwnerTag(slot.owner_tag()),
                },
                None => OutputOpening::Exit(utxo),
            },
        ))
    }

    fn verify_dummy(&self, slot: Slot<'_>) -> Result<SlotOpening, AuditError> {
        let commitment = ProofInputUtxo {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(slot.tree_id()),
            blinding: self.blinding(slot)?,
            ..ProofInputUtxo::default()
        }
        .hash()?;
        Ok(slot.rebuilt(commitment, OutputOpening::Dummy))
    }

    /// SPP's TXOB blinding under the seed the transaction key derives.
    fn blinding(&self, slot: Slot<'_>) -> Result<[u8; 32], AuditError> {
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &self.seed_out,
            slot.index,
        )?)
    }

    /// The proven map classifies each position, its default bits name notes alone.
    fn inputs(&self, spent: SpentInputs<'_>) -> Result<Vec<AuditedInput>, AuditError> {
        let SpentInputs {
            map,
            evidence,
            nullifiers,
            trees,
        } = spent;
        nullifiers
            .iter()
            .enumerate()
            .map(|(index, nullifier)| {
                let class = map.slot(index).ok_or(AuditError::DisclosureLayout)?;
                let opening = match class {
                    InputClass::Dummy => InputOpening::Dummy,
                    InputClass::Address => InputOpening::Address,
                    InputClass::Note => match evidence {
                        AuditEvidence::Entry {
                            default_input_bits,
                            inputs,
                        } if default_input_bits >> index & 1 == 1 => {
                            let entry = inputs.get(index).ok_or(AuditError::DisclosureLayout)?;
                            let tree = trees.and_then(|trees| trees.get(index).copied().flatten());
                            InputOpening::External(Box::new(self.default_input(entry, tree)?))
                        }
                        AuditEvidence::None
                        | AuditEvidence::SingleAssetPayout { .. }
                        | AuditEvidence::Entry { .. } => InputOpening::Real,
                    },
                };
                Ok(AuditedInput {
                    nullifier: *nullifier,
                    opening,
                })
            })
            .collect()
    }

    /// A mixed entry names each input's owner and key.
    fn default_input(
        &self,
        entry: &EntryInput,
        tree: Option<u16>,
    ) -> Result<AuditedDefaultInput, AuditError> {
        let utxo = AuditedUtxo {
            owner_key: entry.owner_key,
            nullifier_pk: entry.nullifier_pk,
            asset: hash_bytes(&entry.mint)?,
            mint: Some(Address::new_from_array(entry.mint)),
            amount: entry.amount,
            blinding: entry.blinding,
            data_hash: entry.data_hash,
            ring_data_hash: entry.ring_data_hash,
        };
        let commitment = tree.map(|tree| utxo.commitment(tree, None)).transpose()?;
        Ok(AuditedDefaultInput { utxo, commitment })
    }
}

impl AuditedTransaction {
    /// A slot appears once, in published order.
    fn place(&mut self, slot_index: u32, context: OutputContext, opened: SlotOpening) {
        self.outputs
            .retain(|output| output.slot_index != slot_index);
        self.payload_errors
            .retain(|error| error.slot_index != slot_index);
        match opened {
            Ok(opening) => {
                let at = self
                    .outputs
                    .partition_point(|output| output.slot_index < slot_index);
                self.outputs.insert(
                    at,
                    AuditedOutput {
                        slot_index,
                        context,
                        opening,
                    },
                );
            }
            Err(kind) => {
                let at = self
                    .payload_errors
                    .partition_point(|error| error.slot_index < slot_index);
                self.payload_errors
                    .insert(at, OutputPayloadError { slot_index, kind });
            }
        }
    }
}
