use custom_ring_interface::{
    blinding::ring_blinding_seed, ring_body_output, stream::DeliveredSlot, AuditEvidence,
    AuditStreamLayout, AuditorMessage, EntryRecord, OutputRecord, ParsedTransact, RecordKind,
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

use zolana_ring_transaction::{open_recipient_body, OpenedRecipientBody, PayloadRead};

use crate::{
    disclosure::{canonical, AuditEnvelope},
    encryption::auditor_view_tag,
    types::{
        AuditedEntryInput, AuditedOutput, AuditedTransaction, AuditedUtxo, OutputOpening,
        OutputPayloadError, OutputPayloadErrorKind, RingOwnerTag,
    },
    AuditError,
};

/// Only [`crate::RingScan::audit`] binds the transaction to its confirmed event.
#[must_use = "run the audit explicitly"]
pub struct TransactionAudit<'a> {
    transaction: &'a ShieldedTransaction,
    layout: AuditStreamLayout,
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
        }
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
        // A slot without a ring body is an exit, its record sits in the auditor message.
        let exits = tx
            .output_slots
            .iter()
            .filter(|slot| ring_body_output(&slot.payload).is_none())
            .count();
        let message = AuditorMessage::parse(data, layout, exits)
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
        let keys = opened.recipient_keys(message.recipient_keys)?;
        let transfer = Transfer::new(ring, first_nullifier, tx_key, &salt)?;
        let mut audited = AuditedTransaction {
            tx_signature: tx.tx_signature,
            slot: tx.slot,
            tx_viewing_pk,
            real_inputs: opened.real_inputs,
            outputs: Vec::new(),
            payload_errors: Vec::new(),
            nullifiers: tx.nullifiers.clone(),
            entries: entry_inputs(&opened.evidence)?,
        };
        let mut exit = 0;
        for ((index, output), recipient) in (0u32..).zip(&tx.output_slots).zip(&keys) {
            let slot = Slot { index, output };
            // 1. The proof encrypts each record to the slot's sealed key under the transaction's secret.
            let secret = DeliveredSlot {
                agreement: &tx_key.ecdh(recipient)?,
                tx_viewing_pk: tx_viewing_pk.as_bytes(),
                recipient_viewing_pk: recipient.as_bytes(),
                salt: &salt,
                output_index: index,
                first_nullifier: &first_nullifier,
            }
            .secret()?;
            // 2. A body leads with its record, an exit's record is the next in the message.
            let ciphertext = match ring_body_output(&output.payload) {
                Some((body, _)) => body,
                None => {
                    let record = message
                        .exit_record(exit)
                        .ok_or(AuditError::AuditorMessageLength(data.len()))?;
                    exit += 1;
                    &record[..]
                }
            };
            let read = match open_recipient_body(ciphertext, &secret) {
                Ok(body) => transfer.slot(slot, body)?,
                Err(_) => SlotRead::refused(OutputPayloadErrorKind::Disclosure),
            };
            audited.place(index, output.output_context.clone(), read);
        }
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

    fn commitment(self) -> [u8; 32] {
        self.output.output_context.hash
    }
}

/// A slot's proven opening and its payload's fault, apart.
struct SlotRead {
    opening: Option<OutputOpening>,
    error: Option<OutputPayloadErrorKind>,
}

impl SlotRead {
    const fn refused(kind: OutputPayloadErrorKind) -> Self {
        Self {
            opening: None,
            error: Some(kind),
        }
    }
}

struct Transfer {
    ring: Address,
    first_nullifier: [u8; 32],
    seed_out: [u8; 32],
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

    /// The proof binds each record field to the published commitment, payload data hashes join only
    /// when they rebuild it.
    fn slot(&self, slot: Slot<'_>, body: OpenedRecipientBody) -> Result<SlotRead, AuditError> {
        let OpenedRecipientBody { record, payload } = body;
        let ring = match record.kind {
            RecordKind::Dummy => return self.verify_dummy(slot),
            RecordKind::Ring => Some(self.ring),
            RecordKind::Exit => None,
        };
        let OutputRecord {
            owner_key,
            mint,
            amount,
            nullifier_pk,
            blinding,
            ..
        } = record;
        // The proof holds both record fields canonical.
        if canonical(nullifier_pk).is_err() || canonical(blinding).is_err() {
            return Err(AuditError::DisclosureField);
        }
        // An exit's data sits in its scheme 3 body, sealed to its owner alone.
        let claimed = match payload {
            PayloadRead::Absent => Some(([0; 32], [0; 32])),
            PayloadRead::Opened(payload) => Some((
                payload
                    .data
                    .first_chunk::<32>()
                    .copied()
                    .unwrap_or_default(),
                payload.ring_data_hash.unwrap_or_default(),
            )),
            PayloadRead::Malformed => None,
        }
        .filter(|(data_hash, ring_data_hash)| {
            canonical(*data_hash).is_ok() && canonical(*ring_data_hash).is_ok()
        });
        let mut utxo = AuditedUtxo {
            owner_key,
            nullifier_pk,
            asset: hash_bytes(&mint)?,
            mint: Some(Address::new_from_array(mint)),
            amount,
            blinding,
            data_hash: claimed.map(|(data_hash, _)| data_hash),
            ring_data_hash: claimed.map(|(_, ring_data_hash)| ring_data_hash),
        };
        let mut error = None;
        if utxo.commitment(slot.tree_id(), ring)? != Some(slot.commitment()) {
            utxo.data_hash = None;
            utxo.ring_data_hash = None;
            error = Some(OutputPayloadErrorKind::Payload);
        }
        Ok(SlotRead {
            opening: Some(match ring {
                Some(_) => OutputOpening::Ring {
                    utxo,
                    owner_tag: RingOwnerTag(slot.owner_tag()),
                },
                None => OutputOpening::Exit(utxo),
            }),
            error,
        })
    }

    fn verify_dummy(&self, slot: Slot<'_>) -> Result<SlotRead, AuditError> {
        let commitment = ProofInputUtxo {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(slot.tree_id()),
            blinding: self.blinding(slot)?,
            ..ProofInputUtxo::default()
        }
        .hash()?;
        Ok(match commitment == slot.commitment() {
            true => SlotRead {
                opening: Some(OutputOpening::Dummy),
                error: None,
            },
            false => SlotRead::refused(OutputPayloadErrorKind::Commitment),
        })
    }

    /// SPP's TXOB blinding under the seed the transaction key derives.
    fn blinding(&self, slot: Slot<'_>) -> Result<[u8; 32], AuditError> {
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &self.seed_out,
            slot.index,
        )?)
    }
}

/// The default-ring notes in note order, each bit names one of the `R` notes.
fn entry_inputs(evidence: &AuditEvidence) -> Result<Vec<AuditedEntryInput>, AuditError> {
    let AuditEvidence::Entry {
        default_note_bits: default_input_bits,
        inputs,
    } = evidence
    else {
        return Ok(Vec::new());
    };
    inputs
        .iter()
        .enumerate()
        .filter(|(note, _)| default_input_bits >> note & 1 == 1)
        .map(|(_, entry)| entry_input(entry))
        .collect()
}

/// The opener refused a noncanonical nullifier key or commitment.
fn entry_input(entry: &EntryRecord) -> Result<AuditedEntryInput, AuditError> {
    Ok(AuditedEntryInput {
        owner_key: entry.owner_key,
        nullifier_pk: entry.nullifier_pk,
        asset: hash_bytes(&entry.mint)?,
        mint: Address::new_from_array(entry.mint),
        amount: entry.amount,
        commitment: entry.input_commitment,
    })
}

impl AuditedTransaction {
    /// A slot appears once, in published order.
    /// A slot whose record stands and whose payload failed sits in both lists.
    fn place(&mut self, slot_index: u32, context: OutputContext, read: SlotRead) {
        self.outputs
            .retain(|output| output.slot_index != slot_index);
        self.payload_errors
            .retain(|error| error.slot_index != slot_index);
        if let Some(opening) = read.opening {
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
        if let Some(kind) = read.error {
            let at = self
                .payload_errors
                .partition_point(|error| error.slot_index < slot_index);
            self.payload_errors
                .insert(at, OutputPayloadError { slot_index, kind });
        }
    }
}
