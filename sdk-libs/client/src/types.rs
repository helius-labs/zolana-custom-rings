use core::fmt;

#[cfg(feature = "rpc")]
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::ProofInputUtxo;
use spr_hasher::{
    primitives::{right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use spr_interface::tree_slot::tree_id_field;
use spr_keypair::X25519Pubkey;
use spr_transaction::{
    utxo::{program_id_proof_input_hash, UTXO_DOMAIN},
    OutputContext,
};

use crate::{AuditError, REDACTED};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedTransaction {
    pub tx_signature: Signature,
    pub slot: u64,
    /// Checked against the key the auditor envelope seals.
    pub tx_viewing_pk: X25519Pubkey,
    /// Published order, a slot whose record did not open sits in `payload_errors` instead.
    pub outputs: Vec<AuditedOutput>,
    pub payload_errors: Vec<OutputPayloadError>,
    /// `R`, the notes the proof spent, their nullifiers sit among `nullifiers` at unnamed
    /// positions.
    pub real_inputs: u8,
    /// SPP's published nullifiers, notes, addresses and padding alike.
    pub nullifiers: Vec<[u8; 32]>,
    /// The default-ring notes among the `R`, in note order.
    pub entries: Vec<AuditedEntryInput>,
}

/// One opened slot, its note rebuilt to the published commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedOutput {
    pub slot_index: u32,
    pub context: OutputContext,
    pub opening: OutputOpening,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputOpening {
    Ring {
        utxo: AuditedUtxo,
        owner_tag: RingOwnerTag,
    },
    /// A default-ring note, its owner the published owner tag.
    Exit(AuditedUtxo),
    Dummy,
}

/// Left free by the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingOwnerTag(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditedUtxo {
    /// The raw Solana key whose owner identity the commitment binds.
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    /// `hash_bytes(mint)`.
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    pub amount: u64,
    pub blinding: [u8; 32],
    /// Absent with `ring_data_hash` while no payload rebuilt the published commitment.
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// A ring or default-ring note an earlier audit opened, indexed by its UTXO hash.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KnownUtxo {
    pub owner_key: [u8; 32],
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    pub amount: u64,
    pub blinding: [u8; 32],
    /// Absent with `ring_data_hash` while no payload rebuilt the published commitment.
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub tree_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtxoOwner {
    Keyed { nullifier_pk: [u8; 32] },
}

/// A note one transaction created, at its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedUtxo {
    pub commitment: [u8; 32],
    pub slot_index: u32,
    pub leaf_index: u64,
    pub utxo: KnownUtxo,
    /// False on an exit, its note leaves the ring.
    pub ring_note: bool,
}

/// Bound by the proof to the spent note at its note position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditedEntryInput {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub asset: [u8; 32],
    pub mint: Address,
    pub amount: u64,
    /// SPP's spent UTXO hash under the note's tree.
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputPayloadError {
    pub slot_index: u32,
    pub kind: OutputPayloadErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "rpc", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rpc", serde(rename_all = "camelCase"))]
pub enum OutputPayloadErrorKind {
    /// The slot's record holds a value outside the field.
    Disclosure,
    /// A dummy's derived opening hashes to another commitment.
    Commitment,
    /// The payload's data hashes rebuild no commitment, the record stands without them.
    Payload,
}

impl AuditedTransaction {
    pub fn utxos(&self) -> impl Iterator<Item = CreatedUtxo> + '_ {
        self.outputs.iter().filter_map(AuditedOutput::created)
    }
}

impl AuditedOutput {
    pub fn created(&self) -> Option<CreatedUtxo> {
        self.opening.utxo().map(|utxo| CreatedUtxo {
            commitment: self.context.hash,
            slot_index: self.slot_index,
            leaf_index: self.context.leaf_index,
            utxo: KnownUtxo::opened(*utxo, self.context.tree_id),
            ring_note: matches!(self.opening, OutputOpening::Ring { .. }),
        })
    }
}

impl OutputOpening {
    pub fn utxo(&self) -> Option<&AuditedUtxo> {
        match self {
            Self::Ring { utxo, .. } | Self::Exit(utxo) => Some(utxo),
            Self::Dummy => None,
        }
    }
}

impl AuditedUtxo {
    /// `Poseidon(owner_identity(owner_key), nullifier_pk)`.
    pub fn owner_hash(&self) -> Result<[u8; 32], AuditError> {
        UtxoOwner::Keyed {
            nullifier_pk: self.nullifier_pk,
        }
        .hash(&self.owner_key)
    }

    /// The commitment of the note in `tree_id`, `ring` `None` for the default ring.
    pub(crate) fn commitment(
        &self,
        tree_id: u16,
        ring: Option<Address>,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        KnownUtxo::opened(*self, tree_id).commitment(ring)
    }
}

impl KnownUtxo {
    pub fn opened(utxo: AuditedUtxo, tree_id: u16) -> Self {
        Self {
            owner_key: utxo.owner_key,
            owner: UtxoOwner::Keyed {
                nullifier_pk: utxo.nullifier_pk,
            },
            asset: utxo.asset,
            mint: utxo.mint,
            amount: utxo.amount,
            blinding: utxo.blinding,
            data_hash: utxo.data_hash,
            ring_data_hash: utxo.ring_data_hash,
            tree_id,
        }
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], AuditError> {
        self.owner.hash(&self.owner_key)
    }

    /// The UTXO hash, `ring` `None` for the default ring, `None` without the data hashes.
    pub fn commitment(&self, ring: Option<Address>) -> Result<Option<[u8; 32]>, AuditError> {
        let (Some(data_hash), Some(ring_data_hash)) = (self.data_hash, self.ring_data_hash) else {
            return Ok(None);
        };
        Ok(Some(
            ProofInputUtxo {
                domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
                tree_id: tree_id_field(self.tree_id),
                owner_hash: self.owner_hash()?,
                asset: self.asset,
                amount: right_align(&self.amount.to_be_bytes()),
                blinding: self.blinding,
                data_hash,
                ring_data_hash,
                ring_program_id: program_id_proof_input_hash(&ring)?,
            }
            .hash()?,
        ))
    }
}

impl UtxoOwner {
    pub fn nullifier_pk(self) -> Option<[u8; 32]> {
        match self {
            Self::Keyed { nullifier_pk } => Some(nullifier_pk),
        }
    }

    pub(crate) fn hash(self, owner_key: &[u8; 32]) -> Result<[u8; 32], AuditError> {
        match self {
            Self::Keyed { nullifier_pk } => Ok(Poseidon::hashv(&[
                &solana_owner_identity(owner_key)?,
                &nullifier_pk,
            ])?),
        }
    }
}

impl fmt::Debug for AuditedUtxo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            owner_key,
            nullifier_pk,
            asset,
            mint,
            amount,
            blinding: _,
            data_hash,
            ring_data_hash,
        } = self;
        f.debug_struct("AuditedUtxo")
            .field("owner_key", owner_key)
            .field("nullifier_pk", nullifier_pk)
            .field("asset", asset)
            .field("mint", mint)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .finish()
    }
}

impl fmt::Debug for KnownUtxo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            owner_key,
            owner,
            asset,
            mint,
            amount,
            blinding: _,
            data_hash,
            ring_data_hash,
            tree_id,
        } = self;
        f.debug_struct("KnownUtxo")
            .field("owner_key", owner_key)
            .field("owner", owner)
            .field("asset", asset)
            .field("mint", mint)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .field("tree_id", tree_id)
            .finish()
    }
}
