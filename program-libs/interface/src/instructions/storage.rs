use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::primitives::solana_owner_identity;
use zolana_ring_policy::ListSet;

use crate::{
    error::CustomRingError,
    instruction::{list_and_mint_entry, write_count},
    member_registry::{EscrowKey, QueueEntry},
    storage::{RegistryId, Revision},
    ApplyRecordsIxData, RecordWriteData, AUDIT_CIPHERTEXT_LEN,
};

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    pub const UPDATE_IMMEDIATE: u8 = 2;
    // 3 retired.
    /// No data, the authority and the new authority both sign.
    pub const UPDATE_AUTHORITY: u8 = 4;
}

/// The first byte of each write in an update.
pub mod write_kind {
    pub const RECORD: u8 = 0;
    pub const ESCROW: u8 = 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateMode {
    /// The outgoing root stays readable for the grace period.
    Graced,
    /// Every earlier root stops verifying.
    Immediate,
}

/// The creator signs and becomes the authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeIxData {
    pub registry_id: RegistryId,
    /// Little endian.
    pub grace_slots: [u8; 8],
}

/// Encoded as its `write_kind` byte and body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageWriteData {
    Record(RecordWriteData),
    Escrow(EscrowWriteData),
}

/// The leaf binds every field except `eph_u`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EscrowWriteData {
    /// Its owner identity is the leaf member.
    pub owner: Address,
    pub nullifier_pk: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// Tags 1 and 2, `revision || count u8 || count writes || ApplyRecordsIxData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdateIxData<'a> {
    pub revision: Revision,
    pub writes: Vec<StorageWriteData>,
    pub apply: &'a ApplyRecordsIxData,
}

impl UpdateMode {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Graced => tag::UPDATE,
            Self::Immediate => tag::UPDATE_IMMEDIATE,
        }
    }
}

impl InitializeIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }
}

impl StorageWriteData {
    /// The leaf write the apply proof hashes.
    pub fn entry(&self) -> Result<QueueEntry, CustomRingError> {
        match self {
            Self::Record(write) => list_and_mint_entry(
                write.member,
                &write.lists,
                &write.mint_policy,
                ListSet::STORAGE_WRITES,
            ),
            // The leaf binds the published envelope and no other key.
            Self::Escrow(write) => QueueEntry::escrow(write.member()?, &write.key()),
        }
    }

    pub fn encode_all(writes: &[Self]) -> Vec<u8> {
        let mut out = Vec::new();
        for write in writes {
            write.encode_into(&mut out);
        }
        out
    }

    pub fn parse_all(mut data: &[u8]) -> Result<Vec<Self>, CustomRingError> {
        let mut writes = Vec::new();
        while !data.is_empty() {
            let (write, rest) = Self::split(data)?;
            writes.push(write);
            data = rest;
        }
        Ok(writes)
    }

    fn split(data: &[u8]) -> Result<(Self, &[u8]), CustomRingError> {
        let (kind, rest) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        match *kind {
            write_kind::RECORD => leading(rest).map(|(write, rest)| (Self::Record(write), rest)),
            write_kind::ESCROW => leading(rest).map(|(write, rest)| (Self::Escrow(write), rest)),
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let (kind, body) = match self {
            Self::Record(write) => (write_kind::RECORD, bytemuck::bytes_of(write)),
            Self::Escrow(write) => (write_kind::ESCROW, bytemuck::bytes_of(write)),
        };
        out.push(kind);
        out.extend_from_slice(body);
    }
}

impl EscrowWriteData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn member(&self) -> Result<[u8; 32], CustomRingError> {
        Ok(solana_owner_identity(self.owner.as_array())?)
    }

    pub fn key(&self) -> EscrowKey<'_> {
        EscrowKey {
            nullifier_pk: &self.nullifier_pk,
            ciphertext: &self.ciphertext,
        }
    }
}

impl<'a> StorageUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let (revision, data) = data
            .split_first_chunk::<8>()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let (count, mut rest) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let count = write_count(usize::from(*count))?;
        let mut writes = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (write, tail) = StorageWriteData::split(rest)?;
            writes.push(write);
            rest = tail;
        }
        Ok(Self {
            revision: Revision(*revision),
            writes,
            apply: ApplyRecordsIxData::parse(rest)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let count = write_count(self.writes.len())?;
        Ok([
            &self.revision.0[..],
            &[count],
            &StorageWriteData::encode_all(&self.writes),
            bytemuck::bytes_of(self.apply),
        ]
        .concat())
    }
}

fn leading<T: Pod>(data: &[u8]) -> Result<(T, &[u8]), CustomRingError> {
    let (body, rest) = data
        .split_at_checked(core::mem::size_of::<T>())
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let value = bytemuck::try_pod_read_unaligned(body)
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    Ok((value, rest))
}

const _: () = assert!(core::mem::align_of::<InitializeIxData>() == 1);
const _: () = assert!(InitializeIxData::SIZE == 40);
const _: () = assert!(core::mem::align_of::<EscrowWriteData>() == 1);
const _: () = assert!(EscrowWriteData::SIZE == 128);
