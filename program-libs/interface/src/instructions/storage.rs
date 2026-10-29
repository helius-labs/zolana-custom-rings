use bytemuck::{Pod, Zeroable};
use zolana_ring_policy::ListSet;

use crate::{
    error::CustomRingError,
    instruction::{list_and_mint_entry, write_count},
    member_registry::QueueEntry,
    storage::{RegistryId, Revision},
    ApplyRecordsIxData, WriteRecordsIxData,
};

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    pub const UPDATE_IMMEDIATE: u8 = 2;
    // 3 retired.
    /// No data, the authority and the new authority both sign.
    pub const UPDATE_AUTHORITY: u8 = 4;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct StorageWriteData {
    pub member: [u8; 32],
    pub lists: WriteRecordsIxData,
    /// [`mint_policy_write`](crate::mint_policy_write) of the replacement settings.
    pub mint_policy: [u8; 33],
    /// Nonzero only on an escrow write, the [`EscrowKey::hash`](crate::EscrowKey::hash).
    pub escrow_key: [u8; 32],
}

/// Tags 1 and 2, `revision || count u8 || count writes || ApplyRecordsIxData`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageUpdateIxData<'a> {
    pub revision: Revision,
    pub writes: &'a [StorageWriteData],
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
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The leaf write the apply proof hashes, an escrow write carries nothing else.
    pub fn entry(&self) -> Result<QueueEntry, CustomRingError> {
        if self.escrow_key == [0; 32] {
            return list_and_mint_entry(
                self.member,
                &self.lists,
                &self.mint_policy,
                ListSet::STORAGE_WRITES,
            );
        }
        if self.lists != WriteRecordsIxData::default() || self.mint_policy != [0; 33] {
            return Err(CustomRingError::InvalidInstructionData);
        }
        QueueEntry::escrow_hash(self.member, self.escrow_key)
    }
}

impl<'a> StorageUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let (revision, data) = data
            .split_first_chunk::<8>()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let (count, rest) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let count = write_count(usize::from(*count))?;
        let (writes, apply) = rest
            .split_at_checked(usize::from(count) * StorageWriteData::SIZE)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        Ok(Self {
            revision: Revision(*revision),
            writes: bytemuck::try_cast_slice(writes)
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
            apply: ApplyRecordsIxData::parse(apply)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let count = write_count(self.writes.len())?;
        Ok([
            &self.revision.0[..],
            &[count],
            bytemuck::cast_slice(self.writes),
            bytemuck::bytes_of(self.apply),
        ]
        .concat())
    }
}

const _: () = assert!(core::mem::align_of::<InitializeIxData>() == 1);
const _: () = assert!(InitializeIxData::SIZE == 40);
const _: () = assert!(core::mem::align_of::<StorageWriteData>() == 1);
const _: () = assert!(StorageWriteData::SIZE == 113);
