//! The storage program's tags, instruction data and write classification.
//!
//! The apply proof, and no authority label, decides whether an update retires the older roots. The
//! instruction carries the restrictive bit and the statement binds it, so a label the writes do not
//! prove fails verification. A private mask requires its owner's tracking row unless a mint preimage
//! authenticates an asset key at the same write position.
//!
//! Read after `program-libs/interface/src/accounts/storage.rs`, `program-libs/interface/src/accounts/tracking.rs`.
//! Read before `programs/storage/src/instructions/update.rs`.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_ring_policy::{ListSet, Member};

use crate::{
    error::CustomRingError,
    instruction::{list_and_mint_entry, write_count},
    member_registry::RecordWrite,
    storage::{RegistryId, Revision, StorageError},
    ApplyRecordsIxData, CustomRingProof, ReaderKeyBytes, RecordWriteData,
    REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    /// No data, the authority and the new authority both sign.
    pub const UPDATE_AUTHORITY: u8 = 4;
    pub const ENROLL: u8 = 6;
    /// Permissionless, the applier names the authorization accounts.
    pub const APPLY_ENROLLMENTS: u8 = 7;
    pub const OWNER_GRANT: u8 = 8;
    /// The ring program signs its ring PDA as creator through CPI.
    pub const INITIALIZE_TRACKING: u8 = 9;
}

/// The creator signs and becomes the authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeIxData {
    pub registry_id: RegistryId,
    /// Little endian.
    pub grace_slots: [u8; 8],
    /// `ring_id_field` of the ring it serves, immutable, zero serves as a curator only.
    pub ring_id: [u8; 32],
    /// Nonzero lets a salted list read the registry, immutable.
    pub tracking_registry: Address,
}

/// Tag 9, accounts `payer, creator, tracking_registry, system_program`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeTrackingIxData {
    /// `ring_id_field` of the ring program.
    pub ring_id: [u8; 32],
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
}

/// Tag 6 ahead of a first enrollment's proof, accounts `payer, owner, tracking_registry, authorization, system_program`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EnrollIxData {
    /// Final after the first enrollment, with `list_tag`, `eph_u` and `ciphertext`.
    pub nullifier_pk: [u8; 32],
    pub list_tag: [u8; 32],
    /// Canonical and nonzero, the owner's signature alone authorizes it.
    pub viewing_u: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

/// Tag 6 data, a first enrollment holds the `RegisterKey` proof and a rotation none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollRequest<'a> {
    pub ix: &'a EnrollIxData,
    pub proof: Option<&'a CustomRingProof>,
}

/// Tag 7, accounts `tracking_registry` then one to `APPLY_BATCH` authorizations in chain order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyEnrollmentsIxData {
    pub revision: Revision,
    pub proof: CustomRingProof,
    pub new_root: [u8; 32],
    /// Little endian, a tracking tree outgrows the policy tree's u32 index.
    pub new_next_index: [u8; 8],
}

/// Tag 8, accounts `payer, owner, tracking_registry, grant, system_program`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct OwnerGrantIxData {
    pub reader: ReaderKeyBytes,
    /// One grants, zero revokes.
    pub active: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct AssetWrite {
    pub write_index: u8,
    pub mint: Address,
}

#[must_use]
pub struct RecordWriteClassification<'a, I> {
    pub entries: I,
    pub asset_writes: &'a [AssetWrite],
}

/// Tag 1, `revision || count u8 || writes || asset_count u8 || asset writes || tracking_revision || ApplyRecordsIxData`,
/// `tracking_revision` present exactly when a private write needs its owner's row. Accounts `authority, registry`,
/// then the pinned `tracking_registry` with that revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdateIxData<'a> {
    pub revision: Revision,
    pub writes: Vec<RecordWriteData>,
    pub asset_writes: Vec<AssetWrite>,
    /// Names the tracking root the selected rows open under, the update raises the floor to it.
    pub tracking_revision: Option<Revision>,
    pub apply: &'a ApplyRecordsIxData,
}

impl InitializeIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }
}

impl InitializeTrackingIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl EnrollIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> EnrollRequest<'a> {
    /// Exactly the fields, or the fields and one proof.
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        let (ix, proof) = data
            .split_at_checked(EnrollIxData::SIZE)
            .ok_or(StorageError::InvalidInstructionData)?;
        Ok(Self {
            ix: bytemuck::try_from_bytes(ix).map_err(|_| StorageError::InvalidInstructionData)?,
            proof: match proof.is_empty() {
                true => None,
                false => Some(
                    bytemuck::try_from_bytes(proof)
                        .map_err(|_| StorageError::InvalidInstructionData)?,
                ),
            },
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let proof = self.proof.map_or(&[][..], bytemuck::bytes_of);
        [bytemuck::bytes_of(self.ix), proof].concat()
    }
}

impl ApplyEnrollmentsIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn new_next_index(&self) -> u64 {
        u64::from_le_bytes(self.new_next_index)
    }

    /// One account per chained entry, an apply key serves up to `APPLY_BATCH`.
    pub fn check_count(authorizations: usize) -> Result<(), StorageError> {
        match authorizations {
            0 => Err(StorageError::NoEnrollmentsNamed),
            count => storage_write_count(count).map(|_| ()),
        }
    }
}

impl OwnerGrantIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<I> RecordWriteClassification<'_, I>
where
    I: Iterator<Item = Result<RecordWrite, CustomRingError>>,
{
    /// One bit per write whose private mask needs its owner's tracking row.
    pub fn private_writes(self) -> Result<u16, StorageError> {
        let mut assets = self.asset_writes.iter().peekable();
        let mut private_writes = 0u16;
        let mut count = 0;
        for (index, entry) in self.entries.enumerate() {
            // 1. The batch bound fixes the bitmap width, private masks require inclusion regardless of written values.
            count = index + 1;
            storage_write_count(count)?;
            let entry = entry.map_err(|_| StorageError::InvalidInstructionData)?;
            let private = entry.mask & ListSet::PRIVATE_LISTS.record_bits() != 0;
            // 2. Mint preimages exempt only their matching private positions in strictly ascending order.
            if let Some(asset) = assets
                .peek()
                .filter(|asset| usize::from(asset.write_index) <= index)
            {
                if usize::from(asset.write_index) != index
                    || !private
                    || Member::asset(&asset.mint)
                        .map_err(|_| StorageError::InvalidAssetWrite)?
                        .as_bytes()
                        != &entry.member
                {
                    return Err(StorageError::InvalidAssetWrite);
                }
                assets.next();
            } else if private {
                private_writes |= 1u16 << index;
            }
        }
        // 3. Empty batches and asset positions outside the consumed writes have no valid statement.
        storage_write_count(count)?;
        if assets.next().is_some() {
            return Err(StorageError::InvalidAssetWrite);
        }
        Ok(private_writes)
    }
}

impl<'a> StorageUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        // 1. The bounded write count fixes every record boundary before optional proof metadata.
        let (revision, data) = data
            .split_first_chunk::<8>()
            .ok_or(StorageError::InvalidInstructionData)?;
        let (count, rest) = data
            .split_first()
            .ok_or(StorageError::InvalidInstructionData)?;
        let count = usize::from(storage_write_count(usize::from(*count))?);
        let (writes, rest) = rest
            .split_at_checked(count * core::mem::size_of::<RecordWriteData>())
            .ok_or(StorageError::InvalidInstructionData)?;
        // 2. Asset preimages name write positions, their hashes and ordering are checked with the derived bitmap.
        let (asset_count, rest) = rest
            .split_first()
            .ok_or(StorageError::InvalidInstructionData)?;
        if usize::from(*asset_count) > count {
            return Err(StorageError::InvalidAssetWrite);
        }
        let (assets, rest) = rest
            .split_at_checked(usize::from(*asset_count) * core::mem::size_of::<AssetWrite>())
            .ok_or(StorageError::InvalidInstructionData)?;
        let writes: Vec<RecordWriteData> = writes
            .as_chunks::<{ core::mem::size_of::<RecordWriteData>() }>()
            .0
            .iter()
            .map(|bytes| bytemuck::pod_read_unaligned(bytes))
            .collect();
        let asset_writes: Vec<AssetWrite> = assets
            .as_chunks::<{ core::mem::size_of::<AssetWrite>() }>()
            .0
            .iter()
            .map(|bytes| bytemuck::pod_read_unaligned(bytes))
            .collect();
        // 3. The derived bitmap, never a flag, decides whether a tracking revision follows.
        let private_writes = RecordWriteClassification {
            entries: writes.iter().map(RecordWriteData::storage_entry),
            asset_writes: &asset_writes,
        }
        .private_writes()?;
        let (tracking_revision, rest) = match private_writes {
            0 => (None, rest),
            _ => {
                let (revision, rest) = rest
                    .split_first_chunk::<8>()
                    .ok_or(StorageError::InvalidInstructionData)?;
                (Some(Revision(*revision)), rest)
            }
        };
        let apply =
            ApplyRecordsIxData::parse(rest).map_err(|_| StorageError::InvalidInstructionData)?;
        // 4. The restrictive bit has one encoding, the statement binds it.
        if apply.restrictive > 1 {
            return Err(StorageError::InvalidInstructionData);
        }
        Ok(Self {
            revision: Revision(*revision),
            writes,
            asset_writes,
            tracking_revision,
            apply,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let count = storage_write_count(self.writes.len())?;
        if (self.private_writes()? != 0) != self.tracking_revision.is_some() {
            return Err(StorageError::InvalidTrackingRegistry);
        }
        let asset_count =
            u8::try_from(self.asset_writes.len()).map_err(|_| StorageError::InvalidAssetWrite)?;
        let mut data = Vec::new();
        data.extend_from_slice(&self.revision.0);
        data.push(count);
        data.extend_from_slice(bytemuck::cast_slice(&self.writes));
        data.push(asset_count);
        data.extend_from_slice(bytemuck::cast_slice(&self.asset_writes));
        if let Some(revision) = self.tracking_revision {
            data.extend_from_slice(&revision.0);
        }
        data.extend_from_slice(bytemuck::bytes_of(self.apply));
        Ok(data)
    }

    pub fn private_writes(&self) -> Result<u16, StorageError> {
        RecordWriteClassification {
            entries: self.entries(),
            asset_writes: &self.asset_writes,
        }
        .private_writes()
    }

    /// The leaf writes the apply proof hashes, a mint settings tag above 1 refused.
    pub fn entries(&self) -> impl Iterator<Item = Result<RecordWrite, CustomRingError>> + '_ {
        self.writes.iter().map(RecordWriteData::storage_entry)
    }
}

impl RecordWriteData {
    /// The authority's write, the storage program takes no other.
    pub fn storage_entry(&self) -> Result<RecordWrite, CustomRingError> {
        list_and_mint_entry(
            self.member,
            &self.lists,
            &self.mint_policy,
            ListSet::STORAGE_WRITES,
        )
    }
}

fn storage_write_count(count: usize) -> Result<u8, StorageError> {
    write_count(count).map_err(|error| match error {
        CustomRingError::AuthorityBatchTooLarge => StorageError::BatchTooLarge,
        _ => StorageError::InvalidInstructionData,
    })
}

const _: () = assert!(core::mem::align_of::<AssetWrite>() == 1);
const _: () = assert!(core::mem::size_of::<AssetWrite>() == 33);
const _: () = assert!(core::mem::align_of::<InitializeIxData>() == 1);
const _: () = assert!(InitializeIxData::SIZE == 104);
const _: () = assert!(core::mem::align_of::<InitializeTrackingIxData>() == 1);
const _: () = assert!(InitializeTrackingIxData::SIZE == 65);
const _: () = assert!(core::mem::align_of::<EnrollIxData>() == 1);
const _: () = assert!(EnrollIxData::SIZE == 192);
const _: () = assert!(core::mem::align_of::<ApplyEnrollmentsIxData>() == 1);
const _: () = assert!(ApplyEnrollmentsIxData::SIZE == 240);
const _: () = assert!(core::mem::align_of::<OwnerGrantIxData>() == 1);
const _: () = assert!(OwnerGrantIxData::SIZE == 35);
