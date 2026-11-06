//! The instruction tags, compute budgets and data of every ring instruction but the transfer.
//!
//! `WriteRecordsIxData::entry_within` holds a list write to its writer's lists and its value inside
//! its mask. The apply circuit takes the chained value as given, a value past the mask would reach the tree.
//!
//! Read after `program-libs/interface/src/accounts/state.rs`. Read before `program-libs/interface/src/instructions/transact.rs`,
//! `programs/custom-ring/src/lib.rs`.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};
use zolana_ring_policy::{ListSet, ListWrite, MintPolicy, Writer};

use crate::{
    error::CustomRingError,
    member_registry::{check_member, RecordWrite, APPLY_BATCH},
    state::{RingRole, RingRoles},
    TAGGED_X25519_KEY_LEN,
};

macro_rules! instruction_tags {
    ($($(#[$doc:meta])* $variant:ident = $tag:ident: $value:expr => $units:expr,)*) => {
        pub mod tag {
            $($(#[$doc])* pub const $tag: u8 = $value;)*
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum InstructionTag {
            $($variant = tag::$tag,)*
        }

        impl TryFrom<u8> for InstructionTag {
            type Error = CustomRingError;

            fn try_from(value: u8) -> Result<Self, CustomRingError> {
                match value {
                    $(tag::$tag => Ok(Self::$variant),)*
                    _ => Err(CustomRingError::InvalidInstructionData),
                }
            }
        }

        pub const fn compute_unit_limit(tag: InstructionTag) -> u32 {
            match tag {
                $(InstructionTag::$variant => $units,)*
            }
        }
    };
}

const ACCOUNT_UNITS: u32 = 50_000;
/// One policy hash plus a curator registry load.
const POLICY_UNITS: u32 = 150_000;
/// A ring proof, and for most the SPP CPI with its own proof.
const PROOF_UNITS: u32 = 1_400_000;

instruction_tags! {
    Transfer = TRANSFER: 55 => PROOF_UNITS,
    Merge = MERGE: 57 => PROOF_UNITS,
    UpdateAuthority = UPDATE_AUTHORITY: 6 => ACCOUNT_UNITS,
    SetPaused = SET_PAUSED: 11 => ACCOUNT_UNITS,
    /// Ring-local tags must not collide with the forwarded SPP tags.
    SetCoSigner = SET_CO_SIGNER: 27 => ACCOUNT_UNITS,
    ClearCoSigner = CLEAR_CO_SIGNER: 62 => ACCOUNT_UNITS,
    SetDelegate = SET_DELEGATE: 64 => ACCOUNT_UNITS,
    AuthorityTransfer = AUTHORITY_TRANSFER: 56 => PROOF_UNITS,
    /// Signed by the upgrade authority, one budget for the ring account, its policy, the tracking and SPP CPIs.
    Initialize = INITIALIZE: 53 => 3 * ACCOUNT_UNITS + POLICY_UNITS,
    UpdatePolicy = UPDATE_POLICY: 54 => POLICY_UNITS,
}

/// Fixed for the ring's life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum RingKind {
    #[wincode(tag = 0)]
    AuditOnly,
    #[wincode(tag = 1)]
    Policy,
    #[wincode(tag = 2)]
    Anonymous,
    #[wincode(tag = 3)]
    AnonymousPolicy,
}

impl RingKind {
    pub const fn has_policy(self) -> bool {
        matches!(self, Self::Policy | Self::AnonymousPolicy)
    }

    pub const fn anonymous(self) -> bool {
        matches!(self, Self::Anonymous | Self::AnonymousPolicy)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InitializeIxData {
    /// Auditor X25519 public key as `0x04 || canonical little-endian u`.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub kind: RingKind,
    pub roles: RingRoles,
    /// Required on a policy ring.
    pub policy: Option<PolicyBindingIxData>,
}

/// The admin and the new key sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateAuthorityIxData {
    pub role: RingRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetPausedIxData {
    pub paused: bool,
}

/// Creates or rescopes the signer's `CoSigner` record, clearing it takes no data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SetCoSignerRecordIxData {
    pub signer: Address,
    /// [`CoSignScope`](crate::CoSignScope) bits.
    pub scope: u8,
}

impl SetCoSignerRecordIxData {
    pub fn check(&self) -> Result<crate::CoSignScope, CustomRingError> {
        let scope =
            crate::CoSignScope::new(self.scope).ok_or(CustomRingError::InvalidCoSignerScope)?;
        if self.signer == Address::default() {
            return Err(CustomRingError::InvalidCoSigner);
        }
        Ok(scope)
    }
}

/// The circuit uses one BSB22 commitment; its point and proof of knowledge are mandatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct CustomRingProof {
    pub groth16: PlainGroth16Proof,
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

impl CustomRingProof {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

const _: () = assert!(CustomRingProof::SIZE == 192);

/// Compressed Groth16 points, `b` decompresses to SPP's raw 128 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct PlainGroth16Proof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

/// `source` 0 names the ring's own records, `k` the `k`-th trailing curator registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SourceSpec {
    pub list_id: u8,
    pub source: u8,
}

/// The table a policy write stores, the program computes its hash.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PolicyTableIxData {
    #[wincode(with = "containers::Vec<SourceSpec, FixIntLen<u8>>")]
    pub sources: Vec<SourceSpec>,
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub rules: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PolicyBindingIxData {
    pub table: PolicyTableIxData,
}

/// `source` 0 is the ring's own records, 1 the single trailing curator `StorageRegistry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct PolicySourceIxData {
    pub list_id: u8,
    pub source: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum UpdatePolicyIxData {
    #[wincode(tag = 0)]
    Rules(PolicyTableIxData),
    #[wincode(tag = 1)]
    Source(PolicySourceIxData),
    /// One trailing records registry under any authority.
    #[wincode(tag = 2)]
    Records,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct WriteRecordsIxData {
    pub mask: [u8; 8],
    pub value: [u8; 8],
}

/// One record write inside a storage update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RecordWriteData {
    pub member: [u8; 32],
    pub lists: WriteRecordsIxData,
    /// [`mint_policy_write`] of the replacement settings.
    pub mint_policy: MintPolicyWrite,
}

impl Default for RecordWriteData {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// The proof that applies a storage update's writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyRecordsIxData {
    pub proof: CustomRingProof,
    pub new_root: [u8; 32],
    pub new_next_index: [u8; 4],
    /// The proven `ApplyRecordsStatement::restrictive`, one or zero.
    pub restrictive: u8,
}

macro_rules! fixed_ix_data {
    ($($ty:ident),*) => {$(
        impl $ty {
            pub const SIZE: usize = core::mem::size_of::<Self>();

            /// The data of exactly one instance.
            pub fn parse(data: &[u8]) -> Result<&Self, CustomRingError> {
                bytemuck::try_from_bytes(data).map_err(|_| CustomRingError::InvalidInstructionData)
            }
        }

        const _: () = assert!(core::mem::align_of::<$ty>() == 1);
    )*};
}

fixed_ix_data!(WriteRecordsIxData, ApplyRecordsIxData);

impl WriteRecordsIxData {
    pub const fn new(write: ListWrite) -> Self {
        Self {
            mask: write.mask().to_le_bytes(),
            value: write.value().to_le_bytes(),
        }
    }

    pub const fn mask(&self) -> u64 {
        u64::from_le_bytes(self.mask)
    }

    pub const fn value(&self) -> u64 {
        u64::from_le_bytes(self.value)
    }

    /// The entry of `writer` changing `member`'s lists, only the lists `writer` owns.
    pub fn entry(&self, member: [u8; 32], writer: Writer) -> Result<RecordWrite, CustomRingError> {
        self.entry_within(member, writer.writable())
    }

    pub(crate) fn entry_within(
        &self,
        member: [u8; 32],
        writable: ListSet,
    ) -> Result<RecordWrite, CustomRingError> {
        check_member(&member)?;
        let (mask, value) = (self.mask(), self.value());
        if mask == 0 || value & !mask != 0 {
            return Err(CustomRingError::ValueOutsideMask);
        }
        if !ListSet::from_record_bits(mask).is_some_and(|lists| lists.is_subset(writable)) {
            return Err(CustomRingError::ListBitNotWritable);
        }
        Ok(RecordWrite {
            member,
            mask,
            value,
            mint_policy: None,
        })
    }
}

impl RecordWriteData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn entry(&self) -> Result<RecordWrite, CustomRingError> {
        list_and_mint_entry(
            self.member,
            &self.lists,
            &self.mint_policy,
            Writer::Authority.writable(),
        )
    }
}

pub type MintPolicyWrite = [u8; 1 + MintPolicy::LEN];

/// `1 || MintPolicy::bytes` replaces the settings, all zero keeps them.
pub fn mint_policy_write(policy: Option<MintPolicy>) -> MintPolicyWrite {
    let mut write = [0; 1 + MintPolicy::LEN];
    if let Some(policy) = policy {
        write[0] = 1;
        write[1..].copy_from_slice(&policy.bytes());
    }
    write
}

/// A write that keeps both the lists and the mint settings is refused.
pub(crate) fn list_and_mint_entry(
    member: [u8; 32],
    lists: &WriteRecordsIxData,
    mint_policy: &MintPolicyWrite,
    writable: ListSet,
) -> Result<RecordWrite, CustomRingError> {
    check_member(&member)?;
    let mut entry = if *lists == WriteRecordsIxData::default() {
        RecordWrite {
            member,
            ..RecordWrite::default()
        }
    } else {
        lists.entry_within(member, writable)?
    };
    let [tag, policy @ ..] = *mint_policy;
    entry.mint_policy = match tag {
        0 if *mint_policy == mint_policy_write(None) && entry.mask != 0 => None,
        1 => {
            let policy = MintPolicy::from_bytes(policy);
            policy.limits.check()?;
            Some(policy)
        }
        _ => return Err(CustomRingError::InvalidInstructionData),
    };
    Ok(entry)
}

impl ApplyRecordsIxData {
    pub const fn new_next_index(&self) -> u32 {
        u32::from_le_bytes(self.new_next_index)
    }

    /// `StorageUpdateIxData::parse` refuses a byte above one.
    pub const fn restrictive(&self) -> bool {
        self.restrictive != 0
    }
}

/// One to `APPLY_BATCH` writes, `AuthorityBatchTooLarge` past it.
pub(crate) fn write_count(count: usize) -> Result<u8, CustomRingError> {
    match count {
        0 => Err(CustomRingError::InvalidInstructionData),
        1..=APPLY_BATCH => Ok(count as u8),
        _ => Err(CustomRingError::AuthorityBatchTooLarge),
    }
}

const _: () = assert!(WriteRecordsIxData::SIZE == 16);
const _: () = assert!(core::mem::align_of::<RecordWriteData>() == 1);
const _: () = assert!(RecordWriteData::SIZE == 145);
const _: () = assert!(ApplyRecordsIxData::SIZE == 229);
const _: () = assert!(APPLY_BATCH <= u8::MAX as usize);

#[cfg(test)]
mod tests {
    use spr_hasher::primitives::right_align;
    use zolana_ring_policy::ListId;

    use super::*;

    fn lists(mask: u64, value: u64) -> WriteRecordsIxData {
        WriteRecordsIxData {
            mask: mask.to_le_bytes(),
            value: value.to_le_bytes(),
        }
    }

    #[test]
    fn a_member_writes_only_its_own_lists_within_the_mask() {
        let member = right_align(&[7]);
        let viewing = ListId::RingViewing.record_bit();
        let allow = ListId::Allow.record_bit();
        let write = |mask, value| lists(mask, value).entry(member, Writer::Member);
        assert!(write(viewing, viewing).is_ok());
        assert_eq!(
            write(allow, allow),
            Err(CustomRingError::ListBitNotWritable)
        );
        for unwritable in ListSet::PRIVATE_LISTS.iter() {
            assert_eq!(
                write(unwritable.record_bit(), 0),
                Err(CustomRingError::ListBitNotWritable)
            );
        }
        assert_eq!(write(1 << 9, 0), Err(CustomRingError::ListBitNotWritable));
        assert_eq!(
            write(viewing, viewing | allow),
            Err(CustomRingError::ValueOutsideMask)
        );
        assert_eq!(write(0, 0), Err(CustomRingError::ValueOutsideMask));
        assert_eq!(
            lists(viewing, 0).entry([0; 32], Writer::Member),
            Err(CustomRingError::MemberOutOfRange)
        );
    }

    #[test]
    fn the_authority_writes_only_the_authority_lists() {
        let write = |mask| {
            RecordWriteData {
                mint_policy: mint_policy_write(None),
                member: right_align(&[9]),
                lists: lists(mask, 0),
            }
            .entry()
        };
        assert!(write(ListId::Block.record_bit()).is_ok());
        assert_eq!(
            write(ListId::RingViewing.record_bit()),
            Err(CustomRingError::ListBitNotWritable)
        );
    }
}
