use core::ops::BitOr;

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::HasherError;
use wincode::{SchemaRead, SchemaWrite};
use zolana_ring_policy::{
    registry_field, EncodedRuleTable, ListId, PolicySource, RuleTable, SourceMap,
};

use crate::{
    error::CustomRingError,
    storage::{root_at, Revision, Root, StorageError, StorageRegistry},
    TAGGED_X25519_KEY_LEN,
};

/// Roots a transfer proof may bind, applications in between leave it provable.
pub const ROOT_HISTORY: usize = 32;
/// One slot per list the enum can name, all eight enter the hash.
pub const N_SOURCE_SLOTS: usize = zolana_ring_policy::MAX_SOURCES;

/// Created only at its canonical PDA, an owned account with the discriminator needs no address check.
pub trait RingAccount: Pod + sealed::Sealed {
    const DISCRIMINATOR: u8;
    const SEED: &'static [u8];
    const SIZE: usize = core::mem::size_of::<Self>();
    /// Not an initialized account of the program.
    const INVALID: CustomRingError;
    /// Creation over an existing account.
    const EXISTS: CustomRingError;
    /// Not the canonical address.
    const ADDRESS: CustomRingError;

    fn bump(&self) -> u8;

    /// Field invariants the setters keep.
    fn valid(&self) -> bool {
        true
    }

    /// The initialized account in `data`, `None` for another length or discriminator.
    fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|account| data[0] == Self::DISCRIMINATOR && account.valid())
    }

    fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        let initialized = data.first() == Some(&Self::DISCRIMINATOR);
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|account| initialized && account.valid())
    }

    /// `program`'s initialized account for off-chain readers.
    fn decode(owner: &Address, program: &Address, data: &[u8]) -> Option<Self> {
        (owner == program)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! ring_accounts {
    ($(
        $ty:ident = $disc:ident: $disc_value:literal, $seed:ident: $seed_value:literal,
        $invalid:ident, $exists:ident, $address:ident $(, $valid:expr)?;
    )*) => {$(
        pub const $disc: u8 = $disc_value;
        pub const $seed: &[u8] = $seed_value;

        impl sealed::Sealed for $ty {}

        impl $ty {
            pub const SEED: &'static [u8] = $seed;
            pub const SIZE: usize = core::mem::size_of::<Self>();
        }

        impl RingAccount for $ty {
            const DISCRIMINATOR: u8 = $disc;
            const SEED: &'static [u8] = $seed;
            const INVALID: CustomRingError = CustomRingError::$invalid;
            const EXISTS: CustomRingError = CustomRingError::$exists;
            const ADDRESS: CustomRingError = CustomRingError::$address;

            fn bump(&self) -> u8 {
                self.bump
            }

            $(fn valid(&self) -> bool {
                ($valid)(self)
            })?
        }

        // Byte fields only, the `Pod` image is the account data with no padding.
        const _: () = assert!(core::mem::align_of::<$ty>() == 1);
    )*};
}

// Discriminator zero marks an uninitialized account.
// Discriminators 1 to 13 are retired, never reuse them.
ring_accounts! {
    RingPolicy = RING_POLICY: 15, RING_POLICY_PDA_SEED: b"policy",
        InvalidRingPolicy, RingPolicyAlreadyExists, InvalidRingPolicy,
        |ring: &RingPolicy| ring.mode().is_ok();
    CoSigner = CO_SIGNER: 14, CO_SIGNER_PDA_SEED: b"co_signer",
        InvalidCoSignerRecord, CoSignerRecordAlreadyExists, InvalidCoSignerRecord,
        |record: &CoSigner| record.scope().is_some() && record.signer != Address::default();
}

macro_rules! le_getters {
    ($($ty:ident { $($field:ident: $int:ty),* })*) => {$(
        impl $ty {
            $(pub const fn $field(&self) -> $int {
                <$int>::from_le_bytes(self.$field)
            })*
        }
    )*};
}

le_getters! {
    RingPolicy { created_slot: u64, generation: u32, generation_slot: u64 }
}

/// Nonzero keys, pairwise distinct with the delegate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable, SchemaRead, SchemaWrite)]
#[repr(C)]
pub struct RingRoles {
    /// Rotates every role and appoints the delegate.
    pub admin: Address,
    /// Signs `UpdatePolicy` and the authority record updates Ring RPC accepts.
    pub policy: Address,
    pub pauser: Address,
    /// Signs `SetCoSigner` and `ClearCoSigner`.
    pub cosign_admin: Address,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum RingRole {
    #[wincode(tag = 0)]
    Admin,
    #[wincode(tag = 1)]
    Policy,
    #[wincode(tag = 2)]
    Pauser,
    #[wincode(tag = 3)]
    CosignAdmin,
}

impl RingRoles {
    pub const fn key(&self, role: RingRole) -> &Address {
        match role {
            RingRole::Admin => &self.admin,
            RingRole::Policy => &self.policy,
            RingRole::Pauser => &self.pauser,
            RingRole::CosignAdmin => &self.cosign_admin,
        }
    }

    fn key_mut(&mut self, role: RingRole) -> &mut Address {
        match role {
            RingRole::Admin => &mut self.admin,
            RingRole::Policy => &mut self.policy,
            RingRole::Pauser => &mut self.pauser,
            RingRole::CosignAdmin => &mut self.cosign_admin,
        }
    }

    /// `ZeroRoleKey` or `DuplicateRoleKey` unless every key and the delegate are nonzero and distinct.
    pub fn check(&self, delegate: Option<&Address>) -> Result<(), CustomRingError> {
        let keys = || {
            [&self.admin, &self.policy, &self.pauser, &self.cosign_admin]
                .into_iter()
                .chain(delegate)
        };
        if keys().any(|key| *key == Address::default()) {
            return Err(CustomRingError::ZeroRoleKey);
        }
        if keys()
            .enumerate()
            .any(|(index, key)| keys().take(index).any(|earlier| earlier == key))
        {
            return Err(CustomRingError::DuplicateRoleKey);
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum RingMode {
    Confidential = 0,
    /// Escrows every output nullifier key in the registry.
    ConfidentialEscrow = 1,
    /// Hides the sender and discloses every opening to the auditor.
    Anonymous = 2,
}

impl TryFrom<u8> for RingMode {
    type Error = CustomRingError;

    fn try_from(byte: u8) -> Result<Self, CustomRingError> {
        match byte {
            0 => Ok(Self::Confidential),
            1 => Ok(Self::ConfidentialEscrow),
            2 => Ok(Self::Anonymous),
            _ => Err(CustomRingError::InvalidRingMode),
        }
    }
}

/// Nonzero subset of the class bits.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CoSignScope(u8);

impl CoSignScope {
    pub const TRANSFERS: Self = Self(1);
    pub const DEPOSITS: Self = Self(2);
    pub const WITHDRAWALS: Self = Self(4);
    pub const ALL: Self = Self(Self::TRANSFERS.0 | Self::DEPOSITS.0 | Self::WITHDRAWALS.0);

    pub const fn new(bits: u8) -> Option<Self> {
        if bits == 0 || bits & !Self::ALL.0 != 0 {
            return None;
        }
        Some(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for CoSignScope {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Count of `CoSigner` records covering each class, a class with none demands no co-signer.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CoSignerCounts([u8; 3]);

impl CoSignerCounts {
    const CLASSES: [CoSignScope; 3] = [
        CoSignScope::TRANSFERS,
        CoSignScope::DEPOSITS,
        CoSignScope::WITHDRAWALS,
    ];

    /// `None` without a record.
    pub fn covered(&self) -> Option<CoSignScope> {
        let bits = Self::CLASSES
            .iter()
            .zip(self.0)
            .filter(|(_, count)| *count != 0)
            .fold(0, |bits, (class, _)| bits | class.bits());
        CoSignScope::new(bits)
    }

    pub fn added(self, scope: CoSignScope) -> Result<Self, CustomRingError> {
        self.step(scope, u8::checked_add)
    }

    pub fn removed(self, scope: CoSignScope) -> Result<Self, CustomRingError> {
        self.step(scope, u8::checked_sub)
    }

    fn step(
        mut self,
        scope: CoSignScope,
        step: fn(u8, u8) -> Option<u8>,
    ) -> Result<Self, CustomRingError> {
        for (class, count) in Self::CLASSES.iter().zip(&mut self.0) {
            if scope.contains(*class) {
                *count = step(*count, 1).ok_or(CustomRingError::CoSignerCountOutOfRange)?;
            }
        }
        Ok(self)
    }
}

/// One list's source, slot `i` is empty (`list_id == 0`) or serves list `i + 1`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct SourceSlot {
    pub list_id: u8,
    /// The curator's `StorageRegistry` serving the list, zero for the ring's own records.
    pub registry: Address,
}

impl SourceSlot {
    /// The field the policy hash and the circuit read for the slot.
    pub fn policy_source(&self) -> Result<PolicySource, HasherError> {
        let registry = if self.registry == Address::default() {
            [0u8; 32]
        } else {
            registry_field(self.registry.as_array())?
        };
        Ok(PolicySource {
            list_id: self.list_id,
            registry,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ListRegistry {
    Own,
    Curator(Address),
}

/// One per ring, every ring instruction and transfer passes it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingPolicy {
    pub discriminator: u8,
    pub bump: u8,
    /// [`RingMode`] byte.
    pub mode: u8,
    pub co_signers: CoSignerCounts,
    pub roles: RingRoles,
    /// Zero without a delegate.
    pub delegate: Address,
    /// Auditor X25519 public key as `0x04 || canonical little-endian u`.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    /// Little endian, the slot `Initialize` ran in.
    pub created_slot: [u8; 8],
    /// The ring's own `StorageRegistry`, zero on an audit-only ring bound to none.
    pub records: Address,
    /// Zero without a policy.
    pub policy_hash: [u8; 32],
    /// Non-empty exactly for the lists `rules` references.
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    /// Little endian, one more at every table, source or records write.
    pub generation: [u8; 4],
    /// Little endian, the slot of the write `generation` counts.
    pub generation_slot: [u8; 8],
    /// Mirrors `records`.
    pub own_roots: RootMirror,
    /// Mirrors the curator registry the sources name.
    pub curator_roots: RootMirror,
}

/// A `StorageRegistry` root history as `SyncRoots` last copied it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RootMirror {
    /// Zero before the first sync, a reader refuses roots of another registry.
    pub registry: Address,
    /// Newest first, as the registry holds them.
    pub roots: [Root; ROOT_HISTORY],
}

/// At `[CO_SIGNER_PDA_SEED, signer]`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct CoSigner {
    pub discriminator: u8,
    pub signer: Address,
    /// [`CoSignScope`] bits.
    pub scope: u8,
    pub bump: u8,
}

impl RootMirror {
    /// The registry's root rule over the last synced copy, a root dropped since stays valid until the next sync.
    pub fn root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError> {
        root_at(&self.roots, revision, slot)
    }

    fn root_of(
        &self,
        registry: &Address,
        revision: Revision,
        slot: u64,
    ) -> Result<[u8; 32], CustomRingError> {
        if self.registry != *registry {
            return Err(CustomRingError::MirrorNotSynced);
        }
        self.root(revision, slot)
            .map_err(|_| CustomRingError::MirrorRootExpired)
    }
}

#[must_use]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NewRing {
    pub bump: u8,
    pub mode: RingMode,
    pub roles: RingRoles,
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub created_slot: u64,
    pub records: Address,
}

impl NewRing {
    /// Unsynced mirrors and no policy, boxed in place past the SBF stack frame.
    pub fn account(self) -> Box<RingPolicy> {
        let mut ring: Box<RingPolicy> = bytemuck::zeroed_box();
        ring.discriminator = RING_POLICY;
        ring.bump = self.bump;
        ring.mode = self.mode as u8;
        ring.roles = self.roles;
        ring.auditor_pubkey = self.auditor_pubkey;
        ring.created_slot = self.created_slot.to_le_bytes();
        ring.records = self.records;
        ring
    }
}

impl RingPolicy {
    pub fn mode(&self) -> Result<RingMode, CustomRingError> {
        RingMode::try_from(self.mode)
    }

    /// A policy ring pins its table at `Initialize`, an audit-only ring never writes one.
    pub fn has_policy(&self) -> bool {
        self.written_policy_hash().is_some()
    }

    pub fn delegate(&self) -> Option<&Address> {
        (self.delegate != Address::default()).then_some(&self.delegate)
    }

    /// `UnauthorizedAuthority` unless `signer` holds `role`.
    pub fn check_role(&self, role: RingRole, signer: &Address) -> Result<(), CustomRingError> {
        if self.roles.key(role) != signer {
            return Err(CustomRingError::UnauthorizedAuthority);
        }
        Ok(())
    }

    /// `ZeroRoleKey` or `DuplicateRoleKey` unless `key` stays apart from the other roles and the delegate.
    pub fn rotate_role(&mut self, role: RingRole, key: Address) -> Result<(), CustomRingError> {
        let mut roles = self.roles;
        *roles.key_mut(role) = key;
        roles.check(self.delegate())?;
        self.roles = roles;
        Ok(())
    }

    /// `PolicyNotSet` before the first policy write.
    pub fn policy_hash(&self) -> Result<&[u8; 32], CustomRingError> {
        self.written_policy_hash()
            .ok_or(CustomRingError::PolicyNotSet)
    }

    pub fn written_policy_hash(&self) -> Option<&[u8; 32]> {
        (self.policy_hash != [0; 32]).then_some(&self.policy_hash)
    }

    /// Validates the table against the sources and repins its hash.
    pub fn set_policy(
        &mut self,
        sources: [SourceSlot; N_SOURCE_SLOTS],
        rules: EncodedRuleTable,
        slot: u64,
    ) -> Result<(), CustomRingError> {
        let source_map = source_map(&sources)?;
        rules.validate(&source_map)?;
        let policy_hash = rules.hash(&source_map)?;
        self.count_generation(slot)?;
        self.policy_hash = policy_hash;
        self.sources = sources;
        self.rules = rules;
        Ok(())
    }

    /// `InvalidSource` for the curator, the own mirror stays empty until the next sync.
    pub fn rebind_records(&mut self, records: Address, slot: u64) -> Result<(), CustomRingError> {
        if self.curator() == Some(records) {
            return Err(CustomRingError::InvalidSource);
        }
        self.count_generation(slot)?;
        self.records = records;
        self.own_roots = RootMirror::zeroed();
        Ok(())
    }

    fn count_generation(&mut self, slot: u64) -> Result<(), CustomRingError> {
        let generation = self
            .generation()
            .checked_add(1)
            .ok_or(CustomRingError::PolicyGenerationOverflow)?;
        self.generation = generation.to_le_bytes();
        self.generation_slot = slot.to_le_bytes();
        Ok(())
    }

    /// The registry serving `list_id`, `None` when the table does not reference it.
    pub fn registry_for(&self, list_id: ListId) -> Option<ListRegistry> {
        let slot = self.sources[list_id.slot()];
        (slot.list_id != 0).then(|| match slot.registry {
            registry if registry == Address::default() => ListRegistry::Own,
            registry => ListRegistry::Curator(registry),
        })
    }

    /// The one curator registry the sources name, `None` when every list is the ring's own.
    pub fn curator(&self) -> Option<Address> {
        self.sources
            .iter()
            .map(|slot| slot.registry)
            .find(|registry| *registry != Address::default())
    }

    /// The map `policy_hash` was computed over.
    pub fn source_map(&self) -> Result<SourceMap, CustomRingError> {
        source_map(&self.sources)
    }

    pub fn rule_table(&self) -> Result<RuleTable, CustomRingError> {
        Ok(self.rules.validate(&self.source_map()?)?)
    }

    /// `UnmirroredRegistry` unless `registry` is the records or the curator.
    pub fn sync(
        &mut self,
        registry: &Address,
        source: &StorageRegistry,
    ) -> Result<(), CustomRingError> {
        let mirror = match self.curator() {
            _ if *registry == self.records => &mut self.own_roots,
            Some(curator) if curator == *registry => &mut self.curator_roots,
            _ => return Err(CustomRingError::UnmirroredRegistry),
        };
        *mirror = RootMirror {
            registry: *registry,
            roots: source.roots,
        };
        Ok(())
    }

    pub fn own_root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], CustomRingError> {
        self.own_roots.root_of(&self.records, revision, slot)
    }

    /// `MirrorNotSynced` without a curator source.
    pub fn curator_root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], CustomRingError> {
        let curator = self.curator().ok_or(CustomRingError::MirrorNotSynced)?;
        self.curator_roots.root_of(&curator, revision, slot)
    }
}

impl CoSigner {
    pub const fn scope(&self) -> Option<CoSignScope> {
        CoSignScope::new(self.scope)
    }
}

fn source_map(sources: &[SourceSlot; N_SOURCE_SLOTS]) -> Result<SourceMap, CustomRingError> {
    let mut slots = [PolicySource::default(); N_SOURCE_SLOTS];
    for (dst, slot) in slots.iter_mut().zip(sources) {
        *dst = slot.policy_source()?;
    }
    Ok(SourceMap::from_slots(slots)?)
}

const _: () = assert!(core::mem::size_of::<SourceSlot>() == 33);
const _: () = assert!(ROOT_HISTORY <= u8::MAX as usize);
const _: () = assert!(RingPolicy::SIZE == 4196);
const _: () = assert!(core::mem::offset_of!(RingPolicy, roles) == 6);
const _: () = assert!(core::mem::offset_of!(RingPolicy, delegate) == 134);
const _: () = assert!(core::mem::offset_of!(RingPolicy, auditor_pubkey) == 166);
const _: () = assert!(core::mem::offset_of!(RingPolicy, records) == 207);
const _: () = assert!(core::mem::offset_of!(RingPolicy, own_roots) == 1060);
const _: () = assert!(CoSigner::SIZE == 35);
