//! The ring account, and the rule naming the roots a frame may bind.
//!
//! SPP's ring config holds a ring's activation, its pause flag and the authority rail switch, and SPP
//! reads no list or auditor key. `RingPolicy` holds what the ring adds. The program rebuilds each
//! statement from the account, so a prover picks no role key, auditor key, policy hash or registry.
//!
//! Read after `docs/spec.md`, `docs/design/records-and-roots.md`. Read before
//! `program-libs/interface/src/accounts/storage.rs`, `program-libs/interface/src/accounts/tracking.rs`,
//! `program-libs/interface/src/instructions/transact.rs`, `programs/custom-ring/src/instructions/accounts/loader.rs`.
//!
//! Invariants
//! 1. `policy_hash` hashes `rules` and `sources`, and `set_policy` is the one write and validates the whole table first. The circuit holds its table to the hash, so a table the program refused never reaches a proof.
//! 2. A nonzero `records` names a registry of the ring's own `ring_id`, and `tracking` the registry `Initialize` created, and it never moves. `RegistrySlots::load` compares each account it reads to these addresses.
//! 3. `RootRead` fixes the registries a frame reads. Every transfer and a hidden owner's merge read the tracking root, a delegate transfer and a merge read no policy root, so a policy update fails neither in flight.
//! 4. `LiveRoots` reads each root at the frame's revision and slot. The frame names a revision and never a root.

use core::ops::BitOr;

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::HasherError;
use wincode::{SchemaRead, SchemaWrite};
use zolana_ring_policy::{
    registry_field, EncodedRuleTable, ListId, ListSet, PolicySource, RuleTable, SourceMap,
};

use crate::{
    error::CustomRingError,
    storage::{Revision, StorageRegistry},
    tracking::TrackingRegistry,
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

/// One per ring, every transfer, merge and role write passes it.
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
    /// The own `StorageRegistry`, zero means no thresholds.
    pub records: Address,
    /// Every read compares it, a forged registry would prove any wallet absent.
    pub tracking: Address,
    /// Zero without a policy.
    pub policy_hash: [u8; 32],
    /// Non-empty exactly for the lists `rules` references.
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    /// Little endian, one more at every table, source or records write.
    pub generation: [u8; 4],
    /// Little endian, the slot of the write `generation` counts.
    pub generation_slot: [u8; 8],
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

#[must_use]
#[derive(Debug, Copy, Clone)]
pub struct PolicyUpdate {
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    pub slot: u64,
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
    pub tracking: Address,
}

impl NewRing {
    /// No policy, boxed in place past the SBF stack frame.
    pub fn account(self) -> Box<RingPolicy> {
        let mut ring: Box<RingPolicy> = bytemuck::zeroed_box();
        ring.discriminator = RING_POLICY;
        ring.bump = self.bump;
        ring.mode = self.mode as u8;
        ring.roles = self.roles;
        ring.auditor_pubkey = self.auditor_pubkey;
        ring.created_slot = self.created_slot.to_le_bytes();
        ring.records = self.records;
        ring.tracking = self.tracking;
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

    /// Thresholds live in the own registry, the approval mask reads them with or without a policy.
    pub fn thresholds_active(&self) -> bool {
        self.records != Address::default()
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

    /// `PolicyNotSet` on a ring with no table.
    pub fn policy_hash(&self) -> Result<&[u8; 32], CustomRingError> {
        self.written_policy_hash()
            .ok_or(CustomRingError::PolicyNotSet)
    }

    pub fn written_policy_hash(&self) -> Option<&[u8; 32]> {
        (self.policy_hash != [0; 32]).then_some(&self.policy_hash)
    }

    /// `Initialize`, the table write and the source write all end here, the one point a table
    /// reaches the account, and each validates the whole table it would store.
    pub fn set_policy(&mut self, update: PolicyUpdate) -> Result<(), CustomRingError> {
        let PolicyUpdate {
            sources,
            rules,
            slot,
        } = update;
        let source_map = source_map_of(&sources)?;
        rules.validate(&source_map)?;
        let policy_hash = rules.hash(&source_map)?;
        self.count_generation(slot)?;
        self.policy_hash = policy_hash;
        self.sources = sources;
        self.rules = rules;
        Ok(())
    }

    pub fn rebind_records(&mut self, records: Address, slot: u64) -> Result<(), CustomRingError> {
        self.count_generation(slot)?;
        self.records = records;
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
        source_map_of(&self.sources)
    }

    /// `SourceMap::salted` of `source_map`, read from the slots with no registry hash.
    pub fn salted(&self) -> ListSet {
        ListSet::salted_among(|list_id| self.sources[list_id.slot()].list_id != 0)
    }

    pub fn rule_table(&self) -> Result<RuleTable, CustomRingError> {
        Ok(self.rules.validate(&self.source_map()?)?)
    }

    /// Account order after the ring account.
    pub fn root_registries(&self, read: RootRead) -> impl Iterator<Item = Address> {
        self.own_registry(read)
            .into_iter()
            .chain(self.curator_registry(read))
            .chain([self.tracking])
    }

    pub fn salted_registries(&self) -> Vec<Address> {
        self.salted()
            .iter()
            .map(|list_id| *source_address(&self.sources[list_id.slot()], &self.records))
            .collect()
    }

    /// A salted list needs a floor against the ring's tracking registry.
    pub fn check_source_pair(
        &self,
        address: &Address,
        source: &StorageRegistry,
    ) -> Result<(), CustomRingError> {
        // An unpaired source serving a private list takes no floor, and a blocked enrolled owner
        // then proves itself unenrolled under an old tracking root. A public read holds no such
        // risk, one curator serves many rings and pins at most one of their registries.
        match source.tracking_registry == self.tracking || !self.reads_salted(address) {
            true => Ok(()),
            false => Err(CustomRingError::SaltedSourceOtherTracking),
        }
    }

    /// The floor a frame's tracking root answers to through `source`, zero with no salted read.
    ///
    /// The one exception to tracking grace, a stale root could prove a blocked owner unenrolled.
    /// A source's floor counts revisions of the registry it pins, so a public curator's floor
    /// says nothing of the ring's registry and comparing them would refuse a live root.
    pub fn tracking_floor(&self, address: &Address, source: &StorageRegistry) -> Revision {
        match self.reads_salted(address) {
            true => source.tracking_floor,
            false => Revision::default(),
        }
    }

    /// The ring maps a private list to the source at `address`.
    pub fn reads_salted(&self, address: &Address) -> bool {
        self.salted()
            .iter()
            .any(|list_id| source_address(&self.sources[list_id.slot()], &self.records) == address)
    }

    pub fn own_registry(&self, read: RootRead) -> Option<Address> {
        (read != RootRead::None).then_some(self.records)
    }

    pub fn curator_registry(&self, read: RootRead) -> Option<Address> {
        (read == RootRead::Policy).then(|| self.curator()).flatten()
    }
}

impl CoSigner {
    pub const fn scope(&self) -> Option<CoSignScope> {
        CoSignScope::new(self.scope)
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

/// Policy roots only, every read also takes the pinned tracking registry.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RootRead {
    None,
    Own,
    /// The own root, and the curator root when the ring names one.
    Policy,
}

impl RootRead {
    /// A delegate reads no policy root, a restrictive update cannot fail its in-flight proof.
    pub fn transfer(ring: &RingPolicy, delegate: bool) -> Self {
        match (delegate, ring.has_policy(), ring.thresholds_active()) {
            (true, _, _) | (false, false, false) => Self::None,
            (false, true, _) => Self::Policy,
            (false, false, true) => Self::Own,
        }
    }

    /// A merge runs no rules.
    pub const fn merge() -> Self {
        Self::None
    }
}

/// The roots the passed registries serve at `slot`, a revoked root fails at once.
#[derive(Debug, Copy, Clone)]
pub struct LiveRoots<'a> {
    pub own: Option<&'a StorageRegistry>,
    pub curator: Option<&'a StorageRegistry>,
    /// Bound by address to the ring's pin.
    pub tracking: &'a TrackingRegistry,
    /// `RingPolicy::tracking_floor` of the sources passed, zero with no salted read.
    pub tracking_floor: Revision,
    pub slot: u64,
}

impl LiveRoots<'_> {
    pub fn own(&self, revision: Revision) -> Result<[u8; 32], CustomRingError> {
        self.served(self.own, revision)?
            .ok_or(CustomRingError::MissingRegistry)
    }

    pub fn curator(&self, revision: Revision) -> Result<[u8; 32], CustomRingError> {
        self.served(self.curator, revision)?
            .ok_or(CustomRingError::MissingRegistry)
    }

    /// Refused below a salted source's floor, the one exception to tracking grace.
    pub fn tracking(&self, revision: Revision) -> Result<[u8; 32], CustomRingError> {
        if revision.value() < self.tracking_floor.value() {
            return Err(CustomRingError::TrackingRootBelowFloor);
        }
        self.tracking
            .root(revision, self.slot)
            .map_err(|_| CustomRingError::RootNotServed)
    }

    /// Without the records, `None` at revision zero and `unread` otherwise.
    pub fn own_if_read(
        &self,
        revision: Revision,
        unread: CustomRingError,
    ) -> Result<Option<[u8; 32]>, CustomRingError> {
        Self::named(self.served(self.own, revision)?, revision, unread)
    }

    /// Without a curator, `None` at revision zero and `unread` otherwise.
    pub fn curator_if_read(
        &self,
        revision: Revision,
        unread: CustomRingError,
    ) -> Result<Option<[u8; 32]>, CustomRingError> {
        Self::named(self.served(self.curator, revision)?, revision, unread)
    }

    fn served(
        &self,
        registry: Option<&StorageRegistry>,
        revision: Revision,
    ) -> Result<Option<[u8; 32]>, CustomRingError> {
        registry
            .map(|registry| {
                registry
                    .root(revision, self.slot)
                    .map_err(|_| CustomRingError::RootNotServed)
            })
            .transpose()
    }

    fn named(
        root: Option<[u8; 32]>,
        revision: Revision,
        unread: CustomRingError,
    ) -> Result<Option<[u8; 32]>, CustomRingError> {
        match root {
            None if revision.value() != 0 => Err(unread),
            root => Ok(root),
        }
    }
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
    Anonymous = 2,
}

impl TryFrom<u8> for RingMode {
    type Error = CustomRingError;

    fn try_from(byte: u8) -> Result<Self, CustomRingError> {
        match byte {
            0 => Ok(Self::Confidential),
            2 => Ok(Self::Anonymous),
            _ => Err(CustomRingError::InvalidRingMode),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CoSignScope(u8);

impl CoSignScope {
    pub const NONE: Self = Self(0);
    pub const TRANSFERS: Self = Self(1);
    pub const DEPOSITS: Self = Self(2);
    pub const WITHDRAWALS: Self = Self(4);
    pub const APPROVE_OUTFLOW: Self = Self(8);
    pub const APPROVE_WITHDRAWAL: Self = Self(16);
    pub const APPROVALS: Self = Self(Self::APPROVE_OUTFLOW.0 | Self::APPROVE_WITHDRAWAL.0);
    pub const ALL: Self =
        Self(Self::TRANSFERS.0 | Self::DEPOSITS.0 | Self::WITHDRAWALS.0 | Self::APPROVALS.0);

    /// A record's scope is nonzero.
    pub const fn new(bits: u8) -> Option<Self> {
        if bits == 0 || bits & !Self::ALL.0 != 0 {
            return None;
        }
        Some(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl BitOr for CoSignScope {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Records per optional class.
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
        let covered = Self::CLASSES
            .iter()
            .zip(self.0)
            .filter(|(_, count)| *count != 0)
            .fold(CoSignScope::NONE, |covered, (class, _)| covered | *class);
        CoSignScope::new(covered.bits())
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

/// A zero slot serves the own records.
fn source_address<'a>(slot: &'a SourceSlot, records: &'a Address) -> &'a Address {
    match slot.registry == Address::default() {
        true => records,
        false => &slot.registry,
    }
}

fn source_map_of(sources: &[SourceSlot; N_SOURCE_SLOTS]) -> Result<SourceMap, CustomRingError> {
    let mut slots = [PolicySource::default(); N_SOURCE_SLOTS];
    for (dst, slot) in slots.iter_mut().zip(sources) {
        *dst = slot.policy_source()?;
    }
    Ok(SourceMap::from_slots(slots)?)
}

const _: () = assert!(core::mem::size_of::<SourceSlot>() == 33);
const _: () = assert!(ROOT_HISTORY <= u8::MAX as usize);
const _: () = assert!(RingPolicy::SIZE == 1125);
const _: () = assert!(core::mem::offset_of!(RingPolicy, roles) == 6);
const _: () = assert!(core::mem::offset_of!(RingPolicy, delegate) == 134);
const _: () = assert!(core::mem::offset_of!(RingPolicy, auditor_pubkey) == 166);
const _: () = assert!(core::mem::offset_of!(RingPolicy, records) == 207);
const _: () = assert!(core::mem::offset_of!(RingPolicy, tracking) == 239);
const _: () = assert!(CoSigner::SIZE == 35);
