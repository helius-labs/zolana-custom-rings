use core::ops::BitOr;

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::HasherError;
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
// Discriminators 1 to 9, 11 and 12 are retired, never reuse them.
ring_accounts! {
    RingProgramConfig = RING_PROGRAM_CONFIG: 10, CONFIG_PDA_SEED: b"config",
        ConfigNotInitialized, ConfigAlreadyInitialized, InvalidConfigPda,
        |config: &RingProgramConfig| config.mode().is_ok()
            && config.has_policy <= 1;
    RingPolicy = RING_POLICY: 13, RING_POLICY_PDA_SEED: b"policy",
        InvalidRingPolicy, RingPolicyAlreadyExists, InvalidRingPolicy;
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
    RingProgramConfig { created_slot: u64 }
    RingPolicy { generation: u32, generation_slot: u64 }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingProgramConfig {
    pub discriminator: u8,
    pub authority: Address,
    /// Auditor X25519 public key as `0x04 || canonical little-endian u`.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub bump: u8,
    /// One for a policy ring.
    pub has_policy: u8,
    /// [`RingMode`] byte.
    pub mode: u8,
    pub co_signers: CoSignerCounts,
    /// Zero without a delegate.
    pub delegate: Address,
    /// Little endian, the slot `CreateConfig` ran in.
    pub created_slot: [u8; 8],
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

impl RingProgramConfig {
    pub fn mode(&self) -> Result<RingMode, CustomRingError> {
        RingMode::try_from(self.mode)
    }

    pub const fn has_policy(&self) -> bool {
        self.has_policy == 1
    }

    pub fn delegate(&self) -> Option<&Address> {
        (self.delegate != Address::default()).then_some(&self.delegate)
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct RingPolicy {
    pub discriminator: u8,
    pub bump: u8,
    /// The ring's own `StorageRegistry`, fixed at creation.
    pub records: Address,
    /// Zero without a policy.
    pub policy_hash: [u8; 32],
    /// Non-empty exactly for the lists `rules` references.
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
    pub rules: EncodedRuleTable,
    /// Little endian, one more at every table or source write.
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

impl RingPolicy {
    /// Unsynced mirrors and no policy, boxed in place past the SBF stack frame.
    pub fn new(bump: u8, records: Address) -> Box<Self> {
        let mut policy: Box<Self> = bytemuck::zeroed_box();
        policy.discriminator = RING_POLICY;
        policy.bump = bump;
        policy.records = records;
        policy
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
        let generation = self
            .generation()
            .checked_add(1)
            .ok_or(CustomRingError::PolicyGenerationOverflow)?;
        let source_map = source_map(&sources)?;
        rules.validate(&source_map)?;
        self.policy_hash = rules.hash(&source_map)?;
        self.sources = sources;
        self.rules = rules;
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

const _: () = assert!(RingProgramConfig::SIZE == 112);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, co_signers) == 69);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, delegate) == 72);
const _: () = assert!(core::mem::offset_of!(RingProgramConfig, created_slot) == 104);
const _: () = assert!(core::mem::size_of::<SourceSlot>() == 33);
const _: () = assert!(ROOT_HISTORY <= u8::MAX as usize);
const _: () = assert!(RingPolicy::SIZE == 3991);
const _: () = assert!(core::mem::offset_of!(RingPolicy, own_roots) == 855);
const _: () = assert!(CoSigner::SIZE == 35);
