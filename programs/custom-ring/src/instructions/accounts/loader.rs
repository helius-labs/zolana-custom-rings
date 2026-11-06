//! Every account read of the program, and what each read accepts as proof of the account's identity.
//!
//! Owner and discriminator suffice for an account created only at its canonical PDA. A registry any
//! authority can create gets its identity from the ring's pin, by address.
//!
//! A statement binds root values, and these rules fix the roots a frame may name:
//!
//! 1. A frame names a revision and the registry serves the root, no root value comes from the frame.
//! 2. A registry serves its current root and each retired root before its expiry.
//! 3. A batch the apply proof marks permissive retires the root under the registry's grace, an in-flight proof still settles.
//! 4. A batch the apply proof marks restrictive retires every earlier root at once, a revocation takes effect in the next transaction.
//! 5. A tracking root always retires under grace, enrollment refuses no in-flight proof.
//! 6. A floor limits that grace, a stale tracking root could prove an owner with a private entry unenrolled.
//!
//! A source that pins a tracking registry records a floor at each private write, the tracking revision the
//! write proved its rows under. `LiveRoots::tracking` refuses a frame below the highest floor among sources
//! the ring reads a private list from.
//!
//! Read after `instructions/runtime/instruction_runtime.rs`. Read before `program-libs/interface/src/accounts/state.rs`.

use custom_ring_interface::{
    cosign::{CoSignCover, CoSignRequirement, MAX_CO_SIGNERS},
    storage::{Revision, StorageRegistry},
    tracking::TrackingRegistry,
    CoSigner, CustomRingError, LiveRoots, RingAccount, RingPolicy, RingRole, RootRead,
    SettlementAccount, TokenAccountState, STORAGE_PROGRAM_ID,
};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use spr_interface::{BPF_LOADER_UPGRADEABLE_ID, SHIELDED_POOL_PROGRAM_ID};
use zolana_ring_policy::ring_id_field;

/// Owner and discriminator suffice, accounts are created only at their canonical PDA.
#[inline(always)]
pub fn load<'a, T: RingAccount>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, T>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(T::INVALID.into());
    }
    let data = account.try_borrow().map_err(|_| T::INVALID)?;
    Ref::filter_map(data, T::from_data).map_err(|_| T::INVALID.into())
}

#[inline(always)]
pub fn load_mut<'a, T: RingAccount>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, T>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(T::INVALID.into());
    }
    let data = account.try_borrow_mut().map_err(|_| T::INVALID)?;
    RefMut::filter_map(data, T::from_data_mut).map_err(|_| T::INVALID.into())
}

#[inline(always)]
pub fn load_policy<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, RingPolicy>, ProgramError> {
    load(program_id, account)
}

#[inline(always)]
pub fn load_policy_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, RingPolicy>, ProgramError> {
    load_mut(program_id, account)
}

/// The ring account whose `role` the signer holds, the processor checks the signature.
#[must_use]
pub struct RoleHolder<'a> {
    pub program_id: &'a Address,
    pub role: RingRole,
    pub signer: &'a AccountView,
}

impl RoleHolder<'_> {
    #[inline(always)]
    pub fn load<'a>(self, ring: &'a AccountView) -> Result<Ref<'a, RingPolicy>, ProgramError> {
        let ring = load_policy(self.program_id, ring)?;
        ring.check_role(self.role, self.signer.address())?;
        Ok(ring)
    }

    #[inline(always)]
    pub fn load_mut<'a>(
        self,
        ring: &'a mut AccountView,
    ) -> Result<RefMut<'a, RingPolicy>, ProgramError> {
        let ring = load_policy_mut(self.program_id, ring)?;
        ring.check_role(self.role, self.signer.address())?;
        Ok(ring)
    }
}

/// Any authority's registry, the storage program creates it only at its canonical PDA.
pub fn load_storage_registry(
    account: &AccountView,
) -> Result<Ref<'_, StorageRegistry>, ProgramError> {
    let invalid = CustomRingError::InvalidStorageRegistry;
    if !account.owned_by(&STORAGE_PROGRAM_ID) {
        return Err(invalid.into());
    }
    let data = account.try_borrow().map_err(|_| invalid)?;
    Ref::filter_map(data, StorageRegistry::from_data).map_err(|_| invalid.into())
}

/// A registry fit to hold the ring's records, one own registry per ring, its ring id scopes every address.
pub fn load_records_registry<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, StorageRegistry>, ProgramError> {
    let registry = load_storage_registry(account)?;
    let ring_id = ring_id_field(program_id.as_array()).map_err(CustomRingError::from)?;
    if registry.ring_id != ring_id {
        return Err(CustomRingError::RecordsRegistryOtherRing.into());
    }
    Ok(registry)
}

/// The ring's live registries, read where an instruction names them after the ring account.
pub struct RingRegistries<'a> {
    own: Option<Ref<'a, StorageRegistry>>,
    curator: Option<Ref<'a, StorageRegistry>>,
    tracking: Ref<'a, TrackingRegistry>,
    tracking_floor: Revision,
    pub len: usize,
}

impl RingRegistries<'_> {
    pub fn roots(&self, slot: u64) -> LiveRoots<'_> {
        LiveRoots {
            own: self.own.as_deref(),
            curator: self.curator.as_deref(),
            tracking: &self.tracking,
            tracking_floor: self.tracking_floor,
            slot,
        }
    }
}

#[must_use]
pub struct RegistrySlots<'a> {
    pub ring: &'a RingPolicy,
    pub read: RootRead,
}

impl RegistrySlots<'_> {
    /// Own, curator, then tracking, each compared with the ring's pin before its bytes are read.
    #[inline(never)]
    pub fn load<'b>(
        self,
        mut next: impl FnMut() -> Result<&'b AccountView, ProgramError>,
    ) -> Result<RingRegistries<'b>, ProgramError> {
        let mut len = 0;
        let mut bound_account = |bound: &Address| {
            let account = next()?;
            if account.address() != bound {
                return Err(ProgramError::from(CustomRingError::UnboundRegistry));
            }
            len += 1;
            Ok(account)
        };
        let ring = self.ring;
        let mut tracking_floor = 0;
        let mut storage = |bound: Option<Address>| {
            bound
                .map(|bound| {
                    let source = load_storage_registry(bound_account(&bound)?)?;
                    // A private list's source pins the ring's tracking registry, its floor counts those revisions.
                    ring.check_source_pair(&bound, &source)?;
                    tracking_floor =
                        u64::max(tracking_floor, ring.tracking_floor(&bound, &source).value());
                    Ok::<_, ProgramError>(source)
                })
                .transpose()
        };
        let own = storage(self.ring.own_registry(self.read))?;
        let curator = storage(self.ring.curator_registry(self.read))?;
        let tracking = load_tracking_registry(bound_account(&self.ring.tracking)?)?;
        Ok(RingRegistries {
            own,
            curator,
            tracking,
            tracking_floor: tracking_floor.into(),
            len,
        })
    }
}

/// Any creator can make one with a matching `ring_id`, a caller compares the address.
fn load_tracking_registry(
    account: &AccountView,
) -> Result<Ref<'_, TrackingRegistry>, ProgramError> {
    let invalid = CustomRingError::InvalidTrackingRegistry;
    if !account.owned_by(&STORAGE_PROGRAM_ID) {
        return Err(invalid.into());
    }
    let data = account.try_borrow().map_err(|_| invalid)?;
    Ref::filter_map(data, TrackingRegistry::from_data).map_err(|_| invalid.into())
}

/// The shielded pool by address, its account position differs per forwarded layout.
#[inline(always)]
pub fn validate_spp_program(accounts: &[AccountView]) -> ProgramResult {
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if !accounts
        .iter()
        .any(|account| account.address() == &spp_id && account.executable())
    {
        return Err(CustomRingError::InvalidShieldedPoolProgram.into());
    }
    Ok(())
}

pub fn check_funding_signer(
    accounts: &[AccountView],
    index: usize,
) -> Result<&AccountView, ProgramError> {
    let funder = accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !funder.is_signer() {
        return Err(CustomRingError::MissingFundingSigner.into());
    }
    Ok(funder)
}

#[must_use]
pub struct CoSignerSlot<'a> {
    pub program_id: &'a Address,
    pub record: &'a AccountView,
    pub signer: &'a AccountView,
}

impl CoSignerSlot<'_> {
    pub fn verify(self, requirement: CoSignRequirement) -> Result<CoSignCover, ProgramError> {
        let cover = requirement.cover(&*load::<CoSigner>(self.program_id, self.record)?)?;
        if !self.signer.is_signer() {
            return Err(CustomRingError::MissingCoSigner.into());
        }
        if self.signer.address() != &cover.signer {
            return Err(CustomRingError::UnauthorizedCoSigner.into());
        }
        Ok(cover)
    }
}

/// `[record, signer]` pairs lead the slice until the demand is covered, each pair covers a new class.
#[derive(Default)]
pub struct CoSigners {
    signers: [Address; MAX_CO_SIGNERS],
    len: usize,
}

impl CoSigners {
    pub fn verify(
        program_id: &Address,
        accounts: &[AccountView],
        mut requirement: Option<CoSignRequirement>,
    ) -> Result<Self, ProgramError> {
        let mut co_signers = Self::default();
        let mut pairs = accounts.as_chunks::<2>().0.iter();
        for slot in &mut co_signers.signers {
            let Some(current) = requirement else {
                break;
            };
            let [record, signer] = pairs.next().ok_or(ProgramError::NotEnoughAccountKeys)?;
            let cover = CoSignerSlot {
                program_id,
                record,
                signer,
            }
            .verify(current)?;
            *slot = cover.signer;
            co_signers.len += 1;
            requirement = cover.rest;
        }
        Ok(co_signers)
    }

    pub const fn accounts(&self) -> usize {
        2 * self.len
    }

    pub fn as_slice(&self) -> &[Address] {
        &self.signers[..self.len]
    }

    pub fn contains(&self, address: &Address) -> bool {
        self.as_slice().contains(address)
    }
}

pub(crate) struct LoadedSettlement<'a>(pub &'a AccountView);

impl SettlementAccount for LoadedSettlement<'_> {
    fn address(&self) -> &Address {
        self.0.address()
    }

    fn owner(&self) -> &Address {
        self.0.owner()
    }

    fn token_account(&self) -> Result<TokenAccountState, CustomRingError> {
        let data = self
            .0
            .try_borrow()
            .map_err(|_| CustomRingError::AnonymousExitTokenAccountInvalid)?;
        TokenAccountState::unpack(&data)
    }
}

/// Passes only the program's nonzero loader-v3 upgrade authority.
#[must_use]
pub struct UpgradeAuthorityCheck<'a> {
    pub program_id: &'a Address,
    pub authority: &'a AccountView,
    pub program: &'a AccountView,
    pub program_data: &'a AccountView,
}

impl UpgradeAuthorityCheck<'_> {
    pub fn verify(self) -> ProgramResult {
        let unauthorized = CustomRingError::UnauthorizedInitializer;
        if self.program.address() != self.program_id
            || self.program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
        {
            return Err(unauthorized.into());
        }
        let Some(UpgradeableLoaderState::Program {
            programdata_address,
        }) = loader_state(self.program)?
        else {
            return Err(unauthorized.into());
        };
        if self.program_data.address().as_array() != programdata_address.as_array()
            || self.program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
        {
            return Err(unauthorized.into());
        }
        let Some(UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(upgrade_authority),
            ..
        }) = loader_state(self.program_data)?
        else {
            return Err(unauthorized.into());
        };
        let upgrade_authority = upgrade_authority.to_bytes();
        if upgrade_authority == [0; 32] || upgrade_authority != self.authority.address().to_bytes()
        {
            return Err(unauthorized.into());
        }
        Ok(())
    }
}

/// bincode reads only the enum, the trailing ELF bytes of program data stay untouched.
fn loader_state(account: &AccountView) -> Result<Option<UpgradeableLoaderState>, ProgramError> {
    let data = account
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    Ok(
        bincode::serde::decode_from_slice(&data, bincode::config::legacy())
            .ok()
            .map(|(state, _)| state),
    )
}
