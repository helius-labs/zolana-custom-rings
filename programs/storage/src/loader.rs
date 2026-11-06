//! Account access of the Storage program, each account an instruction reads or writes loads here.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/storage.rs`,
//! `program-libs/interface/src/accounts/tracking.rs`. Read before
//! `programs/storage/src/instructions/update.rs`, `programs/storage/src/instructions/enroll.rs`.
//!
//! Guarantees:
//! 1. A registry, authorization or grant loads only when the program owns it, at its exact size and under its discriminator.
//! 2. A created account takes its canonical bump from the derivation, never from instruction data.
//!
//! Relies on:
//! 1. The processor checks the signature of each creator or owner a seed names, ahead of its `init` or `write`.

use custom_ring_interface::{
    owner_grant::OwnerGrant,
    storage::{Revision, StorageError, StorageRegistry},
    storage_instruction::{
        EnrollIxData, InitializeIxData, InitializeTrackingIxData, OwnerGrantIxData,
    },
    tracking::{FirstEnrollment, TrackingAuthorization, TrackingRegistry},
};
use pinocchio::{
    account::{Ref, RefMut},
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

/// Seeds of the longest PDA here and its bump.
const MAX_SIGNER_SEEDS: usize = 6;

#[must_use]
pub struct RegistryInit<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub creator: &'a Address,
    pub ix: &'a InitializeIxData,
}

impl RegistryInit<'_> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let seeds = StorageRegistry::seeds(self.creator, &self.ix.registry_id);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidRegistry)?;
        if account.address() != &address {
            return Err(StorageError::InvalidRegistry.into());
        }
        check_writable(account)?;
        if account.data_len() != 0 {
            return Err(StorageError::AlreadyInitialized.into());
        }
        CanonicalPda {
            program_id: self.program_id,
            payer: self.payer,
            seeds: &seeds,
            bump,
            size: StorageRegistry::SIZE,
        }
        .create(account)?;
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&StorageRegistry::new(
                *self.creator,
                self.ix,
            )));
        Ok(())
    }
}

/// Creates a registry the ring pins by address, its seeds and ring id authenticate nothing.
#[must_use]
pub struct TrackingRegistryInit<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub creator: &'a Address,
    pub ix: &'a InitializeTrackingIxData,
}

impl TrackingRegistryInit<'_> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let seeds = TrackingRegistry::seeds(self.creator, &self.ix.ring_id);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidTrackingRegistry)?;
        if account.address() != &address || !account.is_writable() {
            return Err(StorageError::InvalidTrackingRegistry.into());
        }
        if account.data_len() != 0 {
            return Err(StorageError::AlreadyInitialized.into());
        }
        CanonicalPda {
            program_id: self.program_id,
            payer: self.payer,
            seeds: &seeds,
            bump,
            size: TrackingRegistry::SIZE,
        }
        .create(account)?;
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&TrackingRegistry::new(self.ix)));
        Ok(())
    }
}

/// A first enrollment, whose owner signature and proof the processor checked.
#[must_use]
pub struct TrackingAuthorizationInit<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub owner: &'a Address,
    pub registry: &'a Address,
    pub ix: &'a EnrollIxData,
}

impl TrackingAuthorizationInit<'_> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let seeds = TrackingAuthorization::seeds(self.registry, self.owner);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidTrackingAuthorization)?;
        if account.address() != &address || !account.is_writable() {
            return Err(StorageError::InvalidTrackingAuthorization.into());
        }
        CanonicalPda {
            program_id: self.program_id,
            payer: self.payer,
            seeds: &seeds,
            bump,
            size: TrackingAuthorization::SIZE,
        }
        .create(account)?;
        let first = FirstEnrollment {
            registry: *self.registry,
            owner: *self.owner,
            ix: self.ix,
        }
        .account();
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&first));
        Ok(())
    }
}

/// One owner's consent to one reader, whose signature the processor checked.
#[must_use]
pub struct OwnerGrantWrite<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub owner: &'a Address,
    pub registry: &'a Address,
    pub ix: &'a OwnerGrantIxData,
}

impl OwnerGrantWrite<'_> {
    /// Creates the grant, a later call changes only whether it is active.
    #[inline(always)]
    pub fn write(self, account: &mut AccountView) -> ProgramResult {
        let seeds = OwnerGrant::seeds(self.registry, self.owner, &self.ix.reader);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidOwnerGrant)?;
        // The derivation names the owner, whose signature the processor checked.
        if account.address() != &address || !account.is_writable() {
            return Err(StorageError::InvalidOwnerGrant.into());
        }
        if account.data_len() != 0 {
            if !account.owned_by(self.program_id) {
                return Err(StorageError::InvalidOwnerGrant.into());
            }
            let mut grant =
                RefMut::filter_map(account.try_borrow_mut()?, OwnerGrant::from_data_mut)
                    .map_err(|_| StorageError::InvalidOwnerGrant)?;
            grant.active = self.ix.active;
            return Ok(());
        }
        CanonicalPda {
            program_id: self.program_id,
            payer: self.payer,
            seeds: &seeds,
            bump,
            size: OwnerGrant::SIZE,
        }
        .create(account)?;
        let grant = OwnerGrant {
            discriminator: OwnerGrant::DISCRIMINATOR,
            active: self.ix.active,
        };
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&grant));
        Ok(())
    }
}

/// Any creator's registry, the storage program never reads a ring's trust from it.
#[inline(always)]
pub fn load_tracking_registry<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, TrackingRegistry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(StorageError::InvalidTrackingRegistry.into());
    }
    Ref::filter_map(account.try_borrow()?, TrackingRegistry::from_data)
        .map_err(|_| StorageError::InvalidTrackingRegistry.into())
}

/// The pinned registry's root at `revision`, a row proven under another registry guards no salted read.
#[must_use]
pub struct PinnedTrackingRoot<'a> {
    pub program_id: &'a Address,
    pub registry: &'a StorageRegistry,
    pub revision: Revision,
    pub slot: u64,
}

impl PinnedTrackingRoot<'_> {
    #[inline(always)]
    pub fn load(self, account: &AccountView) -> Result<[u8; 32], ProgramError> {
        if account.address() != &self.registry.tracking_registry {
            return Err(StorageError::InvalidTrackingRegistry.into());
        }
        Ok(load_tracking_registry(self.program_id, account)?.root(self.revision, self.slot)?)
    }
}

#[inline(always)]
pub fn load_tracking_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, TrackingRegistry>, ProgramError> {
    if !account.owned_by(program_id) || !account.is_writable() {
        return Err(StorageError::InvalidTrackingRegistry.into());
    }
    RefMut::filter_map(account.try_borrow_mut()?, TrackingRegistry::from_data_mut)
        .map_err(|_| StorageError::InvalidTrackingRegistry.into())
}

/// An authorization of `registry`, its stored field binds it because it is created only at its PDA.
#[inline(always)]
pub fn load_owned_tracking_authorization_mut<'a>(
    program_id: &Address,
    registry: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, TrackingAuthorization>, ProgramError> {
    if !account.owned_by(program_id) || !account.is_writable() {
        return Err(StorageError::InvalidTrackingAuthorization.into());
    }
    let authorization = RefMut::filter_map(
        account.try_borrow_mut()?,
        TrackingAuthorization::from_data_mut,
    )
    .map_err(|_| StorageError::InvalidTrackingAuthorization)?;
    if &authorization.registry != registry {
        return Err(StorageError::InvalidTrackingAuthorization.into());
    }
    Ok(authorization)
}

#[inline(always)]
pub fn load_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, StorageRegistry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(StorageError::InvalidRegistry.into());
    }
    check_writable(account)?;
    RefMut::filter_map(account.try_borrow_mut()?, StorageRegistry::from_data_mut)
        .map_err(|_| StorageError::InvalidRegistry.into())
}

#[inline(always)]
pub fn check_authority(registry: &StorageRegistry, authority: &AccountView) -> ProgramResult {
    if authority.address() != &registry.authority {
        return Err(StorageError::Unauthorized.into());
    }
    Ok(())
}

#[inline(always)]
pub fn check_signer(account: &AccountView) -> Result<(), StorageError> {
    match account.is_signer() {
        true => Ok(()),
        false => Err(StorageError::MissingSignature),
    }
}

#[inline(always)]
fn check_writable(account: &AccountView) -> Result<(), StorageError> {
    match account.is_writable() {
        true => Ok(()),
        false => Err(StorageError::ReadOnlyRegistry),
    }
}

/// Handles a donated balance, `seeds` and `bump` come from the caller's derivation.
#[must_use]
struct CanonicalPda<'a> {
    program_id: &'a Address,
    payer: &'a AccountView,
    seeds: &'a [&'a [u8]],
    bump: u8,
    size: usize,
}

impl CanonicalPda<'_> {
    #[inline(always)]
    fn create(self, account: &mut AccountView) -> ProgramResult {
        let bump = [self.bump];
        // The slot past the last seed keeps the bump, the slice below ends on it.
        let mut signer_seeds: [Seed; MAX_SIGNER_SEEDS] =
            core::array::from_fn(|_| Seed::from(&bump));
        for (slot, seed) in signer_seeds.iter_mut().zip(self.seeds) {
            *slot = Seed::from(*seed);
        }
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            self.size,
            self.program_id,
            self.payer,
            None,
            &[Signer::from(&signer_seeds[..=self.seeds.len()])],
        )
    }
}
