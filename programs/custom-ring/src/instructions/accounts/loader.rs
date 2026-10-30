use custom_ring_interface::{
    anonymous_exit_destination, cosign::CoSignRequirement, storage::StorageRegistry, CoSigner,
    CustomRingError, LiveRoots, RingAccount, RingPolicy, RingRole, RootRead, SettlementAccount,
    TokenAccountState, STORAGE_PROGRAM_ID,
};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use spr_interface::{
    instruction::InterfaceTransfer, BPF_LOADER_UPGRADEABLE_ID, SHIELDED_POOL_PROGRAM_ID,
};

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

/// The ring's live registries, read where an instruction names them after the ring account.
pub struct RingRegistries<'a> {
    own: Option<Ref<'a, StorageRegistry>>,
    curator: Option<Ref<'a, StorageRegistry>>,
    pub len: usize,
}

impl RingRegistries<'_> {
    pub fn roots(&self, slot: u64) -> LiveRoots<'_> {
        LiveRoots {
            own: self.own.as_deref(),
            curator: self.curator.as_deref(),
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
    /// `UnboundRegistry` unless each account `next` yields is the bound one, the records first.
    #[inline(never)]
    pub fn load<'b>(
        self,
        mut next: impl FnMut() -> Result<&'b AccountView, ProgramError>,
    ) -> Result<RingRegistries<'b>, ProgramError> {
        let mut registries = RingRegistries {
            own: None,
            curator: None,
            len: 0,
        };
        for (index, bound) in self.ring.root_registries(self.read).enumerate() {
            let account = next()?;
            if account.address() != &bound {
                return Err(CustomRingError::UnboundRegistry.into());
            }
            let registry = Some(load_storage_registry(account)?);
            match index {
                0 => registries.own = registry,
                _ => registries.curator = registry,
            }
            registries.len = index + 1;
        }
        Ok(registries)
    }
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

/// The demanded co-signature's `[co_signer_record, co_signer]` slot.
#[must_use]
pub struct CoSignerSlot<'a> {
    pub program_id: &'a Address,
    pub record: &'a AccountView,
    pub signer: &'a AccountView,
}

impl CoSignerSlot<'_> {
    /// The record's signer, signing.
    pub fn verify(self, requirement: CoSignRequirement) -> Result<Address, ProgramError> {
        let expected = requirement.check(&*load::<CoSigner>(self.program_id, self.record)?)?;
        if !self.signer.is_signer() {
            return Err(CustomRingError::MissingCoSigner.into());
        }
        if self.signer.address() != &expected {
            return Err(CustomRingError::UnauthorizedCoSigner.into());
        }
        Ok(expected)
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

/// The destination every anonymous withdrawal names, read from the settlement window SPP settles.
pub fn load_anonymous_exit(
    transfers: &[InterfaceTransfer],
    window: &[AccountView],
) -> Result<Option<[u8; 32]>, CustomRingError> {
    let accounts: Vec<LoadedSettlement<'_>> = window.iter().map(LoadedSettlement).collect();
    anonymous_exit_destination(transfers, &accounts)
}

pub(crate) struct LoadedSettlement<'a>(pub &'a AccountView);

impl SettlementAccount for LoadedSettlement<'_> {
    fn address(&self) -> &Address {
        self.0.address()
    }

    fn owner(&self) -> &Address {
        self.0.owner()
    }

    fn data_len(&self) -> usize {
        self.0.data_len()
    }

    fn token_account(&self) -> Result<TokenAccountState, CustomRingError> {
        let data = self
            .0
            .try_borrow()
            .map_err(|_| CustomRingError::AnonymousExitTokenAccountInvalid)?;
        TokenAccountState::unpack(&data)
    }
}
