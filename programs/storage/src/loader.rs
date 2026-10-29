use custom_ring_interface::storage::{RegistryId, StorageError, StorageRegistry};
use pinocchio::{
    account::RefMut,
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

#[must_use]
pub struct RegistryInit<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub creator: &'a Address,
    pub registry_id: &'a RegistryId,
    pub grace_slots: u64,
}

impl RegistryInit<'_> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let seeds = StorageRegistry::seeds(self.creator, self.registry_id);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidRegistry)?;
        if account.address() != &address {
            return Err(StorageError::InvalidRegistry.into());
        }
        if account.data_len() != 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        let bump = [bump];
        let [seed, creator, registry_id] = seeds;
        let signer_seeds = [
            Seed::from(seed),
            Seed::from(creator),
            Seed::from(registry_id),
            Seed::from(&bump),
        ];
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            StorageRegistry::SIZE,
            self.program_id,
            self.payer,
            None,
            &[Signer::from(signer_seeds.as_slice())],
        )?;
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&StorageRegistry::new(
                *self.creator,
                self.grace_slots,
            )));
        Ok(())
    }
}

#[inline(always)]
pub fn load_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, StorageRegistry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(StorageError::InvalidRegistry.into());
    }
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
