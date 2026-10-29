use custom_ring_interface::storage::{StorageError, StorageRegistry};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

#[inline(always)]
pub fn init_registry(account: &mut AccountView, registry: &StorageRegistry) -> ProgramResult {
    let mut data = account.try_borrow_mut()?;
    if data.len() != StorageRegistry::SIZE {
        return Err(StorageError::InvalidRegistry.into());
    }
    data.copy_from_slice(bytemuck::bytes_of(registry));
    Ok(())
}

#[inline(always)]
pub fn load_registry<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, StorageRegistry>, ProgramError> {
    check_owner(program_id, account)?;
    Ref::filter_map(account.try_borrow()?, StorageRegistry::from_data)
        .map_err(|_| StorageError::InvalidRegistry.into())
}

#[inline(always)]
pub fn load_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, StorageRegistry>, ProgramError> {
    check_owner(program_id, account)?;
    RefMut::filter_map(account.try_borrow_mut()?, StorageRegistry::from_data_mut)
        .map_err(|_| StorageError::InvalidRegistry.into())
}

#[inline(always)]
fn check_owner(program_id: &Address, account: &AccountView) -> ProgramResult {
    match account.owned_by(program_id) {
        true => Ok(()),
        false => Err(StorageError::InvalidRegistry.into()),
    }
}
