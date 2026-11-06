//! Writes a ring account's first image.
//!
//! Read after `instructions/mod.rs`. Read before `instructions/configuration/setup/initialize.rs`.

use custom_ring_interface::RingAccount;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};

pub(crate) struct Init<'a, T>(pub &'a T);

impl<T: RingAccount> Init<'_, T> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let mut data = account
            .try_borrow_mut()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        if data.len() != T::SIZE {
            return Err(T::INVALID.into());
        }
        // A nonzero first byte is a live discriminator, never overwrite it.
        if data[0] != 0 {
            return Err(T::EXISTS.into());
        }
        data.copy_from_slice(bytemuck::bytes_of(self.0));
        Ok(())
    }
}
