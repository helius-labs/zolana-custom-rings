//! Shared instruction plumbing, and the one place the program signs as `ring_auth`.
//!
//! SPP accepts a ring's call on that one signature. `PlacedRingAuth` exists only after an address
//! check, and every signed call goes through it. A forwarded list also passes the slot check.
//!
//! Read after `instructions/transfer/verify.rs`. Read before `instructions/accounts/loader.rs`.

use custom_ring_interface::{CustomRingError, RingAccount};
use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_slice, Seed, Signer, MAX_CPI_ACCOUNTS},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use spr_interface::{RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};
use wincode::{config::DefaultConfig, SchemaRead};

const _: () = assert!(custom_ring_interface::MAX_SPP_CPI_ACCOUNTS == MAX_CPI_ACCOUNTS);

/// Instruction data of `T`, trailing bytes refused.
#[inline(never)]
pub(crate) fn parse<'a, T: SchemaRead<'a, DefaultConfig, Dst = T>>(
    data: &'a [u8],
) -> Result<T, CustomRingError> {
    wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)
}

pub(crate) fn no_data(data: &[u8]) -> Result<(), CustomRingError> {
    if !data.is_empty() {
        return Err(CustomRingError::InvalidInstructionData);
    }
    Ok(())
}

pub(crate) fn check_system_program(account: &AccountView) -> Result<(), CustomRingError> {
    if !pinocchio_system::check_id(account.address()) {
        return Err(CustomRingError::InvalidSystemProgram);
    }
    Ok(())
}

#[must_use]
pub(crate) struct Pda<'a, const N: usize> {
    pub program_id: &'a Address,
    pub seeds: &'a [&'a [u8]; N],
}

impl<const N: usize> Pda<'_, N> {
    /// The canonical bump, `T::ADDRESS` for another address.
    pub fn bump<T: RingAccount>(&self, address: &Address) -> Result<u8, CustomRingError> {
        self.canonical(address).ok_or(T::ADDRESS)
    }

    pub fn canonical(&self, address: &Address) -> Option<u8> {
        Address::derive_program_address(self.seeds, self.program_id)
            .filter(|(derived, _)| address_eq(address, derived))
            .map(|(_, bump)| bump)
    }

    /// Creates `T`'s account at the canonical address, refusing an occupied one.
    #[inline(never)]
    pub fn create<T: RingAccount>(
        &self,
        payer: &AccountView,
        account: &mut AccountView,
    ) -> Result<u8, ProgramError> {
        let bump = self.bump::<T>(account.address())?;
        if account.data_len() != 0 {
            return Err(T::EXISTS.into());
        }
        self.allocate(PdaAllocation {
            payer,
            account,
            space: T::SIZE,
            bump,
        })?;
        Ok(bump)
    }

    pub fn allocate(&self, allocation: PdaAllocation<'_>) -> ProgramResult {
        let PdaAllocation {
            payer,
            account,
            space,
            bump,
        } = allocation;
        let bump_seed = [bump];
        let signer: Vec<Seed> = self
            .seeds
            .iter()
            .map(|seed| Seed::from(*seed))
            .chain([Seed::from(&bump_seed)])
            .collect();
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            space,
            self.program_id,
            payer,
            None,
            &[Signer::from(signer.as_slice())],
        )
    }
}

pub(crate) struct PdaAllocation<'a> {
    pub payer: &'a AccountView,
    pub account: &'a mut AccountView,
    pub space: usize,
    pub bump: u8,
}

/// Refunds the rent and closes, `mismatch` when the recipient is the account.
pub(crate) fn close_into(
    account: &mut AccountView,
    rent_recipient: &mut AccountView,
    mismatch: CustomRingError,
) -> ProgramResult {
    if account.address() == rent_recipient.address() {
        return Err(mismatch.into());
    }
    let refund = rent_recipient
        .lamports()
        .checked_add(account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    account.set_lamports(0);
    account.close()
}

pub(crate) struct RingAuth {
    address: Address,
    bump: u8,
}

pub(crate) struct PlacedRingAuth(RingAuth);

impl RingAuth {
    pub fn derive(program_id: &Address) -> Result<Self, CustomRingError> {
        let (address, bump) = Address::derive_program_address(&[RING_AUTH_PDA_SEED], program_id)
            .ok_or(CustomRingError::MissingRingAuth)?;
        Ok(Self { address, bump })
    }

    /// A direct SPP call names the PDA as `account`.
    pub fn check_account(self, account: &AccountView) -> Result<PlacedRingAuth, CustomRingError> {
        if account.address() != &self.address {
            return Err(CustomRingError::MissingRingAuth);
        }
        Ok(PlacedRingAuth(self))
    }

    /// SPP reads every copy of the PDA as signed, a forwarded list holds it at `index` alone.
    /// A second copy would pass as an owner or a funder under the ring's own signature.
    pub fn check_slot(
        self,
        accounts: &[AccountView],
        index: usize,
    ) -> Result<PlacedRingAuth, CustomRingError> {
        if accounts.get(index).map(AccountView::address) != Some(&self.address) {
            return Err(CustomRingError::MissingRingAuth);
        }
        if accounts
            .iter()
            .enumerate()
            .any(|(position, account)| position != index && account.address() == &self.address)
        {
            return Err(CustomRingError::RingAuthOutOfSlot);
        }
        Ok(PlacedRingAuth(self))
    }
}

impl PlacedRingAuth {
    pub fn invoke<A: AsRef<AccountView>>(&self, accounts: &[A], data: &[u8]) -> ProgramResult {
        self.invoke_program(
            &Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            accounts,
            data,
        )
    }

    /// Raises the PDA alone to a signer.
    #[inline(never)]
    pub fn invoke_program<A: AsRef<AccountView>>(
        &self,
        program_id: &Address,
        accounts: &[A],
        data: &[u8],
    ) -> ProgramResult {
        if accounts.len() > MAX_CPI_ACCOUNTS {
            return Err(CustomRingError::TooManyAccounts.into());
        }
        let RingAuth { address, bump } = &self.0;
        let metas: Vec<InstructionAccount> = accounts
            .iter()
            .map(|account| {
                let account = account.as_ref();
                let is_signer = account.is_signer() || address_eq(account.address(), address);
                InstructionAccount::new(account.address(), account.is_writable(), is_signer)
            })
            .collect();
        let bump = [*bump];
        let seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(&bump)];
        let instruction = InstructionView {
            program_id,
            accounts: &metas,
            data,
        };
        invoke_signed_with_slice(&instruction, accounts, &[Signer::from(seeds.as_slice())])
    }
}
