use bytemuck::Zeroable;
use custom_ring_interface::{
    CreateConfigIxData, CustomRingError, RingMode, RingProgramConfig, RING_PROGRAM_CONFIG,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;

use crate::{
    instructions::{
        instruction_runtime::{check_system_program, parse, Pda},
        loader::UpgradeAuthorityCheck,
    },
    state::{is_x25519_key, Init},
};

/// Only the active loader-v3 upgrade authority creates the ring's singleton config.
#[inline(never)]
pub fn process_create_config_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let CreateConfigIxData {
        auditor_pubkey,
        kind,
    } = parse(data)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    // 1. The signer holds the upgrade authority of the deployed binary.
    check_system_program(system_program)?;
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    // 2. A canonical auditor key of large order keeps every envelope agreement contributory.
    if !is_x25519_key(&auditor_pubkey) {
        return Err(CustomRingError::InvalidAuditorPubkey.into());
    }
    // 3. The canonical PDA holds the kind for the ring's life.
    let bump = Pda {
        program_id,
        seeds: &[RingProgramConfig::SEED],
    }
    .create::<RingProgramConfig>(payer, config)?;
    Init(&RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: *authority.address(),
        auditor_pubkey,
        bump,
        has_policy: u8::from(kind.has_policy()),
        mode: if kind.anonymous() {
            RingMode::Anonymous
        } else {
            RingMode::Confidential
        } as u8,

        created_slot: Clock::get()?.slot.to_le_bytes(),
        ..RingProgramConfig::zeroed()
    })
    .init(config)
}
