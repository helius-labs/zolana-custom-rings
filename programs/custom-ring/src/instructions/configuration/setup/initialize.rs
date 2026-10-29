use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, InitializeIxData, PolicyBindingIxData, RingKind, RingMode, RingPolicy,
    RingProgramConfig, DEFAULT_INSERT_FEE, RING_PROGRAM_CONFIG,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_interface::instruction::{encode_instruction, tag, CreateRingConfigData};

use crate::{
    instructions::{
        instruction_runtime::{check_system_program, parse, Pda, RingAuth},
        loader::{load_policy_mut, validate_spp_program, UpgradeAuthorityCheck},
        policy_binding::{RecordsBinding, TableBinding},
    },
    state::{is_x25519_key, Init},
};

/// Only the active loader-v3 upgrade authority initializes the ring, it becomes the config authority.
#[inline(never)]
pub fn process_initialize_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: InitializeIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let ring_auth = iter.next_mut("ring_auth")?;
    let spp_program = iter.next_account("spp_program")?;

    // 1. The signer holds the upgrade authority of the deployed binary.
    check_system_program(system_program)?;
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    validate_spp_program(core::slice::from_ref(spp_program))?;
    // 2. A canonical auditor key of large order keeps every envelope agreement contributory.
    if !is_x25519_key(&ix.auditor_pubkey) {
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
        auditor_pubkey: ix.auditor_pubkey,
        bump,
        has_policy: u8::from(ix.kind.has_policy()),
        mode: if ix.kind.anonymous() {
            RingMode::Anonymous
        } else {
            RingMode::Confidential
        } as u8,
        insert_fee: DEFAULT_INSERT_FEE.to_le_bytes(),
        created_slot: Clock::get()?.slot.to_le_bytes(),
        ..RingProgramConfig::zeroed()
    })
    .init(config)?;
    // 4. A policy ring pins its table, an audit-only ring may bind records alone for its withdrawal exemptions.
    match &ix.policy {
        Some(binding) => PolicyCreation {
            program_id,
            payer,
            authority: authority.address(),
            binding,
            kind: ix.kind,
        }
        .create(iter)?,
        None if ix.kind.has_policy() => return Err(CustomRingError::PolicyNotSet.into()),
        None => {}
    }
    // 5. SPP's `RingConfig` sits at the ring PDA, the one point where SPP checks the ring's identity.
    let placed = RingAuth::derive(program_id)?.check_account(ring_auth)?;
    let data = encode_instruction(
        tag::CREATE_RING_CONFIG,
        // Rail off and config inert until governance runs `set_ring_activation`.
        &CreateRingConfigData {
            program_id: *program_id,
            // SPP admin actions on the ring pass only through the ring program.
            authority: *ring_auth.address(),
        },
    );
    let cpi_accounts = [&*payer, &*protocol_config, &*ring_auth, &*system_program];
    placed.invoke(cpi_accounts.as_slice(), &data)
}

#[must_use]
struct PolicyCreation<'a> {
    program_id: &'a Address,
    payer: &'a AccountView,
    authority: &'a Address,
    binding: &'a PolicyBindingIxData,
    kind: RingKind,
}

impl PolicyCreation<'_> {
    #[inline(never)]
    fn create(self, mut iter: AccountIterator<'_>) -> ProgramResult {
        let policy = iter.next_mut("policy")?;
        let records = iter.next_account("records")?;
        let curators = iter.remaining_unchecked()?;
        let table = &self.binding.table;
        if !self.kind.has_policy() && !(table.sources.is_empty() && table.rules.is_empty()) {
            return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
        }
        RecordsBinding {
            records,
            config_authority: self.authority,
            storage_authority: &self.binding.storage_authority,
        }
        .check()?;
        let bump = Pda {
            program_id: self.program_id,
            seeds: &[RingPolicy::SEED],
        }
        .create::<RingPolicy>(self.payer, policy)?;
        Init(&*RingPolicy::new(bump, *records.address())).init(policy)?;
        if !self.kind.has_policy() {
            return Ok(());
        }
        // Sources name exactly the lists the rules reference.
        let bound = TableBinding {
            records: records.address(),
            table,
            curators,
        }
        .bind()?;
        // The pinned hash binds every later policy proof.
        load_policy_mut(self.program_id, policy)?.set_policy(
            bound.sources,
            bound.rules,
            Clock::get()?.slot,
        )?;
        Ok(())
    }
}
