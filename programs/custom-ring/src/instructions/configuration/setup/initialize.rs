use custom_ring_interface::{
    CustomRingError, InitializeIxData, NewRing, PolicyBindingIxData, RingKind, RingMode, RingPolicy,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_interface::instruction::{encode_instruction, tag, CreateRingConfigData};

use crate::{
    instructions::{
        instruction_runtime::{check_system_program, parse, Pda, RingAuth},
        loader::{validate_spp_program, UpgradeAuthorityCheck},
        policy_binding::{RecordsBinding, TableBinding},
    },
    state::{is_x25519_key, Init},
};

/// Only the active loader-v3 upgrade authority initializes the ring, it holds no role it does not name.
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
    let ring = iter.next_mut("ring")?;
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
    // 3. The canonical PDA holds the kind for the ring's life and four distinct nonzero role keys.
    ix.roles.check(None)?;
    let bump = Pda {
        program_id,
        seeds: &[RingPolicy::SEED],
    }
    .create::<RingPolicy>(payer, ring)?;
    // 4. A policy ring pins its table, an audit-only ring may bind records alone for its withdrawal exemptions.
    let records = match &ix.policy {
        Some(binding) => PolicyCreation {
            binding,
            kind: ix.kind,
            policy_authority: &ix.roles.policy,
        }
        .records(&mut iter)?,
        None if ix.kind.has_policy() => return Err(CustomRingError::PolicyNotSet.into()),
        None => Address::default(),
    };
    let slot = Clock::get()?.slot;
    let mut account = NewRing {
        bump,
        mode: if ix.kind.anonymous() {
            RingMode::Anonymous
        } else {
            RingMode::Confidential
        },
        roles: ix.roles,
        auditor_pubkey: ix.auditor_pubkey,
        created_slot: slot,
        records,
    }
    .account();
    if let Some(binding) = ix.policy.as_ref().filter(|_| ix.kind.has_policy()) {
        // Sources name exactly the lists the rules reference, the pinned hash binds every later policy proof.
        let bound = TableBinding {
            records: &records,
            table: &binding.table,
            curators: iter.remaining_unchecked()?,
        }
        .bind()?;
        account.set_policy(bound.sources, bound.rules, slot)?;
    }
    Init(&*account).init(ring)?;
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
    binding: &'a PolicyBindingIxData,
    kind: RingKind,
    policy_authority: &'a Address,
}

impl PolicyCreation<'_> {
    #[inline(never)]
    fn records(self, iter: &mut AccountIterator<'_>) -> Result<Address, ProgramError> {
        let records = iter.next_account("records")?;
        let table = &self.binding.table;
        if !self.kind.has_policy() && !(table.sources.is_empty() && table.rules.is_empty()) {
            return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
        }
        RecordsBinding {
            records,
            policy_authority: self.policy_authority,
            storage_authority: &self.binding.storage_authority,
        }
        .check()?;
        Ok(*records.address())
    }
}
