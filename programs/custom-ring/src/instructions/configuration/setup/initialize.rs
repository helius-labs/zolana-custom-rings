//! Creates the ring account, its tracking registry and SPP's `RingConfig` in one instruction.
//!
//! The ring account fixes the auditor key and the mode for the ring's life. SPP admits any program's
//! `RingConfig` and reads no auditor key, so the check of who sets those values lives here.
//!
//! The instruction guarantees:
//!
//! 1. Only the deployed binary's upgrade authority creates the ring, at its one canonical PDA.
//! 2. The auditor key is canonical and of large order, and nonzero keys hold the four roles.
//! 3. A policy ring stores a validated table and its hash, any other ring stores no rule.
//! 4. The ring pins the tracking registry that storage derives from `ring_auth`, a registry of another creator fails that derivation, and each salted source of the stored table pins that registry.
//! 5. `RingConfig` names `ring_auth` as its authority, so SPP's ring admin actions pass through the program.
//!
//! The instruction relies on storage for the registry's derivation, and on SPP for `RingConfig`'s derivation and activation.
//!
//! Read after `instructions/accounts/loader.rs`, `state.rs`. Read before `instructions/verification/policy_binding.rs`.

use custom_ring_interface::{
    is_auditor_key,
    storage_instruction::{tag as storage_tag, InitializeTrackingIxData},
    CustomRingError, InitializeIxData, NewRing, PolicyBindingIxData, PolicyUpdate, RingKind,
    RingMode, RingPolicy, STORAGE_PROGRAM_ID,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_interface::instruction::{encode_instruction, tag, CreateRingConfigData};
use zolana_ring_policy::ring_id_field;

use crate::{
    instructions::{
        instruction_runtime::{check_system_program, parse, Pda, RingAuth},
        loader::{validate_spp_program, UpgradeAuthorityCheck},
        policy_binding::{ProposedSources, TableBinding},
    },
    state::Init,
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
    let tracking = iter.next_mut("tracking_registry")?;
    // Only the runtime reads it, the CPI names the storage program by id.
    iter.next_account("storage_program")?;

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
    if !is_auditor_key(&ix.auditor_pubkey) {
        return Err(CustomRingError::InvalidAuditorPubkey.into());
    }
    // 3. The canonical PDA holds the kind for the ring's life and four nonzero role keys.
    ix.roles.check(None)?;
    let bump = Pda {
        program_id,
        seeds: &[RingPolicy::SEED],
    }
    .create::<RingPolicy>(payer, ring)?;
    // 4. A policy ring pins its table, any other ring may bind records alone for its thresholds.
    let registries = iter.remaining_unchecked()?;
    let records = match &ix.policy {
        Some(binding) => Some(
            PolicyCreation {
                binding,
                kind: ix.kind,
            }
            .records(registries)?,
        ),
        None if ix.kind.has_policy() => return Err(CustomRingError::PolicyNotSet.into()),
        None => None,
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
        records: records.map_or_else(Address::default, |records| *records.address()),
        tracking: *tracking.address(),
    }
    .account();
    if let Some(binding) = ix.policy.as_ref().filter(|_| ix.kind.has_policy()) {
        // Sources name exactly the lists the rules reference, the pinned hash binds every later policy proof.
        let bound = TableBinding {
            table: &binding.table,
            curators: &registries[1..],
        }
        .bind()?;
        account.set_policy(PolicyUpdate {
            sources: bound.sources,
            rules: bound.rules,
            slot,
        })?;
    }
    // 5. The records and the curator load once, each salted source pairs with the ring before the account exists.
    if let Some(records) = records {
        ProposedSources {
            program_id,
            proposed: &account,
            registries,
        }
        .check([*records.address()].into_iter().chain(account.curator()))?;
    }
    Init(&*account).init(ring)?;
    let placed = RingAuth::derive(program_id)?.check_account(ring_auth)?;
    // 6. Storage creates the registry at the address these seeds fix, the ring PDA's signature admits no other ring.
    let tracking_data = [
        &[storage_tag::INITIALIZE_TRACKING][..],
        bytemuck::bytes_of(&InitializeTrackingIxData {
            ring_id: ring_id_field(program_id.as_array()).map_err(CustomRingError::from)?,
            auditor_pubkey: ix.auditor_pubkey,
        }),
    ]
    .concat();
    let tracking_accounts = [&*payer, &*ring_auth, &*tracking, &*system_program];
    placed.invoke_program(
        &STORAGE_PROGRAM_ID,
        tracking_accounts.as_slice(),
        &tracking_data,
    )?;
    // 7. SPP binds the ring program to its canonical configuration account.
    let data = encode_instruction(
        tag::CREATE_RING_CONFIG,
        // SPP starts the authority rail off, and the config stays inert until `set_ring_activation`
        // unless the protocol config allows permissionless activation.
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
}

impl PolicyCreation<'_> {
    /// The records account leads the registries, `ProposedSources::check` loads it.
    #[inline(never)]
    fn records(self, registries: &[AccountView]) -> Result<&AccountView, ProgramError> {
        let records = registries
            .first()
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let table = &self.binding.table;
        if !self.kind.has_policy() && !(table.sources.is_empty() && table.rules.is_empty()) {
            return Err(CustomRingError::PolicyOnAuditOnlyRing.into());
        }
        Ok(records)
    }
}
