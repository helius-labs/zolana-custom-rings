use custom_ring_interface::{
    cosign::CoSignDemand, merge_ring_instruction_data, CoSignScope, CustomRingError,
    CustomRingMergeIxDataRef, RingMode, RING_DEPOSIT_DEPOSITOR_INDEX,
    RING_DEPOSIT_RING_CONFIG_INDEX, RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use spr_account_checks::AccountIterator;
use spr_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::{
    deposit_audit::{AuditedDeposit, DepositVerification},
    instruction_runtime::RingAuth,
    loader::{
        check_co_signer, check_funding_signer, load_config, load_registry, validate_spp_program,
    },
    merge_disclosure::MergeAudit,
};

#[inline(never)]
pub fn process_merge_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let request = CustomRingMergeIxDataRef::from_bytes(data)?;

    let mut iter = AccountIterator::new(accounts);
    let config = Box::new(*load_config(program_id, iter.next_account("config")?)?);
    let mode = config.mode()?;
    // 1. Only a key escrow ring binds its own root, its owner's record escrows the merged key.
    let root = match mode {
        RingMode::ConfidentialEscrow => Some(
            load_registry(program_id, iter.next_account("registry")?)?
                .own_root(request.registry_root_index)?,
        ),
        _ if request.registry_root_index != 0 => {
            return Err(CustomRingError::UnexpectedMemberRegistryRoot.into())
        }
        _ => None,
    };
    // 2. A merge is a transfer, a co-signer scoped to transfers signs it.
    let demand = CoSignDemand {
        approval_required: false,
        classes: CoSignScope::TRANSFERS,
        withdrawals: Vec::new(),
    };
    if let Some(expected) = demand.signer(&config)? {
        check_co_signer(iter.next_account("co_signer")?, &expected)?;
    }
    // 3. The ring PDA sits in its SPP slot alone and the payer SPP debits signs.
    let spp_accounts = iter.remaining()?;
    let ring_auth =
        RingAuth::derive(program_id)?.check_slot(spp_accounts, RING_MERGE_RING_CONFIG_INDEX)?;
    check_funding_signer(spp_accounts, RING_MERGE_PAYER_INDEX)?;

    // 4. A bad SPP proof point is refused before the disclosure pairing.
    let spp_body = request.spp_merge_body()?;
    // 5. The disclosure proves the owner's opening to the auditor, under key escrow its record too.
    let parties = custom_ring_interface::AnonymousParties {
        payer: spp_accounts[RING_MERGE_PAYER_INDEX].address().as_array(),
        cosigner: config.co_signer().map(Address::as_array),
        exit_destination: None,
    }
    .identities()
    .map_err(CustomRingError::from)?;
    MergeAudit {
        party_identities: &parties,
        program_id,
        config: &config,
        anonymous: mode == RingMode::Anonymous,
        member_registry_root: root.as_ref(),
        output_ring_data_hash: request.output_ring_data_hash,
        disclosure: request.disclosure,
        spp_body: &spp_body,
    }
    .verify()?;
    // 6. SPP verifies its merge proof over the ring data hash the ring selects.
    let forwarded = merge_ring_instruction_data(request.output_ring_data_hash, &spp_body);
    validate_spp_program(spp_accounts)?;
    ring_auth.invoke(spp_accounts, &forwarded)
}

#[inline(never)]
pub fn process_audited_deposit_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // 1. The proof prefix leads SPP's own deposit data, forwarded unchanged.
    let audited = AuditedDeposit::parse(data)?;
    let deposit = RingDepositIxDataRef::from_bytes(audited.spp_data.get(1..).unwrap_or_default())
        .map_err(|_| CustomRingError::InvalidDepositData)?;

    let mut iter = AccountIterator::new(accounts);
    let config = Box::new(*load_config(program_id, iter.next_account("config")?)?);
    let mode = config.mode()?;
    // 2. Only a registry-mode ring binds its own root, its outputs escrow keys.
    let registry_root = match mode {
        RingMode::ConfidentialEscrow => Some(
            load_registry(program_id, iter.next_account("registry")?)?
                .own_root(audited.registry_root_index)?,
        ),
        _ if audited.registry_root_index != 0 => {
            return Err(CustomRingError::UnexpectedMemberRegistryRoot.into())
        }
        _ => None,
    };
    // 3. A co-signer scoped to deposits signs.
    let demand = CoSignDemand {
        approval_required: false,
        classes: CoSignScope::DEPOSITS,
        withdrawals: Vec::new(),
    };
    if let Some(expected) = demand.signer(&config)? {
        check_co_signer(iter.next_account("co_signer")?, &expected)?;
    }
    let spp_accounts = iter.remaining()?;
    let anonymous = mode == RingMode::Anonymous;
    // 4. Public deposit fields in an anonymous ring would name the recipient.
    if anonymous
        && deposit
            .deposits
            .iter()
            .any(|entry| entry.ring_data_hash != &[0; 32])
    {
        return Err(CustomRingError::AnonymousRingDataNotZero.into());
    }
    // 5. The ring PDA sits in its SPP slot alone and the depositor SPP debits signs.
    let ring_auth =
        RingAuth::derive(program_id)?.check_slot(spp_accounts, RING_DEPOSIT_RING_CONFIG_INDEX)?;
    check_funding_signer(spp_accounts, RING_DEPOSIT_DEPOSITOR_INDEX)?;

    // 6. The proof binds the SPP data and target tree, the auditor opens every output.
    let tree = spp_accounts
        .first()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    DepositVerification {
        program_id,
        tree: tree.address(),
        auditor_pubkey: &config.auditor_pubkey,
        anonymous,
        member_registry_root: registry_root.as_ref(),
        audited: &audited,
        deposit: &deposit,
    }
    .verify()?;
    // 7. SPP runs the deposit the proof bound, signed by the ring PDA.
    validate_spp_program(spp_accounts)?;
    ring_auth.invoke(spp_accounts, audited.spp_data)
}
