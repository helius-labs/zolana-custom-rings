//! Merge and audited deposit refusals ahead of the forward.

use bytemuck::Zeroable;
use custom_ring_interface::{
    merge_disclosure_field_count, tag, CoSignScope, CustomRingError, CustomRingMergeIxData,
    DepositPrefix, MergeDisclosure, RingDepositAuditCapsule, RootRead, AUDIT_CIPHERTEXT_LEN,
    MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, RING_DEPOSIT_DEPOSITOR_INDEX,
    RING_DEPOSIT_RING_CONFIG_INDEX, RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX,
};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use spr_interface::instruction::instruction_data::{
    deposit::{DepositAssetKind, EncryptedRingDepositData, RingDepositEntry, RingDepositIxData},
    merge_transact::{merge_circuit_width, MergeOutputEncryption, MergeProof, MergeTransactIxData},
};

use crate::{
    common::{
        auditor_pubkey, delegate_ring, off_curve_g2, on_curve_g2, policy_pda, reaches_verification,
        refused, ring_auth, set_co_signer, CoSignerSlot, Ring, Sent, Setup, PROGRAM, SYSTEM,
    },
    transact_rules::SPP,
};

/// A merge of `inputs` notes, `registry` the own revision a key escrow ring binds.
pub fn merge_data(registry: Option<u64>, inputs: usize) -> CustomRingMergeIxData {
    CustomRingMergeIxData {
        own_revision: registry.unwrap_or_default().into(),
        output_ring_data_hash: [8; 32],
        disclosure: merge_disclosure(inputs),
        merge: MergeTransactIxData {
            expiry_unix_ts: 1_800_000_000,
            proof: MergeProof {
                b: on_curve_g2(),
                ..MergeProof::zeroed()
            },
            output_utxo_hash: [1; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [2; 16],
                ciphertext: [[3; 32]; 3],
            },
            private_tx_hash: [4; 32],
            nullifiers: vec![[5; 32]; inputs],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    }
}

/// The disclosure a merge of `inputs` notes carries, its field count the width's.
pub fn merge_disclosure(inputs: usize) -> MergeDisclosure {
    let width = merge_circuit_width(inputs).expect("a merge width");
    MergeDisclosure {
        proof: Zeroable::zeroed(),
        eph_pk: auditor_pubkey(),
        ciphertext: [3; AUDIT_CIPHERTEXT_LEN],
        fields: vec![[0x0f; 32]; merge_disclosure_field_count(width)],
    }
}

fn merge_instruction(ring: &Ring, registry: Option<u64>) -> Instruction {
    merge_instruction_with(ring, &merge_data(registry, 8))
}

/// The forwarded list follows the ring account.
pub fn merge_instruction_with(ring: &Ring, data: &CustomRingMergeIxData) -> Instruction {
    let mut spp: Vec<AccountMeta> = (0..RING_MERGE_PAYER_INDEX)
        .map(|_| AccountMeta::new(Address::new_unique(), false))
        .collect();
    spp[RING_MERGE_RING_CONFIG_INDEX] = AccountMeta::new(ring_auth(), false);
    spp.push(AccountMeta::new(ring.payer.pubkey(), true));
    let mut accounts = vec![AccountMeta::new_readonly(policy_pda(), false)];
    accounts.extend(ring.registries(RootRead::merge(&ring.read(&policy_pda())).unwrap()));
    accounts.extend(spp);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: [&[tag::MERGE][..], &data.serialize().unwrap()].concat(),
    }
}

fn merge(ring: &mut Ring, registry: Option<u64>) -> Sent {
    let instruction = merge_instruction(ring, registry);
    ring.send(instruction, &[])
}

#[test]
fn an_escrow_merge_revision_its_registry_does_not_serve_is_refused() {
    let mut ring = delegate_ring(&Keypair::new());
    refused(merge(&mut ring, Some(1)), CustomRingError::RootNotServed);
    reaches_verification(merge(&mut ring, Some(0)));
}

#[test]
fn a_merge_outside_key_escrow_binds_no_root() {
    for setup in [Setup::AuditOnly, Setup::Policy, Setup::Anonymous] {
        let mut ring = Ring::new(setup);
        let mut data = merge_data(Some(1), 8);
        data.output_ring_data_hash = [0; 32];
        let instruction = merge_instruction_with(&ring, &data);
        refused(
            ring.send(instruction, &[]),
            CustomRingError::UnexpectedMemberRegistryRoot,
        );
        let mut data = merge_data(None, 8);
        data.output_ring_data_hash = [0; 32];
        let instruction = merge_instruction_with(&ring, &data);
        reaches_verification(ring.send(instruction, &[]));
    }
}

#[test]
fn a_merge_proof_point_off_the_curve_is_refused_before_the_forward() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut instruction = merge_instruction(&ring, None);
    let compressed = alt_bn128_g2_compress_be(&on_curve_g2()).unwrap();
    let at = instruction
        .data
        .windows(compressed.len())
        .position(|window| window == compressed)
        .expect("the merge carries b compressed");
    instruction.data[at..at + compressed.len()].copy_from_slice(&off_curve_g2());
    refused(
        ring.send(instruction, &[]),
        CustomRingError::InvalidSppProofPoint,
    );
}

fn deposit_entry(slot_index: u8, eph_pk: &[u8; 33]) -> RingDepositEntry {
    let capsule = RingDepositAuditCapsule {
        slot_index,
        eph_pk,
        ciphertext: &[3; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
        recipient_ciphertext: &[],
    }
    .encode();
    RingDepositEntry {
        asset_index: 0,
        view_tag: [1; 32],
        owner_utxo_hash: [0x0f; 32],
        amount: 10,
        ring_data_hash: [0; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: auditor_pubkey(),
            salt: [2; 16],
            ciphertext: capsule,
        },
    }
}

fn deposit_of(deposits: Vec<RingDepositEntry>) -> RingDepositIxData {
    RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits,
    }
}

pub fn ring_deposit() -> RingDepositIxData {
    deposit_of(vec![deposit_entry(0, &auditor_pubkey())])
}

/// `registry` the own revision an escrow-mode ring binds.
fn audited_deposit(ring: &mut Ring, registry: Option<u64>) -> Sent {
    let instruction = deposit_instruction(ring, registry, &ring_deposit());
    ring.send(instruction, &[])
}

pub fn deposit_instruction(
    ring: &Ring,
    registry: Option<u64>,
    deposit: &RingDepositIxData,
) -> Instruction {
    let prefix = DepositPrefix {
        tag: tag::DEPOSIT,
        proof: Zeroable::zeroed(),
        own_revision: registry.unwrap_or_default().into(),
        curator_revision: Default::default(),
    };
    let data = [
        bytemuck::bytes_of(&prefix),
        &[spr_interface::instruction::tag::RING_DEPOSIT],
        &deposit.serialize().unwrap(),
    ]
    .concat();
    let mut spp: Vec<AccountMeta> = (0..=RING_DEPOSIT_RING_CONFIG_INDEX)
        .map(|_| AccountMeta::new(Address::new_unique(), false))
        .collect();
    spp[RING_DEPOSIT_DEPOSITOR_INDEX] = AccountMeta::new(ring.payer.pubkey(), true);
    spp[RING_DEPOSIT_RING_CONFIG_INDEX] = AccountMeta::new(ring_auth(), false);
    spp.extend([
        AccountMeta::new_readonly(Address::new_unique(), false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new(Address::new_unique(), false),
    ]);
    let mut accounts = vec![AccountMeta::new_readonly(policy_pda(), false)];
    accounts.extend(ring.registries(RootRead::deposit(&ring.read(&policy_pda())).unwrap()));
    accounts.extend(spp);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

#[test]
fn an_escrowing_deposit_revision_its_registry_does_not_serve_is_refused() {
    let mut ring = delegate_ring(&Keypair::new());
    refused(
        audited_deposit(&mut ring, Some(1)),
        CustomRingError::RootNotServed,
    );
    reaches_verification(audited_deposit(&mut ring, Some(0)));
}

#[test]
fn a_merge_and_a_deposit_carry_the_co_signer_their_class_demands() {
    let co_signer = Keypair::new();
    let with_co_signer = |mut instruction: Instruction, slot: usize| {
        let pair = CoSignerSlot::own(co_signer.pubkey()).signed();
        instruction.accounts.splice(slot..slot, pair);
        instruction
    };
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(
        &mut ring,
        &co_signer.pubkey(),
        CoSignScope::TRANSFERS.bits(),
    );
    let merge = merge_instruction(&ring, None);
    refused(
        ring.send(merge.clone(), &[]),
        CustomRingError::InvalidCoSignerRecord,
    );
    reaches_verification(ring.send(with_co_signer(merge, MERGE_SPP), &[&co_signer]));
    set_co_signer(&mut ring, &co_signer.pubkey(), CoSignScope::DEPOSITS.bits());
    let deposit = deposit_instruction(&ring, None, &ring_deposit());
    refused(
        ring.send(deposit.clone(), &[]),
        CustomRingError::InvalidCoSignerRecord,
    );
    reaches_verification(ring.send(with_co_signer(deposit, DEPOSIT_SPP), &[&co_signer]));
}

#[test]
fn an_audited_deposit_without_a_bound_root_reaches_its_proof() {
    let mut ring = Ring::new(Setup::AuditOnly);
    reaches_verification(audited_deposit(&mut ring, None));
}

#[test]
fn a_merge_naming_the_ring_pda_past_its_slot_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut instruction = merge_instruction(&ring, None);
    instruction
        .accounts
        .push(AccountMeta::new(ring_auth(), false));
    refused(
        ring.send(instruction, &[]),
        CustomRingError::RingAuthOutOfSlot,
    );
}

/// The merge's forwarded list starts after the ring account.
const MERGE_SPP: usize = 1;
/// The deposit's forwarded list starts after the ring account.
const DEPOSIT_SPP: usize = 1;

#[test]
fn a_merge_forward_holds_the_ring_pda_a_signing_payer_and_a_written_root() {
    let mut ring = Ring::new(Setup::AuditOnly);
    for (index, error) in [
        (
            RING_MERGE_RING_CONFIG_INDEX,
            CustomRingError::MissingRingAuth,
        ),
        (
            RING_MERGE_PAYER_INDEX,
            CustomRingError::MissingFundingSigner,
        ),
    ] {
        let mut instruction = merge_instruction(&ring, None);
        instruction.accounts[MERGE_SPP + index] = AccountMeta::new(Address::new_unique(), false);
        refused(ring.send(instruction, &[]), error);
    }
}

#[test]
fn a_forward_past_the_cpi_account_cap_is_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    ring.deploy_stand_in(SPP);
    let mut instruction = merge_instruction(&ring, None);
    instruction.accounts.extend(std::iter::repeat_n(
        AccountMeta::new_readonly(SPP, false),
        128,
    ));
    // The merge proof precedes the forward, the cap holds the forward alone.
    reaches_verification(ring.send(instruction, &[]));
}

#[test]
fn an_audited_deposit_forwards_deposit_data_its_capsules_open() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut untagged = deposit_instruction(&ring, None, &ring_deposit());
    untagged.data[core::mem::size_of::<DepositPrefix>()] =
        spr_interface::instruction::tag::RING_DEPOSIT.wrapping_add(1);
    refused(
        ring.send(untagged, &[]),
        CustomRingError::InvalidAuditedDeposit,
    );
    let mut truncated = deposit_instruction(&ring, None, &ring_deposit());
    truncated.data.pop();
    refused(
        ring.send(truncated, &[]),
        CustomRingError::InvalidDepositData,
    );
    let misplaced = deposit_instruction(
        &ring,
        None,
        &deposit_of(vec![deposit_entry(1, &auditor_pubkey())]),
    );
    refused(
        ring.send(misplaced, &[]),
        CustomRingError::InvalidDepositDisclosure,
    );
    let mut unhashable = ring_deposit();
    unhashable.deposits[0].owner_utxo_hash = [0xff; 32];
    let instruction = deposit_instruction(&ring, None, &unhashable);
    refused(ring.send(instruction, &[]), CustomRingError::HashingFailed);
}

#[test]
fn every_deposit_capsule_opens_under_one_key_at_its_own_index() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let key = auditor_pubkey();
    let mut other = key;
    other[1] ^= 1;
    let mut mistagged = key;
    mistagged[0] = 0x02;
    let mut bare = deposit_entry(1, &key);
    bare.encrypted.ciphertext[0] ^= 1;
    let mut send = |entries| {
        let instruction = deposit_instruction(&ring, None, &deposit_of(entries));
        ring.send(instruction, &[])
    };
    for refused_entries in [
        vec![deposit_entry(0, &key), deposit_entry(1, &other)],
        vec![deposit_entry(0, &key), deposit_entry(0, &key)],
        vec![deposit_entry(0, &key), bare],
        vec![deposit_entry(0, &mistagged)],
        Vec::new(),
        (0..=MAX_RING_DEPOSIT_AUDIT_SLOTS as u8)
            .map(|slot| deposit_entry(slot, &key))
            .collect(),
    ] {
        refused(
            send(refused_entries),
            CustomRingError::InvalidDepositDisclosure,
        );
    }
    reaches_verification(send(vec![deposit_entry(0, &key), deposit_entry(1, &key)]));
}

#[test]
fn an_audited_deposit_holds_the_ring_pda_and_a_signing_depositor() {
    let mut ring = Ring::new(Setup::AuditOnly);
    for (index, error) in [
        (
            RING_DEPOSIT_RING_CONFIG_INDEX,
            CustomRingError::MissingRingAuth,
        ),
        (
            RING_DEPOSIT_DEPOSITOR_INDEX,
            CustomRingError::MissingFundingSigner,
        ),
    ] {
        let mut instruction = deposit_instruction(&ring, None, &ring_deposit());
        instruction.accounts[DEPOSIT_SPP + index] = AccountMeta::new(Address::new_unique(), false);
        refused(ring.send(instruction, &[]), error);
    }
}
