//! Policy transfers read every root from the live registries they pass, each bound to the ring.

use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    storage_instruction::InitializeTrackingIxData,
    tag,
    tracking::TrackingRegistry,
    CustomRingError, PolicyTableIxData, RingPolicy, RingRail, RingRole, RingTransactData,
    SourceSpec, UpdatePolicyIxData, STORAGE_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};
use zolana_ring_policy::{ring_id_field, ListId, ListSet};

use crate::{
    common::{
        allow_list_table, auditor_pubkey, list_table, policy_pda, reaches_verification, refused,
        retired, root, tracking_registry, transact, Ring, Sent, Setup, UpdatePolicyIx, PROGRAM,
        RECORDS,
    },
    transact_rules::{spp_list, Fixture},
};

const CURATOR: Address = Address::new_from_array([0x5c; 32]);

/// A confidential transfer from the payer naming `registries` after the ring account.
fn transfer_reading(ring: &mut Ring, registries: &[Address], data: &RingTransactData<'_>) -> Sent {
    let owner = [AccountMeta::new_readonly(ring.payer.pubkey(), true)];
    let accounts = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        registries
            .iter()
            .chain(&[tracking_registry()])
            .map(|registry| AccountMeta::new_readonly(*registry, false))
            .collect(),
        spp_list(&ring.payer.pubkey(), data, &owner),
    ]
    .concat();
    ring.send(
        transact(tag::TRANSFER, accounts, data.encode().unwrap()),
        &[],
    )
}

/// A policy ring whose allow list the `CURATOR` registry of another authority serves at revision 4.
fn subscriber_ring() -> Ring {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.holder(RingRole::Policy);
    ring.store_registry(CURATOR, &Keypair::new().pubkey(), &[root(4, [0x0c; 32])]);
    let curated = PolicyTableIxData {
        sources: vec![SourceSpec {
            list_id: ListId::Allow as u8,
            source: 1,
        }],
        ..allow_list_table(Vec::new())
    };
    ring.send(
        UpdatePolicyIx {
            authority: authority.pubkey(),
            update: UpdatePolicyIxData::Rules(curated),
            trailing: &[CURATOR],
        }
        .instruction(),
        &[&authority],
    )
    .unwrap();
    ring
}

#[test]
fn a_policy_transfer_proves_under_a_live_storage_root() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let policy_key = ring.roles.policy.pubkey();
    ring.store_registry(
        RECORDS,
        &policy_key,
        &[root(1, [0x0d; 32]), retired(0, [0x0e; 32], 1_000)],
    );
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.own_revision = Some(Revision::from(1));
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
    // A retired root verifies until its registry expiry.
    data.own_revision = Some(Revision::from(0));
    ring.warp(999);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
    ring.warp(1_000);
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::RootNotServed,
    );
}

#[test]
fn a_curator_revocation_refuses_the_next_subscriber_transfer() {
    let fixture = Fixture::new();
    let mut ring = subscriber_ring();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    reaches_verification(transfer_reading(&mut ring, &[RECORDS, CURATOR], &data));
    ring.apply_immediate(CURATOR, [0x0b; 32]);
    refused(
        transfer_reading(&mut ring, &[RECORDS, CURATOR], &data),
        CustomRingError::RootNotServed,
    );
}

#[test]
fn a_registry_the_ring_does_not_bind_is_refused() {
    let fixture = Fixture::new();
    let mut ring = subscriber_ring();
    let stranger = Address::new_from_array([0x5d; 32]);
    ring.store_registry(stranger, &Keypair::new().pubkey(), &[root(4, [0x0c; 32])]);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    for registries in [[stranger, CURATOR], [RECORDS, stranger], [CURATOR, RECORDS]] {
        refused(
            transfer_reading(&mut ring, &registries, &data),
            CustomRingError::UnboundRegistry,
        );
    }
}

#[test]
fn update_policy_rebinds_the_records_to_a_registry_of_any_authority() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.holder(RingRole::Policy);
    let rebind = |records: Address| {
        UpdatePolicyIx {
            authority: authority.pubkey(),
            update: UpdatePolicyIxData::Records,
            trailing: &[records],
        }
        .instruction()
    };
    refused(
        ring.send(rebind(policy_pda()), &[&authority]),
        CustomRingError::InvalidStorageRegistry,
    );
    let records = Address::new_from_array([0x5b; 32]);
    ring.store_registry(records, &Keypair::new().pubkey(), &[root(3, [0x0f; 32])]);
    let before: RingPolicy = ring.read(&policy_pda());
    ring.send(rebind(records), &[&authority]).unwrap();
    let after: RingPolicy = ring.read(&policy_pda());
    assert_eq!(after.records, records);
    assert_eq!(after.policy_hash, before.policy_hash);
    assert_eq!(after.generation(), before.generation() + 1);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.own_revision = Some(Revision::from(3));
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::UnboundRegistry,
    );
    reaches_verification(transfer_reading(&mut ring, &[records], &data));
}

/// Valid but for its address.
fn forged_tracking() -> Vec<u8> {
    let registry = TrackingRegistry::new(&InitializeTrackingIxData {
        ring_id: ring_id_field(PROGRAM.as_array()).unwrap(),
        auditor_pubkey: auditor_pubkey(),
    });
    bytemuck::bytes_of(&registry).to_vec()
}

#[test]
fn a_forged_tracking_registry_with_a_matching_ring_id_and_an_empty_root_fails_at_load() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let forged = Address::new_from_array([0x5e; 32]);
    ring.store(forged, STORAGE_PROGRAM_ID, forged_tracking());
    let pinned: TrackingRegistry = ring.read(&tracking_registry());
    let copy: TrackingRegistry = ring.read(&forged);
    assert_eq!(copy.ring_id, pinned.ring_id);
    assert_eq!(copy.roots[0].hash, pinned.roots[0].hash);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    let owner = [AccountMeta::new_readonly(ring.payer.pubkey(), true)];
    let reading = |tracking: Address, ring: &mut Ring| {
        let accounts = [
            vec![
                AccountMeta::new_readonly(policy_pda(), false),
                AccountMeta::new_readonly(RECORDS, false),
                AccountMeta::new_readonly(tracking, false),
            ],
            spp_list(&ring.payer.pubkey(), &data, &owner),
        ]
        .concat();
        ring.send(
            transact(tag::TRANSFER, accounts, data.encode().unwrap()),
            &[],
        )
    };
    refused(reading(forged, &mut ring), CustomRingError::UnboundRegistry);
    reaches_verification(reading(tracking_registry(), &mut ring));
}

/// Configures a private allow list on the paired records, then pins `pair` and `floor` as a read finds them.
fn read_private_allow_list(ring: &mut Ring, pair: Address, floor: u64) {
    let authority = ring.holder(RingRole::Policy);
    let update = UpdatePolicyIx {
        authority: authority.pubkey(),
        update: UpdatePolicyIxData::Rules(list_table(ListId::PrivateAllow, Vec::new())),
        trailing: &[RECORDS],
    }
    .instruction();
    ring.send(update, &[&authority]).unwrap();
    pin_records(ring, pair, floor);
}

fn pin_records(ring: &mut Ring, pair: Address, floor: u64) {
    pin_registry(ring, RECORDS, pair, floor);
}

fn pin_registry(ring: &mut Ring, address: Address, pair: Address, floor: u64) {
    let mut records: StorageRegistry = ring.read(&address);
    records.tracking_registry = pair;
    records.tracking_floor = Revision::from(floor);
    ring.store(
        address,
        STORAGE_PROGRAM_ID,
        bytemuck::bytes_of(&records).to_vec(),
    );
}

fn store_tracking_history(ring: &mut Ring) {
    let mut tracking: TrackingRegistry = ring.read(&tracking_registry());
    tracking.roots[0] = root(3, [0x09; 32]);
    tracking.roots[1] = retired(2, [0x08; 32], u64::MAX);
    ring.store(
        tracking_registry(),
        STORAGE_PROGRAM_ID,
        bytemuck::bytes_of(&tracking).to_vec(),
    );
}

#[test]
fn a_salted_list_reads_its_own_source_under_the_tracking_pin() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    read_private_allow_list(&mut ring, Address::default(), 0);
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.salted(), ListSet::single(ListId::PrivateAllow));
    for unpaired in [Address::default(), Address::new_from_array([0x61; 32])] {
        pin_records(&mut ring, unpaired, 0);
        refused(
            transfer_reading(&mut ring, &[RECORDS], &data),
            CustomRingError::SaltedSourceOtherTracking,
        );
    }
    pin_records(&mut ring, tracking_registry(), 0);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
}

#[test]
fn an_unpaired_private_source_cannot_name_an_old_tracking_root() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    store_tracking_history(&mut ring);
    read_private_allow_list(&mut ring, Address::default(), 0);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.tracking_revision = Revision::from(2);
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::SaltedSourceOtherTracking,
    );
    pin_records(&mut ring, tracking_registry(), 3);
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::TrackingRootBelowFloor,
    );
}

#[test]
fn a_curated_public_ring_reads_a_curator_pinned_to_its_own_tracking_registry() {
    let fixture = Fixture::new();
    let mut ring = subscriber_ring();
    store_tracking_history(&mut ring);
    pin_registry(
        &mut ring,
        CURATOR,
        Address::new_from_array([0x61; 32]),
        u64::MAX,
    );
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    data.tracking_revision = Revision::from(2);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS, CURATOR], &data));
}

#[test]
fn a_private_list_mapped_to_a_curator_on_another_tracking_registry_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.holder(RingRole::Policy);
    ring.store_registry(CURATOR, &Keypair::new().pubkey(), &[root(4, [0x0c; 32])]);
    pin_registry(&mut ring, CURATOR, tracking_registry(), 0);
    let curated = PolicyTableIxData {
        sources: vec![SourceSpec {
            list_id: ListId::PrivateAllow as u8,
            source: 1,
        }],
        ..list_table(ListId::PrivateAllow, Vec::new())
    };
    ring.send(
        UpdatePolicyIx {
            authority: authority.pubkey(),
            update: UpdatePolicyIxData::Rules(curated),
            trailing: &[CURATOR],
        }
        .instruction(),
        &[&authority],
    )
    .unwrap();
    pin_registry(&mut ring, CURATOR, Address::new_from_array([0x61; 32]), 0);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    refused(
        transfer_reading(&mut ring, &[RECORDS, CURATOR], &data),
        CustomRingError::SaltedSourceOtherTracking,
    );
    pin_registry(&mut ring, CURATOR, tracking_registry(), 0);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS, CURATOR], &data));
}

#[test]
fn a_ring_with_no_salted_list_answers_to_no_floor_of_its_pinned_records() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    store_tracking_history(&mut ring);
    pin_records(&mut ring, tracking_registry(), 3);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.tracking_revision = Revision::from(2);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
}

#[test]
fn a_tracking_root_below_the_salted_floor_is_refused_at_load() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    store_tracking_history(&mut ring);
    read_private_allow_list(&mut ring, tracking_registry(), 3);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.tracking_revision = Revision::from(2);
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::TrackingRootBelowFloor,
    );
    data.tracking_revision = Revision::from(3);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
    pin_records(&mut ring, tracking_registry(), 2);
    data.tracking_revision = Revision::from(2);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
}
