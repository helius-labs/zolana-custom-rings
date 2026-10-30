//! Policy transfers read every root from the live registries they pass, each bound to the ring.

use custom_ring_interface::{
    storage::Revision, tag, CustomRingError, PolicyTableIxData, RingPolicy, RingRail, RingRole,
    RingTransactData, SourceSpec, UpdatePolicyIxData,
};
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};
use zolana_ring_policy::ListId;

use crate::{
    common::{
        allow_list_table, policy_pda, reaches_verification, refused, retired, root, transact, Ring,
        Sent, Setup, UpdatePolicyIx, RECORDS,
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
    data.policy.as_mut().unwrap().own_revision = Revision::from(1);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
    // A retired root verifies until its registry expiry.
    data.policy.as_mut().unwrap().own_revision = Revision::from(0);
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
fn update_policy_rebinds_the_records_to_another_registry_of_the_same_authority() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.holder(RingRole::Policy);
    let rebind = |records: Address| {
        UpdatePolicyIx {
            authority: authority.pubkey(),
            update: UpdatePolicyIxData::Records {
                storage_authority: Address::default(),
            },
            trailing: &[records],
        }
        .instruction()
    };
    let foreign = Address::new_from_array([0x5e; 32]);
    ring.store_registry(foreign, &Keypair::new().pubkey(), &[root(3, [0x0f; 32])]);
    refused(
        ring.send(rebind(foreign), &[&authority]),
        CustomRingError::StorageAuthorityMismatch,
    );
    let records = Address::new_from_array([0x5b; 32]);
    ring.store_registry(records, &authority.pubkey(), &[root(3, [0x0f; 32])]);
    let before: RingPolicy = ring.read(&policy_pda());
    ring.send(rebind(records), &[&authority]).unwrap();
    let after: RingPolicy = ring.read(&policy_pda());
    assert_eq!(after.records, records);
    assert_eq!(after.policy_hash, before.policy_hash);
    assert_eq!(after.generation(), before.generation() + 1);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().own_revision = Revision::from(3);
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::UnboundRegistry,
    );
    reaches_verification(transfer_reading(&mut ring, &[records], &data));
}
