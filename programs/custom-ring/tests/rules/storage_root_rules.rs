//! Policy transfers read every root from the policy's mirrors, refused until `SyncRoots` copies it.

use custom_ring_interface::{
    storage::Revision, CustomRingError, PolicyTableIxData, RingPolicy, RingRail, SourceSpec,
    UpdatePolicyIxData,
};
use solana_address::Address;
use solana_keypair::{Keypair, Signer};
use zolana_ring_policy::ListId;

use crate::{
    common::{
        allow_list_table, policy_pda, reaches_verification, refused, retired, root, sync_roots,
        Ring, Setup, UpdatePolicyIx, RECORDS,
    },
    transact_rules::{confidential, policy_meta, Fixture},
};

const CURATOR: Address = Address::new_from_array([0x5c; 32]);

#[test]
fn a_policy_transfer_proves_under_a_synced_storage_root() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.pubkey();
    ring.store_registry(
        RECORDS,
        &authority,
        &[root(1, [0x0d; 32]), retired(0, [0x0e; 32], 1_000)],
    );
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    let policy = data.policy.as_mut().unwrap();
    policy.own_revision = Revision::from(1);
    // The mirror holds revision 0 alone until the writer syncs.
    refused(
        confidential(&mut ring, vec![policy_meta()], &data),
        CustomRingError::MirrorRootExpired,
    );
    ring.send(sync_roots(&RECORDS), &[]).unwrap();
    reaches_verification(confidential(&mut ring, vec![policy_meta()], &data));
    // A retired root keeps its registry expiry in the mirror.
    data.policy.as_mut().unwrap().own_revision = Revision::from(0);
    ring.warp(999);
    reaches_verification(confidential(&mut ring, vec![policy_meta()], &data));
    ring.warp(1_000);
    refused(
        confidential(&mut ring, vec![policy_meta()], &data),
        CustomRingError::MirrorRootExpired,
    );
}

#[test]
fn a_curator_registry_of_another_authority_serves_a_list_after_sync_roots() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.insecure_clone();
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
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    refused(
        confidential(&mut ring, vec![policy_meta()], &data),
        CustomRingError::MirrorNotSynced,
    );
    // Only the records and the curator source have a mirror.
    let stranger = Address::new_from_array([0x5d; 32]);
    ring.store_registry(stranger, &authority.pubkey(), &[root(4, [0x0c; 32])]);
    refused(
        ring.send(sync_roots(&stranger), &[]),
        CustomRingError::UnmirroredRegistry,
    );
    ring.send(sync_roots(&CURATOR), &[]).unwrap();
    reaches_verification(confidential(&mut ring, vec![policy_meta()], &data));
}

#[test]
fn update_policy_rebinds_the_records_to_another_registry_of_the_same_authority() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.insecure_clone();
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
    // The old registry's mirror no longer serves a proof over an own list.
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().own_revision = Revision::from(3);
    refused(
        confidential(&mut ring, vec![policy_meta()], &data),
        CustomRingError::MirrorNotSynced,
    );
    refused(
        ring.send(sync_roots(&RECORDS), &[]),
        CustomRingError::UnmirroredRegistry,
    );
    ring.send(sync_roots(&records), &[]).unwrap();
    reaches_verification(confidential(&mut ring, vec![policy_meta()], &data));
}
