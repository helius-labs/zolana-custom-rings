//! Every configuration path pairs each salted source of the account it would store with the ring's
//! tracking registry, and a refused write stores nothing.

use custom_ring_interface::{
    CustomRingError, InitializeIxData, PolicyBindingIxData, PolicySourceIxData, PolicyTableIxData,
    RingKind, RingPolicy, RingRole, SourceSpec, UpdatePolicyIxData,
};
use solana_address::Address;
use solana_keypair::{Keypair, Signer};
use zolana_ring_policy::{ListId, ListSet, Rule, Subject};

use crate::common::{
    auditor_pubkey, policy_pda, refused, ring_auth, root, tracking_registry, InitializeIx, Ring,
    Sent, Setup, UpdatePolicyIx, RECORDS,
};

const CURATOR: Address = Address::new_from_array([0x63; 32]);
const FOREIGN_TRACKING: Address = Address::new_from_array([0x64; 32]);
const UNPAIRED: Address = Address::new_from_array([0; 32]);

/// Requires every output owner on each list, `source` 0 reads the own records and 1 the curator.
fn table(lists: &[(ListId, u8)]) -> PolicyTableIxData {
    PolicyTableIxData {
        sources: lists
            .iter()
            .map(|&(list_id, source)| SourceSpec {
                list_id: list_id as u8,
                source,
            })
            .collect(),
        rules: lists
            .iter()
            .map(|&(list_id, _)| Rule::require(Subject::OutputOwner, list_id).encoded())
            .collect(),
    }
}

fn write(ring: &mut Ring, update: UpdatePolicyIxData, trailing: &[Address]) -> Sent {
    let authority = ring.holder(RingRole::Policy);
    let instruction = UpdatePolicyIx {
        authority: authority.pubkey(),
        update,
        trailing,
    }
    .instruction();
    ring.send(instruction, &[&authority])
}

/// Refused with `error`, the stored account unchanged.
fn refused_unchanged(
    ring: &mut Ring,
    sent: impl FnOnce(&mut Ring) -> Sent,
    error: CustomRingError,
) {
    let before: RingPolicy = ring.read(&policy_pda());
    refused(sent(ring), error);
    let after: RingPolicy = ring.read(&policy_pda());
    assert_eq!(after, before);
}

/// A curator registry of another authority, pinned to `tracking`.
fn curator(ring: &mut Ring, tracking: Address) {
    ring.store_registry(CURATOR, &Keypair::new().pubkey(), &[root(4, [0x0c; 32])]);
    ring.pair_registry(CURATOR, tracking, 0);
}

/// A policy ring reading the private allow list from its paired records.
fn salted_ring() -> Ring {
    let mut ring = Ring::new(Setup::Policy);
    let rules = table(&[(ListId::Allow, 0), (ListId::PrivateAllow, 0)]);
    write(&mut ring, UpdatePolicyIxData::Rules(rules), &[RECORDS]).expect("paired records");
    ring
}

fn initialize(ring: &mut Ring, lists: &[(ListId, u8)], curators: &[Address]) -> Sent {
    for account in [policy_pda(), ring_auth(), tracking_registry()] {
        ring.drain(&account);
    }
    let authority = ring.authority.insecure_clone();
    let instruction = InitializeIx {
        payer: ring.payer.pubkey(),
        authority: authority.pubkey(),
        data: InitializeIxData {
            auditor_pubkey: auditor_pubkey(),
            kind: RingKind::Policy,
            roles: ring.roles.addresses(),
            policy: Some(PolicyBindingIxData {
                table: table(lists),
            }),
        },
        curators,
    }
    .instruction();
    ring.send(instruction, &[&authority])
}

#[test]
fn initialize_stores_a_salted_source_only_when_it_pairs_with_the_ring() {
    let own = [(ListId::PrivateAllow, 0)];
    let curated = [(ListId::PrivateAllow, 1)];
    for pair in [UNPAIRED, FOREIGN_TRACKING] {
        let mut ring = Ring::new(Setup::Policy);
        ring.pair_registry(RECORDS, pair, 0);
        refused(
            initialize(&mut ring, &own, &[]),
            CustomRingError::SaltedSourceOtherTracking,
        );
        assert_eq!(ring.lamports(&policy_pda()), 0);
        curator(&mut ring, pair);
        refused(
            initialize(&mut ring, &curated, &[CURATOR]),
            CustomRingError::SaltedSourceOtherTracking,
        );
        assert_eq!(ring.lamports(&policy_pda()), 0);
    }
    let mut ring = Ring::new(Setup::Policy);
    initialize(&mut ring, &own, &[]).expect("paired records");
    curator(&mut ring, tracking_registry());
    initialize(&mut ring, &curated, &[CURATOR]).expect("paired curator");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.salted_registries(), vec![CURATOR]);
}

#[test]
fn a_rule_change_enabling_a_salted_read_pairs_its_source_first() {
    let mut ring = Ring::new(Setup::Policy);
    let own = || UpdatePolicyIxData::Rules(table(&[(ListId::PrivateAllow, 0)]));
    refused_unchanged(
        &mut ring,
        |ring| write(ring, own(), &[]),
        CustomRingError::MissingRegistry,
    );
    for pair in [UNPAIRED, FOREIGN_TRACKING] {
        ring.pair_registry(RECORDS, pair, 0);
        refused_unchanged(
            &mut ring,
            |ring| write(ring, own(), &[RECORDS]),
            CustomRingError::SaltedSourceOtherTracking,
        );
    }
    let curated = || UpdatePolicyIxData::Rules(table(&[(ListId::PrivateAllow, 1)]));
    for pair in [UNPAIRED, FOREIGN_TRACKING] {
        curator(&mut ring, pair);
        refused_unchanged(
            &mut ring,
            |ring| write(ring, curated(), &[CURATOR]),
            CustomRingError::SaltedSourceOtherTracking,
        );
    }
    ring.pair_registry(RECORDS, tracking_registry(), 0);
    write(&mut ring, own(), &[RECORDS]).expect("paired records");
    curator(&mut ring, tracking_registry());
    write(&mut ring, curated(), &[CURATOR]).expect("paired curator");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.salted(), ListSet::single(ListId::PrivateAllow));
}

#[test]
fn an_unpaired_curator_serves_a_public_list_and_no_salted_one() {
    let mut ring = Ring::new(Setup::Policy);
    curator(&mut ring, UNPAIRED);
    let public = table(&[(ListId::Allow, 1)]);
    write(&mut ring, UpdatePolicyIxData::Rules(public), &[CURATOR]).expect("public curator");
    let salted = table(&[(ListId::Allow, 1), (ListId::PrivateAllow, 1)]);
    refused_unchanged(
        &mut ring,
        |ring| write(ring, UpdatePolicyIxData::Rules(salted), &[CURATOR, RECORDS]),
        CustomRingError::SaltedSourceOtherTracking,
    );
}

#[test]
fn a_source_move_pairs_the_salted_source_it_sets() {
    let mut ring = salted_ring();
    let move_private = |source| {
        UpdatePolicyIxData::Source(PolicySourceIxData {
            list_id: ListId::PrivateAllow as u8,
            source,
        })
    };
    for pair in [UNPAIRED, FOREIGN_TRACKING] {
        curator(&mut ring, pair);
        refused_unchanged(
            &mut ring,
            |ring| write(ring, move_private(1), &[CURATOR]),
            CustomRingError::SaltedSourceOtherTracking,
        );
    }
    curator(&mut ring, tracking_registry());
    write(&mut ring, move_private(1), &[CURATOR]).expect("paired curator");
    refused_unchanged(
        &mut ring,
        |ring| write(ring, move_private(0), &[]),
        CustomRingError::MissingRegistry,
    );
    write(&mut ring, move_private(0), &[RECORDS]).expect("paired records");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.salted_registries(), vec![RECORDS]);
}

#[test]
fn a_public_source_move_passes_the_salted_source_it_keeps() {
    let mut ring = salted_ring();
    curator(&mut ring, UNPAIRED);
    let move_allow = || {
        UpdatePolicyIxData::Source(PolicySourceIxData {
            list_id: ListId::Allow as u8,
            source: 1,
        })
    };
    refused_unchanged(
        &mut ring,
        |ring| write(ring, move_allow(), &[CURATOR]),
        CustomRingError::MissingRegistry,
    );
    write(&mut ring, move_allow(), &[CURATOR, RECORDS]).expect("the kept records pair");
}

#[test]
fn a_records_rebind_under_a_salted_list_pairs_the_new_records() {
    let mut ring = salted_ring();
    let records = Address::new_from_array([0x65; 32]);
    let policy = ring.roles.policy.pubkey();
    ring.store_registry(records, &policy, &[root(0, [0x0e; 32])]);
    for pair in [UNPAIRED, FOREIGN_TRACKING] {
        ring.pair_registry(records, pair, 0);
        refused_unchanged(
            &mut ring,
            |ring| write(ring, UpdatePolicyIxData::Records, &[records]),
            CustomRingError::SaltedSourceOtherTracking,
        );
    }
    ring.pair_registry(records, tracking_registry(), 0);
    write(&mut ring, UpdatePolicyIxData::Records, &[records]).expect("paired records");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.records, records);
}
