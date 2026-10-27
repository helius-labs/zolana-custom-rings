//! The floor and grace a published root sets, ahead of the policy proof.

use custom_ring_interface::{
    CustomRingError, MemberRegistry, PolicyProof, RingRail, OWN_GRACE_SLOTS,
};
use solana_keypair::Signer;

use crate::common::{publish_root, reaches_verification, refused, registry_pda, Ring, Sent, Setup};
use crate::transact_rules::{confidential, registry_meta, Fixture};

fn publish(ring: &mut Ring, root: [u8; 32]) {
    let authority = ring.authority.insecure_clone();
    ring.send(publish_root(&authority.pubkey(), root), &[&authority])
        .expect("the authority publishes");
}

/// A policy transfer bound to history slot `index`.
fn transfer_under(ring: &mut Ring, fixture: &Fixture, index: u8) -> Sent {
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy = data.policy.map(|policy| PolicyProof {
        own_root_index: index,
        ..policy
    });
    confidential(ring, vec![registry_meta()], &data)
}

#[test]
fn a_published_root_binds_the_next_transfer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    // 1. One instruction moves the registry to the root, history slot 1 at the floor.
    publish(&mut ring, [7; 32]);
    let registry: MemberRegistry = ring.read(&registry_pda());
    assert_eq!((registry.current_root(), registry.floor()), ([7; 32], 1));
    // 2. A transfer under that slot passes every check up to the proof.
    reaches_verification(transfer_under(&mut ring, &fixture, 1));
}

#[test]
fn a_second_publish_in_the_grace_refuses_roots_below_the_first_floor_at_once() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    // 1. Two publishes inside one grace window.
    publish(&mut ring, [1; 32]);
    publish(&mut ring, [2; 32]);
    let raised_at = ring.read::<MemberRegistry>(&registry_pda()).floor_slot();
    // 2. The sentinel root sits below the first floor, stale at once.
    refused(
        transfer_under(&mut ring, &fixture, 0),
        CustomRingError::RootBelowFloor,
    );
    // 3. The first published root lives exactly through the grace.
    ring.warp(raised_at + OWN_GRACE_SLOTS - 1);
    reaches_verification(transfer_under(&mut ring, &fixture, 1));
    ring.warp(raised_at + OWN_GRACE_SLOTS);
    refused(
        transfer_under(&mut ring, &fixture, 1),
        CustomRingError::RootBelowFloor,
    );
}
