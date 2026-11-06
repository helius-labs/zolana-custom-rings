//! The pre-proof refusals an anonymous policy ring adds to the confidential rail.

use custom_ring_interface::{
    tag, CustomRingError, FramedSenderBundle, RingRail, RingTransactData, SlotBody,
    RECIPIENT_BODY_LEN,
};
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};

use crate::{
    common::{reaches_verification, refused, Ring, Sent, Setup},
    transact_rules::{send, spp_list, Fixture},
};

/// An anonymous policy transfer, `prefix` after the ring account, the payer signing.
fn transfer(ring: &mut Ring, prefix: Vec<AccountMeta>, data: &RingTransactData<'_>) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &[]);
    send(
        ring,
        tag::TRANSFER,
        prefix,
        data.encode().unwrap(),
        spp,
        &[],
    )
}

#[test]
fn an_anonymous_policy_transfer_passing_every_check_reaches_its_keys() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    reaches_verification(transfer(
        &mut ring,
        Vec::new(),
        &fixture.transfer(RingRail::Anonymous, 2, 2, true),
    ));
}

#[test]
fn an_anonymous_policy_transfer_takes_public_co_owners_in_the_run() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    let owner = Keypair::new();
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[&owner],
    ));
}

/// The program judges no tag, SPP's external data hash binds its bytes.
#[test]
fn an_anonymous_transfer_reaches_its_keys_under_any_canonical_tags() {
    let fixture = Fixture::new();
    let tags = [[0; 32], [0x2f; 32]];
    let body = [0x3c; RECIPIENT_BODY_LEN];
    for (setup, policy) in [(Setup::AnonymousPolicy, true), (Setup::Anonymous, false)] {
        let mut ring = Ring::new(setup);
        let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, policy);
        for (output, (tag, body)) in data.outputs.iter_mut().zip([
            (&tags[0], SlotBody::None),
            (&tags[1], SlotBody::Recipient(&body)),
        ]) {
            output.owner_tag = custom_ring_interface::stream::slot_tag(*tag);
            output.body = body;
        }
        data.sender = data.sender.map(|sender| FramedSenderBundle {
            tag: &tags[1],
            ..sender
        });
        fixture.fit_bundle(&mut data);
        let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
        reaches_verification(send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ));
    }
}

/// `m` and the bodiless count fix the bundle, a byte fewer shifts every later section.
#[test]
fn a_short_sender_bundle_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let sender = data.sender.unwrap();
    let mut compact = data.encode().unwrap();
    let body = compact
        .windows(32)
        .position(|window| window == sender.tag)
        .unwrap()
        + 32;
    compact.remove(body);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(&mut ring, tag::TRANSFER, Vec::new(), compact, spp, &[]),
        CustomRingError::RingTransactLength,
    );
}

#[test]
fn an_anonymous_policy_ring_refuses_a_confidential_transfer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    fixture.fit_stream(&mut data);
    let sent = transfer(&mut ring, Vec::new(), &data);
    assert!(
        sent.is_err(),
        "a confidential transfer reached an anonymous ring's keys"
    );
}
