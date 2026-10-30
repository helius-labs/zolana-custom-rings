//! The pre-proof refusals an anonymous policy ring adds to the confidential rail.

use custom_ring_interface::{
    tag, CustomRingError, RingOutput, RingRail, RingTransactData, SenderBundle,
};
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};

use crate::{
    common::{key_registration, reaches_verification, refused, register_key, Ring, Sent, Setup},
    forward_rules::{
        deposit_instruction, merge_data, merge_disclosure, merge_instruction_with, ring_deposit,
    },
    transact_rules::{registry_meta, send, spp_list, Fixture},
};

/// An anonymous policy transfer, `prefix` after the registry, the payer its only signer.
fn transfer(ring: &mut Ring, prefix: Vec<AccountMeta>, data: &RingTransactData<'_>) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &[]);
    let prefix = [vec![registry_meta()], prefix].concat();
    send(
        ring,
        tag::TRANSACT,
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
fn an_anonymous_policy_transfer_takes_no_signer_but_the_payer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    let owner = Keypair::new();
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    refused(
        send(
            &mut ring,
            tag::TRANSACT,
            vec![registry_meta()],
            data.encode().unwrap(),
            spp,
            &[&owner],
        ),
        CustomRingError::InvalidAnonymousSigner,
    );
}

/// The audit proof binds no tag and no body.
#[test]
fn an_anonymous_transfer_reaches_its_keys_under_any_tags_and_bodies() {
    let fixture = Fixture::new();
    let tags = [[0; 32], [0xff; 32]];
    let body = [0x3c; 300];
    for (setup, policy) in [(Setup::AnonymousPolicy, true), (Setup::Anonymous, false)] {
        let mut ring = Ring::new(setup);
        let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, policy);
        for (output, (tag, body)) in data
            .outputs
            .iter_mut()
            .zip([(&tags[0], None), (&tags[1], Some(&body[..1]))])
        {
            let RingOutput::Anonymous { hash, .. } = *output else {
                panic!("an anonymous transfer publishes anonymous slots");
            };
            *output = RingOutput::Anonymous { hash, tag, body };
        }
        data.sender = Some(SenderBundle {
            tag: &tags[1],
            body: &body,
        });
        let prefix = match policy {
            true => vec![registry_meta()],
            false => Vec::new(),
        };
        let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
        reaches_verification(send(
            &mut ring,
            tag::TRANSACT,
            prefix,
            data.encode().unwrap(),
            spp,
            &[],
        ));
    }
}

/// A change output carries no body, the sender bundle always one.
#[test]
fn an_empty_sender_bundle_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let sender = data.sender.unwrap();
    let mut compact = data.encode().unwrap();
    let len = compact
        .windows(32)
        .position(|window| window == sender.tag)
        .unwrap()
        + 32;
    compact[len..len + 2].copy_from_slice(&0u16.to_le_bytes());
    compact.drain(len + 2..len + 2 + sender.body.len());
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(&mut ring, tag::TRANSACT, Vec::new(), compact, spp, &[]),
        CustomRingError::AnonymousBodyLength,
    );
}

#[test]
fn an_anonymous_policy_ring_escrows_no_key() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    data.key_escrow = true;
    fixture.disclose(&mut data);
    refused(
        transfer(&mut ring, Vec::new(), &data),
        CustomRingError::FlagNotAllowed,
    );
    let member = Keypair::new();
    let registration = register_key(&member.pubkey(), &key_registration(), None);
    refused(
        ring.send(registration, &[&member]),
        CustomRingError::AnonymousRingRefused,
    );
}

#[test]
fn an_anonymous_policy_ring_refuses_the_delegate_rail() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let delegate = Keypair::new();
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::DELEGATE_TRANSACT,
            vec![
                registry_meta(),
                AccountMeta::new_readonly(delegate.pubkey(), true),
            ],
            data.encode().unwrap(),
            spp,
            &[&delegate],
        ),
        CustomRingError::AnonymousRingRefused,
    );
}

#[test]
fn an_anonymous_policy_merge_discloses_its_owner_to_the_auditor_alone() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut merge = |data| {
        let instruction = merge_instruction_with(&ring, None, &data);
        ring.send(instruction, &[])
    };
    let disclosed = |registry, inputs| {
        let mut data = merge_data(registry, inputs);
        data.output_ring_data_hash = [0; 32];
        data.disclosure = Some(merge_disclosure(inputs));
        data
    };
    refused(
        merge(merge_data(None, 8)),
        CustomRingError::MissingMergeDisclosure,
    );
    refused(
        merge(disclosed(Some(1), 8)),
        CustomRingError::UnexpectedMemberRegistryRoot,
    );
    let mut narrow = disclosed(None, 8);
    narrow.disclosure.as_mut().unwrap().fields.pop();
    refused(merge(narrow), CustomRingError::MergeDisclosureWidth);
    let mut untagged = disclosed(None, 8);
    untagged.disclosure.as_mut().unwrap().eph_pk[0] = 0;
    refused(merge(untagged), CustomRingError::InvalidMergeDisclosure);
    refused(
        merge(disclosed(None, 25)),
        CustomRingError::UnsupportedCircuit,
    );
    let mut ring_data = disclosed(None, 8);
    ring_data.output_ring_data_hash = [8; 32];
    refused(merge(ring_data), CustomRingError::AnonymousRingDataNotZero);
    reaches_verification(merge(disclosed(None, 8)));
}

#[test]
fn an_anonymous_policy_deposit_names_no_recipient() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut named = ring_deposit();
    named.deposits[0].ring_data_hash = [1; 32];
    let instruction = deposit_instruction(&ring, None, &named);
    refused(
        ring.send(instruction, &[]),
        CustomRingError::AnonymousRingDataNotZero,
    );
    let instruction = deposit_instruction(&ring, Some(1), &ring_deposit());
    refused(
        ring.send(instruction, &[]),
        CustomRingError::UnexpectedMemberRegistryRoot,
    );
    let instruction = deposit_instruction(&ring, None, &ring_deposit());
    reaches_verification(ring.send(instruction, &[]));
}

#[test]
fn an_anonymous_policy_ring_refuses_a_confidential_transfer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    fixture.disclose(&mut data);
    let sent = transfer(&mut ring, Vec::new(), &data);
    assert!(
        sent.is_err(),
        "a confidential transfer reached an anonymous ring's keys"
    );
}
