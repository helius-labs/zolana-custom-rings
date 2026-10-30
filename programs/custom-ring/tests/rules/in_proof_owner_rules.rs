//! The in-proof owner rail refuses any owner signer, a relayer alone pays and signs.

use custom_ring_interface::{tag, CustomRingError, DELIVERED_AUDIT_CAPACITIES};
use solana_instruction::AccountMeta;
use solana_keypair::Signer;

use crate::{
    common::{reaches_verification, refused, Ring, Setup},
    transact_rules::{send, spp_list, Fixture},
};

const OWNER: [u8; 32] = [0x71; 32];

#[test]
fn a_relayer_pays_a_policy_transfer_its_owner_signs_in_the_proof() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let data = fixture.in_proof_owner(&OWNER, 2, 2, true);
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

#[test]
fn a_relayer_pays_an_audit_only_transfer_its_owner_signs_in_the_proof() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.in_proof_owner(&OWNER, 2, 2, false);
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

#[test]
fn every_delivered_capacity_reaches_its_sender_key() {
    let fixture = Fixture::new();
    for outputs in DELIVERED_AUDIT_CAPACITIES {
        let mut ring = Ring::new(Setup::AuditOnly);
        let data = fixture.in_proof_owner(&OWNER, 1, outputs as u8, false);
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

#[test]
fn an_owner_signer_beside_the_in_proof_owner_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let data = fixture.in_proof_owner(&OWNER, 2, 2, true);
    // The signer's inputs would spend under the policy sender the proof names.
    let signer = [AccountMeta::new_readonly(ring.payer.pubkey(), true)];
    let spp = spp_list(&ring.payer.pubkey(), &data, &signer);
    refused(
        send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ),
        CustomRingError::OwnerSignerOnInProofRail,
    );
}
