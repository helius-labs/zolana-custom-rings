//! The in-proof owner rail, a relayer pays and the owner signs inside the proof.

use custom_ring_interface::{tag, TRANSFER_OUTPUT_CAPACITIES};
use solana_keypair::Signer;

use crate::{
    common::{reaches_verification, Ring, Setup},
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
fn every_output_capacity_reaches_its_sender_key() {
    let fixture = Fixture::new();
    for outputs in TRANSFER_OUTPUT_CAPACITIES {
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
