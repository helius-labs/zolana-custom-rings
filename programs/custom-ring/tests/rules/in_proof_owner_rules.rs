//! The in-proof owner rail, a relayer pays and the owner signs inside the proof.

use custom_ring_interface::{
    tag, transact_flag, CustomRingError, DisclosureFormat, RingRail, SINGLE_ASSET_PAYOUT_INPUTS,
    SINGLE_ASSET_PAYOUT_OUTPUTS, TRANSFER_OUTPUT_CAPACITIES,
};
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
fn every_output_capacity_reaches_its_sender_key() {
    let fixture = Fixture::new();
    // Only the payout key holds this width and it refuses an in-proof owner.
    for outputs in TRANSFER_OUTPUT_CAPACITIES
        .into_iter()
        .filter(|outputs| *outputs != SINGLE_ASSET_PAYOUT_OUTPUTS)
    {
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
fn an_in_proof_owner_on_a_payout_frame_is_refused() {
    let fixture = Fixture::new().with_format(DisclosureFormat::SingleAssetPayout);
    let mut ring = Ring::new(Setup::AuditOnly);
    let data = fixture.transfer(
        RingRail::Confidential,
        SINGLE_ASSET_PAYOUT_INPUTS as u8,
        SINGLE_ASSET_PAYOUT_OUTPUTS as u8,
        false,
    );
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    let mut bytes = data.encode().unwrap();
    bytes[transact_flag::BYTE] |= transact_flag::OWNER_IN_PROOF;
    let spp_proof = bytes
        .windows(data.spp_proof.proof_a.len())
        .rposition(|window| window == data.spp_proof.proof_a)
        .unwrap();
    let owner_section = [OWNER, [0x44; 32], [0x45; 32]];
    bytes.splice(spp_proof..spp_proof, owner_section.into_iter().flatten());
    refused(
        send(&mut ring, tag::TRANSFER, Vec::new(), bytes, spp, &[]),
        CustomRingError::FlagNotAllowed,
    );
}
