//! The in-proof owner rail refuses any owner signer, a relayer alone pays and signs.

use custom_ring_interface::{tag, CustomRingError};
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
