use custom_ring_interface::{tracking::TrackingAuthorization, STORAGE_PROGRAM_ID};
use solana_address::Address;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{random_blinding, NullifierKey, PublicKey, ShieldedAddress, X25519Keypair};
use spr_transaction::{Data, Mint, Utxo, WalletUtxo};
use zolana_ring_client::NullifierKeyEnvelope;

use super::{AllowedNullifiers, DelegateSourceError, ResolvedSource, TrackingEnrollment};
use crate::tests::support::{
    account, auditor, keypair, program, ring_utxo, wallet, Chain, TRACKING, TREE_ID,
};

fn enrollment<'a>(chain: &'a Chain, auditor: &'a X25519Keypair) -> TrackingEnrollment<'a, Chain> {
    TrackingEnrollment {
        rpc: chain,
        tracking_registry: TRACKING,
        auditor,
    }
}

/// `owner`'s tracking authorization sealing `key` to the ring auditor.
fn enrolled(owner: Address, key: &NullifierKey) -> Chain {
    let envelope = NullifierKeyEnvelope::new(key, &[0; 32], &auditor().pubkey()).unwrap();
    let authorization = TrackingAuthorization {
        discriminator: TrackingAuthorization::DISCRIMINATOR,
        registry: TRACKING,
        owner,
        nullifier_pk: envelope.nullifier_pk,
        list_tag: [0; 32],
        viewing_u: [0; 32],
        eph_u: envelope.sealed.eph_pk.u(),
        ciphertext: envelope.sealed.ciphertext,
        applied: 1,
    };
    Chain::default().with(
        TrackingAuthorization::find_address(&TRACKING, &owner).0,
        account(STORAGE_PROGRAM_ID, &authorization),
    )
}

#[tokio::test]
async fn a_zero_key_pda_source_moves_with_no_enrollment() {
    let pda = Address::new_from_array([9; 32]);
    let source = ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(&pda),
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        viewing_pubkey: X25519Keypair::new().pubkey(),
    };
    let (chain, auditor) = (Chain::default(), auditor());

    let resolved = ResolvedSource::resolve(source, &enrollment(&chain, &auditor))
        .await
        .unwrap();

    assert_eq!(*resolved.nullifier_key().secret(), [0; 31]);
    let note = Utxo {
        owner: source.signing_pubkey,
        asset: Mint::SOL,
        amount: 5,
        blinding: random_blinding(),
        ring_program_id: Some(program()),
        data: Data::default(),
    };
    resolved
        .check_notes(&[wallet(note, resolved.nullifier_key(), TREE_ID, 0)])
        .unwrap();
}

#[tokio::test]
async fn a_nonzero_source_spends_under_its_enrolled_key() {
    let owner = keypair(11);
    let source = owner.shielded_address().unwrap();
    let (chain, auditor) = (
        enrolled(source.solana_address().unwrap(), &owner.nullifier_key),
        auditor(),
    );

    let resolved = ResolvedSource::resolve(source, &enrollment(&chain, &auditor))
        .await
        .unwrap();

    assert_eq!(
        resolved.nullifier_key().secret(),
        owner.nullifier_key.secret()
    );
    resolved
        .check_notes(&[ring_utxo(&owner, Mint::SOL, 5, 0)])
        .unwrap();
}

#[tokio::test]
async fn an_unenrolled_nonzero_source_is_refused() {
    let source = keypair(12).shielded_address().unwrap();
    let (chain, auditor) = (Chain::default(), auditor());

    let refused = ResolvedSource::resolve(source, &enrollment(&chain, &auditor)).await;

    assert!(matches!(refused, Err(DelegateSourceError::Unenrolled)));
}

#[tokio::test]
async fn an_enrollment_under_another_key_is_refused() {
    let source = keypair(13).shielded_address().unwrap();
    let other = NullifierKey::from_secret([14; 31]);
    let (chain, auditor) = (
        enrolled(source.solana_address().unwrap(), &other),
        auditor(),
    );

    let refused = ResolvedSource::resolve(source, &enrollment(&chain, &auditor)).await;

    assert!(matches!(refused, Err(DelegateSourceError::KeyMismatch)));
}

#[tokio::test]
async fn a_recovered_note_of_another_owner_is_refused() {
    let (owner, stranger) = (keypair(15), keypair(16));
    let source = owner.shielded_address().unwrap();
    let (chain, auditor) = (
        enrolled(source.solana_address().unwrap(), &owner.nullifier_key),
        auditor(),
    );
    let resolved = ResolvedSource::resolve(source, &enrollment(&chain, &auditor))
        .await
        .unwrap();

    let refused = resolved.check_notes(&[
        ring_utxo(&owner, Mint::SOL, 5, 0),
        ring_utxo(&stranger, Mint::SOL, 5, 1),
    ]);

    assert!(matches!(
        refused,
        Err(DelegateSourceError::ForeignNote { index: 1 })
    ));
}

/// A pinned relay vector holds no openings, its honest frame's nullifiers stand in for them.
pub(crate) fn allowed_as_pinned(
    sources: &[ShieldedAddress],
    nullifiers: impl IntoIterator<Item = [u8; 32]>,
) -> AllowedNullifiers {
    AllowedNullifiers {
        sources: sources.iter().map(ShieldedAddress::to_bytes).collect(),
        nullifiers: nullifiers.into_iter().collect(),
    }
}

fn zero_key_source(seed: u8) -> ShieldedAddress {
    ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(&Address::new_from_array([seed; 32])),
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        viewing_pubkey: X25519Keypair::new().pubkey(),
    }
}

fn zero_key_note(owner: &ShieldedAddress, leaf: u64) -> WalletUtxo {
    let note = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::SOL,
        amount: 5,
        blinding: random_blinding(),
        ring_program_id: Some(program()),
        data: Data::default(),
    };
    wallet(note, &NullifierKey::from_secret([0; 31]), TREE_ID, leaf)
}

/// Own and member notes pass around an address and padding, a victim's note leaves `R` unmet.
#[tokio::test]
async fn every_spent_note_answers_to_the_requested_openings() {
    let (owner, member) = (keypair(17), zero_key_source(18));
    let source = owner.shielded_address().unwrap();
    let (chain, auditor) = (
        enrolled(source.solana_address().unwrap(), &owner.nullifier_key),
        auditor(),
    );
    let enrollment = enrollment(&chain, &auditor);
    let own = ring_utxo(&owner, Mint::SOL, 5, 0);
    let members = zero_key_note(&member, 1);
    let mut allowed = AllowedNullifiers::default();
    for (address, notes) in [(source, vec![own.clone()]), (member, vec![members.clone()])] {
        let resolved = ResolvedSource::resolve(address, &enrollment).await.unwrap();
        allowed.admit(&resolved, &notes).unwrap();
    }
    allowed.check_sources([&member, &source]).unwrap();
    let victim = zero_key_note(&zero_key_source(19), 2);
    let (address, dummy) = ([0x5a; 32], [0x5b; 32]);

    allowed
        .check_spends(2, [&own.nullifier, &address, &members.nullifier, &dummy])
        .unwrap();
    let refused = allowed.check_spends(2, [&own.nullifier, &address, &victim.nullifier]);

    assert!(matches!(
        refused,
        Err(DelegateSourceError::UnrequestedInput {
            spent: 2,
            allowed: 1
        })
    ));
    assert!(matches!(
        allowed.check_sources([&source]),
        Err(DelegateSourceError::SourcesMismatch)
    ));
}

#[tokio::test]
async fn a_relabeled_zero_key_opening_is_refused() {
    let (source, victim) = (zero_key_source(20), zero_key_source(21));
    let (chain, auditor) = (Chain::default(), auditor());
    let resolved = ResolvedSource::resolve(source, &enrollment(&chain, &auditor))
        .await
        .unwrap();
    let mut relabeled = zero_key_note(&victim, 0);
    relabeled.utxo.owner = source.signing_pubkey;
    let mut allowed = AllowedNullifiers::default();

    let refused = allowed.admit(&resolved, &[zero_key_note(&source, 1), relabeled]);

    assert!(matches!(
        refused,
        Err(DelegateSourceError::UnboundOpening { index: 1 })
    ));
    assert_eq!(allowed, AllowedNullifiers::default());
}
