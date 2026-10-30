//! Scheme 10 opened into a wallet by `open_ring_confidential`.

use solana_address::Address;
use solana_signature::Signature;
use spr_client::{OutputContext, OutputSlot, ShieldedTransaction};
use spr_interface::instruction::instruction_data::transact::OwnerTag;
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey};
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, Data, Mint, Utxo, WalletUtxo,
};
use zolana_ring_client::open_ring_confidential;
use zolana_ring_transaction::{RingAssets, RingDelivery, RingOutputRail};

const RING: Address = Address::new_from_array([42; 32]);
const TREE: u16 = 7;
const HELD: u64 = 10;
const SENT: u64 = 3;

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn address(owner: &ShieldedKeypair) -> ShieldedAddress {
    owner.shielded_address().unwrap()
}

/// One ring input of `HELD` lamports, its transaction viewing key from the input's nullifier.
fn spend(owner: &ShieldedKeypair) -> (ConfidentialTransaction, [u8; 32]) {
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: HELD,
        blinding: [3; 32],
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let nullifier_pubkey = address(owner).nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let nullifier = owner.nullifier(&utxo_hash, &utxo.blinding).unwrap();
    let input = WalletUtxo {
        nullifier,
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE,
        leaf_index: 1,
        latest_tree_id: None,
        slot: 1,
        tx_signature: Signature::from([1; 64]),
        slot_index: 0,
    };
    let payer = address(owner).solana_address().unwrap();
    let transaction = ConfidentialTransaction::new_with_ring(vec![input], payer, RING)
        .unwrap()
        .with_output_tree_id(TREE)
        .unwrap();
    (transaction, nullifier)
}

/// `SENT` to `recipient` and the change back, published as the indexer serves them.
fn transfer(
    sender: &ShieldedKeypair,
    recipient: &ShieldedKeypair,
    delivery: RingDelivery,
) -> ShieldedTransaction {
    let (mut tx, nullifier) = spend(sender);
    tx.transfer_sol(&address(recipient), SENT).unwrap();
    let tx_key = sender
        .viewing_key
        .get_transaction_viewing_key(&nullifier)
        .unwrap();
    let rail = RingOutputRail::new(tx_key, delivery);
    let proof = rail.encrypt(tx, &address(sender)).unwrap();
    let published = rail.published_slots(&proof, &address(sender)).unwrap();
    let output_slots = published
        .iter()
        .zip(&proof.external_data.outputs)
        .enumerate()
        .map(|(leaf, (slot, output))| OutputSlot {
            view_tag: match output.owner_tag {
                OwnerTag::Inline(tag) => tag,
                ref other => panic!("inline owner tag expected, got {other:?}"),
            },
            output_context: OutputContext {
                hash: *slot.wire.hash(),
                tree_id: TREE,
                leaf_index: leaf as u64,
            },
            payload: output.data.clone().unwrap(),
        })
        .collect();
    ShieldedTransaction {
        slot: 9,
        tx_signature: Signature::from([9; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(rail.tx_viewing_key().pubkey()),
        salt: Some(rail.salt()),
        output_slots,
        messages: Vec::new(),
        nullifiers: vec![nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    }
}

fn held(owner: &ShieldedKeypair, transactions: &[ShieldedTransaction]) -> Vec<(u64, bool)> {
    let notes = open_ring_confidential(owner, &RingAssets::new([]).unwrap(), transactions).unwrap();
    assert!(notes.pending.is_empty());
    notes
        .owned
        .utxos
        .iter()
        .map(|utxo| {
            assert_eq!(utxo.utxo.ring_program_id, Some(RING));
            assert_eq!(utxo.utxo.asset, Mint::SOL);
            assert_eq!(utxo.utxo.owner, owner.signing_pubkey());
            (
                utxo.utxo.amount,
                notes.owned.spent.contains(&utxo.nullifier),
            )
        })
        .collect()
}

#[test]
fn a_delivered_transfer_opens_for_its_recipient_by_trial_over_the_held_mints() {
    let (sender, recipient) = (keypair(1), keypair(2));
    let tx = transfer(&sender, &recipient, RingDelivery::Delivered);
    assert_eq!(held(&recipient, std::slice::from_ref(&tx)), [(SENT, false)]);
    assert_eq!(
        held(&sender, std::slice::from_ref(&tx)),
        [(HELD - SENT, false)]
    );
    assert!(held(&keypair(3), &[tx]).is_empty());
}

#[test]
fn a_note_reads_spent_once_a_scanned_transaction_spends_it() {
    let (sender, recipient) = (keypair(1), keypair(2));
    let received = transfer(&sender, &recipient, RingDelivery::Delivered);
    let notes = open_ring_confidential(
        &recipient,
        &RingAssets::new([]).unwrap(),
        std::slice::from_ref(&received),
    )
    .unwrap();
    let spent_by = ShieldedTransaction {
        tx_signature: Signature::from([10; 64]),
        nullifiers: vec![notes.owned.utxos[0].nullifier],
        output_slots: Vec::new(),
        ..received.clone()
    };
    assert_eq!(held(&recipient, &[received, spent_by]), [(SENT, true)]);
}
