//! The ring output rails, read back as a recipient and the ring program read them.

use custom_ring_interface::{
    blinding::ring_blinding_seed, stream::DeliveredSlot, stream::SlotSecret, RingOutput,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_interface::instruction::instruction_data::transact::OwnerTag;
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey};
use spr_transaction::{
    instructions::transact::{ConfidentialTransaction, Shape, SppProofInputs, SppProofOutputUtxo},
    Data, Mint, Utxo, WalletUtxo,
};
use zolana_ring_transaction::{
    listed_recipients, AnonymousOutput, AnonymousPlan, AnonymousSlot,
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, OutputBlindings,
    PublishedSlot, RingAssets, RingDelivery, RingDeliveryOpening, RingOutputRail,
    RingRailError as E, RingUtxoOwner, TaggedPayment, UnverifiedRecipientPlaintext,
    VerifiedRecipientPlaintext, DUMMY_RECIPIENT_VIEWING_PK, RECIPIENT_BODY_LEN,
};

const RING: Address = Address::new_from_array([42; 32]);
const TREE: u16 = 7;
const USDC: Mint = Mint {
    asset: Address::new_from_array([9; 32]),
    asset_id: 2,
};

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn address(owner: &ShieldedKeypair) -> ShieldedAddress {
    owner.shielded_address().unwrap()
}

fn input(owner: &ShieldedKeypair, asset: Mint, amount: u64, leaf: u64) -> WalletUtxo {
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset,
        amount,
        blinding: [3 + leaf as u8; 32],
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let nullifier_pubkey = address(owner).nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE,
        leaf_index: leaf,
        latest_tree_id: None,
        slot: 1,
        tx_signature: Signature::from([1; 64]),
        slot_index: 0,
    }
}

fn ring_spend(
    owner: &ShieldedKeypair,
    inputs: Vec<WalletUtxo>,
    compact: bool,
) -> (ConfidentialTransaction, ViewingKey) {
    let tx_key = owner
        .viewing_key
        .get_transaction_viewing_key(&inputs[0].nullifier)
        .unwrap();
    let payer = address(owner).solana_address().unwrap();
    let transaction = match compact {
        true => ConfidentialTransaction::new_compact_with_ring(inputs, payer, RING),
        false => ConfidentialTransaction::new_with_ring(inputs, payer, RING),
    }
    .unwrap()
    .with_output_tree_id(TREE)
    .unwrap();
    (transaction, tx_key)
}

fn ring_transfer(owner: &ShieldedKeypair, compact: bool) -> (ConfidentialTransaction, ViewingKey) {
    ring_spend(owner, vec![input(owner, Mint::SOL, 10, 1)], compact)
}

fn delivered_secret(
    reader: &ViewingKey,
    proof: &SppProofInputs,
    rail: &RingOutputRail,
    index: u32,
) -> SlotSecret {
    let tx_pk = rail.tx_viewing_key().pubkey();
    DeliveredSlot {
        agreement: &reader.ecdh(&tx_pk).unwrap(),
        tx_viewing_pk: tx_pk.as_bytes(),
        recipient_viewing_pk: reader.pubkey().as_bytes(),
        salt: &rail.salt(),
        output_index: index,
        first_nullifier: &proof.input_utxos[0].nullifier(),
    }
    .secret()
    .unwrap()
}

/// The UTXO a delivered body opens to under `secret`, `None` for another key's body.
fn open(wire: RingOutput<'_>, owner: &ShieldedAddress, secret: &SlotSecret) -> Option<Utxo> {
    let RingOutput::Delivered { body, .. } = wire else {
        panic!("delivered slot expected")
    };
    let delivered = RingDeliveryOpening {
        ring: RING,
        body,
        slot_secret: secret,
        owner: RingUtxoOwner {
            signing_pubkey: &owner.signing_pubkey,
            nullifier_pubkey: &owner.nullifier_pubkey,
        },
        commitment: wire.hash(),
        tree_id: TREE,
    }
    .open(&RingAssets::new([]).unwrap())
    .unwrap()?;
    delivered.mint.map(|mint| delivered.note.utxo(mint))
}

/// The recipient body at output `position`, opened by `reader`.
fn decrypt(
    reader: &ViewingKey,
    rail: &RingOutputRail,
    slot: &PublishedSlot<'_>,
    position: u32,
) -> Vec<u8> {
    let RingOutput::Anonymous {
        body: Some(body), ..
    } = slot.wire
    else {
        panic!("anonymous recipient slot expected")
    };
    reader
        .decrypt_utxo(body, &rail.tx_viewing_key().pubkey(), rail.salt(), position)
        .unwrap()
}

/// The sender bundle message, sealed after every output.
fn bundle(
    reader: &ViewingKey,
    rail: &RingOutputRail,
    proof: &SppProofInputs,
) -> AnonymousTransferSenderPlaintext {
    let sender = rail.published_sender(proof).unwrap().unwrap();
    let slot = u32::try_from(proof.output_utxos.len()).unwrap();
    let plaintext = reader
        .decrypt_utxo(
            sender.body,
            &rail.tx_viewing_key().pubkey(),
            rail.salt(),
            slot,
        )
        .unwrap();
    AnonymousTransferSenderPlaintext::deserialize(&plaintext).unwrap()
}

fn recipient_note(plaintext: &[u8]) -> AnonymousTransferRecipientPlaintext {
    AnonymousTransferRecipientPlaintext::deserialize(plaintext).unwrap()
}

fn payment(recipient: &ShieldedAddress, tag: u8) -> TaggedPayment {
    TaggedPayment {
        recipient: recipient.viewing_pubkey,
        tag: [tag; 32],
    }
}

fn anonymous(tx_key: ViewingKey, plan: AnonymousPlan) -> RingOutputRail {
    RingOutputRail::new(tx_key, RingDelivery::Anonymous(Box::new(plan)))
}

/// The reader's view of output `position`, every ring mint tried.
fn reader<'a>(
    owner: &'a ShieldedAddress,
    assets: &'a RingAssets,
    proof: &'a SppProofInputs,
    position: usize,
) -> AnonymousOutput<'a> {
    AnonymousOutput {
        owner,
        assets,
        ring: RING,
        tree_id: TREE,
        utxo_hash: &proof.external_data.outputs[position].utxo_hash,
    }
}

/// The output seed the sender re-derives from its transaction key and the published salt.
fn output_seed(rail: &RingOutputRail, proof: &SppProofInputs) -> [u8; 32] {
    let seed = ring_blinding_seed(&rail.tx_viewing_key().secret_bytes(), &rail.salt()).unwrap();
    *OutputBlindings::new(&proof.input_utxos[0].nullifier(), &seed)
        .unwrap()
        .output_seed()
}

#[test]
fn a_delivered_output_opens_only_for_the_key_its_owner_tag_names() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = RingOutputRail::new(tx_key.clone(), RingDelivery::Delivered);
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    assert_eq!(proof.external_data.salt, rail.salt());
    assert_eq!(
        proof.blinding_seed,
        ring_blinding_seed(&tx_key.secret_bytes(), &rail.salt()).unwrap()
    );
    assert_ne!(
        RingOutputRail::new(tx_key, RingDelivery::Delivered).salt(),
        rail.salt(),
        "a resent attempt draws a fresh salt"
    );
    assert_eq!(
        proof.external_data.outputs[0].owner_tag,
        OwnerTag::Inline(recipient.viewing_pubkey.u())
    );
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published.len(), proof.output_utxos.len());
    assert!(published
        .iter()
        .all(|slot| matches!(slot.wire, RingOutput::Delivered { .. })));
    let secret = delivered_secret(&receiver.viewing_key, &proof, &rail, 0);
    let opened = open(published[0].wire, &recipient, &secret).unwrap();
    assert_eq!(
        (opened.amount, opened.blinding),
        (3, proof.output_utxos[0].blinding)
    );
    assert_eq!(proof.output_utxos[0].ring_data_hash, None);
    let stranger = delivered_secret(&keypair(3).viewing_key, &proof, &rail, 0);
    assert!(open(published[0].wire, &recipient, &stranger).is_none());
}

/// The change leads under the sender tag with no data.
#[test]
fn an_anonymous_transfer_seals_each_payment_at_its_position_and_the_bundle_after_them() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let paid = payment(&recipient, 0x0b);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(tx_key, AnonymousPlan::new([0x0a; 32]).with_payment(paid));
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    let assets = RingAssets::new([]).unwrap();

    assert_eq!(proof.output_utxos[0].owner_address, Some(address(&sender)));
    assert_eq!(
        published[0].anonymous,
        Some(AnonymousSlot::Change { tag: [0x0a; 32] })
    );
    assert_eq!(published[1].anonymous, Some(AnonymousSlot::Payment(paid)));
    assert_eq!(
        proof.external_data.outputs[0].owner_tag,
        OwnerTag::Inline([0x0a; 32])
    );
    assert_eq!(
        proof.external_data.outputs[1].owner_tag,
        OwnerTag::Inline([0x0b; 32])
    );
    assert!(proof
        .output_utxos
        .iter()
        .all(|output| output.ring_data_hash.is_none()));

    assert_eq!(proof.external_data.outputs[0].data, None);
    assert_eq!(proof.external_data.messages[0].view_tag, [0x0a; 32]);
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(
        sent.verified.recipient_viewing_pks,
        vec![recipient.viewing_pubkey]
    );
    assert_eq!(sent.unverified.blinding_seed, output_seed(&rail, &proof));
    let change = reader(&address(&sender), &assets, &proof, 0)
        .sender_change(sent, &proof.input_utxos[0].nullifier())
        .unwrap();
    let [opened] = change.as_slice() else {
        panic!("one change output")
    };
    assert!(reader(&address(&sender), &assets, &proof, 0).rebuilds(opened));
    assert_eq!((opened.asset, opened.amount), (Mint::SOL, 7));

    let note = recipient_note(&decrypt(&receiver.viewing_key, &rail, &published[1], 1));
    assert_eq!(
        note.unverified.sender_pubkey,
        address(&sender).viewing_pubkey
    );
    assert_eq!(note.verified.mint, Mint::SOL.asset);
    let utxo = reader(&recipient, &assets, &proof, 1)
        .open_recipient(note.clone())
        .unwrap()
        .unwrap();
    assert_eq!(
        (utxo.amount, utxo.blinding),
        (3, proof.output_utxos[1].blinding)
    );
    assert_eq!(
        reader(&recipient, &assets, &proof, 0)
            .open_recipient(note)
            .unwrap(),
        None,
        "a body rebuilds only the hash published at its own output"
    );
    let stranger = decrypt(&keypair(3).viewing_key, &rail, &published[1], 1);
    assert!(AnonymousTransferRecipientPlaintext::deserialize(&stranger)
        .ok()
        .and_then(|body| reader(&recipient, &assets, &proof, 1)
            .open_recipient(body)
            .unwrap())
        .is_none());
}

#[test]
fn the_bundle_carries_the_spl_and_the_sol_change_and_their_outputs_no_data() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_spend(
        &sender,
        vec![input(&sender, USDC, 10, 1), input(&sender, Mint::SOL, 5, 2)],
        false,
    );
    tx.transfer_with_ring(&recipient, USDC, 4, Some(RING))
        .unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new([0x0a; 32]).with_payment(payment(&recipient, 0x0b)),
    );
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(
        (proof.output_utxos[0].asset, proof.output_utxos[1].asset),
        (USDC, Mint::SOL)
    );
    assert_eq!(
        published[0].anonymous,
        Some(AnonymousSlot::Change { tag: [0x0a; 32] })
    );
    assert!(matches!(
        published[1].anonymous,
        Some(AnonymousSlot::Change { tag }) if tag != [0x0a; 32] && tag[0] == 0
    ));
    for change in &published[..2] {
        assert!(matches!(
            change.wire,
            RingOutput::Anonymous { body: None, .. }
        ));
    }
    let assets = RingAssets::new([USDC]).unwrap();
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(
        listed_recipients(&sent).copied().collect::<Vec<_>>(),
        vec![recipient.viewing_pubkey]
    );
    let change = reader(&address(&sender), &assets, &proof, 0)
        .sender_change(sent, &proof.input_utxos[0].nullifier())
        .unwrap();
    for (position, (utxo, (asset, amount))) in
        change.iter().zip([(USDC, 6), (Mint::SOL, 5)]).enumerate()
    {
        assert_eq!((utxo.asset, utxo.amount), (asset, amount));
        assert!(reader(&address(&sender), &assets, &proof, position).rebuilds(utxo));
    }
    let note = recipient_note(&decrypt(&keypair(2).viewing_key, &rail, &published[2], 2));
    assert_eq!((note.verified.mint, note.verified.amount), (USDC.asset, 4));
}

#[test]
fn an_spl_only_change_opens_one_note_at_output_0() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_spend(&sender, vec![input(&sender, USDC, 10, 1)], false);
    tx.transfer_with_ring(&recipient, USDC, 4, Some(RING))
        .unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new([0x0a; 32]).with_payment(payment(&recipient, 0x0b)),
    );
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let assets = RingAssets::new([USDC]).unwrap();
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(sent.verified.sol_amount, 0);
    // A zero SOL amount yields no note, else a phantom would take blinding slot 1.
    let change = reader(&address(&sender), &assets, &proof, 0)
        .sender_change(sent, &proof.input_utxos[0].nullifier())
        .unwrap();
    assert_eq!(change.len(), 1);
    assert_eq!((change[0].asset, change[0].amount), (USDC, 6));
    assert!(reader(&address(&sender), &assets, &proof, 0).rebuilds(&change[0]));
}

#[test]
fn a_dummy_publishes_a_zero_led_tag_and_a_recipient_length_body() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(
        tx_key.clone(),
        AnonymousPlan::new([0x0a; 32]).with_payment(payment(&recipient, 0x0b)),
    );
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    for dummy in &published[2..] {
        let Some(AnonymousSlot::Dummy { tag }) = dummy.anonymous else {
            panic!("dummy slot expected")
        };
        assert_eq!(tag[0], 0);
        let RingOutput::Anonymous {
            body: Some(dummy), ..
        } = dummy.wire
        else {
            panic!("recipient body expected")
        };
        assert_eq!(dummy.len(), RECIPIENT_BODY_LEN);
    }
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    let dummy = X25519Pubkey::from_bytes(DUMMY_RECIPIENT_VIEWING_PK).unwrap();
    assert_eq!(
        sent.verified.recipient_viewing_pks,
        vec![recipient.viewing_pubkey, dummy, dummy]
    );
    assert_eq!(
        listed_recipients(&sent).copied().collect::<Vec<_>>(),
        vec![recipient.viewing_pubkey]
    );
}

#[test]
fn a_dummy_body_takes_the_length_of_a_data_free_recipient_plaintext() {
    let owner = address(&keypair(1));
    let plaintext = AnonymousTransferRecipientPlaintext {
        verified: VerifiedRecipientPlaintext {
            owner_pubkey: owner.signing_pubkey,
            mint: USDC.asset,
            amount: 3,
        },
        unverified: UnverifiedRecipientPlaintext {
            sender_pubkey: owner.viewing_pubkey,
            blinding: [5; 32],
            data: Data::default(),
        },
    };
    assert_eq!(plaintext.serialize().unwrap().len(), RECIPIENT_BODY_LEN);
}

#[test]
fn a_transfer_without_sender_change_at_output_0_is_refused() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 10).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new([0x0a; 32]).with_payment(payment(&recipient, 0x0b)),
    );
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::MissingSenderChange)
    ));
}

#[test]
fn an_anonymous_payment_refuses_ring_data_of_its_own() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.add_output_utxo(
        SppProofOutputUtxo::new(Mint::SOL, 3, recipient)
            .unwrap()
            .with_ring_data_hash(RING, [1; 32]),
    )
    .unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new([0x0a; 32]).with_payment(payment(&recipient, 0x0b)),
    );
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::DeliveredOutputData { slot_index: 1 })
    ));
}

#[test]
fn an_exit_to_the_hidden_sender_is_refused() {
    let sender = keypair(1);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    let other_view = ShieldedAddress {
        viewing_pubkey: address(&keypair(2)).viewing_pubkey,
        ..address(&sender)
    };
    tx.transfer_with_ring(&other_view, Mint::SOL, 2, None)
        .unwrap();
    assert!(matches!(
        anonymous(tx_key, AnonymousPlan::new([0x0a; 32])).encrypt(tx, &address(&sender)),
        Err(E::RingSenderExit { slot_index: 1 })
    ));
}

#[test]
fn an_exit_publishes_scheme_3_under_its_owner_tag() {
    let sender = keypair(1);
    let exit = address(&keypair(3));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_with_ring(&exit, Mint::SOL, 2, None).unwrap();
    let rail = anonymous(tx_key, AnonymousPlan::new([0x0a; 32]));
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published[1].anonymous, Some(AnonymousSlot::Exit));
    assert!(published[1].wire.is_exit());
    assert_eq!(
        proof.external_data.outputs[1].owner_tag,
        OwnerTag::Inline(exit.signing_pubkey.confidential_view_tag().unwrap())
    );
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(
        listed_recipients(&sent).count(),
        0,
        "an exit's owner reads no shared tag and is never listed"
    );
}

#[test]
fn an_anonymous_ring_output_to_another_owner_needs_a_planned_payment() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    assert!(matches!(
        anonymous(tx_key, AnonymousPlan::new([0x0a; 32])).encrypt(tx, &address(&sender)),
        Err(E::UnplannedRingOutput { slot_index: 1 })
    ));
}

#[test]
fn a_payment_planned_for_another_owner_is_refused() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let other = address(&keypair(3));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new([0x0a; 32]).with_payment(payment(&other, 0x0b)),
    );
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::RingPaymentSlot { slot_index: 1 })
    ));
}

#[test]
fn a_delivered_rail_refuses_output_data_and_compact_padding() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    for ring in [Some(RING), None] {
        let (mut tx, tx_key) = ring_transfer(&sender, false);
        let output = SppProofOutputUtxo::new(Mint::SOL, 3, recipient)
            .unwrap()
            .with_memo(vec![1]);
        tx.add_output_utxo(match ring {
            Some(ring) => output.with_ring_program_id(ring),
            None => output,
        })
        .unwrap();
        let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
        assert!(matches!(
            rail.encrypt(tx, &address(&sender)),
            Err(E::DeliveredOutputData { slot_index: 0 })
        ));
    }

    let (tx, tx_key) = ring_transfer(&sender, true);
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.transfer_sol(&recipient, 3).unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::DeliveredCompactPadding { .. })
    ));
}
