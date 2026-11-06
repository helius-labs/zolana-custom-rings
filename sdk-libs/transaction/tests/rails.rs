//! The ring output rails, read back as a recipient and the ring program read them.

use custom_ring_interface::{
    blinding::ring_blinding_seed, ring_body_output, stream::DeliveredSlot, stream::SlotSecret,
    BundleLayout, ChangeCell, RecipientBody, SenderBundle, SlotBody,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, MIN_REPLY_LEN, RECIPIENT_BODY_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_interface::{instruction::instruction_data::transact::OwnerTag, ZERO_NULLIFIER_PUBKEY};
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey};
use spr_transaction::{
    instructions::transact::{ConfidentialTransaction, Shape, SppProofInputs, SppProofOutputUtxo},
    Data, Mint, TransactionError, Utxo, WalletUtxo,
};
use zolana_ring_transaction::{
    open_recipient_body, open_reply, open_sender_bundle, random_tag_preimage, seal_recipient_body,
    seal_reply, AnonymousOutput, AnonymousPlan, AnonymousSlot, OpenedBody, OpenedNote,
    OutputBlindings, PublishedSlot, ReplyMetadata, RingAssets, RingDelivery, RingOutputRail,
    RingRailError as E,
};

const RING: Address = Address::new_from_array([42; 32]);
const TREE: u16 = 7;
const USDC: Mint = Mint {
    asset: Address::new_from_array([9; 32]),
    asset_id: 2,
};
const DATA_HASH: [u8; 32] = [1; 32];
const RING_DATA_HASH: [u8; 32] = [2; 32];
const APP_DATA: [u8; 3] = [7, 8, 9];

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

/// The recipient body at output `position`, opened by `reader`.
fn decrypt(
    reader: &ViewingKey,
    rail: &RingOutputRail,
    proof: &SppProofInputs,
    slot: &PublishedSlot<'_>,
    position: u32,
) -> RecipientBody {
    let SlotBody::Recipient(body) = slot.body else {
        panic!("recipient slot expected")
    };
    open_recipient_body(body, &delivered_secret(reader, proof, rail, position)).unwrap()
}

/// The sender bundle at index `m`, `m` read from the frame's published slots.
fn bundle(reader: &ViewingKey, rail: &RingOutputRail, proof: &SppProofInputs) -> SenderBundle {
    let sender = rail
        .published_sender(proof, &reader.pubkey())
        .unwrap()
        .unwrap();
    let outputs = &proof.external_data.outputs;
    let layout = BundleLayout {
        outputs: outputs.len(),
        change: outputs
            .iter()
            .filter(|output| output.data.is_none())
            .count(),
    };
    let secret = delivered_secret(reader, proof, rail, u32::try_from(outputs.len()).unwrap());
    open_sender_bundle(sender.body, &secret, layout).unwrap()
}

/// Cell `slot` at slot `slot`, the change leads.
fn change_at(
    sender: &ShieldedAddress,
    assets: &RingAssets,
    proof: &SppProofInputs,
    sent: &SenderBundle,
    slot: usize,
) -> Utxo {
    let blindings =
        OutputBlindings::published(&proof.input_utxos[0].nullifier(), &sent.output_seed);
    note(
        reader(sender, assets, proof, slot)
            .open_change(&sent.change[slot], blindings.at(slot as u32).unwrap())
            .unwrap(),
    )
}

/// The note a body opens to, panicking on a miss or an unknown mint.
fn note(opened: Option<OpenedBody>) -> Utxo {
    match opened {
        Some(OpenedBody::Note(opened)) => opened.utxo,
        other => panic!("a note expected, got {other:?}"),
    }
}

fn payment(recipient: &ShieldedAddress) -> X25519Pubkey {
    recipient.viewing_pubkey
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

struct PaidFrame {
    rail: RingOutputRail,
    proof: SppProofInputs,
    position: usize,
}

fn pay(sender: &ShieldedKeypair, output: SppProofOutputUtxo, delivery: RingDelivery) -> PaidFrame {
    let owner = output.owner_address;
    let (mut tx, tx_key) = ring_transfer(sender, false);
    tx.add_output_utxo(output).unwrap();
    let rail = RingOutputRail::new(tx_key, delivery);
    let proof = rail.encrypt(tx, &address(sender)).unwrap();
    let position = proof
        .output_utxos
        .iter()
        .position(|output| output.owner_address == owner)
        .unwrap();
    PaidFrame {
        rail,
        proof,
        position,
    }
}

impl PaidFrame {
    fn body(&self, sender: &ShieldedKeypair, reader: &ViewingKey) -> RecipientBody {
        let published = self
            .rail
            .published_slots(&self.proof, &address(sender))
            .unwrap();
        decrypt(
            reader,
            &self.rail,
            &self.proof,
            &published[self.position],
            self.position as u32,
        )
    }
}

fn both_rails(recipient: &ShieldedAddress) -> [RingDelivery; 2] {
    [
        RingDelivery::Delivered,
        RingDelivery::Anonymous(Box::new(
            AnonymousPlan::new().with_payment(payment(recipient)),
        )),
    ]
}

fn data_note(recipient: ShieldedAddress) -> SppProofOutputUtxo {
    SppProofOutputUtxo::new(Mint::SOL, 3, recipient)
        .unwrap()
        .with_ring_data_hash(RING, RING_DATA_HASH)
        .with_utxo_data(APP_DATA.to_vec(), DATA_HASH)
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
        OwnerTag::Inline(custom_ring_interface::stream::slot_tag(
            recipient.viewing_pubkey.u()
        ))
    );
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published.len(), proof.output_utxos.len());
    assert!(published
        .iter()
        .all(|slot| slot.anonymous.is_none() && matches!(slot.body, SlotBody::Recipient(_))));
    let assets = RingAssets::new([]).unwrap();
    let body = decrypt(&receiver.viewing_key, &rail, &proof, &published[0], 0);
    let opened = note(
        reader(&recipient, &assets, &proof, 0)
            .open_body(&body)
            .unwrap(),
    );
    assert_eq!(
        (opened.amount, opened.blinding),
        (3, proof.output_utxos[0].blinding)
    );
    assert_eq!(proof.output_utxos[0].ring_data_hash, None);
    let stranger = decrypt(&keypair(3).viewing_key, &rail, &proof, &published[0], 0);
    assert_eq!(
        reader(&recipient, &assets, &proof, 0)
            .open_body(&stranger)
            .unwrap(),
        None
    );
}

/// The change leads under the sender tag with no data.
#[test]
fn an_anonymous_transfer_seals_each_payment_at_its_position_and_the_bundle_after_them() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let paid = payment(&recipient);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(tx_key, AnonymousPlan::new().with_payment(paid));
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    let assets = RingAssets::new([]).unwrap();

    assert_eq!(proof.output_utxos[0].owner_address, Some(address(&sender)));
    assert_eq!(published[0].anonymous, Some(AnonymousSlot::Change));
    assert_eq!(
        published[1].anonymous,
        Some(AnonymousSlot::Payment { recipient: paid })
    );
    assert_eq!(proof.external_data.outputs[0].data, None);
    assert_eq!(
        proof.external_data.outputs[0].owner_tag,
        OwnerTag::Inline([0; 32]),
        "a change slot publishes zero"
    );
    let n0 = proof.input_utxos[0].nullifier();
    let recipient_secret = delivered_secret(&receiver.viewing_key, &proof, &rail, 1);
    assert_eq!(
        proof.external_data.outputs[1].owner_tag,
        OwnerTag::Inline(custom_ring_interface::stream::slot_tag(
            recipient_secret.recipient_tag().unwrap()
        ))
    );
    let sender_secret = delivered_secret(&sender.viewing_key, &proof, &rail, 2);
    assert_eq!(
        proof.external_data.messages[0].view_tag,
        sender_secret.sender_tag().unwrap()
    );
    assert_eq!(
        rail.sender_bundle_tag(&address(&sender).viewing_pubkey, &n0, 2)
            .unwrap(),
        proof.external_data.messages[0].view_tag
    );

    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(sent.recipient_keys, [recipient.viewing_pubkey.u()]);
    assert_eq!(sent.output_seed, output_seed(&rail, &proof));
    assert_eq!(
        sent.change,
        [ChangeCell {
            mint: Mint::SOL.asset.to_bytes(),
            amount: 7
        }]
    );
    let change = change_at(&address(&sender), &assets, &proof, &sent, 0);
    assert_eq!((change.asset, change.amount), (Mint::SOL, 7));

    let body = decrypt(&receiver.viewing_key, &rail, &proof, &published[1], 1);
    assert_eq!(body.mint, Mint::SOL.asset.to_bytes());
    let utxo = note(
        reader(&recipient, &assets, &proof, 1)
            .open_body(&body)
            .unwrap(),
    );
    assert_eq!(
        (utxo.amount, utxo.blinding),
        (3, proof.output_utxos[1].blinding)
    );
    assert_eq!(
        reader(&recipient, &assets, &proof, 0)
            .open_body(&body)
            .unwrap(),
        None,
        "a body rebuilds only the hash published at its own output"
    );
    let stranger = decrypt(&keypair(3).viewing_key, &rail, &proof, &published[1], 1);
    assert_eq!(
        reader(&recipient, &assets, &proof, 1)
            .open_body(&stranger)
            .unwrap(),
        None,
        "another viewing key reads other bytes"
    );
}

#[test]
fn the_bundle_carries_the_spl_and_the_sol_change() {
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
        AnonymousPlan::new().with_payment(payment(&recipient)),
    );
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(
        (proof.output_utxos[0].asset, proof.output_utxos[1].asset),
        (USDC, Mint::SOL)
    );
    for change in &published[..2] {
        assert_eq!(change.body, SlotBody::None);
    }
    let assets = RingAssets::new([USDC]).unwrap();
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(sent.recipient_keys[0], recipient.viewing_pubkey.u());
    for (position, (asset, amount)) in [(USDC, 6), (Mint::SOL, 5)].into_iter().enumerate() {
        let utxo = change_at(&address(&sender), &assets, &proof, &sent, position);
        assert_eq!((utxo.asset, utxo.amount), (asset, amount));
    }
    let body = decrypt(&keypair(2).viewing_key, &rail, &proof, &published[2], 2);
    assert_eq!((body.mint, body.amount), (USDC.asset.to_bytes(), 4));
}

#[test]
fn a_zero_amount_change_slot_rebuilds_from_its_cell() {
    let sender = keypair(1);
    let (tx, tx_key) = ring_spend(&sender, vec![input(&sender, Mint::SOL, 0, 1)], false);
    let rail = anonymous(tx_key, AnonymousPlan::new());
    let mut tx = tx;
    tx.add_output_utxo(SppProofOutputUtxo {
        owner_address: Some(address(&sender)),
        asset: Mint::SOL,
        ring_program_id: Some(RING),
        ..Default::default()
    })
    .unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(sent.change[0].amount, 0);
    let assets = RingAssets::new([]).unwrap();
    let change = change_at(&address(&sender), &assets, &proof, &sent, 0);
    assert_eq!(change.amount, 0);
}

#[test]
fn a_reader_tries_the_registered_key_then_the_zero_key() {
    let owner = address(&keypair(2));
    let blinding = [5; 32];
    let assets = RingAssets::new([USDC]).unwrap();
    let body = RecipientBody {
        blinding,
        amount: 9,
        mint: USDC.asset.to_bytes(),
        ..RecipientBody::default()
    };
    let hash_under = |nullifier_pk: &[u8; 32]| {
        Utxo {
            owner: owner.signing_pubkey,
            asset: USDC,
            amount: 9,
            blinding,
            ring_program_id: Some(RING),
            data: Data::default(),
        }
        .hash(nullifier_pk, &[0; 32], &[0; 32], TREE)
        .unwrap()
    };
    let open = |hash: &[u8; 32]| {
        AnonymousOutput {
            owner: &owner,
            assets: &assets,
            ring: RING,
            tree_id: TREE,
            utxo_hash: hash,
        }
        .open_body(&body)
        .unwrap()
    };
    for key in [owner.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY] {
        assert!(matches!(
            open(&hash_under(&key)),
            Some(OpenedBody::Note(OpenedNote { nullifier_pk, .. })) if nullifier_pk == key
        ));
    }
    assert_eq!(open(&hash_under(&[0x11; 32])), None, "a third key misses");

    let sender = keypair(1);
    let receiver = keypair(2);
    for delivery in both_rails(&owner) {
        for key in [owner.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY, [0x11; 32]] {
            let named = ShieldedAddress {
                nullifier_pubkey: key,
                ..owner
            };
            let frame = pay(
                &sender,
                SppProofOutputUtxo::new(Mint::SOL, 3, named)
                    .unwrap()
                    .with_ring_program_id(RING),
                delivery.clone(),
            );
            let opened = reader(&owner, &assets, &frame.proof, frame.position)
                .open_body(&frame.body(&sender, &receiver.viewing_key))
                .unwrap();
            let rebuilt = opened.map(|opened| match opened {
                OpenedBody::Note(note) => note.nullifier_pk,
                other => panic!("a note expected, got {other:?}"),
            });
            assert_eq!(rebuilt, (key != [0x11; 32]).then_some(key));
        }
    }
}

#[test]
fn a_data_note_seals_on_both_rails_and_its_reader_rebuilds_the_commitment() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let assets = RingAssets::new([]).unwrap();
    for delivery in both_rails(&recipient) {
        let frame = pay(&sender, data_note(recipient), delivery);
        let body = frame.body(&sender, &receiver.viewing_key);
        assert_eq!(body.ring_data_hash, Some(RING_DATA_HASH));
        assert_eq!(body.data, [&DATA_HASH[..], &APP_DATA[..]].concat());
        let opened = reader(&recipient, &assets, &frame.proof, frame.position)
            .open_body(&body)
            .unwrap();
        let Some(OpenedBody::Note(opened)) = opened else {
            panic!("a note expected, got {opened:?}")
        };
        let output = &frame.proof.output_utxos[frame.position];
        assert_eq!(opened.data_hash, Some(DATA_HASH));
        assert_eq!(opened.ring_data_hash, Some(RING_DATA_HASH));
        assert_eq!(opened.nullifier_pk, recipient.nullifier_pubkey);
        assert_eq!(opened.utxo.data, output.data);
        assert_eq!(
            (opened.utxo.amount, opened.utxo.blinding),
            (3, output.blinding)
        );
    }
}

#[test]
fn a_body_with_a_mutated_data_hash_opens_to_none() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let assets = RingAssets::new([]).unwrap();
    for delivery in both_rails(&recipient) {
        let frame = pay(&sender, data_note(recipient), delivery);
        let body = frame.body(&sender, &receiver.viewing_key);
        let opens = |body: &RecipientBody| {
            reader(&recipient, &assets, &frame.proof, frame.position)
                .open_body(body)
                .unwrap()
        };
        assert!(opens(&body).is_some());
        let mut mutated = body.clone();
        mutated.data[31] ^= 1;
        assert_eq!(opens(&mutated), None);
        let dropped = RecipientBody {
            data: Vec::new(),
            ..body.clone()
        };
        assert_eq!(opens(&dropped), None);
        let short = RecipientBody {
            data: DATA_HASH[..31].to_vec(),
            ..body.clone()
        };
        assert_eq!(opens(&short), None);
        let other_ring_data = RecipientBody {
            ring_data_hash: Some([3; 32]),
            ..body
        };
        assert_eq!(opens(&other_ring_data), None);
    }
}

#[test]
fn a_rebuilt_body_of_an_unregistered_mint_names_the_mint() {
    let owner = address(&keypair(2));
    let mint = Address::new_from_array([0x44; 32]);
    let utxo = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::new(mint, 0),
        amount: 9,
        blinding: [5; 32],
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let hash = utxo
        .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let assets = RingAssets::new([USDC]).unwrap();
    let opened = AnonymousOutput {
        owner: &owner,
        assets: &assets,
        ring: RING,
        tree_id: TREE,
        utxo_hash: &hash,
    }
    .open_body(&RecipientBody {
        blinding: [5; 32],
        amount: 9,
        mint: mint.to_bytes(),
        ..RecipientBody::default()
    })
    .unwrap();
    assert!(matches!(
        opened,
        Some(OpenedBody::UnknownMint(OpenedNote { utxo, .. })) if utxo.asset.asset == mint && utxo.amount == 9
    ));
}

#[test]
fn a_dummy_publishes_the_tag_of_its_preimage_and_a_recipient_length_body() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(
        tx_key.clone(),
        AnonymousPlan::new().with_payment(payment(&recipient)),
    );
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    for dummy in &published[2..] {
        let Some(AnonymousSlot::Dummy { preimage }) = dummy.anonymous else {
            panic!("dummy slot expected")
        };
        let tag = custom_ring_interface::stream::slot_tag(
            SlotSecret::new(preimage).unwrap().recipient_tag().unwrap(),
        );
        assert_eq!(dummy.owner_tag, &tag);
        assert!(matches!(
            dummy.body,
            SlotBody::Recipient(body) if body.len() == RECIPIENT_BODY_LEN
        ));
    }
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert_eq!(
        sent.recipient_keys,
        [recipient.viewing_pubkey.u(), [0; 32], [0; 32]]
    );
}

#[test]
fn a_transfer_with_no_change_leads_with_its_payment_and_the_bundle_stays() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 10).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new().with_payment(payment(&recipient)),
    );
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert!(matches!(
        published[0].anonymous,
        Some(AnonymousSlot::Payment { .. })
    ));
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert!(sent.change.is_empty());
    assert_eq!(sent.recipient_keys[0], recipient.viewing_pubkey.u());
    let body = decrypt(&receiver.viewing_key, &rail, &proof, &published[0], 0);
    assert_eq!(body.amount, 10);
}

#[test]
fn the_bundle_carries_one_cell_per_change_output_of_any_asset() {
    let sender = keypair(1);
    let (mut tx, tx_key) = ring_spend(&sender, vec![input(&sender, USDC, 10, 1)], false);
    for _ in 0..2 {
        tx.transfer_with_ring(&address(&sender), USDC, 3, Some(RING))
            .unwrap();
    }
    let rail = anonymous(tx_key, AnonymousPlan::new());
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert!(sent.recipient_keys.iter().all(|key| *key == [0; 32]));
    let assets = RingAssets::new([USDC]).unwrap();
    let mut amounts: Vec<u64> = (0..sent.change.len())
        .map(|slot| change_at(&address(&sender), &assets, &proof, &sent, slot))
        .inspect(|utxo| assert_eq!(utxo.asset, USDC))
        .map(|utxo| utxo.amount)
        .collect();
    amounts.sort_unstable();
    assert_eq!(amounts, [3, 3, 4]);
}

#[test]
fn change_outputs_past_the_output_count_are_refused_before_any_proof() {
    let sender = keypair(1);
    let (mut tx, tx_key) = ring_spend(&sender, vec![input(&sender, USDC, 10, 1)], false);
    for _ in 0..2 {
        tx.transfer_with_ring(&address(&sender), USDC, 3, Some(RING))
            .unwrap();
    }
    let rail = anonymous(tx_key, AnonymousPlan::new());
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    assert!(matches!(
        tx.pad_utxos(Shape::IN1_OUT2, &address(&sender)).err(),
        Some(TransactionError::TooManyOutputsForShape { got: 3, max: 2 })
    ));
}

/// A recipient at the sender's address under another nullifier key is a payment, not change.
#[test]
fn a_recipient_differing_in_its_nullifier_key_is_no_change() {
    let sender = keypair(1);
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    let other_key = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..address(&sender)
    };
    tx.transfer_with_ring(&other_key, Mint::SOL, 3, Some(RING))
        .unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new().with_payment(payment(&other_key)),
    );
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert!(published[0].anonymous.unwrap().is_change());
    assert!(matches!(
        published[1].anonymous,
        Some(AnonymousSlot::Payment { .. })
    ));
}

/// Compact padding leaves the frame, the bundle length and each kept slot index follow `m`.
#[test]
fn compact_padding_omits_a_suffix_and_keeps_every_index() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let (mut tx, tx_key) = ring_transfer(&sender, true);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new().with_payment(payment(&recipient)),
    );
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    assert_eq!(proof.output_utxos.len(), 4);
    assert_eq!(proof.external_data.outputs.len(), 2);
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published.len(), 2);
    let framed = rail
        .published_sender(&proof, &address(&sender).viewing_pubkey)
        .unwrap()
        .unwrap();
    assert_eq!(
        framed.body.len(),
        BundleLayout {
            outputs: 2,
            change: 1
        }
        .byte_len()
    );
    let body = decrypt(&receiver.viewing_key, &rail, &proof, &published[1], 1);
    assert_eq!(body.blinding, proof.output_utxos[1].blinding);
    let assets = RingAssets::new([]).unwrap();
    assert!(reader(&recipient, &assets, &proof, 1)
        .open_body(&body)
        .unwrap()
        .is_some());
}

#[test]
fn a_delivered_rail_omits_compact_padding_from_the_frame() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (tx, tx_key) = ring_transfer(&sender, true);
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.transfer_sol(&recipient, 3).unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    assert_eq!(proof.external_data.outputs.len(), 2);
    assert_eq!(
        rail.published_slots(&proof, &address(&sender))
            .unwrap()
            .len(),
        2
    );
}

fn reply_of(sender: &ShieldedAddress) -> ReplyMetadata {
    ReplyMetadata {
        viewing_key: sender.viewing_pubkey,
        owner_key: sender.signing_pubkey.as_ed25519().unwrap(),
        nullifier_pk: sender.nullifier_pubkey,
        data: Data::default(),
    }
}

#[test]
fn no_default_path_attaches_a_reply() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new().with_payment(payment(&recipient)),
    );
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert!(published.iter().all(|slot| slot.reply.is_empty()));
}

/// A slot without a reply and a dummy publish the same length, a reply never names its slot.
#[test]
fn a_reply_frame_gives_every_body_one_length() {
    let sender = keypair(1);
    let receiver = keypair(2);
    let recipient = address(&receiver);
    let other = address(&keypair(3));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    tx.transfer_sol(&other, 2).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new()
            .with_payment(payment(&recipient))
            .with_reply(reply_of(&address(&sender)))
            .with_payment(payment(&other)),
    );
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    for slot in &published[1..] {
        assert_eq!(slot.reply.len(), MIN_REPLY_LEN);
    }
    assert!(published[0].reply.is_empty(), "change carries no reply");
    let data = proof.external_data.outputs[1].data.as_ref().unwrap();
    let (_, reply) = ring_body_output(data).unwrap();
    let secret = delivered_secret(&receiver.viewing_key, &proof, &rail, 1);
    let claim = open_reply(reply, &secret).unwrap().expect("a reply opens");
    assert_eq!(claim.claimed(), &reply_of(&address(&sender)));
}

#[test]
fn a_reply_longer_than_its_length_is_refused_and_padding_is_checked() {
    let sender = address(&keypair(1));
    let secret = SlotSecret::new([3; 32]).unwrap();
    assert!(matches!(
        seal_reply(&reply_of(&sender), MIN_REPLY_LEN - 1, &secret),
        Err(E::ReplyMetadataLength { .. })
    ));
    let sealed = seal_reply(&reply_of(&sender), MIN_REPLY_LEN + 8, &secret).unwrap();
    assert!(open_reply(&sealed, &secret).unwrap().is_some());
    let mut tampered = sealed;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(open_reply(&tampered, &secret).unwrap().is_none());
}

#[test]
fn a_reply_of_a_zero_or_non_canonical_viewing_key_opens_nothing() {
    let reply = reply_of(&address(&keypair(1)));
    let secret = SlotSecret::new([3; 32]).unwrap();
    let sealed = seal_reply(&reply, MIN_REPLY_LEN, &secret).unwrap();
    let held = reply.viewing_key.u();
    let claimed = |viewing_u: [u8; 32]| {
        let mut forged = sealed.clone();
        for (byte, (held, claimed)) in forged.iter_mut().zip(held.iter().zip(viewing_u)) {
            *byte ^= held ^ claimed;
        }
        open_reply(&forged, &secret).unwrap()
    };
    assert!(claimed(held).is_some());
    assert!(claimed([0; 32]).is_none());
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    assert!(claimed(modulus).is_none());
}

/// One label per kind, a reply never restarts the body's counter under one slot secret.
#[test]
fn a_body_and_a_reply_under_one_secret_read_different_keystreams() {
    let sender = address(&keypair(1));
    let secret = SlotSecret::new([3; 32]).unwrap();
    let zero_body = RecipientBody::default();
    let body = seal_recipient_body(&zero_body, &secret).unwrap();
    let reply = seal_reply(&reply_of(&sender), MIN_REPLY_LEN, &secret).unwrap();
    let head = reply_of(&sender);
    let keystream = |index: usize, plain: u8| reply[index] ^ plain;
    assert_ne!(
        (0..32)
            .map(|index| keystream(index, head.viewing_key.u()[index]))
            .collect::<Vec<_>>(),
        body[..32],
    );
    assert_eq!(RECIPIENT_BODY_LEN, body.len());
}

#[test]
fn a_bundle_of_another_length_than_the_frame_counts_is_refused() {
    let secret = SlotSecret::new([3; 32]).unwrap();
    let layout = BundleLayout {
        outputs: 2,
        change: 1,
    };
    assert!(matches!(
        open_sender_bundle(&[0; 112], &secret, layout),
        Err(E::SenderBundleLength { len: 112 })
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
        anonymous(tx_key, AnonymousPlan::new()).encrypt(tx, &address(&sender)),
        Err(E::RingSenderExit { slot_index: 1 })
    ));
}

#[test]
fn an_exit_publishes_scheme_3_under_its_owner_tag() {
    let sender = keypair(1);
    let exit = address(&keypair(3));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_with_ring(&exit, Mint::SOL, 2, None).unwrap();
    let rail = anonymous(tx_key, AnonymousPlan::new());
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert_eq!(published[1].anonymous, Some(AnonymousSlot::Exit));
    assert!(matches!(published[1].body, SlotBody::Exit(_)));
    assert_eq!(
        proof.external_data.outputs[1].owner_tag,
        OwnerTag::Inline(exit.signing_pubkey.confidential_view_tag().unwrap())
    );
    let sent = bundle(&sender.viewing_key, &rail, &proof);
    assert!(
        sent.recipient_keys.iter().all(|key| *key == [0; 32]),
        "an exit's owner reads no shared tag and is never listed"
    );
}

#[test]
fn an_exit_publishes_its_memo_on_both_rails() {
    let sender = keypair(1);
    let exit = address(&keypair(3));
    for delivery in [
        RingDelivery::Delivered,
        RingDelivery::Anonymous(Box::new(AnonymousPlan::new())),
    ] {
        let output = SppProofOutputUtxo::new(Mint::SOL, 2, exit)
            .unwrap()
            .with_memo(vec![1]);
        let frame = pay(&sender, output, delivery);
        let published = frame
            .rail
            .published_slots(&frame.proof, &address(&sender))
            .unwrap();
        assert!(matches!(
            published[frame.position].body,
            SlotBody::Exit(payload) if payload.len() > CONFIDENTIAL_DATA_FREE_BODY_LEN
        ));
    }
}

#[test]
fn an_anonymous_ring_output_to_another_owner_needs_a_planned_payment() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    assert!(matches!(
        anonymous(tx_key, AnonymousPlan::new()).encrypt(tx, &address(&sender)),
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
    let rail = anonymous(tx_key, AnonymousPlan::new().with_payment(payment(&other)));
    assert!(matches!(
        rail.encrypt(tx, &address(&sender)),
        Err(E::RingPaymentSlot { slot_index: 1 })
    ));
}

#[test]
fn a_dataless_delivered_slot_takes_the_plain_body_length() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (tx, tx_key) = ring_transfer(&sender, false);
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered);
    let mut tx = tx
        .with_blinding_seed(rail.blinding_seed().unwrap())
        .unwrap();
    tx.transfer_sol(&recipient, 3).unwrap();
    tx.pad_utxos(Shape::IN1_OUT4, &address(&sender)).unwrap();
    let proof = rail.encrypt(tx, &address(&sender)).unwrap();
    let published = rail.published_slots(&proof, &address(&sender)).unwrap();
    assert!(published.iter().any(|slot| slot.output.is_dummy()));
    for slot in &published {
        assert!(matches!(
            slot.body,
            SlotBody::Recipient(body) if body.len() == RECIPIENT_BODY_LEN
        ));
    }
}

#[test]
fn a_dummy_preimage_is_a_canonical_field_value_with_a_free_top_byte() {
    let mut top_bytes = std::collections::BTreeSet::new();
    for _ in 0..256 {
        let preimage = random_tag_preimage();
        assert!(is_canonical_bn254_scalar_be(&preimage));
        top_bytes.insert(preimage[0]);
    }
    assert!(
        top_bytes.len() > 1,
        "a zero led sampler would mark every dummy"
    );
}

/// A frame whose tag differs from its slot's derivation never reaches a proof.
#[test]
fn a_published_tag_other_than_the_slots_own_is_refused_at_build() {
    let sender = keypair(1);
    let recipient = address(&keypair(2));
    let (mut tx, tx_key) = ring_transfer(&sender, false);
    tx.transfer_sol(&recipient, 3).unwrap();
    let rail = anonymous(
        tx_key,
        AnonymousPlan::new().with_payment(payment(&recipient)),
    );
    let sealed = rail.encrypt(tx, &address(&sender)).unwrap();
    for (slot, tag) in [(0, [1; 32]), (1, recipient.viewing_pubkey.u())] {
        let mut forged = sealed.clone();
        forged.external_data.outputs[slot].owner_tag = OwnerTag::Inline(tag);
        assert!(
            matches!(
                rail.published_slots(&forged, &address(&sender)),
                Err(E::RingOutputFraming { slot_index }) if slot_index == slot
            ),
            "{slot}"
        );
    }
    let mut forged = sealed.clone();
    forged.external_data.messages[0].view_tag = [1; 32];
    assert!(matches!(
        rail.published_sender(&forged, &address(&sender).viewing_pubkey),
        Err(E::SenderBundleFraming)
    ));
}

#[test]
fn a_body_with_data_under_a_zero_hash_opens_nothing() {
    let owner = keypair(1);
    let owner_address = address(&owner);
    let utxo = Utxo {
        owner: owner_address.signing_pubkey,
        asset: Mint::SOL,
        amount: 5,
        blinding: [7; 32],
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let hash = utxo
        .hash(&owner_address.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let assets = RingAssets::new([]).unwrap();
    let output = AnonymousOutput {
        owner: &owner_address,
        assets: &assets,
        ring: RING,
        tree_id: TREE,
        utxo_hash: &hash,
    };
    let body = |data: Vec<u8>| RecipientBody {
        blinding: [7; 32],
        amount: 5,
        mint: Mint::SOL.asset.to_bytes(),
        ring_data_hash: None,
        data,
    };
    assert!(output.open_body(&body(Vec::new())).unwrap().is_some());
    let forged = [&[0u8; 32][..], b"unbound"].concat();
    assert_eq!(output.open_body(&body(forged)).unwrap(), None);
}

#[test]
fn a_memo_on_a_ring_output_is_refused_on_both_rails() {
    let owner = keypair(1);
    let recipient = address(&keypair(2));
    let sender = address(&owner);
    let transaction = |memo: bool| {
        let (mut tx, _) = ring_spend(&owner, vec![input(&owner, Mint::SOL, 10, 0)], false);
        let output = SppProofOutputUtxo {
            owner_address: Some(recipient),
            asset: Mint::SOL,
            amount: 4,
            ring_program_id: Some(RING),
            ..Default::default()
        };
        let output = match memo {
            true => output.with_memo(b"lost".to_vec()),
            false => output,
        };
        tx.add_output_utxo(output).unwrap();
        tx
    };
    for memo in [false, true] {
        let delivered = RingOutputRail::new(ViewingKey::new(), RingDelivery::Delivered)
            .encrypt(transaction(memo), &sender);
        let plan = AnonymousPlan::new().with_payment(recipient.viewing_pubkey);
        let hidden =
            RingOutputRail::new(ViewingKey::new(), RingDelivery::Anonymous(Box::new(plan)))
                .encrypt(transaction(memo), &sender);
        for sealed in [delivered, hidden] {
            match memo {
                true => assert!(matches!(
                    sealed,
                    Err(zolana_ring_transaction::RingRailError::OutputDataNotCarried { .. })
                )),
                false => assert!(sealed.is_ok()),
            }
        }
    }
}

#[test]
fn single_asset_payout_delivers_every_compact_opening() {
    use custom_ring_interface::{ring_body_format, DisclosureFormat, SINGLE_ASSET_PAYOUT_OUTPUTS};
    use zolana_ring_transaction::open_compact_recipient_body;

    let sender = keypair(1);
    let recipients: Vec<_> = (0..SINGLE_ASSET_PAYOUT_OUTPUTS)
        .map(|index| keypair(10 + index as u8))
        .collect();
    let (mut transaction, tx_key) = ring_spend(
        &sender,
        vec![input(&sender, USDC, SINGLE_ASSET_PAYOUT_OUTPUTS as u64, 1)],
        false,
    );
    for recipient in &recipients {
        transaction
            .transfer_with_ring(&address(recipient), USDC, 1, Some(RING))
            .unwrap();
    }
    let rail = RingOutputRail::new(tx_key, RingDelivery::Delivered)
        .with_format(DisclosureFormat::SingleAssetPayout);
    let proof = rail.encrypt(transaction, &address(&sender)).unwrap();
    assert_eq!(
        proof.external_data.outputs.len(),
        SINGLE_ASSET_PAYOUT_OUTPUTS
    );
    for (index, recipient) in recipients.iter().enumerate() {
        let data = proof.external_data.outputs[index].data.as_ref().unwrap();
        assert_eq!(
            ring_body_format(data),
            Some(DisclosureFormat::SingleAssetPayout)
        );
        let (ciphertext, reply) = ring_body_output(data).unwrap();
        assert!(reply.is_empty());
        let secret = delivered_secret(&recipient.viewing_key, &proof, &rail, index as u32);
        let body = open_compact_recipient_body(ciphertext, &secret).unwrap();
        assert_eq!(body.asset_id, USDC.asset_id);
        assert_eq!(body.amount, 1);
        assert_eq!(body.blinding, proof.output_utxos[index].blinding);
        let opened = reader(
            &address(recipient),
            &RingAssets::new([USDC]).unwrap(),
            &proof,
            index,
        )
        .open_body(&RecipientBody {
            blinding: body.blinding,
            amount: body.amount,
            mint: USDC.asset.to_bytes(),
            ..RecipientBody::default()
        })
        .unwrap();
        assert!(matches!(opened, Some(OpenedBody::Note(_))));
    }
    let mut wrong_asset = proof.clone();
    wrong_asset.output_utxos[0].asset = Mint::SOL;
    assert!(matches!(
        rail.check_format(&wrong_asset),
        Err(E::PayoutProfile)
    ));
    let mut data = proof.clone();
    data.output_utxos[0].data_hash = Some(DATA_HASH);
    assert!(matches!(rail.check_format(&data), Err(E::PayoutProfile)));
}

#[test]
fn data_padding_hides_real_ring_body_lengths_on_both_rails() {
    let sender = keypair(1);
    let receiver = keypair(2);
    for delivery in both_rails(&address(&receiver)) {
        let (mut transaction, tx_key) = ring_transfer(&sender, false);
        transaction
            .add_output_utxo(data_note(address(&receiver)))
            .unwrap();
        let rail = RingOutputRail::new(tx_key, delivery);
        let mut transaction = transaction
            .with_blinding_seed(rail.blinding_seed().unwrap())
            .unwrap();
        transaction
            .pad_utxos(Shape::new(1, 8), &address(&sender))
            .unwrap();
        let proof = rail.encrypt(transaction, &address(&sender)).unwrap();
        let slots = rail.published_slots(&proof, &address(&sender)).unwrap();
        let widths: Vec<_> = slots
            .iter()
            .filter_map(|slot| match slot.body {
                SlotBody::Recipient(body) => Some(body.len()),
                _ => None,
            })
            .collect();
        assert!(widths.len() > 1);
        assert!(widths.iter().all(|width| *width == widths[0]));
        assert!(widths[0] > RECIPIENT_BODY_LEN);
        let index = proof
            .output_utxos
            .iter()
            .position(|output| output.owner_address == Some(address(&receiver)))
            .unwrap();
        assert_eq!(
            decrypt(
                &receiver.viewing_key,
                &rail,
                &proof,
                &slots[index],
                index as u32
            )
            .data,
            [&DATA_HASH[..], &APP_DATA[..]].concat()
        );
    }
}
