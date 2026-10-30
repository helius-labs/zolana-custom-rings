//! Pins `test-vectors/wallet/anonymous-bodies.json` for the TS SDK, one sealed four-output transfer.

use custom_ring_interface::blinding::ring_blinding_seed;
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_keypair::{
    viewing_key::ViewTag, PublicKey, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
    X25519Pubkey,
};
use spr_transaction::{Mint, SppProofOutputUtxo, Utxo};

use crate::{
    anonymous_rail::AnonymousSeal, AnonymousOutput, AnonymousSlot,
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, OutputBlindings,
    RingAssets, TaggedPayment, DUMMY_RECIPIENT_VIEWING_PK, RECIPIENT_BODY_LEN,
};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/wallet/anonymous-bodies.json"
);
const RING: Address = Address::new_from_array([0x2a; 32]);
const TREE: u16 = 3;
const USDC: Mint = Mint {
    asset: Address::new_from_array([9; 32]),
    asset_id: 2,
};
const SALT: [u8; 16] = [0x5c; 16];
const FIRST_NULLIFIER: [u8; 32] = [0x0f; 32];
const DUMMY_TAG: ViewTag = {
    let mut tag = [0xd7; 32];
    tag[0] = 0;
    tag
};
const DUMMY_BODY: [u8; RECIPIENT_BODY_LEN] = [0xb3; RECIPIENT_BODY_LEN];

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Vectors {
    description: String,
    ring_program_id: String,
    tree_id: u16,
    /// Registered beside SOL.
    mints: Vec<MintJson>,
    salt: String,
    first_nullifier: String,
    tx_viewing_pk: String,
    blinding_seed: String,
    sender: Party,
    recipients: Vec<Party>,
    outputs: Vec<OutputCase>,
    sender_bundle: BundleCase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Party {
    ed25519_seed: String,
    viewing_secret: String,
    viewing_pubkey: String,
    owner_pubkey: String,
    nullifier_pubkey: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct MintJson {
    asset: String,
    asset_id: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    position: u32,
    tag: String,
    utxo_hash: String,
    /// Absent on a change output.
    ciphertext: Option<String>,
    /// Absent on the change and the dummy.
    opened: Option<Opened>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Opened {
    sealed_to: String,
    plaintext: String,
    owner_pubkey: String,
    sender_pubkey: String,
    mint: MintJson,
    amount: u64,
    blinding: String,
    rebuilt_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct BundleCase {
    tag: String,
    slot_index: u32,
    ciphertext: String,
    plaintext: String,
    recipient_viewing_pks: Vec<String>,
    output_seed: String,
    change: Vec<ChangeCase>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ChangeCase {
    position: u32,
    mint: MintJson,
    amount: u64,
    blinding: String,
    rebuilt_hash: String,
}

struct Fixture {
    sender: ShieldedKeypair,
    recipients: [ShieldedKeypair; 2],
    tx_viewing_key: ViewingKey,
    blinding_seed: [u8; 32],
    assets: RingAssets,
}

impl Fixture {
    fn new() -> Self {
        let sender = keypair(1);
        let tx_viewing_key = sender
            .viewing_key
            .get_transaction_viewing_key(&FIRST_NULLIFIER)
            .unwrap();
        let blinding_seed = ring_blinding_seed(&tx_viewing_key.secret_bytes(), &SALT).unwrap();
        Self {
            sender,
            recipients: [keypair(2), keypair(3)],
            tx_viewing_key,
            blinding_seed,
            assets: RingAssets::new([USDC]).unwrap(),
        }
    }

    fn address(keys: &ShieldedKeypair) -> ShieldedAddress {
        keys.shielded_address().unwrap()
    }

    /// Change at 0, a bootstrap payment, a shared payment, a dummy.
    fn outputs(&self) -> Vec<SppProofOutputUtxo> {
        let blindings = OutputBlindings::new(&FIRST_NULLIFIER, &self.blinding_seed).unwrap();
        let [bob, carol] = &self.recipients;
        [
            (Some(Self::address(&self.sender)), Mint::SOL, 70),
            (Some(Self::address(bob)), USDC, 20),
            (Some(Self::address(carol)), Mint::SOL, 10),
            (None, Mint::SOL, 0),
        ]
        .into_iter()
        .zip(0u32..)
        .map(
            |((owner_address, asset, amount), position)| SppProofOutputUtxo {
                asset,
                amount,
                blinding: blindings.at(position).unwrap(),
                ring_program_id: owner_address.map(|_| RING),
                owner_address,
                ..Default::default()
            },
        )
        .collect()
    }

    fn slots(&self) -> [AnonymousSlot; 4] {
        let [bob, carol] = &self.recipients;
        let sender = &self.sender.viewing_key;
        [
            AnonymousSlot::Change {
                tag: sender.get_sender_view_tag(0).unwrap(),
            },
            AnonymousSlot::Payment(TaggedPayment {
                recipient: bob.viewing_pubkey(),
                tag: bob.viewing_key.recipient_bootstrap_view_tag(),
            }),
            AnonymousSlot::Payment(TaggedPayment {
                recipient: carol.viewing_pubkey(),
                tag: sender
                    .get_send_shared_view_tag(&carol.viewing_pubkey(), 0)
                    .unwrap(),
            }),
            AnonymousSlot::Dummy { tag: DUMMY_TAG },
        ]
    }
}

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn party(seed: u8) -> Party {
    let keys = keypair(seed);
    let address = Fixture::address(&keys);
    Party {
        ed25519_seed: hex::encode([seed; 32]),
        viewing_secret: hex::encode(*keys.viewing_key.secret_bytes()),
        viewing_pubkey: hex::encode(address.viewing_pubkey.as_bytes()),
        owner_pubkey: hex::encode(address.signing_pubkey.as_bytes()),
        nullifier_pubkey: hex::encode(address.nullifier_pubkey),
    }
}

fn mint_json(mint: Mint) -> MintJson {
    MintJson {
        asset: hex::encode(mint.asset.as_array()),
        asset_id: mint.asset_id,
    }
}

fn reader_output<'a>(
    owner: &'a ShieldedAddress,
    assets: &'a RingAssets,
    utxo_hash: &'a [u8; 32],
) -> AnonymousOutput<'a> {
    AnonymousOutput {
        owner,
        assets,
        ring: RING,
        tree_id: TREE,
        utxo_hash,
    }
}

/// Opens one recipient body as its reader does and rebuilds the published hash.
fn open(
    fixture: &Fixture,
    reader: &ShieldedKeypair,
    position: u32,
    ciphertext: &[u8],
    utxo_hash: &[u8; 32],
) -> Opened {
    let plaintext = reader
        .viewing_key
        .decrypt_utxo(ciphertext, &fixture.tx_viewing_key.pubkey(), SALT, position)
        .unwrap();
    let owner = Fixture::address(reader);
    let note = AnonymousTransferRecipientPlaintext::deserialize(&plaintext).unwrap();
    let sender_pubkey = hex::encode(note.unverified.sender_pubkey.as_bytes());
    let utxo = reader_output(&owner, &fixture.assets, utxo_hash)
        .open_recipient(note)
        .unwrap()
        .unwrap();
    Opened {
        sealed_to: hex::encode(owner.viewing_pubkey.as_bytes()),
        plaintext: hex::encode(&plaintext),
        owner_pubkey: hex::encode(utxo.owner.as_bytes()),
        sender_pubkey,
        mint: mint_json(utxo.asset),
        amount: utxo.amount,
        blinding: hex::encode(utxo.blinding),
        rebuilt_hash: hex::encode(rebuilt_hash(&utxo, &owner)),
    }
}

fn rebuilt_hash(utxo: &Utxo, owner: &ShieldedAddress) -> [u8; 32] {
    utxo.hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap()
}

fn compute_vectors() -> Vectors {
    let fixture = Fixture::new();
    let outputs = fixture.outputs();
    let slots = fixture.slots();
    let sender = Fixture::address(&fixture.sender);
    let seal = AnonymousSeal {
        tx_viewing_key: &fixture.tx_viewing_key,
        salt: SALT,
        sender: &sender,
        outputs: &outputs,
        slots: &slots,
    };
    let hashes: Vec<[u8; 32]> = outputs
        .iter()
        .map(|output| output.hash(TREE).unwrap())
        .collect();
    let cases = slots
        .iter()
        .zip(&hashes)
        .enumerate()
        .map(|(index, (slot, utxo_hash))| {
            let position = u32::try_from(index).unwrap();
            let ciphertext = match (slot, seal.body(index).unwrap()) {
                (AnonymousSlot::Dummy { .. }, Some(sealed)) => {
                    assert_eq!(sealed.len(), RECIPIENT_BODY_LEN);
                    Some(DUMMY_BODY.to_vec())
                }
                (_, sealed) => sealed,
            };
            let opened = match (slot, &ciphertext) {
                (AnonymousSlot::Payment(_), Some(ciphertext)) => Some(open(
                    &fixture,
                    &fixture.recipients[index - 1],
                    position,
                    ciphertext,
                    utxo_hash,
                )),
                _ => None,
            };
            OutputCase {
                position,
                tag: hex::encode(slot.tag().unwrap()),
                utxo_hash: hex::encode(utxo_hash),
                ciphertext: ciphertext.map(hex::encode),
                opened,
            }
        })
        .collect();
    let blindings = OutputBlindings::new(&FIRST_NULLIFIER, &fixture.blinding_seed).unwrap();
    let ciphertext = seal.sender_bundle(&blindings).unwrap();
    let slot_index = u32::try_from(outputs.len()).unwrap();
    let plaintext = fixture
        .sender
        .viewing_key
        .decrypt_utxo(
            &ciphertext,
            &fixture.tx_viewing_key.pubkey(),
            SALT,
            slot_index,
        )
        .unwrap();
    let bundle = AnonymousTransferSenderPlaintext::deserialize(&plaintext).unwrap();
    let recipient_viewing_pks = bundle
        .verified
        .recipient_viewing_pks
        .iter()
        .map(|key| hex::encode(key.as_bytes()))
        .collect();
    let change = reader_output(&sender, &fixture.assets, &hashes[0])
        .sender_change(bundle, &FIRST_NULLIFIER)
        .unwrap()
        .iter()
        .zip(0u32..)
        .map(|(utxo, position)| ChangeCase {
            position,
            mint: mint_json(utxo.asset),
            amount: utxo.amount,
            blinding: hex::encode(utxo.blinding),
            rebuilt_hash: hex::encode(rebuilt_hash(utxo, &sender)),
        })
        .collect();
    Vectors {
        description: "One anonymous transfer sealed by zolana-ring-transaction, change at output \
                      0, a bootstrap payment, a shared payment and a dummy. The transaction \
                      viewing key derives from the sender's viewing key and first_nullifier, \
                      every recipient body is sealed to its reader at its output position under \
                      the salt, the change output carries no body, and the zolana scheme 2 \
                      sender bundle is sealed to the sender at the output count. Blindings are \
                      TXOB(first_nullifier, output_seed, position) with output_seed = \
                      TXOS(first_nullifier, blinding_seed), the bundle publishing output_seed. \
                      Bodies are the zolana anonymous plaintexts, verified fields then \
                      unverified ones, the bundle listing one key per output after the change \
                      and 0x04 || 0^32 for the dummy. The dummy body is fixed here, random on \
                      chain. Produced by sdk-libs/transaction/src/tests/anonymous_bodies.rs."
            .to_string(),
        ring_program_id: hex::encode(RING.as_array()),
        tree_id: TREE,
        mints: vec![mint_json(USDC)],
        salt: hex::encode(SALT),
        first_nullifier: hex::encode(FIRST_NULLIFIER),
        tx_viewing_pk: hex::encode(fixture.tx_viewing_key.pubkey().as_bytes()),
        blinding_seed: hex::encode(fixture.blinding_seed),
        sender: party(1),
        recipients: vec![party(2), party(3)],
        outputs: cases,
        sender_bundle: BundleCase {
            tag: hex::encode(fixture.sender.viewing_key.get_sender_view_tag(0).unwrap()),
            slot_index,
            ciphertext: hex::encode(&ciphertext),
            plaintext: hex::encode(&plaintext),
            recipient_viewing_pks,
            output_seed: hex::encode(blindings.output_seed()),
            change,
        },
    }
}

fn committed() -> Vectors {
    serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
        .expect("vector json")
}

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    hex::decode(text).unwrap().try_into().unwrap()
}

#[test]
fn anonymous_bodies_vector() {
    assert_eq!(committed(), compute_vectors());
}

/// Reads the committed bytes alone, as the TS mirror does.
#[test]
fn the_committed_bodies_decode_and_rebuild_their_hashes() {
    let vectors = committed();
    let first_nullifier = bytes(&vectors.first_nullifier);
    let salt = bytes(&vectors.salt);
    let ring = Address::new_from_array(bytes(&vectors.ring_program_id));
    let assets = RingAssets::new(vectors.mints.iter().map(|mint| Mint {
        asset: Address::new_from_array(bytes(&mint.asset)),
        asset_id: mint.asset_id,
    }))
    .unwrap();
    let parties: Vec<(ViewingKey, ShieldedAddress)> = std::iter::once(&vectors.sender)
        .chain(&vectors.recipients)
        .map(|party| {
            let viewing_key = ViewingKey::from_bytes(&bytes(&party.viewing_secret));
            let address = ShieldedAddress {
                signing_pubkey: PublicKey::from_bytes(bytes(&party.owner_pubkey)).unwrap(),
                nullifier_pubkey: bytes(&party.nullifier_pubkey),
                viewing_pubkey: X25519Pubkey::from_bytes(bytes(&party.viewing_pubkey)).unwrap(),
            };
            assert_eq!(viewing_key.pubkey(), address.viewing_pubkey);
            (viewing_key, address)
        })
        .collect();
    let tx_viewing_key = parties[0]
        .0
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    assert_eq!(
        hex::encode(tx_viewing_key.pubkey().as_bytes()),
        vectors.tx_viewing_pk
    );
    let blinding_seed = ring_blinding_seed(&tx_viewing_key.secret_bytes(), &salt).unwrap();
    assert_eq!(hex::encode(blinding_seed), vectors.blinding_seed);
    let output = |owner, utxo_hash| AnonymousOutput {
        owner,
        assets: &assets,
        ring,
        tree_id: vectors.tree_id,
        utxo_hash,
    };
    let hashes: Vec<[u8; 32]> = vectors
        .outputs
        .iter()
        .map(|case| bytes(&case.utxo_hash))
        .collect();
    for (case, utxo_hash) in vectors.outputs.iter().zip(&hashes) {
        let Some(ciphertext) = &case.ciphertext else {
            assert!(case.opened.is_none());
            continue;
        };
        let ciphertext = hex::decode(ciphertext).unwrap();
        let Some(opened) = &case.opened else {
            assert_eq!(ciphertext.len(), RECIPIENT_BODY_LEN);
            assert_eq!(case.tag.get(..2), Some("00"));
            continue;
        };
        let (viewing_key, owner) = parties
            .iter()
            .find(|(_, address)| hex::encode(address.viewing_pubkey.as_bytes()) == opened.sealed_to)
            .unwrap();
        let plaintext = viewing_key
            .decrypt_utxo(&ciphertext, &tx_viewing_key.pubkey(), salt, case.position)
            .unwrap();
        assert_eq!(hex::encode(&plaintext), opened.plaintext);
        let sent = tx_viewing_key
            .decrypt_slot_ephemeral(&owner.viewing_pubkey, &ciphertext, salt, case.position)
            .unwrap();
        assert_eq!(sent, plaintext, "the sender reads its own payment");
        let note = AnonymousTransferRecipientPlaintext::deserialize(&plaintext).unwrap();
        assert_eq!(note.unverified.sender_pubkey, parties[0].1.viewing_pubkey);
        let utxo = output(owner, utxo_hash)
            .open_recipient(note)
            .unwrap()
            .unwrap();
        assert_eq!(utxo.amount, opened.amount);
        assert_eq!(hex::encode(utxo_hash), opened.rebuilt_hash);
        assert_eq!(mint_json(utxo.asset), opened.mint);
    }
    let bundle = &vectors.sender_bundle;
    assert_eq!(bundle.slot_index as usize, vectors.outputs.len());
    let plaintext = parties[0]
        .0
        .decrypt_utxo(
            &hex::decode(&bundle.ciphertext).unwrap(),
            &tx_viewing_key.pubkey(),
            salt,
            bundle.slot_index,
        )
        .unwrap();
    assert_eq!(hex::encode(&plaintext), bundle.plaintext);
    let plaintext = AnonymousTransferSenderPlaintext::deserialize(&plaintext).unwrap();
    let blindings = OutputBlindings::new(&first_nullifier, &blinding_seed).unwrap();
    assert_eq!(&plaintext.unverified.blinding_seed, blindings.output_seed());
    let listed: Vec<X25519Pubkey> = parties[1..]
        .iter()
        .map(|(_, address)| address.viewing_pubkey)
        .chain([X25519Pubkey::from_bytes(DUMMY_RECIPIENT_VIEWING_PK).unwrap()])
        .collect();
    assert_eq!(plaintext.verified.recipient_viewing_pks, listed);
    let sender = &parties[0].1;
    let change = output(sender, &hashes[0])
        .sender_change(plaintext, &first_nullifier)
        .unwrap();
    assert_eq!(change.len(), bundle.change.len());
    for (utxo, case) in change.iter().zip(&bundle.change) {
        let position = case.position as usize;
        assert!(output(sender, &hashes[position]).rebuilds(utxo));
        assert_eq!(hex::encode(utxo.blinding), case.blinding);
        assert_eq!(utxo.blinding, blindings.at(case.position).unwrap());
    }
}

#[test]
#[ignore = "rewrites test-vectors/wallet/anonymous-bodies.json"]
fn write_anonymous_bodies_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
