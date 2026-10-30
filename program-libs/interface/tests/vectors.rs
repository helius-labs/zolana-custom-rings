//! Pins `test-vectors/wallet/ring-secrets.json` for the Go circuits and the TS SDK.

use std::collections::BTreeSet;

use custom_ring_interface::blinding::ring_blinding_seed;
use custom_ring_interface::{
    domain,
    stream::{DeliveredSlot, SenderCommitment, SlotSecret},
};
use serde_json::{json, Value};
use spr_hasher::primitives::solana_owner_identity;
use spr_instruction::derivation::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};
use spr_keypair::X25519Keypair;

const RING_SECRETS_JSON: &str = include_str!("../../../test-vectors/wallet/ring-secrets.json");

const OUTPUT_INDEXES: [u32; 3] = [0, 1, 15];

#[test]
fn ring_derivation_vectors() {
    assert_eq!(
        committed(RING_SECRETS_JSON),
        Scenario::new().secret_vectors()
    );
}

#[test]
fn domains_are_their_ascii_tags() {
    let table: [(u32, &[u8; 4]); 15] = [
        (domain::AUDIT_STATEMENT, b"CRAU"),
        (domain::DELIVERED_SLOT_SECRET, b"CRDS"),
        (domain::BLINDING_SEED, b"CRBS"),
        (domain::SENDER_COMMITMENT, b"CRSC"),
        (domain::DISCLOSURE_PAD, b"CROD"),
        (domain::POLICY_STATEMENT, b"CRPO"),
        (domain::POLICY_TABLE, b"CRTB"),
        (domain::QUEUE_WRITE, b"CRQW"),
        (domain::APPLY_RECORDS, b"CRAP"),
        (domain::REGISTER_KEY, b"CRRG"),
        (domain::DEPOSIT_BLINDING, b"CRDB"),
        (domain::DEPOSIT_STATEMENT, b"CRDP"),
        (domain::MERGE_STATEMENT, b"CRMG"),
        (domain::WITHDRAWALS, b"CRPW"),
        (domain::WITHDRAWAL_EXEMPTION, b"CRWX"),
    ];
    for (value, ascii) in table {
        assert_eq!(
            value,
            u32::from_be_bytes(*ascii),
            "{}",
            String::from_utf8_lossy(ascii)
        );
    }
    let kept = [
        DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
        DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
        DOMAIN_PRIVATE_TX_BLINDING_V1,
    ];
    let distinct: BTreeSet<u32> = table.iter().map(|(value, _)| *value).chain(kept).collect();
    assert_eq!(distinct.len(), table.len() + kept.len());
}

#[test]
#[ignore = "regenerates test-vectors/wallet/ring-secrets.json, run with --nocapture and commit the output"]
fn print_ring_secret_vectors() {
    let vectors = Scenario::new().secret_vectors();
    println!("{}", serde_json::to_string_pretty(&vectors).expect("json"));
}

struct Scenario {
    tx_viewing_secret: [u8; 32],
    recipient_viewing_secret: [u8; 32],
    salt: [u8; 16],
    first_nullifier: [u8; 32],
    sender_key: [u8; 32],
    deposit_blinding_secret: [u8; 32],
}

impl Scenario {
    fn new() -> Self {
        let mut tx_viewing_secret = pattern(0x17);
        tx_viewing_secret[0] &= 248;
        tx_viewing_secret[31] = (tx_viewing_secret[31] & 127) | 64;
        Self {
            tx_viewing_secret,
            recipient_viewing_secret: pattern(0x5c),
            salt: pattern(0x3e),
            first_nullifier: field(0x2b),
            sender_key: pattern(0x61),
            deposit_blinding_secret: field(0x08),
        }
    }

    fn secret_vectors(&self) -> Value {
        let blinding_seed = self.blinding_seed();
        let output_blinding_seed =
            derive_output_blinding_seed(&self.first_nullifier, &blinding_seed)
                .expect("output blinding seed");
        let outputs: Vec<Value> = OUTPUT_INDEXES
            .into_iter()
            .map(|output_index| {
                let delivered = self.delivered_secret(output_index);
                let blinding = derive_transact_output_blinding(
                    &self.first_nullifier,
                    &output_blinding_seed,
                    output_index,
                )
                .expect("output blinding");
                json!({
                    "output_index": output_index,
                    "delivered_slot_secret": hex::encode(delivered.as_bytes()),
                    "blinding": hex::encode(blinding),
                })
            })
            .collect();
        let sender_pk_hash = solana_owner_identity(&self.sender_key).expect("sender pk hash");
        let private_tx_blinding = derive_private_tx_blinding(&self.first_nullifier, &blinding_seed)
            .expect("private tx blinding");
        let sender_commitment = SenderCommitment {
            sender_pk_hash,
            private_tx_blinding,
        }
        .derive()
        .expect("sender commitment");
        let deposit_blinding =
            domain::deposit_blinding(&self.deposit_blinding_secret).expect("deposit blinding");
        json!({
            "description": "Ring output blindings of one transaction. blinding_seed is \
                Poseidon(CRBS, pack_be(tx_viewing_secret), salt), every output blinding \
                Poseidon(TXOB, first_nullifier, output_blinding_seed, output_index) with \
                output_blinding_seed = Poseidon(TXOS, first_nullifier, blinding_seed). A \
                delivered slot secret is Poseidon(CRDS, pack_be(agreement), pack_be(tx_viewing_pk), \
                pack_be(recipient_viewing_pk), salt, output_index, first_nullifier) with agreement \
                = X25519(tx_viewing_secret, recipient_viewing_pk). The deposit blinding is Poseidon(CRDB, deposit_blinding_secret). The sender commitment is \
                Poseidon(CRSC, sender_pk_hash, private_tx_blinding) with sender_pk_hash = \
                owner_identity(sender_key) and private_tx_blinding = Poseidon(TXPB, \
                first_nullifier, blinding_seed). Produced by \
                program-libs/interface/tests/vectors.rs print_ring_secret_vectors.",
            "tx_viewing_secret": hex::encode(self.tx_viewing_secret),
            "tx_viewing_pk": hex::encode(self.tx_viewing_pk()),
            "recipient_viewing_secret": hex::encode(self.recipient_viewing_secret),
            "recipient_viewing_pk": hex::encode(self.recipient_viewing_pk()),
            "agreement": hex::encode(self.agreement()),
            "salt": hex::encode(self.salt),
            "first_nullifier": hex::encode(self.first_nullifier),
            "blinding_seed": hex::encode(blinding_seed),
            "output_blinding_seed": hex::encode(output_blinding_seed),
            "outputs": outputs,
            "sender_key": hex::encode(self.sender_key),
            "sender_pk_hash": hex::encode(sender_pk_hash),
            "private_tx_blinding": hex::encode(private_tx_blinding),
            "sender_commitment": hex::encode(sender_commitment),
            "deposit_blinding_secret": hex::encode(self.deposit_blinding_secret),
            "deposit_blinding": hex::encode(deposit_blinding),
        })
    }

    fn tx_viewing_pk(&self) -> [u8; 33] {
        *X25519Keypair::from_bytes(&self.tx_viewing_secret)
            .pubkey()
            .as_bytes()
    }

    fn recipient_viewing_pk(&self) -> [u8; 33] {
        *X25519Keypair::from_bytes(&self.recipient_viewing_secret)
            .pubkey()
            .as_bytes()
    }

    fn agreement(&self) -> [u8; 32] {
        let recipient = X25519Keypair::from_bytes(&self.recipient_viewing_secret).pubkey();
        *X25519Keypair::from_bytes(&self.tx_viewing_secret)
            .ecdh(&recipient)
            .expect("agreement")
    }

    fn delivered_secret(&self, output_index: u32) -> SlotSecret {
        DeliveredSlot {
            agreement: &self.agreement(),
            tx_viewing_pk: &self.tx_viewing_pk(),
            recipient_viewing_pk: &self.recipient_viewing_pk(),
            salt: &self.salt,
            output_index,
            first_nullifier: &self.first_nullifier,
        }
        .secret()
        .expect("delivered slot secret")
    }

    fn blinding_seed(&self) -> [u8; 32] {
        ring_blinding_seed(&self.tx_viewing_secret, &self.salt).expect("blinding seed")
    }
}

fn pattern<const N: usize>(seed: u8) -> [u8; N] {
    core::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(0x1d)))
}

/// Canonical, the top byte is zero.
fn field(seed: u8) -> [u8; 32] {
    let mut value = pattern(seed);
    value[0] = 0;
    value
}

fn committed(json: &str) -> Value {
    serde_json::from_str(json).expect("committed vector json")
}
