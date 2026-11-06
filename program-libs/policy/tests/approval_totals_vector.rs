//! Reads `test-vectors/policy/approval_totals.json`, the digests the transfer circuit binds.

use serde::Deserialize;
use zolana_ring_policy::{ApprovalTotals, DebitInput, DebitOutput, DebitTransfer, PublicGross};

const PUBLIC_SLOTS: usize = 3;

#[derive(Deserialize)]
struct Note {
    owner: u64,
    asset: u64,
    amount: u64,
    ring: bool,
}

#[derive(Deserialize)]
struct Public {
    asset: u64,
    gross: u128,
}

#[derive(Deserialize)]
struct Quantities {
    name: String,
    #[serde(default)]
    inputs: Vec<Note>,
    #[serde(default)]
    outputs: Vec<Note>,
    #[serde(default)]
    public: Vec<Public>,
}

#[derive(Deserialize)]
struct QuantityVector {
    cases: Vec<Quantities>,
}

#[derive(Deserialize)]
struct Digest {
    name: String,
    slots: usize,
    blinder: String,
    commitment: String,
}

#[derive(Deserialize)]
struct DigestVector {
    cases: Vec<Digest>,
}

fn identity(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn field(encoded: &str) -> [u8; 32] {
    hex::decode(encoded.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn every_digest_matches_the_circuit() {
    let quantities: QuantityVector =
        serde_json::from_str(include_str!("../../../test-vectors/policy/quantities.json")).unwrap();
    let digests: DigestVector = serde_json::from_str(include_str!(
        "../../../test-vectors/policy/approval_totals.json"
    ))
    .unwrap();
    assert_eq!(digests.cases.len(), quantities.cases.len());
    for (case, digest) in quantities.cases.iter().zip(&digests.cases) {
        assert_eq!(case.name, digest.name);
        let inputs: Vec<DebitInput> = case
            .inputs
            .iter()
            .map(|note| DebitInput {
                owner: identity(note.owner),
                asset: identity(note.asset),
                amount: note.amount,
            })
            .collect();
        let outputs: Vec<DebitOutput> = case
            .outputs
            .iter()
            .map(|note| DebitOutput {
                ring: note.ring,
                owner: identity(note.owner),
                asset: identity(note.asset),
                amount: note.amount,
            })
            .collect();
        let mut public_slots: Vec<PublicGross> = case
            .public
            .iter()
            .map(|public| PublicGross {
                asset: identity(public.asset),
                gross: public.gross,
            })
            .collect();
        let public_gross = public_slots.clone();
        public_slots.resize(
            PUBLIC_SLOTS,
            PublicGross {
                asset: [0; 32],
                gross: 0,
            },
        );
        let mut slot_assets: Vec<Option<[u8; 32]>> =
            outputs.iter().map(|output| Some(output.asset)).collect();
        slot_assets.resize(digest.slots, None);
        let senders: Vec<[u8; 32]> = inputs.iter().map(|input| input.owner).collect();
        let transfer = DebitTransfer {
            senders: &senders,
            assets: &[],
            inputs: &inputs,
            outputs: &outputs,
            public_gross: &public_gross,
        };
        let totals = ApprovalTotals::new(&transfer, &slot_assets, &public_slots);
        assert_eq!(
            totals.commitment(&field(&digest.blinder)).unwrap(),
            field(&digest.commitment),
            "{}",
            case.name
        );
    }
}
