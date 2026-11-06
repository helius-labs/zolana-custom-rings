//! Reads the vectors `prover/circuits` writes from its solved witnesses, a mismatch names a statement the keys refuse.

use custom_ring_interface::{
    cosign::ApprovalMask, domain, key_catalog::RING_KEYS, AuditHead, AuditLayout,
    ConfidentialSender, MergePublicInput, OpeningRecord, RecordKind, RingOutput, SignerDataCounts,
    SignerSet, SlotBody, TransferFamily, TransferRoots, TransferStatement, ANONYMOUS_PARTIES,
    DATA_TAIL_LEN,
};
use serde::Deserialize;
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};

fn vector<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/../../test-vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value.trim_start_matches("0x")).unwrap()
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn arrays<const N: usize>(values: &[String]) -> Vec<[u8; N]> {
    values.iter().map(|value| array(value)).collect()
}

/// The vector holds identities where `SignerSet::new` takes addresses, the chain rule is one.
fn signer_chain(identities: &[[u8; 32]], slots: usize) -> [u8; 32] {
    if identities.is_empty() {
        return [0; 32];
    }
    let mut cells = identities.to_vec();
    cells.resize(slots, [0; 32]);
    create_hash_chain_4_from_slice(&cells).unwrap()
}

#[derive(Deserialize)]
struct OutputCase {
    hash: String,
    record: String,
    #[serde(default)]
    tail: Option<String>,
}

#[derive(Deserialize)]
struct WithdrawalCase {
    owner: String,
    asset: String,
    amount: u64,
}

#[derive(Deserialize)]
struct TransferCase {
    name: String,
    family: String,
    in_proof: bool,
    public_owners: bool,
    delegate: bool,
    approval_mask: u8,
    approval_totals: String,
    signer_data_counts: u64,
    no_spend: bool,
    first_nullifier: String,
    ring_id: String,
    tx_viewing_u: String,
    auditor_pubkey: String,
    envelope: String,
    salt: String,
    layout: u8,
    output_capacity: usize,
    outputs: Vec<OutputCase>,
    input_count: usize,
    input_nullifier_chain: String,
    private_tx_hash: String,
    sender: Option<String>,
    party_identities: Option<Vec<String>>,
    #[serde(default)]
    signer_slots: usize,
    #[serde(default)]
    signers: Vec<String>,
    signer_count: usize,
    signer_chain: String,
    policy_hash: String,
    own_root: String,
    curator_root: String,
    tracking_root: String,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    public_gross: Vec<String>,
    #[serde(default)]
    withdrawals: Vec<WithdrawalCase>,
    withdrawal_hash: String,
    elements: Vec<String>,
    public_input_hash: String,
}

impl TransferCase {
    fn withdrawal_hash(&self) -> [u8; 32] {
        let mut fields = vec![
            domain::field(domain::WITHDRAWALS),
            right_align(&(self.withdrawals.len() as u64).to_be_bytes()),
        ];
        for leg in &self.withdrawals {
            fields.extend([
                array(&leg.owner),
                array(&leg.asset),
                right_align(&leg.amount.to_be_bytes()),
            ]);
        }
        create_hash_chain_4_from_slice(&fields).unwrap()
    }
}

/// Every position rebuilds from the preimages, through the final hash.
#[test]
fn transfer_statements_reach_the_go_public_inputs() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<TransferCase>,
    }
    let vector: Vector = vector("audit/transfer_statement.json");
    assert!(!vector.cases.is_empty());
    for case in &vector.cases {
        let hashes: Vec<[u8; 32]> = case.outputs.iter().map(|o| array(&o.hash)).collect();
        let records: Vec<Vec<u8>> = case
            .outputs
            .iter()
            .map(|o| hex::decode(o.record.trim_start_matches("0x")).unwrap())
            .collect();
        let tails: Vec<Option<[u8; DATA_TAIL_LEN]>> = case
            .outputs
            .iter()
            .map(|o| o.tail.as_deref().map(array))
            .collect();
        let zero_tag = [0u8; 32];
        let outputs: Vec<RingOutput<'_>> = (0..case.outputs.len())
            .map(|slot| RingOutput {
                hash: &hashes[slot],
                owner_tag: zero_tag,
                body: SlotBody::None,
                record: &records[slot],
                tail: tails[slot].as_ref(),
            })
            .collect();
        let signers = arrays::<32>(&case.signers);
        let run = SignerSet {
            count: signers.len(),
            chain: signer_chain(&signers, case.signer_slots),
        };
        assert_eq!(run.count, case.signer_count, "{}", case.name);
        assert_eq!(hex::encode(run.chain), case.signer_chain, "{}", case.name);
        assert_eq!(
            hex::encode(case.withdrawal_hash()),
            case.withdrawal_hash,
            "{}",
            case.name
        );
        let parties: Option<[[u8; 32]; ANONYMOUS_PARTIES]> = case
            .party_identities
            .as_deref()
            .map(|parties| arrays::<32>(parties).try_into().unwrap());
        let sender: [u8; 32] = case.sender.as_deref().map(array).unwrap_or_default();
        let family = match case.family.as_str() {
            "confidential" => TransferFamily::Confidential {
                sender: match (case.in_proof, case.delegate) {
                    (true, _) => ConfidentialSender::InProof(&sender),
                    (_, true) => ConfidentialSender::Authority,
                    _ => ConfidentialSender::Signer,
                },
            },
            _ => TransferFamily::Anonymous {
                party_identities: parties.as_ref().unwrap(),
                public_owners: case.public_owners,
                delegate: case.delegate,
            },
        };
        let envelope = bytes(&case.envelope);
        let roots = TransferRoots {
            policy_hash: array(&case.policy_hash),
            own_root: array(&case.own_root),
            curator_root: array(&case.curator_root),
            tracking_root: array(&case.tracking_root),
        };
        let statement = TransferStatement {
            head: AuditHead {
                first_nullifier: &array(&case.first_nullifier),
                ring_id: &array(&case.ring_id),
                tx_viewing_u: &array(&case.tx_viewing_u),
                auditor_pubkey: &array(&case.auditor_pubkey),
                envelope: &envelope,
                salt: &array(&case.salt),
                layout: AuditLayout {
                    format: if case.layout & 4 != 0 {
                        custom_ring_interface::DisclosureFormat::SingleAssetPayout
                    } else {
                        custom_ring_interface::DisclosureFormat::Standard
                    },
                    has_data: case.layout & 1 != 0,
                    entry: case.layout & 2 != 0,
                },
            },
            family,
            approval_mask: ApprovalMask::new(case.approval_mask).unwrap(),
            approval_totals: &array(&case.approval_totals),
            signer_data_counts: SignerDataCounts::new(case.signer_data_counts).unwrap(),
            no_spend: case.no_spend,
            outputs: &outputs,
            output_capacity: case.output_capacity,
            input_count: case.input_count,
            input_nullifier_chain: array(&case.input_nullifier_chain),
            private_tx_hash: &array(&case.private_tx_hash),
            signers: run,
            roots: &roots,
            public_assets: &arrays::<32>(&case.public_assets).try_into().unwrap(),
            public_amounts: &arrays::<32>(&case.public_amounts).try_into().unwrap(),
            public_gross: &arrays::<32>(&case.public_gross).try_into().unwrap(),
            withdrawal_hash: &array(&case.withdrawal_hash),
        };
        let elements: Vec<String> = statement
            .elements()
            .unwrap()
            .iter()
            .map(hex::encode)
            .collect();
        assert_eq!(elements, case.elements, "{}", case.name);
        assert_eq!(
            hex::encode(statement.hash().unwrap()),
            case.public_input_hash,
            "{}",
            case.name
        );
    }
}

#[test]
fn merge_statement_matches_the_go_vector() {
    #[derive(Deserialize)]
    struct Request {
        #[serde(rename = "outputUtxoHash")]
        output_utxo_hash: String,
        #[serde(rename = "firstNullifier")]
        first_nullifier: String,
        #[serde(rename = "ringProgramId")]
        ring_id: String,
        payer: String,
        #[serde(rename = "trackingRoot")]
        tracking_root: String,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        record: String,
        ciphertext: String,
        elements: Vec<String>,
        public_input_hash: String,
        request: Request,
    }
    #[derive(Deserialize)]
    struct Vector {
        auditor_pk: String,
        eph_pk: String,
        cases: Vec<Case>,
    }
    let vector: Vector = vector("merge/merge.json");
    for case in &vector.cases {
        let request = &case.request;
        let record = OpeningRecord::decode(&bytes(&case.record)).unwrap();
        assert_eq!(record.record.kind, RecordKind::Ring);
        // Element 10 is what the program computes from the signer under a zero key.
        let elements = arrays::<32>(&case.elements);
        assert_eq!(elements[10] == [0; 32], case.name == "nonzero");
        let statement = MergePublicInput {
            output_utxo_hash: &array(&request.output_utxo_hash),
            first_nullifier: &array(&request.first_nullifier),
            ring_id: &array(&request.ring_id),
            auditor_pk: &array(&vector.auditor_pk),
            eph_pk: &array(&vector.eph_pk),
            ciphertext: &array(&case.ciphertext),
            payer: &array(&request.payer),
            published_owner: &elements[10],
            tracking_root: &array(&request.tracking_root),
        };
        assert_eq!(elements, statement.elements().unwrap());
        assert_eq!(
            array::<32>(&case.public_input_hash),
            statement.hash().unwrap()
        );
    }
}

#[test]
fn signer_chains_match_the_go_run() {
    #[derive(Deserialize)]
    struct Case {
        name: String,
        slots: usize,
        signers: Vec<String>,
        signer_chain: String,
    }
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<Case>,
    }
    let vector: Vector = vector("audit/signer_set.json");
    for case in vector.cases {
        let signers = arrays::<32>(&case.signers);
        assert_eq!(
            hex::encode(signer_chain(&signers, case.slots)),
            case.signer_chain,
            "{}",
            case.name
        );
    }
}

#[test]
fn zero_nullifier_key_matches_the_go_twin() {
    #[derive(Deserialize)]
    struct Vector {
        nullifier_pk: String,
    }
    let vector: Vector = vector("registry/zero_nullifier.json");
    assert_eq!(
        array::<32>(&vector.nullifier_pk),
        spr_interface::ZERO_NULLIFIER_PUBKEY
    );
}

#[test]
fn record_pools_match_the_compiled_keys() {
    #[derive(Deserialize)]
    struct Key {
        key: String,
        own: usize,
        curator: usize,
        tracking: usize,
    }
    #[derive(Deserialize)]
    struct Vector {
        keys: Vec<Key>,
    }
    let vector: Vector = vector("policy/pool_capacity.json");
    assert!(RING_KEYS
        .iter()
        .filter(|ring_key| ring_key.circuit.record_pools().is_some())
        .all(|ring_key| vector
            .keys
            .iter()
            .any(|key| key.key.replace('_', "-") == ring_key.name)));
    for key in vector.keys {
        let name = key.key.replace('_', "-");
        let ring_key = RING_KEYS
            .iter()
            .find(|ring_key| ring_key.name == name)
            .unwrap_or_else(|| panic!("{name} is no catalog key"));
        let pools = ring_key.circuit.record_pools().unwrap();
        assert_eq!(
            (pools.own, pools.curator, pools.tracking),
            (key.own, key.curator, key.tracking),
            "{name}"
        );
    }
}
