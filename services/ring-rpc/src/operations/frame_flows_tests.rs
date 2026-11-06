use custom_ring_interface::InputClass;
use solana_signature::Signature;
use spr_keypair::{NullifierKey, PublicKey, X25519Keypair};
use spr_transaction::{Mint, OutputContext};
use zolana_ring_client::{
    AuditedDefaultInput, AuditedInput, AuditedOutput, AuditedUtxo, CreatedUtxo, KnownUtxo,
    OutputPayloadError, OutputPayloadErrorKind, RingOwnerTag, UtxoOwner,
};

use super::*;
use crate::{
    tracking::HeldEnrollment,
    utxos::{block_on, CreatedIn, PageWork},
};

const ALICE: [u8; 32] = [0xa1; 32];
const BOB: [u8; 32] = [0xb2; 32];
const RING: Address = Address::new_from_array([0x44; 32]);

fn mint_of_asset() -> Address {
    Address::new_from_array([0x07; 32])
}

fn assets() -> RingAssets {
    RingAssets::new([Mint::new(mint_of_asset(), 6)]).expect("assets")
}

fn asset_field() -> [u8; 32] {
    assets()
        .fields()
        .find(|(_, mint)| mint.asset == mint_of_asset())
        .expect("registered")
        .0
}

fn owner_identity(owner_key: &[u8; 32]) -> [u8; 32] {
    *Member::owner_tag(owner_key).expect("identity").as_bytes()
}

fn key_of(owner_key: &[u8; 32]) -> NullifierKey {
    NullifierKey::from_secret([owner_key[0] & 0x1f; 31])
}

/// `commitment` stays a canonical field element.
fn note(owner_key: [u8; 32], commitment: u8, amount: u64) -> CreatedUtxo {
    CreatedUtxo {
        commitment: [commitment; 32],
        slot_index: 0,
        leaf_index: 0,
        utxo: KnownUtxo {
            owner_key,
            owner: UtxoOwner::Keyed {
                nullifier_pk: key_of(&owner_key).pubkey().expect("key"),
            },
            asset: asset_field(),
            mint: None,
            amount,
            blinding: [5; 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        },
        ring_note: true,
    }
}

fn frame() -> CreatedIn {
    CreatedIn {
        slot: 1,
        tx_signature: Signature::from([7; 64]),
        event_index: 0,
    }
}

fn store_with(notes: &[CreatedUtxo]) -> AuditStore {
    let store = AuditStore::default();
    let rows = notes
        .iter()
        .map(|note| HeldEnrollment::unsealed(note.utxo.owner_key, &key_of(&note.utxo.owner_key)))
        .collect();
    let admission = block_on(store.enrollment_admission(rows)).expect("admission");
    store.admit_enrollments(admission).expect("admitted");
    let opener = |held: &HeldEnrollment| Some(key_of(&held.owner_key));
    let mut work = PageWork::new(&store, &opener);
    work.open(frame(), notes.iter().copied());
    store.commit(block_on(work.finish()).expect("page"));
    store
}

fn spend(created: &CreatedUtxo) -> AuditedInput {
    AuditedInput {
        nullifier: key_of(&created.utxo.owner_key)
            .nullifier(&created.commitment, &created.utxo.blinding)
            .expect("nullifier"),
        opening: InputOpening::Real,
    }
}

fn utxo(owner_key: [u8; 32], amount: u64) -> AuditedUtxo {
    AuditedUtxo {
        owner_key,
        nullifier_pk: [3; 32],
        asset: asset_field(),
        mint: None,
        amount,
        blinding: [6; 32],
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
    }
}

fn slot(slot_index: u32, opening: OutputOpening) -> AuditedOutput {
    AuditedOutput {
        slot_index,
        context: OutputContext {
            hash: [slot_index as u8 + 1; 32],
            tree_id: 1,
            leaf_index: 0,
        },
        opening,
    }
}

fn ring_slot(index: u32, owner_key: [u8; 32], amount: u64) -> AuditedOutput {
    slot(
        index,
        OutputOpening::Ring {
            utxo: utxo(owner_key, amount),
            owner_tag: RingOwnerTag([0x33; 32]),
        },
    )
}

fn audited(inputs: Vec<AuditedInput>, outputs: Vec<AuditedOutput>) -> AuditedTransaction {
    AuditedTransaction {
        tx_signature: Signature::from([9; 64]),
        slot: 2,
        tx_viewing_pk: X25519Keypair::from_bytes(&[3; 32]).pubkey(),
        outputs,
        payload_errors: Vec::new(),
        real_inputs: inputs
            .iter()
            .filter(|input| input.opening.class() == InputClass::Note)
            .count() as u8,
        inputs,
    }
}

fn read(
    store: &AuditStore,
    audited: &AuditedTransaction,
    public: Vec<PublicFlow>,
) -> Result<TransferRead, RingRpcError> {
    let notes = block_on(real_input_notes(store, audited))?;
    FrameFlows {
        audited,
        notes: &notes,
        owner_signers: Vec::new(),
        public,
        assets: &assets(),
        ring: RING,
    }
    .read(0)
}

fn outflows(flows: &[OwnerFlow]) -> Vec<([u8; 32], u128)> {
    flows
        .iter()
        .map(|flow| (*flow.owner.as_bytes(), flow.flow.charged_outflow))
        .collect()
}

fn refused<T>(result: Result<T, RingRpcError>) -> bool {
    matches!(
        result,
        Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
    )
}

fn public(withdrawn: u64, deposited: u64) -> PublicFlow {
    PublicFlow {
        mint: mint_of_asset(),
        asset: asset_field(),
        deposited: deposited.into(),
        withdrawn: withdrawn.into(),
    }
}

/// The vector Go `TestRingSecretsMatchRustVectors` holds `SolanaOwnerIdentity` to.
#[test]
fn the_reservation_key_is_the_identity_a_deposit_and_the_circuit_hold() {
    let wallet = PublicKey::from_ed25519(&ALICE);
    assert_eq!(
        owner_identity(&ALICE),
        wallet.owner_proof_input_hash().expect("identity")
    );
}

#[test]
fn change_returns_to_its_owner_and_a_credit_never_moves() {
    let (alice, bob) = (note(ALICE, 0x10, 30), note(BOB, 0x11, 10));
    let store = store_with(&[alice, bob]);
    let read = read(
        &store,
        &audited(
            vec![spend(&alice), spend(&bob)],
            vec![ring_slot(0, ALICE, 5), ring_slot(1, BOB, 35)],
        ),
        Vec::new(),
    )
    .expect("rows");
    assert_eq!(outflows(&read.flows), [(owner_identity(&ALICE), 25)]);
    assert!(read.spends_note);
}

#[test]
fn an_exit_to_the_same_owner_counts_as_leaving() {
    let alice = note(ALICE, 0x10, 30);
    let store = store_with(&[alice]);
    let exit = slot(0, OutputOpening::Exit(utxo(ALICE, 30)));
    let read = read(
        &store,
        &audited(vec![spend(&alice)], vec![exit]),
        Vec::new(),
    )
    .expect("rows");
    assert_eq!(outflows(&read.flows), [(owner_identity(&ALICE), 30)]);
}

/// A withdrawal of funds a deposit let the owner keep still leaves, the shared formula charges it.
#[test]
fn a_withdrawal_reads_the_statement_gross_and_never_an_empty_one() {
    let alice = note(ALICE, 0x10, 1000);
    let store = store_with(&[alice]);
    let transaction = audited(vec![spend(&alice)], vec![ring_slot(0, ALICE, 1000)]);
    let read_public = |public_flows| {
        read(&store, &transaction, public_flows)
            .expect("rows")
            .flows
    };
    assert_eq!(
        outflows(&read_public(vec![public(999, 1000)])),
        [(owner_identity(&ALICE), 999)]
    );
    assert!(outflows(&read_public(Vec::new()))
        .iter()
        .all(|(_, outflow)| *outflow == 0));
}

#[test]
fn a_dummy_input_and_a_dummy_slot_answer_for_nothing() {
    let store = store_with(&[]);
    let read = read(
        &store,
        &audited(
            vec![AuditedInput {
                nullifier: [0x11; 32],
                opening: InputOpening::Dummy,
            }],
            vec![slot(0, OutputOpening::Dummy)],
        ),
        Vec::new(),
    )
    .expect("rows");
    assert!(read.flows.is_empty());
    assert!(!read.spends_note);
}

/// A real input the index cannot name refuses until its note opens.
#[test]
fn an_unresolved_nullifier_refuses_the_signature_until_its_note_opens() {
    let alice = note(ALICE, 0x12, 40);
    let transaction = audited(vec![spend(&alice)], vec![ring_slot(0, BOB, 40)]);
    assert!(refused(read(&store_with(&[]), &transaction, Vec::new())));
    let store = store_with(&[alice]);
    let read = read(&store, &transaction, Vec::new()).expect("opened");
    assert_eq!(outflows(&read.flows), [(owner_identity(&ALICE), 40)]);
}

/// Default-ring evidence names its own owner, a co-signer signs an entry with no index row.
#[test]
fn an_external_input_answers_under_its_own_evidence() {
    let transaction = audited(
        vec![AuditedInput {
            nullifier: [0x11; 32],
            opening: InputOpening::External(Box::new(AuditedDefaultInput {
                utxo: utxo(ALICE, 40),
                commitment: None,
            })),
        }],
        vec![ring_slot(0, BOB, 40)],
    );
    let read = read(&store_with(&[]), &transaction, Vec::new()).expect("rows");
    assert_eq!(outflows(&read.flows), [(owner_identity(&ALICE), 40)]);
}

#[test]
fn an_unread_slot_or_an_unknown_mint_refuses_the_whole_read() {
    let alice = note(ALICE, 0x10, 30);
    let store = store_with(&[alice]);
    let mut transaction = audited(vec![spend(&alice)], vec![ring_slot(0, BOB, 30)]);
    transaction.payload_errors.push(OutputPayloadError {
        slot_index: 1,
        kind: OutputPayloadErrorKind::Commitment,
    });
    assert!(refused(read(&store, &transaction, Vec::new())));
    let no_mints = RingAssets::new([]).expect("assets");
    let transaction = audited(vec![spend(&alice)], vec![ring_slot(0, BOB, 30)]);
    let notes = block_on(real_input_notes(&store, &transaction)).expect("notes");
    assert!(refused(
        FrameFlows {
            audited: &transaction,
            notes: &notes,
            owner_signers: Vec::new(),
            public: Vec::new(),
            assets: &no_mints,
            ring: RING,
        }
        .read(0)
    ));
}

/// A no-spend frame sits on the ring's own tag, only ring caps read its legs.
#[test]
fn a_public_funded_transfer_with_no_sender_reads_as_no_spend() {
    let read = read(
        &store_with(&[]),
        &audited(Vec::new(), vec![ring_slot(0, BOB, 15)]),
        vec![public(0, 15)],
    )
    .expect("no spend");
    assert!(!read.spends_note);
    let [row] = read.flows.as_slice() else {
        panic!("one public row, {:?}", read.flows);
    };
    assert_eq!(row.flow.charged_outflow, 0);
    assert_eq!(row.flow.deposited, 15);
    assert_eq!(*row.owner.as_bytes(), owner_identity(RING.as_array()));
}

/// `test-vectors/policy/quantities.json`, the figure the policy circuit reaches.
#[test]
fn the_reserved_figure_matches_the_circuit_quantities() {
    fn identity(value: &serde_json::Value) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.as_u64().expect("identity").to_be_bytes());
        bytes
    }
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/policy/quantities.json"
    ))
    .expect("vector");
    for case in vector["cases"].as_array().expect("cases") {
        let notes = |key: &str| case[key].as_array().cloned().unwrap_or_default();
        let inputs: Vec<DebitInput> = notes("inputs")
            .iter()
            .map(|input| DebitInput {
                owner: identity(&input["owner"]),
                asset: identity(&input["asset"]),
                amount: input["amount"].as_u64().expect("amount"),
            })
            .collect();
        let outputs: Vec<DebitOutput> = notes("outputs")
            .iter()
            .map(|output| DebitOutput {
                ring: output["ring"].as_bool().expect("ring"),
                owner: identity(&output["owner"]),
                asset: identity(&output["asset"]),
                amount: output["amount"].as_u64().expect("amount"),
            })
            .collect();
        let public: Vec<PublicFlow> = notes("public")
            .iter()
            .map(|public| PublicFlow {
                mint: Address::new_from_array(identity(&public["asset"])),
                asset: identity(&public["asset"]),
                deposited: 0,
                withdrawn: public["gross"].as_u64().expect("gross").into(),
            })
            .collect();
        let rows = OwnerFlows {
            inputs: &inputs,
            outputs: &outputs,
            owner_signers: &[],
            public: &public,
            no_spend_owner: Member::from_bytes([0xee; 32]).expect("tag"),
        }
        .rows(|asset| Ok(Address::new_from_array(*asset)))
        .expect("rows");
        let reserved: Vec<([u8; 32], [u8; 32], u128)> = rows
            .iter()
            .filter(|row| row.flow.charged_outflow != 0)
            .map(|row| {
                (
                    *row.owner.as_bytes(),
                    row.flow.asset.to_bytes(),
                    row.flow.charged_outflow,
                )
            })
            .collect();
        let circuit: Vec<([u8; 32], [u8; 32], u128)> = notes("rows")
            .iter()
            .filter(|row| row["charged_outflow"].as_u64() != Some(0))
            .map(|row| {
                (
                    identity(&row["owner"]),
                    identity(&row["asset"]),
                    u128::from(row["charged_outflow"].as_u64().expect("charged outflow")),
                )
            })
            .collect();
        assert_eq!(reserved, circuit, "{}", case["name"]);
    }
}
