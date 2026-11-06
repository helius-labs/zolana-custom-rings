use solana_address::Address;
use solana_signature::Signature;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use spr_client::ClientError;
use spr_event::tag;
use spr_event_parser::{InstructionGroup, ParsedInstruction};
use spr_interface::{
    instruction::{CircuitId, InterfaceTransfer, TransactIxData, TransactProof, TreeContext},
    SHIELDED_POOL_CPI_AUTHORITY, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE,
};
use spr_interface::{
    instruction::{InputUtxo, MessageData, OwnerTag, TransactOutput},
    verifying_keys::{AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CacheWrite},
};
use spr_transaction::SOL_MINT;

use super::*;

fn ring_invoked_in(groups: &[InstructionGroup], ring: Address) -> Result<bool, AuditError> {
    Ok(!ring_instructions_in(groups, ring)?.is_empty())
}

fn ring_withdrawals_in(
    groups: &[InstructionGroup],
    ring: Address,
) -> Result<Vec<RingWithdrawal>, AuditError> {
    ring_withdrawals_of(&ring_instructions_in(groups, ring)?)
}

const RING: Address = Address::new_from_array([9u8; 32]);
const OTHER: Address = Address::new_from_array([8u8; 32]);
const POOL: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
const SOL: Address = Address::new_from_array(SOL_INTERFACE);
const RECIPIENT: Address = Address::new_from_array([3u8; 32]);
const CPI_AUTHORITY: Address = Address::new_from_array(SHIELDED_POOL_CPI_AUTHORITY);
const MINT: Address = Address::new_from_array([4u8; 32]);
const TOKEN_ACCOUNT: Address = Address::new_from_array([5u8; 32]);

fn instruction(program_id: Address, stack_height: u32) -> ParsedInstruction {
    ParsedInstruction::new(program_id, Vec::new(), Vec::new(), stack_height)
}

fn group(outer: Address, inner: &[(Address, u32)]) -> InstructionGroup {
    InstructionGroup {
        outer: instruction(outer, 1),
        inner: inner
            .iter()
            .map(|(program_id, height)| instruction(*program_id, *height))
            .collect(),
    }
}

fn event_data() -> String {
    let event = spr_event::TransactEvent {
        input_trees: vec![spr_event::InputTreeSequence {
            tree: spr_interface::pda::tree(0).to_bytes(),
            first_input_queue_seq: 0,
        }],
        output_tree: spr_interface::pda::tree(0).to_bytes(),
        first_output_leaf_index: 0,
    };
    bs58::encode(
        [
            vec![tag::EMIT_EVENT, spr_event::EventKind::Transact as u8],
            borsh::to_vec(&event).unwrap(),
        ]
        .concat(),
    )
    .into_string()
}

#[test]
fn pool_directly_under_the_ring_is_attributed() {
    let groups = [group(RING, &[(POOL, 2), (OTHER, 3)])];
    assert!(ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn only_confirmed_ring_transfer_events_require_auditor_messages() {
    for kind in [tag::RING_TRANSACT, tag::RING_AUTHORITY_TRANSACT] {
        let mut source = instruction(POOL, 2);
        source.data = ring_transact_bytes(Vec::new());
        source.data[0] = kind;
        let mut event = instruction(POOL, 3);
        event.data = bs58::decode(event_data()).into_vec().unwrap();
        let origin = ring_event_origin_in(
            &[InstructionGroup {
                outer: instruction(RING, 1),
                inner: vec![source, event],
            }],
            0,
            RING,
        )
        .unwrap();
        assert!(origin.ring_invoked);
        assert_eq!(
            origin.requires_audit(),
            matches!(kind, tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT)
        );
    }
}

#[test]
fn pool_at_top_level_is_not_attributed() {
    let groups = [group(POOL, &[(OTHER, 2)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn pool_under_an_intermediary_is_not_attributed() {
    let groups = [group(RING, &[(OTHER, 2), (POOL, 3)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn ring_nested_under_another_program_still_signs_for_the_pool() {
    let groups = [group(OTHER, &[(RING, 2), (POOL, 3), (OTHER, 2), (POOL, 3)])];
    assert!(ring_invoked_in(&groups, RING).expect("walk"));
    let groups = [group(OTHER, &[(RING, 2), (OTHER, 2), (POOL, 3)])];
    assert!(!ring_invoked_in(&groups, RING).expect("walk"));
}

#[test]
fn stack_height_without_a_parent_is_an_error() {
    let groups = [group(RING, &[(POOL, 4)])];
    assert!(matches!(
        ring_invoked_in(&groups, RING),
        Err(AuditError::InvalidStackHeight(4))
    ));
}

/// The pinned client decodes no version 0 transaction, its loaded addresses are refused.
#[test]
fn a_lookup_table_transaction_is_refused() {
    let payer = Address::new_from_array([1u8; 32]);
    let table = Address::new_from_array([2u8; 32]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 1
                },
                "accountKeys": [payer.to_string(), RING.to_string()],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ],
                "addressTableLookups": [
                    { "accountKey": table.to_string(), "writableIndexes": [0], "readonlyIndexes": [1] }
                ]
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        {
                            "programIdIndex": 3,
                            "accounts": [2],
                            "data": ring_transact_data(Vec::new()),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                }
            ],
            "loadedAddresses": {
                "writable": [OTHER.to_string()],
                "readonly": [POOL.to_string()]
            }
        },
        "version": 0
    });
    let parse = |json: &serde_json::Value| {
        let transaction: EncodedConfirmedTransactionWithStatusMeta =
            serde_json::from_value(json.clone()).expect("rpc shape");
        confirmed_origin(transaction, 0, RING)
    };
    assert!(matches!(
        parse(&json),
        Err(AuditError::Client(ClientError::AddressLookupTable))
    ));
    let origins = ConfirmedRingOrigins {
        signature: Signature::from([6; 64]),
        transaction: serde_json::from_value(json.clone()).unwrap(),
        ring: RING,
    }
    .read()
    .unwrap();
    assert_eq!(origins.keys().copied().collect::<Vec<_>>(), [0]);
    assert_eq!(origins[&0].pool_accounts, [OTHER]);
    assert_eq!(origins[&0].signers, [payer]);
    for loaded in [
        serde_json::json!({"writable": [OTHER.to_string()], "readonly": []}),
        serde_json::json!({"writable": [], "readonly": []}),
        serde_json::Value::Null,
    ] {
        let mut missing = json.clone();
        missing["meta"]["loadedAddresses"] = loaded;
        assert!(ConfirmedRingOrigins {
            signature: Signature::from([6; 64]),
            transaction: serde_json::from_value(missing).unwrap(),
            ring: RING,
        }
        .read()
        .is_err());
    }
}

#[test]
fn event_ordinals_separate_two_origins_in_one_transaction() {
    let payer = Address::new_from_array([1u8; 32]);
    let signature = Signature::from([7u8; 64]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [signature.to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 3
                },
                "accountKeys": [
                    payer.to_string(), RING.to_string(), OTHER.to_string(), POOL.to_string()
                ],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null },
                    { "programIdIndex": 2, "accounts": [0], "data": "", "stackHeight": null }
                ]
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0, 0, 0],
            "postBalances": [0, 0, 0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": ring_transact_data(Vec::new()),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                },
                {
                    "index": 1,
                    "instructions": [
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": ring_transact_data(Vec::new()),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 3,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                }
            ]
        }
    });
    let origins = ConfirmedRingOrigins {
        signature,
        transaction: serde_json::from_value(json.clone()).unwrap(),
        ring: RING,
    }
    .read()
    .unwrap();
    assert_eq!(origins.keys().copied().collect::<Vec<_>>(), [0, 1]);
    assert!(origins[&0].ring_invoked);
    assert!(!origins[&1].ring_invoked);
    assert_eq!(origins[&0].signers, [payer]);
    let other = ConfirmedRingOrigins {
        signature,
        transaction: serde_json::from_value(json.clone()).unwrap(),
        ring: OTHER,
    }
    .read()
    .unwrap();
    assert_eq!(other.keys().copied().collect::<Vec<_>>(), [0, 1]);
    assert!(!other[&0].ring_invoked);
    assert!(other[&1].ring_invoked);
    assert!(ConfirmedRingOrigins {
        signature: Signature::from([8; 64]),
        transaction: serde_json::from_value(json.clone()).unwrap(),
        ring: RING,
    }
    .read()
    .is_err());
    let first: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_value(json.clone()).expect("rpc shape");
    let second: EncodedConfirmedTransactionWithStatusMeta =
        serde_json::from_value(json).expect("rpc shape");

    assert!(confirmed_origin(first, 0, RING)
        .map(|origin| origin.ring_invoked)
        .expect("first origin"));
    assert!(!confirmed_origin(second, 1, RING)
        .map(|origin| origin.ring_invoked)
        .expect("second origin"));
}

/// The settlement walk reads instruction groups, so it needs no confirmed
/// transaction and no RPC.
#[test]
fn withdrawals_read_from_instruction_groups_without_a_transaction() {
    let mut pool = instruction(POOL, 2);
    pool.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 77 }]);
    pool.accounts = vec![Address::default(), SOL, RECIPIENT];
    let groups = [InstructionGroup {
        outer: instruction(RING, 1),
        inner: vec![pool],
    }];

    assert_eq!(
        ring_withdrawals_in(&groups, RING).expect("walk"),
        vec![RingWithdrawal {
            screened_owner: None,
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 77,
        }]
    );
}

#[test]
fn cached_settlement_vectors_match_rust_and_exclude_the_cache() {
    let selection = CacheAccess {
        read_bitmap: 1,
        write_slots: CacheAccess::NO_WRITES,
    };
    let circuits = [
        CircuitId::ConfidentialRingEddsaCached(1, 2, 1, selection),
        CircuitId::AnonymousRingEddsaCached(
            1,
            2,
            1,
            AnonymousRingEddsaProofData {
                bsb22_commitment: Bsb22Commitment {
                    commitment: [17; 32],
                    commitment_pok: [18; 32],
                },
                default_owner_tag: Some([19; 32]),
            },
            selection,
        ),
    ];
    let mut writing = circuits;
    for circuit in &mut writing {
        match circuit {
            CircuitId::ConfidentialRingEddsaCached(_, _, _, access)
            | CircuitId::AnonymousRingEddsaCached(_, _, _, _, access) => {
                access.write_slots = CacheAccess::NO_WRITES;
                for (entry, (output, slot)) in access.write_slots.iter_mut().zip([(0, 0), (1, 1)]) {
                    *entry = CacheWrite { output, slot };
                }
            }
            _ => panic!("cached test rail"),
        }
    }
    let circuits: Vec<_> = circuits.into_iter().chain(writing).collect();
    let vectors: Vec<_> =
        include_str!("../../../../../test-vectors/settlement/cached_ring_settlement.hex")
            .lines()
            .collect();
    assert_eq!(vectors.len(), circuits.len());
    for (circuit, encoded) in circuits.into_iter().zip(vectors) {
        assert_settlement_vector(circuit, encoded);
    }
}

#[test]
fn anonymous_settlement_vector_matches_rust_and_has_no_cache() {
    let circuit = CircuitId::AnonymousRingEddsa(
        1,
        2,
        1,
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: [21; 32],
                commitment_pok: [22; 32],
            },
            default_owner_tag: None,
        },
    );
    assert_settlement_vector(
        circuit,
        include_str!("../../../../../test-vectors/settlement/anonymous_ring_settlement.hex").trim(),
    );
}

fn assert_settlement_vector(circuit: CircuitId, encoded: &str) {
    let data = TransactIxData {
        expiry_unix_ts: 0,
        private_tx_hash: [1; 32],
        circuit,
        tx_viewing_pk: [2; 33],
        salt: [3; 16],
        proof: TransactProof::zeroed(),
        interface_transfers: vec![
            InterfaceTransfer::SolWithdrawal { amount: 7 },
            InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 254,
            },
        ],
        data_hash: Some([4; 32]),
        ring_data_hash: Some([5; 32]),
        outputs: vec![
            TransactOutput {
                utxo_hash: [6; 32],
                owner_tag: OwnerTag::Inline([7; 32]),
                data: Some(vec![8, 9]),
            },
            TransactOutput {
                utxo_hash: [10; 32],
                owner_tag: OwnerTag::Account(1),
                data: None,
            },
        ],
        messages: vec![MessageData {
            view_tag: [11; 32],
            data: vec![12, 13, 14],
        }],
        inputs: vec![InputUtxo {
            nullifier_hash: [20; 32],
            tree_index: 0,
        }],
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    };
    let bytes = hex::decode(encoded).expect("pinned wire vector");
    assert_eq!(data.serialize().expect("serialize"), bytes);
    let mut answers = instruction(POOL, 2);
    answers.data = [vec![tag::RING_TRANSACT], bytes].concat();
    answers.accounts = vec![
        OTHER,
        SOL,
        RECIPIENT,
        CPI_AUTHORITY,
        MINT,
        OTHER,
        TOKEN_ACCOUNT,
        OTHER,
    ];
    if let Some(access) = circuit.cache_access() {
        if access.read_bitmap != 0 {
            answers.accounts.push(OTHER);
        }
        if access.writes_cache() {
            answers.accounts.extend([OTHER, OTHER]);
        }
    }
    let mut groups = [InstructionGroup {
        outer: instruction(RING, 1),
        inner: vec![answers],
    }];
    assert_eq!(
        ring_withdrawals_in(&groups, RING).expect("settlement"),
        vec![
            RingWithdrawal {
                screened_owner: None,
                recipient: RECIPIENT,
                asset: SOL_MINT,
                amount: 7
            },
            RingWithdrawal {
                screened_owner: None,
                recipient: TOKEN_ACCOUNT,
                asset: MINT,
                amount: 9
            },
        ]
    );
    groups
        .first_mut()
        .expect("group")
        .inner
        .first_mut()
        .expect("instruction")
        .accounts
        .truncate(7);
    assert!(matches!(
        ring_withdrawals_in(&groups, RING),
        Err(AuditError::SettlementAccounts)
    ));
}

#[test]
fn withdrawals_of_a_ring_that_did_not_sign_are_not_reported() {
    let mut pool = instruction(POOL, 2);
    pool.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 77 }]);
    pool.accounts = vec![Address::default(), SOL, RECIPIENT];
    let groups = [InstructionGroup {
        outer: instruction(OTHER, 1),
        inner: vec![pool],
    }];

    assert!(ring_withdrawals_in(&groups, RING).expect("walk").is_empty());
}

fn ring_transact_bytes(interface_transfers: Vec<InterfaceTransfer>) -> Vec<u8> {
    let data = TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: [0u8; 32],
        circuit: CircuitId::ConfidentialRingEddsa(0, 0, 3),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
        tree_contexts: vec![TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        }],
    };
    let mut encoded = vec![tag::RING_TRANSACT];
    encoded.extend_from_slice(&data.serialize().expect("serialize"));
    encoded
}

fn ring_transact_data(interface_transfers: Vec<InterfaceTransfer>) -> String {
    bs58::encode(ring_transact_bytes(interface_transfers)).into_string()
}

/// A ring transact CPI with `accounts` as its pool-instruction account indices.
fn withdrawing_transaction(
    interface_transfers: Vec<InterfaceTransfer>,
    accounts: Vec<u8>,
) -> EncodedConfirmedTransactionWithStatusMeta {
    let payer = Address::new_from_array([1u8; 32]);
    let tree = Address::new_from_array([2u8; 32]);
    let json = serde_json::json!({
        "slot": 7,
        "blockTime": null,
        "transaction": {
            "signatures": [Signature::from([6u8; 64]).to_string()],
            "message": {
                "header": {
                    "numRequiredSignatures": 1,
                    "numReadonlySignedAccounts": 0,
                    "numReadonlyUnsignedAccounts": 6
                },
                "accountKeys": [
                    payer.to_string(),
                    RING.to_string(),
                    POOL.to_string(),
                    Address::default().to_string(),
                    OTHER.to_string(),
                    tree.to_string(),
                    SOL.to_string(),
                    RECIPIENT.to_string(),
                    CPI_AUTHORITY.to_string(),
                    MINT.to_string(),
                    TOKEN_ACCOUNT.to_string()
                ],
                "recentBlockhash": Address::default().to_string(),
                "instructions": [
                    { "programIdIndex": 1, "accounts": [0], "data": "", "stackHeight": null }
                ]
            }
        },
        "meta": {
            "err": null,
            "status": { "Ok": null },
            "fee": 5000,
            "preBalances": [1, 0],
            "postBalances": [0, 0],
            "innerInstructions": [
                {
                    "index": 0,
                    "instructions": [
                        {
                            "programIdIndex": 2,
                            "accounts": accounts,
                            "data": ring_transact_data(interface_transfers),
                            "stackHeight": 2
                        },
                        {
                            "programIdIndex": 2,
                            "accounts": [],
                            "data": event_data(),
                            "stackHeight": 3
                        }
                    ]
                }
            ]
        }
    });
    serde_json::from_value(json).expect("rpc shape")
}

/// The recipient is the account following `SOL_INTERFACE` in the settlement
/// accounts appended to the pool instruction.
#[test]
fn sol_withdrawal_reports_its_recipient_and_amount() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![InterfaceTransfer::SolWithdrawal { amount: 4_200 }],
            vec![0, 5, 5, 2, 3, 4, 6, 7],
        ),
        0,
        RING,
    )
    .expect("walk");

    assert!(origin.ring_invoked);
    assert_eq!(
        origin.withdrawals,
        vec![RingWithdrawal {
            screened_owner: None,
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 4_200,
        }]
    );
}

/// The credited token account and the mint sit at indices 3 and 1 of the SPL
/// settlement group.
#[test]
fn spl_withdrawal_reports_its_mint_and_token_account() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 42,
            }],
            vec![0, 5, 5, 2, 3, 8, 9, 4, 10, 4],
        ),
        0,
        RING,
    )
    .expect("walk");

    assert_eq!(
        origin.withdrawals,
        vec![RingWithdrawal {
            screened_owner: None,
            recipient: TOKEN_ACCOUNT,
            asset: MINT,
            amount: 9,
        }]
    );
}

/// A preceding SPL withdrawal shifts the SOL settlement group by five accounts.
#[test]
fn mixed_spl_and_sol_legs_are_both_reported() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![
                InterfaceTransfer::SplWithdrawal {
                    amount: 9,
                    spl_interface_bump: 42,
                },
                InterfaceTransfer::SolWithdrawal { amount: 11 },
            ],
            vec![0, 5, 5, 2, 3, 8, 9, 4, 10, 4, 6, 7],
        ),
        0,
        RING,
    )
    .expect("walk");

    assert_eq!(
        origin.withdrawals,
        vec![
            RingWithdrawal {
                screened_owner: None,
                recipient: TOKEN_ACCOUNT,
                asset: MINT,
                amount: 9,
            },
            RingWithdrawal {
                screened_owner: None,
                recipient: RECIPIENT,
                asset: SOL_MINT,
                amount: 11,
            }
        ]
    );
}

#[test]
fn spl_settlement_group_without_the_cpi_authority_is_an_error() {
    let origin = confirmed_origin(
        withdrawing_transaction(
            vec![InterfaceTransfer::SplWithdrawal {
                amount: 9,
                spl_interface_bump: 42,
            }],
            vec![0, 5, 5, 2, 3, 4, 9, 4, 10, 4],
        ),
        0,
        RING,
    );

    assert!(matches!(origin, Err(AuditError::SettlementAccounts)));
}

#[test]
fn a_confirmed_response_for_another_signature_is_rejected() {
    let result = confirmed_origin_for(
        Signature::from([7; 64]),
        withdrawing_transaction(Vec::new(), Vec::new()),
        0,
        RING,
    );
    assert!(matches!(result, Err(AuditError::Unavailable { .. })));
}

#[test]
fn a_failed_transaction_grants_no_origin() {
    let mut response =
        serde_json::to_value(withdrawing_transaction(Vec::new(), Vec::new())).unwrap();
    response["meta"]["err"] = serde_json::json!("AccountNotFound");
    let result = confirmed_origin_for(
        Signature::from([6; 64]),
        serde_json::from_value(response).unwrap(),
        0,
        RING,
    );
    assert!(matches!(
        result,
        Err(AuditError::Client(ClientError::TransactionFailed(_)))
    ));
}

#[test]
fn ring_transfer_outer_tags_preserve_confirmed_ring_origin() {
    for (outer_tag, inner_tag) in [
        (custom_ring_interface::tag::TRANSFER, tag::RING_TRANSACT),
        (
            custom_ring_interface::tag::AUTHORITY_TRANSFER,
            tag::RING_AUTHORITY_TRANSACT,
        ),
    ] {
        let mut outer = instruction(RING, 1);
        outer.data = vec![outer_tag];
        let mut source = instruction(POOL, 2);
        source.data = ring_transact_bytes(Vec::new());
        source.data[0] = inner_tag;
        let mut event = instruction(POOL, 3);
        event.data = bs58::decode(event_data()).into_vec().unwrap();
        let groups = [InstructionGroup {
            outer,
            inner: vec![source, event],
        }];
        assert!(ring_event_origin_in(&groups, 0, RING).unwrap().ring_invoked);
        assert!(
            !ring_event_origin_in(&groups, 0, OTHER)
                .unwrap()
                .ring_invoked
        );
    }
}

fn confirmed_transfer_fixture() -> (InstructionGroup, ShieldedTransaction) {
    use spr_event::{encode_event_instruction, EventKind, InputTreeSequence, TransactEvent};
    use spr_transaction::{OutputContext, OutputSlot};

    let key = spr_keypair::X25519Keypair::from_bytes(&[7; 32]).pubkey();
    let mut data = TransactIxData::deserialize(&ring_transact_bytes(Vec::new())[1..]).unwrap();
    data.tx_viewing_pk = *key.as_bytes();
    data.salt = [0; 16];
    data.inputs = vec![
        InputUtxo {
            nullifier_hash: [20; 32],
            tree_index: 0,
        },
        InputUtxo {
            nullifier_hash: [21; 32],
            tree_index: 0,
        },
    ];
    data.outputs = vec![
        TransactOutput {
            utxo_hash: [6; 32],
            owner_tag: OwnerTag::Inline([7; 32]),
            data: Some(vec![8, 9]),
        },
        TransactOutput {
            utxo_hash: [10; 32],
            owner_tag: OwnerTag::Account(1),
            data: None,
        },
    ];
    data.messages = vec![MessageData {
        view_tag: [11; 32],
        data: vec![12, 13, 14],
    }];
    let event = TransactEvent {
        input_trees: vec![InputTreeSequence {
            tree: spr_interface::pda::tree(1).to_bytes(),
            first_input_queue_seq: 5,
        }],
        output_tree: spr_interface::pda::tree(3).to_bytes(),
        first_output_leaf_index: 42,
    };
    let group = InstructionGroup {
        outer: instruction(RING, 1),
        inner: vec![
            ParsedInstruction::new(
                POOL,
                vec![RING, RECIPIENT],
                [vec![tag::RING_TRANSACT], data.serialize().unwrap()].concat(),
                2,
            ),
            ParsedInstruction::new(
                POOL,
                vec![],
                encode_event_instruction(EventKind::Transact, &event),
                3,
            ),
        ],
    };
    let indexed = ShieldedTransaction {
        slot: 99,
        tx_signature: Signature::from([6; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(key),
        salt: None,
        output_slots: vec![
            OutputSlot {
                view_tag: [7; 32],
                output_context: OutputContext {
                    hash: [6; 32],
                    tree_id: 3,
                    leaf_index: 42,
                },
                payload: vec![8, 9],
            },
            OutputSlot {
                view_tag: RECIPIENT.to_bytes(),
                output_context: OutputContext {
                    hash: [10; 32],
                    tree_id: 3,
                    leaf_index: 43,
                },
                payload: vec![],
            },
        ],
        messages: data.messages,
        nullifiers: vec![[20; 32], [21; 32]],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    (group, indexed)
}

#[test]
fn confirmed_event_binds_every_indexed_audit_and_recovery_field() {
    let (group, indexed) = confirmed_transfer_fixture();
    let origin = ring_event_origin_in(&[group], 0, RING).unwrap();
    let mut valid = indexed.clone();
    origin.bind_transaction(&mut valid, RING).unwrap();
    assert_eq!(
        valid.salt,
        Some([0; 16]),
        "normalize only the confirmed zero salt"
    );
    type Mutation = (&'static str, fn(&mut ShieldedTransaction));
    let mutations: &[Mutation] = &[
        ("kind", |tx| tx.proofless = true),
        ("viewing key", |tx| tx.tx_viewing_pk = None),
        ("salt", |tx| tx.salt = Some([1; 16])),
        ("missing message", |tx| tx.messages.clear()),
        ("message tag", |tx| tx.messages[0].view_tag[0] ^= 1),
        ("message data", |tx| tx.messages[0].data[0] ^= 1),
        ("nullifier", |tx| tx.nullifiers[0][0] ^= 1),
        ("nullifier order", |tx| tx.nullifiers.swap(0, 1)),
        ("nullifier count", |tx| tx.nullifiers.push([22; 32])),
        ("output count", |tx| {
            tx.output_slots.pop();
        }),
        ("output tag", |tx| tx.output_slots[0].view_tag[0] ^= 1),
        ("output commitment", |tx| {
            tx.output_slots[0].output_context.hash[0] ^= 1
        }),
        ("output payload", |tx| tx.output_slots[0].payload[0] ^= 1),
        ("output tree", |tx| {
            tx.output_slots[0].output_context.tree_id += 1
        }),
        ("output position", |tx| {
            tx.output_slots[1].output_context.leaf_index += 1
        }),
        ("ring", |tx| tx.ring_program_id = Some(OTHER)),
    ];
    for (name, mutate) in mutations {
        let mut forged = indexed.clone();
        mutate(&mut forged);
        assert!(
            matches!(
                origin.bind_transaction(&mut forged, RING),
                Err(AuditError::ConfirmedEventMismatch)
            ),
            "{name}"
        );
    }
}

#[test]
fn confirmed_event_wire_fixture_matches_the_shared_parser() {
    let (group, indexed) = confirmed_transfer_fixture();
    check_event_wire_fixture("confirmed-event", group, indexed);
    let (group, indexed) = confirmed_merge_fixture();
    check_event_wire_fixture("confirmed-merge-event", group, indexed);
}

fn check_event_wire_fixture(name: &str, group: InstructionGroup, mut indexed: ShieldedTransaction) {
    let origin = ring_event_origin_in(std::slice::from_ref(&group), 0, RING).unwrap();
    origin.bind_transaction(&mut indexed, RING).unwrap();
    let fixture = serde_json::json!({
        "ring": RING.to_string(),
        "source": {
            "programId": POOL.to_string(),
            "accounts": group.inner[0].accounts.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "dataHex": hex::encode(&group.inner[0].data),
        },
        "eventDataHex": hex::encode(&group.inner[1].data),
        "expected": {
            "viewingKeyHex": hex::encode(origin.event.event.tx_viewing_pk),
            "saltHex": hex::encode(origin.event.event.salt),
            "nullifiersHex": indexed.nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
            "messages": indexed.messages.iter().map(|message| serde_json::json!({"viewTagHex": hex::encode(message.view_tag), "dataHex": hex::encode(&message.data)})).collect::<Vec<_>>(),
            "outputs": indexed.output_slots.iter().map(|slot| serde_json::json!({
                "viewTagHex": hex::encode(slot.view_tag), "hashHex": hex::encode(slot.output_context.hash),
                "payloadHex": hex::encode(&slot.payload), "treeId": slot.output_context.tree_id, "leafIndex": slot.output_context.leaf_index,
            })).collect::<Vec<_>>(),
        },
    });
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("WRITE_RING_EVENT_FIXTURE").is_some() {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
        )
        .unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture, pinned);
}

fn confirmed_merge_fixture() -> (InstructionGroup, ShieldedTransaction) {
    use spr_event::{encode_event_instruction, EventKind, InputTreeSequence, MergeEvent};
    use spr_interface::instruction::instruction_data::{
        merge_ring::{MergeRingAuthority, MergeRingIxData},
        merge_transact::{MergeOutputEncryption, MergeProof, MergeTransactIxData},
    };
    let (mut group, mut indexed) = confirmed_transfer_fixture();
    indexed.tx_viewing_pk = None;
    indexed.salt = None;
    indexed.messages.clear();
    indexed.output_slots.truncate(1);
    indexed.output_slots[0].view_tag = [20; 32];
    indexed.output_slots[0].payload =
        spr_event::encode_merge_output_data(spr_event::MergeOutputDataRef {
            salt: &[7; 16],
            ciphertext: &[[0; 32]; 3],
            prefix: &[[13; 32]],
        });
    let data = MergeRingIxData {
        output_ring_data_hash: [13; 32],
        authority: MergeRingAuthority::Ring,
        merge: MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [6; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [7; 16],
                ciphertext: [[0; 32]; 3],
            },
            private_tx_hash: [0; 32],
            nullifiers: indexed.nullifiers.clone(),
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    };
    let event = MergeEvent {
        input_trees: vec![InputTreeSequence {
            tree: spr_interface::pda::tree(1).to_bytes(),
            first_input_queue_seq: 5,
        }],
        output_tree: spr_interface::pda::tree(3).to_bytes(),
        output_leaf_index: 42,
        output_view_tag: [20; 32],
    };
    group.inner[0].data = [vec![tag::RING_MERGE_TRANSACT], data.serialize().unwrap()].concat();
    group.inner[1].data = encode_event_instruction(EventKind::Merge, &event);
    (group, indexed)
}

/// Only a ring caller forwarding the exact body with the anonymous flag binds a disclosure.
fn merge_proof() -> custom_ring_interface::CustomRingProof {
    custom_ring_interface::CustomRingProof {
        groth16: custom_ring_interface::PlainGroth16Proof {
            proof_a: [1; 32],
            proof_b: [2; 64],
            proof_c: [3; 32],
        },
        commitment: [1; 32],
        commitment_pok: [2; 32],
    }
}

fn record_merge_group() -> (
    InstructionGroup,
    custom_ring_interface::CustomRingMergeIxData,
) {
    use custom_ring_interface::{CustomRingMergeIxData, SealedMergeRecord};
    use spr_interface::instruction::instruction_data::merge_ring::MergeRingIxData;
    let (mut group, _) = confirmed_merge_fixture();
    let spp = MergeRingIxData::deserialize(&group.inner[0].data[1..]).unwrap();
    let request = CustomRingMergeIxData {
        tracking_revision: Default::default(),
        output_ring_data_hash: spp.output_ring_data_hash,
        authority: spp.authority,
        sealed: SealedMergeRecord {
            proof: merge_proof(),
            eph_pk: [4; 33],
            envelope: [5; custom_ring_interface::MERGE_ENVELOPE_LEN],
            record: [6; custom_ring_interface::MERGE_RECORD_LEN],
        },
        merge: spp.merge,
    };
    group.outer.data = [vec![ring_tag::MERGE], request.serialize().unwrap()].concat();
    (group, request)
}

#[test]
fn a_record_merge_binds_the_record_its_ring_forwarded() {
    let (mut group, request) = record_merge_group();
    let origin = ring_event_origin_in(std::slice::from_ref(&group), 0, RING).unwrap();
    assert_eq!(origin.event.kind(), ConfirmedEventKind::Merge);
    assert_eq!(
        origin.merge_disclosure,
        Some(ConfirmedMergeDisclosure {
            eph_pk: request.sealed.eph_pk,
            envelope: request.sealed.envelope,
            record: request.sealed.record,
        })
    );
    let mut other = request;
    other.merge.expiry_unix_ts ^= 1;
    group.outer.data = [vec![ring_tag::MERGE], other.serialize().unwrap()].concat();
    let rewritten = ring_event_origin_in(std::slice::from_ref(&group), 0, RING).unwrap();
    assert_eq!(rewritten.merge_disclosure, None);
}

#[test]
fn a_ring_tag_equal_to_spp_merge_names_no_record_and_no_source() {
    let (mut group, _) = record_merge_group();
    group.outer.data[0] = tag::RING_MERGE_TRANSACT;
    let origin = ring_event_origin_in(std::slice::from_ref(&group), 0, RING).unwrap();
    assert_eq!(origin.merge_disclosure, None);
    let (mut group, _) = record_merge_group();
    group.inner[0].program_id = RING;
    assert!(matches!(
        ring_event_origin_in(std::slice::from_ref(&group), 0, RING),
        Err(AuditError::InvalidEventIndex(0))
    ));
}

#[test]
fn rpc_origin_binds_the_confirmed_slot() {
    let origin =
        confirmed_origin(withdrawing_transaction(Vec::new(), Vec::new()), 0, RING).unwrap();
    let mut indexed = ShieldedTransaction {
        slot: 7,
        tx_signature: Signature::from([6; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: Vec::new(),
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    origin.bind_transaction(&mut indexed, RING).unwrap();
    indexed.slot = 8;
    assert!(matches!(
        origin.bind_transaction(&mut indexed, RING),
        Err(AuditError::ConfirmedEventMismatch)
    ));
}

#[test]
fn policy_owners_come_from_confirmed_metadata_without_live_accounts() {
    use custom_ring_interface::{RingRail, RingTransactData};
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../test-vectors/proof/ring-transact-expansion.json"
    ))
    .unwrap();
    let bytes = hex::decode(vectors["cases"][0]["compact"].as_str().unwrap()).unwrap();
    let parsed = RingTransactData::parse(&bytes, RingRail::Confidential).unwrap();
    let mut data = parsed.data().clone();
    let owners = [[0x61; 32]];
    let transfers = vec![
        InterfaceTransfer::SolWithdrawal { amount: 7 },
        InterfaceTransfer::SplWithdrawal {
            amount: 9,
            spl_interface_bump: 0,
        },
    ];
    data.interface_transfers = transfers.clone();
    data.spl_withdrawal_owners = &owners;
    let mut frame = vec![ring_tag::TRANSFER];
    frame.extend(data.encode().unwrap());
    let mut source = instruction(POOL, 2);
    source.data = ring_transact_bytes(transfers);
    let mut legs = vec![
        RingWithdrawal {
            screened_owner: None,
            recipient: RECIPIENT,
            asset: SOL_MINT,
            amount: 7,
        },
        RingWithdrawal {
            screened_owner: None,
            recipient: TOKEN_ACCOUNT,
            asset: MINT,
            amount: 9,
        },
    ];
    // No account backend is involved, so changing or closing TOKEN_ACCOUNT later cannot alter this.
    bind_withdrawal_owners(&source, &frame, &mut legs).unwrap();
    assert_eq!(legs[0].screened_owner, Some(RECIPIENT));
    assert_eq!(
        legs[1].screened_owner,
        Some(Address::new_from_array(owners[0]))
    );
    source.data = ring_transact_bytes(vec![InterfaceTransfer::SolWithdrawal { amount: 8 }]);
    assert!(bind_withdrawal_owners(&source, &frame, &mut legs).is_err());
}

/// One in-proof or signer frame and its forwarded SPP data, the pool accounts ending in a SOL leg.
fn origin_of_frame(
    in_proof: bool,
    interface_transfers: Vec<InterfaceTransfer>,
) -> Result<RingOrigin, AuditError> {
    use custom_ring_interface::{
        CustomRingProof, FrameExtensions, InProofOwner, InputTrees, PlainGroth16Proof, RingOutput,
        SlotBody,
    };
    let zero = [0u8; 32];
    let groth16 = PlainGroth16Proof {
        proof_a: zero,
        proof_b: [0; 64],
        proof_c: zero,
    };
    let proof = CustomRingProof {
        groth16,
        commitment: zero,
        commitment_pok: zero,
    };
    let (hash, u) = ([1u8; 32], [2u8; 32]);
    let record = [4u8; custom_ring_interface::OUTPUT_RECORD_LEN];
    let nullifiers = [[7u8; 32]];
    let envelope = [0u8; 2048];
    let keys = [0u8; 64];
    let output = RingOutput {
        hash: &hash,
        owner_tag: custom_ring_interface::stream::slot_tag(u),
        body: SlotBody::Recipient(&record),
        record: &record,
    };
    let context = TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    };
    let mut data = RingTransactData {
        rail: RingRail::Confidential,
        n_in: 1,
        n_out: 2,
        proof: &proof,
        tracking_revision: Default::default(),
        own_revision: None,
        policy: None,
        spl_withdrawal_owners: &[],
        approval: Default::default(),
        no_spend: false,
        public_owners: false,
        expiry_unix_ts: 0,
        tx_viewing_u: &zero,
        salt: &[0; 16],
        extensions: FrameExtensions::default(),
        interface_transfers: interface_transfers.clone(),
        has_data: false,
        entry: false,
        wide_owners: false,
        outputs: vec![output, output],
        replies: None,
        sender: None,
        envelope: &[],
        recipient_keys: &keys,
        private_tx_hash: &zero,
        anonymous: None,
        in_proof_owner: in_proof.then_some(InProofOwner {
            owner: &zero,
            commitment: &zero,
            commitment_pok: &zero,
        }),
        spp_proof: &groth16,
        nullifiers: &nullifiers,
        input_trees: InputTrees::One(context),
    };
    data.envelope = &envelope[..data.audit_stream().unwrap().envelope().len];
    let frame = [vec![ring_tag::TRANSFER], data.encode().unwrap()].concat();
    let spp = TransactIxData {
        expiry_unix_ts: u64::MAX,
        private_tx_hash: zero,
        circuit: data.circuit(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        proof: TransactProof::zeroed(),
        inputs: Vec::new(),
        interface_transfers,
        data_hash: None,
        ring_data_hash: None,
        outputs: Vec::new(),
        messages: Vec::new(),
        tree_contexts: vec![context],
    };
    let mut source = instruction(POOL, 2);
    source.data = [vec![tag::RING_TRANSACT], spp.serialize().unwrap()].concat();
    source.accounts = vec![OTHER, OTHER, SOL, RECIPIENT];
    let mut event = instruction(POOL, 3);
    event.data = bs58::decode(event_data()).into_vec().unwrap();
    let mut outer = instruction(RING, 1);
    outer.data = frame;
    ring_event_origin_in(
        &[InstructionGroup {
            outer,
            inner: vec![source, event],
        }],
        0,
        RING,
    )
}

#[test]
fn an_in_proof_withdrawal_reads_under_the_confidential_rail() {
    let leg = vec![InterfaceTransfer::SolWithdrawal { amount: 4_200 }];
    let signer = origin_of_frame(false, leg.clone()).expect("signer rail reads");
    assert_eq!(signer.withdrawals.len(), 1);
    let no_leg = origin_of_frame(true, Vec::new()).expect("in-proof without a leg reads");
    assert!(no_leg.audit_frame(RingMode::Confidential).is_ok());
    let in_proof = origin_of_frame(true, leg).expect("in-proof with a leg reads");
    assert_eq!(in_proof.withdrawals.len(), 1);
    assert!(in_proof.audit_frame(RingMode::Confidential).is_ok());
}

fn tagged_frames(committed: &str, tag_byte: u8) -> Vec<Vec<u8>> {
    committed
        .lines()
        .map(|line| [vec![tag_byte], hex::decode(line.trim()).unwrap()].concat())
        .collect()
}

#[test]
fn a_frame_reads_under_its_tag_alone() {
    let current = include_str!("../../../../../test-vectors/settlement/frame.hex");
    let [first, ..] = &tagged_frames(current, ring_tag::TRANSFER)[..] else {
        panic!("a vector frame")
    };
    assert!(audit_frame_of(first, RingMode::Confidential).is_ok());
    for unassigned in [31, 43, 44, 45, 46, 47] {
        assert!(audit_frame_of(&[unassigned], RingMode::Confidential).is_err());
    }
}

#[test]
fn a_failed_settlement_yields_no_origin() {
    let settled = withdrawing_transaction(Vec::new(), Vec::new());
    let mut failed = serde_json::to_value(&settled).unwrap();
    failed["meta"]["err"] = serde_json::json!("AccountNotFound");
    let failed: EncodedConfirmedTransactionWithStatusMeta = serde_json::from_value(failed).unwrap();
    assert!(matches!(
        confirmed_origin(failed, 0, RING),
        Err(AuditError::Client(ClientError::TransactionFailed(_)))
    ));
}
