use custom_ring_interface::{
    cosign::ApprovalMask, storage::Revision, stream::slot_tag, AnonymousProofData, AppMessage,
    BundleLayout, CustomRingProof, FrameExtensions, FramedSenderBundle, InputTrees,
    PlainGroth16Proof, Replies, RingOutput, SlotBody, MIN_REPLY_LEN, OUTPUT_RECORD_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1;
use spr_client::ComputeBudgetConfig;
use spr_interface::instruction::TreeContext;
use spr_transaction::Mint;

use super::*;
use crate::tests::support::keypair;

const LIMIT: usize = v1::MAX_ADDRESSES as usize;

fn address(seed: u32) -> Address {
    let mut bytes = [0xaa; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    Address::new_from_array(bytes)
}

fn note(owner: u8, seed: u32) -> SpentInput {
    SpentInput {
        owner: keypair(owner).signing_pubkey(),
        asset: Mint::SOL.asset,
        nullifier_pubkey: [owner; 32],
        data_hash: None,
        ring_program_id: Some(address(0)),
        tree_id: 1,
        nullifier_pda: address(1000 + seed),
    }
}

/// Payer, program, one nullifier PDA per input and `other` accounts.
fn decide(inputs: &[SpentInput], other: u32) -> Result<CeilingDecision, AddressCeilingError> {
    decide_under(
        inputs,
        other,
        MergeCapacity {
            keyed: 45,
            zero_key: 45,
        },
    )
}

fn decide_under(
    inputs: &[SpentInput],
    other: u32,
    merge_capacity: MergeCapacity,
) -> Result<CeilingDecision, AddressCeilingError> {
    let accounts = inputs
        .iter()
        .map(|input| input.nullifier_pda)
        .chain((0..other).map(|seed| address(5000 + seed)))
        .map(|account| AccountMeta::new(account, false))
        .collect();
    AddressCeiling {
        payer: address(1),
        instruction: &Instruction {
            program_id: address(2),
            accounts,
            data: Vec::new(),
        },
        budget: ComputeBudgetConfig::new(1_000_000),
        inputs,
        merge_capacity,
    }
    .decide()
}

#[test]
fn a_transaction_at_the_ceiling_stays_one_transaction() {
    let inputs: Vec<_> = (0..10).map(|seed| note(1, seed)).collect();
    let other = LIMIT as u32 - 2 - 10;
    let Ok(CeilingDecision::Inline(size)) = decide(&inputs, other) else {
        panic!("under the ceiling");
    };
    assert_eq!(size.addresses, LIMIT);
}

/// The compiled count passes by two, the wider group alone reaches the ceiling.
#[test]
fn merging_first_names_only_the_groups_the_ceiling_needs() {
    let inputs: Vec<_> = (0..4)
        .map(|seed| note(1, seed))
        .chain((4..6).map(|seed| note(2, seed)))
        .collect();
    let other = LIMIT as u32 - 2 - 6 + 2;
    let Ok(CeilingDecision::MergeFirst { groups, addresses }) = decide(&inputs, other) else {
        panic!("merge first");
    };
    assert_eq!(addresses, LIMIT - 1);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].inputs, [0, 1, 2, 3]);
    assert_eq!(groups[0].owner, inputs[0].owner);
}

#[test]
fn mixed_owners_form_no_group_and_report_the_compiled_count() {
    let inputs: Vec<_> = (0..4).map(|seed| note(seed as u8 + 1, seed)).collect();
    let other = LIMIT as u32 - 2 - 4 + 1;
    let Err(AddressCeilingError::Unsupported {
        compiled,
        limit,
        after_merging,
        data_notes,
    }) = decide(&inputs, other)
    else {
        panic!("unsupported");
    };
    assert_eq!((compiled, limit), (LIMIT + 1, LIMIT));
    assert_eq!((after_merging, data_notes), (LIMIT + 1, 0));
}

#[test]
fn a_data_note_stays_out_of_every_group() {
    let inputs: Vec<_> = (0..4)
        .map(|seed| SpentInput {
            data_hash: Some([9; 32]),
            ..note(1, seed)
        })
        .collect();
    let other = LIMIT as u32 - 2 - 4 + 1;
    let Err(AddressCeilingError::Unsupported {
        after_merging,
        data_notes,
        ..
    }) = decide(&inputs, other)
    else {
        panic!("unsupported");
    };
    assert_eq!((after_merging, data_notes), (LIMIT + 1, 4));
}

#[test]
fn notes_of_another_asset_or_key_or_tree_do_not_merge() {
    let first = note(1, 0);
    let unlike = [
        SpentInput {
            asset: address(7),
            ..note(1, 1)
        },
        SpentInput {
            nullifier_pubkey: [9; 32],
            ..note(1, 2)
        },
        SpentInput {
            tree_id: 2,
            ..note(1, 3)
        },
    ];
    let inputs = [&[first][..], &unlike].concat();
    let other = LIMIT as u32 - 2 - 4 + 1;
    assert!(matches!(
        decide(&inputs, other),
        Err(AddressCeilingError::Unsupported { .. })
    ));
}

#[test]
fn consolidation_short_of_the_ceiling_is_refused_with_how_far_it_reached() {
    let inputs: Vec<_> = (0..4).map(|seed| note(1, seed)).collect();
    let other = LIMIT as u32 - 2 - 4 + 5;
    let Err(AddressCeilingError::Unsupported {
        compiled,
        after_merging,
        ..
    }) = decide(&inputs, other)
    else {
        panic!("unsupported");
    };
    assert_eq!((compiled, after_merging), (LIMIT + 5, LIMIT + 2));
}

/// A group past one merge's capacity leaves one note per merge, the count reads each.
#[tokio::test]
async fn an_oversized_group_splits_and_the_count_keeps_every_note_left() {
    use crate::{
        tests::support::{ring, ring_utxo, Chain, RingSettings, TREE_ID},
        FittedMerge, MergeProofInput,
    };
    use custom_ring_interface::RingMode;
    use spr_interface::pda;

    let owner = keypair(1);
    let notes: Vec<_> = (0..49)
        .map(|leaf| ring_utxo(&owner, Mint::SOL, 5, leaf))
        .collect();
    let keyed = FittedMerge {
        ring: ring(),
        inputs: notes,
        output_tree_id: TREE_ID,
        keys: &owner,
        proof_input: &MergeProofInput {
            nullifier_key: owner.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID),
        },
        payer: address(1),
    }
    .prepare(&Chain::ring(RingSettings::new(RingMode::Confidential)))
    .await
    .unwrap()
    .published_inputs();
    assert!(keyed < 49);
    let capacity = MergeCapacity {
        keyed,
        zero_key: keyed,
    };

    let inputs: Vec<_> = (0..49).map(|seed| note(1, seed)).collect();
    // Past the first merge alone, two notes left reach the ceiling exactly.
    let reachable = LIMIT as u32 - 2 - 2;
    let Ok(CeilingDecision::MergeFirst { groups, addresses }) =
        decide_under(&inputs, reachable, capacity)
    else {
        panic!("merge first");
    };
    assert_eq!(addresses, LIMIT);
    let widths: Vec<usize> = groups.iter().map(|group| group.inputs.len()).collect();
    assert_eq!(widths, [keyed, 49 - keyed]);
    assert!(widths.iter().all(|width| *width <= keyed));

    // One more account, an unsplit group of one PDA would still read as under the ceiling.
    let Err(AddressCeilingError::Unsupported { after_merging, .. }) =
        decide_under(&inputs, reachable + 1, capacity)
    else {
        panic!("unsupported");
    };
    assert_eq!(after_merging, LIMIT + 1);
}

/// One input past a capacity is a run of one, it stays a note of its own and merges nothing.
#[test]
fn a_lone_note_past_the_capacity_is_named_by_no_merge() {
    let inputs: Vec<_> = (0..4).map(|seed| note(1, seed)).collect();
    let capacity = MergeCapacity {
        keyed: 3,
        zero_key: 3,
    };
    let Ok(CeilingDecision::MergeFirst { groups, addresses }) =
        decide_under(&inputs, LIMIT as u32 - 2 - 4 + 1, capacity)
    else {
        panic!("merge first");
    };
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].inputs, [0, 1, 2]);
    assert_eq!(addresses, LIMIT - 1);
}

/// The owner's signature and account leave a zero-key merge narrower, pinned from its own selection.
#[tokio::test]
async fn a_zero_key_group_splits_at_the_zero_key_capacity() {
    use crate::{
        tests::support::{ring, ring_utxo, zero_key, Chain, RingSettings, TREE_ID},
        FittedMerge, MergeProofInput,
    };
    use custom_ring_interface::RingMode;
    use spr_interface::{pda, ZERO_NULLIFIER_PUBKEY};

    let owner = keypair(1);
    let notes: Vec<_> = (0..52)
        .map(|leaf| zero_key(ring_utxo(&owner, Mint::SOL, 5, leaf)))
        .collect();
    let carried = FittedMerge {
        ring: ring(),
        inputs: notes,
        output_tree_id: TREE_ID,
        keys: &owner,
        proof_input: &MergeProofInput {
            nullifier_key: owner.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID),
        },
        payer: address(1),
    }
    .prepare(&Chain::ring(RingSettings::new(RingMode::Confidential)))
    .await
    .unwrap()
    .published_inputs();
    assert_eq!(carried, WIDEST_ZERO_KEY_MERGE);

    let inputs: Vec<_> = (0..4)
        .map(|seed| SpentInput {
            nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
            ..note(1, seed)
        })
        .collect();
    let capacity = MergeCapacity {
        keyed: 45,
        zero_key: 2,
    };
    let Ok(CeilingDecision::MergeFirst { groups, .. }) =
        decide_under(&inputs, LIMIT as u32 - 2 - 4 + 1, capacity)
    else {
        panic!("merge first");
    };
    assert_eq!(groups[0].inputs, [0, 1]);
}

/// Inputs a zero-key merge carries in one v1 transaction, measured here.
const WIDEST_ZERO_KEY_MERGE: usize = 43;

/// An anonymous transfer of `inputs` x `outputs`, slot 0 change, each other slot a body and a reply.
fn anonymous_transfer(inputs: usize, outputs: usize, reply_len: Option<usize>) -> Instruction {
    anonymous_transfer_with(inputs, outputs, reply_len, FrameExtensions::default())
}

fn anonymous_transfer_with(
    inputs: usize,
    outputs: usize,
    reply_len: Option<usize>,
    extensions: FrameExtensions<'_>,
) -> Instruction {
    let proof = CustomRingProof::zeroed();
    let spp_proof = PlainGroth16Proof::zeroed();
    let field = [1; 32];
    let salt = [2; 16];
    let body = [4; OUTPUT_RECORD_LEN];
    let bundle = vec![5; BundleLayout { outputs }.byte_len()];
    let nullifiers = vec![field; inputs];
    let region = vec![6; reply_len.unwrap_or(0) * outputs];
    let keys = vec![8; 32 * outputs];
    let envelope_room = vec![7; 8192];
    let mut data = RingTransactData {
        rail: RingRail::Anonymous,
        n_in: inputs as u8,
        n_out: outputs as u8,
        proof: &proof,
        tracking_revision: Revision::from(9),
        own_revision: None,
        policy: None,
        spl_withdrawal_owners: &[],
        approval: ApprovalMask::default(),
        no_spend: false,
        public_owners: false,
        expiry_unix_ts: u32::MAX,
        tx_viewing_u: &field,
        salt: &salt,
        extensions,
        interface_transfers: Vec::new(),
        has_data: false,
        entry: false,
        wide_owners: false,
        outputs: (0..outputs)
            .map(|slot| RingOutput {
                hash: &field,
                owner_tag: match slot {
                    0 => [0; 32],
                    _ => slot_tag(field),
                },
                body: SlotBody::Recipient(&body),
                record: &body,
            })
            .collect(),
        replies: reply_len.map(|len| Replies::new(len as u16, &region).unwrap()),
        sender: Some(FramedSenderBundle {
            tag: &field,
            body: &bundle,
        }),
        envelope: &[],
        recipient_keys: &keys,
        private_tx_hash: &field,
        anonymous: Some(AnonymousProofData {
            commitment: &field,
            commitment_pok: &field,
            default_owner_tag: None,
        }),
        in_proof_owner: None,
        spp_proof: &spp_proof,
        nullifiers: &nullifiers,
        input_trees: InputTrees::One(TreeContext {
            utxo_tree_root_index: 1,
            nullifier_tree_root_index: 2,
        }),
    };
    data.envelope = &envelope_room[..data.audit_stream().unwrap().envelope().len];
    Instruction {
        program_id: address(2),
        accounts: vec![AccountMeta::new(address(1), true)],
        data: [
            vec![custom_ring_interface::tag::TRANSFER],
            data.encode().unwrap(),
        ]
        .concat(),
    }
}

/// A message count past SPP's list names the rail's limit, the fit never reads it as an unparsed frame.
#[test]
fn a_frame_past_the_application_message_limit_is_refused_by_name() {
    let view_tag = [8; 32];
    let message = AppMessage {
        view_tag: &view_tag,
        data: &[],
    };
    let one = anonymous_transfer_with(
        1,
        2,
        None,
        FrameExtensions {
            messages: vec![message],
            ..FrameExtensions::default()
        },
    );
    assert!(fit(&one).is_ok());
    let count = one
        .data
        .windows(32)
        .position(|window| window == view_tag)
        .unwrap()
        - 1;
    assert_eq!(one.data[count], 1);
    let mut past = one;
    past.data[count] = u8::MAX;
    assert!(matches!(
        fit(&past),
        Err(FitError::ApplicationMessages { limit })
            if limit == custom_ring_interface::max_application_messages(RingRail::Anonymous)
    ));
}

fn budget() -> ComputeBudgetConfig {
    ComputeBudgetConfig::new(1_000_000)
}

fn fit(instruction: &Instruction) -> Result<Fit, FitError> {
    TransactionFit::of(instruction, FitSigners::new(address(1)), budget())
}

fn decide_transfer(instruction: &Instruction) -> Result<CeilingDecision, AddressCeilingError> {
    AddressCeiling {
        payer: address(1),
        instruction,
        budget: budget(),
        inputs: &[],
        merge_capacity: MergeCapacity {
            keyed: 45,
            zero_key: 45,
        },
    }
    .decide()
}

/// Past the payer, `signers` more required signatures.
fn with_signers(mut instruction: Instruction, signers: u32) -> Instruction {
    instruction
        .accounts
        .extend((0..signers).map(|seed| AccountMeta::new_readonly(address(7000 + seed), true)));
    instruction
}

fn carrying(signers: u32) -> Instruction {
    with_signers(
        Instruction {
            program_id: address(2),
            accounts: Vec::new(),
            data: Vec::new(),
        },
        signers,
    )
}

#[test]
fn past_the_byte_ceiling_a_transfer_refuses_at_each_preproof_check() {
    let small = anonymous_transfer(2, 2, None);
    let inline = fit(&small).unwrap();
    assert!(inline.bytes > small.data.len());
    assert!(matches!(
        decide_transfer(&small),
        Ok(CeilingDecision::Inline(size)) if size.bytes == inline.bytes
    ));

    let wide = anonymous_transfer(16, 8, Some(4 * MIN_REPLY_LEN));
    assert!(spp_cpi_bytes(&wide).unwrap().is_some());
    let refused = |bytes: usize| bytes > wide.data.len() && bytes > v1::MAX_TRANSACTION_SIZE;
    assert!(matches!(
        fit(&wide),
        Err(FitError::Bytes { bytes, limit: v1::MAX_TRANSACTION_SIZE }) if refused(bytes)
    ));
    assert!(matches!(
        decide_transfer(&wide),
        Err(AddressCeilingError::Fit(FitError::Bytes { bytes, .. })) if refused(bytes)
    ));
    assert!(matches!(
        crate::submission::check_transaction_size(&address(1), &wide, budget()),
        Err(RingError::TransactionTooLarge { bytes, limit: v1::MAX_TRANSACTION_SIZE })
            if refused(bytes)
    ));
}

#[test]
fn signatures_past_the_limit_refuse_at_each_preproof_check() {
    let limit = usize::from(v1::MAX_SIGNATURES);
    let payer_signs = |signature_count: usize| signature_count as u32 - 1;

    let at_limit = fit(&carrying(payer_signs(limit))).unwrap();
    assert_eq!(at_limit.signatures, limit);
    let past = carrying(payer_signs(limit + 1));
    assert!(matches!(
        fit(&past),
        Err(FitError::Signatures { signatures, limit: 12 }) if signatures == limit + 1
    ));
    assert!(matches!(
        decide_transfer(&past),
        Err(AddressCeilingError::Fit(FitError::Signatures { .. }))
    ));
    assert!(matches!(
        crate::submission::check_transaction_size(&address(1), &past, budget()),
        Err(RingError::AddressCeiling(AddressCeilingError::Fit(
            FitError::Signatures { .. }
        )))
    ));

    let repeated = with_signers(with_signers(carrying(0), 3), 3);
    assert_eq!(fit(&repeated).unwrap().signatures, 4);
}

#[test]
fn an_expansion_past_the_cpi_limit_refuses() {
    let refused_at = (MIN_REPLY_LEN..)
        .find(|len| {
            matches!(
                spp_cpi_bytes(&anonymous_transfer(5, 8, Some(*len))),
                Err(FitError::CpiBytes { .. })
            )
        })
        .unwrap();
    let refused = anonymous_transfer(5, 8, Some(refused_at));
    assert!(matches!(
        decide_transfer(&refused),
        Err(AddressCeilingError::Fit(FitError::CpiBytes { bytes, limit: MAX_CPI_DATA_LEN }))
            if bytes > MAX_CPI_DATA_LEN
    ));
    let last_fit = spp_cpi_bytes(&anonymous_transfer(5, 8, Some(refused_at - 1))).unwrap();
    assert!(last_fit.is_some_and(|bytes| bytes <= MAX_CPI_DATA_LEN));
}

#[test]
fn the_expansion_counts_the_exact_bytes_the_program_forwards() {
    let wide = anonymous_transfer(5, 8, Some(MIN_REPLY_LEN));
    let parsed = RingTransactData::parse(&wide.data[1..], RingRail::Anonymous).unwrap();
    let forwarded = parsed
        .data()
        .spp_instruction_data_under(&RingPolicy::zeroed(), TransactProof::zeroed())
        .unwrap();
    assert_eq!(spp_cpi_bytes(&wide).unwrap(), Some(forwarded.len()));

    let garbled = Instruction {
        data: vec![custom_ring_interface::tag::TRANSFER, 0],
        ..wide
    };
    assert!(matches!(fit(&garbled), Err(FitError::UnparsedFrame)));
}

#[test]
fn setup_joins_the_count_and_can_refuse() {
    let signers = |setup| FitSigners::new(address(1)).with_setup(setup);
    let create = Instruction {
        program_id: address(3),
        accounts: vec![
            AccountMeta::new(address(1), true),
            AccountMeta::new(address(4), false),
            AccountMeta::new_readonly(address(5), true),
        ],
        data: vec![1],
    };
    let small = anonymous_transfer(2, 2, None);
    let alone = fit(&small).unwrap();
    let setup = core::slice::from_ref(&create);
    let joined = TransactionFit::of(&small, signers(setup), budget()).unwrap();
    assert_eq!(joined.setup.instructions, 1);
    assert_eq!(joined.setup.signatures, 1);
    assert_eq!(joined.setup.addresses, 3);
    assert_eq!(joined.bytes, alone.bytes + joined.setup.bytes);
    assert_eq!(joined.addresses, alone.addresses + 3);

    let filler = Instruction {
        data: vec![0; v1::MAX_TRANSACTION_SIZE - alone.bytes],
        ..create.clone()
    };
    let setup = core::slice::from_ref(&filler);
    assert!(matches!(
        TransactionFit::of(&small, signers(setup), budget()),
        Err(FitError::Bytes { .. })
    ));

    let at_ceiling = Instruction {
        program_id: address(2),
        accounts: (0..u32::from(v1::MAX_ADDRESSES) - 2)
            .map(|seed| AccountMeta::new(address(5000 + seed), false))
            .collect(),
        data: Vec::new(),
    };
    assert_eq!(
        fit(&at_ceiling).unwrap().addresses,
        usize::from(v1::MAX_ADDRESSES)
    );
    assert!(matches!(
        TransactionFit::of(&at_ceiling, signers(core::slice::from_ref(&create)), budget()),
        Err(FitError::Addresses { addresses, limit: 64 })
            if addresses == usize::from(v1::MAX_ADDRESSES) + 3
    ));
}
