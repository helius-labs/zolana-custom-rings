//! The SPP account positions the ring program reads, against the pinned SPP builders.

use custom_ring_interface::{
    amount_field, signed_amount, CoSignScope, PublicLeg, PublicSlotError, PublicSlots,
    RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX, RING_TRANSACT_ACCOUNT_PREFIX_LEN,
    RING_TRANSACT_RING_CONFIG_INDEX, SOL_ASSET_ADDRESS, SYSTEM_PROGRAM_ID, TRANSACT_PAYER_INDEX,
};
use solana_address::Address;
use spr_hasher::primitives::{hash_bytes, right_align};
use spr_instruction::instruction::{DepositAsset, MergeRing, RingTransact};
use spr_interface::{
    instruction::{
        instruction_data::merge_transact::{MergeOutputEncryption, MergeProof},
        CircuitId, InterfaceTransfer, MergeTransactIxData, TransactIxData, TransactProof,
    },
    pda, N_PUBLIC_SLOTS, SOL_ASSET_FIELD,
};
use spr_transaction::instructions::transact::signed_magnitude_to_field;

const PAYER: Address = Address::new_from_array([1; 32]);
const RING: Address = Address::new_from_array([2; 32]);
const TREE: Address = Address::new_from_array([3; 32]);
const INPUT_TREE: Address = Address::new_from_array([4; 32]);

fn ring_config() -> Address {
    pda::ring_auth(&RING).0
}

#[test]
fn transact_accounts_put_the_payer_and_the_ring_config_where_the_ring_reads_them() {
    let transact = RingTransact {
        payer: PAYER,
        input_trees: vec![INPUT_TREE],
        output_tree: TREE,
        ring_program_id: RING,
        owner_signers: vec![],
        interface_transfer_accounts: vec![],
        data: TransactIxData {
            expiry_unix_ts: 0,
            tx_viewing_pk: [4; 33],
            salt: [0; 16],
            interface_transfers: vec![],
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![],
            messages: vec![],
            private_tx_hash: [0; 32],
            circuit: CircuitId::ConfidentialRingEddsa(1, 2, N_PUBLIC_SLOTS as u8),
            proof: TransactProof::zeroed(),
            inputs: vec![],
            tree_contexts: vec![],
        },
    }
    .cpi_instruction();
    let accounts = &transact.accounts;
    assert_eq!(accounts[TRANSACT_PAYER_INDEX].pubkey, PAYER);
    assert!(accounts[TRANSACT_PAYER_INDEX].is_signer);
    assert_eq!(
        accounts[RING_TRANSACT_RING_CONFIG_INDEX].pubkey,
        ring_config()
    );
    assert!(accounts[RING_TRANSACT_RING_CONFIG_INDEX].is_signer);
    assert_eq!(
        accounts[RING_TRANSACT_ACCOUNT_PREFIX_LEN].pubkey,
        INPUT_TREE
    );
}

#[test]
fn merge_accounts_put_the_payer_and_the_ring_config_where_the_ring_reads_them() {
    let merge = MergeRing {
        input_tree: INPUT_TREE,
        output_tree: TREE,
        ring_program_id: RING,
        payer: PAYER,
        owner: None,
        data: MergeTransactIxData {
            expiry_unix_ts: 0,
            proof: MergeProof {
                a: [0; 32],
                b: [0; 128],
                c: [0; 32],
            },
            output_utxo_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: Default::default(),
                ciphertext: Default::default(),
            },
            private_tx_hash: [0; 32],
            nullifiers: vec![[1; 32]],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
        output_ring_data_hash: [0; 32],
        cache: None,
    }
    .cpi_instruction();
    let accounts = &merge.accounts;
    assert_eq!(accounts[RING_MERGE_PAYER_INDEX].pubkey, PAYER);
    assert!(accounts[RING_MERGE_PAYER_INDEX].is_signer);
    assert_eq!(accounts[RING_MERGE_RING_CONFIG_INDEX].pubkey, ring_config());
    assert!(accounts[RING_MERGE_RING_CONFIG_INDEX].is_signer);
}

#[test]
fn sol_and_the_system_program_keep_their_zero_addresses() {
    assert_eq!(SOL_ASSET_ADDRESS, DepositAsset::Sol.mint().to_bytes());
    assert_eq!(
        SYSTEM_PROGRAM_ID,
        solana_address::address!("11111111111111111111111111111111")
    );
}

#[test]
fn public_amount_fields_match_the_spp_proof_inputs() {
    let spl_interface_bump = 0;
    for amount in [1, 7, u64::MAX] {
        for (transfer, is_deposit) in [
            (InterfaceTransfer::SolDeposit { amount }, true),
            (InterfaceTransfer::SolWithdrawal { amount }, false),
            (
                InterfaceTransfer::SplDeposit {
                    amount,
                    spl_interface_bump,
                },
                true,
            ),
            (
                InterfaceTransfer::SplWithdrawal {
                    amount,
                    spl_interface_bump,
                },
                false,
            ),
        ] {
            assert_eq!(
                amount_field(signed_amount(transfer)).unwrap(),
                signed_magnitude_to_field(is_deposit, amount),
                "{transfer:?}"
            );
        }
    }
    let beyond = i128::from(u64::MAX) + 1;
    assert!(amount_field(beyond).is_err());
    assert!(amount_field(-beyond).is_err());
}

fn sol(amount: u64, deposit: bool) -> PublicLeg {
    PublicLeg {
        transfer: match deposit {
            true => InterfaceTransfer::SolDeposit { amount },
            false => InterfaceTransfer::SolWithdrawal { amount },
        },
        mint: None,
    }
}

fn spl(mint: [u8; 32], amount: u64, deposit: bool) -> PublicLeg {
    let spl_interface_bump = 0;
    PublicLeg {
        transfer: match deposit {
            true => InterfaceTransfer::SplDeposit {
                amount,
                spl_interface_bump,
            },
            false => InterfaceTransfer::SplWithdrawal {
                amount,
                spl_interface_bump,
            },
        },
        mint: Some(mint),
    }
}

fn fold<const N: usize>(legs: [PublicLeg; N]) -> Result<PublicSlots, PublicSlotError> {
    PublicSlots::fold(legs.map(Ok))
}

#[test]
fn public_slots_fold_the_gross_withdrawal_per_asset_without_its_deposits() {
    let mint = [9; 32];
    let slots = fold([
        sol(60, false),
        spl(mint, 100, true),
        sol(40, false),
        spl(mint, 5, false),
    ])
    .unwrap();
    assert_eq!(
        slots.asset_fields().unwrap(),
        [SOL_ASSET_FIELD, hash_bytes(&mint).unwrap(), [0; 32]]
    );
    assert_eq!(slots.amounts(), [-100, 95, 0]);
    assert_eq!(slots.gross(), [100, 5, 0]);
    assert_eq!(
        slots.gross_fields(),
        slots.gross().map(|gross| right_align(&gross.to_be_bytes()))
    );
    let fourth = fold([
        spl([1; 32], 1, false),
        spl([2; 32], 1, false),
        spl([3; 32], 1, false),
        spl([4; 32], 1, false),
    ]);
    assert!(matches!(
        fourth,
        Err(PublicSlotError::TooManyAssets { asset }) if asset == [4; 32]
    ));
}

#[test]
fn public_slots_name_the_classes_of_their_legs() {
    let classes = |legs: &[PublicLeg]| {
        PublicSlots::fold(legs.iter().copied().map(Ok::<_, PublicSlotError>))
            .unwrap()
            .classes()
    };
    assert_eq!(classes(&[]), CoSignScope::NONE);
    assert_eq!(classes(&[sol(1, true)]), CoSignScope::DEPOSITS);
    assert_eq!(classes(&[sol(1, false)]), CoSignScope::WITHDRAWALS);
    assert_eq!(
        classes(&[sol(2, false), sol(1, true)]),
        CoSignScope::DEPOSITS | CoSignScope::WITHDRAWALS
    );
}

#[test]
fn a_gross_past_u64_survives_a_net_within_it() {
    let slots = fold([sol(u64::MAX, false), sol(u64::MAX, true), sol(1, false)]).unwrap();
    assert_eq!(slots.amounts()[0], -1);
    assert_eq!(slots.gross()[0], u128::from(u64::MAX) + 1);
    assert!(matches!(
        fold([sol(u64::MAX, false), sol(1, false)]),
        Err(PublicSlotError::AmountOverflow { .. })
    ));
    assert!(matches!(
        fold([sol(7, false), sol(7, true)]),
        Err(PublicSlotError::ZeroNet { .. })
    ));
}

#[test]
fn the_widest_accepted_legs_fold_a_gross_past_u64_to_a_net_within_it() {
    let mut legs = [sol(u64::MAX, true); spr_interface::MAX_INTERFACE_TRANSFERS];
    for [withdrawal, _] in legs.as_chunks_mut::<2>().0 {
        *withdrawal = sol(u64::MAX, false);
    }
    legs[legs.len() - 1] = sol(u64::MAX - 1, true);
    let slots = fold(legs).unwrap();
    assert_eq!(slots.amounts(), [-1, 0, 0]);
    let withdrawals = (spr_interface::MAX_INTERFACE_TRANSFERS / 2) as u128;
    assert_eq!(slots.gross()[0], withdrawals * u128::from(u64::MAX));
    assert_eq!(
        slots.classes(),
        CoSignScope::DEPOSITS | CoSignScope::WITHDRAWALS
    );
}

#[test]
fn an_intermediate_net_past_u64_is_refused_whatever_the_final_net() {
    // SPP's `assign_public_amounts_and_assets` refuses the same running net.
    assert!(matches!(
        fold([sol(u64::MAX, true), sol(1, true), sol(2, false)]),
        Err(PublicSlotError::AmountOverflow { .. })
    ));
    let reordered = fold([sol(u64::MAX, true), sol(2, false), sol(1, true)]).unwrap();
    assert_eq!(reordered.amounts()[0], i128::from(u64::MAX) - 1);
}
