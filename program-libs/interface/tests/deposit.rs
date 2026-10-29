use custom_ring_interface::{
    CustomRingProof, DepositContext, DepositPublicInput, DepositRegistry, DepositedAsset,
    PlainGroth16Proof, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN as CT,
};
use spr_hasher::HasherError;

#[test]
fn context_binds_ring_tree_wire_and_wire_length() {
    let ring = [1; 32];
    let tree = [2; 32];
    let context = DepositContext {
        program_id: &ring,
        tree: &tree,
        spp_data: &[1],
    };
    let expected = context.hash().unwrap();
    for changed in [
        DepositContext {
            program_id: &[3; 32],
            ..context
        },
        DepositContext {
            tree: &[3; 32],
            ..context
        },
        DepositContext {
            spp_data: &[2],
            ..context
        },
        DepositContext {
            spp_data: &[0, 1],
            ..context
        },
    ] {
        assert_ne!(expected, changed.hash().unwrap());
    }
}

#[test]
fn public_statement_binds_each_opening_ciphertext_key_and_context() {
    let owners = [[1; 32], [2; 32]];
    let ciphertexts = [[3; CT], [4; CT]];
    let assets = [asset(10, 11), asset(12, 13)];
    let input = DepositPublicInput {
        context_hash: &[5; 32],
        anonymous: false,
        owner_utxo_hashes: &owners,
        ciphertexts: &ciphertexts,
        assets: &assets,
        auditor_pk: &[6; 33],
        eph_pk: &[7; 33],
        registry: None,
    };
    let registry = |own_root, key_escrow, policy_hash| {
        Some(DepositRegistry {
            own_root,
            key_escrow,
            policy_hash,
        })
    };
    let expected = input.hash().unwrap();
    for changed in [
        DepositPublicInput {
            context_hash: &[6; 32],
            ..input
        },
        DepositPublicInput {
            anonymous: true,
            ..input
        },
        DepositPublicInput {
            owner_utxo_hashes: &[[2; 32], [1; 32]],
            ..input
        },
        DepositPublicInput {
            ciphertexts: &[[4; CT], [3; CT]],
            ..input
        },
        DepositPublicInput {
            auditor_pk: &[7; 33],
            ..input
        },
        DepositPublicInput {
            eph_pk: &[8; 33],
            ..input
        },
        DepositPublicInput {
            assets: &[asset(10, 11), asset(12, 14)],
            ..input
        },
        DepositPublicInput {
            assets: &[asset(10, 11), asset(14, 13)],
            ..input
        },
        DepositPublicInput {
            registry: registry(&[9; 32], false, None),
            ..input
        },
        DepositPublicInput {
            registry: registry(&[0; 32], false, Some(&[9; 32])),
            ..input
        },
        DepositPublicInput {
            owner_utxo_hashes: &owners[..1],
            ciphertexts: &ciphertexts[..1],
            assets: &assets[..1],
            ..input
        },
    ] {
        assert_ne!(expected, changed.hash().unwrap());
    }
    let escrowed = DepositPublicInput {
        registry: registry(&[9; 32], true, None),
        ..input
    };
    assert_ne!(
        escrowed.hash().unwrap(),
        DepositPublicInput {
            registry: registry(&[9; 32], false, None),
            ..input
        }
        .hash()
        .unwrap()
    );
}

fn asset(asset: u8, amount: u64) -> DepositedAsset {
    DepositedAsset {
        asset: [asset; 32],
        amount,
    }
}

#[test]
fn statement_rejects_empty_oversized_and_mismatched_batches() {
    let input = DepositPublicInput {
        context_hash: &[0; 32],
        anonymous: false,
        owner_utxo_hashes: &[],
        ciphertexts: &[],
        assets: &[],
        auditor_pk: &[0; 33],
        eph_pk: &[0; 33],
        registry: None,
    };
    assert_eq!(input.hash(), Err(HasherError::InvalidNumFields));
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]; 9],
            ciphertexts: &[[0; CT]; 9],
            assets: &[asset(0, 0); 9],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]],
            ciphertexts: &[[0; CT]],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
}

#[test]
fn proof_prefix_size_matches_the_instruction_serializer() {
    let proof = CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: [1; 32],
            proof_b: [2; 64],
            proof_c: [3; 32],
        },
        commitment: [4; 32],
        commitment_pok: [5; 32],
    };
    let bytes = wincode::serialize(&proof).unwrap();
    assert_eq!(bytes.len(), CustomRingProof::SIZE);
    assert_eq!(&bytes[..32], &[1; 32]);
    assert_eq!(&bytes[160..], &[5; 32]);
}
