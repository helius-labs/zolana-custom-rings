use super::*;
use custom_ring_test_validator::{
    policy::ApplyOwnerEnrollments, shared::STORAGE_CPI_OWNER_PROGRAM,
};

#[test]
fn every_apply_capacity_settles_and_refuses_an_altered_root() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    for count in [1, 2, 4, 8, 16] {
        StorageRecords {
            ring,
            writes: allow_writes(count)?,
            env: &env,
        }
        .send()?;
    }
    Ok(())
}

#[test]
fn a_pda_enrolls_and_applies_its_key_on_the_validator() -> Result<()> {
    use custom_ring_interface::STORAGE_PROGRAM_ID;
    use custom_ring_sdk::Enroll;
    use solana_instruction::AccountMeta;
    use spr_keypair::{NullifierKey, ViewingKey};
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let owner = Address::find_program_address(&[b"owner"], &STORAGE_CPI_OWNER_PROGRAM).0;
    let viewing_key = ViewingKey::new();
    let mut instruction = env
        .run(
            Enroll {
                ring,
                payer: env.payer.pubkey(),
                owner,
                nullifier_key: &NullifierKey::from_secret([7; 31]),
                viewing_pubkey: viewing_key.pubkey(),
                list_salt: viewing_key.merge_seed(
                    ring.program_id().as_array(),
                    &zolana_ring_keys::LIST_SALT_LABEL,
                )?,
            }
            .prove(env.client.ring_client()),
        )?
        .instruction();
    instruction.program_id = STORAGE_CPI_OWNER_PROGRAM;
    instruction.accounts[1].is_signer = false;
    instruction
        .accounts
        .push(AccountMeta::new_readonly(STORAGE_PROGRAM_ID, false));
    send(env.client.rpc(), &env.payer, &[instruction])?;
    let enrolled = owner_enrollment(&env, ring, owner)?.context("the PDA's enrollment")?;
    ensure!(enrolled.viewing_u == viewing_key.pubkey().u() && enrolled.is_pending());
    ApplyOwnerEnrollments {
        ring,
        owners: &[owner],
        env: &env,
    }
    .send()?;
    let applied = owner_enrollment(&env, ring, owner)?.context("the PDA's enrollment")?;
    ensure!(!applied.is_pending());
    Ok(())
}

#[test]
fn a_zero_key_payment_settles_for_a_registered_and_an_unregistered_owner_without_a_salted_read(
) -> Result<()> {
    let env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let delegate = env.funded_keypair()?;
    EnrolledDelegate {
        ring,
        delegate: &delegate,
        members: &[sender],
    }
    .set(&env)?;
    let at_zero = |owner: &ShieldedKeypair| -> Result<_> {
        let recipient = ShieldedAddress {
            nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
            ..owner.shielded_address()?
        };
        let input = RingNotes {
            ring,
            owner: sender,
            amount: 1_000_000,
            asset: DepositAsset::Sol,
            count: 1,
            env: &env,
        }
        .deposit()?;
        let input = indexed_note(
            input.into_iter().next().context("deposited input")?,
            sender,
            &env,
            env.tree,
        )?;
        let mut prepared =
            ConfidentialTransaction::new_with_ring(vec![input], sender.pubkey(), ring_program)?
                .with_output_tree_id(env.tree_id(env.tree)?)?;
        prepared.transfer_sol(&recipient, 1)?;
        Ok(prepared)
    };
    // No rule reads a salted list on the payee, so a registered owner may take the zero key too.
    for owner in [sender, &env.recipient.keypair] {
        let receipt = OwnerTransfer {
            ring,
            sender,
            prepared: at_zero(owner)?,
            interface_transfer_accounts: Vec::new(),
            auditor_tag: auditor_view_tag(&auditor.pubkey()),
            cosigner: None,
        }
        .send(&env)?;
        let audited = AuditLookup {
            scan: RingScan::new(ring_program, auditor.pubkey()).with_mode(RingMode::Confidential),
            auditor: &auditor,
            signature: receipt.signature,
        }
        .run(&env)?;
        ensure!(audited
            .outputs
            .iter()
            .filter_map(|output| output.opening.utxo())
            .any(|output| output.amount == 1 && output.nullifier_pk == ZERO_NULLIFIER_PUBKEY));
    }
    Ok(())
}

#[test]
fn viewing_key_rotation_survives_restart_and_a_wallet_wipe() -> Result<()> {
    use spr_keypair::ViewingKey;
    use zolana_ring_client::{AnonymousSync, AnonymousWallet};
    use zolana_ring_keys::RotatingRingKeys;
    let env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::AnonymousAuditOnly,
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    EnrollOwners {
        ring,
        owners: &[sender, recipient],
        env: &env,
    }
    .send()?;
    let notes = RingNotes {
        ring,
        owner: sender,
        amount: 1_000_000,
        asset: DepositAsset::Sol,
        count: 2,
        env: &env,
    }
    .deposit_hidden_from(&env.payer)?;
    let inputs = notes
        .into_iter()
        .map(|note| indexed_note(note, sender, &env, env.tree))
        .collect::<Result<Vec<_>>>()?;
    let assets = env.ring_assets()?;
    let history = ViewingHistory::new(recipient.viewing_pubkey(), 0).with_ring(ring_program, None);
    let mut wallet = AnonymousWallet::new(history);
    let original_keys = RotatingRingKeys::new(recipient)?;
    let mut rotated = recipient.clone();
    rotated.viewing_key = ViewingKey::new();
    let original_address = owner_enrollment(&env, ring, recipient.pubkey())?
        .context("recipient enrollment before rotation")?;
    assert_ne!(rotated.viewing_pubkey(), recipient.viewing_pubkey());
    assert_eq!(rotated.pubkey(), recipient.pubkey());
    assert_eq!(
        rotated.nullifier_key.pubkey()?,
        original_address.nullifier_pk
    );
    for (index, (input, destination)) in inputs.into_iter().zip([recipient, &rotated]).enumerate() {
        if index == 1 {
            EnrollOwners {
                ring,
                owners: &[&rotated],
                env: &env,
            }
            .send()?;
            let updated = owner_enrollment(&env, ring, recipient.pubkey())?
                .context("the rotated recipient enrollment")?;
            assert_eq!(updated.viewing_u, rotated.viewing_pubkey().u());
            assert_eq!(updated.nullifier_pk, original_address.nullifier_pk);
            assert!(!updated.is_pending(), "a rotation leaves no tracking work");
            let history = wallet
                .history()
                .clone()
                .with_rotated_key(rotated.viewing_pubkey(), 1)?;
            wallet.update_history(history)?;
        }
        let payment = AnonymousPayment {
            ring,
            sender,
            payer: env.payer.pubkey(),
            inputs: vec![input],
            to: ring_address(destination, ring_program)?,
            amount: 101 * (index as u64 + 1),
        }
        .transfer()?;
        PaymentLanding {
            transfer: payment,
            payer: &env.payer,
            auditor_tag: auditor_view_tag(&auditor.pubkey()),
        }
        .land(&env)?;
        if index == 0 {
            let scan = env.client.block_on(async {
                AnonymousSync::new(&original_keys, &assets)
                    .fetch_wallet(env.client.as_async().indexer(), &wallet)
                    .await
                    .map_err(anyhow::Error::from)
            })?;
            wallet.absorb(scan)?;
            ensure!(wallet.notes().len() == 1 && wallet.notes()[0].utxo.amount == 101);
        }
    }
    let stored = wallet.to_json();
    let mut restarted = AnonymousWallet::from_json(&stored)?;
    let restarted_keys =
        RotatingRingKeys::new(&rotated)?.with_retired(vec![recipient.viewing_key.clone()])?;
    let scan = env.client.block_on(async {
        AnonymousSync::new(&restarted_keys, &assets)
            .fetch_wallet(env.client.as_async().indexer(), &restarted)
            .await
            .map_err(anyhow::Error::from)
    })?;
    restarted.absorb(scan)?;
    let mut amounts: Vec<_> = restarted
        .notes()
        .iter()
        .map(|note| note.utxo.amount)
        .collect();
    amounts.sort_unstable();
    ensure!(amounts == [101, 202]);
    let empty = ViewingHistory::new(recipient.viewing_pubkey(), 0)
        .with_ring(ring_program, None)
        .with_rotated_key(rotated.viewing_pubkey(), 1)?;
    let recovered = env.client.block_on(async {
        AnonymousSync::new(&restarted_keys, &assets)
            .full_scan(env.client.as_async().indexer(), &empty, ring_program)
            .await
            .map_err(anyhow::Error::from)
    })?;
    let recovered = spr_transaction::verify_spendable(&restarted_keys, recovered.decrypted())?;
    let mut amounts: Vec<_> = recovered.utxos().map(|note| note.utxo.amount).collect();
    amounts.sort_unstable();
    ensure!(amounts == [101, 202]);
    Ok(())
}

#[test]
fn compact_output_suffix_settles_under_a_larger_key() -> Result<()> {
    let env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    enroll_actors(&env, ring)?;
    let sender = &env.sender.keypair;
    let note = RingNotes {
        ring,
        owner: sender,
        amount: 1_000_000,
        asset: DepositAsset::Sol,
        count: 1,
        env: &env,
    }
    .deposit()?;
    let note = indexed_note(
        note.into_iter().next().context("deposited input")?,
        sender,
        &env,
        env.tree,
    )?;
    let mut transaction =
        ConfidentialTransaction::new_compact_with_ring(vec![note], sender.pubkey(), ring_program)?
            .with_output_tree_id(env.tree_id(env.tree)?)?;
    transaction.transfer_sol(&env.recipient.keypair.shielded_address()?, 1)?;
    let operation = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_shape(spr_client::Shape::IN2_OUT4)?;
    let proven = env.run(operation.prove(env.client.ring_client()))?;
    let instruction = proven.instruction()?;
    let data = frame(&instruction, RingRail::Confidential)?;
    ensure!(data.outputs.len() < 4 && !data.outputs.is_empty());
    let mut salt = *data.salt;
    salt[0] ^= 1;
    let altered = reframed(
        &instruction,
        &RingTransactData {
            salt: &salt,
            ..data
        },
    )?;
    let before = fetch_account(env.client.rpc(), &env.tree)?;
    let rejected = send_expecting_rejection(env.client.rpc(), sender, altered)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejected);
    assert_account_unchanged(env.client.rpc(), &env.tree, &before)?;
    land(&env, instruction, sender, &[])?;
    Ok(())
}
