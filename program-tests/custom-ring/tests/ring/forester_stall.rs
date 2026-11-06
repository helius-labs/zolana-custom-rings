use spr_interface::shape::Shape;

use super::*;

/// Surfpool's account write, the queue boundary reads as a full nullifier batch no forester drains.
fn exhaust_dummy_input_headroom(env: &TestEnv) -> Result<()> {
    let mut data = tree_data(env)?;
    let mut tree = TreeAccount::from_bytes(&mut data, env.tree.to_bytes())
        .map_err(|error| anyhow!("tree layout {error:?}"))?;
    let state_capacity = tree.utxo_tree().capacity();
    let nullifier = tree.nullifier_tree();
    let queue_index = nullifier.capacity - state_capacity;
    nullifier.queue_next_index = queue_index;
    nullifier
        .get_current_batch_mut()
        .map_err(|error| anyhow!("current batch {error:?}"))?
        .start_index = queue_index;
    ensure!(
        tree.dummy_input_headroom()
            .map_err(|error| anyhow!("headroom {error:?}"))?
            == 0
    );
    env.set_account_data(env.tree, &data)
}

pub(super) fn tree_data(env: &TestEnv) -> Result<Vec<u8>> {
    Ok(env
        .client
        .rpc()
        .get_account(env.tree)?
        .ok_or_else(|| anyhow!("tree account {} not found", env.tree))?
        .data)
}

pub(super) fn nullifier_queue_index(env: &TestEnv) -> Result<u64> {
    let mut data = tree_data(env)?;
    let mut tree = TreeAccount::from_bytes(&mut data, env.tree.to_bytes())
        .map_err(|error| anyhow!("tree layout {error:?}"))?;
    Ok(tree.nullifier_tree().queue_next_index)
}

#[test]
fn a_stalled_forester_stops_a_dummy_input_transfer_and_no_deposit() -> Result<()> {
    let env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    enroll_actors(&env, ring)?;
    let sender = &env.sender.keypair;
    let notes = || RingNotes {
        ring,
        owner: sender,
        amount: 1_000_000,
        asset: DepositAsset::Sol,
        count: 1,
        env: &env,
    };
    let input = notes().deposit()?;
    let input = indexed_note(
        input.into_iter().next().context("deposited input")?,
        sender,
        &env,
        env.tree,
    )?;

    exhaust_dummy_input_headroom(&env)?;
    let queue_index = nullifier_queue_index(&env)?;

    // The deposit path touches no nullifier tree.
    notes().deposit()?;
    assert_eq!(nullifier_queue_index(&env)?, queue_index);

    // One real input in a two-input shape leaves the second slot a dummy, SPP then flips its public flag.
    let mut prepared =
        ConfidentialTransaction::new_with_ring(vec![input], sender.pubkey(), ring_program)?
            .with_output_tree_id(env.tree_id(env.tree)?)?;
    prepared.transfer_sol(&env.recipient.keypair.shielded_address()?, 1)?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    })
    .with_shape(Shape::IN2_OUT2)?;
    let proven = env.run(transfer.prove(env.client.ring_client()))?;
    let refused = land(&env, proven.instruction()?, sender, &[])
        .err()
        .context("a dummy input settled on a full nullifier batch")?;
    let code = format!(
        "{:#x}",
        ShieldedPoolError::TransactProofVerificationFailed as u32
    );
    ensure!(
        refused.to_string().contains(&code),
        "refused by {refused:#}"
    );
    Ok(())
}
