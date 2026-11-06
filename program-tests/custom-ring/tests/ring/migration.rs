use super::*;

#[test]
fn an_old_tree_note_migrates_into_the_active_tree() -> Result<()> {
    let mut env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());

    let old_tree = env.create_registered_tree()?;
    assert_ne!(old_tree, env.tree);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    enroll_actors(&env, ring)?;

    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let deposit = RingDeposit {
        ring,
        payer: sender,
        recipient: DepositRecipient::Confidential(sender.shielded_address()?),
        tree: old_tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
        list_salt: None,
    };
    let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.ring_client()))?;
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(utxo, sender, &env, old_tree)?],
        sender.pubkey(),
        ring_program,
    )?
    .with_output_tree_id(env.tree_id(env.tree)?)?;
    prepared.transfer_sol(&recipient.shielded_address()?, ENTRY_AMOUNT)?;
    let migrated = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    assert_eq!(
        migrated.indexed.nullifiers.len(),
        1,
        "the old-tree note is spent"
    );

    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&migrated.indexed),
    }
    .sync()?;
    let received = unspent_utxo(&env.recipient.wallet, ENTRY_AMOUNT)?;
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![indexed_note(received, recipient, &env, env.tree)?],
        recipient.pubkey(),
        ring_program,
    )?;
    prepared.transfer_sol(&sender.shielded_address()?, SECOND_HOP_AMOUNT)?;
    let hop = OwnerTransfer {
        ring,
        sender: recipient,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor.pubkey()),
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?;
    assert_eq!(
        ring_amounts(&audited)?,
        vec![SECOND_HOP_AMOUNT, ENTRY_AMOUNT - SECOND_HOP_AMOUNT],
        "the active-tree note spends in turn"
    );
    Ok(())
}
