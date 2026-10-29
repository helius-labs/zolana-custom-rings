use super::*;

#[test]
fn an_outflow_limit_ring_bounds_each_transfer() -> Result<()> {
    const UNDER_THRESHOLD: u64 = 250_000_000;
    const OVER_THRESHOLD: u64 = 350_000_000;
    const OVER_CAP: u64 = 700_000_000;
    const DEPOSITS: [u64; 3] = [300_000_000, 400_000_000, 800_000_000];
    const _: () = assert!(UNDER_THRESHOLD <= LIMIT_COSIGN_ABOVE);
    const _: () = assert!(OVER_THRESHOLD > LIMIT_COSIGN_ABOVE && OVER_THRESHOLD <= LIMIT_CAP);
    const _: () = assert!(OVER_CAP > LIMIT_CAP);

    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    land(
        &env,
        custom_ring_sdk::AuthorityListWrite::new(ring, env.payer.pubkey()).with_mint_policy(
            Member::asset(&Address::new_from_array(
                custom_ring_interface::SOL_ASSET_ADDRESS,
            ))?,
            zolana_ring_policy::MintPolicy {
                cap: LIMIT_CAP,
                cosign_above: LIMIT_COSIGN_ABOVE,
                ..Default::default()
            },
        )?,
        &env.payer,
        &[],
    )?;
    let sender = &env.sender.keypair;
    let sender_address = sender.shielded_address()?;
    let recipient = env.recipient.keypair.shielded_address()?;

    let mut utxos = Vec::with_capacity(DEPOSITS.len());
    for amount in DEPOSITS {
        let deposit = RingDeposit {
            ring,
            payer: sender,
            recipient: DepositRecipient::Confidential(sender_address),
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.ring_client()))?;
        utxos.push(utxo);
    }
    let tree_id = env.tree_id(env.tree)?;
    let prepare = |input: Utxo, amount: u64| -> Result<ConfidentialTransaction> {
        let input = indexed_note(input, sender, &env, env.tree)?;
        let mut transfer =
            ConfidentialTransaction::new_with_ring(vec![input], sender.pubkey(), ring_program)?
                .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(&recipient, amount)?;
        Ok(transfer)
    };
    let cosigner = Keypair::new();
    let prove = |transaction: ConfidentialTransaction| {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_co_signer(cosigner.pubkey());
        env.run(transfer.prove(env.client.ring_client()))
    };

    // A send below the threshold lands with no approval.
    let proven = prove(prepare(utxos[0].clone(), UNDER_THRESHOLD)?)?;
    let instruction = proven.instruction()?;
    assert!(
        !frame(&instruction, RingRail::Confidential)?.approval_required,
        "an under-threshold send asks nobody"
    );
    let signature = land(&env, instruction, sender, &[])?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // Above the threshold the chain refuses the send until the co-signer signs.
    send(
        rpc,
        &env.payer,
        &[custom_ring_sdk::SetCoSigner {
            ring,
            payer: env.payer.pubkey(),
            authority: env.payer.pubkey(),
            signer: cosigner.pubkey(),
            scope: CoSignScope::WITHDRAWALS,
        }
        .instruction()?],
    )?;
    let proven = prove(prepare(utxos[1].clone(), OVER_THRESHOLD)?)?;
    let instruction = proven.instruction()?;
    assert!(
        frame(&instruction, RingRail::Confidential)?.approval_required,
        "an over-threshold send asks the co-signer"
    );
    assert_eq!(proven.co_signer, Some(cosigner.pubkey()));
    let rejection =
        send_expecting_rejection(rpc, sender, without_signer(instruction, cosigner.pubkey()))?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let signed = prove(prepare(utxos[1].clone(), OVER_THRESHOLD)?)?;
    let signature = land(&env, signed.instruction()?, sender, &[&cosigner])?;
    wait_for_indexed_transaction(indexer, auditor_tag, signature);

    // A single send above the cap is refused before any proof.
    match prove(prepare(utxos[2].clone(), OVER_CAP)?) {
        Err(RingError::OutflowCapExceeded { cap, outflow, .. }) => {
            assert_eq!(cap, LIMIT_CAP);
            assert_eq!(outflow, OVER_CAP);
        }
        Err(other) => return Err(anyhow!("expected the cap refusal, got {other}")),
        Ok(_) => return Err(anyhow!("the capped send was proven")),
    }
    Ok(())
}

#[test]
fn the_key_escrow_lifecycle_ends_in_a_delegate_move() -> Result<()> {
    const SEND: u64 = DEFAULT_DEPOSIT / 4;

    let env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let member = &env.sender.keypair;
    let member_address = member.shielded_address()?;
    let deposit = |recipient: ShieldedAddress| RingDeposit {
        ring,
        payer: member,
        recipient: DepositRecipient::Confidential(recipient),
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { signature, utxo } =
        env.run(deposit(member_address).send(env.client.ring_client()))?;
    let input = indexed_note(utxo, member, &env, env.tree)?;
    // 1. Recover the direct deposit before any transfer can disclose its
    // opening.
    assert_transaction_compute_units(
        rpc,
        &signature,
        "audited ring deposit",
        u64::from(compute_unit_limit(InstructionTag::AuditedDeposit)),
    )?;
    let recovery = RingRecovery::new(ring_program, &auditor).for_member(SourceMember {
        address: &member_address,
        nullifier_key: &member.nullifier_key,
    });
    let client = env.client.as_async();
    let deposited =
        env.client
            .block_on(recovery.run(client.indexer(), client.rpc(), &env.ring_assets()?))?;
    assert!(deposited.unopened.is_empty());
    assert!(deposited.unsupported_deposits.is_empty());
    assert_eq!(deposited.utxos.len(), 1);
    assert_eq!(deposited.utxos[0].utxo, input.utxo);
    assert_eq!(deposited.utxos[0].utxo.amount, DEFAULT_DEPOSIT);

    let tree_id = env.tree_id(env.tree)?;
    let mut transfer =
        ConfidentialTransaction::new_with_ring(vec![input], member.pubkey(), ring_program)?
            .with_output_tree_id(tree_id)?;
    transfer.transfer_sol(&member_address, SEND)?;
    OwnerTransfer {
        ring,
        sender: member,
        prepared: transfer,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;

    // 2. The member escrows its nullifier key, the auditor opens it from the
    //    applied record.
    register_key(&env, ring, member)?;
    Queued::now(&env.client, ring)?.apply(&env.client, &env.payer)?;
    let member_tag = owner_member(member)?;
    let read = wait_for("the registered key", || {
        Ok(match env.member_record(ring, member_tag) {
            Ok(read) if read.sealed.is_some() => Probe::Ready(read),
            Ok(_) => Probe::Retry(anyhow!("no sealed key yet")),
            Err(error) => Probe::Retry(error),
        })
    })?;
    let escrowed = read
        .escrowed(&member_address.nullifier_pubkey)?
        .context("the record escrows the member's nullifier key")?;
    let nullifier_key = escrowed.sealed.open(&auditor)?;
    assert_eq!(nullifier_key.pubkey()?, member_address.nullifier_pubkey);
    assert_eq!(
        env.run(ring.require_registry(env.client.as_async()))?
            .next_index(),
        2,
        "one registered member plus sentinel"
    );

    let delegate = Keypair::new();
    DelegateAppointment {
        ring,
        delegate: &delegate,
    }
    .send(&env)?;
    env.enable_authority_rail(ring)?;
    let recovery = RingRecovery::new(ring_program, &auditor).for_member(SourceMember {
        address: &member_address,
        nullifier_key: &nullifier_key,
    });
    let client = env.client.as_async();
    let recovered =
        env.client
            .block_on(recovery.run(client.indexer(), client.rpc(), &env.ring_assets()?))?;
    assert!(recovered.unopened.is_empty(), "every audited note opens");
    let mut amounts: Vec<u64> = recovered
        .utxos
        .iter()
        .map(|held| held.utxo.amount)
        .collect();
    amounts.sort_unstable();
    assert_eq!(amounts, [SEND, DEFAULT_DEPOSIT - SEND]);
    let (moved, change): (Vec<_>, Vec<_>) = recovered
        .utxos
        .into_iter()
        .partition(|held| held.utxo.amount == SEND);
    let moved = moved.into_iter().next().context("the sent note")?;
    let change = change.into_iter().next().context("the change note")?;
    let pay = |to: &ShieldedAddress| -> Result<ConfidentialTransaction> {
        let mut transfer = ConfidentialTransaction::new_with_ring(
            vec![change.clone()],
            member.pubkey(),
            ring_program,
        )?
        .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(to, 1)?;
        Ok(transfer)
    };

    // 3. Key escrow refuses an owner without an enrolled key before any prover
    //    round, for the zero key and for an enrolled owner naming another key.
    let unreachable = env.client_with(|| {
        AsyncProverClient::new("http://127.0.0.1:1".to_owned())
            .with_proof_data_source(ProofDataSource::Client)
    });
    let refused = |to: &ShieldedAddress| -> Result<Member> {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender: member,
            nullifier_key: Some(&member.nullifier_key),
            transaction: pay(to)?,
        });
        match unreachable.block_on(transfer.prove(unreachable.ring_client())) {
            Err(RingError::UnregisteredOutputKey { owner }) => Ok(owner),
            other => Err(anyhow!(
                "expected UnregisteredOutputKey, got {:?}",
                other.err()
            )),
        }
    };
    let unregistered = env.recipient.keypair.shielded_address()?;
    let unregistered_owner =
        Member::from_bytes(unregistered.signing_pubkey.owner_proof_input_hash()?)?;
    assert_eq!(refused(&unregistered)?, unregistered_owner);
    let zero_key = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..unregistered
    };
    assert_eq!(refused(&zero_key)?, unregistered_owner);
    let mismatched = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..member_address
    };
    assert_eq!(
        refused(&mismatched)?,
        Member::from_bytes(member_address.signing_pubkey.owner_proof_input_hash()?)?
    );
    match env.run(
        custom_ring_sdk::EscrowedRecipients {
            ring,
            recipients: &[member_address, unregistered],
        }
        .check(env.client.as_async()),
    ) {
        Err(RingError::UnregisteredOutputKey { owner }) => assert_eq!(owner, unregistered_owner),
        other => return Err(anyhow!("expected UnregisteredOutputKey, got {other:?}")),
    }

    // 4. A deposit binds the recipient's record under key escrow, one to an owner
    //    without an escrowed key is refused before proving.
    match env.run(deposit(unregistered).send(env.client.ring_client())) {
        Err(RingError::UnregisteredOutputKey { owner }) => {
            assert_eq!(owner, unregistered_owner)
        }
        Err(other) => return Err(anyhow!("expected UnregisteredOutputKey, got {other}")),
        Ok(_) => return Err(anyhow!("a deposit to an unregistered owner landed")),
    }
    let RingDepositReceipt { signature, .. } =
        env.run(deposit(member_address).send(env.client.ring_client()))?;
    assert_transaction_compute_units(
        rpc,
        &signature,
        "escrowed audited deposit",
        u64::from(compute_unit_limit(InstructionTag::AuditedDeposit)),
    )?;

    // 5. The delegate moves the enrolled member's note back to the member.
    let moved_nullifier = moved.nullifier;
    let proven = DelegateTransfer::new(DelegateTransferInput {
        ring,
        delegate: delegate.pubkey(),
        payer: env.payer.pubkey(),
        source: member_address,
        source_nullifier_key: &nullifier_key,
        inputs: vec![moved],
        outputs: vec![DelegateOutput {
            recipient: member_address,
            asset: SOL_MINT,
            amount: SEND,
        }],
    })
    .with_assets(&env.assets);
    let proven = env.run(proven.prove(env.client.ring_client()))?;
    let signature = land(&env, proven.instruction()?, &env.payer, &[&delegate])?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert!(
        indexed.nullifiers.contains(&moved_nullifier),
        "the delegate spent the note"
    );
    let mut member_wallet = Wallet::new(member_address, env.assets.clone())?;
    WalletSync {
        wallet: &mut member_wallet,
        keys: member,
        assets: &env.ring_assets()?,
        transactions: std::slice::from_ref(&indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&member_wallet),
        vec![(SOL_MINT, SEND, Some(ring_program))],
        "the delegate moved the registered member's note"
    );
    Ok(())
}
