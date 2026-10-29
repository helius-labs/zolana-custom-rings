use super::*;

/// The full custom-ring lifecycle: config creation, SPP registration, two ring SOL
/// deposits, one custom-ring transfer, and then the assertion that matters --
/// the auditor client's decrypted amounts, assets and blindings equal what the
/// sender actually sent.
#[test]
fn auditor_sees_every_ring_transfer() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);

    // 1. The auditor is off chain. Only its public key ever reaches the program;
    //    the secret never leaves this test and is what the final decryption uses.
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_pubkey = *auditor_pk.as_bytes();

    // 2. A policy ring initializes only with its policy, SPP registers it in the same instruction.
    let authority = env.payer.pubkey();
    let register = RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::policy(&EMPTY),
    };
    register.create_records(rpc)?;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[custom_ring_sdk::Initialize {
            ring,
            payer: authority,
            authority,
            auditor_pubkey: auditor_pk,
            kind: custom_ring_sdk::RingKind::Policy,
            policy: None,
        }
        .instruction()?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::PolicyNotSet as u32)
        .at(0)
        .assert_client(&rejection);
    assert!(
        env.run(ring.registration(env.client.as_async()))?.is_none(),
        "no SPP ring config without the policy"
    );
    // The ring forwards the protocol config unchecked.
    let mut substituted = register.initialize(&env.client)?;
    substituted.accounts[6].pubkey = Address::new_unique();
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[substituted],
    }
    .send(rpc)?;
    Rejection::pool(ShieldedPoolError::InvalidProtocolConfig)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &env.payer, &[register.initialize(&env.client)?])?;
    register.complete(&env.client)?;

    let (config_address, config_bump) =
        Address::find_program_address(&[CONFIG_PDA_SEED], &ring_program);
    assert_eq!(config_address, ring.config_pda(), "sdk config PDA helper");
    let config: RingProgramConfig = fetch_state(rpc, &config_address)?;
    assert_eq!(
        config,
        RingProgramConfig {
            discriminator: RING_PROGRAM_CONFIG,
            authority,
            auditor_pubkey,
            bump: config_bump,
            has_policy: 1,
            mode: RingMode::Confidential as u8,
            ..config
        },
        "custom-ring config account"
    );
    assert_eq!(config.co_signers.covered(), None, "no co-signer");
    assert_eq!(config.delegate(), None, "no delegate");

    // 3. Register the ring with SPP. The `RingConfig` SPP allocates IS the ring's
    //    `ring_auth` PDA, and the content is built on chain from the config
    //    account, so the registered authority is `ring_auth` itself and the
    //    authority-transact rail stays disabled.
    let (ring_auth, ring_auth_bump) = pda::ring_auth(&ring_program);
    assert_eq!(ring_auth, ring.ring_auth_pda(), "sdk ring_auth PDA helper");
    let ring_config: RingConfig = fetch_state(rpc, &ring_auth)?;
    assert_eq!(
        ring_config,
        RingConfig {
            discriminator: RING_CONFIG,
            authority: ring_auth,
            program_id: ring_program,
            ring_authority_transact_is_enabled: 0,
            paused: 0,
            // The fixture bootstraps with permissionless activation.
            activated: 1,
            bump: ring_auth_bump,
        },
        "SPP ring config"
    );

    // 3b. The human authority reaches the SPP flags only through the program,
    //     and a paused ring takes no deposit until it is reopened.
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[UpdateRingConfig {
            authority,
            ring_config: ring_auth,
            paused: true,
        }
        .instruction()],
    }
    .send(rpc)?;
    Rejection::pool(ShieldedPoolError::UnauthorizedCaller)
        .at(0)
        .assert_client(&rejection);
    let sender_address = env.sender.keypair.shielded_address()?;
    let deposit = |amount| RingDeposit {
        ring,
        payer: &env.sender.keypair,
        recipient: DepositRecipient::Confidential(sender_address),
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount,
        cosigner: None,
    };
    let proven_while_open = {
        let prepared = env.run(deposit(RING_DEPOSIT_A).prepare(env.client.as_async()))?;
        env.run(prepared.prove(env.client.ring_client()))?
    };
    send(rpc, &env.payer, &[ring.pause(authority)?])?;
    assert!(
        registration(&env, ring)?.paused,
        "paused by the ring authority"
    );
    match env.run(deposit(RING_DEPOSIT_A).send(env.client.ring_client())) {
        Err(RingError::RingPaused) => {}
        Err(other) => return Err(anyhow!("expected RingPaused, got {other}")),
        Ok(_) => return Err(anyhow!("the paused ring took a deposit")),
    }
    let rejection = send_expecting_rejection(rpc, &env.sender.keypair, proven_while_open)?;
    Rejection::pool(ShieldedPoolError::RingPaused)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &env.payer, &[ring.resume(authority)?])?;

    // 4. Two ring SOL deposits give the sender the ring-owned UTXOs the transfer
    //    spends. Their blindings come back from the deposit builder, so the spend
    //    is rebuilt without needing a wallet sync here.
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let RingDepositReceipt { utxo, .. } =
            env.run(deposit(amount).send(env.client.ring_client()))?;
        spendable.push(utxo);
    }

    // 5. Every output opens under the transaction viewing key the auditor recovers.
    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, &env.sender.keypair, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared =
        ConfidentialTransaction::new_with_ring(inputs, env.sender.keypair.pubkey(), ring_program)?;
    prepared.transfer_sol(
        &env.recipient.keypair.shielded_address()?,
        RING_TRANSFER_AMOUNT,
    )?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender: &env.sender.keypair,
        nullifier_key: Some(&env.sender.keypair.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.ring_client()))?;
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    let recipient_utxo = Note {
        owner: &env.recipient.keypair,
        asset: SOL_MINT,
        amount: RING_TRANSFER_AMOUNT,
        blinding: output_blinding(&proven.outputs, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let change_note = Note {
        owner: &env.sender.keypair,
        asset: SOL_MINT,
        amount: RING_CHANGE,
        blinding: output_blinding(&proven.outputs, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };

    // 6. Before the real spend, a flipped byte of the sealed transaction key fails the audit
    //    proof and leaves the tree unchanged.
    let instruction = proven.instruction()?;
    let tampered = {
        let original = frame(&instruction, RingRail::Confidential)?;
        let mut sealed = *original.sealed;
        sealed[0] ^= 1;
        reframed(
            &instruction,
            &RingTransactData {
                sealed: &sealed,
                ..original
            },
        )?
    };
    let tree_before = fetch_account(rpc, &env.tree)?;
    let rejection = send_expecting_rejection(rpc, &env.sender.keypair, tampered)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&rejection);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    let (blockhash, _) = rpc.get_latest_blockhash()?;
    let message = compile_message(
        &env.sender.keypair.pubkey(),
        &[instruction],
        blockhash,
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer)),
    )?;
    let transaction = sign_transaction(message, &[&env.sender.keypair])?;
    let transaction_size =
        bincode::serde::encode_to_vec(&transaction, bincode::config::legacy())?.len();
    assert!(
        transaction_size <= MAX_TRANSACTION_SIZE,
        "transaction v1 size {transaction_size} exceeds {MAX_TRANSACTION_SIZE}"
    );
    let signature = rpc
        .client()
        .send_and_confirm_transaction(&transaction)
        .map_err(|error| anyhow!("send v1 failed {error}"))?;
    assert_transaction_compute_units(
        // 7. The real custom-ring transfer.
        rpc,
        &signature,
        "custom-ring transact 2x2",
        CUSTOM_RING_TRANSACT_CU_LIMIT,
    )?;

    // 8. What the auditor sees. Photon matches the auditor view tag against
    //    MESSAGE tags, which is what makes the transaction discoverable to
    //    someone who owns no output in it.
    let auditor_tag = auditor_view_tag(&auditor_pk);
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(
        indexed.messages.last().map(|message| message.view_tag),
        Some(auditor_tag),
        "the auditor message is the last published message"
    );
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spent");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the key the sender derived"
    );

    let client = env.client.as_async();
    let audited = env
        .client
        .block_on(RingScan::new(ring_program, auditor.pubkey()).audit(
            &auditor,
            client.indexer(),
            client.rpc(),
            &env.ring_assets()?,
        ))?
        .transactions;
    assert_eq!(
        audited.len(),
        1,
        "exactly one auditor-tagged transaction landed (the tampered one never did)"
    );
    let audited = audited
        .first()
        .ok_or_else(|| anyhow!("audited transaction"))?;
    assert_eq!(audited.tx_signature, signature, "audited signature");
    assert_eq!(
        audited.tx_viewing_pk, tx_viewing_pk,
        "auditor recovered the transaction's viewing key"
    );
    assert_eq!(
        opened(audited),
        vec![
            recipient_utxo.opened(RECIPIENT_SLOT)?,
            change_note.opened(CHANGE_SLOT)?
        ],
        "auditor-decrypted outputs equal what the sender sent, owners and blindings included"
    );
    assert!(audited.payload_errors.is_empty());

    // 9. Normal operation is undisturbed: the recipient still discovers its
    //    output through `Wallet::sync` on its own view tag, with no auditor key.
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT, Some(ring_program))],
        "recipient wallet discovers the custom ring output"
    );
    let received = unspent_utxo(&env.recipient.wallet, RING_TRANSFER_AMOUNT)?;

    // 10. The second hop is proven through both clients, the policy statement
    //     holds the same parity as the audit statement.
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: second_hop(&env, received.clone())?,
        asynchronous: second_hop(&env, received)?,
        auditor_tag,
    }
    .send(&env)?;
    let audited_hop = AuditLookup {
        ring: ring_program,
        scan: RingScan::new(ring_program, auditor.pubkey()),
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?;
    assert_eq!(
        ring_amounts(&audited_hop)?,
        vec![SECOND_HOP_AMOUNT, RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT],
        "second hop outputs"
    );

    // 11. The config authority hands over, only the new key pauses the ring.
    let successor = env.funded_keypair()?;
    rpc.create_and_send_transaction(
        &[custom_ring_sdk::UpdateAuthority {
            ring,
            authority,
            new_authority: successor.pubkey(),
        }
        .instruction()],
        authority,
        &[&env.payer, &successor],
        ComputeBudgetConfig::for_instruction_count(1),
    )?;
    let rejection = ExpectRejection {
        payer: &env.payer,
        instructions: &[ring.pause(authority)?],
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::UnauthorizedAuthority as u32)
        .at(0)
        .assert_client(&rejection);
    send(rpc, &successor, &[ring.pause(successor.pubkey())?])?;
    assert!(registration(&env, ring)?.paused, "paused by the successor");
    send(rpc, &successor, &[ring.resume(successor.pubkey())?])?;
    assert!(
        !registration(&env, ring)?.paused,
        "reopened by the successor"
    );

    Ok(())
}

#[test]
fn an_audit_only_ring_audits_every_transfer() -> Result<()> {
    let mut env = setup()?;
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
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    let config: RingProgramConfig = fetch_state(rpc, &ring.config_pda())?;
    assert_eq!(config.has_policy, 0, "audit-only config flag");

    let sender = &env.sender.keypair;
    let sender_address = sender.shielded_address()?;
    let deposit_source = env.funded_keypair()?;
    env.fund(deposit_source.pubkey(), RING_DEPOSIT_A + RING_DEPOSIT_B)?;
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let deposit = RingDeposit {
            ring,
            payer: &deposit_source,
            recipient: DepositRecipient::Confidential(sender_address),
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let RingDepositReceipt { utxo, .. } =
            env.run(deposit.send_with_fee_payer(env.client.ring_client(), sender))?;
        spendable.push(utxo);
    }

    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, sender, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let mut prepared =
        ConfidentialTransaction::new_with_ring(inputs, sender.pubkey(), ring_program)?;
    prepared.transfer_sol(
        &env.recipient.keypair.shielded_address()?,
        RING_TRANSFER_AMOUNT,
    )?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: prepared,
    });
    let proven = env.run(transfer.prove(env.client.ring_client()))?;
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    let signature = land(&env, proven.instruction()?, sender, &[])?;

    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spent");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the on-chain tx_viewing_pk is the sender's"
    );
    let audited = AuditLookup {
        ring: ring_program,
        scan: RingScan::new(ring_program, auditor_pk),
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    assert_eq!(
        audited.tx_viewing_pk, tx_viewing_pk,
        "auditor recovered the transaction viewing key"
    );
    assert_eq!(
        ring_amounts(&audited)?,
        [RING_TRANSFER_AMOUNT, RING_CHANGE],
        "auditor decrypts both output amounts"
    );

    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&indexed),
    }
    .sync()?;
    let received = unspent_utxo(&env.recipient.wallet, RING_TRANSFER_AMOUNT)?;
    let hop = AsyncHopParity {
        ring,
        sender: &env.recipient.keypair,
        blocking: second_hop(&env, received.clone())?,
        asynchronous: second_hop(&env, received)?,
        auditor_tag,
    }
    .send(&env)?;
    let audited_hop = AuditLookup {
        ring: ring_program,
        scan: RingScan::new(ring_program, auditor_pk),
        auditor: &auditor,
        signature: hop.signature,
    }
    .run(&env)?;
    assert_eq!(
        ring_amounts(&audited_hop)?,
        vec![SECOND_HOP_AMOUNT, RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT],
        "second hop outputs"
    );
    Ok(())
}

/// Default-ring notes are legal ring transact inputs and outputs
/// (`AssertRingMemberOrFree`).
#[test]
fn ring_value_leaves_and_enters_through_audited_transfers() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let recipient_address = recipient.shielded_address()?;
    let scan = || RingScan::new(ring_program, auditor.pubkey());

    // 1. Entry, a default-ring deposit is spent into ring-bound notes.
    let deposited = DefaultRingDeposit {
        depositor: sender,
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEFAULT_DEPOSIT,
    }
    .send(rpc, indexer, &env.assets)?;
    let entry_input = deposited.input_utxo(&env)?;
    wait_for_merkle_proof(indexer, env.tree, entry_input.utxo_hash);
    let mut prepared =
        ConfidentialTransaction::new_with_ring(vec![entry_input], sender.pubkey(), ring_program)?;
    prepared.transfer_sol(&recipient_address, ENTRY_AMOUNT)?;
    let entry = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_ring_note = Note {
        owner: recipient,
        asset: SOL_MINT,
        amount: ENTRY_AMOUNT,
        blinding: output_blinding(&entry.outputs, RECIPIENT_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    let sender_change = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: ENTRY_CHANGE,
        blinding: output_blinding(&entry.outputs, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan(),
                auditor: &auditor,
                signature: entry.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_ring_note.opened(RECIPIENT_SLOT)?,
            sender_change.opened(CHANGE_SLOT)?
        ],
        "entry outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&entry.indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(SOL_MINT, ENTRY_AMOUNT, Some(ring_program))],
        "recipient wallet after the entry"
    );

    // 2. Exit, the ring-bound change is spent into a default-ring note for the
    //    recipient, the new change stays in the ring.
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![sender_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    prepared.transfer_with_ring(
        &recipient_address,
        env.assets.mint(&SOL_MINT)?,
        EXIT_AMOUNT,
        None,
    )?;
    let exit = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_default_note = Note {
        owner: recipient,
        asset: SOL_MINT,
        amount: EXIT_AMOUNT,
        blinding: output_blinding(&exit.outputs, RECIPIENT_SLOT)?,
        ring_program_id: None,
    };
    let exit_change = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: EXIT_CHANGE,
        blinding: output_blinding(&exit.outputs, CHANGE_SLOT)?,
        ring_program_id: Some(ring_program),
    };
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan(),
                auditor: &auditor,
                signature: exit.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_default_note.opened(RECIPIENT_SLOT)?,
            exit_change.opened(CHANGE_SLOT)?
        ],
        "exit outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&exit.indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (SOL_MINT, EXIT_AMOUNT, None),
            (SOL_MINT, ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the exit"
    );

    // 3. Refusal, a note of another ring, as the recipient output or as the
    //    input, is refused before the unreachable prover is asked.
    let unreachable = env.client_with(|| AsyncProverClient::new("http://127.0.0.1:1".to_string()));
    let prove = |prepared: ConfidentialTransaction| {
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring,
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: prepared,
        });
        unreachable.block_on(transfer.prove(unreachable.ring_client()))
    };
    let mut foreign_output = ConfidentialTransaction::new_with_ring(
        vec![exit_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    foreign_output.transfer_with_ring(
        &recipient_address,
        Mint::SOL,
        REFUSED_AMOUNT,
        Some(FOREIGN_RING),
    )?;
    expect_foreign_ring(prove(foreign_output), FOREIGN_RING)?;

    let foreign_note = Note {
        owner: sender,
        asset: SOL_MINT,
        amount: EXIT_CHANGE,
        blinding: random_blinding(),
        ring_program_id: Some(FOREIGN_RING),
    };
    let mut foreign_input = ConfidentialTransaction::new_with_ring(
        vec![foreign_note.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    foreign_input.transfer_sol(&recipient_address, REFUSED_AMOUNT)?;
    expect_foreign_ring(prove(foreign_input), FOREIGN_RING)?;

    Ok(())
}

/// The same crossing carries an SPL mint, and a ring transact settles a public
/// USDC withdrawal.
#[test]
fn usdc_crosses_the_ring_boundary_and_withdraws_through_a_ring_transact() -> Result<()> {
    let mut env = setup()?;
    let rpc = env.client.rpc();
    let indexer = env.client.indexer();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_tag = auditor_view_tag(&auditor.pubkey());
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::policy(&EMPTY),
    }
    .send(&env.client)?;
    let usdc = env.usdc_mint;
    let usdc_deposit = |user_token| {
        DepositAsset::Spl(DepositSplAccounts {
            mint: usdc,
            user_token,
            token_program: pda::spl_token_program_id(),
        })
    };
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let sender_address = sender.shielded_address()?;
    let recipient_address = recipient.shielded_address()?;
    let scan = || RingScan::new(ring_program, auditor.pubkey());
    let ring_utxo = |owner, amount, blinding| Note {
        owner,
        asset: usdc,
        amount,
        blinding,
        ring_program_id: Some(ring_program),
    };

    let sender_usdc = create_token_account(rpc, &env.payer, &usdc, &sender.pubkey())?;
    mint_to(rpc, &env.payer, &usdc, &sender_usdc, USDC_FUNDING)?;

    // 1. Public -> default ring, the sender signs as the token authority.
    let deposited = DefaultRingDeposit {
        depositor: sender,
        tree: env.tree,
        asset: usdc_deposit(sender_usdc),
        amount: USDC_DEFAULT_DEPOSIT,
    }
    .send(rpc, indexer, &env.assets)?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &sender_usdc)?),
        USDC_FUNDING - USDC_DEFAULT_DEPOSIT,
        "funding account after the default deposit"
    );
    let entry_input = deposited.input_utxo(&env)?;
    wait_for_merkle_proof(indexer, env.tree, entry_input.utxo_hash);

    // 2. Entry, the default USDC note is spent into ring-bound notes.
    let mut prepared =
        ConfidentialTransaction::new_with_ring(vec![entry_input], sender.pubkey(), ring_program)?;
    prepared.transfer(&recipient_address, usdc, USDC_ENTRY_AMOUNT)?;
    let entry = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_ring_note = ring_utxo(
        recipient,
        USDC_ENTRY_AMOUNT,
        output_blinding(&entry.outputs, RECIPIENT_SLOT)?,
    );
    let entry_change = ring_utxo(
        sender,
        USDC_ENTRY_CHANGE,
        output_blinding(&entry.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan(),
                auditor: &auditor,
                signature: entry.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_ring_note.opened(RECIPIENT_SLOT)?,
            entry_change.opened(CHANGE_SLOT)?
        ],
        "entry outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&entry.indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![(usdc, USDC_ENTRY_AMOUNT, Some(ring_program))],
        "recipient wallet after the entry"
    );

    // 3. In-ring hop.
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![entry_change.input_utxo(&env)?],
        sender.pubkey(),
        ring_program,
    )?;
    prepared.transfer(&recipient_address, usdc, USDC_HOP_AMOUNT)?;
    let hop = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_hop_note = ring_utxo(
        recipient,
        USDC_HOP_AMOUNT,
        output_blinding(&hop.outputs, RECIPIENT_SLOT)?,
    );
    let hop_change = ring_utxo(
        sender,
        USDC_HOP_CHANGE,
        output_blinding(&hop.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan(),
                auditor: &auditor,
                signature: hop.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_hop_note.opened(RECIPIENT_SLOT)?,
            hop_change.opened(CHANGE_SLOT)?
        ],
        "hop outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&hop.indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the hop"
    );

    // 4. Direct USDC ring deposit.
    let deposit = RingDeposit {
        ring,
        payer: sender,
        recipient: DepositRecipient::Confidential(sender_address),
        tree: env.tree,
        asset: usdc_deposit(sender_usdc),
        amount: USDC_RING_DEPOSIT,
        cosigner: None,
    };
    let RingDepositReceipt { utxo: receipt, .. } =
        env.run(deposit.send(env.client.ring_client()))?;
    assert_eq!(
        token_amount(&fetch_account(rpc, &sender_usdc)?),
        USDC_FUNDING - USDC_DEFAULT_DEPOSIT - USDC_RING_DEPOSIT,
        "funding account after the ring deposit"
    );
    let receipt_input = indexed_note(receipt, sender, &env, env.tree)?;
    wait_for_merkle_proof(indexer, env.tree, receipt_input.utxo_hash);

    // 5. Exit, the hop change and the ring-deposit receipt are spent together,
    //    the receipt spend proves the sdk receipt utxo matches the leaf.
    let mut prepared = ConfidentialTransaction::new_with_ring(
        vec![hop_change.input_utxo(&env)?, receipt_input],
        sender.pubkey(),
        ring_program,
    )?;
    prepared.transfer_with_ring(
        &recipient_address,
        env.assets.mint(&usdc)?,
        USDC_EXIT_AMOUNT,
        None,
    )?;
    let exit = OwnerTransfer {
        ring,
        sender,
        prepared,
        interface_transfer_accounts: Vec::new(),
        auditor_tag,
        cosigner: None,
    }
    .send(&env)?;
    let recipient_default_note = Note {
        ring_program_id: None,
        ..ring_utxo(
            recipient,
            USDC_EXIT_AMOUNT,
            output_blinding(&exit.outputs, RECIPIENT_SLOT)?,
        )
    };
    let exit_change = ring_utxo(
        sender,
        USDC_EXIT_CHANGE,
        output_blinding(&exit.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan(),
                auditor: &auditor,
                signature: exit.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_default_note.opened(RECIPIENT_SLOT)?,
            exit_change.opened(CHANGE_SLOT)?
        ],
        "exit outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&exit.indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_EXIT_AMOUNT, None),
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the exit"
    );

    // 6. A ring transact settles a public USDC withdrawal beside a ring send,
    //    the withdrawal past the threshold demands the co-signer.
    let recipient_usdc = create_token_account(rpc, &env.payer, &usdc, &recipient.pubkey())?;
    let cosigner = Keypair::new();
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
    StorageRecords::mint_policy(
        ring,
        Member::asset(&usdc)?,
        zolana_ring_policy::MintPolicy {
            withdrawal_threshold: USDC_WITHDRAW_AMOUNT - 1,
            ..Default::default()
        },
        &env,
    )
    .send()?;
    let withdraw = || -> Result<ConfidentialTransaction> {
        let mut transfer = ConfidentialTransaction::new_with_ring(
            vec![exit_change.input_utxo(&env)?],
            sender.pubkey(),
            ring_program,
        )?;
        transfer.withdraw(usdc, USDC_WITHDRAW_AMOUNT, recipient_usdc)?;
        transfer.transfer(&recipient_address, usdc, USDC_FINAL_SEND)?;
        Ok(transfer)
    };
    let settlement =
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint: usdc,
            spl_interface: pda::spl_interface(&usdc),
            user_token_account: recipient_usdc,
            token_program: pda::spl_token_program_id(),
        });
    let unsigned = CustomRingTransfer::new(CustomRingTransferInput {
        ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction: withdraw()?,
    })
    .with_interface_transfer_accounts(vec![settlement])
    .with_co_signer(cosigner.pubkey());
    let unsigned = env.run(unsigned.prove(env.client.ring_client()))?;
    assert_eq!(unsigned.co_signer, Some(cosigner.pubkey()));
    let rejection = send_expecting_rejection(
        rpc,
        sender,
        without_signer(unsigned.instruction()?, cosigner.pubkey()),
    )?;
    Rejection::custom(CustomRingError::MissingCoSigner as u32)
        .at(0)
        .assert_client(&rejection);
    let withdrawal = OwnerTransfer {
        ring,
        sender,
        prepared: withdraw()?,
        interface_transfer_accounts: vec![settlement],
        auditor_tag,
        cosigner: Some(&cosigner),
    }
    .send(&env)?;
    let recipient_final_note = ring_utxo(
        recipient,
        USDC_FINAL_SEND,
        output_blinding(&withdrawal.outputs, RECIPIENT_SLOT)?,
    );
    let final_change = ring_utxo(
        sender,
        USDC_FINAL_CHANGE,
        output_blinding(&withdrawal.outputs, CHANGE_SLOT)?,
    );
    assert_eq!(
        token_amount(&fetch_account(rpc, &recipient_usdc)?),
        USDC_WITHDRAW_AMOUNT,
        "public recipient after the ring withdrawal"
    );
    assert_eq!(
        token_amount(&fetch_account(rpc, &pda::spl_interface(&usdc))?),
        USDC_DEFAULT_DEPOSIT + USDC_RING_DEPOSIT - USDC_WITHDRAW_AMOUNT,
        "vault keeps the shielded remainder"
    );
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan(),
                auditor: &auditor,
                signature: withdrawal.signature,
            }
            .run(&env)?
        ),
        vec![
            recipient_final_note.opened(RECIPIENT_SLOT)?,
            final_change.opened(CHANGE_SLOT)?
        ],
        "withdrawal outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&withdrawal.indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_FINAL_SEND, Some(ring_program)),
            (usdc, USDC_EXIT_AMOUNT, None),
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the withdrawal"
    );

    // 7. The delegate re-owns the recipient's final note to the sender over the
    //    authority rail, refused until governance enables the rail.
    let delegate = Keypair::new();
    EscrowedDelegate {
        ring,
        delegate: &delegate,
        members: &[sender],
    }
    .set(&env)?;
    let moved = || -> Result<ProvenRingTransfer> {
        let transfer = DelegateTransfer::new(DelegateTransferInput {
            ring,
            delegate: delegate.pubkey(),
            payer: env.payer.pubkey(),
            source: recipient_address,
            source_nullifier_key: &recipient.nullifier_key,
            inputs: vec![recipient_final_note.input_utxo(&env)?],
            outputs: vec![DelegateOutput {
                recipient: sender_address,
                asset: usdc,
                amount: USDC_FINAL_SEND,
            }],
        })
        .with_assets(&env.assets);
        Ok(env.run(transfer.prove(env.client.ring_client()))?)
    };
    let rejection = RejectedTransact {
        payer: &env.payer,
        signers: &[&delegate],
        instruction: moved()?.instruction()?,
    }
    .send(rpc)?;
    Rejection::pool(ShieldedPoolError::RingAuthorityTransactDisabled)
        .at(0)
        .assert_client(&rejection);
    env.enable_authority_rail(ring)?;
    let proven = moved()?;
    let moved_note = ring_utxo(
        sender,
        USDC_FINAL_SEND,
        output_blinding(&proven.outputs, 0)?,
    );
    let signature = land(&env, proven.instruction()?, &env.payer, &[&delegate])?;
    let indexed = wait_for_indexed_transaction(indexer, auditor_tag, signature);
    // Key escrow keeps the owner's nullifier key out of the disclosure, the record holds it.
    let escrowed_key = env
        .member_record(ring, owner_member(sender)?)?
        .nullifier_pk
        .context("the sender's record escrows no nullifier key")?;
    let escrowed = HashMap::from([(
        sender.signing_pubkey().confidential_view_tag()?,
        escrowed_key,
    )]);
    assert_eq!(
        opened(
            &AuditLookup {
                ring: ring_program,
                scan: scan().with_escrowed_keys(escrowed),
                auditor: &auditor,
                signature,
            }
            .run(&env)?
        ),
        vec![moved_note.opened(0)?],
        "delegate move outputs"
    );
    let assets = env.ring_assets()?;
    WalletSync {
        wallet: &mut env.recipient.wallet,
        keys: &env.recipient.keypair,
        assets: &assets,
        transactions: std::slice::from_ref(&indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&env.recipient.wallet),
        vec![
            (usdc, USDC_EXIT_AMOUNT, None),
            (usdc, USDC_HOP_AMOUNT, Some(ring_program)),
            (usdc, USDC_ENTRY_AMOUNT, Some(ring_program)),
        ],
        "recipient wallet after the delegate move"
    );

    Ok(())
}
