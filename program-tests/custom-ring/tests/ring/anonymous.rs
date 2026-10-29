use super::*;

/// The operator cli runs an anonymous ring, a separate fee payer funds the hidden owner's
/// deposits and payment, and `audit` opens the payment with the auditor key.
#[test]
fn cli_pays_an_anonymous_ring_address_end_to_end() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let keys = PathBuf::from(isolated_temp_path("zolana-ring-anonymous"));
    std::fs::create_dir_all(&keys)?;
    let auditor_key = keys.join("auditor.key");
    let auditor = write_auditor_key(&auditor_key)?;
    let ring_rpc = RingRpcSpec {
        env: &env,
        ring: ring.program_id(),
        auditor: auditor.clone(),
    }
    .serve()?;
    let project = RingProject::create(&env, &auditor.pubkey())?;
    project.write_config(RingToml {
        env: &env,
        ring_rpc: &ring_rpc.url,
        policy: None,
        mode: ModeName::Anonymous,
    })?;
    let init = project.run(&["init"])?;
    assert!(init.contains("spp ring    registered"), "{init}");
    let config = env.run(ring.require_config(env.client.as_async()))?;
    assert_eq!(config.mode, RingMode::Anonymous);

    // 1. Without a fee payer the cli refuses, it never charges the hidden owner or the authority.
    let recipient = ShieldedKeypair::new_ed25519()?;
    let minted = ViewingHistory::new(recipient.viewing_pubkey(), 0).request_tag(&recipient)?;
    let request = RingPaymentRequest::new(ring_address(&recipient, ring.program_id())?, minted.tag)
        .to_string();
    let amount = PAIR_AMOUNT.to_string();
    let refused = project.output(&["transfer", &request, "--amount", &amount])?;
    assert!(
        !refused.status.success(),
        "an anonymous transfer needs a fee payer"
    );
    let text = merged(&refused);
    assert!(text.contains("--fee-payer-keypair"), "{text}");

    // 2. The fee payer funds two deposits into the hidden balance and the payment.
    let fee_payer = keys.join("fee-payer.json");
    solana_keypair::write_keypair_file(&Keypair::new(), &fee_payer)
        .map_err(|e| anyhow!("write the fee payer keypair {e}"))?;
    let fee_payer = fee_payer.to_str().context("the fee payer path is utf-8")?;
    let paid = project.run(&[
        "--fee-payer-keypair",
        fee_payer,
        "transfer",
        &request,
        "--amount",
        &amount,
    ])?;
    assert!(
        paid.contains(&format!("{amount} base units")),
        "the payment names its amount in\n{paid}"
    );
    let sender = project.demo_sender()?;
    assert_eq!(
        env.client.rpc().get_balance(sender.pubkey())?,
        0,
        "the hidden owner never holds a lamport, it pays nothing"
    );

    // 3. `audit` opens the payment, its hidden sender and the recipient's output.
    let signature = paid
        .lines()
        .find_map(|line| line.strip_prefix("transact")?.trim().parse().ok())
        .context("transfer CLI did not print its confirmed signature")?;
    custom_ring_cli::wait_for_indexed_transaction(&env.client, signature)?;
    let auditor_key = auditor_key
        .to_str()
        .context("the auditor key path is utf-8")?;
    let audited = project.run(&["audit", "--auditor-key", auditor_key])?;
    for line in [
        format!("hidden sender {}", sender.pubkey()),
        format!("ring to {}", recipient.pubkey()),
    ] {
        assert!(audited.contains(&line), "{line} in\n{audited}");
    }
    project.remove()?;
    std::fs::remove_dir_all(keys)?;
    Ok(())
}

/// No public signer names an owner, the auditor opens the sender and every note, and each
/// payment takes the spec view tag its pair has reached.
#[test]
fn an_anonymous_ring_hides_owners_and_preserves_auditor_access() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    let auditor_pk = auditor.pubkey();
    let auditor_tag = auditor_view_tag(&auditor_pk);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor_pk,
        tier: Tier::AnonymousAuditOnly,
    }
    .send(&env.client)?;
    let config = env.run(ring.require_config(env.client.as_async()))?;
    assert_eq!(config.mode, RingMode::Anonymous);
    let sender_keys = &env.sender.keypair;
    let recipient_keys = &env.recipient.keypair;

    // 1. The ring payer funds every spend and a separate source the deposits, each deposit
    //    takes the sender's next sender tag, the owner's key signs nothing in public.
    let payer = &env.payer;
    let deposit_source = env.funded_keypair()?;
    env.fund(deposit_source.pubkey(), RING_DEPOSIT_A + RING_DEPOSIT_B)?;
    let mut sender_history = ViewingHistory::new(sender_keys.viewing_pubkey(), 0);
    let mut spendable = Vec::with_capacity(2);
    for amount in [RING_DEPOSIT_A, RING_DEPOSIT_B] {
        let deposit = RingDeposit {
            ring,
            payer: &deposit_source,
            recipient: DepositRecipient::Anonymous {
                keys: sender_keys,
                history: &sender_history,
            },
            tree: env.tree,
            asset: DepositAsset::Sol,
            amount,
            cosigner: None,
        };
        let next = deposit
            .viewing_history()?
            .context("an anonymous deposit advances its history")?;
        let RingDepositReceipt { signature, utxo } =
            env.run(deposit.send_with_fee_payer(env.client.ring_client(), payer))?;
        custom_ring_cli::wait_for_indexed_transaction(&env.client, signature)?;
        sender_history = next;
        spendable.push(utxo);
    }
    assert_eq!(sender_history.current().tx_count(), 2);

    // 2. The first payment to the recipient's address takes its bootstrap tag.
    let inputs = spendable
        .into_iter()
        .map(|utxo| indexed_note(utxo, sender_keys, &env, env.tree))
        .collect::<Result<Vec<_>, _>>()?;
    let transfer = AnonymousPayment {
        ring,
        sender: sender_keys,
        history: &sender_history,
        payer,
        inputs,
        to: ring_address(recipient_keys, ring_program)?,
        first_contact: FirstContact::Bootstrap,
        amount: RING_TRANSFER_AMOUNT,
    }
    .transfer()?;
    let proven = env.run(transfer.prove(env.client.ring_client()))?;
    let advanced = proven
        .viewing_history
        .clone()
        .context("an anonymous transfer advances its sender's history")?;
    assert_eq!(advanced.current().tx_count(), 3);
    assert_eq!(
        advanced
            .current()
            .known_recipients()
            .get(&recipient_keys.viewing_pubkey())
            .map(|counter| counter.next()),
        Some(0),
        "a bootstrap payment pairs the recipient"
    );
    let tx_viewing_pk = proven.tx_viewing_key.pubkey();
    let instruction = proven.instruction()?;
    assert!(
        !signers(&instruction).contains(&sender_keys.pubkey()),
        "no transaction signer names the owner"
    );

    // 3. A corrupted inner BSB22 commitment reaches SPP with every proof fixed,
    //    SPP refuses the encoding or the proof of knowledge.
    let valid = frame(&instruction, RingRail::Anonymous)?
        .anonymous
        .context("an anonymous transfer carries its BSB22 commitment")?;
    let (commitment, pok) = (*valid.commitment, *valid.commitment_pok);
    let tree_before = fetch_account(rpc, &env.tree)?;
    for (commitment, commitment_pok, error) in [
        (
            [0xff; 32],
            pok,
            ShieldedPoolError::InvalidTransactProofEncoding,
        ),
        (
            commitment,
            [0xff; 32],
            ShieldedPoolError::InvalidTransactProofEncoding,
        ),
        (
            commitment,
            commitment,
            ShieldedPoolError::TransactProofVerificationFailed,
        ),
    ] {
        let tampered = reframed(
            &instruction,
            &RingTransactData {
                anonymous: Some(AnonymousProofData {
                    commitment: &commitment,
                    commitment_pok: &commitment_pok,
                    ..valid
                }),
                ..frame(&instruction, RingRail::Anonymous)?
            },
        )?;
        let rejection = send_expecting_rejection(rpc, payer, tampered)?;
        Rejection::pool(error).at(0).assert_client(&rejection);
        assert_account_unchanged(rpc, &env.tree, &tree_before)?;
    }
    let landed = PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?;
    sender_history = landed.history;
    let indexed = landed.indexed;
    assert_eq!(indexed.nullifiers.len(), 2, "both inputs spent");
    assert_eq!(
        indexed.tx_viewing_pk,
        Some(tx_viewing_pk),
        "the first nullifier fixes the transaction viewing key of every attempt"
    );
    assert!(
        indexed.output_slots[0].payload.is_empty(),
        "output 0 is the sender change and carries no body"
    );
    let (auditor_message, sender_bundle) = indexed.messages.split_last().unwrap();
    assert_eq!(auditor_message.view_tag, auditor_tag);
    assert!(
        matches!(sender_bundle, [bundle] if anonymous_sender_output_body(&bundle.data).is_some()),
        "the sender bundle is the only message before the auditor's"
    );
    assert!(
        indexed.output_slots.iter().any(|slot| {
            slot.view_tag == recipient_keys.viewing_pubkey().u()
                && anonymous_recipient_output_body(&slot.payload).is_some()
        }),
        "the payment publishes a recipient body under the bootstrap tag"
    );

    // 4. The auditor reads the hidden sender, its inputs and every output's asset and amount.
    let audited = AuditLookup {
        ring: ring_program,
        scan: RingScan::new(ring_program, auditor_pk).with_mode(RingMode::Anonymous),
        auditor: &auditor,
        signature: indexed.tx_signature,
    }
    .run(&env)?;
    let mut amounts = ring_amounts(&audited)?;
    amounts.sort_unstable();
    assert_eq!(amounts, [RING_TRANSFER_AMOUNT, RING_CHANGE]);
    assert!(
        audited
            .outputs
            .iter()
            .filter_map(|output| output.opening.utxo())
            .all(|utxo| utxo.mint == Some(SOL_MINT)),
        "the disclosure names every output's asset"
    );
    assert_eq!(
        audited.sender.map(|sender| sender.owner_key),
        Some(sender_keys.signing_pubkey().as_ed25519()?),
        "the auditor names the hidden sender"
    );
    let mut input_amounts: Vec<u64> = audited
        .inputs
        .iter()
        .filter_map(|input| input.opening.opened().map(|opening| opening.amount))
        .collect();
    input_amounts.sort_unstable();
    assert_eq!(input_amounts, [RING_DEPOSIT_B, RING_DEPOSIT_A]);

    // 5. The recipient finds the bootstrap payment and learns the sender's viewing key.
    let mut recipient_wallet = fresh_wallet(&env, recipient_keys, ring_program)?;
    recipient_wallet.sync(&env)?;
    assert_eq!(
        sorted_notes(recipient_wallet.unspent()),
        vec![(SOL_MINT, RING_TRANSFER_AMOUNT, Some(ring_program))]
    );
    assert_eq!(
        recipient_wallet.history.current().known_senders().len(),
        1,
        "the bootstrap payment pairs the sender"
    );

    // 6. The sender mints a payment request, the recipient pays it under the request tag.
    let minted = sender_history.request_tag(sender_keys)?;
    sender_history = minted.history;
    let request = RingPaymentRequest::new(ring_address(sender_keys, ring_program)?, minted.tag);
    let transfer = AnonymousPayment {
        ring,
        sender: recipient_keys,
        history: &recipient_wallet.history,
        payer,
        inputs: vec![held_note(&recipient_wallet, &env, RING_TRANSFER_AMOUNT)?],
        to: request.address.clone(),
        first_contact: FirstContact::Request(request.request_view_tag),
        amount: SECOND_HOP_AMOUNT,
    }
    .transfer()?;
    let landed = PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?;
    assert!(
        landed
            .indexed
            .output_slots
            .iter()
            .any(|slot| slot.view_tag == request.request_view_tag),
        "the payment publishes the request tag"
    );
    recipient_wallet.history = landed.history;
    recipient_wallet.sync(&env)?;
    assert_eq!(
        sorted_notes(recipient_wallet.unspent()),
        vec![(
            SOL_MINT,
            RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT,
            Some(ring_program)
        )],
        "the recipient finds the change of its spend by its sender tag"
    );

    // 7. The sender pays the paired recipient under their first shared tag.
    let mut sender_wallet = fresh_wallet(&env, sender_keys, ring_program)?;
    sender_wallet.history = sender_history;
    sender_wallet.sync(&env)?;
    assert_eq!(
        sorted_notes(sender_wallet.unspent()),
        vec![
            (SOL_MINT, SECOND_HOP_AMOUNT, Some(ring_program)),
            (SOL_MINT, RING_CHANGE, Some(ring_program)),
        ],
        "the sender finds its change and the request payment"
    );
    assert_eq!(sender_wallet.history.current().request_count(), 1);
    let shared_tag = sender_keys.get_send_shared_view_tag(&recipient_keys.viewing_pubkey(), 0)?;
    let transfer = AnonymousPayment {
        ring,
        sender: sender_keys,
        history: &sender_wallet.history,
        payer,
        inputs: vec![held_note(&sender_wallet, &env, RING_CHANGE)?],
        to: ring_address(recipient_keys, ring_program)?,
        first_contact: FirstContact::Bootstrap,
        amount: PAIR_AMOUNT,
    }
    .transfer()?;
    let landed = PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?;
    assert!(
        landed
            .indexed
            .output_slots
            .iter()
            .any(|slot| slot.view_tag == shared_tag),
        "a paired recipient takes the shared tag"
    );
    sender_wallet.history = landed.history;
    recipient_wallet.sync(&env)?;
    assert_eq!(
        sorted_notes(recipient_wallet.unspent()),
        vec![
            (SOL_MINT, PAIR_AMOUNT, Some(ring_program)),
            (
                SOL_MINT,
                RING_TRANSFER_AMOUNT - SECOND_HOP_AMOUNT,
                Some(ring_program)
            ),
        ],
        "the recipient finds the shared tag payment"
    );

    // 8. A fresh wallet of the sender rebuilds its counters and counterparties from index 0.
    let mut fresh_sender = fresh_wallet(&env, sender_keys, ring_program)?;
    fresh_sender.sync(&env)?;
    sender_wallet.sync(&env)?;
    assert_eq!(
        sorted_notes(fresh_sender.unspent()),
        vec![
            (SOL_MINT, SECOND_HOP_AMOUNT, Some(ring_program)),
            (SOL_MINT, RING_CHANGE - PAIR_AMOUNT, Some(ring_program)),
        ]
    );
    let (rebuilt, stored) = (
        fresh_sender.history.current(),
        sender_wallet.history.current(),
    );
    assert_eq!(rebuilt.tx_count(), stored.tx_count());
    assert_eq!(rebuilt.request_count(), stored.request_count());
    assert_eq!(rebuilt.known_recipients(), stored.known_recipients());
    assert_eq!(
        rebuilt.known_senders().len(),
        1,
        "the request payment pairs its sender"
    );

    // 9. The recipient merges both notes, a fresh wallet finds the merge from
    //    its own spends and sees both inputs spent.
    let merged_inputs: Vec<WalletUtxo> = recipient_wallet.unspent().cloned().collect();
    let tree_id = env.tree_id(env.tree)?;
    let prepared = CustomRingMerge::new(ring, merged_inputs.clone(), None)?
        .with_output_tree_id(tree_id)
        .encrypt(recipient_keys)?;
    let merged_hash = prepared.output().hash(tree_id)?;
    let merge = RingMergeOperation::new(
        prepared,
        MergeProofInput {
            nullifier_key: recipient_keys.nullifier_key.clone(),
            input_tree: env.tree,
            output_tree: env.tree,
            co_signer: None,
        },
    );
    land(&env, merge, payer, &[])?;
    let mut fresh_recipient = fresh_wallet(&env, recipient_keys, ring_program)?;
    fresh_recipient.sync(&env)?;
    for input in &merged_inputs {
        assert!(fresh_recipient.is_spent(input), "the merge spent its input");
    }
    assert_eq!(
        sorted_notes(fresh_recipient.unspent()),
        vec![(SOL_MINT, MERGED_AMOUNT, Some(ring_program))],
        "the sync opens the merge"
    );

    // 10. The merged note spends like any other.
    let merged = fresh_recipient
        .unspent()
        .find(|held| held.utxo_hash == merged_hash)
        .cloned()
        .context("the merged note")?;
    let transfer = AnonymousPayment {
        ring,
        sender: recipient_keys,
        history: &fresh_recipient.history,
        payer,
        inputs: vec![indexed_note(
            merged.utxo.clone(),
            recipient_keys,
            &env,
            env.tree,
        )?],
        to: ring_address(sender_keys, ring_program)?,
        first_contact: FirstContact::Bootstrap,
        amount: MERGED_SPEND,
    }
    .transfer()?;
    fresh_recipient.history = PaymentLanding {
        transfer,
        payer,
        auditor_tag,
    }
    .land(&env)?
    .history;
    fresh_recipient.sync(&env)?;
    assert!(fresh_recipient.is_spent(&merged));
    Ok(())
}

/// The anonymous ring's policy proof screens the hidden sender against its own record.
#[test]
fn an_anonymous_policy_ring_screens_its_hidden_sender() -> Result<()> {
    let env = setup()?;
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::anonymous_policy(&FROZEN_SENDERS),
    }
    .send(&env.client)?;
    let config = env.run(ring.require_config(env.client.as_async()))?;
    assert_eq!(config.mode, RingMode::Anonymous);
    assert!(config.has_policy, "the anonymous ring pins a table");
    assert_eq!(policy_registry(ring, &env)?.rule_table()?, FROZEN_SENDERS);

    // 1. A separate depositor funds the hidden note, the owner signs nothing.
    let sender = &env.sender.keypair;
    let depositor = env.funded_keypair()?;
    env.fund(depositor.pubkey(), RING_DEPOSIT_B)?;
    let deposited = RingNotes {
        ring,
        owner: sender,
        amount: RING_DEPOSIT_B,
        count: 1,
        env: &env,
    }
    .deposit_hidden_from(&depositor)?
    .into_iter()
    .next()
    .context("the hidden note")?;
    let input = indexed_note(deposited, sender, &env, env.tree)?;
    let history = ViewingHistory::new(sender.viewing_pubkey(), 0);
    let to = ring_address(&env.recipient.keypair, ring_program)?;
    let payment = || AnonymousPayment {
        ring,
        sender,
        history: &history,
        payer: &env.payer,
        inputs: vec![input.clone()],
        to: to.clone(),
        first_contact: FirstContact::Bootstrap,
        amount: PAIR_AMOUNT,
    };
    let sender_member = owner_member(sender)?;
    let frozen = |present| RegistryWrite {
        ring,
        list_id: ListId::Frozen,
        member: sender_member,
        present,
        env: &env,
    };

    // 2. A Frozen hidden sender is refused before any prover round.
    frozen(true).send()?;
    let unreachable = env.client_with(|| {
        AsyncProverClient::new("http://127.0.0.1:1".to_owned())
            .with_proof_data_source(ProofDataSource::Client)
    });
    match unreachable.block_on(payment().transfer()?.prove(unreachable.ring_client())) {
        Err(RingError::PolicyRuleUnsatisfied(_)) => {}
        other => {
            return Err(anyhow!(
                "expected PolicyRuleUnsatisfied, got {:?}",
                other.err()
            ))
        }
    }

    // 3. Clearing the bit admits the same payment, and the auditor opens its hidden sender.
    frozen(false).send()?;
    let landed = PaymentLanding {
        transfer: payment().transfer()?,
        payer: &env.payer,
        auditor_tag: auditor_view_tag(&auditor.pubkey()),
    }
    .land(&env)?;
    let audited = AuditLookup {
        ring: ring_program,
        scan: RingScan::new(ring_program, auditor.pubkey()).with_mode(config.mode),
        auditor: &auditor,
        signature: landed.indexed.tx_signature,
    }
    .run(&env)?;
    let opened = audited
        .sender
        .context("an anonymous transfer discloses its sender to the auditor")?;
    assert_eq!(
        opened.owner_key,
        sender.signing_pubkey().confidential_view_tag()?,
        "the auditor opens the screened owner"
    );
    Ok(())
}

fn fresh_wallet<'a>(
    env: &TestEnv,
    keys: &'a ShieldedKeypair,
    ring: Address,
) -> Result<RingWallet<'a>> {
    Ok(RingWallet::new(keys, env.ring_assets()?, ring))
}
