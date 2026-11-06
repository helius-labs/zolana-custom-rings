use super::*;
use custom_ring_sdk::CoOwner;
use zolana_ring_policy::MintPolicy;

#[test]
fn public_co_owner_receives_payment_under_each_owners_net_debit_cap() -> Result<()> {
    let env = setup()?;
    let rpc = env.client.rpc();
    let ring_program = custom_ring_program_id()?;
    let ring = CustomRing::new(ring_program);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::anonymous_policy(&EMPTY),
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let co_owner = &env.recipient.keypair;
    EnrollOwners {
        ring,
        owners: &[sender, co_owner],
        env: &env,
    }
    .send()?;
    StorageRecords::mint_policy(
        ring,
        Member::asset(&SOL_MINT)?,
        MintPolicy {
            cap: 10_000_000,
            ..MintPolicy::default()
        },
        &env,
    )
    .send()?;
    let mut inputs = Vec::new();
    for (owner, amount) in [(sender, 10_000_000), (co_owner, 1_000_000)] {
        for note in (RingNotes {
            ring,
            owner,
            amount,
            asset: DepositAsset::Sol,
            count: 1,
            env: &env,
        })
        .deposit_hidden_from(&env.payer)?
        {
            inputs.push(indexed_note(note, owner, &env, env.tree)?);
        }
    }
    let transfer = AnonymousPayment {
        ring,
        sender,
        payer: env.payer.pubkey(),
        inputs,
        to: ring_address(co_owner, ring_program)?,
        amount: 11_000_000,
    }
    .transfer()?
    .with_co_owner(CoOwner {
        owner: co_owner.pubkey(),
        nullifier_key: &co_owner.nullifier_key,
    });
    let proven = env.run(transfer.prove(env.client.ring_client()))?;
    let instruction = proven.instruction()?;
    assert!(!signers(&instruction).contains(&sender.pubkey()));
    assert!(signers(&instruction).contains(&co_owner.pubkey()));

    let original = frame(&instruction, RingRail::Anonymous)?;
    let mut envelope = original.envelope.to_vec();
    envelope[0] ^= 1;
    let altered = reframed(
        &instruction,
        &RingTransactData {
            envelope: &envelope,
            ..original
        },
    )?;
    let tree_before = fetch_account(rpc, &env.tree)?;
    let error = RejectedTransact {
        payer: &env.payer,
        signers: &[co_owner],
        instruction: altered,
    }
    .send(rpc)?;
    Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
        .at(0)
        .assert_client(&error);
    assert_account_unchanged(rpc, &env.tree, &tree_before)?;

    let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer));
    let size = spr_client::transaction_size(
        &env.payer.pubkey(),
        std::slice::from_ref(&instruction),
        budget,
    )?;
    ensure!(
        size.bytes <= MAX_TRANSACTION_SIZE,
        "mixed owner frame exceeds the limit"
    );
    let signature = land(&env, instruction, &env.payer, &[co_owner])?;
    let units = assert_transaction_compute_units(
        rpc,
        &signature,
        "mixed owner net debit",
        u64::from(budget.cu_limit),
    )?;
    let indexed = wait_for_indexed_transaction(
        env.client.indexer(),
        auditor_view_tag(&auditor.pubkey()),
        signature,
    );
    assert_eq!(
        indexed
            .output_slots
            .iter()
            .filter(|slot| {
                slot.view_tag != [0; 32] && ring_body_output(&slot.payload).is_some()
            })
            .count(),
        1
    );
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor.pubkey()).with_mode(RingMode::Anonymous),
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    assert!(audited.payload_errors.is_empty());
    let mut spent: Vec<_> = AuditedSpends {
        ring,
        auditor: &auditor,
        owners: &[sender.pubkey(), co_owner.pubkey()],
        audited: &audited,
    }
    .notes(&env)?
    .iter()
    .map(|note| (note.amount, note.owner_key))
    .collect();
    spent.sort_unstable();
    assert_eq!(
        spent,
        [
            (1_000_000, co_owner.signing_pubkey().as_ed25519()?),
            (10_000_000, sender.signing_pubkey().as_ed25519()?),
        ]
    );
    let mut wallet = RingWallet::new(co_owner, env.ring_assets()?, ring_program);
    wallet.sync(&env)?;
    assert!(wallet.unspent().any(|note| note.utxo.amount == 11_000_000));
    assert!(!wallet.unspent().any(|note| note.utxo.amount == 1_000_000));
    println!(
        "mixed owner net debit settled {signature}, measured {} bytes and {units} CU, and refused the changed envelope",
        size.bytes
    );
    Ok(())
}
