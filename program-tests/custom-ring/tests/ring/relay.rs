//! Each relay operation lands through a served Ring RPC that pays the fee and proves with the suite's prover.

use anyhow::bail;
use custom_ring_sdk::{MergeRelay, PreparedAuthorityTransfer, RelaySent};
use custom_ring_test_validator::{
    policy::{DEPOSIT, TRANSFER_AMOUNT},
    ring_rpc::RelayedRingRpc,
};
use zolana_ring_client::rpc::{
    AuthorityPayment, AuthorityTransfer, AuthorityTransferAttestation, AuthorityTransferRequest,
    MergeSettings, MergeSettingsAttestation, MergeSettingsRequest, RelayOperation,
};

use super::*;

#[test]
fn a_relayed_anonymous_payment_reaches_its_recipient() -> Result<()> {
    let relayed = RelayedRing::register(Tier::AnonymousAuditOnly)?;
    let env = &relayed.env;
    let ring_rpc = relayed.serve()?;
    let (sender, recipient) = (&env.sender.keypair, &env.recipient.keypair);
    let ring_program = relayed.ring.program_id();
    relayed.notes(sender, 2).deposit_hidden_from(&env.payer)?;
    let mut sender_wallet = RingWallet::new(sender, env.ring_assets()?, ring_program);
    sender_wallet.sync(env)?;
    let transfer = AnonymousPayment {
        ring: relayed.ring,
        sender,
        history: &sender_wallet.history,
        payer: ring_rpc.fee_payer,
        inputs: sender_wallet.unspent().cloned().collect(),
        to: ring_address(recipient, ring_program)?,
        first_contact: FirstContact::Bootstrap,
        amount: TRANSFER_AMOUNT,
    }
    .transfer()?;
    let quote = ring_rpc.quote(env, RelayOperation::Anonymous)?;

    let prepared = env.run(transfer.prepare_relay(env.client.as_async(), quote))?;
    let relay_id = env.run(prepared.send(&ring_rpc.relay))?.submitted()?;

    ring_rpc.confirmed(env, &relay_id)?;
    let mut recipient_wallet = RingWallet::new(recipient, env.ring_assets()?, ring_program);
    recipient_wallet.sync(env)?;
    sender_wallet.sync(env)?;
    assert_eq!(
        sorted_notes(recipient_wallet.unspent()),
        [(SOL_MINT, TRANSFER_AMOUNT, Some(ring_program))]
    );
    assert_eq!(
        sorted_notes(sender_wallet.unspent()),
        [(SOL_MINT, 2 * DEPOSIT - TRANSFER_AMOUNT, Some(ring_program))]
    );
    Ok(())
}

#[test]
fn a_relayed_confidential_transfer_signed_in_the_proof_reaches_its_recipient() -> Result<()> {
    let relayed = RelayedRing::register(Tier::policy(&EMPTY))?;
    let env = &relayed.env;
    let ring_rpc = relayed.serve()?;
    let sender = &env.sender.keypair;
    let recipient = env.recipient.keypair.shielded_address()?;
    let ring_program = relayed.ring.program_id();
    let mut transaction = relayed.deposit_spend(sender, ring_rpc.fee_payer)?;
    transaction.transfer_sol(&recipient, TRANSFER_AMOUNT)?;
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: relayed.ring,
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_in_proof_owner(&sender.signing_key);
    let quote = ring_rpc.quote(env, RelayOperation::Confidential)?;

    let prepared = env.run(transfer.prepare_relay(env.client.as_async(), quote))?;
    let relay_id = env.run(prepared.send(&ring_rpc.relay))?.submitted()?;

    let signature = ring_rpc.confirmed(env, &relay_id)?;
    let auditor_tag = auditor_view_tag(&relayed.auditor.pubkey());
    let indexed = wait_for_indexed_transaction(env.client.indexer(), auditor_tag, signature);
    let mut recipient_wallet = Wallet::new(recipient, env.assets.clone())?;
    WalletSync {
        wallet: &mut recipient_wallet,
        keys: &env.recipient.keypair,
        assets: &env.ring_assets()?,
        transactions: std::slice::from_ref(&indexed),
    }
    .sync()?;
    assert_eq!(
        sorted_unspent_notes(&recipient_wallet),
        [(SOL_MINT, TRANSFER_AMOUNT, Some(ring_program))]
    );
    Ok(())
}

#[test]
fn a_relayed_deposit_lands_the_note_the_auditor_recovers() -> Result<()> {
    let relayed = RelayedRing::register(Tier::AuditOnly)?;
    let env = &relayed.env;
    let ring_rpc = relayed.serve()?;
    let depositor = &env.sender.keypair;
    let deposit = RingDeposit {
        ring: relayed.ring,
        payer: depositor,
        recipient: DepositRecipient::Confidential(depositor.shielded_address()?),
        tree: env.tree,
        asset: DepositAsset::Sol,
        amount: DEPOSIT,
        cosigner: None,
    };
    let quote = ring_rpc.quote(env, RelayOperation::Deposit)?;

    let prepared = env.run(deposit.prepare_relay(env.client.as_async(), quote))?;
    let RelaySent::SignMessage(pending) = env.run(prepared.send(&ring_rpc.relay))? else {
        bail!("the depositor signs its funding");
    };
    let relay_id = pending.relay_id().clone();
    env.run(pending.sign(&ring_rpc.relay, depositor))?;

    let signature = ring_rpc.confirmed(env, &relay_id)?;
    assert_eq!(relayed.recovered(depositor, signature)?, [DEPOSIT]);
    Ok(())
}

#[test]
fn a_relayed_user_merge_lands_one_note_of_the_merged_value() -> Result<()> {
    let relayed = RelayedRing::register(Tier::AuditOnly)?;
    let env = &relayed.env;
    let ring_rpc = relayed.serve()?;
    let owner = &env.sender.keypair;
    let inputs = relayed
        .notes(owner, 2)
        .deposit()?
        .into_iter()
        .map(|utxo| indexed_note(utxo, owner, env, env.tree))
        .collect::<Result<Vec<_>>>()?;
    let quote = ring_rpc.quote(env, RelayOperation::Merge)?;

    let prepared = MergeRelay {
        ring: relayed.ring,
        sender: owner.shielded_address()?,
        nullifier_key: owner.nullifier_key.clone(),
        inputs,
    }
    .prepare(quote)?;
    let relay_id = env.run(prepared.send(&ring_rpc.relay))?.submitted()?;

    let signature = ring_rpc.confirmed(env, &relay_id)?;
    assert_eq!(relayed.recovered(owner, signature)?, [2 * DEPOSIT]);
    Ok(())
}

#[test]
fn a_relayed_authority_transfer_moves_the_escrowed_members_note() -> Result<()> {
    const MOVED: u64 = TRANSFER_AMOUNT / 2;

    let relayed = RelayedRing::register(Tier::policy(&EMPTY))?;
    let env = &relayed.env;
    let member = &env.sender.keypair;
    let member_address = member.shielded_address()?;
    let delegate = env.funded_keypair()?;
    relayed.escrow(&delegate)?;
    env.enable_authority_rail(relayed.ring)?;
    relayed.keyed_notes(member)?;
    let ring_rpc = relayed.serve()?;
    let transfer = AuthorityTransfer {
        source: member_address.into(),
        mint: SOL_MINT.into(),
        payments: vec![AuthorityPayment {
            recipient: member_address.into(),
            amount: MOVED,
        }],
    };

    // The service opens the member's note and escrowed key at its next backfill.
    let pending = wait_for("the service to open the escrowed note", || {
        let request = AuthorityTransferRequest::new(AuthorityTransferAttestation {
            target: ring_rpc.target,
            delegate: delegate.pubkey(),
            transfer: transfer.clone(),
        })
        .sign(&delegate)?;
        Ok(
            match env.run(PreparedAuthorityTransfer::new(request).send(&ring_rpc.relay)) {
                Ok(RelaySent::SignMessage(pending)) => Probe::Ready(pending),
                Ok(RelaySent::Submitted(_)) => bail!("the delegate signs the move"),
                Err(error) => Probe::Retry(error.into()),
            },
        )
    })?;
    let relay_id = pending.relay_id().clone();
    env.run(pending.sign(&ring_rpc.relay, &delegate))?;

    let signature = ring_rpc.confirmed(env, &relay_id)?;
    let recovered = relayed.recovered(member, signature)?;
    assert_eq!(
        recovered.len(),
        3,
        "the move pays one note and returns the change"
    );
    assert!(recovered.contains(&MOVED));
    assert_eq!(recovered.iter().sum::<u64>(), DEPOSIT);
    Ok(())
}

#[test]
fn a_managed_merge_pass_settles_the_wallet_toward_its_target() -> Result<()> {
    let relayed = RelayedRing::register(Tier::policy(&EMPTY))?;
    let env = &relayed.env;
    let member = &env.sender.keypair;
    relayed.escrow(&env.funded_keypair()?)?;
    relayed.keyed_notes(member)?;
    let ring_rpc = relayed.serve()?;
    let request = MergeSettingsRequest::new(MergeSettingsAttestation {
        target: ring_rpc.target,
        owner: member.pubkey(),
        settings: MergeSettings {
            mint: SOL_MINT.into(),
            target_note_count: 1,
            min_average_amount: 0,
        },
    })
    .sign(member)?;
    env.run(ring_rpc.relay.set_merge_settings(request))?;

    // A pass merges nothing until the backfill opens the notes and the escrowed key.
    let sent = wait_for("a managed merge", || {
        let sent = ring_rpc.managed_merge_pass()?;
        Ok(if sent.is_empty() {
            Probe::NotYet
        } else {
            Probe::Ready(sent)
        })
    })?;

    let [signature] = <[Signature; 1]>::try_from(sent).map_err(|_| anyhow!("one merge"))?;
    let landed = wait_for("the merge to land", || {
        Ok(
            match env.client.rpc().client().get_signature_status(&signature)? {
                Some(landed) => Probe::Ready(landed),
                None => Probe::NotYet,
            },
        )
    })?;
    ensure!(landed.is_ok(), "the merge failed {landed:?}");
    assert_eq!(relayed.recovered(member, signature)?, [DEPOSIT]);
    Ok(())
}

struct RelayedRing {
    env: TestEnv,
    ring: CustomRing,
    auditor: X25519Keypair,
}

impl RelayedRing {
    fn register(tier: Tier) -> Result<Self> {
        let env = setup()?;
        let ring = CustomRing::new(custom_ring_program_id()?);
        let auditor = X25519Keypair::new();
        RegisterRing {
            ring,
            payer: &env.payer,
            auditor_pubkey: auditor.pubkey(),
            tier,
        }
        .send(&env.client)?;
        Ok(Self { env, ring, auditor })
    }

    fn serve(&self) -> Result<RelayedRingRpc> {
        RingRpcSpec {
            env: &self.env,
            ring: self.ring.program_id(),
            auditor: self.auditor.clone(),
        }
        .serve_relayed()
    }

    fn notes<'a>(&'a self, owner: &'a ShieldedKeypair, count: usize) -> RingNotes<'a> {
        RingNotes {
            ring: self.ring,
            owner,
            amount: DEPOSIT,
            count,
            env: &self.env,
        }
    }

    fn deposit_spend(
        &self,
        owner: &ShieldedKeypair,
        payer: Address,
    ) -> Result<ConfidentialTransaction> {
        let env = &self.env;
        let [deposited] = <[Utxo; 1]>::try_from(self.notes(owner, 1).deposit()?)
            .map_err(|_| anyhow!("one deposited note"))?;
        Ok(ConfidentialTransaction::new_with_ring(
            vec![indexed_note(deposited, owner, env, env.tree)?],
            payer,
            self.ring.program_id(),
        )?
        .with_output_tree_id(env.tree_id(env.tree)?)?)
    }

    /// Two notes a transfer gave the owner, the service opens no confidential deposit.
    fn keyed_notes(&self, owner: &ShieldedKeypair) -> Result<()> {
        let mut prepared = self.deposit_spend(owner, owner.pubkey())?;
        prepared.transfer_sol(&owner.shielded_address()?, TRANSFER_AMOUNT)?;
        OwnerTransfer {
            ring: self.ring,
            sender: owner,
            prepared,
            interface_transfer_accounts: Vec::new(),
            auditor_tag: auditor_view_tag(&self.auditor.pubkey()),
            cosigner: None,
        }
        .send(&self.env)?;
        Ok(())
    }

    fn escrow(&self, delegate: &Keypair) -> Result<()> {
        EscrowedDelegate {
            ring: self.ring,
            delegate,
            members: &[&self.env.sender.keypair],
        }
        .set(&self.env)
    }

    fn recovered(&self, owner: &ShieldedKeypair, signature: Signature) -> Result<Vec<u64>> {
        let env = &self.env;
        custom_ring_cli::wait_for_indexed_transaction(&env.client, signature)?;
        let client = env.client.as_async();
        let address = owner.shielded_address()?;
        let recovery =
            RingRecovery::new(self.ring.program_id(), &self.auditor).for_member(SourceMember {
                address: &address,
                nullifier_key: &owner.nullifier_key,
            });
        let recovered = env.client.block_on(recovery.run(
            client.indexer(),
            client.rpc(),
            &env.ring_assets()?,
        ))?;
        ensure!(recovered.unopened.is_empty(), "every note opens");
        let mut amounts: Vec<u64> = recovered
            .utxos
            .iter()
            .map(|held| held.utxo.amount)
            .collect();
        amounts.sort_unstable();
        Ok(amounts)
    }
}
