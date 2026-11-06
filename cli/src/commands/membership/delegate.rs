//! `delegate move`, the permanent delegate spends a member's ring notes.

use anyhow::{anyhow, ensure, Context as _, Result};
use custom_ring_sdk::{
    DelegateMove, DelegatePayment, DelegateSource, DelegateSourceError, ResolvedSource,
    TrackingEnrollment,
};
use solana_signer::Signer;
use spr_client::{IndexerRpcConfig, Rpc};
use spr_transaction::SOL_MINT;
use zolana_ring_client::{RecoveryStep, RingRecovery, SourceMember};

use crate::{
    assets,
    controls::{ring_auditor_key, DualControl},
    file, line,
    transact::{PAYER_FEE_BUDGET, SENDER_FEE_BUDGET},
    Context, DelegateMoveArgs,
};

/// The source keeps note ownership until the delegate's signed move executes.
pub fn run_move(ctx: &Context, args: DelegateMoveArgs) -> Result<()> {
    let (source, amount) = (args.source, args.amount);
    ensure!(amount > 0, "the move amount must be greater than zero");
    let mint = args.mint.map_or(SOL_MINT, |mint| mint.0);
    let config = ctx.ring_config()?;
    let delegate = file::read_keypair(&ctx.path(&args.delegate_keypair))?;
    let stored = config.delegate.context("the ring has no delegate")?;
    ensure!(
        stored == delegate.pubkey(),
        "the delegate keypair {} is not the ring's delegate {stored}",
        delegate.pubkey()
    );
    DualControl {
        cosigner: None,
        delegate: Some(stored),
    }
    .check()?;
    // The auditor key decrypts recovery material, only the delegate signs.
    let auditor = ring_auditor_key(ctx, &args.auditor_key)?;
    let chain = ctx.chain();
    let enrollment = TrackingEnrollment {
        rpc: chain.rpc(),
        tracking_registry: config.account().tracking,
        auditor: &auditor,
    };
    let resolved = ctx
        .block(async { anyhow::Ok(ResolvedSource::resolve(source, &enrollment).await) })?
        .map_err(|error| match error {
            DelegateSourceError::Unenrolled => {
                anyhow!(
                    "member {source} has no enrolled key, it runs `zolana-ring key register` first"
                )
            }
            error => anyhow::Error::from(error).context(format!("delegate source {source}")),
        })?;
    let assets = assets::resolve(ctx.rpc(), mint)?.assets;
    let indexer_config = IndexerRpcConfig::at_slot(ctx.rpc().get_slot()?);
    let start = || {
        RingRecovery::new(ctx.ring.program_id(), &auditor)
            .with_mode(config.mode)
            .with_indexer_config(indexer_config)
            .for_member(SourceMember {
                address: &source,
                nullifier_key: resolved.nullifier_key(),
            })
    };
    let mut recovery = start();
    let recovered = loop {
        match ctx.block(recovery.run(chain.indexer(), chain.rpc(), &assets))? {
            RecoveryStep::Complete(notes) => break notes,
            RecoveryStep::Paused(progress) => recovery = start().with_progress(progress),
        }
    };
    resolved.check_notes(&recovered.utxos)?;
    if !recovered.unopened.is_empty() {
        line("unopened notes", recovered.unopened.len());
    }
    let authority = ctx.authority()?;
    let transfer = ctx.block(
        DelegateMove {
            exits: Vec::new(),
            withdrawals: Vec::new(),
            ring: ctx.ring,
            delegate: delegate.pubkey(),
            payer: authority.pubkey(),
            sources: vec![DelegateSource {
                address: source,
                nullifier_key: resolved.nullifier_key(),
                utxos: &recovered.utxos,
            }],
            payments: args
                .to
                .iter()
                .map(|to| DelegatePayment {
                    recipient: *to,
                    mint,
                    amount,
                })
                .collect(),
            assets: assets.registry(),
            tx_viewing_key: spr_keypair::ViewingKey::new(),
        }
        .select(ctx.ring_client()),
    )?;
    ctx.require_balance(authority.pubkey(), SENDER_FEE_BUDGET + PAYER_FEE_BUDGET)?;
    ctx.ring_rpc().check_serves(ctx.ring.program_id())?;
    let signers = [&delegate as &(dyn Signer + Sync)];
    let moved = ctx.submit(transfer, authority, &signers)?;
    for to in &args.to {
        line("to", to);
    }
    line("amount", format_args!("{amount} base units each"));
    line("mint", mint);
    line("move", moved);
    Ok(())
}
