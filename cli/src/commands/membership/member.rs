use anyhow::{Context as _, Result};
use custom_ring_interface::tracking::TrackingAuthorization;
use custom_ring_sdk::{CustomRing, Enroll, EnrollPending};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{BlockingIndexer, BlockingRpc};
use spr_keypair::ShieldedKeypair;
use spr_transaction::ShieldedKeys;
use zolana_ring_client::RingIndexer;
use zolana_ring_keys::ListSaltHolder;

use crate::{line, patiently, wait_for, Context, KeyCommand, Probe, Zolana};

const SEAL_PROMPT: &str = "seal the member key to the ring auditor and enroll it?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    AlreadyRegistered,
    Enroll,
    Declined,
}

#[must_use]
pub(crate) struct KeyEnrollment<'a> {
    pub members: &'a [&'a ShieldedKeypair],
}

pub fn key(ctx: &Context, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Register => register_key(ctx),
        KeyCommand::Apply => apply(ctx),
        KeyCommand::Rotate => crate::viewing_keys::rotate(ctx),
    }
}

fn register_key(ctx: &Context) -> Result<()> {
    let sender = ctx.sender()?;
    let member = ShieldedKeypair::from_keypair(&sender)?;
    line("member", sender.pubkey());
    let registered = registered(ctx.ring, &ctx.zolana, &member)?;
    match plan(registered, || ctx.ask_yes(SEAL_PROMPT, true))? {
        Plan::AlreadyRegistered => line("key", "already enrolled"),
        Plan::Declined => line("key", "not enrolled"),
        Plan::Enroll => {
            register(ctx, &member)?;
            line("key", "enrolled");
        }
    }
    Ok(())
}

impl KeyEnrollment<'_> {
    pub(crate) fn ensure(self, ctx: &Context) -> Result<()> {
        for member in self.members {
            let outcome = if registered(ctx.ring, &ctx.zolana, member)? {
                "already enrolled"
            } else {
                register(ctx, member)?;
                "enrolled"
            };
            line("member key", format_args!("{} {outcome}", member.pubkey()));
        }
        // The indexer can serve a registration after an apply read the queue.
        wait_for("every member key applied", || {
            for member in self.members {
                if !applied(ctx.ring, &ctx.zolana, member)? {
                    if let Some(signature) = apply_pending(ctx)? {
                        line("enrollments", signature);
                    }
                    return Ok(Probe::NotYet);
                }
            }
            Ok(Probe::Ready(()))
        })
    }
}

fn apply(ctx: &Context) -> Result<()> {
    match apply_pending(ctx)? {
        Some(signature) => line("enrollments", signature),
        None => line("enrollments", "none pending"),
    }
    Ok(())
}

fn apply_pending(ctx: &Context) -> Result<Option<Signature>> {
    let pending = patiently("the pending enrollments", || {
        ctx.block(EnrollPending { ring: ctx.ring }.prove(ctx.ring_client()))
    })?;
    let Some(instruction) = pending else {
        return Ok(None);
    };
    Ok(Some(ctx.send(&[ctx.funded_authority()?], &[instruction])?))
}

fn register(ctx: &Context, member: &ShieldedKeypair) -> Result<()> {
    let payer = ctx.funded_authority()?;
    let instruction = ctx.block(
        Enroll {
            ring: ctx.ring,
            payer: payer.pubkey(),
            owner: member.pubkey(),
            nullifier_key: &member.nullifier_key,
            viewing_pubkey: ctx.ring_keys(member)?.address()?.viewing_pubkey,
            list_salt: member.list_salt(&ctx.ring.program_id())?,
        }
        .prove(ctx.ring_client()),
    )?;
    ctx.send(&[payer, member], &[instruction.instruction()])?;
    Ok(())
}

fn plan(registered: bool, confirm: impl FnOnce() -> Result<bool>) -> Result<Plan> {
    Ok(match registered {
        true => Plan::AlreadyRegistered,
        false if confirm()? => Plan::Enroll,
        false => Plan::Declined,
    })
}

/// The first key is final, the member's authorization account holds it.
fn registered<R: BlockingRpc, I: BlockingIndexer + RingIndexer>(
    ring: CustomRing,
    zolana: &Zolana<R, I>,
    keys: &ShieldedKeypair,
) -> Result<bool> {
    Ok(authorization(ring, zolana, keys)?.is_some())
}

/// An apply has landed the member's row in the tracking root.
pub(crate) fn applied<R: BlockingRpc, I: BlockingIndexer + RingIndexer>(
    ring: CustomRing,
    zolana: &Zolana<R, I>,
    keys: &ShieldedKeypair,
) -> Result<bool> {
    Ok(authorization(ring, zolana, keys)?.is_some_and(|held| !held.is_pending()))
}

pub(crate) fn authorization<R: BlockingRpc, I: BlockingIndexer + RingIndexer>(
    ring: CustomRing,
    zolana: &Zolana<R, I>,
    keys: &ShieldedKeypair,
) -> Result<Option<TrackingAuthorization>> {
    let policy = zolana.block_on(ring.require_policy(zolana.as_async().rpc()))?;
    let (address, _) = TrackingAuthorization::find_address(&policy.tracking, &keys.pubkey());
    zolana
        .rpc()
        .get_account(address)?
        .map(|account| {
            TrackingAuthorization::decode(&account.owner, &account.data)
                .with_context(|| format!("{address} is not a tracking authorization"))
        })
        .transpose()
}
