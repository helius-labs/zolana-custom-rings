//! `list-approval`, the policy authority's side of a wallet update pending list approval.
//! Approval is the authority's own record update, the off chain check behind it stays with the authority.

use anyhow::{ensure, Context as _, Result};
use custom_ring_sdk::AuthorityRecordUpdate;
use solana_address::Address;
use solana_signer::Signer;
use zolana_ring_client::rpc::{ListApprovalScope, PendingListApproval};
use zolana_ring_policy::{ListChange, ListSet, Member};

use crate::{line, Context, ListApprovalCommand};

pub fn run(ctx: &Context, command: ListApprovalCommand) -> Result<()> {
    match command {
        ListApprovalCommand::Pending => pending(ctx),
        ListApprovalCommand::Approve { wallet } => approve(ctx, wallet),
    }
}

fn pending(ctx: &Context) -> Result<()> {
    let pending = read_pending(ctx, ctx.record_update_target()?.registry)?;
    if pending.is_empty() {
        line("pending", "none");
    }
    for update in &pending {
        line(
            "wallet",
            format_args!(
                "{} awaits {} until slot {}",
                update.wallet.0,
                list_names(awaited(update)?),
                update.valid_until_slot
            ),
        );
    }
    Ok(())
}

/// The writer lands the wallet's pending updates in the same batch as the approval.
fn approve(ctx: &Context, wallet: Address) -> Result<()> {
    let target = ctx.record_update_target()?;
    let lists = read_pending(ctx, target.registry)?
        .iter()
        .filter(|update| update.wallet.0 == wallet)
        .try_fold(ListSet::EMPTY, |lists, update| {
            Ok::<_, anyhow::Error>(lists.union(awaited(update)?))
        })?;
    ensure!(
        !lists.is_empty(),
        "no update of {wallet} is pending list approval"
    );
    let authority = ctx.authority()?;
    let write = ListChange {
        set: lists,
        clear: ListSet::EMPTY,
    }
    .check()?;
    let update = AuthorityRecordUpdate::new(target, authority.pubkey())
        .with_write(Member::owner_tag(wallet.as_array())?, write)?;
    let revision = ctx
        .ring_rpc()
        .apply_record_update(update.sign(authority)?)?;
    line(
        "approved",
        format_args!("{wallet} {} at revision {revision}", list_names(lists)),
    );
    Ok(())
}

fn read_pending(ctx: &Context, registry: Address) -> Result<Vec<PendingListApproval>> {
    let authority = ctx.authority()?;
    ctx.ring_rpc().pending_list_approvals(
        ListApprovalScope {
            target: ctx.ring_rpc_target()?,
            authority: authority.pubkey(),
            registry,
        },
        authority,
    )
}

fn awaited(update: &PendingListApproval) -> Result<ListSet> {
    ListSet::from_record_bits(update.awaited_lists)
        .context("the ring rpc named a list bit no list owns")
}

fn list_names(lists: ListSet) -> String {
    lists
        .iter()
        .map(|list| list.name())
        .collect::<Vec<_>>()
        .join(", ")
}
