//! `enrolment`, the config authority's side of a wallet enrolment that awaits authority lists.

use anyhow::{ensure, Context as _, Result};
use custom_ring_sdk::AuthorityRecordUpdate;
use solana_address::Address;
use solana_signer::Signer;
use zolana_ring_client::rpc::PendingEnrolment;
use zolana_ring_policy::{ListChange, ListSet, Member};

use crate::{line, Context, EnrolmentCommand};

pub fn run(ctx: &Context, command: EnrolmentCommand) -> Result<()> {
    match command {
        EnrolmentCommand::Pending => pending(ctx),
        EnrolmentCommand::Approve { wallet } => approve(ctx, wallet),
    }
}

fn pending(ctx: &Context) -> Result<()> {
    let enrolments = read_pending(ctx)?;
    if enrolments.is_empty() {
        line("pending", "none");
    }
    for enrolment in &enrolments {
        line(
            "wallet",
            format_args!(
                "{} awaits {} until slot {}",
                enrolment.wallet.0,
                list_names(awaited(enrolment)?),
                enrolment.valid_until_slot
            ),
        );
    }
    Ok(())
}

/// The writer lands the wallet's enrolments in the same batch as the approval.
fn approve(ctx: &Context, wallet: Address) -> Result<()> {
    let lists = read_pending(ctx)?
        .iter()
        .filter(|enrolment| enrolment.wallet.0 == wallet)
        .try_fold(ListSet::EMPTY, |lists, enrolment| {
            Ok::<_, anyhow::Error>(lists.union(awaited(enrolment)?))
        })?;
    ensure!(
        !lists.is_empty(),
        "no enrolment of {wallet} awaits the config authority"
    );
    let authority = ctx.authority()?;
    let write = ListChange {
        set: lists,
        clear: ListSet::EMPTY,
    }
    .check()?;
    let update = AuthorityRecordUpdate::new(ctx.record_update_target()?, authority.pubkey())
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

fn read_pending(ctx: &Context) -> Result<Vec<PendingEnrolment>> {
    ctx.ring_rpc()
        .pending_enrolments(ctx.ring_rpc_target()?, ctx.authority()?)
}

fn awaited(enrolment: &PendingEnrolment) -> Result<ListSet> {
    ListSet::from_record_bits(enrolment.awaited_lists)
        .context("the ring rpc named a list bit no list owns")
}

fn list_names(lists: ListSet) -> String {
    lists
        .iter()
        .map(|list| list.name())
        .collect::<Vec<_>>()
        .join(", ")
}
