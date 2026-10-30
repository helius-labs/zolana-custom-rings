//! `list`, the member records of the ring's registry and where each list reads them.

use anyhow::{bail, Context as _, Result};
use clap::{builder::PossibleValue, Args, ValueEnum};
use custom_ring_interface::ListRegistry;
use custom_ring_sdk::{
    AuthorityRecordUpdate, MemberRecords, PolicyUpdate, SourceOwner, UpdatePolicy,
    WalletRecordUpdate,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_ring_policy::{ListId, ListSet, ListWrite, ListWriteError, Member};

use crate::{
    catalogue::{check_curator, Catalogue},
    line,
    policy::{self, Pinned},
    records,
    ui::{self, icon},
    Context, EntryArgs, ListCommand,
};

#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = true)]
pub struct MemberArgs {
    /// A member's Solana address, repeatable.
    #[arg(long = "owner", value_name = "ADDRESS")]
    owners: Vec<Address>,
    /// A mint the list screens, repeatable.
    #[arg(long = "asset", value_name = "MINT")]
    assets: Vec<Address>,
}

/// The escrow bit comes only from `key register`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberList(ListId);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Subject {
    pub member: Member,
    pub label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListChange {
    Set,
    Clear,
}

#[must_use]
pub(crate) struct ListUpdate<'a> {
    pub authority: &'a Keypair,
    pub list_id: ListId,
    pub subjects: &'a [Subject],
    pub change: ListChange,
}

pub fn run(ctx: &Context, command: ListCommand) -> Result<()> {
    match command {
        ListCommand::Add(entry) => entry.write(ctx, ListChange::Set),
        ListCommand::Clear(entry) => entry.write(ctx, ListChange::Clear),
        ListCommand::Show(entry) => entry.show(ctx),
        ListCommand::SetSource {
            list_id,
            curator,
            own,
        } => {
            let source = match curator.filter(|_| !own) {
                Some(curator) => {
                    let curator = Catalogue::load(ctx.catalogue.as_deref())?
                        .resolve(ctx.config.target, &curator)?;
                    check_curator(ctx, curator, list_id.id())?;
                    SourceOwner::Curator(policy::curator_records(ctx, curator)?)
                }
                None => SourceOwner::Own,
            };
            set_source(ctx, list_id.id(), source)
        }
        ListCommand::Join { list } => list.write(ctx, ListChange::Set),
        ListCommand::Leave { list } => list.write(ctx, ListChange::Clear),
    }
}

impl MemberArgs {
    pub(crate) fn subjects(&self) -> Result<Vec<Subject>> {
        let owners = self.owners.iter().map(|tag| {
            Ok(Subject {
                member: Member::owner_tag(tag.as_array())?,
                label: format!("owner {tag}"),
            })
        });
        let assets = self.assets.iter().map(|mint| {
            Ok(Subject {
                member: Member::asset(mint)?,
                label: format!("asset {mint}"),
            })
        });
        owners.chain(assets).collect()
    }
}

impl MemberList {
    /// In `ListId::ALL` order.
    pub const ALL: [Self; 2] = [Self(ListId::RingViewing), Self(ListId::Recovery)];

    pub const fn id(self) -> ListId {
        self.0
    }

    fn write(self, ctx: &Context, change: ListChange) -> Result<()> {
        let list_id = self.0;
        let sender = ctx.sender()?;
        let member = Member::owner_tag(sender.pubkey().as_array())?;
        line(
            "member",
            format_args!("{} {}", list_id.name(), sender.pubkey()),
        );
        let read = records::read_one(
            &ctx.zolana,
            MemberRecords {
                ring: ctx.ring,
                members: &[member],
            },
        )?;
        if read.listed(list_id) == change.present() {
            line("list", "already there");
            return Ok(());
        }
        let update = WalletRecordUpdate::new(ctx.record_update_target()?, sender.pubkey())?
            .with_lists(change.write(list_id)?)?
            .sign(&sender)?;
        warn_link(ctx, sender.pubkey());
        let revision = ctx.ring_rpc().apply_record_update(update)?;
        line("list", change.outcome());
        line("revision", revision);
        Ok(())
    }
}

impl ValueEnum for MemberList {
    fn value_variants<'a>() -> &'a [Self] {
        &Self::ALL
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.0.name()))
    }
}

impl ListChange {
    fn write(self, list_id: ListId) -> Result<ListWrite, ListWriteError> {
        let list = ListSet::single(list_id);
        let (set, clear) = match self {
            Self::Set => (list, ListSet::EMPTY),
            Self::Clear => (ListSet::EMPTY, list),
        };
        zolana_ring_policy::ListChange { set, clear }.check()
    }

    const fn present(self) -> bool {
        matches!(self, Self::Set)
    }

    const fn outcome(self) -> &'static str {
        match self {
            Self::Set => "added",
            Self::Clear => "removed",
        }
    }
}

impl EntryArgs {
    fn write(self, ctx: &Context, change: ListChange) -> Result<()> {
        let list_id = self.list_id.id();
        let subjects = self.members.subjects()?;
        let outcomes = ListUpdate {
            authority: ctx.authority()?,
            list_id,
            subjects: &subjects,
            change,
        }
        .send(ctx)?;
        for (subject, outcome) in subjects.iter().zip(outcomes) {
            line(
                "member",
                format_args!("{} {}", list_id.name(), subject.label),
            );
            line("list", outcome);
        }
        Ok(())
    }

    fn show(self, ctx: &Context) -> Result<()> {
        let list_id = self.list_id.id();
        let subjects = self.members.subjects()?;
        let members: Vec<Member> = subjects.iter().map(|subject| subject.member).collect();
        let pinned = policy::pinned(ctx)?;
        let (source, reads) = match pinned.account.registry_for(list_id) {
            Some(ListRegistry::Curator(registry)) => (
                format!("curator registry {registry}"),
                records::read_curator(ctx, &pinned.account, &members)?,
            ),
            _ => (
                format!("own records {}", pinned.account.records),
                records::read(
                    &ctx.zolana,
                    MemberRecords {
                        ring: ctx.ring,
                        members: &members,
                    },
                )?,
            ),
        };
        line("source", source);
        for (subject, read) in subjects.iter().zip(&reads) {
            line(
                "member",
                format_args!("{} {}", list_id.name(), subject.label),
            );
            line("listed", read.listed(list_id));
            let record = match read.record() {
                Some(_) => "present",
                None => "absent",
            };
            line("record", record);
        }
        Ok(())
    }
}

impl ListUpdate<'_> {
    /// Writes the ring's own registry only, a curator's list is written on the curator ring.
    pub(crate) fn send(self, ctx: &Context) -> Result<Vec<&'static str>> {
        let list_id = self.list_id;
        if let Some(ListRegistry::Curator(registry)) =
            policy::pinned(ctx)?.account.registry_for(list_id)
        {
            bail!(
                "the {} list reads curator registry {registry}, write it on the curator ring",
                list_id.name()
            );
        }
        let members: Vec<Member> = self.subjects.iter().map(|subject| subject.member).collect();
        let reads = records::read(
            &ctx.zolana,
            MemberRecords {
                ring: ctx.ring,
                members: &members,
            },
        )?;
        let mut update =
            AuthorityRecordUpdate::new(ctx.record_update_target()?, self.authority.pubkey());
        let mut changed = false;
        let mut outcomes = Vec::with_capacity(self.subjects.len());
        for (subject, read) in self.subjects.iter().zip(&reads) {
            if read.listed(list_id) == self.change.present() {
                outcomes.push("already there");
                continue;
            }
            update = update.with_write(subject.member, self.change.write(list_id)?)?;
            changed = true;
            outcomes.push(self.change.outcome());
        }
        if changed {
            ctx.ring_rpc()
                .apply_record_update(update.sign(self.authority)?)?;
        }
        Ok(outcomes)
    }
}

/// The registry a source names, as the policy stores it.
pub(crate) fn expected_registry(source: SourceOwner) -> ListRegistry {
    match source {
        SourceOwner::Own => ListRegistry::Own,
        SourceOwner::Curator(registry) => ListRegistry::Curator(registry),
    }
}

fn set_source(ctx: &Context, list_id: ListId, source: SourceOwner) -> Result<()> {
    let Pinned { account, .. } = policy::pinned(ctx)?;
    let authority = ctx.funded_authority()?;
    let outcome = if account.registry_for(list_id) == Some(expected_registry(source)) {
        "already present"
    } else {
        let point = UpdatePolicy {
            ring: ctx.ring,
            authority: authority.pubkey(),
            update: PolicyUpdate::Source { list_id, source },
        }
        .instruction()?;
        ctx.send(&[authority], &[point])?;
        "created"
    };
    let registry = policy::pinned(ctx)?
        .account
        .registry_for(list_id)
        .with_context(|| format!("the policy does not reference the {} list", list_id.name()))?;
    let (glyph, reads) = match source {
        SourceOwner::Own => (icon::LISTS, "its own records".to_owned()),
        SourceOwner::Curator(registry) => (icon::CURATOR, format!("curator registry {registry}")),
    };
    ui::heading(glyph, &format!("the {} list reads {reads}", list_id.name()));
    line("source", outcome);
    line(
        "registry",
        match registry {
            ListRegistry::Own => account.records,
            ListRegistry::Curator(registry) => registry,
        },
    );
    Ok(())
}

fn warn_link(ctx: &Context, signer: Address) {
    let ring = ctx.ring.program_id();
    ui::warn(format!(
        "{signer} signs, the chain links that key to ring {ring}"
    ));
}

#[cfg(test)]
mod tests {
    use clap::{error::ErrorKind, Parser};

    use super::*;
    use crate::{Cli, Command, ListCommand};

    const TAG: &str = "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh";
    const MINT: &str = "So11111111111111111111111111111111111111112";

    fn parse(verb: &str, flags: &[&str]) -> Result<Vec<Subject>, clap::Error> {
        let argv = ["zolana-ring", "list", verb, "block"]
            .into_iter()
            .chain(flags.iter().copied());
        let Command::List(command) = Cli::try_parse_from(argv)?.command else {
            panic!("a list command");
        };
        let members = match command {
            ListCommand::Add(entry) | ListCommand::Clear(entry) | ListCommand::Show(entry) => {
                entry.members
            }
            _ => panic!("a member command"),
        };
        Ok(members.subjects().expect("members"))
    }

    fn subject(member: Member, label: String) -> Subject {
        Subject { member, label }
    }

    #[test]
    fn every_member_command_takes_repeated_owners_and_assets() {
        let tag = Member::owner_tag(Address::from_str_const(TAG).as_array()).expect("member");
        let mint = Member::asset(&Address::from_str_const(MINT)).expect("mint");
        for verb in ["add", "clear", "show"] {
            assert_eq!(
                parse(verb, &["--owner", TAG]).expect(verb),
                [subject(tag, format!("owner {TAG}"))]
            );
            assert_eq!(
                parse(verb, &["--asset", MINT, "--owner", TAG, "--owner", TAG]).expect(verb),
                [
                    subject(tag, format!("owner {TAG}")),
                    subject(tag, format!("owner {TAG}")),
                    subject(mint, format!("asset {MINT}")),
                ]
            );
        }
        assert_eq!(
            parse("add", &[]).expect_err("no member").kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn a_member_writes_only_its_own_lists() {
        let join = |list: &str| Cli::try_parse_from(["zolana-ring", "list", "join", list]);
        for list in MemberList::ALL {
            assert!(join(list.0.name()).is_ok(), "{}", list.0.name());
        }
        for list in ["allow", "escrow", "block"] {
            assert!(join(list).is_err(), "{list}");
        }
    }

    #[test]
    fn the_member_lists_are_the_lists_a_member_writes() {
        let lists: Vec<ListId> = MemberList::ALL.into_iter().map(MemberList::id).collect();
        let written: Vec<ListId> = ListId::ALL
            .into_iter()
            .filter(|list_id| ListSet::MEMBER_WRITES.contains(*list_id))
            .collect();
        assert_eq!(lists, written);
    }

    #[test]
    fn a_source_names_the_registry_account() {
        let curator = Address::new_from_array([4; 32]);
        assert_eq!(expected_registry(SourceOwner::Own), ListRegistry::Own);
        assert_eq!(
            expected_registry(SourceOwner::Curator(curator)),
            ListRegistry::Curator(curator)
        );
    }
}
