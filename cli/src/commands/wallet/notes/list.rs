//! `list`, the member records of the ring's registry and where each list reads them.

use anyhow::{bail, ensure, Context as _, Result};
use clap::{builder::PossibleValue, Args, ValueEnum};
use custom_ring_interface::ListRegistry;
use custom_ring_sdk::{
    AuthorityRecordUpdate, MemberRecords, OwnerSaltCheck, PolicyUpdate, SaltedOwnerCheck,
    SourceOwner, UpdatePolicy, WalletRecordUpdate,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_ring_keys::{RingAddress, RingKeyError};
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
    /// A member on a private list, its ring address or its owner key with the salt read from Ring RPC, repeatable.
    #[arg(long = "salted-owner", value_name = "RING_ADDRESS_OR_OWNER", value_parser = parse_salted_owner)]
    salted_owners: Vec<SaltedOwner>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaltedOwner {
    Address(Box<RingAddress>),
    Key(Address),
}

fn parse_salted_owner(text: &str) -> Result<SaltedOwner, RingKeyError> {
    match RingAddress::from_base58(text) {
        Ok(address) => Ok(SaltedOwner::Address(Box::new(address))),
        Err(refused) => text.parse().map(SaltedOwner::Key).map_err(|_| refused),
    }
}

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
    /// A private list reads only an owner's salted key, a public one never does.
    pub(crate) fn subjects(
        &self,
        list_id: ListId,
        ring: Address,
        read_salt: &dyn Fn(&Address) -> Result<[u8; 32]>,
    ) -> Result<Vec<Subject>> {
        if !ListSet::PRIVATE_LISTS.contains(list_id) {
            ensure!(
                self.salted_owners.is_empty(),
                "the {} list is public, name its owners with --owner",
                list_id.name()
            );
            return self.public_subjects();
        }
        ensure!(
            self.owners.is_empty() && self.assets.is_empty(),
            "the {} list keys owners by their salt, name them with --salted-owner",
            list_id.name()
        );
        self.salted_owners
            .iter()
            .map(|salted| {
                let (owner, list_salt) = match salted {
                    SaltedOwner::Address(address) => {
                        ensure!(
                            address.ring_program_id == ring,
                            "a ring address of ring {} cannot name a member of ring {ring}",
                            address.ring_program_id
                        );
                        ensure!(
                            address.list_salt != [0; 32],
                            "a ring address with no salt has no tracking row and no private record"
                        );
                        (
                            address.recipient.signing_pubkey.as_ed25519()?,
                            address.list_salt,
                        )
                    }
                    SaltedOwner::Key(owner) => (owner.to_bytes(), read_salt(owner)?),
                };
                Ok(Subject {
                    member: Member::salted(&Member::owner_tag(&owner)?, &list_salt)?,
                    label: format!("salted owner {}", Address::new_from_array(owner)),
                })
            })
            .collect()
    }

    fn public_subjects(&self) -> Result<Vec<Subject>> {
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
    pub const ALL: [Self; 1] = [Self(ListId::RingViewing)];

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
    /// Checked against the chain, a salted entry under any other salt is one no proof reads.
    fn checked_subjects(&self, ctx: &Context) -> Result<Vec<Subject>> {
        let list_id = self.list_id.id();
        let read_salt = |owner: &Address| -> Result<[u8; 32]> {
            let list_salt = ctx
                .ring_rpc()
                .list_salt(ctx.ring_rpc_target()?, *owner, ctx.authority()?)?
                .with_context(|| format!("{owner} has no tracking row and no private record"))?;
            ctx.zolana
                .block_on(
                    OwnerSaltCheck {
                        ring: ctx.ring,
                        owner,
                        list_salt: &list_salt,
                    }
                    .run(ctx.zolana.as_async()),
                )
                .with_context(|| format!("the salt Ring RPC returned opens no tag of {owner}"))?;
            Ok(list_salt)
        };
        let subjects = self
            .members
            .subjects(list_id, ctx.ring.program_id(), &read_salt)?;
        for salted in &self.members.salted_owners {
            let SaltedOwner::Address(address) = salted else {
                continue;
            };
            ctx.zolana
                .block_on(
                    SaltedOwnerCheck {
                        ring: ctx.ring,
                        address,
                    }
                    .run(ctx.zolana.as_async()),
                )
                .with_context(|| {
                    format!(
                        "the salt of {} does not reach a list entry",
                        address.to_base58()
                    )
                })?;
        }
        Ok(subjects)
    }

    fn write(self, ctx: &Context, change: ListChange) -> Result<()> {
        let list_id = self.list_id.id();
        let subjects = self.checked_subjects(ctx)?;
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
        let subjects = self.checked_subjects(ctx)?;
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
            current: &account,
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
        Ok(members
            .subjects(ListId::Block, Address::new_from_array([0x11; 32]), &|_| {
                bail!("no read")
            })
            .expect("members"))
    }

    /// A private list keys an owner by its salt, the same key the circuit derives.
    #[test]
    fn a_private_list_writes_the_salted_key_and_refuses_a_plain_owner() {
        let ring = Address::new_from_array([0x11; 32]);
        let wallet = spr_keypair::ShieldedKeypair::from_keypair(
            spr_keypair::SigningKey::from_ed25519_bytes(&[7; 32]),
        )
        .unwrap();
        let address = RingAddress::enrolled(&wallet, ring).unwrap();
        let args = |owners: Vec<Address>, addresses: Vec<RingAddress>| MemberArgs {
            owners,
            assets: Vec::new(),
            salted_owners: addresses
                .into_iter()
                .map(|address| SaltedOwner::Address(Box::new(address)))
                .collect(),
        };
        let no_read = |_: &Address| -> Result<[u8; 32]> { bail!("no read") };
        let salted = args(Vec::new(), vec![address.clone()])
            .subjects(ListId::PrivateBlock, ring, &no_read)
            .unwrap();
        let owner = address.recipient.signing_pubkey.as_ed25519().unwrap();
        assert_eq!(
            salted[0].member,
            Member::salted(&Member::owner_tag(&owner).unwrap(), &address.list_salt).unwrap()
        );
        assert_ne!(salted[0].member, Member::owner_tag(&owner).unwrap());

        let by_key = MemberArgs {
            owners: Vec::new(),
            assets: Vec::new(),
            salted_owners: vec![SaltedOwner::Key(Address::new_from_array(owner))],
        };
        let read = by_key
            .subjects(ListId::PrivateBlock, ring, &|_| Ok(address.list_salt))
            .unwrap();
        assert_eq!(read[0].member, salted[0].member);
        assert!(by_key
            .subjects(ListId::PrivateBlock, ring, &no_read)
            .is_err());

        let plain = TAG.parse().unwrap();
        assert!(args(vec![plain], Vec::new())
            .subjects(ListId::PrivateAllow, ring, &no_read)
            .is_err());
        assert!(args(Vec::new(), vec![address.clone()])
            .subjects(ListId::Block, ring, &no_read)
            .is_err());
        assert!(args(Vec::new(), vec![address])
            .subjects(
                ListId::PrivateBlock,
                Address::new_from_array([0x12; 32]),
                &no_read
            )
            .is_err());
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
        for list in ["allow", "block"] {
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
