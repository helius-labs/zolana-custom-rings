//! `policy`, the pinned rule table read, checked against `ring.toml` and replaced.

#[cfg(test)]
mod example_tests;
pub mod grammar;
pub mod render;

pub use grammar::{
    describe, describe_limit, Alternative, AssetLimitSpec, CompiledPolicy, LimitSpec, ListName,
    PolicyError, PolicySpec, RuleSpec, SourceSpec, Sources, SubjectName,
};
pub use render::render;

use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::{ListRegistry, RingPolicy};
use custom_ring_sdk::{
    CustomRing, PinnedPolicy, PolicyTable, PolicyUpdate, SyncRoots, UpdatePolicy,
};
use solana_address::Address;
use solana_signer::Signer;
use zolana_ring_policy::RuleTable;

use crate::{
    catalogue::check_curator,
    line,
    ui::{self, icon},
    Context, PolicyCommand,
};

const NO_POLICY: &str =
    "the ring pins no policy, `zolana-ring init` pins the table of a policy ring";

pub(crate) struct Pinned {
    pub account: Box<RingPolicy>,
    pub policy: PinnedPolicy,
}

#[derive(Debug, PartialEq, Eq)]
struct Line {
    label: String,
    text: String,
}

pub fn run(ctx: &Context, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Show => {
            let pinned = pinned(ctx)?;
            let title = format!("policy {}", ctx.ring.policy_pda());
            ui::heading(icon::POLICY, &title);
            print_pinned(&pinned);
            for (member, policy) in crate::records::mint_policies(ctx)? {
                line(
                    "mint record",
                    format_args!(
                        "{} threshold {} cap {} co-sign {} withdrawal {}",
                        hex::encode(member),
                        policy.threshold,
                        policy.cap,
                        policy.cosign_above,
                        policy.withdrawal_threshold
                    ),
                );
            }
        }
        PolicyCommand::Check => {
            let (compiled, pinned) = (compiled(ctx)?, pinned(ctx)?);
            verify_rows(&compiled, &pinned)?;
            ensure!(
                mint_changes(ctx, &compiled)?.is_empty(),
                "mint settings differ from ring.toml"
            );
            verify_sources(ctx, &compiled, &pinned)?;
            line("policy", "matches ring.toml");
            line("generation", pinned.account.generation());
        }
        PolicyCommand::Set { yes } => set(ctx, yes)?,
    }
    Ok(())
}

pub(crate) fn pinned(ctx: &Context) -> Result<Pinned> {
    pinned_if_any(ctx)?.context(NO_POLICY)
}

/// `None` on an audit-only ring and before `init` pins the table.
pub(crate) fn pinned_if_any(ctx: &Context) -> Result<Option<Pinned>> {
    match ctx.block(ctx.ring.policy(ctx.chain()))? {
        Some(account) => Pinned::of(account),
        None => Ok(None),
    }
}

impl Pinned {
    /// `None` before the first policy write.
    pub(crate) fn of(account: Box<RingPolicy>) -> Result<Option<Self>> {
        if account.policy_hash().is_err() {
            return Ok(None);
        }
        let policy = PinnedPolicy::of(&account)?;
        Ok(Some(Self { account, policy }))
    }
}

/// The `StorageRegistry` a curator ring serves its lists from.
pub(crate) fn curator_records(ctx: &Context, curator: CustomRing) -> Result<Address> {
    let program = curator.program_id();
    let policy = ctx
        .block(curator.policy(ctx.chain()))?
        .with_context(|| format!("curator {program} has no ring policy"))?;
    Ok(policy.records)
}

/// One `SyncRoots` per distinct curator registry, a newly named curator has no mirror yet.
pub(crate) fn curator_syncs(
    ring: CustomRing,
    sources: &[(zolana_ring_policy::ListId, Address)],
) -> Vec<solana_instruction::Instruction> {
    let mut registries: Vec<Address> = sources.iter().map(|(_, registry)| *registry).collect();
    registries.sort();
    registries.dedup();
    registries
        .into_iter()
        .map(|registry| SyncRoots { ring, registry }.instruction())
        .collect()
}

/// Each shared list with its curator's records.
pub(crate) fn curator_sources(
    ctx: &Context,
    sources: &[(zolana_ring_policy::ListId, CustomRing)],
) -> Result<Vec<(zolana_ring_policy::ListId, Address)>> {
    sources
        .iter()
        .map(|&(list_id, curator)| Ok((list_id, curator_records(ctx, curator)?)))
        .collect()
}

/// The rows and their hash, what a source re-point never changes.
pub(crate) fn verify_rows(compiled: &CompiledPolicy, pinned: &Pinned) -> Result<()> {
    pinned
        .policy
        .matches(&compiled.rules)
        .context("the pinned table differs from ring.toml")
}

/// Every referenced list reads the registry ring.toml names.
pub(crate) fn verify_sources(
    ctx: &Context,
    compiled: &CompiledPolicy,
    pinned: &Pinned,
) -> Result<()> {
    let registry = |source: Option<ListRegistry>| match source {
        Some(ListRegistry::Own) => pinned.account.records,
        Some(ListRegistry::Curator(registry)) => registry,
        None => Default::default(),
    };
    for list_id in compiled.rules.referenced().iter() {
        let expected = match compiled.curator(list_id) {
            Some(curator) => ListRegistry::Curator(curator_records(ctx, curator)?),
            None => ListRegistry::Own,
        };
        let chain = pinned.account.registry_for(list_id);
        ensure!(
            chain == Some(expected),
            "the {} list reads registry {} on chain, ring.toml expects {}",
            list_id.name(),
            registry(chain),
            registry(Some(expected))
        );
    }
    Ok(())
}

pub(crate) fn print_pinned(pinned: &Pinned) {
    let account = &pinned.account;
    let (generation, slot) = (account.generation(), account.generation_slot());
    line("generation", format_args!("{generation} at slot {slot}"));
    line("hash", hex::encode(pinned.policy.policy_hash));
    let table = &pinned.policy.table;
    let rows = table_lines(table);
    if rows.is_empty() {
        line("rules", "none, an empty table");
    }
    rows.iter().for_each(Line::print);
    let referenced = table.referenced();
    if !referenced.is_empty() {
        ui::heading(icon::LISTS, "sources");
    }
    for list_id in referenced.iter() {
        let source = match account.registry_for(list_id) {
            Some(ListRegistry::Own) => format!("own records {}", account.records),
            Some(ListRegistry::Curator(registry)) => format!("curator registry {registry}"),
            None => "no source".to_owned(),
        };
        line(list_id.name(), source);
    }
}

fn compiled(ctx: &Context) -> Result<CompiledPolicy> {
    let audit_only = "ring.toml has no [policy] table, the ring is audit-only";
    let spec = ctx.config.policy.as_ref().context(audit_only)?;
    Ok(spec.compile(ctx.config.target)?)
}

fn set(ctx: &Context, yes: bool) -> Result<()> {
    let program = ctx.ring.program_id();
    let (compiled, current) = (compiled(ctx)?, pinned(ctx)?);
    let verified =
        verify_rows(&compiled, &current).and_then(|()| verify_sources(ctx, &compiled, &current));
    let mint_changes = mint_changes(ctx, &compiled)?;
    if verified.is_ok() && mint_changes.is_empty() {
        line("policy", "already present");
        return Ok(());
    }
    for (list_id, curator) in &compiled.shared_sources {
        check_curator(ctx, *curator, *list_id)?;
    }
    ui::heading(icon::PIN, &format!("re-pin the table of {program}"));
    print_diff(&current.policy.table, &compiled.rules);
    line("mint record updates", mint_changes.len());
    for (list_id, curator) in &compiled.shared_sources {
        let curator = curator.program_id();
        line(list_id.name(), format_args!("curator {curator}"));
    }
    ui::warn("proofs built against the old table are refused from now on");
    ctx.confirm(
        yes,
        "replace the pinned table?",
        format_args!("pass --yes to replace the table of {program}, proofs built against the old table are refused from now on"),
        format_args!("the table of {program} stays, the change was not confirmed"),
    )?;
    let authority = ctx.funded_authority()?;
    let shared_sources = curator_sources(ctx, &compiled.shared_sources)?;
    let replace = UpdatePolicy {
        ring: ctx.ring,
        authority: authority.pubkey(),
        update: PolicyUpdate::Rules(PolicyTable {
            rules: &compiled.rules,
            shared_sources: &shared_sources,
        }),
    }
    .instruction()?;
    let mut instructions = vec![replace];
    instructions.extend(curator_syncs(ctx.ring, &shared_sources));
    ctx.send(&[authority], &instructions)?;
    crate::records::write_mint_policies(ctx, &mint_changes)?;
    let (before, after) = (
        current.account.generation(),
        pinned(ctx)?.account.generation(),
    );
    line("policy", "replaced");
    line("generation", format_args!("{after} replaces {before}"));
    Ok(())
}

fn table_lines(table: &RuleTable) -> Vec<Line> {
    let lines: Vec<Line> = table
        .rules()
        .iter()
        .enumerate()
        .map(|(index, rule)| Line {
            label: format!("rule {}", index + 1),
            text: describe(rule),
        })
        .collect();
    lines
}

fn print_diff(old: &RuleTable, new: &RuleTable) {
    for (label, from, to) in [("removed", old, new), ("added", new, old)] {
        for rule in from
            .rules()
            .iter()
            .filter(|rule| !to.rules().contains(rule))
        {
            line(label, describe(rule));
        }
    }
}

impl Line {
    fn print(&self) {
        line(&self.label, &self.text);
    }
}

/// Replacing policy settings preserves the independent withdrawal co-sign threshold.
pub(crate) fn mint_changes(
    ctx: &Context,
    compiled: &CompiledPolicy,
) -> Result<std::collections::BTreeMap<[u8; 32], zolana_ring_policy::MintPolicy>> {
    let current = crate::records::mint_policies(ctx)?;
    let mut desired = compiled.mint_policies.clone();
    for (member, old) in &current {
        desired.entry(*member).or_default().withdrawal_threshold = old.withdrawal_threshold;
    }
    desired.retain(|member, policy| *policy != current.get(member).copied().unwrap_or_default());
    Ok(desired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_ring_policy::{ListId, Rule, Subject};
    #[test]
    fn table_lines_show_only_rules() {
        let table = RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .build();
        assert_eq!(table_lines(&table).len(), 1);
        assert!(table_lines(&RuleTable::empty()).is_empty());
    }
}
