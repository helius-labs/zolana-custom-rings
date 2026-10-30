#[path = "state/account.rs"]
mod account;
#[path = "validation/limits.rs"]
mod limits;
#[path = "operations/merge.rs"]
mod merge;
#[path = "operations/register_key.rs"]
mod register_key;
pub(crate) mod support;

/// A table every fixture member satisfies on the allow list.
pub(crate) fn pipeline_rules() -> zolana_ring_policy::RuleTable {
    use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};
    RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build()
}
