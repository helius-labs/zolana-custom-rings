//! Ring member lists, one bit each in a member registry record, and the rule table over them.
//!
//! SPP holds no list. A ring's rules read one bit per list from its registries, and the semantics
//! live here for every side. The program links the crate for the table hash and its validation, the
//! SDKs also for refusals ahead of a proof.
//!
//! Read after `docs/design/records-and-roots.md`. Read before `program-libs/policy/src/list.rs`, `program-libs/policy/src/rule_table/mod.rs`.

mod approval_totals;
mod asset_limits;
mod list;
mod member;
mod mint;
mod quantities;
mod rule_table;
mod rules;

pub use approval_totals::{ApprovalTotals, OutputTotals, PublicTotals, APPROVAL_TOTALS_DOMAIN};
pub use asset_limits::{AssetLimits, AssetLimitsError};
pub use list::{ListChange, ListId, ListSet, ListWrite, ListWriteError, Writer};
pub use member::{Member, MemberError, WALLET_GRANT_DOMAIN};
pub use mint::MintPolicy;
pub use quantities::{
    owner_debits, ApprovalInputs, ApprovalMask, DebitInput, DebitOutput, DebitTransfer, GuardScope,
    OwnerDebit, PublicGross,
};
pub use rule_table::{
    EncodedRuleTable, Guard, Mode, OutflowLimit, PolicySource, PolicyTableError, Rule, RuleSource,
    RuleTable, RuleTableBuilder, RuleTableError, SourceMap, SourceMapError, Subject, TableParts,
    MAX_RULES, MAX_SOURCES, POLICY_TABLE_DOMAIN, POLICY_TABLE_FIELDS,
};
pub use rules::{
    OutputSubjects, PaymentSubjects, RecordLists, RuleRefusal, TransferSubject, TransferSubjects,
};

/// The ring id field a UTXO inside the ring carries.
pub fn ring_id_field(program_id: &[u8; 32]) -> Result<[u8; 32], spr_hasher::HasherError> {
    spr_hasher::primitives::hash_bytes(program_id)
}

/// The source slot field of a curator's member registry, an address can exceed the modulus.
pub fn registry_field(registry: &[u8; 32]) -> Result<[u8; 32], spr_hasher::HasherError> {
    spr_hasher::primitives::hash_bytes(registry)
}

pub(crate) fn field_u8(value: u8) -> [u8; 32] {
    spr_hasher::primitives::right_align(&[value])
}
