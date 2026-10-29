#[path = "records/apply_records.rs"]
mod apply_records;
#[path = "records/authority_write_records.rs"]
mod authority_write_records;
#[path = "configuration/setup/create_config.rs"]
mod create_config;
#[path = "configuration/setup/create_member_registry.rs"]
mod create_member_registry;
#[path = "configuration/setup/create_policy.rs"]
mod create_policy;
#[path = "settlement/deposit_audit.rs"]
mod deposit_audit;
#[path = "settlement/forward.rs"]
mod forward;
#[path = "configuration/setup/init_spp_ring_config.rs"]
mod init_spp_ring_config;
#[path = "settlement/insert_fee.rs"]
mod insert_fee;
#[path = "runtime/instruction_runtime.rs"]
mod instruction_runtime;
#[path = "accounts/loader.rs"]
mod loader;
#[path = "settlement/merge_disclosure.rs"]
mod merge_disclosure;
#[path = "verification/policy_binding.rs"]
mod policy_binding;
#[path = "verification/public_legs.rs"]
mod public_legs;
#[path = "configuration/access/read_access.rs"]
mod read_access;
#[path = "records/register_key.rs"]
mod register_key;
#[path = "configuration/access/set_authority.rs"]
mod set_authority;
#[path = "configuration/access/set_cosigner.rs"]
mod set_cosigner;
#[path = "configuration/access/set_delegate.rs"]
mod set_delegate;
#[path = "configuration/policy/set_insert_fee.rs"]
mod set_insert_fee;
#[path = "configuration/access/set_paused.rs"]
mod set_paused;
#[path = "configuration/policy/set_policy_rules.rs"]
mod set_policy_rules;
#[path = "configuration/policy/set_policy_source.rs"]
mod set_policy_source;
mod transact;
#[path = "records/sync_roots.rs"]
mod sync_roots;
#[path = "verification/verifier.rs"]
mod verifier;
#[path = "records/write_records.rs"]
mod write_records;

pub(crate) use apply_records::process_apply_records_ix;
pub(crate) use authority_write_records::process_authority_write_records_ix;
pub(crate) use create_config::process_create_config_ix;
pub(crate) use create_member_registry::process_create_member_registry_ix;
pub(crate) use create_policy::process_create_policy_ix;
pub(crate) use forward::{process_audited_deposit_ix, process_merge_ix};
pub(crate) use init_spp_ring_config::process_init_spp_ring_config_ix;
pub(crate) use read_access::{process_grant_read_access_ix, process_revoke_read_access_ix};
pub(crate) use register_key::process_register_key_ix;
pub(crate) use set_authority::process_set_authority_ix;
pub(crate) use set_cosigner::{process_clear_cosigner_ix, process_set_cosigner_ix};
pub(crate) use set_delegate::process_set_delegate_ix;
pub(crate) use set_insert_fee::process_set_insert_fee_ix;
pub(crate) use set_paused::process_set_paused_ix;
pub(crate) use set_policy_rules::process_set_policy_rules_ix;
pub(crate) use set_policy_source::process_set_policy_source_ix;
pub(crate) use sync_roots::process_sync_roots_ix;
pub(crate) use transact::process_transact_ix;
pub(crate) use write_records::process_write_records_ix;
