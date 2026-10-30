#[path = "settlement/deposit_audit.rs"]
mod deposit_audit;
#[path = "settlement/forward.rs"]
mod forward;
#[path = "configuration/setup/initialize.rs"]
mod initialize;
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
#[path = "configuration/access/set_cosigner.rs"]
mod set_cosigner;
#[path = "configuration/access/set_delegate.rs"]
mod set_delegate;
#[path = "configuration/access/set_paused.rs"]
mod set_paused;
mod transfer;
#[path = "configuration/access/update_authority.rs"]
mod update_authority;
#[path = "configuration/policy/update_policy.rs"]
mod update_policy;
#[path = "verification/verifier.rs"]
mod verifier;

pub(crate) use forward::{process_deposit_ix, process_merge_ix};
pub(crate) use initialize::process_initialize_ix;
pub(crate) use set_cosigner::{process_clear_cosigner_ix, process_set_cosigner_ix};
pub(crate) use set_delegate::process_set_delegate_ix;
pub(crate) use set_paused::process_set_paused_ix;
pub(crate) use transfer::process_transfer_ix;
pub(crate) use update_authority::process_update_authority_ix;
pub(crate) use update_policy::process_update_policy_ix;
