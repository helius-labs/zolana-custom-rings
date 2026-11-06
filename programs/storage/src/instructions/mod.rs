//! One processor per instruction tag of the Storage program.
//!
//! Read after `programs/storage/src/lib.rs`. Read before `programs/storage/src/instructions/update.rs`,
//! `programs/storage/src/instructions/enroll.rs`, `programs/storage/src/instructions/apply_enrollments.rs`.

mod apply_enrollments;
mod enroll;
mod initialize;
mod initialize_tracking;
mod owner_grant;
mod update;
mod update_authority;

pub use apply_enrollments::process_apply_enrollments_ix;
pub use enroll::process_enroll_ix;
pub use initialize::process_initialize_ix;
pub use initialize_tracking::process_initialize_tracking_ix;
pub use owner_grant::process_owner_grant_ix;
pub use update::process_update_ix;
pub use update_authority::process_update_authority_ix;
