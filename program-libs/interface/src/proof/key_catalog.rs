//! Every ring circuit and its proving key, no verifying keys.
use spr_interface::N_PUBLIC_SLOTS;

use crate::{
    disclosure::{AnonymousAuditKey, DisclosureLayout},
    member_registry::APPLY_BATCH,
    transact::RingRail,
};

pub use crate::ring_keys::RING_KEYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingCircuit {
    DeliveredAudit {
        outputs: u8,
    },
    AnonymousAudit {
        class: u8,
        outputs: u8,
    },
    /// Opens every spent UTXO, the key of a transfer spending a default-ring note.
    AnonymousEntryAudit {
        class: u8,
        outputs: u8,
    },
    /// A statement bit reads the sender.
    MemberPolicy {
        withdrawals: u8,
        own_only: bool,
        outputs: u8,
    },
    DelegatePolicy {
        own_only: bool,
        inputs: u8,
        outputs: u8,
    },
    ApplyRecords {
        writes: u8,
    },
    RegisterKey,
    WithdrawalExemption,
    Deposit {
        capacity: u8,
    },
    AnonymousMerge {
        width: u8,
    },
}

impl RingCircuit {
    pub const fn audit(layout: DisclosureLayout, n_out: u8) -> Self {
        match layout {
            DisclosureLayout::Delivered(_) => Self::DeliveredAudit { outputs: n_out },
            DisclosureLayout::Anonymous(layout) => {
                let class = layout.key.class() as u8;
                match layout.key {
                    AnonymousAuditKey::Commitment { .. } => Self::AnonymousAudit {
                        class,
                        outputs: n_out,
                    },
                    AnonymousAuditKey::Entry => Self::AnonymousEntryAudit {
                        class,
                        outputs: n_out,
                    },
                }
            }
        }
    }

    pub const fn policy(
        rail: RingRail,
        n_in: u8,
        n_out: u8,
        withdrawals: u8,
        own_only: bool,
    ) -> Self {
        match rail {
            RingRail::Confidential | RingRail::Anonymous => Self::MemberPolicy {
                outputs: n_out,
                withdrawals: withdrawal_capacity(withdrawals),
                own_only,
            },
            RingRail::Delegate => Self::DelegatePolicy {
                own_only,
                inputs: n_in,
                outputs: n_out,
            },
        }
    }

    pub const fn deposit(count: u8) -> Self {
        Self::Deposit {
            capacity: match count {
                0..=1 => 1,
                2 => 2,
                3..=4 => 4,
                _ => 8,
            },
        }
    }

    pub const fn apply_records(pending: u64) -> Self {
        Self::ApplyRecords {
            writes: match pending {
                0..=1 => 1,
                2 => 2,
                3..=4 => 4,
                5..=8 => 8,
                _ => APPLY_BATCH as u8,
            },
        }
    }
}

/// A policy key's record pool widths, mirror `recordCapacity` in `prover/circuits/policy/pooled_policy.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPools {
    pub own: usize,
    /// Zero without a curator registry.
    pub curator: usize,
}

struct PolicyShape {
    outputs: usize,
    withdrawals: usize,
    public_assets: usize,
    own_only: bool,
}

impl RingCircuit {
    /// Each pool takes as many subjects as records, `None` outside the policy keys.
    pub fn record_pools(self) -> Option<RecordPools> {
        let shape = match self {
            Self::MemberPolicy {
                outputs,
                withdrawals,
                own_only,
            } => PolicyShape {
                outputs: outputs.into(),
                withdrawals: withdrawals.into(),
                public_assets: N_PUBLIC_SLOTS,
                own_only,
            },
            Self::DelegatePolicy {
                outputs, own_only, ..
            } => PolicyShape {
                outputs: outputs.into(),
                withdrawals: 0,
                public_assets: 0,
                own_only,
            },
            _ => return None,
        };
        // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
        let withdrawal_assets = shape.withdrawals.min(N_PUBLIC_SLOTS);
        let distinct = 1 + 2 * shape.outputs + shape.withdrawals;
        Some(RecordPools {
            own: distinct + withdrawal_assets.max(shape.public_assets),
            curator: if shape.own_only {
                0
            } else {
                distinct + withdrawal_assets
            },
        })
    }
}

/// `name` is the prover's circuit name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingKey {
    pub circuit: RingCircuit,
    pub name: &'static str,
}

impl RingKey {
    pub fn file_name(self) -> String {
        format!("{}.key", self.name.replace('-', "_"))
    }

    /// The release lock section, `custom-ring-audit-delivered-2` reads `audit_delivered_2_key`.
    pub fn section(self) -> String {
        let stem = self.name.strip_prefix(NAME_PREFIX).unwrap_or(self.name);
        key_suffixed(&stem.replace('-', "_"), "_")
    }

    pub fn asset(self, tag: &str) -> String {
        format!("{}-{tag}.key", key_suffixed(self.name, "-"))
    }
}

const NAME_PREFIX: &str = "custom-ring-";

/// One `key` suffix, a name that already ends in key takes none.
fn key_suffixed(name: &str, separator: &str) -> String {
    match name.ends_with("key") {
        true => name.to_owned(),
        false => format!("{name}{separator}key"),
    }
}

/// Smallest compiled capacity covering the public withdrawal count.
pub const fn withdrawal_capacity(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        9..=16 => 16,
        _ => 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_carry_one_key_suffix() {
        let delivered = RingKey {
            circuit: RingCircuit::DeliveredAudit { outputs: 2 },
            name: "custom-ring-audit-delivered-2",
        };
        let register = RingKey {
            circuit: RingCircuit::RegisterKey,
            name: "custom-ring-register-key",
        };
        assert_eq!(delivered.file_name(), "custom_ring_audit_delivered_2.key");
        assert_eq!(delivered.section(), "audit_delivered_2_key");
        assert_eq!(
            delivered.asset("v5"),
            "custom-ring-audit-delivered-2-key-v5.key"
        );
        assert_eq!(register.section(), "register_key");
        assert_eq!(register.asset("v5"), "custom-ring-register-key-v5.key");
    }
}
