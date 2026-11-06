//! Every ring circuit and its proving key, no verifying keys.
//!
//! A frame names its key by shape, and a key's widths fix its statement chains, its stream and its
//! record pools. A frame off the catalog has no key and `RingShapeUnkeyed` refuses it.
//!
//! Read after `program-libs/interface/src/codec/stream.rs`. Read before `program-libs/interface/src/proof/verification.rs`,
//! `programs/custom-ring/src/instructions/verification/verifier.rs`.

use spr_interface::{shape::MAX_TRANSACTION_ADDRESSES, N_PUBLIC_SLOTS};

use crate::{audit_stream::AuditKey, member_registry::APPLY_BATCH, transact::RingRail};

pub use crate::ring_keys::RING_KEYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingCircuit {
    /// Every rail, the statement's bits name it.
    Transfer {
        outputs: u8,
        /// The widest published input count.
        inputs: u8,
        withdrawals: u8,
        owners: u8,
        /// One evidence slot per input, the key also spends default-ring notes.
        entry: bool,
        /// A salted and a public record per owner fit.
        wide: bool,
    },
    ApplyRecords {
        writes: u8,
        mode: ApplyMode,
    },
    ApplyEnrollments {
        writes: u8,
    },
    RegisterKey,
    Merge,
}

/// Mirror `Key.Private` in `prover/ring/keys.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// No write needs a tracking row, the key compiles no row opening.
    Public,
    /// At least one private owner write, the key compiles a tracking row opening per write slot.
    Private,
}

/// One transfer key, mirror `Shapes` in `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferShape {
    pub outputs: u8,
    pub inputs: u8,
    pub withdrawals: u8,
    pub owners: u8,
    pub entry: bool,
    pub wide: bool,
    /// The most tracking rows one inline transaction on the key opens.
    pub tracking: u8,
    /// Excludes input and public slot assets.
    pub records: u8,
}

const fn narrow(
    outputs: u8,
    inputs: u8,
    withdrawals: u8,
    owners: u8,
    pools: [u8; 2],
) -> TransferShape {
    TransferShape {
        outputs,
        inputs,
        withdrawals,
        owners,
        entry: false,
        wide: false,
        tracking: pools[0],
        records: pools[1],
    }
}

const fn wide(
    outputs: u8,
    inputs: u8,
    withdrawals: u8,
    owners: u8,
    pools: [u8; 2],
) -> TransferShape {
    TransferShape {
        entry: false,
        wide: true,
        ..narrow(outputs, inputs, withdrawals, owners, pools)
    }
}

const fn entry(
    outputs: u8,
    inputs: u8,
    withdrawals: u8,
    owners: u8,
    pools: [u8; 2],
) -> TransferShape {
    TransferShape {
        entry: true,
        wide: true,
        ..narrow(outputs, inputs, withdrawals, owners, pools)
    }
}

/// Ascending outputs, a frame takes the first that holds its SPP width.
const NARROW_SHAPES: [TransferShape; 3] = [
    narrow(2, 24, 4, 4, [6, 12]),
    narrow(4, 24, 4, 4, [8, 16]),
    narrow(8, 16, 4, 4, [12, 24]),
];
/// The wide flag takes the first row holding the frame, the last only past 24 inputs.
const WIDE_SHAPES: [TransferShape; 2] =
    [wide(8, 24, 32, 13, [42, 88]), wide(2, 40, 4, 8, [11, 24])];
/// A frame takes the first row holding its width.
const ENTRY_SHAPES: [TransferShape; 3] = [
    entry(4, 8, 4, 8, [14, 32]),
    entry(8, 2, 4, 2, [14, 36]),
    entry(8, 5, 4, 4, [15, 38]),
];
const WIDE_ENTRY_SHAPE: TransferShape = entry(8, 8, 32, 8, [38, 80]);

pub const TRANSFER_SHAPES: [TransferShape; 9] = [
    NARROW_SHAPES[0],
    NARROW_SHAPES[1],
    NARROW_SHAPES[2],
    WIDE_SHAPES[0],
    WIDE_SHAPES[1],
    ENTRY_SHAPES[0],
    ENTRY_SHAPES[1],
    ENTRY_SHAPES[2],
    WIDE_ENTRY_SHAPE,
];

/// What names a frame's key, nothing else moves a recipient key's counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameKey {
    pub rail: RingRail,
    /// `n`, the frame's nullifier count.
    pub inputs: usize,
    pub outputs: usize,
    pub spends_default_ring: bool,
    pub wide: bool,
}

impl FrameKey {
    pub fn shape(self) -> Option<TransferShape> {
        let holds = |shape: &TransferShape| {
            self.outputs <= usize::from(shape.outputs) && self.inputs <= usize::from(shape.inputs)
        };
        // SPP's authority rail holds every input to the ring.
        let delegate = matches!(self.rail, RingRail::Delegate | RingRail::AnonymousDelegate);
        if delegate && self.spends_default_ring {
            return None;
        }
        match (self.spends_default_ring, self.wide) {
            (true, false) => ENTRY_SHAPES.into_iter().find(holds),
            (true, true) => Some(WIDE_ENTRY_SHAPE).filter(holds),
            (false, true) => WIDE_SHAPES.into_iter().find(holds),
            (false, false) => NARROW_SHAPES.into_iter().find(holds),
        }
    }
}

impl TransferShape {
    fn holds(self, spend: TransferSpend) -> bool {
        (1..=usize::from(self.inputs)).contains(&spend.inputs)
            && spend.legs <= usize::from(self.withdrawals)
            && spend.owners <= usize::from(self.owners)
            && self
                .circuit()
                .record_pools()
                .is_some_and(|pools| spend.pools.within(pools))
    }

    pub const fn audit_key(self) -> AuditKey {
        AuditKey {
            class: self.inputs as usize,
            entry: self.entry,
        }
    }

    /// A stream sealed under one row opens under the other, only an entry key's class moves its first key counter.
    #[must_use]
    pub const fn seals_like(self, other: Self) -> bool {
        self.audit_key().first_key_counter() == other.audit_key().first_key_counter()
    }

    /// The catalog row of `circuit`, `None` outside the transfer keys.
    #[must_use]
    pub fn of(circuit: RingCircuit) -> Option<Self> {
        TRANSFER_SHAPES
            .into_iter()
            .find(|shape| shape.circuit() == circuit)
    }

    const fn circuit(self) -> RingCircuit {
        RingCircuit::Transfer {
            outputs: self.outputs,
            inputs: self.inputs,
            withdrawals: self.withdrawals,
            owners: self.owners,
            entry: self.entry,
            wide: self.wide,
        }
    }
}

/// Addresses SPP takes beside its nullifier PDAs, zolana/docs/spec.md.
const SPP_ADDRESSES: usize = 4;
/// Ring program, ring, ring config, own, curator, tracking.
const RING_ADDRESSES: usize = 6;

/// The only spend input that moves a row's address cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowAuthorization {
    /// Every row signs in the owner run.
    Run,
    /// One row signs inside SPP's anonymous proof and spends ring notes only.
    InProof,
    /// One row hides, every withdrawal names one destination.
    Hidden,
}

impl RowAuthorization {
    /// Rows outside the owner run, each takes its nullifier PDA alone.
    pub const fn unsigned_rows(self) -> usize {
        match self {
            Self::Run => 0,
            Self::InProof | Self::Hidden => 1,
        }
    }
}

/// What takes a v1 transaction's addresses beside its owner signers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferAddresses {
    /// The shape's nullifier PDAs.
    pub n_inputs: usize,
    pub co_signers: usize,
    pub legs: usize,
}

impl TransferAddresses {
    /// The owner signers that fit, a co-signer takes its record too.
    #[must_use]
    pub const fn owner_signers(self) -> usize {
        MAX_TRANSACTION_ADDRESSES
            .saturating_sub(SPP_ADDRESSES + RING_ADDRESSES)
            .saturating_sub(self.n_inputs)
            .saturating_sub(self.co_signers.saturating_mul(2))
            .saturating_sub(self.legs)
    }

    /// The rows that fit, one bound for the catalog's pools and the SDK's refusal.
    #[must_use]
    pub const fn owner_rows(self, authorization: RowAuthorization) -> usize {
        self.owner_signers() + authorization.unsigned_rows()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferSpend {
    pub rail: RingRail,
    /// Published inputs, the spent notes.
    pub inputs: usize,
    pub outputs: usize,
    pub spends_default_ring: bool,
    /// Public withdrawal legs.
    pub legs: usize,
    /// Distinct live input owners, rows the key opens.
    pub owners: usize,
    /// Distinct records the spend opens in each pool, a salted read takes a row beside the public one.
    pub pools: RecordPools,
    /// The header's wide flag, `fitted` derives it from the spend.
    pub wide: bool,
}

impl TransferSpend {
    /// The wide flag follows the narrow key failing to hold the spend.
    #[must_use]
    pub fn fitted(self) -> Self {
        let narrow = FrameKey {
            wide: false,
            ..self.frame_key()
        }
        .shape();
        Self {
            wide: !narrow.is_some_and(|shape| shape.holds(self)),
            ..self
        }
    }

    const fn frame_key(self) -> FrameKey {
        FrameKey {
            rail: self.rail,
            inputs: self.inputs,
            outputs: self.outputs,
            spends_default_ring: self.spends_default_ring,
            wide: self.wide,
        }
    }
}

impl RingCircuit {
    /// The one transfer key serving the spend, `None` when the catalog keys none.
    pub fn transfer(spend: TransferSpend) -> Option<Self> {
        spend
            .frame_key()
            .shape()
            .filter(|shape| shape.holds(spend))
            .map(TransferShape::circuit)
    }

    pub const fn apply_records(pending: u64, mode: ApplyMode) -> Self {
        Self::ApplyRecords {
            writes: apply_width(pending),
            mode,
        }
    }

    pub const fn apply_enrollments(pending: u64) -> Self {
        Self::ApplyEnrollments {
            writes: apply_width(pending),
        }
    }
}

/// The narrowest apply key width holding `pending` writes up to `APPLY_BATCH`, the same for every apply circuit.
pub const fn apply_width(pending: u64) -> u8 {
    match pending {
        0..=1 => 1,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        _ => APPLY_BATCH as u8,
    }
}

/// A transfer key's record pool widths, mirror `recordCapacity` in `prover/circuits/policy/record_pool.go`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordPools {
    pub own: usize,
    pub curator: usize,
    pub tracking: usize,
}

impl RecordPools {
    const fn within(self, capacity: Self) -> bool {
        self.own <= capacity.own
            && self.curator <= capacity.curator
            && self.tracking <= capacity.tracking
    }
}

impl RingCircuit {
    /// The withdrawal slots of a transfer key, `None` outside the transfer keys.
    pub fn withdrawals(self) -> Option<u8> {
        match self {
            Self::Transfer { withdrawals, .. } => Some(withdrawals),
            _ => None,
        }
    }

    /// The owner rows of a transfer key, `None` outside the transfer keys.
    pub fn owners(self) -> Option<u8> {
        match self {
            Self::Transfer { owners, .. } => Some(owners),
            _ => None,
        }
    }

    /// Each pool takes as many subjects as records, `None` outside the transfer keys.
    pub fn record_pools(self) -> Option<RecordPools> {
        let shape = TransferShape::of(self)?;
        // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
        let withdrawal_assets = usize::from(shape.withdrawals).min(N_PUBLIC_SLOTS);
        let records = usize::from(shape.records) + usize::from(shape.inputs);
        Some(RecordPools {
            own: records + withdrawal_assets.max(N_PUBLIC_SLOTS),
            curator: records + withdrawal_assets,
            tracking: usize::from(shape.tracking),
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

    /// The release lock section, `custom-ring-apply-records-2` reads `apply_records_2_key`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_carry_one_key_suffix() {
        let apply = RingKey {
            circuit: RingCircuit::ApplyRecords {
                writes: 2,
                mode: ApplyMode::Public,
            },
            name: "custom-ring-apply-records-2",
        };
        let register = RingKey {
            circuit: RingCircuit::RegisterKey,
            name: "custom-ring-register-key",
        };
        assert_eq!(apply.file_name(), "custom_ring_apply_records_2.key");
        assert_eq!(apply.section(), "apply_records_2_key");
        assert_eq!(apply.asset("v6"), "custom-ring-apply-records-2-key-v6.key");
        assert_eq!(register.section(), "register_key");
        assert_eq!(register.asset("v6"), "custom-ring-register-key-v6.key");
    }

    fn spend(
        rail: RingRail,
        outputs: usize,
        spends_default_ring: bool,
        wide: bool,
    ) -> TransferSpend {
        TransferSpend {
            rail,
            inputs: 1,
            outputs,
            spends_default_ring,
            legs: 0,
            owners: 1,
            pools: RecordPools::default(),
            wide,
        }
    }

    const TWO: RingCircuit = NARROW_SHAPES[0].circuit();
    const FOUR: RingCircuit = NARROW_SHAPES[1].circuit();
    const EIGHT: RingCircuit = NARROW_SHAPES[2].circuit();
    const WIDE: RingCircuit = WIDE_SHAPES[0].circuit();
    const WIDE_INPUTS: RingCircuit = WIDE_SHAPES[1].circuit();
    const ENTRY_FOUR: RingCircuit = ENTRY_SHAPES[0].circuit();
    const ENTRY_EIGHT_TWO: RingCircuit = ENTRY_SHAPES[1].circuit();
    const ENTRY_EIGHT_FIVE: RingCircuit = ENTRY_SHAPES[2].circuit();
    const WIDE_ENTRY: RingCircuit = WIDE_ENTRY_SHAPE.circuit();

    #[test]
    fn every_rail_shares_the_key_of_its_output_width() {
        for rail in [
            RingRail::Confidential,
            RingRail::Anonymous,
            RingRail::Delegate,
            RingRail::AnonymousDelegate,
        ] {
            let key = |outputs| RingCircuit::transfer(spend(rail, outputs, false, false));
            assert_eq!(key(2), Some(TWO));
            assert_eq!(key(4), Some(FOUR));
            assert_eq!(key(8), Some(EIGHT));
            assert_eq!(key(16), None);
        }
    }

    #[test]
    fn the_wide_flag_names_the_wide_key_of_the_width() {
        let key =
            |outputs| RingCircuit::transfer(spend(RingRail::Confidential, outputs, false, true));
        assert_eq!(key(2), Some(WIDE));
        assert_eq!(key(8), Some(WIDE));
        assert_eq!(key(16), None);
    }

    #[test]
    fn the_published_inputs_route_a_two_output_wide_spend() {
        let wide_spend = |inputs, legs, owners| {
            RingCircuit::transfer(TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, 2, false, true)
            })
        };
        assert_eq!(wide_spend(24, 0, 1), Some(WIDE));
        assert_eq!(wide_spend(25, 0, 1), Some(WIDE_INPUTS));
        assert_eq!(wide_spend(40, 4, 8), Some(WIDE_INPUTS));
        assert_eq!(wide_spend(41, 0, 1), None);
        assert_eq!(wide_spend(25, 5, 1), None);
        assert_eq!(wide_spend(25, 0, 9), None);
    }

    #[test]
    fn a_narrow_spend_past_24_inputs_fits_the_wide_flag() {
        let fitted = |inputs| {
            TransferSpend {
                inputs,
                ..spend(RingRail::Confidential, 2, false, false)
            }
            .fitted()
        };
        assert!(!fitted(24).wide);
        assert_eq!(RingCircuit::transfer(fitted(24)), Some(TWO));
        assert!(fitted(25).wide);
        assert_eq!(RingCircuit::transfer(fitted(25)), Some(WIDE_INPUTS));
    }

    #[test]
    fn an_entry_past_the_small_keys_fits_the_wide_entry_key() {
        let entered = |inputs, outputs, legs, owners| {
            RingCircuit::transfer(
                TransferSpend {
                    inputs,
                    legs,
                    owners,
                    ..spend(RingRail::Anonymous, outputs, true, false)
                }
                .fitted(),
            )
        };
        assert_eq!(entered(8, 2, 4, 8), Some(ENTRY_FOUR));
        assert_eq!(entered(2, 8, 4, 2), Some(ENTRY_EIGHT_TWO));
        assert_eq!(entered(1, 2, 5, 1), Some(WIDE_ENTRY));
        assert_eq!(entered(8, 2, 32, 8), Some(WIDE_ENTRY));
        // Four and eight output entries past four legs fit one inline transaction.
        assert_eq!(entered(2, 4, 32, 2), Some(WIDE_ENTRY));
        assert_eq!(entered(1, 8, 27, 1), Some(WIDE_ENTRY));
        assert_eq!(entered(3, 8, 21, 3), Some(WIDE_ENTRY));
        assert_eq!(entered(9, 2, 0, 1), None);
        assert_eq!(entered(1, 2, 33, 1), None);
        assert_eq!(entered(8, 2, 5, 9), None);
    }

    #[test]
    fn a_spend_past_its_key_is_unkeyed() {
        let past = |inputs, legs, owners, wide| {
            RingCircuit::transfer(TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, 2, false, wide)
            })
        };
        assert_eq!(past(24, 4, 4, false), Some(TWO));
        assert_eq!(past(0, 0, 1, false), None);
        assert_eq!(past(25, 0, 1, false), None);
        assert_eq!(past(1, 5, 1, false), None);
        assert_eq!(past(1, 0, 5, false), None);
        assert_eq!(past(1, 5, 5, true), Some(WIDE));
        assert_eq!(past(1, 33, 1, true), None);
        assert_eq!(past(1, 0, 14, true), None);
    }

    #[test]
    fn a_spend_past_the_narrow_key_fits_the_wide_flag() {
        let fitted = |outputs, inputs, legs, owners| {
            TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, outputs, false, false)
            }
            .fitted()
            .wide
        };
        assert!(!fitted(2, 24, 4, 4));
        assert!(fitted(2, 1, 5, 1));
        assert!(fitted(2, 5, 0, 5));
        assert!(fitted(8, 17, 0, 1));
    }

    #[test]
    fn an_entry_takes_the_first_entry_key_holding_its_width() {
        let entered = |rail, outputs, inputs, owners| {
            RingCircuit::transfer(TransferSpend {
                inputs,
                owners,
                ..spend(rail, outputs, true, false)
            })
        };
        assert_eq!(entered(RingRail::Confidential, 2, 8, 8), Some(ENTRY_FOUR));
        assert_eq!(entered(RingRail::Anonymous, 4, 1, 1), Some(ENTRY_FOUR));
        assert_eq!(entered(RingRail::Anonymous, 8, 2, 2), Some(ENTRY_EIGHT_TWO));
        assert_eq!(
            entered(RingRail::Anonymous, 8, 3, 1),
            Some(ENTRY_EIGHT_FIVE)
        );
        assert_eq!(
            entered(RingRail::Confidential, 8, 4, 4),
            Some(ENTRY_EIGHT_FIVE)
        );
        assert_eq!(
            entered(RingRail::Confidential, 8, 5, 3),
            Some(ENTRY_EIGHT_FIVE)
        );
        assert_eq!(entered(RingRail::Anonymous, 8, 6, 1), None);
        assert_eq!(entered(RingRail::Anonymous, 8, 9, 1), None);
        assert_eq!(entered(RingRail::Delegate, 2, 1, 1), None);
        assert_eq!(entered(RingRail::AnonymousDelegate, 2, 1, 1), None);
    }

    #[test]
    fn the_address_bound_leaves_room_for_each_key_of_the_catalog() {
        let bound = |n_inputs, co_signers, legs| {
            TransferAddresses {
                n_inputs,
                co_signers,
                legs,
            }
            .owner_signers()
        };
        assert_eq!(bound(24, 0, 0), 30);
        assert_eq!(bound(32, 0, 0), 22);
        assert_eq!(bound(24, 5, 4), 16);
        assert_eq!(bound(64, 5, 32), 0);
        for shape in TRANSFER_SHAPES {
            let owners = usize::from(shape.owners);
            assert!(owners <= bound(owners, 0, 0));
        }
    }

    #[test]
    fn oversized_account_counts_leave_no_owner_capacity() {
        let base = TransferAddresses::default();
        for accounts in [
            TransferAddresses {
                n_inputs: usize::MAX,
                ..base
            },
            TransferAddresses {
                co_signers: usize::MAX,
                ..base
            },
            TransferAddresses {
                legs: usize::MAX,
                ..base
            },
        ] {
            assert_eq!(accounts.owner_signers(), 0);
        }
    }

    #[test]
    fn the_pools_reserve_distinct_input_assets() {
        let pools = |circuit: RingCircuit| {
            let pools = circuit.record_pools().unwrap();
            (pools.own, pools.curator, pools.tracking)
        };
        assert_eq!(pools(TWO), (39, 39, 6));
        assert_eq!(pools(FOUR), (43, 43, 8));
        assert_eq!(pools(EIGHT), (43, 43, 12));
        assert_eq!(pools(WIDE), (115, 115, 42));
        assert_eq!(pools(WIDE_INPUTS), (67, 67, 11));
        assert_eq!(pools(ENTRY_FOUR), (43, 43, 14));
        assert_eq!(pools(ENTRY_EIGHT_TWO), (41, 41, 14));
        assert_eq!(pools(ENTRY_EIGHT_FIVE), (46, 46, 15));
        assert_eq!(pools(WIDE_ENTRY), (91, 91, 38));
    }

    #[test]
    fn a_spend_past_a_narrow_keys_pools_moves_to_the_wide_key() {
        let fitted = |outputs, pools| {
            RingCircuit::transfer(
                TransferSpend {
                    pools,
                    ..spend(RingRail::Confidential, outputs, false, false)
                }
                .fitted(),
            )
        };
        let tracked = RecordPools {
            tracking: 7,
            ..RecordPools::default()
        };
        assert_eq!(fitted(2, tracked), Some(WIDE));
        let opened = |own| RecordPools {
            own,
            ..RecordPools::default()
        };
        let capacity = TWO.record_pools().unwrap().own;
        assert_eq!(fitted(2, opened(capacity)), Some(TWO));
        assert_eq!(fitted(2, opened(capacity + 1)), Some(WIDE));
        assert_eq!(fitted(2, RecordPools::default()), Some(TWO));
        let past_wide = RecordPools {
            tracking: 43,
            ..RecordPools::default()
        };
        assert_eq!(fitted(8, past_wide), None);
    }

    #[test]
    fn forty_distinct_input_assets_fit_the_largest_input_key() {
        let inputs = 40;
        let owner_subjects = 3;
        let candidate = TransferSpend {
            inputs,
            pools: RecordPools {
                own: inputs + owner_subjects,
                curator: inputs + owner_subjects,
                tracking: owner_subjects,
            },
            ..spend(RingRail::Confidential, 2, false, false)
        };
        assert_eq!(RingCircuit::transfer(candidate.fitted()), Some(WIDE_INPUTS));
        let limit = WIDE_INPUTS.record_pools().unwrap().own;
        assert_eq!(
            RingCircuit::transfer(TransferSpend {
                pools: RecordPools {
                    own: limit + 1,
                    ..candidate.pools
                },
                ..candidate.fitted()
            }),
            None
        );
    }

    #[test]
    fn the_payout_widths_have_no_key() {
        for spends_default_ring in [false, true] {
            for wide in [false, true] {
                let key = FrameKey {
                    rail: RingRail::Confidential,
                    inputs: 1,
                    outputs: 16,
                    spends_default_ring,
                    wide,
                };
                assert_eq!(key.shape(), None, "{key:?}");
            }
        }
    }

    #[test]
    fn ordinary_seals_keep_key_positions_across_input_and_output_capacities() {
        for (smaller, larger) in [
            (NARROW_SHAPES[0], WIDE_SHAPES[1]),
            (NARROW_SHAPES[0], WIDE_SHAPES[0]),
            (NARROW_SHAPES[2], WIDE_SHAPES[0]),
        ] {
            assert!(smaller.seals_like(larger));
        }
    }

    #[test]
    fn entry_seals_bind_input_capacity() {
        assert!(!ENTRY_SHAPES[1].seals_like(ENTRY_SHAPES[2]));
    }
}
