//! Each owner's guard, debit and charged outflow per asset, mirror `prover/circuits/policy/outflow.go` and `rules.go`.
//!
//! The circuit computes these values. A wallet computes the same ones for its approval bits ahead of
//! a proof, and the program derives no threshold.
//!
//! Read after `program-libs/policy/src/asset_limits.rs`. Read before `program-libs/policy/src/approval_totals.rs`, `prover/circuits/policy/outflow.go`.

use crate::MintPolicy;

/// A live input, keyed by owner identity so one owner's notes aggregate across nullifier keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebitInput {
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

/// A live output, an exit leaves the ring even when it pays its own owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebitOutput {
    pub ring: bool,
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

/// A public slot's statement-bound gross withdrawal, no deposit subtracted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicGross {
    pub asset: [u8; 32],
    pub gross: u128,
}

/// One row's quantities of one asset, the sums pass a u64 and `held = debit + kept`.
/// `debit` is the owner's net outflow, `charged_outflow` adds the charge the cap reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerDebit {
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub debit: u128,
    pub kept: u128,
    pub charge: u128,
    pub charged_outflow: u128,
}

/// One transfer's parties, the assets are its output and public assets.
#[derive(Clone, Copy, Debug)]
pub struct DebitTransfer<'a> {
    pub senders: &'a [[u8; 32]],
    pub assets: &'a [[u8; 32]],
    pub inputs: &'a [DebitInput],
    pub outputs: &'a [DebitOutput],
    pub public_gross: &'a [PublicGross],
}

/// Nonzero charged outflow rows by ascending owner then assets order, no caller input selects a share.
#[must_use]
pub fn owner_debits(transfer: &DebitTransfer<'_>) -> Vec<OwnerDebit> {
    let owners = ordered_owners(transfer);
    let mut flows: Vec<OwnerDebit> = Vec::new();
    for (position, asset) in transfer.assets.iter().enumerate() {
        if !transfer.assets[..position].contains(asset) {
            flows.extend(asset_flows(transfer, &owners, asset));
        }
    }
    flows.retain(|flow| flow.charged_outflow != 0);
    flows.sort_by_key(|flow| flow.owner);
    flows
}

pub(crate) fn ordered_owners(transfer: &DebitTransfer<'_>) -> Vec<[u8; 32]> {
    let mut owners: Vec<[u8; 32]> = transfer
        .senders
        .iter()
        .filter(|owner| **owner != [0; 32])
        .copied()
        .collect();
    // Big-endian bytes order as the field integers the circuit's rows ascend by.
    owners.sort_unstable();
    owners.dedup();
    owners
}

pub(crate) fn asset_flows(
    transfer: &DebitTransfer<'_>,
    owners: &[[u8; 32]],
    asset: &[u8; 32],
) -> Vec<OwnerDebit> {
    let mut rows: Vec<OwnerDebit> = owners
        .iter()
        .map(|owner| {
            let held: u128 = transfer
                .inputs
                .iter()
                .filter(|input| input.owner == *owner && input.asset == *asset)
                .map(|input| u128::from(input.amount))
                .sum();
            let returned: u128 = transfer
                .outputs
                .iter()
                .filter(|output| output.ring && output.owner == *owner && output.asset == *asset)
                .map(|output| u128::from(output.amount))
                .sum();
            let debit = held.saturating_sub(returned);
            OwnerDebit {
                owner: *owner,
                asset: *asset,
                debit,
                kept: held - debit,
                charge: 0,
                charged_outflow: debit,
            }
        })
        .collect();
    let exits: u128 = transfer
        .outputs
        .iter()
        .filter(|output| !output.ring && output.asset == *asset)
        .map(|output| u128::from(output.amount))
        .sum();
    let gross: u128 = transfer
        .public_gross
        .iter()
        .filter(|public| public.asset == *asset)
        .map(|public| public.gross)
        .sum();
    let leaving = exits + gross;
    let sum_debit: u128 = rows.iter().map(|row| row.debit).sum();
    let sum_kept: u128 = rows.iter().map(|row| row.kept).sum();
    let displaced = leaving.min(sum_debit + sum_kept) - leaving.min(sum_debit);
    if displaced == 0 {
        return rows;
    }
    let (mut running, mut previous) = (0, 0);
    for row in &mut rows {
        running += row.kept;
        let share = mul_div_floor(displaced, running, sum_kept);
        row.charge = share - previous;
        row.charged_outflow = row.debit + row.charge;
        previous = share;
    }
    rows
}

/// `a * b / divisor` rounded down, the product can pass a u128 and `divisor` stays below 2^126.
fn mul_div_floor(a: u128, b: u128, divisor: u128) -> u128 {
    let (whole, part) = (a / divisor, a % divisor);
    let (mut quotient, mut remainder) = (0u128, 0u128);
    for bit in (0..u128::BITS - b.leading_zeros()).rev() {
        quotient <<= 1;
        remainder <<= 1;
        if (b >> bit) & 1 == 1 {
            quotient += whole;
            remainder += part;
        }
        quotient += remainder / divisor;
        remainder %= divisor;
    }
    quotient
}

/// Compared with amount guards, `receipt + exit + paid`.
#[derive(Clone, Copy, Debug)]
pub struct GuardScope<'a> {
    /// Default-ring notes stay out, entry funding is a receipt.
    pub ring_inputs: &'a [DebitInput],
    /// Outputs and withdrawals, `ring` clear on an exit or a withdrawal.
    pub payments: &'a [DebitOutput],
}

impl GuardScope<'_> {
    #[must_use]
    pub fn owner(&self, owner: &[u8; 32], asset: &[u8; 32]) -> u128 {
        let total = |ring: bool| -> u128 {
            self.payments
                .iter()
                .filter(|pay| pay.ring == ring && pay.owner == *owner && pay.asset == *asset)
                .map(|pay| u128::from(pay.amount))
                .sum()
        };
        let spent: u128 = self
            .ring_inputs
            .iter()
            .filter(|input| input.owner == *owner && input.asset == *asset)
            .map(|input| u128::from(input.amount))
            .sum();
        total(true).saturating_sub(spent) + total(false)
    }

    /// Over the asset's distinct owners.
    #[must_use]
    pub fn asset(&self, asset: &[u8; 32]) -> u128 {
        let of_asset: Vec<&DebitOutput> = self
            .payments
            .iter()
            .filter(|pay| pay.asset == *asset)
            .collect();
        of_asset
            .iter()
            .enumerate()
            .filter(|(position, pay)| {
                !of_asset[..*position]
                    .iter()
                    .any(|seen| seen.owner == pay.owner)
            })
            .map(|(_, pay)| self.owner(&pay.owner, asset))
            .sum()
    }
}

/// The statement's proven approval bits, the program derives no threshold itself.
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApprovalMask(u8);

impl ApprovalMask {
    pub const EMPTY: Self = Self(0);
    /// Some `charged_outflow` passes the asset's `cosign_above`.
    pub const OUTFLOW: Self = Self(1);
    /// Some public gross passes the asset's `withdrawal_threshold`.
    pub const WITHDRAWAL: Self = Self(2);

    /// `None` when a bit no class names is set.
    pub const fn new(bits: u8) -> Option<Self> {
        if bits & !(Self::OUTFLOW.0 | Self::WITHDRAWAL.0) != 0 {
            return None;
        }
        Some(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ApprovalInputs<'a> {
    pub flows: &'a [OwnerDebit],
    pub public_gross: &'a [PublicGross],
}

impl ApprovalInputs<'_> {
    /// A zero threshold and an asset with no record both mean no threshold.
    pub fn mask(&self, policy_of: impl Fn(&[u8; 32]) -> MintPolicy) -> ApprovalMask {
        let over_outflow = self.flows.iter().any(|flow| {
            let above = policy_of(&flow.asset).cosign_above;
            above != 0 && flow.charged_outflow > u128::from(above)
        });
        let over_withdrawal = self.public_gross.iter().any(|public| {
            let threshold = policy_of(&public.asset).withdrawal_threshold;
            threshold != 0 && public.gross > u128::from(threshold)
        });
        let bit = |set: bool, mask: ApprovalMask| match set {
            true => mask,
            false => ApprovalMask::EMPTY,
        };
        bit(over_outflow, ApprovalMask::OUTFLOW)
            .union(bit(over_withdrawal, ApprovalMask::WITHDRAWAL))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [1; 32];
    const BOB: [u8; 32] = [2; 32];
    const CAROL: [u8; 32] = [3; 32];
    const SOL: [u8; 32] = [4; 32];
    const USDC: [u8; 32] = [5; 32];

    fn input(owner: [u8; 32], asset: [u8; 32], amount: u64) -> DebitInput {
        DebitInput {
            owner,
            asset,
            amount,
        }
    }

    fn ring(owner: [u8; 32], asset: [u8; 32], amount: u64) -> DebitOutput {
        DebitOutput {
            ring: true,
            owner,
            asset,
            amount,
        }
    }

    fn debits(
        senders: &[[u8; 32]],
        inputs: &[DebitInput],
        outputs: &[DebitOutput],
    ) -> Vec<OwnerDebit> {
        owner_debits(&DebitTransfer {
            senders,
            assets: &[SOL, USDC],
            inputs,
            outputs,
            public_gross: &[],
        })
    }

    type NetDebit = ([u8; 32], [u8; 32], u128);

    fn row(owner: [u8; 32], asset: [u8; 32], debit: u128) -> NetDebit {
        (owner, asset, debit)
    }

    fn net(rows: Vec<OwnerDebit>) -> Vec<NetDebit> {
        rows.iter()
            .map(|row| (row.owner, row.asset, row.debit))
            .collect()
    }

    #[test]
    fn change_returns_to_its_owner_and_the_rest_is_the_debit() {
        assert_eq!(
            net(debits(
                &[ALICE],
                &[input(ALICE, SOL, 100), input(ALICE, SOL, 50)],
                &[ring(ALICE, SOL, 30), ring(BOB, SOL, 120)],
            )),
            [row(ALICE, SOL, 120)]
        );
    }

    #[test]
    fn an_exit_to_the_same_owner_counts_as_leaving() {
        let exit = DebitOutput {
            ring: false,
            ..ring(ALICE, SOL, 40)
        };
        assert_eq!(
            net(debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[exit, ring(ALICE, SOL, 60)]
            )),
            [row(ALICE, SOL, 40)]
        );
    }

    #[test]
    fn a_credit_never_moves_between_owners_or_assets() {
        assert_eq!(
            net(debits(
                &[ALICE, BOB],
                &[input(ALICE, SOL, 100), input(BOB, USDC, 70)],
                &[ring(BOB, SOL, 100), ring(ALICE, USDC, 70)],
            )),
            [row(ALICE, SOL, 100), row(BOB, USDC, 70)]
        );
        assert_eq!(
            net(debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[ring(ALICE, USDC, 100)]
            )),
            [row(ALICE, SOL, 100)]
        );
    }

    #[test]
    fn a_single_owner_deposit_offsets_its_debit_and_clamps_at_zero() {
        assert_eq!(
            net(debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[ring(ALICE, SOL, 80), ring(BOB, SOL, 70)],
            )),
            [row(ALICE, SOL, 20)]
        );
        assert_eq!(
            net(debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[ring(ALICE, SOL, 150)]
            )),
            []
        );
    }

    #[test]
    fn a_repeated_sender_or_asset_takes_one_row_and_a_stranger_none() {
        assert_eq!(
            net(owner_debits(&DebitTransfer {
                senders: &[ALICE, ALICE],
                assets: &[SOL, SOL],
                inputs: &[input(ALICE, SOL, 9), input(CAROL, SOL, 5)],
                outputs: &[],
                public_gross: &[],
            })),
            [row(ALICE, SOL, 9)]
        );
    }

    #[test]
    fn the_sum_passes_a_u64() {
        assert_eq!(
            net(debits(
                &[ALICE],
                &[input(ALICE, SOL, u64::MAX), input(ALICE, SOL, u64::MAX)],
                &[],
            )),
            [row(ALICE, SOL, 2 * u128::from(u64::MAX))]
        );
    }

    #[test]
    fn a_share_past_u128_in_the_product_stays_exact() {
        let big = 1u128 << 72;
        assert_eq!(mul_div_floor(big, big, big), big);
        assert_eq!(mul_div_floor(big - 1, big, big + 1), big - 2);
        assert_eq!(mul_div_floor(2, 2, 3), 1);
        assert_eq!(mul_div_floor(0, big, big), 0);
    }

    #[test]
    fn repeating_a_sender_or_reordering_them_changes_no_charge() {
        let inputs = [input(ALICE, SOL, 2), input(BOB, SOL, 1)];
        let outputs = [ring(ALICE, SOL, 2), ring(BOB, SOL, 1)];
        let public_gross = [PublicGross {
            asset: SOL,
            gross: 2,
        }];
        let run = |senders: &[[u8; 32]]| {
            owner_debits(&DebitTransfer {
                senders,
                assets: &[SOL],
                inputs: &inputs,
                outputs: &outputs,
                public_gross: &public_gross,
            })
        };
        let rows = run(&[ALICE, BOB]);
        assert_eq!(rows, run(&[BOB, ALICE, BOB]));
        assert_eq!(
            rows.iter().map(|row| row.charge).collect::<Vec<_>>(),
            [1, 1]
        );
    }

    #[test]
    fn a_guard_nets_only_same_ring_inputs_and_only_ring_payments() {
        let ring_inputs = [input(ALICE, SOL, 100)];
        let exit = DebitOutput {
            ring: false,
            ..ring(ALICE, SOL, 40)
        };
        let payments = [ring(ALICE, SOL, 130), exit, ring(BOB, SOL, 5)];
        let scope = GuardScope {
            ring_inputs: &ring_inputs,
            payments: &payments,
        };
        assert_eq!(scope.owner(&ALICE, &SOL), 70);
        assert_eq!(scope.asset(&SOL), 75);
        let unnetted = GuardScope {
            ring_inputs: &[],
            payments: &payments,
        };
        assert_eq!(unnetted.owner(&ALICE, &SOL), 170);
    }

    #[test]
    fn a_mask_reads_outflow_and_gross_apart() {
        let flow = OwnerDebit {
            owner: ALICE,
            asset: SOL,
            debit: 0,
            kept: 10,
            charge: 10,
            charged_outflow: 10,
        };
        let gross = PublicGross {
            asset: SOL,
            gross: 10,
        };
        let (flows, public_gross) = ([flow], [gross]);
        let inputs = ApprovalInputs {
            flows: &flows,
            public_gross: &public_gross,
        };
        let policy = |cosign_above, withdrawal_threshold| {
            move |_: &[u8; 32]| MintPolicy {
                cosign_above,
                withdrawal_threshold,
                ..MintPolicy::EMPTY
            }
        };
        assert_eq!(inputs.mask(policy(0, 0)), ApprovalMask::EMPTY);
        assert_eq!(inputs.mask(policy(10, 10)), ApprovalMask::EMPTY);
        assert_eq!(inputs.mask(policy(9, 10)), ApprovalMask::OUTFLOW);
        assert_eq!(inputs.mask(policy(10, 9)), ApprovalMask::WITHDRAWAL);
        assert_eq!(
            inputs.mask(policy(9, 9)),
            ApprovalMask::OUTFLOW.union(ApprovalMask::WITHDRAWAL)
        );
        assert_eq!(ApprovalMask::new(4), None);
    }
}
