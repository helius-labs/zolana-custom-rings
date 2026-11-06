//! Reads `test-vectors/policy/quantities.json`, the values the policy circuit reaches.

use serde::Deserialize;
use zolana_ring_policy::{
    owner_debits, ApprovalInputs, DebitInput, DebitOutput, DebitTransfer, GuardScope, MintPolicy,
    PublicGross,
};

#[derive(Deserialize)]
struct Note {
    owner: u64,
    asset: u64,
    amount: u64,
    ring: bool,
}

#[derive(Deserialize)]
struct Row {
    owner: u64,
    asset: u64,
    debit: u128,
    kept: u128,
    charge: u128,
    charged_outflow: u128,
}

#[derive(Deserialize)]
struct Guard {
    owner: u64,
    asset: u64,
    guard: u128,
}

#[derive(Deserialize)]
struct AssetGuard {
    asset: u64,
    guard: u128,
}

#[derive(Deserialize)]
struct Public {
    asset: u64,
    gross: u128,
}

#[derive(Deserialize)]
struct Threshold {
    asset: u64,
    cosign_above: u64,
    withdrawal_threshold: u64,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    inputs: Vec<Note>,
    #[serde(default)]
    outputs: Vec<Note>,
    #[serde(default)]
    withdrawals: Vec<Note>,
    #[serde(default)]
    public: Vec<Public>,
    #[serde(default)]
    rows: Vec<Row>,
    #[serde(default)]
    guards: Vec<Guard>,
    #[serde(default)]
    asset_guards: Vec<AssetGuard>,
    #[serde(default)]
    thresholds: Vec<Threshold>,
    #[serde(default)]
    mask: u8,
}

#[derive(Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

fn identity(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn input(note: &Note) -> DebitInput {
    DebitInput {
        owner: identity(note.owner),
        asset: identity(note.asset),
        amount: note.amount,
    }
}

fn payment(note: &Note) -> DebitOutput {
    DebitOutput {
        ring: note.ring,
        owner: identity(note.owner),
        asset: identity(note.asset),
        amount: note.amount,
    }
}

#[test]
fn every_quantity_matches_the_circuit() {
    let vector: Vector =
        serde_json::from_str(include_str!("../../../test-vectors/policy/quantities.json")).unwrap();
    for case in vector.cases {
        let inputs: Vec<DebitInput> = case.inputs.iter().map(input).collect();
        let ring_inputs: Vec<DebitInput> = case
            .inputs
            .iter()
            .filter(|note| note.ring)
            .map(input)
            .collect();
        let outputs: Vec<DebitOutput> = case.outputs.iter().map(payment).collect();
        let payments: Vec<DebitOutput> = case
            .outputs
            .iter()
            .chain(&case.withdrawals)
            .map(payment)
            .collect();
        let public_gross: Vec<PublicGross> = case
            .public
            .iter()
            .map(|public| PublicGross {
                asset: identity(public.asset),
                gross: public.gross,
            })
            .collect();
        let senders: Vec<[u8; 32]> = inputs.iter().map(|input| input.owner).collect();
        let assets: Vec<[u8; 32]> = inputs
            .iter()
            .map(|input| input.asset)
            .chain(outputs.iter().map(|output| output.asset))
            .chain(public_gross.iter().map(|public| public.asset))
            .collect();
        let flows = owner_debits(&DebitTransfer {
            senders: &senders,
            assets: &assets,
            inputs: &inputs,
            outputs: &outputs,
            public_gross: &public_gross,
        });
        let got: Vec<_> = flows
            .iter()
            .map(|row| {
                (
                    row.owner,
                    row.asset,
                    row.debit,
                    row.kept,
                    row.charge,
                    row.charged_outflow,
                )
            })
            .collect();
        let want: Vec<_> = case
            .rows
            .iter()
            .map(|row| {
                (
                    identity(row.owner),
                    identity(row.asset),
                    row.debit,
                    row.kept,
                    row.charge,
                    row.charged_outflow,
                )
            })
            .collect();
        assert_eq!(got, want, "{}", case.name);
        let scope = GuardScope {
            ring_inputs: &ring_inputs,
            payments: &payments,
        };
        for guard in &case.guards {
            assert_eq!(
                scope.owner(&identity(guard.owner), &identity(guard.asset)),
                guard.guard,
                "{}",
                case.name
            );
        }
        for guard in &case.asset_guards {
            assert_eq!(
                scope.asset(&identity(guard.asset)),
                guard.guard,
                "{}",
                case.name
            );
        }
        let policy_of = |asset: &[u8; 32]| {
            case.thresholds
                .iter()
                .find(|threshold| identity(threshold.asset) == *asset)
                .map_or(MintPolicy::EMPTY, |threshold| MintPolicy {
                    cosign_above: threshold.cosign_above,
                    withdrawal_threshold: threshold.withdrawal_threshold,
                    ..MintPolicy::EMPTY
                })
        };
        assert_eq!(
            ApprovalInputs {
                flows: &flows,
                public_gross: &public_gross,
            }
            .mask(policy_of)
            .bits(),
            case.mask,
            "{}",
            case.name
        );
    }
}
