use solana_address::Address;
use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo, Mint};
use zolana_ring_policy::{Member, MintPolicy};

use super::support::{keypair, program, ring_utxo};
use crate::{limits::Outflows, RingError};

fn sol() -> [u8; 32] {
    *Member::asset(&Mint::SOL.asset).unwrap().as_bytes()
}

struct Case {
    /// One spent note per amount.
    held: &'static [u64],
    returned: u64,
    gross: u128,
}

impl Case {
    fn flows(&self) -> Vec<zolana_ring_policy::OwnerDebit> {
        self.read(|outflows| outflows.flows().unwrap())
    }

    fn read<T>(&self, read: impl FnOnce(&Outflows<'_>) -> T) -> T {
        let owner = keypair(1);
        let sender = owner.shielded_address().unwrap();
        let mut public_assets = [[0; 32]; N_PUBLIC_SLOTS];
        public_assets[0] = sol();
        let mut public_gross = [0; N_PUBLIC_SLOTS];
        public_gross[0] = self.gross;
        let outputs = [SppProofOutputUtxo::new(Mint::SOL, self.returned, sender)
            .unwrap()
            .with_ring_program_id(program())];
        let inputs: Vec<SppProofInputUtxo> = (0..)
            .zip(self.held)
            .map(|(index, held)| ring_utxo(&owner, Mint::SOL, *held, index).into())
            .collect();
        read(&Outflows {
            senders: &[sender.signing_pubkey.owner_proof_input_hash().unwrap()],
            inputs: &inputs,
            outputs: &outputs,
            public_assets: &public_assets,
            public_gross: &public_gross,
        })
    }
}

fn capped(cap: u64) -> impl Fn(&[u8; 32]) -> MintPolicy {
    move |_| MintPolicy {
        cap,
        ..MintPolicy::EMPTY
    }
}

/// `S 200, withdraw 150, S 50`, the public leg is what leaves.
#[test]
fn a_withdrawal_counts_against_the_cap_through_its_debit() {
    let flows = Case {
        held: &[200],
        returned: 50,
        gross: 150,
    }
    .flows();
    assert_eq!(flows[0].charged_outflow, 150);
    assert!(Outflows::check_caps(&flows, capped(150)).is_ok());
    assert!(matches!(
        Outflows::check_caps(&flows, capped(100)),
        Err(RingError::OutflowCapExceeded {
            cap: 100,
            charged_outflow: 150,
            ..
        })
    ));
}

/// The intended composition cost. A spends 100 and receives 100 back, B's public deposit of 100
/// funds a public withdrawal of 100, A's net outflow is zero and its charged outflow is 100.
#[test]
fn a_returned_spend_beside_a_public_withdrawal_is_charged() {
    let flows = Case {
        held: &[100],
        returned: 100,
        gross: 100,
    }
    .flows();
    assert_eq!(
        (flows[0].debit, flows[0].charge, flows[0].charged_outflow),
        (0, 100, 100)
    );
    assert!(Outflows::check_caps(&flows, capped(100)).is_ok());
    assert!(matches!(
        Outflows::check_caps(&flows, capped(99)),
        Err(RingError::OutflowCapExceeded {
            charged_outflow: 100,
            ..
        })
    ));
}

/// The circuit bounds an aggregate at 72 bits, a gross past `u64::MAX` keeps its exact charged outflow.
#[test]
fn a_gross_past_u64_keeps_its_exact_charged_outflow() {
    let case = Case {
        held: &[u64::MAX, u64::MAX],
        returned: 0,
        gross: u128::from(u64::MAX) + 1,
    };
    let flows = case.flows();
    let charged_outflow = flows[0].charged_outflow;
    assert!(charged_outflow > u128::from(u64::MAX));
    assert!(Outflows::check_caps(&flows, capped(0)).is_ok());
    assert!(case.read(|outflows| outflows.approval_totals(4)).is_ok());
    assert!(matches!(
        Outflows::check_caps(&flows, capped(u64::MAX)),
        Err(RingError::OutflowCapExceeded { charged_outflow: refused, .. }) if refused == charged_outflow
    ));
}

#[test]
fn change_alone_is_no_outflow() {
    let flows = Case {
        held: &[100],
        returned: 100,
        gross: 0,
    }
    .flows();
    assert!(flows.is_empty());
    assert!(Outflows::check_caps(&flows, capped(1)).is_ok());
    let _ = Address::default();
}
