use solana_address::Address;
use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::{instructions::transact::SppProofOutputUtxo, Mint};
use zolana_ring_policy::{Member, OutflowLimit};

use super::support::{keypair, program};
use crate::{limits::Outflows, RingError};

/// Ring change stays the sender's, an exit to the sender leaves it.
#[test]
fn the_outflow_counts_what_leaves_the_sender_less_its_public_deposit() {
    let sender = keypair(1).shielded_address().unwrap();
    let other = keypair(2).shielded_address().unwrap();
    let sol = Member::asset(&Mint::SOL.asset).unwrap();
    let output = |owner, amount, ring: Option<Address>| {
        let output = SppProofOutputUtxo::new(Mint::SOL, amount, owner).unwrap();
        match ring {
            Some(ring) => output.with_ring_program_id(ring),
            None => output,
        }
    };
    let outputs = [
        output(other, 3, Some(program())),
        output(sender, 7, Some(program())),
        output(sender, 2, None),
    ];
    let mut public_assets = [[0; 32]; N_PUBLIC_SLOTS];
    public_assets[0] = *sol.as_bytes();
    let sender_id = sender.signing_pubkey.owner_proof_input_hash().unwrap();
    let approval = |net: i128, cap: u64, cosign_above: u64| {
        let mut public_amounts = [0; N_PUBLIC_SLOTS];
        public_amounts[0] = net;
        Outflows {
            sender: sender_id,
            ring: program(),
            outputs: &outputs,
            public_assets: &public_assets,
            public_amounts: &public_amounts,
        }
        .approval_required(&[OutflowLimit::of(&sol)
            .with_cap(cap)
            .with_cosign_above(cosign_above)])
    };
    assert!(!approval(0, 5, 5).unwrap());
    assert!(approval(0, 5, 4).unwrap());
    assert!(matches!(
        approval(-1, 5, 0),
        Err(RingError::OutflowCapExceeded {
            outflow: 6,
            cap: 5,
            ..
        })
    ));
    assert!(!approval(5, 0, 1).unwrap());
    assert!(matches!(
        approval(6, 0, 0),
        Err(RingError::DepositAboveOutflow { asset }) if asset == *sol.as_bytes()
    ));
}
