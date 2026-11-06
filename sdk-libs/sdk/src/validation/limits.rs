//! A shared vector pins `owner_debits` to the circuit.

use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};
use zolana_ring_policy::{
    owner_debits, ApprovalTotals, DebitInput, DebitOutput, DebitTransfer, Member, MintPolicy,
    OwnerDebit, PublicGross,
};
use zolana_ring_transaction::ClassifiedInput;

use crate::RingError;

pub(crate) struct Outflows<'a> {
    /// The transfer's owner rows, zero rows pad.
    pub senders: &'a [[u8; 32]],
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// No deposit subtracted, a net of the legs undercounts `leaving`.
    pub public_gross: &'a [u128; N_PUBLIC_SLOTS],
}

impl Outflows<'_> {
    fn debit_inputs(&self) -> Result<Vec<DebitInput>, RingError> {
        self.inputs
            .iter()
            .filter(|input| input.is_note())
            .map(|input| {
                Ok(DebitInput {
                    owner: input.utxo.owner.owner_proof_input_hash()?,
                    asset: *Member::asset(&input.utxo.asset.asset)?.as_bytes(),
                    amount: input.utxo.amount,
                })
            })
            .collect()
    }

    /// Default-ring notes stay out, entry funding is a receipt.
    pub fn ring_inputs(&self) -> Result<Vec<DebitInput>, RingError> {
        self.inputs
            .iter()
            .filter(|input| input.is_note() && input.utxo.ring_program_id.is_some())
            .map(|input| {
                Ok(DebitInput {
                    owner: input.utxo.owner.owner_proof_input_hash()?,
                    asset: *Member::asset(&input.utxo.asset.asset)?.as_bytes(),
                    amount: input.utxo.amount,
                })
            })
            .collect()
    }

    /// An exit reads no ring output, so it counts as leaving.
    fn debit_outputs(&self) -> Result<Vec<DebitOutput>, RingError> {
        self.outputs
            .iter()
            .filter(|output| !output.is_dummy())
            .filter_map(|output| output.owner_address.map(|owner| (output, owner)))
            .map(|(output, owner)| {
                Ok(DebitOutput {
                    ring: output.ring_program_id.is_some(),
                    owner: owner.signing_pubkey.owner_proof_input_hash()?,
                    asset: *Member::asset(&output.asset.asset)?.as_bytes(),
                    amount: output.amount,
                })
            })
            .collect()
    }

    /// `read` sees the transfer every quantity of the circuit derives from.
    fn read_transfer<T>(&self, read: impl FnOnce(&DebitTransfer<'_>) -> T) -> Result<T, RingError> {
        let inputs = self.debit_inputs()?;
        let outputs = self.debit_outputs()?;
        let public_gross: Vec<PublicGross> = self
            .public_assets
            .iter()
            .zip(self.public_gross)
            .filter(|(asset, _)| **asset != [0; 32])
            .map(|(asset, gross)| PublicGross {
                asset: *asset,
                gross: *gross,
            })
            .collect();
        let assets: Vec<[u8; 32]> = outputs
            .iter()
            .map(|output| output.asset)
            .chain(inputs.iter().map(|input| input.asset))
            .chain(public_gross.iter().map(|public| public.asset))
            .collect();
        Ok(read(&DebitTransfer {
            senders: self.senders,
            assets: &assets,
            inputs: &inputs,
            outputs: &outputs,
            public_gross: &public_gross,
        }))
    }

    /// `charged_outflow` per row and asset.
    pub fn flows(&self) -> Result<Vec<OwnerDebit>, RingError> {
        self.read_transfer(owner_debits)
    }

    /// One slot per output of the key and per public slot, the layout the circuit commits.
    pub fn approval_totals(&self, capacity: usize) -> Result<ApprovalTotals, RingError> {
        let slot_assets = (0..capacity)
            .map(|slot| match self.outputs.get(slot) {
                Some(output) if !output.is_dummy() => {
                    Ok(Some(*Member::asset(&output.asset.asset)?.as_bytes()))
                }
                _ => Ok(None),
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let public_slots: Vec<PublicGross> = self
            .public_assets
            .iter()
            .zip(self.public_gross)
            .map(|(asset, gross)| PublicGross {
                asset: *asset,
                gross: *gross,
            })
            .collect();
        self.read_transfer(|transfer| ApprovalTotals::new(transfer, &slot_assets, &public_slots))
    }

    /// Refuses before proving what the circuit fails to solve.
    pub fn check_caps(
        flows: &[OwnerDebit],
        policy_of: impl Fn(&[u8; 32]) -> MintPolicy,
    ) -> Result<(), RingError> {
        for flow in flows {
            let cap = policy_of(&flow.asset).cap;
            if cap != 0 && flow.charged_outflow > u128::from(cap) {
                return Err(RingError::OutflowCapExceeded {
                    asset: flow.asset,
                    cap,
                    charged_outflow: flow.charged_outflow,
                });
            }
        }
        Ok(())
    }
}
