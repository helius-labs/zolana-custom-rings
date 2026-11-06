//! Assembles the transfer statement and verifies the ring proof over it.
//!
//! The statement is all the ring proof says to the program. A cell the prover could choose freely
//! would pass a proof about other notes, keys or roots. `TransferStatement::elements` fixes the order,
//! and `statement` in `prover/circuits/transfer/transfer.go` mirrors it.
//!
//! The program supplies these elements, the prover must not choose them:
//!
//! 1. `ring_id` from the program id, SPP reads the same value from `RingConfig`. Another value would pass a proof about another ring's notes.
//! 2. `auditor_pubkey` from the ring account. A frame value would seal the audit stream to a key the prover holds.
//! 3. The rail bits from the tag, the ring's mode and the frame's owner flags, SPP's selector reads the same flags.
//! 4. `signers` from the run SPP hashes, the proof holds each live owner to it.
//! 5. `party_identities` from the accounts the instruction names in public.
//! 6. `sender` by hashing the key the frame names, the proof holds the inputs to it.
//! 7. The roots from the pinned registries and `policy_hash` from the ring account, the frame names only revisions.
//! 8. The public slots from the frame's legs and the window's mints in SPP's fold, SPP's proof refuses another assignment.
//! 9. `withdrawal_hash` from the live settlement accounts.
//!
//! The frame supplies the rest, and a proof refuses any other value:
//!
//! 1. `first_nullifier`, `tx_viewing_u`, `salt`, the outputs and `private_tx_hash` also reach SPP in the forwarded data.
//! 2. The envelope, records and tails also reach SPP as the auditor message, the ring proof alone ties them to the sealed key.
//! 3. `approval_mask`, `approval_totals`, `signer_data_counts` and `no_spend` each meet a value the ring proof computes.
//! 4. The counts and the layout size the sections the ring proof opens.
//!
//! Read after `instructions/transfer/accounts.rs`, `instructions/verification/public_legs.rs`. Read before `program-libs/interface/src/proof/statement.rs`, `instructions/runtime/instruction_runtime.rs`.

use custom_ring_interface::{CustomRingError, ParsedTransact, RingPolicy, TransferBinding};
use pinocchio::{Address, ProgramResult};
use zolana_ring_policy::ring_id_field;

use super::accounts::TransactAccounts;
use crate::instructions::verifier::{ring_key, RingProof};

#[must_use]
pub(super) struct RingStatements<'a> {
    pub program_id: &'a Address,
    pub ring: &'a RingPolicy,
    pub transfer: &'a ParsedTransact<'a>,
    pub accounts: &'a TransactAccounts,
}

impl RingStatements<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let ring_id = ring_id_field(self.program_id.as_array()).map_err(CustomRingError::from)?;
        let data = self.transfer.data();
        let slots = &self.accounts.public_slots;
        let public_assets = slots.asset_fields().map_err(CustomRingError::from)?;
        let public_amounts = slots.amount_fields().map_err(CustomRingError::from)?;
        let public_gross = slots.gross_fields();
        let withdrawal_hash =
            custom_ring_interface::policy_withdrawal_hash(&self.accounts.withdrawals)
                .map_err(CustomRingError::from)?;
        let statement = self
            .transfer
            .transfer_statement(TransferBinding {
                ring_id: &ring_id,
                auditor_pubkey: &self.ring.auditor_pubkey,
                sender: &self.accounts.sender,
                signers: self.accounts.signers,
                party_identities: &self.accounts.party_identities,
                roots: &self.accounts.roots,
                public_assets: &public_assets,
                public_amounts: &public_amounts,
                public_gross: &public_gross,
                withdrawal_hash: &withdrawal_hash,
            })?
            .hash()
            .map_err(CustomRingError::from)?;
        // The frame and the screened withdrawal count select the key, each catalog key compiles `TransferCircuit` at one shape.
        RingProof {
            proof: data.proof,
            statement,
            key: ring_key(data.transfer_circuit(self.accounts.withdrawals.len())?)?,
        }
        .verify()
    }
}
