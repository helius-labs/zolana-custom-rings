//! Custom ring program, the gate that signs as a ring's `ring_auth` PDA in front of SPP.
//!
//! SPP holds notes, nullifiers and value, and verifies its own proof. SPP requires `ring_auth` to sign
//! and reads only `RingConfig` about the ring. SPP reads no policy, no audit data and no co-signer.
//! Every rule below holds only because no other caller can produce that signature.
//!
//! One deployment serves one ring, the seeds of the ring account and of `ring_auth` name no other
//! ring. A ring note commits `hash_bytes` of the program id, the value SPP reads from `RingConfig`.
//!
//! # What the ring adds to SPP
//!
//! 1. Auditor recovery. The ring proof shows the auditor opens each instruction's sealed records, SPP reads none of them.
//! 2. Policy. A transfer on a policy ring proves the rules under the hash and roots the ring pins.
//! 3. Tracking. Owner keys resolve against the rows of the one tracking registry the ring pins.
//! 4. Co-signers. The operation and the proven approval bits demand signed records, outside SPP's account list.
//! 5. Hidden senders. The proof holds the hidden owner apart from the payer, the co-signers, the funders, the exit key and the owner run.
//! 6. Delegate. One permanent key moves notes without owner signatures and outside every policy rule.
//!
//! # What each side verifies in a transfer
//!
//! The program verifies the ring proof, then calls SPP with the data the frame expands to. One
//! transaction holds both, a refusal by either leaves no state. One frame feeds both proofs, and these links tie them:
//!
//! 1. `ring_id` is `hash_bytes` of the program id, the value SPP reads from the signed `RingConfig`.
//! 2. `first_nullifier` and `private_tx_hash` travel unchanged, the ring proof reopens the hash over the slots the audit opened.
//! 3. Off the authority rails, the signer chain covers the run SPP hashes as its owner signers.
//! 4. The public slots fold legs and mints in SPP's order, over the settlement accounts SPP settles.
//! 5. The ring statement binds the output hashes and the auditor message bytes, SPP's external data hash covers the same bytes.
//!
//! A ring deposit is a transfer that spends no note, its public leg funds the outputs. No ring path
//! signs SPP's proofless `ring_deposit`. A merge pairs SPP's merge proof with a ring proof over the
//! auditor's record, see `instructions/settlement/merge.rs`.
//!
//! # Instruction data
//!
//! A frame is a prover's claim. An element enters a statement from the frame only when a proof or
//! SPP refuses any other value, `instructions/transfer/verify.rs` names each element.
//!
//! # Reading order
//!
//! Crate paths start at `src`, `program-libs` and `prover` paths start at the repository root. Each file names its neighbours in the same way.
//!
//! 1. `instructions/transfer/processor.rs`, the stages of one transfer.
//! 2. `instructions/transfer/accounts.rs`, the account windows and the party checks.
//! 3. `instructions/transfer/verify.rs`, the source of each statement element.
//! 4. `instructions/runtime/instruction_runtime.rs`, the placement check behind every `ring_auth` signature.
//! 5. `instructions/accounts/loader.rs`, root reads with grace and floor, and co-signer records.
//! 6. `instructions/settlement/merge.rs`, the merge.
//! 7. `instructions/configuration`, the setup, the delegate, the roles and the policy writes.
//!
//! The statements live in `program-libs/interface/src/proof/statement.rs`, their circuits in
//! `prover/circuits/transfer/transfer.go` and `prover/circuits/merge.go`.

mod instructions;
mod state;

use custom_ring_interface::InstructionTag;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::instructions::*;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (ix_tag, ix_data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let ix_tag = InstructionTag::try_from(*ix_tag)?;

    match ix_tag {
        InstructionTag::Initialize => process_initialize_ix(program_id, accounts, ix_data),
        InstructionTag::Transfer | InstructionTag::AuthorityTransfer => {
            process_transfer_ix(program_id, accounts, ix_data, ix_tag)
        }
        // SPP proves that owner, asset, value and ring ownership stay unchanged.
        InstructionTag::Merge => process_merge_ix(program_id, accounts, ix_data),
        InstructionTag::UpdateAuthority => {
            process_update_authority_ix(program_id, accounts, ix_data)
        }
        InstructionTag::UpdatePolicy => process_update_policy_ix(program_id, accounts, ix_data),
        InstructionTag::SetPaused => process_set_paused_ix(program_id, accounts, ix_data),
        InstructionTag::SetCoSigner => process_set_cosigner_ix(program_id, accounts, ix_data),
        InstructionTag::ClearCoSigner => process_clear_cosigner_ix(program_id, accounts, ix_data),
        InstructionTag::SetDelegate => process_set_delegate_ix(program_id, accounts, ix_data),
    }
}
