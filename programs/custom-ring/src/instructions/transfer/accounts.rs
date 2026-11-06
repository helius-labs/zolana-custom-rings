//! Places the accounts of a transfer and reads every statement value that only an account holds.
//!
//! SPP reads its list by position, and the ring program prepends its own slots. A value read from
//! the wrong slot would verify the ring proof against accounts SPP does not settle.
//!
//! The account windows, in list order:
//!
//! 1. The ring account.
//! 2. The registries `RootRead` names, own then curator then tracking, each compared with the ring's pin.
//! 3. One `[record, signer]` pair per co-signer the demand needs, SPP does not receive them.
//! 4. The delegate's signer on the authority rails, SPP does not receive it.
//! 5. SPP's list, forwarded whole. Prefix, input trees, nullifier PDAs, owner run, settlement groups, cache accounts.
//!
//! On return these facts hold:
//!
//! 1. Each root comes from the registry the ring pins, at the revision the frame names.
//! 2. `ring_auth` sits only in SPP's `ring_config` slot, and the payer signs.
//! 3. A signed record covers every class the ring configured and the operation demands, and every proven approval bit.
//! 4. Every funder of a deposit leg signs, and a delegate frame has no deposit leg.
//! 5. On the anonymous rail each signer in SPP's list is the payer, a co-signer, a funder or in the owner run.
//!
//! The ring proof finishes the party check. `hiddenOwner` in `prover/circuits/transfer/transfer.go` holds
//! the hidden owner apart from each nonzero party cell and from the owner run. SPP validates each settlement account.
//!
//! Read after `instructions/transfer/processor.rs`. Read before `instructions/transfer/verify.rs`.

use custom_ring_interface::{
    cosign::{CoSignDemand, CoSignOperation},
    funder_account_position, AnonymousParties, CustomRingError, ParsedTransact, PublicSlots,
    RailSigner, RingPolicy, RootRead, SignerSet, TransferRoots, ANONYMOUS_PARTIES,
    RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};
use pinocchio::{error::ProgramError, AccountView, Address};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::settlement_accounts;

use crate::instructions::{
    instruction_runtime::{PlacedRingAuth, RingAuth},
    loader::{check_funding_signer, load_anonymous_exit, CoSigners, RegistrySlots},
    public_legs::public_slots,
};

const RING_INDEX: usize = 0;

pub(super) struct TransactAccounts {
    pub roots: TransferRoots,
    /// The in-proof owner's identity, zero otherwise.
    pub sender: [u8; 32],
    /// SPP's owner signer run, default on the authority rails.
    pub signers: SignerSet,
    /// Zeros off the anonymous frame.
    pub party_identities: [[u8; 32]; ANONYMOUS_PARTIES],
    pub public_slots: PublicSlots,
    /// Empty without own records and on the authority rails, no rule screens them.
    pub withdrawals: Vec<custom_ring_interface::PolicyWithdrawal>,
    /// Index of the first forwarded SPP account.
    pub spp: usize,
    pub ring_auth: PlacedRingAuth,
}

#[must_use]
pub(super) struct TransactCheck<'a> {
    pub program_id: &'a Address,
    pub ring: &'a RingPolicy,
    pub transfer: &'a ParsedTransact<'a>,
    pub signer: RailSigner,
    pub slot: u64,
}

impl TransactCheck<'_> {
    #[inline(never)]
    pub fn validate(self, accounts: &[AccountView]) -> Result<TransactAccounts, ProgramError> {
        let (ring, data) = (self.ring, self.transfer.data());
        let delegate_rail = data.rail.is_delegate();
        // 1. The frame names only revisions, the registries the ring pins serve each root. A delegate
        // reads no policy root, a restrictive update cannot fail its proof.
        let read = RootRead::transfer(ring, delegate_rail);
        let registries = RegistrySlots { ring, read }.load({
            let mut after_ring = accounts.iter().skip(RING_INDEX + 1);
            move || after_ring.next().ok_or(ProgramError::NotEnoughAccountKeys)
        })?;
        // 2. The settlement groups end SPP's list ahead of the cache accounts, SPP reads the same window.
        // The public slots, the funders, the withdrawals and the exit all read from it.
        let window = settlement_accounts(&data.interface_transfers, data.circuit(), accounts)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        let public_slots = public_slots(&data.interface_transfers, window)?;
        let bound = data.roots(ring, &registries.roots(self.slot))?;
        // 3. The legs and the frame's spend and approval bits set the demand, step 5 of the run proves
        // those bits. A delegate owes no co-signer.
        let demand = match delegate_rail {
            true => CoSignDemand::NONE,
            false => CoSignOperation {
                spends_note: !data.no_spend,
                public_legs: public_slots.classes(),
                approval: data.approval,
            }
            .demand(),
        };
        let co_signers_start = RING_INDEX + 1 + registries.len;
        let co_signers = CoSigners::verify(
            self.program_id,
            accounts
                .get(co_signers_start..)
                .ok_or(ProgramError::NotEnoughAccountKeys)?,
            demand.requirement(ring),
        )?;
        // 4. The pairs and the delegate slot size the ring's prefix, every SPP index below counts from `spp`.
        let delegate_slot = co_signers_start + co_signers.accounts();
        let spp_start = match self.signer {
            RailSigner::Delegate { .. } => delegate_slot + 1,
            RailSigner::Owners | RailSigner::Payer => delegate_slot,
        };
        let spp = accounts
            .get(spp_start..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        // 5. `ring_auth` signs the forwarded call, its one slot keeps that signature on `ring_config`.
        let ring_auth =
            RingAuth::derive(self.program_id)?.check_slot(spp, RING_TRANSACT_RING_CONFIG_INDEX)?;
        let payer = check_funding_signer(spp, TRANSACT_PAYER_INDEX)?;
        let slots = self.transfer.audit_stream().key.signer_slots();
        // 6. A deposit leg would bring an unlisted asset in on the delegate rail.
        if matches!(self.signer, RailSigner::Delegate { .. })
            && data
                .interface_transfers
                .iter()
                .any(|transfer| transfer.is_deposit())
        {
            return Err(CustomRingError::DelegatePublicLeg.into());
        }
        // 7. A funder signs for its own deposit leg, and SPP moves only that leg's amount under the
        // signature. The walk comes first since the anonymous rail classifies every signer by it.
        let mut funders = Vec::new();
        let mut groups = window;
        for transfer in &data.interface_transfers {
            let (group, rest) = groups
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(CustomRingError::InvalidSettlementAccounts)?;
            groups = rest;
            if let Some(funder) = funder_account_position(transfer) {
                funders.push(*check_funding_signer(group, funder)?.address().as_array());
            }
        }
        // 8. Each rail names who authorizes the spend, and the statement binds that identity.
        let (sender, signers) = match self.signer {
            RailSigner::Payer => {
                let owners = data.owner_signers(spp, window.len())?;
                check_owner_run(owners, &co_signers)?;
                // The proof holds each public owner's live input to the run, an empty run spends nothing.
                if data.public_owners && !data.no_spend && owners.is_empty() {
                    return Err(CustomRingError::OwnerSignerCount.into());
                }
                // A signer outside the four classes takes no party cell and sits outside the run. The
                // proof could not hold it apart from the hidden owner, and its signature could name that owner.
                if spp.iter().any(|account| {
                    account.is_signer()
                        && account.address() != payer.address()
                        && !co_signers.contains(account.address())
                        && !funders.contains(account.address().as_array())
                        && !owners
                            .iter()
                            .any(|owner| owner.address() == account.address())
                }) {
                    return Err(CustomRingError::InvalidAnonymousSigner.into());
                }
                ([0; 32], signer_set(owners, slots)?)
            }
            RailSigner::Owners => {
                let owners = data.owner_signers(spp, window.len())?;
                check_owner_run(owners, &co_signers)?;
                // The in-proof owner signs inside SPP's anonymous rail proof, the frame names its key.
                let sender = match data.in_proof_owner {
                    Some(owner) => {
                        let owner = Address::new_from_array(*owner.owner);
                        if co_signers.contains(&owner) {
                            return Err(CustomRingError::CoSignerIsOwner.into());
                        }
                        solana_owner_identity(owner.as_array()).map_err(CustomRingError::from)?
                    }
                    None if !data.no_spend && owners.is_empty() => {
                        return Err(CustomRingError::OwnerSignerCount.into());
                    }
                    None => [0; 32],
                };
                (sender, signer_set(owners, slots)?)
            }
            RailSigner::Delegate { delegate, .. } => {
                // SPP's authority rail admits no owner signer, the delegate slot is the move's one
                // authorization beside governance's rail flag in `RingConfig`.
                let signer = account_at(accounts, delegate_slot)?;
                if !signer.is_signer() || signer.address() != &delegate {
                    return Err(CustomRingError::UnauthorizedDelegate.into());
                }
                ([0; 32], SignerSet::default())
            }
        };

        // 9. The rules screen each withdrawal's owner and mint as the live accounts hold them, the frame's
        // owner list must match each token account. The statement binds the result as `withdrawal_hash`.
        let withdrawals = match read {
            RootRead::None => Vec::new(),
            RootRead::Own | RootRead::Policy => custom_ring_interface::policy_withdrawals(
                &data.interface_transfers,
                &window
                    .iter()
                    .map(crate::instructions::loader::LoadedSettlement)
                    .collect::<Vec<_>>(),
                data.spl_withdrawal_owners,
            )?,
        };
        // 10. The payer, the co-signers, the funders and a hidden sender's exit key hold the party cells,
        // a zero cell reads as absent.
        let party_identities = match data.rail.anonymous_frame() {
            true => {
                // SPP settles any exit, only a hidden sender needs a destination that names one key.
                // The proof holds the hidden owner apart from that key.
                let exit = match self.signer == RailSigner::Payer && !data.public_owners {
                    true => load_anonymous_exit(&data.interface_transfers, window)?,
                    false => None,
                };
                AnonymousParties {
                    payer: payer.address().as_array(),
                    co_signers: co_signers.as_slice(),
                    funders: &funders,
                    exit_destination: exit.as_ref(),
                }
                .identities()?
            }
            false => [[0; 32]; ANONYMOUS_PARTIES],
        };

        Ok(TransactAccounts {
            roots: bound,
            sender,
            signers,
            party_identities,
            public_slots,
            withdrawals,
            spp: spp_start,
            ring_auth,
        })
    }
}

fn account_at(accounts: &[AccountView], index: usize) -> Result<&AccountView, ProgramError> {
    accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)
}

/// Every entry signs and SPP counts its run up to the first non-signer. A signing settlement account
/// would lengthen SPP's count and fail its exact settlement length, so both programs read one run.
fn check_owner_run(owners: &[AccountView], co_signers: &CoSigners) -> Result<(), CustomRingError> {
    if owners.iter().any(|owner| !owner.is_signer()) {
        return Err(CustomRingError::MissingOwnerSigner);
    }
    // An owner approving its own spend would add no second party.
    if owners
        .iter()
        .any(|owner| co_signers.contains(owner.address()))
    {
        return Err(CustomRingError::CoSignerIsOwner);
    }
    Ok(())
}

fn signer_set(owners: &[AccountView], slots: usize) -> Result<SignerSet, CustomRingError> {
    SignerSet::new(owners.iter().map(|owner| owner.address().as_array()), slots)
}
