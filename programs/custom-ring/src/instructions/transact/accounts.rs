use custom_ring_interface::{
    cosign::{CoSignDemand, CoSignRequirement},
    funder_account_position, AnonymousParties, CustomRingError, CustomRingProof, InputTrees,
    PublicSlots, RailSigner, RingProgramConfig, RingTransactData, ANONYMOUS_PARTIES,
    RING_TRANSACT_ACCOUNT_PREFIX_LEN, RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};
use pinocchio::{error::ProgramError, AccountView, Address};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::settlement_accounts;

use crate::instructions::{
    instruction_runtime::{PlacedRingAuth, RingAuth},
    loader::{check_funding_signer, load_anonymous_exit, load_policy, CoSignerSlot},
    public_legs::PublicLegs,
};

/// The ring policy follows the config, the one account every own and curator root comes from.
const POLICY_INDEX: usize = 1;

pub(super) struct PolicyRoots<'a> {
    pub own_only: bool,
    pub proof: &'a CustomRingProof,
    pub policy_hash: [u8; 32],
    pub own_root: [u8; 32],
    /// Zero without a curator source.
    pub curator_root: [u8; 32],
}

pub(super) struct TransactAccounts<'a> {
    pub policy: Option<PolicyRoots<'a>>,
    pub sender: [u8; 32],
    /// The anonymous rail's party identities, `None` on the other rails.
    pub anonymous_parties: Option<[[u8; 32]; ANONYMOUS_PARTIES]>,
    pub public_slots: PublicSlots,
    pub withdrawals: Vec<custom_ring_interface::PolicyWithdrawal>,
    /// Index of the first forwarded SPP account.
    pub spp: usize,
    pub ring_auth: PlacedRingAuth,
}

#[must_use]
pub(super) struct TransactCheck<'a> {
    pub program_id: &'a Address,
    pub config: &'a RingProgramConfig,
    pub data: &'a RingTransactData<'a>,
    pub signer: RailSigner,
    pub slot: u64,
}

impl<'a> TransactCheck<'a> {
    /// The co-signer demand comes first, its slot moves the SPP list.
    #[inline(never)]
    pub fn validate(self, accounts: &[AccountView]) -> Result<TransactAccounts<'a>, ProgramError> {
        let (config, data) = (self.config, self.data);
        let window = settlement_accounts(&data.interface_transfers, data.circuit(), accounts)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        let legs = PublicLegs::new(&data.interface_transfers, window)?;
        let ring_policy = if config.has_policy() || data.withdrawal_exemption.is_some() {
            Some(load_policy(
                self.program_id,
                account_at(accounts, POLICY_INDEX)?,
            )?)
        } else {
            None
        };
        let demand = CoSignDemand::transact(data.approval_required, legs.legs());
        if let Some(exemption) = data.withdrawal_exemption {
            let root = ring_policy
                .as_ref()
                .ok_or(CustomRingError::InvalidRingPolicy)?
                .own_root(exemption.own_revision, self.slot)?;
            crate::instructions::verifier::RingProof {
                proof: &exemption.proof,
                statement: custom_ring_interface::cosign::WithdrawalExemptionStatement::new(
                    root, &demand,
                )?
                .hash()
                .map_err(CustomRingError::from)?,
                key: crate::instructions::verifier::ring_key(
                    custom_ring_interface::key_catalog::RingCircuit::WithdrawalExemption,
                )?,
            }
            .verify()?;
        }
        let demand = match data.withdrawal_exemption {
            Some(_) => demand.exempt_withdrawals(),
            None => demand,
        };
        let requirement = demand.requirement(config);
        let binding = data.check_policy(
            ring_policy.as_deref().filter(|_| config.has_policy()),
            self.slot,
        )?;
        let prefix = self.prefix(requirement.as_ref().ok().copied().flatten());
        let policy = binding.map(|binding| PolicyRoots {
            own_only: binding.curator_root.is_none(),
            proof: binding.proof.proof,
            policy_hash: binding.policy_hash,
            own_root: binding.own_root,
            curator_root: binding.curator_root.unwrap_or_default(),
        });

        let co_signer = prefix
            .co_signer
            .as_ref()
            .map(|slot| slot.signer(self.program_id, accounts))
            .transpose()?;
        let spp = accounts
            .get(prefix.spp..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let ring_auth =
            RingAuth::derive(self.program_id)?.check_slot(spp, RING_TRANSACT_RING_CONFIG_INDEX)?;
        let payer = check_funding_signer(spp, TRANSACT_PAYER_INDEX)?;
        let sender = match prefix.signer {
            SignerSlot::Payer => {
                if spp
                    .iter()
                    .any(|account| account.is_signer() && account.address() != payer.address())
                {
                    return Err(CustomRingError::InvalidAnonymousSigner.into());
                }
                *data.sender_commitment()
            }
            SignerSlot::Owners => {
                let owners = self.owner_signers(spp, window.len())?;
                if owners.iter().any(|owner| !owner.is_signer()) {
                    return Err(CustomRingError::MissingOwnerSigner.into());
                }
                let sender = match policy {
                    Some(_) => solana_owner_identity(sole_owner(owners)?.as_array())
                        .map_err(CustomRingError::from)?,
                    None => [0; 32],
                };
                if co_signer.is_some_and(|co_signer| {
                    owners.iter().any(|owner| owner.address() == &co_signer)
                }) {
                    return Err(CustomRingError::CoSignerIsOwner.into());
                }
                sender
            }
            SignerSlot::Delegate(slot) => {
                if !data.interface_transfers.is_empty() {
                    return Err(CustomRingError::DelegatePublicLeg.into());
                }
                let delegate = account_at(accounts, slot.index)?;
                if !delegate.is_signer() || delegate.address() != &slot.expected {
                    return Err(CustomRingError::UnauthorizedDelegate.into());
                }
                if co_signer == Some(slot.expected) {
                    return Err(CustomRingError::CoSignerIsDelegate.into());
                }
                [0; 32]
            }
        };

        let mut groups = window;
        for transfer in &data.interface_transfers {
            let (group, rest) = groups
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(CustomRingError::InvalidSettlementAccounts)?;
            groups = rest;
            if let Some(funder) = funder_account_position(transfer) {
                check_funding_signer(group, funder)?;
            }
        }
        let public_slots = legs.slots()?;
        let withdrawals = match data.policy {
            Some(policy) => custom_ring_interface::policy_withdrawals(
                &data.interface_transfers,
                &window
                    .iter()
                    .map(crate::instructions::loader::LoadedSettlement)
                    .collect::<Vec<_>>(),
                policy.spl_withdrawal_owners,
            )?,
            None => Vec::new(),
        };
        // SPP settles any exit, the anonymous rail leaves only to a destination that names one key.
        let anonymous_parties = match self.signer {
            RailSigner::Payer => {
                let exit = load_anonymous_exit(&data.interface_transfers, window)?;
                let parties = AnonymousParties {
                    payer: payer.address().as_array(),
                    cosigner: co_signer.as_ref().map(Address::as_array),
                    exit_destination: exit.as_ref(),
                };
                Some(parties.identities().map_err(CustomRingError::from)?)
            }
            RailSigner::Owners | RailSigner::Delegate(_) => None,
        };

        requirement?;
        Ok(TransactAccounts {
            policy,
            sender,
            anonymous_parties,
            public_slots,
            withdrawals,
            spp: prefix.spp,
            ring_auth,
        })
    }

    fn prefix(&self, co_signer: Option<CoSignRequirement>) -> Prefix {
        let mut next = Cursor(
            POLICY_INDEX
                + usize::from(self.config.has_policy() || self.data.withdrawal_exemption.is_some()),
        );
        let co_signer = co_signer.map(|requirement| next.pair(requirement));
        let signer = match self.signer {
            RailSigner::Owners => SignerSlot::Owners,
            RailSigner::Payer => SignerSlot::Payer,
            RailSigner::Delegate(expected) => SignerSlot::Delegate(next.slot(expected)),
        };
        Prefix {
            co_signer,
            signer,
            spp: next.0,
        }
    }

    /// The run SPP reads as owner signers, between the nullifier PDAs and the settlement groups.
    fn owner_signers<'s>(
        &self,
        spp: &'s [AccountView],
        settlements: usize,
    ) -> Result<&'s [AccountView], CustomRingError> {
        let trees = match self.data.input_trees {
            InputTrees::One(_) => 1,
            InputTrees::Two { .. } => 2,
        };
        let start = RING_TRANSACT_ACCOUNT_PREFIX_LEN + trees + self.data.nullifiers.len();
        spp.len()
            .checked_sub(settlements)
            .and_then(|end| spp.get(start..end))
            .ok_or(CustomRingError::InvalidSettlementAccounts)
    }
}

struct Slot<T> {
    index: usize,
    expected: T,
}

impl Slot<CoSignRequirement> {
    fn signer(
        &self,
        program_id: &Address,
        accounts: &[AccountView],
    ) -> Result<Address, ProgramError> {
        CoSignerSlot {
            program_id,
            record: account_at(accounts, self.index)?,
            signer: account_at(accounts, self.index + 1)?,
        }
        .verify(self.expected)
    }
}

enum SignerSlot {
    Owners,
    Payer,
    Delegate(Slot<Address>),
}

struct Prefix {
    /// The record, its signer next.
    co_signer: Option<Slot<CoSignRequirement>>,
    signer: SignerSlot,
    spp: usize,
}

struct Cursor(usize);

impl Cursor {
    fn slot<T>(&mut self, expected: T) -> Slot<T> {
        self.0 += 1;
        Slot {
            index: self.0 - 1,
            expected,
        }
    }

    fn pair<T>(&mut self, expected: T) -> Slot<T> {
        let slot = self.slot(expected);
        self.0 += 1;
        slot
    }
}

fn account_at(accounts: &[AccountView], index: usize) -> Result<&AccountView, ProgramError> {
    accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)
}

/// A policy transfer spends for exactly one owner, repeats of it are one signer.
fn sole_owner(owners: &[AccountView]) -> Result<&Address, CustomRingError> {
    let (first, rest) = owners
        .split_first()
        .ok_or(CustomRingError::OwnerSignerCount)?;
    if rest.iter().any(|owner| owner.address() != first.address()) {
        return Err(CustomRingError::OwnerSignerCount);
    }
    Ok(first.address())
}
