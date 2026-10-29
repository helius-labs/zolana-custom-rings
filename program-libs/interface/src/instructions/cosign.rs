//! The co-signer a ring operation must carry, one rule for the program and the SDKs.

use crate::{
    CoSignScope, CoSigner, CustomRingError, PublicLeg, RingProgramConfig, SOL_ASSET_ADDRESS,
};
use solana_address::Address;

#[derive(Clone, Debug)]
pub struct CoSignDemand {
    /// Demands a co-signer of any scope when no class is shared.
    pub approval_required: bool,
    pub classes: CoSignScope,
    /// Public withdrawal total per mint, each mint once.
    pub withdrawals: Vec<(Address, u128)>,
}

impl CoSignDemand {
    /// A transact is a transfer, each leg adds its class and a withdrawal its amount.
    pub fn transact(approval_required: bool, legs: &[PublicLeg]) -> Self {
        let mut classes = CoSignScope::TRANSFERS;
        let mut withdrawals: Vec<(Address, u128)> = Vec::new();
        for leg in legs {
            if leg.transfer.is_deposit() {
                classes = classes | CoSignScope::DEPOSITS;
                continue;
            }
            classes = classes | CoSignScope::WITHDRAWALS;
            let mint = Address::new_from_array(leg.mint.unwrap_or(SOL_ASSET_ADDRESS));
            let amount = u128::from(leg.transfer.amount());
            // A u128 sum of u64 legs never overflows.
            match withdrawals.iter_mut().find(|(seen, _)| *seen == mint) {
                Some((_, total)) => *total += amount,
                None => withdrawals.push((mint, amount)),
            }
        }
        Self {
            approval_required,
            classes,
            withdrawals,
        }
    }

    /// Only a verified exemption proof may waive the withdrawal class.
    #[must_use]
    pub fn exempt_withdrawals(mut self) -> Self {
        self.withdrawals.clear();
        self
    }

    /// `None` when no record covers a class of the operation and no approval is demanded.
    pub fn requirement(
        &self,
        config: &RingProgramConfig,
    ) -> Result<Option<CoSignRequirement>, CustomRingError> {
        let covered = config.co_signers.covered();
        let mut shared = covered.map_or(0, CoSignScope::bits) & self.classes.bits();
        if self.withdrawals.is_empty() {
            shared &= !CoSignScope::WITHDRAWALS.bits();
        }
        if let Some(classes) = CoSignScope::new(shared) {
            return Ok(Some(CoSignRequirement::Covering(classes)));
        }
        if !self.approval_required {
            return Ok(None);
        }
        covered
            .map(|_| Some(CoSignRequirement::Any))
            .ok_or(CustomRingError::ApprovalWithoutCoSigner)
    }
}

/// One `CoSigner` record must satisfy it, its signer signs the operation.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoSignRequirement {
    /// The policy proof demands approval and no class is shared.
    Any,
    Covering(CoSignScope),
}

impl CoSignRequirement {
    pub fn check(self, record: &CoSigner) -> Result<Address, CustomRingError> {
        let covers = match self {
            Self::Any => true,
            Self::Covering(classes) => record.scope().is_some_and(|scope| scope.contains(classes)),
        };
        covers
            .then_some(record.signer)
            .ok_or(CustomRingError::CoSignerOutOfScope)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalExemptionStatement {
    pub root: [u8; 32],
    pub assets: [[u8; 32]; spr_interface::N_PUBLIC_SLOTS],
    pub amounts: [[u8; 32]; spr_interface::N_PUBLIC_SLOTS],
}
impl WithdrawalExemptionStatement {
    pub fn new(root: [u8; 32], demand: &CoSignDemand) -> Result<Self, CustomRingError> {
        let mut result = Self {
            root,
            assets: [[0; 32]; spr_interface::N_PUBLIC_SLOTS],
            amounts: [[0; 32]; spr_interface::N_PUBLIC_SLOTS],
        };
        if demand.withdrawals.len() > result.assets.len() {
            return Err(CustomRingError::InvalidInstructionData);
        }
        for (i, (mint, amount)) in demand.withdrawals.iter().enumerate() {
            result.assets[i] = *zolana_ring_policy::Member::asset(mint)
                .map_err(|_| CustomRingError::InvalidInstructionData)?
                .as_bytes();
            result.amounts[i] = spr_hasher::primitives::right_align(&amount.to_be_bytes());
        }
        Ok(result)
    }
    pub fn hash(&self) -> Result<[u8; 32], spr_hasher::HasherError> {
        let mut fields = vec![
            crate::domain::field(crate::domain::WITHDRAWAL_EXEMPTION),
            self.root,
        ];
        for i in 0..self.assets.len() {
            fields.extend([self.assets[i], self.amounts[i]]);
        }
        spr_hasher::hash_chain::create_hash_chain_4_from_slice(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoSignerCounts;
    use bytemuck::Zeroable;
    use spr_interface::instruction::InterfaceTransfer;
    #[test]
    fn exemption_waives_only_withdrawals_and_gross_totals_ignore_deposits() {
        let legs = [
            PublicLeg {
                transfer: InterfaceTransfer::SolWithdrawal { amount: 60 },
                mint: None,
            },
            PublicLeg {
                transfer: InterfaceTransfer::SolWithdrawal { amount: 60 },
                mint: None,
            },
            PublicLeg {
                transfer: InterfaceTransfer::SolDeposit { amount: 100 },
                mint: None,
            },
        ];
        let mut demand = CoSignDemand::transact(false, &legs);
        assert_eq!(demand.withdrawals, vec![(Address::default(), 120)]);
        let config = |scope: CoSignScope| {
            let mut config = RingProgramConfig::zeroed();
            config.co_signers = CoSignerCounts::default().added(scope).unwrap();
            config
        };
        let covering = |classes| Ok(Some(CoSignRequirement::Covering(classes)));
        let withdrawals = config(CoSignScope::WITHDRAWALS);
        assert_eq!(
            demand.requirement(&withdrawals),
            covering(CoSignScope::WITHDRAWALS)
        );
        let exempt = CoSignDemand::transact(false, &legs).exempt_withdrawals();
        assert_eq!(exempt.requirement(&withdrawals), Ok(None));
        for scope in [CoSignScope::TRANSFERS, CoSignScope::DEPOSITS] {
            assert_eq!(exempt.requirement(&config(scope)), covering(scope));
        }
        let approval = CoSignDemand::transact(true, &legs).exempt_withdrawals();
        assert_eq!(
            approval.requirement(&withdrawals),
            Ok(Some(CoSignRequirement::Any))
        );
        assert_eq!(
            approval.requirement(&RingProgramConfig::zeroed()),
            Err(CustomRingError::ApprovalWithoutCoSigner)
        );
        let hash = WithdrawalExemptionStatement::new([1; 32], &demand)
            .unwrap()
            .hash()
            .unwrap();
        demand.withdrawals[0].1 -= 1;
        assert_ne!(
            hash,
            WithdrawalExemptionStatement::new([1; 32], &demand)
                .unwrap()
                .hash()
                .unwrap()
        );
    }
}
