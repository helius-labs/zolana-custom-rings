//! The co-signer a ring operation must carry, one rule for the program and the SDKs.

use crate::{CoSignScope, CustomRingError, PublicLeg, RingProgramConfig, SOL_ASSET_ADDRESS};
use solana_address::Address;

pub struct CoSignDemand {
    /// Demands the co-signer whatever its scope.
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

    /// A shared class demands the co-signer unless a verified exemption is supplied.
    pub fn signer(&self, config: &RingProgramConfig) -> Result<Option<Address>, CustomRingError> {
        self.signer_with_exemption(config, false)
    }

    /// Only a verified registry proof may waive the withdrawal class.
    pub fn signer_with_exemption(
        &self,
        config: &RingProgramConfig,
        withdrawal_exempt: bool,
    ) -> Result<Option<Address>, CustomRingError> {
        let co_signer = config.co_signer().copied();
        if self.approval_required {
            return co_signer
                .map(Some)
                .ok_or(CustomRingError::ApprovalWithoutCoSigner);
        }
        let (Some(co_signer), Some(scope)) = (co_signer, config.co_sign_scope()) else {
            return Ok(None);
        };
        let shared = |class| scope.contains(class) && self.classes.contains(class);
        let in_scope = shared(CoSignScope::TRANSFERS)
            || shared(CoSignScope::DEPOSITS)
            || (shared(CoSignScope::WITHDRAWALS)
                && !withdrawal_exempt
                && !self.withdrawals.is_empty());
        Ok(in_scope.then_some(co_signer))
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
        let mut config = RingProgramConfig::zeroed();
        config.co_signer = Address::new_from_array([7; 32]);
        config.co_sign_scope = CoSignScope::WITHDRAWALS.bits();
        assert_eq!(demand.signer(&config), Ok(Some(config.co_signer)));
        assert_eq!(demand.signer_with_exemption(&config, true), Ok(None));
        for scope in [CoSignScope::TRANSFERS, CoSignScope::DEPOSITS] {
            config.co_sign_scope = scope.bits();
            assert_eq!(
                demand.signer_with_exemption(&config, true),
                Ok(Some(config.co_signer))
            );
        }
        config.co_sign_scope = CoSignScope::WITHDRAWALS.bits();
        demand.approval_required = true;
        assert_eq!(
            demand.signer_with_exemption(&config, true),
            Ok(Some(config.co_signer))
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
