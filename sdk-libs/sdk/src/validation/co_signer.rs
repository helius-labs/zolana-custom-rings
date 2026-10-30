//! The co-signer a ring operation carries, decided by the program's own rule.

use custom_ring_interface::{
    cosign::{CoSignDemand, CoSignRequirement},
    CustomRingError,
};
use solana_address::Address;
use solana_instruction::AccountMeta;
use spr_client::AsyncRpc;

use crate::{CustomRing, CustomRingConfig, RingError};

#[must_use]
pub(crate) struct CoSignerChoice<'a> {
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub demand: &'a CoSignDemand,
    /// The caller's co-signer, read only when the demand needs one.
    pub supplied: Option<Address>,
}

impl CoSignerChoice<'_> {
    /// The supplied signer with its record unread, `None` when nothing is demanded.
    pub fn unchecked(&self) -> Result<Option<(CoSignRequirement, Address)>, RingError> {
        let Some(requirement) = self.demand.requirement(self.config.account())? else {
            return Ok(None);
        };
        let signer = self.supplied.ok_or(CustomRingError::MissingCoSigner)?;
        Ok(Some((requirement, signer)))
    }

    /// The supplied signer, its record covering the demand.
    pub async fn resolve(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<Address>, RingError> {
        let Some((requirement, signer)) = self.unchecked()? else {
            return Ok(None);
        };
        let record = self
            .ring
            .co_signer(rpc, &signer)
            .await?
            .ok_or(CustomRingError::InvalidCoSignerRecord)?;
        Ok(Some(requirement.check(record.account())?))
    }
}

impl CustomRing {
    /// The program reads the record first, the signer next.
    pub fn co_signer_metas(self, signer: Address) -> [AccountMeta; 2] {
        [
            AccountMeta::new_readonly(self.co_signer_pda(&signer), false),
            AccountMeta::new_readonly(signer, true),
        ]
    }
}
