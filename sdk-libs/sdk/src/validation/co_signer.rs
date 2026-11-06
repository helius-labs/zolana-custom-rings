//! The co-signer a ring operation carries, decided by the program's own rule.

use custom_ring_interface::{cosign::CoSignDemand, CustomRingError};
use solana_address::Address;
use solana_instruction::AccountMeta;
use spr_client::AsyncRpc;

use crate::{CustomRing, CustomRingConfig, RingError};

#[must_use]
pub(crate) struct CoSignerChoice<'a> {
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub demand: CoSignDemand,
    pub supplied: Vec<Address>,
}

impl CoSignerChoice<'_> {
    pub async fn resolve(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<Vec<Address>, RingError> {
        let mut requirement = self.demand.requirement(self.config.account());
        let mut supplied = self.supplied.into_iter();
        let mut signers = Vec::new();
        while let Some(current) = requirement {
            let signer = supplied.next().ok_or(CustomRingError::MissingCoSigner)?;
            let record = self
                .ring
                .co_signer(rpc, &signer)
                .await?
                .ok_or(CustomRingError::InvalidCoSignerRecord)?;
            let cover = current.cover(record.account())?;
            signers.push(cover.signer);
            requirement = cover.rest;
        }
        Ok(signers)
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
