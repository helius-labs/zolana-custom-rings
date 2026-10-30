use custom_ring_interface::CustomRingError;
use custom_ring_interface::{settlement_mints, PublicLeg, PublicSlots};
use pinocchio::AccountView;
use spr_interface::{
    error::ShieldedPoolError,
    instruction::{instruction_data::validate_interface_transfers, InterfaceTransfer},
};

pub(crate) struct PublicLegs(Vec<PublicLeg>);

impl PublicLegs {
    /// `window` is the `settlement_accounts` window SPP reads.
    pub fn new(
        transfers: &[InterfaceTransfer],
        window: &[AccountView],
    ) -> Result<Self, CustomRingError> {
        validate_interface_transfers(transfers).map_err(|error| match error {
            ShieldedPoolError::TooManyInterfaceTransfers => CustomRingError::TooManyPublicLegs,
            _ => CustomRingError::ZeroPublicLegAmount,
        })?;
        let legs = transfers
            .iter()
            .zip(settlement_mints(transfers, window))
            .map(|(transfer, mint)| {
                Ok(PublicLeg {
                    transfer: *transfer,
                    mint: mint?.map(|account| account.address().to_bytes()),
                })
            })
            .collect::<Result<_, ShieldedPoolError>>()
            .map_err(|_| CustomRingError::InvalidSettlementAccounts)?;
        Ok(Self(legs))
    }

    pub fn legs(&self) -> &[PublicLeg] {
        &self.0
    }

    pub fn slots(&self) -> Result<PublicSlots, CustomRingError> {
        PublicSlots::fold(self.0.iter().copied().map(Ok))
    }
}
