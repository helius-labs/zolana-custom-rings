//! Folds the public legs into the statement's public slots, the fold SPP's `assign_public_amounts_and_assets` runs.
//!
//! Both proofs must read the same slots, another order or mint would leave them speaking of different assets.
//!
//! Read after `instructions/transfer/accounts.rs`. Read before `instructions/transfer/verify.rs`.

use custom_ring_interface::CustomRingError;
use custom_ring_interface::{settlement_mints, PublicLeg, PublicSlots};
use pinocchio::AccountView;
use spr_interface::instruction::InterfaceTransfer;

/// `window` is the `settlement_accounts` window SPP reads.
pub(crate) fn public_slots(
    transfers: &[InterfaceTransfer],
    window: &[AccountView],
) -> Result<PublicSlots, CustomRingError> {
    PublicSlots::fold(
        transfers
            .iter()
            .zip(settlement_mints(transfers, window))
            .map(|(transfer, mint)| {
                let mint = mint.map_err(|_| CustomRingError::InvalidSettlementAccounts)?;
                Ok(PublicLeg {
                    transfer: *transfer,
                    mint: mint.map(|account| account.address().to_bytes()),
                })
            }),
    )
}
