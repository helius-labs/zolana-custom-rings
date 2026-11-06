//! Publishes a rotated viewing key in the ring's tracking authorization, the account senders read.
//!
//! Read after `zolana_ring_client::ViewingRotation`, whose stored keys and history come first.

use custom_ring_interface::tracking::TrackingAuthorization;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, AsyncRpc, ComputeBudgetConfig};
use spr_keypair::X25519Pubkey;
use spr_transaction::ShieldedKeys;
use zolana_ring_client::{rpc::ENROLL_COMPUTE_UNITS, ViewingHistory};
use zolana_ring_keys::RotatingRingKeys;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    enrollment::{rotation_request, EnrollInstruction},
    submission::check_transaction_size,
    CustomRing, RingError,
};

#[cfg(test)]
#[path = "../tests/operations/viewing_rotation.rs"]
mod tests;

#[must_use]
pub struct RotateViewingKey<'a> {
    pub ring: CustomRing,
    pub owner: &'a (dyn Signer + Sync),
    /// May be the owner.
    pub payer: &'a (dyn Signer + Sync),
    pub keys: &'a RotatingRingKeys,
    pub history: &'a ViewingHistory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotatedViewingKey {
    pub viewing_pubkey: X25519Pubkey,
    /// `None` when the authorization already held the key.
    pub signature: Option<Signature>,
}

impl RotateViewingKey<'_> {
    pub async fn send<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
    ) -> Result<RotatedViewingKey, RingError> {
        // 1. No sync reads a key the history lacks, publishing one strands every later payment.
        let address = self.keys.address()?;
        if self.history.current().viewing_pubkey() != address.viewing_pubkey {
            return Err(RingError::ViewingHistoryNotCurrent);
        }
        // 2. An authorization key the wallet never held is another copy's, publishing over it strands its payments.
        let owner = self.owner.pubkey();
        let registry = self
            .ring
            .require_config(client.zolana())
            .await?
            .account()
            .tracking;
        let enrolled = read_authorization(client, &registry, &owner).await?;
        if enrolled.nullifier_pk != address.nullifier_pubkey {
            return Err(RingError::AlreadyEnrolled { owner });
        }
        if !self
            .keys
            .viewing_public_keys()
            .iter()
            .any(|key| key.u() == enrolled.viewing_u)
        {
            return Err(RingError::ViewingKeyNotHeld { owner });
        }
        let viewing_u = address.viewing_pubkey.u();
        if enrolled.viewing_u == viewing_u {
            return Ok(RotatedViewingKey {
                viewing_pubkey: address.viewing_pubkey,
                signature: None,
            });
        }
        // 3. The rotation repeats the final key, tag and seal, the program refuses any other change.
        let payer = self.payer.pubkey();
        let instruction = EnrollInstruction {
            payer,
            owner,
            tracking_registry: registry,
            request: rotation_request(&enrolled, viewing_u),
        }
        .instruction();
        let budget = ComputeBudgetConfig::new(ENROLL_COMPUTE_UNITS);
        check_transaction_size(&payer, &instruction, budget)?;
        let (blockhash, _) = client.get_latest_blockhash().await?;
        let message = compile_message(&payer, &[instruction], blockhash, budget)?;
        let signers: [&dyn Signer; 2] = [self.owner, self.payer];
        let signature = client
            .process_transaction(sign_transaction(message, &signers)?)
            .await?;
        // 4. A concurrent rotation of the owner can leave the authorization at another key.
        if read_authorization(client, &registry, &owner)
            .await?
            .viewing_u
            != viewing_u
        {
            return Err(RingError::ViewingKeyNotPublished { owner });
        }
        Ok(RotatedViewingKey {
            viewing_pubkey: address.viewing_pubkey,
            signature: Some(signature),
        })
    }
}

async fn read_authorization<R: AsyncRpc, I: RingIndexerBackend>(
    client: &RingClient<R, I>,
    registry: &Address,
    owner: &Address,
) -> Result<TrackingAuthorization, RingError> {
    let (authorization, _) = TrackingAuthorization::find_address(registry, owner);
    client
        .get_account(authorization)
        .await?
        .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data))
        .filter(|enrolled| enrolled.registry == *registry && enrolled.owner == *owner)
        .ok_or(RingError::RotationUnenrolled { owner: *owner })
}
