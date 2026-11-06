use async_trait::async_trait;
use custom_ring_interface::{compute_unit_limit, InstructionTag};
use custom_ring_sdk::{
    CustomRing, CustomRingMerge, MergeProofInput, ProvenCustomRingMerge, RingClient, RingError,
    RingIndexerBackend,
};
use solana_address::Address;
use spr_client::{compile_message, AsyncRpc, ComputeBudgetConfig};
use spr_interface::pda;
use spr_keypair::{PublicKey, ShieldedAddress, ViewingKey};
use spr_transaction::{LocalShieldedKeys, TransactionError};

use crate::{
    error::RingRpcError,
    managed_merge::{BuiltMerge, MergeBuilder, OwnerMerge},
};

/// `payer` must be the relay fee payer.
pub struct RingSdkMergeBuilder<R, I> {
    pub client: RingClient<R, I>,
    pub payer: Address,
}

#[async_trait]
impl<R, I> MergeBuilder for RingSdkMergeBuilder<R, I>
where
    R: AsyncRpc + Send + Sync,
    I: RingIndexerBackend + Send + Sync,
{
    async fn build(&self, merge: OwnerMerge<'_>) -> Result<BuiltMerge, RingRpcError> {
        let proven = OwnerMergeProof {
            client: &self.client,
            payer: self.payer,
        }
        .prove(merge)
        .await
        .map_err(RingRpcError::MergeBuild)?;
        let built = async {
            let (blockhash, last_valid_block_height) =
                self.client.zolana().get_latest_blockhash().await?;
            let message = compile_message(
                &self.payer,
                &[proven.instruction(self.payer)?],
                blockhash,
                ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge)),
            )?;
            Ok::<_, RingError>(BuiltMerge {
                message,
                last_valid_block_height,
            })
        };
        built
            .await
            .map_err(|error| RingRpcError::MergeBuild(error.into()))
    }
}

/// The merged note lands in the input tree.
#[must_use]
pub(crate) struct OwnerMergeProof<'a, R, I> {
    pub client: &'a RingClient<R, I>,
    pub payer: Address,
}

impl<R: AsyncRpc, I: RingIndexerBackend> OwnerMergeProof<'_, R, I> {
    pub async fn prove(
        self,
        merge: OwnerMerge<'_>,
    ) -> Result<ProvenCustomRingMerge, Box<RingError>> {
        let proven = async {
            let tree_id = merge
                .inputs
                .first()
                .map(|input| input.tree_id)
                .ok_or(TransactionError::NoInputs)?;
            let viewing = ViewingKey::new();
            // The merge output commits to the signing and nullifier keys alone.
            let keys = LocalShieldedKeys::new(
                ShieldedAddress {
                    signing_pubkey: PublicKey::from_ed25519(merge.owner.as_array()),
                    nullifier_pubkey: merge.nullifier_key.pubkey()?,
                    viewing_pubkey: viewing.pubkey(),
                },
                vec![viewing],
                merge.nullifier_key.clone(),
            )?;
            let tree = pda::tree(tree_id);
            CustomRingMerge::new(CustomRing::new(merge.ring), merge.inputs, None)?
                .with_output_tree_id(tree_id)
                .encrypt(&keys)?
                .prove(
                    MergeProofInput {
                        nullifier_key: merge.nullifier_key.clone(),
                        input_tree: tree,
                        output_tree: tree,
                    },
                    self.payer,
                    self.client,
                )
                .await
        };
        proven.await.map_err(Box::new)
    }
}
