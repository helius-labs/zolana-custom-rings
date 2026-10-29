use async_trait::async_trait;
use custom_ring_interface::{compute_unit_limit, cosign::CoSignDemand, InstructionTag};
use custom_ring_sdk::{
    CustomRing, DelegateMove, DelegatePayment, RelayedTransferInput, RingClient,
    RingIndexerBackend, RingTransfer,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::{AsyncRpc, ComputeBudgetConfig};
use spr_keypair::{NullifierKey, ShieldedAddress};
use spr_transaction::{AssetRegistry, WalletUtxo};
use zolana_ring_client::rpc::{RelayProofInputs, RelayRail};

use crate::{error::RingRpcError, relay::RelayError};

pub struct RelayProofRequest<'a> {
    pub ring: Address,
    pub fee_payer: Address,
    pub proof_inputs: &'a RelayProofInputs,
    /// Verified over `SppProofInputs::message_hash`, the proof takes it on the anonymous rail.
    pub owner_signature: Option<[u8; 64]>,
}

/// The source's notes open under the escrowed key, the source signs nothing.
#[must_use]
pub struct DelegateSeal<'a> {
    pub ring: Address,
    pub delegate: Address,
    pub fee_payer: Address,
    pub source: ShieldedAddress,
    pub nullifier_key: &'a NullifierKey,
    pub notes: &'a [WalletUtxo],
    pub mint: Address,
    pub payments: Vec<DelegatePayment>,
    pub assets: &'a AssetRegistry,
}

pub struct ProvenRelay {
    pub instruction: Instruction,
    pub budget: ComputeBudgetConfig,
    pub co_signer: Option<Address>,
    pub co_sign_demand: CoSignDemand,
    /// The owners or the delegate, each signs the returned message.
    pub signers: Vec<Address>,
}

#[async_trait]
pub trait RelayProver: Send + Sync {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError>;

    /// Selects the notes and seals the delegate's move, `prove` proves it.
    async fn seal_delegate(&self, seal: DelegateSeal<'_>)
        -> Result<RelayProofInputs, RingRpcError>;
}

pub struct SdkRelayProver<R, I> {
    client: RingClient<R, I>,
}

impl<R, I> SdkRelayProver<R, I> {
    pub fn new(client: RingClient<R, I>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<R: AsyncRpc + 'static, I: RingIndexerBackend + 'static> RelayProver for SdkRelayProver<R, I> {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        let mut transfer = RingTransfer::relayed(RelayedTransferInput {
            ring: CustomRing::new(request.ring),
            proof_inputs: request.proof_inputs,
            fee_payer: request.fee_payer,
        });
        if let Some(signature) = request.owner_signature {
            transfer = transfer.with_owner_signature(signature);
        }
        let proven = transfer
            .prove(&self.client)
            .await
            .map_err(RelayError::proof)?;
        let (tag, delegate) = match request.proof_inputs.rail {
            RelayRail::Delegate { delegate } => (InstructionTag::DelegateTransact, Some(delegate)),
            _ => (InstructionTag::Transact, None),
        };
        Ok(ProvenRelay {
            instruction: proven.instruction().map_err(RelayError::proof)?,
            budget: ComputeBudgetConfig::new(compute_unit_limit(tag)),
            co_signer: proven.co_signer,
            signers: proven
                .owner_signers()
                .iter()
                .copied()
                .chain(delegate)
                .collect(),
            co_sign_demand: proven.co_sign_demand,
        })
    }

    async fn seal_delegate(
        &self,
        seal: DelegateSeal<'_>,
    ) -> Result<RelayProofInputs, RingRpcError> {
        let transfer = DelegateMove {
            ring: CustomRing::new(seal.ring),
            delegate: seal.delegate,
            payer: seal.fee_payer,
            source: seal.source,
            source_nullifier_key: seal.nullifier_key,
            utxos: seal.notes,
            mint: seal.mint,
            payments: seal.payments,
            assets: seal.assets,
            co_signer: None,
        }
        .select(&self.client)
        .await
        .map_err(RelayError::proof)?;
        transfer
            .relay_proof_inputs(self.client.zolana())
            .await
            .map_err(RelayError::proof)
    }
}
