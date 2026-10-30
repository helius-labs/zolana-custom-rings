//! A withdrawal exemption opens only the mints actually withdrawn by this transaction.
use crate::{
    client::{RingClient, RingIndexerBackend},
    prover::{to_instruction_proof, RingRequest},
    records::RecordReads,
    request::{MemberOpening, WithdrawalExemption},
    submission::BoundRoot,
    CustomRing, CustomRingConfig, RingError,
};
use custom_ring_interface::{
    cosign::{CoSignDemand, WithdrawalExemptionStatement},
    key_catalog::RingCircuit,
    CustomRingProof,
};
use spr_client::AsyncRpc;
use zolana_ring_client::AsyncRingIndexer;

pub(super) struct Exemption {
    pub root: BoundRoot,
    request: WithdrawalExemption,
}
impl Exemption {
    pub async fn read(
        ring: CustomRing,
        config: &CustomRingConfig,
        demand: &CoSignDemand,
        own: Option<BoundRoot>,
        client: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<Option<Self>, RingError> {
        // The proof can waive only withdrawals, never approval, transfers or deposits.
        if demand.withdrawals.is_empty()
            || demand.signer(config.account())?.is_none()
            || demand
                .signer_with_exemption(config.account(), true)?
                .is_some()
        {
            return Ok(None);
        }
        let root = match own {
            Some(root) => root,
            None => {
                let Some(registry) = ring.registry(client).await? else {
                    return Ok(None);
                };
                BoundRoot::current(ring, &registry)
            }
        };
        let statement = WithdrawalExemptionStatement::new(root.root, demand)?;
        let reads = RecordReads {
            root,
            members: &statement.assets[..demand.withdrawals.len()],
        }
        .read(client)
        .await?;
        if reads
            .iter()
            .zip(&demand.withdrawals)
            .any(|(read, (_, amount))| {
                read.record().is_none_or(|record| {
                    *amount > u128::from(record.mint_policy.withdrawal_threshold)
                })
            })
        {
            return Ok(None);
        }
        let mut entries: Vec<_> = reads
            .iter()
            .map(|read| Some(MemberOpening::from(&read.opening)))
            .collect();
        entries.resize_with(statement.assets.len(), || None);
        Ok(Some(Self {
            root,
            request: WithdrawalExemption {
                public_input_hash: statement.hash()?,
                root: root.root,
                assets: statement.assets,
                amounts: statement.amounts,
                entries,
            },
        }))
    }
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<CustomRingProof, RingError> {
        to_instruction_proof(
            RingRequest::new(RingCircuit::WithdrawalExemption, &self.request)?
                .prove(client, self.request.public_input_hash)
                .await?,
        )
    }
}
