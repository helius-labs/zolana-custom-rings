use std::sync::Arc;

use custom_ring_sdk::RingClient;
use solana_keypair::Keypair;
use spr_client::{AsyncProverClient, AsyncSolanaRpc, AsyncZolanaClient, AsyncZolanaIndexer};

use crate::{
    database::Store,
    escrow_merge::RingSdkMergeBuilder,
    managed_merge::MergeBuilder,
    relay::RelayParts,
    relay_chain::{FeePayerSubmit, SolanaRelayChain},
    relay_prover::SdkRelayProver,
    relay_submit::RelaySubmit,
};

/// The relay and the managed merge pay through one fee payer.
#[must_use]
pub struct RelayServices {
    pub(crate) parts: RelayParts,
    pub(crate) merge: MergeParts,
}

pub(crate) struct MergeParts {
    pub(crate) builder: Arc<dyn MergeBuilder>,
}

#[must_use]
pub struct RelayServicesInit<'a> {
    pub fee_payer: Keypair,
    pub store: Store,
    pub rpc_url: &'a str,
    pub indexer_url: &'a str,
    pub prover_url: &'a str,
}

impl RelayServicesInit<'_> {
    pub fn build(self) -> RelayServices {
        let ring_client = || {
            let zolana = AsyncZolanaClient::new(
                AsyncSolanaRpc::new(self.rpc_url),
                AsyncZolanaIndexer::new(self.indexer_url),
                AsyncProverClient::new(self.prover_url.to_owned()),
            );
            RingClient::new(zolana, AsyncProverClient::new(self.prover_url.to_owned()))
        };
        let chain = Arc::new(SolanaRelayChain::new(AsyncSolanaRpc::new(self.rpc_url)));
        let submit = Arc::new(FeePayerSubmit::new(self.fee_payer, chain.clone()));
        let builder = Arc::new(RingSdkMergeBuilder {
            client: ring_client(),
            payer: submit.fee_payer(),
        });
        RelayServices {
            parts: RelayParts {
                store: self.store,
                prover: Arc::new(SdkRelayProver::new(ring_client())),
                submit,
                chain,
            },
            merge: MergeParts { builder },
        }
    }
}
