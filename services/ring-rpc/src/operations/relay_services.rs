use std::sync::Arc;

use custom_ring_sdk::RingClient;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_client::{AsyncProverClient, AsyncSolanaRpc, AsyncZolanaClient, AsyncZolanaIndexer};

use crate::{
    database::Store, escrow_merge::RingSdkMergeBuilder, landing::SolanaChain,
    managed_merge::MergeBuilder, relay::RelayParts, relay_prover::SdkRelayProver,
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
        let builder = Arc::new(RingSdkMergeBuilder {
            client: ring_client(),
            payer: self.fee_payer.pubkey(),
        });
        RelayServices {
            parts: RelayParts {
                store: self.store,
                prover: Arc::new(SdkRelayProver::new(ring_client())),
                fee_payer: self.fee_payer,
                chain: Arc::new(SolanaChain::new(self.rpc_url)),
            },
            merge: MergeParts { builder },
        }
    }
}
