use async_trait::async_trait;
use custom_ring_sdk::SignatureHistory;
use solana_address::Address;
use solana_commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_hash::Hash;
use solana_message::VersionedMessage;
use solana_rpc_client_api::config::RpcSimulateTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};
use spr_client::{AsyncRpc, AsyncSolanaRpc, ClientError, RpcSendTransactionConfig};

use crate::{error::RingRpcError, relay::RelayError};

#[async_trait]
pub trait ChainSubmit: Send + Sync {
    async fn slot(&self) -> Result<u64, RingRpcError>;

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError>;

    /// Finalized height, pending signatures cannot expire against a newer fork.
    async fn block_height(&self) -> Result<u64, RingRpcError>;

    async fn account_data(&self, address: Address) -> Result<Option<Vec<u8>>, RingRpcError>;

    async fn rent_exempt_lamports(&self, data_len: usize) -> Result<u64, RingRpcError>;

    /// A transaction the cluster already processed counts as sent, one its preflight refuses fails.
    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError>;

    /// `None` until success or failure is finalized.
    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError>;

    /// Signatures stay unchecked, every program and proof check runs.
    async fn simulate(&self, message: &VersionedMessage) -> Result<Simulation, RingRpcError>;
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Simulation {
    Passed,
    Refused { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    Confirmed { slot: u64 },
    Failed { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestBlockhash {
    pub blockhash: Hash,
    pub last_valid_block_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub signature: Signature,
    pub last_valid_block_height: u64,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Landing {
    Pending,
    Landed(ChainOutcome),
    /// Final, the blockhash can no longer land the signature.
    Expired,
}

pub struct SolanaChain {
    rpc: AsyncSolanaRpc,
}

impl From<(Hash, u64)> for LatestBlockhash {
    fn from((blockhash, last_valid_block_height): (Hash, u64)) -> Self {
        Self {
            blockhash,
            last_valid_block_height,
        }
    }
}

impl Attempt {
    pub async fn landing(self, chain: &dyn ChainSubmit) -> Result<Landing, RingRpcError> {
        if let Some(outcome) = chain.outcome(self.signature).await? {
            return Ok(Landing::Landed(outcome));
        }
        if chain.block_height().await? <= self.last_valid_block_height {
            return Ok(Landing::Pending);
        }
        // The signature can land between the first lookup and the height read.
        Ok(chain
            .outcome(self.signature)
            .await?
            .map_or(Landing::Expired, Landing::Landed))
    }
}

impl SolanaChain {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc: AsyncSolanaRpc::new(rpc_url),
        }
    }
}

#[async_trait]
impl ChainSubmit for SolanaChain {
    async fn account_data(&self, address: Address) -> Result<Option<Vec<u8>>, RingRpcError> {
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .map(|account| account.data))
    }

    async fn rent_exempt_lamports(&self, data_len: usize) -> Result<u64, RingRpcError> {
        Ok(self
            .rpc
            .get_minimum_balance_for_rent_exemption(data_len)
            .await?)
    }

    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.rpc.get_slot().await?)
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        Ok(self.rpc.get_latest_blockhash().await?.into())
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        self.rpc
            .client()
            .get_block_height_with_commitment(CommitmentConfig::finalized())
            .await
            .map_err(|error| ClientError::Rpc(format!("get_block_height: {error}")).into())
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(CommitmentLevel::Confirmed),
            ..RpcSendTransactionConfig::default()
        };
        let Err(error) = self
            .rpc
            .send_transaction_with_config(transaction, config)
            .await
        else {
            return Ok(());
        };
        let refusal = match &error {
            ClientError::SolanaRpcTransaction { source, .. } => source.get_transaction_error(),
            _ => None,
        };
        match refusal {
            Some(TransactionError::AlreadyProcessed) => Ok(()),
            Some(refused) => Err(RelayError::SendRefused {
                reason: refused.to_string(),
            }
            .into()),
            None => Err(error.into()),
        }
    }

    async fn outcome(&self, signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        // Without history a landed signature reads as expired once the status cache drops it.
        let statuses = self
            .rpc
            .signature_statuses_with_history(vec![signature])
            .await?;
        let Some(Some(status)) = statuses.into_iter().next() else {
            return Ok(None);
        };
        Ok(finalized_outcome(status))
    }

    async fn simulate(&self, message: &VersionedMessage) -> Result<Simulation, RingRpcError> {
        let transaction = VersionedTransaction {
            signatures: vec![
                Signature::default();
                usize::from(message.header().num_required_signatures)
            ],
            message: message.clone(),
        };
        let config = RpcSimulateTransactionConfig {
            sig_verify: false,
            replace_recent_blockhash: true,
            commitment: Some(CommitmentConfig::confirmed()),
            ..RpcSimulateTransactionConfig::default()
        };
        let simulated = self
            .rpc
            .client()
            .simulate_transaction_with_config(&transaction, config)
            .await
            .map_err(|error| ClientError::Rpc(format!("simulate_transaction: {error}")))?
            .value;
        Ok(match simulated.err {
            None => Simulation::Passed,
            Some(error) => Simulation::Refused {
                reason: error.to_string(),
            },
        })
    }
}

fn finalized_outcome(status: TransactionStatus) -> Option<ChainOutcome> {
    if status.confirmation_status != Some(TransactionConfirmationStatus::Finalized) {
        return None;
    }
    Some(match status.err {
        None => ChainOutcome::Confirmed { slot: status.slot },
        Some(error) => ChainOutcome::Failed {
            reason: error.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use super::*;

    struct ScriptedLanding {
        statuses: Mutex<VecDeque<Result<Option<TransactionStatus>, RingRpcError>>>,
        finalized_height: Option<u64>,
    }

    #[async_trait]
    impl ChainSubmit for ScriptedLanding {
        async fn simulate(
            &self,
            _message: &solana_message::VersionedMessage,
        ) -> Result<Simulation, RingRpcError> {
            Ok(Simulation::Passed)
        }

        async fn account_data(
            &self,
            _address: solana_address::Address,
        ) -> Result<Option<Vec<u8>>, RingRpcError> {
            Ok(None)
        }

        async fn rent_exempt_lamports(&self, _data_len: usize) -> Result<u64, RingRpcError> {
            Ok(0)
        }

        async fn slot(&self) -> Result<u64, RingRpcError> {
            unreachable!()
        }

        async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
            unreachable!()
        }

        async fn block_height(&self) -> Result<u64, RingRpcError> {
            self.finalized_height.ok_or(RingRpcError::StateUnavailable)
        }

        async fn send(&self, _transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
            unreachable!()
        }

        async fn outcome(
            &self,
            _signature: Signature,
        ) -> Result<Option<ChainOutcome>, RingRpcError> {
            self.statuses
                .lock()
                .expect("statuses")
                .pop_front()
                .expect("scripted status")
                .map(|status| status.and_then(finalized_outcome))
        }
    }

    fn attempt() -> Attempt {
        Attempt {
            signature: Signature::default(),
            last_valid_block_height: 50,
        }
    }

    fn status(
        confirmation_status: TransactionConfirmationStatus,
        err: Option<TransactionError>,
    ) -> TransactionStatus {
        TransactionStatus {
            slot: 41,
            confirmations: (confirmation_status != TransactionConfirmationStatus::Finalized)
                .then_some(1),
            status: err.clone().map_or(Ok(()), Err),
            err,
            confirmation_status: Some(confirmation_status),
        }
    }

    #[tokio::test]
    async fn unfinalized_success_and_failure_keep_the_attempt_pending() {
        for confirmation in [
            TransactionConfirmationStatus::Processed,
            TransactionConfirmationStatus::Confirmed,
        ] {
            for error in [None, Some(TransactionError::AccountNotFound)] {
                let chain = ScriptedLanding {
                    statuses: Mutex::new(VecDeque::from([Ok(Some(status(
                        confirmation.clone(),
                        error,
                    )))])),
                    finalized_height: Some(attempt().last_valid_block_height),
                };
                assert_eq!(
                    attempt().landing(&chain).await.expect("landing"),
                    Landing::Pending
                );
            }
        }
    }

    #[tokio::test]
    async fn an_orphaned_confirmation_expires_after_finalized_height_passes_the_window() {
        let chain = ScriptedLanding {
            statuses: Mutex::new(VecDeque::from([
                Ok(Some(status(TransactionConfirmationStatus::Confirmed, None))),
                Ok(None),
            ])),
            finalized_height: Some(attempt().last_valid_block_height + 1),
        };
        assert_eq!(
            attempt().landing(&chain).await.expect("landing"),
            Landing::Expired
        );
    }

    #[tokio::test]
    async fn finalization_between_status_and_height_wins_over_expiry() {
        for (error, expected) in [
            (None, ChainOutcome::Confirmed { slot: 41 }),
            (
                Some(TransactionError::AccountNotFound),
                ChainOutcome::Failed {
                    reason: TransactionError::AccountNotFound.to_string(),
                },
            ),
        ] {
            let finalized = status(TransactionConfirmationStatus::Finalized, error);
            let chain = ScriptedLanding {
                statuses: Mutex::new(VecDeque::from([Ok(None), Ok(Some(finalized))])),
                finalized_height: Some(attempt().last_valid_block_height + 1),
            };
            assert_eq!(
                attempt().landing(&chain).await.expect("landing"),
                Landing::Landed(expected),
            );
        }
    }

    #[tokio::test]
    async fn status_or_height_errors_never_expire_an_attempt() {
        for chain in [
            ScriptedLanding {
                statuses: Mutex::new(VecDeque::from([Err(RingRpcError::StateUnavailable)])),
                finalized_height: Some(attempt().last_valid_block_height + 1),
            },
            ScriptedLanding {
                statuses: Mutex::new(VecDeque::from([Ok(None)])),
                finalized_height: None,
            },
            ScriptedLanding {
                statuses: Mutex::new(VecDeque::from([
                    Ok(None),
                    Err(RingRpcError::StateUnavailable),
                ])),
                finalized_height: Some(attempt().last_valid_block_height + 1),
            },
        ] {
            assert!(matches!(
                attempt().landing(&chain).await,
                Err(RingRpcError::StateUnavailable),
            ));
        }
    }
}
