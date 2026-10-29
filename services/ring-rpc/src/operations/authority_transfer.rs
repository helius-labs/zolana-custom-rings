use custom_ring_interface::RingMode;
use custom_ring_sdk::DelegatePayment;
use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;
use zolana_ring_client::rpc::{
    AuthorityTransferAttestation, PrepareAuthorityTransferRequest, RelayStep,
};

use crate::{
    authorize::WalletCheck, error::RingRpcError, hub::Hub, relay_prover::DelegateSeal,
    replay::ReplayCheck, upstream::TransactionSource, utxos::SpendableNotes,
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthorityTransferError {
    #[error("the signer is not the ring delegate")]
    NotDelegate = -32220,
    #[error("the ring escrows no key to the service")]
    EscrowUnserved = -32221,
    #[error("the source wallet escrows no nullifier key")]
    SourceUnescrowed = -32222,
    #[error("the source address names another nullifier key")]
    SourceKey = -32223,
    #[error("the service runs no relay")]
    RelayUnavailable = -32224,
}

impl AuthorityTransferError {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl From<AuthorityTransferError> for ErrorObjectOwned {
    fn from(error: AuthorityTransferError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

impl<S: TransactionSource> Hub<S> {
    /// A repeated request returns the stored relay step.
    pub async fn prepare_authority_transfer(
        &self,
        request: &PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingRpcError> {
        let relay = self
            .relay()
            .ok_or(AuthorityTransferError::RelayUnavailable)?;
        let (ring, delegate) = (request.ring.0, request.delegate.0);
        let transfer = &request.transfer;
        let service = self.service(Some(ring))?;
        let shared = self.shared();
        let now = shared.clock.now()?;
        // 1. The named key signed the transfer for the service and ring.
        let nonce = WalletCheck {
            wallet: delegate,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &AuthorityTransferAttestation {
                target: service.read_target(),
                delegate,
                transfer: transfer.clone(),
            },
            now,
        }
        .decide()?;
        let relay_id = request
            .relay_id()
            .map_err(|_| RingRpcError::StateUnavailable)?;
        if let Some(step) = relay.stored(&relay_id).await? {
            return Ok(step);
        }
        // 2. The config names the key its delegate and escrows to the auditor key held here.
        let config = shared.source.ring_config(ring).await?;
        let config = config
            .filter(|config| config.delegate == Some(delegate))
            .ok_or(AuthorityTransferError::NotDelegate)?;
        if config.mode != RingMode::ConfidentialEscrow
            || config.auditor_pubkey != service.auditor_pubkey()
        {
            return Err(AuthorityTransferError::EscrowUnserved.into());
        }
        shared.replay.accept(ReplayCheck {
            ring,
            nonce,
            timestamp: request.timestamp,
            now,
        })?;
        // 3. The escrowed secret opens to the source's nullifier key and stays in memory.
        let source = transfer.source.0;
        let owner_key = source
            .solana_address()
            .map_err(|_| AuthorityTransferError::SourceUnescrowed)?
            .to_bytes();
        let nullifier_key = service
            .escrowed_nullifier_key(&owner_key)?
            .ok_or(AuthorityTransferError::SourceUnescrowed)?;
        if nullifier_key.pubkey()? != source.nullifier_pubkey {
            return Err(AuthorityTransferError::SourceKey.into());
        }
        // 4. Only notes the service opened for the source under that key and mint fund the move.
        let assets = shared.due_assets().await;
        let mint = transfer.mint.0;
        let notes = shared.store(ring).spendable(SpendableNotes {
            ring,
            owner_key,
            mint: assets.registry().mint(&mint)?,
            nullifier_key: &nullifier_key,
        })?;
        relay
            .prepare_delegated(
                relay_id,
                DelegateSeal {
                    ring,
                    delegate,
                    source,
                    nullifier_key: &nullifier_key,
                    notes: &notes,
                    mint,
                    payments: transfer
                        .payments
                        .iter()
                        .map(|payment| DelegatePayment {
                            recipient: payment.recipient.0,
                            amount: payment.amount,
                        })
                        .collect(),
                    assets: assets.registry(),
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use custom_ring_interface::cosign::CoSignDemand;
    use solana_address::Address;
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_message::VersionedMessage;
    use solana_signature::Signature;
    use solana_signer::Signer;
    use solana_transaction::versioned::VersionedTransaction;
    use spr_client::ComputeBudgetConfig;
    use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress, ViewingKey, X25519Keypair};
    use spr_transaction::instructions::transact::ExternalData;
    use zeroize::Zeroizing;
    use zolana_ring_client::rpc::{
        unix_now, AuthorityPayment, AuthorityTransfer, AuthorityTransferAttestation,
        AuthorityTransferRequest, ReadTarget, RelayProofInputs, RelayRail, SignedRequest,
    };

    use super::*;
    use crate::{
        database::Store,
        managed_merge::tests::{Fixture, RecordingRelay, GENESIS, MINT, RING},
        relay::{RelayParts, RelayPayload, ServedRings},
        relay_chain::{ChainOutcome, RelayChain},
        relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
    };

    #[derive(Default)]
    struct SealingProver {
        sealed: Mutex<Vec<Sealed>>,
        proven: Mutex<Vec<(Address, [u8; 31])>>,
    }

    struct Sealed {
        delegate: Address,
        secret: [u8; 31],
        nullifiers: Vec<[u8; 32]>,
    }

    #[async_trait]
    impl RelayProver for SealingProver {
        async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
            let RelayPayload::Transfer(proof_inputs) = request.payload else {
                panic!("an authority transfer proves a transfer");
            };
            let RelayRail::Delegate { delegate } = proof_inputs.rail else {
                panic!("an authority transfer proves on the delegate rail");
            };
            self.proven
                .lock()
                .expect("proven")
                .push((delegate, *proof_inputs.nullifier_key.secret()));
            Ok(ProvenRelay {
                instruction: Instruction {
                    program_id: request.ring,
                    accounts: vec![
                        AccountMeta::new(request.fee_payer, true),
                        AccountMeta::new_readonly(delegate, true),
                    ],
                    data: vec![21],
                },
                budget: ComputeBudgetConfig::new(400_000),
                co_signer: None,
                co_sign_demand: CoSignDemand::transact(false, &[]),
                signers: vec![delegate],
            })
        }

        async fn seal_delegate(
            &self,
            seal: DelegateSeal<'_>,
            _parties: RelayParties,
        ) -> Result<RelayProofInputs, RingRpcError> {
            self.sealed.lock().expect("sealed").push(Sealed {
                delegate: seal.delegate,
                secret: *seal.nullifier_key.secret(),
                nullifiers: seal.notes.iter().map(|note| note.nullifier).collect(),
            });
            let tx_viewing_key = ViewingKey::new();
            Ok(RelayProofInputs {
                rail: RelayRail::Delegate {
                    delegate: seal.delegate,
                },
                ring_program_id: seal.ring,
                sender: seal.source,
                nullifier_key: seal.nullifier_key.clone(),
                external_data: ExternalData::new(
                    *tx_viewing_key.pubkey().as_bytes(),
                    [0; 16],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                tx_viewing_key,
                audit_ephemeral_key: Zeroizing::new([0; 32]),
                inputs: Vec::new(),
                outputs: Vec::new(),
                interface_transfer_accounts: Vec::new(),
                blinding_seed: [0; 32],
                output_tree_id: 1,
            })
        }
    }

    struct IdleChain;

    #[async_trait]
    impl RelayChain for IdleChain {
        async fn slot(&self) -> Result<u64, RingRpcError> {
            Ok(1)
        }

        async fn latest_blockhash(&self) -> Result<(Hash, u64), RingRpcError> {
            Ok((Hash::new_from_array([4; 32]), 100))
        }

        async fn block_height(&self) -> Result<u64, RingRpcError> {
            Ok(1)
        }

        async fn send(&self, _transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
            Ok(())
        }

        async fn outcome(
            &self,
            _signature: Signature,
        ) -> Result<Option<ChainOutcome>, RingRpcError> {
            Ok(None)
        }
    }

    async fn served(delegate: Address) -> (Fixture, Arc<SealingProver>) {
        let prover = Arc::new(SealingProver::default());
        let relay = RelayParts {
            store: Store::open("sqlite::memory:", 1).await.expect("store"),
            prover: prover.clone(),
            submit: Arc::new(RecordingRelay::default()),
            chain: Arc::new(IdleChain),
            rings: ServedRings::One(RING),
        };
        (Fixture::serving(Some(delegate), Some(relay)).await, prover)
    }

    fn address(signing: &Keypair, nullifier_key: &NullifierKey) -> ShieldedAddress {
        ShieldedAddress {
            signing_pubkey: PublicKey::from_ed25519(signing.pubkey().as_array()),
            nullifier_pubkey: nullifier_key.pubkey().expect("nullifier pk"),
            viewing_pubkey: X25519Keypair::new().pubkey(),
        }
    }

    fn request(
        fixture: &Fixture,
        signer: &Keypair,
        source: ShieldedAddress,
    ) -> PrepareAuthorityTransferRequest {
        let recipient = address(
            &Keypair::new_from_array([13; 32]),
            &NullifierKey::from_secret([13; 31]),
        );
        let request: AuthorityTransferRequest = SignedRequest::new(AuthorityTransferAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            delegate: signer.pubkey(),
            transfer: AuthorityTransfer {
                source: source.into(),
                mint: MINT.into(),
                payments: vec![AuthorityPayment {
                    recipient: recipient.into(),
                    amount: 15,
                }],
            },
        });
        request
            .at(unix_now().expect("clock"))
            .sign(signer)
            .expect("signed request")
    }

    #[tokio::test]
    async fn a_delegate_request_spends_the_source_notes_under_the_escrowed_key() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2);

        let step = fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &delegate, address(&wallet, &escrowed)))
            .await
            .expect("prepared transfer");

        let RelayStep::SignMessage { message, .. } = step else {
            panic!("the delegate signs the authority transfer, got {step:?}");
        };
        let message: VersionedMessage = wincode::deserialize(&message.0).expect("message");
        assert!(message.static_account_keys().contains(&delegate.pubkey()));
        let [sealed] = std::mem::take(&mut *prover.sealed.lock().expect("sealed"))
            .try_into()
            .unwrap_or_else(|_| panic!("one seal"));
        assert_eq!(
            (sealed.delegate, sealed.secret),
            (delegate.pubkey(), *escrowed.secret())
        );
        assert_eq!(sealed.nullifiers.len(), 2);
        assert_eq!(
            *prover.proven.lock().expect("proven"),
            [(delegate.pubkey(), *escrowed.secret())]
        );
    }

    #[tokio::test]
    async fn a_request_signed_by_another_key_is_refused() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2);
        let impostor = Keypair::new_from_array([22; 32]);

        let refused = fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &impostor, address(&wallet, &escrowed)))
            .await
            .expect_err("a key other than the delegate is refused");

        assert_eq!(ErrorObjectOwned::from(refused).code(), -32220);
        assert!(prover.sealed.lock().expect("sealed").is_empty());
    }
}
