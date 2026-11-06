use std::collections::HashSet;

use async_trait::async_trait;
use custom_ring_sdk::{
    AllowedNullifiers, DelegateFunding, DelegatePayment, DelegateSourceError, DelegateWithdrawal,
    ResolvedSource, SourceEnrollment,
};
use jsonrpsee::types::ErrorObjectOwned;
use spr_indexer_api::Hash;
use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress};
use spr_transaction::{Mint, WalletUtxo};
use thiserror::Error;
use zolana_ring_client::rpc::{
    Attestation, AuthorityTransferAttestation, DelegateNotesAttestation,
    DelegateSnapshotReleaseAttestation, GetDelegateNotesRequest, GetDelegateNotesResponse,
    GetListSaltRequest, GetListSaltResponse, ListSaltAttestation, PrepareAuthorityTransferRequest,
    RelayStep,
};

use crate::{
    audit::{AuditService, WALLET_NOTE_PAGE_LIMIT},
    authorize::WalletCheck,
    error::RingRpcError,
    hub::Hub,
    relay_prover::{DelegateSeal, SealedSource},
    replay::ReplayCheck,
    tracking::TrackingRefusal,
    upstream::TransactionSource,
    utxos::{SpendableNotes, WalletCursor, WalletStatusQuery},
    wallet_snapshots::WalletSnapshotRelease,
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthorityTransferError {
    #[error("the signer is not the ring delegate")]
    NotDelegate = -32220,
    #[error("the ring seals its keys to another auditor")]
    ForeignAuditor = -32221,
    #[error("the source wallet has no enrolled nullifier key")]
    SourceUnescrowed = -32222,
    #[error("the source address names another nullifier key")]
    SourceKey = -32223,
    #[error("the service runs no relay")]
    RelayUnavailable = -32224,
    #[error("the transaction key is not a clamped X25519 secret")]
    TxViewingKey = -32225,
    #[error("the signer writes no salted list of the ring")]
    NotListWriter = -32226,
    #[error("a stored note of the source belongs to another owner or key")]
    SourceNote = -32227,
    #[error("the sealed move spends a note no requested source holds")]
    UnrequestedInput = -32228,
    #[error("the withdrawal mint uses another token program")]
    WithdrawalMint = -32229,
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

impl From<DelegateSourceError> for RingRpcError {
    fn from(error: DelegateSourceError) -> Self {
        match error {
            DelegateSourceError::Unenrolled => AuthorityTransferError::SourceUnescrowed.into(),
            DelegateSourceError::KeyMismatch => AuthorityTransferError::SourceKey.into(),
            DelegateSourceError::ForeignNote { .. }
            | DelegateSourceError::UnboundOpening { .. } => {
                AuthorityTransferError::SourceNote.into()
            }
            DelegateSourceError::SourcesMismatch | DelegateSourceError::UnrequestedInput { .. } => {
                AuthorityTransferError::UnrequestedInput.into()
            }
            DelegateSourceError::SealMismatch => TrackingRefusal::Sealed.into(),
            DelegateSourceError::Seal(error) => error.into(),
            DelegateSourceError::Keypair(error) => error.into(),
            DelegateSourceError::Transaction(error) => error.into(),
            DelegateSourceError::Client(error) => error.into(),
        }
    }
}

struct DelegateSourceScan {
    address: ShieldedAddress,
    owner_key: [u8; 32],
    resolved: ResolvedSource,
}

struct ScannedEnrollment<'a, S> {
    service: &'a AuditService<S>,
}

#[async_trait]
impl<S: TransactionSource> SourceEnrollment for ScannedEnrollment<'_, S> {
    type Error = RingRpcError;

    async fn escrowed_key(
        &self,
        source: &ShieldedAddress,
    ) -> Result<Option<NullifierKey>, RingRpcError> {
        let owner_key = source
            .solana_address()
            .map_err(|_| AuthorityTransferError::SourceUnescrowed)?
            .to_bytes();
        self.service.escrowed_key(&owner_key).await
    }
}

impl<S: TransactionSource> Hub<S> {
    /// The chain names the delegate, only its signature reads a victim's secret and openings.
    pub async fn delegate_notes(
        &self,
        request: &GetDelegateNotesRequest,
    ) -> Result<GetDelegateNotesResponse, RingRpcError> {
        let (ring, delegate, owner) = (request.ring.0, request.delegate.0, request.owner.0);
        let cursor = request
            .cursor
            .as_ref()
            .map(|cursor| WalletCursor::decode(&cursor.0))
            .transpose()?;
        let service = self.service(Some(ring))?;
        let shared = self.shared();
        self.authorize_delegate_read(
            request,
            &DelegateNotesAttestation {
                target: service.read_target(),
                delegate,
                owner,
                cursor: request.cursor.clone(),
            },
        )
        .await?;
        // One scan answers the secret, it opens to the key the owner's tracking row binds and
        // stays out of the store.
        let enrolled = service.scanned_enrollment(&owner.to_bytes()).await?;
        let nullifier_secret = enrolled
            .held()
            .map(|held| held.secrets(service.auditor_keypair()))
            .transpose()?
            .map(|secrets| {
                spr_hasher::primitives::right_align(&secrets.nullifier_key.secret()).into()
            });
        Ok(GetDelegateNotesResponse {
            nullifier_secret,
            status: shared
                .store(ring)
                .wallet_status(WalletStatusQuery {
                    principal: *PublicKey::from_ed25519(delegate.as_array()).as_bytes(),
                    now: shared.clock.now()?,
                    enrollment: shared.source.tracking_enrollment(ring, owner).await?,
                    wallet: owner,
                    ring,
                    after: cursor,
                    limit: WALLET_NOTE_PAGE_LIMIT,
                })
                .await?,
        })
    }

    pub async fn release_delegate_snapshot(
        &self,
        request: &GetDelegateNotesRequest,
    ) -> Result<bool, RingRpcError> {
        let encoded = request.cursor.as_ref().ok_or(RingRpcError::InvalidCursor)?;
        let cursor = WalletCursor::decode(&encoded.0)?;
        let service = self.service(Some(request.ring.0))?;
        self.authorize_delegate_read(
            request,
            &DelegateSnapshotReleaseAttestation {
                target: service.read_target(),
                delegate: request.delegate.0,
                owner: request.owner.0,
                cursor: encoded.clone(),
            },
        )
        .await?;
        self.shared()
            .store(request.ring.0)
            .release_wallet_snapshot(WalletSnapshotRelease {
                ring: request.ring.0,
                wallet: request.owner.0,
                principal: *PublicKey::from_ed25519(request.delegate.0.as_array()).as_bytes(),
                cursor,
                now: self.shared().clock.now()?,
            })
            .await?;
        Ok(true)
    }

    async fn authorize_delegate_read(
        &self,
        request: &GetDelegateNotesRequest,
        attestation: &impl Attestation,
    ) -> Result<(), RingRpcError> {
        let (ring, delegate) = (request.ring.0, request.delegate.0);
        let shared = self.shared();
        let now = shared.clock.now()?;
        let nonce = WalletCheck {
            wallet: delegate,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation,
            now,
        }
        .decide()?;
        let config = shared
            .source
            .ring_config(ring)
            .await?
            .filter(|config| config.delegate == Some(delegate))
            .ok_or(AuthorityTransferError::NotDelegate)?;
        if config.auditor_pubkey != self.service(Some(ring))?.auditor_pubkey() {
            return Err(AuthorityTransferError::ForeignAuditor.into());
        }
        shared
            .replay
            .accept(ReplayCheck {
                ring,
                nonce,
                timestamp: request.timestamp,
                now: shared.clock.now()?,
            })
            .await?;
        Ok(())
    }

    /// An owner dodging a block need not hand over an address.
    pub async fn list_salt(
        &self,
        request: &GetListSaltRequest,
    ) -> Result<GetListSaltResponse, RingRpcError> {
        let (ring, writer, owner) = (request.ring.0, request.writer.0, request.owner.0);
        let service = self.service(Some(ring))?;
        let shared = self.shared();
        let now = shared.clock.now()?;
        // 1. The named key signed the read for the service and ring.
        let nonce = WalletCheck {
            wallet: writer,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &ListSaltAttestation {
                target: service.read_target(),
                writer,
                owner,
            },
            now,
        }
        .decide()?;
        // 2. The policy authority or the authority of a salted list's registry, under the auditor key held here.
        let config = shared
            .source
            .ring_config(ring)
            .await?
            .ok_or(AuthorityTransferError::NotListWriter)?;
        let writes = config.roles.policy == writer
            || shared
                .source
                .salted_list_writers(ring)
                .await?
                .contains(&writer);
        if !writes {
            return Err(AuthorityTransferError::NotListWriter.into());
        }
        if config.auditor_pubkey != service.auditor_pubkey() {
            return Err(AuthorityTransferError::ForeignAuditor.into());
        }
        shared
            .replay
            .accept(ReplayCheck {
                ring,
                nonce,
                timestamp: request.timestamp,
                now,
            })
            .await?;
        Ok(GetListSaltResponse {
            list_salt: service
                .enrolled_list_salt(&owner.to_bytes())
                .await?
                .map(Hash),
        })
    }

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
        let tx_viewing_key = request
            .tx_viewing_key
            .key()
            .map_err(|_| AuthorityTransferError::TxViewingKey)?;
        let relay_id = request
            .relay_id()
            .map_err(|_| RingRpcError::StateUnavailable)?;
        if let Some(step) = relay.stored(&relay_id).await? {
            return Ok(step);
        }
        // 2. The config names the key its delegate and the auditor key held here.
        let config = shared.source.ring_config(ring).await?;
        let config = config
            .filter(|config| config.delegate == Some(delegate))
            .ok_or(AuthorityTransferError::NotDelegate)?;
        if config.auditor_pubkey != service.auditor_pubkey() {
            return Err(AuthorityTransferError::ForeignAuditor.into());
        }
        if !relay.holds(&relay_id).await? {
            shared
                .replay
                .accept(ReplayCheck {
                    ring,
                    nonce,
                    timestamp: request.timestamp,
                    now,
                })
                .await?;
        }
        // 3. Each source key is the public zero key or its escrowed key, its own notes alone fill
        //    the allowed set the sealed inputs answer to.
        let assets = shared.due_assets().await;
        let mut mints: Vec<Mint> = Vec::new();
        for address in transfer
            .payments
            .iter()
            .chain(&transfer.exits)
            .map(|payment| payment.mint.0)
            .chain(transfer.withdrawals.iter().map(|leg| leg.mint.0))
        {
            let mint = assets.registry().mint(&address)?;
            if !mints.contains(&mint) {
                mints.push(mint);
            }
        }
        let payments: Vec<DelegatePayment> =
            transfer.payments.iter().copied().map(Into::into).collect();
        let exits: Vec<DelegatePayment> = transfer.exits.iter().copied().map(Into::into).collect();
        let withdrawals: Vec<DelegateWithdrawal> = transfer
            .withdrawals
            .iter()
            .copied()
            .map(Into::into)
            .collect();
        let mut candidates = DelegateFunding {
            payments: &payments,
            exits: &exits,
            withdrawals: &withdrawals,
        }
        .candidates()
        .map_err(crate::relay::RelayError::proof)?;
        let unheld = HashSet::new();
        let enrollment = ScannedEnrollment { service: &service };
        let mut resolved_sources = Vec::with_capacity(transfer.sources.len());
        for source in &transfer.sources {
            let address = source.0;
            let owner_key = address
                .solana_address()
                .map_err(|_| AuthorityTransferError::SourceUnescrowed)?
                .to_bytes();
            // A repeated source scans once, a note observed twice would fund the move twice.
            if resolved_sources.iter().any(|held: &DelegateSourceScan| {
                held.owner_key == owner_key
                    && held.address.nullifier_pubkey == address.nullifier_pubkey
            }) {
                continue;
            }
            let resolved = ResolvedSource::resolve(address, &enrollment).await?;
            shared
                .store(ring)
                .visit_spendable_notes(
                    SpendableNotes {
                        ring,
                        owner_key,
                        nullifier_key: resolved.nullifier_key(),
                        mints: &mints,
                        held: &unheld,
                    },
                    |note| candidates.observe(&note),
                )
                .await?;
            resolved_sources.push(DelegateSourceScan {
                address,
                owner_key,
                resolved,
            });
        }
        let mut selected = candidates
            .select()
            .map_err(crate::relay::RelayError::proof)?;
        let mut allowed = AllowedNullifiers::default();
        let mut sources = Vec::with_capacity(resolved_sources.len());
        for source in resolved_sources {
            let owner = PublicKey::from_ed25519(&source.owner_key);
            let notes: Vec<WalletUtxo> = selected
                .extract_if(.., |note| {
                    note.utxo.owner == owner
                        && note.nullifier_pubkey == source.address.nullifier_pubkey
                })
                .collect();
            allowed.admit(&source.resolved, &notes)?;
            sources.push(SealedSource {
                address: source.address,
                nullifier_key: source.resolved.into_nullifier_key(),
                notes,
            });
        }
        if !selected.is_empty() {
            return Err(AuthorityTransferError::SourceNote.into());
        }
        relay
            .prepare_delegated(
                relay_id,
                DelegateSeal {
                    ring,
                    delegate,
                    sources: &sources,
                    allowed: &allowed,
                    tx_viewing_key,
                    payments,
                    exits,
                    withdrawals,
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
    use custom_ring_sdk::{DelegatePayment, DelegateWithdrawal};
    use solana_address::Address;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_message::VersionedMessage;
    use solana_signer::Signer;
    use spr_client::ComputeBudgetConfig;
    use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress, ViewingKey, X25519Keypair};
    use spr_transaction::{instructions::transact::ExternalData, utxo::SppProofInputUtxo};
    use zolana_ring_client::rpc::{
        unix_now, AuthorityPayment, AuthorityTransfer, AuthorityTransferAttestation,
        AuthorityTransferRequest, ReadTarget, RelayProofInputs, RelayRail, SignedRequest,
    };

    use super::*;
    use crate::{
        database::Store,
        managed_merge::tests::{
            fee_payer, list_writer, Fixture, ScriptedChain, GENESIS, LIST_SALT, MINT, RING,
        },
        relay::{RelayParts, RelayPayload},
        relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
        relay_reservations::RelayReservations,
    };

    #[derive(Default)]
    struct SealingProver {
        sealed: Mutex<Vec<Sealed>>,
        proven: Mutex<Vec<(Address, [u8; 31])>>,
        frame: Mutex<Option<Vec<u8>>>,
        /// An input the sealer adds at a position among the sources' notes.
        inserted: Mutex<Option<(usize, SppProofInputUtxo)>>,
    }

    struct Sealed {
        delegate: Address,
        /// One per source, in the request's order.
        secrets: Vec<[u8; 31]>,
        nullifiers: Vec<[u8; 32]>,
        payments: Vec<DelegatePayment>,
        exits: Vec<DelegatePayment>,
        withdrawals: Vec<DelegateWithdrawal>,
    }

    #[async_trait]
    impl RelayProver for SealingProver {
        async fn check_enrollment(
            &self,
            _enrollment: &zolana_ring_client::rpc::RelayEnrollInputs,
        ) -> Result<(), RingRpcError> {
            Err(RingRpcError::StateUnavailable)
        }

        async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
            let RelayPayload::Transfer(proof_inputs) = request.payload else {
                panic!("an authority transfer proves a transfer");
            };
            let RelayRail::Delegate { delegate, .. } = proof_inputs.rail else {
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
                        AccountMeta::new(request.parties.fee_payer, true),
                        AccountMeta::new_readonly(delegate, true),
                    ],
                    data: self
                        .frame
                        .lock()
                        .expect("frame")
                        .clone()
                        .unwrap_or_else(|| vec![21]),
                },
                budget: ComputeBudgetConfig::new(400_000),
                co_signers: Vec::new(),
                signers: vec![delegate],
                tree_fees: 0,
            })
        }

        async fn seal_delegate(
            &self,
            seal: DelegateSeal<'_>,
            _parties: RelayParties,
        ) -> Result<RelayProofInputs, RingRpcError> {
            self.sealed.lock().expect("sealed").push(Sealed {
                delegate: seal.delegate,
                payments: seal.payments.clone(),
                exits: seal.exits.clone(),
                withdrawals: seal.withdrawals.clone(),
                secrets: seal
                    .sources
                    .iter()
                    .map(|source| *source.nullifier_key.secret())
                    .collect(),
                nullifiers: seal
                    .sources
                    .iter()
                    .flat_map(|source| source.notes.iter().map(|note| note.nullifier))
                    .collect(),
            });
            let mut inputs: Vec<SppProofInputUtxo> = seal
                .sources
                .iter()
                .flat_map(|source| source.notes.iter().map(SppProofInputUtxo::from))
                .collect();
            if let Some((position, input)) = self.inserted.lock().expect("inserted").take() {
                inputs.insert(position, input);
            }
            let tx_viewing_key = seal.tx_viewing_key;
            Ok(RelayProofInputs {
                rail: RelayRail::Delegate {
                    delegate: seal.delegate,
                    plan: None,
                },
                ring_program_id: seal.ring,
                sender: seal.sources[0].address,
                nullifier_key: seal.sources[0].nullifier_key.clone(),
                co_owners: Vec::new(),
                approval_blinder: None,
                external_data: ExternalData::new(
                    *tx_viewing_key.pubkey().as_bytes(),
                    [0; 16],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                tx_viewing_key,
                inputs,
                outputs: Vec::new(),
                interface_transfer_accounts: Vec::new(),
                blinding_seed: [0; 32],
                output_tree_id: 1,
                list_salts: Vec::new(),
                wide_owners: false,
            })
        }
    }

    async fn served(delegate: Address) -> (Fixture, Arc<SealingProver>) {
        let prover = Arc::new(SealingProver::default());
        let relay = RelayParts {
            store: Store::open("sqlite::memory:", 1).await.expect("store"),
            prover: prover.clone(),
            fee_payer: fee_payer(),
            chain: Arc::new(ScriptedChain::default()),
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
        request_from(fixture, signer, &[source])
    }

    fn request_from(
        fixture: &Fixture,
        signer: &Keypair,
        sources: &[ShieldedAddress],
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
                exits: Vec::new(),
                withdrawals: Vec::new(),
                sources: sources.iter().map(|source| (*source).into()).collect(),
                payments: vec![AuthorityPayment {
                    recipient: recipient.into(),
                    mint: MINT.into(),
                    amount: 15,
                }],
            },
        });
        request
            .at(unix_now().expect("clock"))
            .sign(signer, &ViewingKey::new())
            .expect("signed request")
    }

    #[tokio::test]
    async fn hosted_public_legs_are_signed_and_forwarded() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;
        let mut transfer = request(&fixture, &delegate, address(&wallet, &escrowed)).transfer;
        transfer.payments[0].amount = 3;
        transfer.exits = transfer.payments.clone();
        transfer.withdrawals = vec![zolana_ring_client::rpc::AuthorityWithdrawal {
            recipient: wallet.pubkey().into(),
            mint: MINT.into(),
            amount: 2,
            token_program: Some(
                Address::new_from_array(spr_interface::SPL_TOKEN_PROGRAM_ID).into(),
            ),
        }];
        let signed = SignedRequest::new(AuthorityTransferAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            delegate: delegate.pubkey(),
            transfer: transfer.clone(),
        })
        .at(unix_now().unwrap())
        .sign(&delegate, &ViewingKey::new())
        .unwrap();
        let mut changed = signed.clone();
        changed.transfer.withdrawals[0].amount += 1;
        assert!(fixture
            .hub
            .prepare_authority_transfer(&changed)
            .await
            .is_err());
        let mut changed = signed.clone();
        changed
            .transfer
            .payments
            .append(&mut changed.transfer.exits);
        assert!(fixture
            .hub
            .prepare_authority_transfer(&changed)
            .await
            .is_err());
        assert!(prover.sealed.lock().unwrap().is_empty());
        fixture
            .hub
            .prepare_authority_transfer(&signed)
            .await
            .unwrap();
        let sealed = prover.sealed.lock().unwrap();
        assert_eq!(
            sealed[0].payments,
            transfer
                .payments
                .into_iter()
                .map(Into::into)
                .collect::<Vec<DelegatePayment>>()
        );
        assert_eq!(
            sealed[0].exits,
            transfer
                .exits
                .into_iter()
                .map(Into::into)
                .collect::<Vec<DelegatePayment>>()
        );
        assert_eq!(
            sealed[0].withdrawals,
            transfer
                .withdrawals
                .into_iter()
                .map(Into::into)
                .collect::<Vec<DelegateWithdrawal>>()
        );
    }

    #[tokio::test]
    async fn hosted_selection_retains_only_the_funded_openings() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let key = fixture.escrow_notes(&wallet, 100).await;
        fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &delegate, address(&wallet, &key)))
            .await
            .unwrap();
        let sealed = prover.sealed.lock().unwrap();
        assert_eq!(sealed[0].nullifiers.len(), 2);
    }

    #[tokio::test]
    async fn a_delegate_request_spends_the_source_notes_under_the_escrowed_key() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;

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
            (sealed.delegate, sealed.secrets),
            (delegate.pubkey(), vec![*escrowed.secret()])
        );
        assert_eq!(sealed.nullifiers.len(), 2);
        assert_eq!(
            *prover.proven.lock().expect("proven"),
            [(delegate.pubkey(), *escrowed.secret())]
        );
    }

    /// The delegate's own wallet and another member's stand alike, each under its escrowed key.
    #[tokio::test]
    async fn a_delegate_request_names_its_own_and_another_members_notes() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let keys = fixture
            .escrow_wallets(&[(&delegate, 1), (&wallet, 2)])
            .await;
        let (own, other) = (&keys[0], &keys[1]);
        let sources = [address(&delegate, own), address(&wallet, other)];

        fixture
            .hub
            .prepare_authority_transfer(&request_from(&fixture, &delegate, &sources))
            .await
            .expect("prepared transfer");

        let [sealed] = std::mem::take(&mut *prover.sealed.lock().expect("sealed"))
            .try_into()
            .unwrap_or_else(|_| panic!("one seal"));
        assert_eq!(sealed.secrets, [*own.secret(), *other.secret()]);
        assert_eq!(sealed.nullifiers.len(), 2);

        let unescrowed = Keypair::new_from_array([12; 32]);
        let missing = address(&unescrowed, &NullifierKey::from_secret([12; 31]));
        assert!(fixture
            .hub
            .prepare_authority_transfer(&request_from(&fixture, &delegate, &[missing]))
            .await
            .is_err());
    }

    /// A stranger's request leaves no row, the delegate's binds one under its own key.
    #[tokio::test]
    async fn a_delegate_frame_reserves_under_the_delegate_alone() {
        let delegate = Keypair::new_from_array([21; 32]);
        let prover = Arc::new(SealingProver::default());
        let chain = Arc::new(ScriptedChain::default());
        *chain.outcome.lock().expect("outcome") =
            Some(crate::landing::ChainOutcome::Confirmed { slot: 1 });
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let relay = RelayParts {
            store: store.clone(),
            prover: prover.clone(),
            fee_payer: fee_payer(),
            chain: chain.clone(),
        };
        let fixture = Fixture::serving(Some(delegate.pubkey()), Some(relay)).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;
        let reservations = RelayReservations::new(store.connection());

        let stranger = Keypair::new_from_array([22; 32]);
        let foreign = request(&fixture, &stranger, address(&wallet, &escrowed));
        assert!(fixture
            .hub
            .prepare_authority_transfer(&foreign)
            .await
            .is_err());
        let foreign_id = foreign.relay_id().expect("relay id");
        assert!(reservations
            .by_relay(&foreign_id)
            .await
            .expect("read")
            .is_none());

        let signed = request(&fixture, &delegate, address(&wallet, &escrowed));
        let relay_id = signed.relay_id().expect("relay id");
        let step = fixture
            .hub
            .prepare_authority_transfer(&signed)
            .await
            .expect("the delegate's request");
        assert!(matches!(step, RelayStep::SignMessage { .. }), "{step:?}");
        let held = reservations
            .by_relay(&relay_id)
            .await
            .expect("read")
            .expect("reservation");
        assert_eq!(held.signer, delegate.pubkey());
        assert_eq!(prover.proven.lock().expect("proven").len(), 1);
    }

    fn notes_request(
        fixture: &Fixture,
        signer: &Keypair,
        owner: Address,
    ) -> GetDelegateNotesRequest {
        SignedRequest::new(DelegateNotesAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            delegate: signer.pubkey(),
            owner,
            cursor: None,
        })
        .at(unix_now().expect("clock"))
        .sign(signer)
        .expect("signed request")
    }

    #[tokio::test]
    async fn the_delegate_reads_the_secret_and_openings_and_another_key_nothing() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, _prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;
        let read = fixture
            .hub
            .delegate_notes(&notes_request(&fixture, &delegate, wallet.pubkey()))
            .await
            .expect("delegate read");
        assert_eq!(
            read.nullifier_secret.expect("secret").0[1..],
            *escrowed.secret()
        );
        let impostor = Keypair::new_from_array([22; 32]);
        let refused = fixture
            .hub
            .delegate_notes(&notes_request(&fixture, &impostor, wallet.pubkey()))
            .await
            .expect_err("only the configured delegate reads");
        assert_eq!(ErrorObjectOwned::from(refused).code(), -32220);
    }

    fn salt_request(fixture: &Fixture, signer: &Keypair, owner: Address) -> GetListSaltRequest {
        SignedRequest::new(ListSaltAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            writer: signer.pubkey(),
            owner,
        })
        .at(unix_now().expect("clock"))
        .sign(signer)
        .expect("signed request")
    }

    #[tokio::test]
    async fn a_list_writer_reads_the_enrolled_salt_and_another_key_nothing() {
        let (fixture, _prover) = served(Keypair::new_from_array([21; 32]).pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.enroll(&wallet, &NullifierKey::from_secret([11; 31]));
        let writer = list_writer();
        let read = fixture
            .hub
            .list_salt(&salt_request(&fixture, &writer, wallet.pubkey()))
            .await
            .expect("the writer reads");
        assert_eq!(read.list_salt.expect("salt").0, LIST_SALT);
        let impostor = Keypair::new_from_array([22; 32]);
        let refused = fixture
            .hub
            .list_salt(&salt_request(&fixture, &impostor, wallet.pubkey()))
            .await
            .expect_err("only a writer reads");
        assert_eq!(ErrorObjectOwned::from(refused).code(), -32226);
        let unenrolled = Keypair::new_from_array([12; 32]);
        let none = fixture
            .hub
            .list_salt(&salt_request(&fixture, &writer, unenrolled.pubkey()))
            .await
            .expect("a complete scan without the enrollment reads nothing");
        assert_eq!(none.list_salt, None);
    }

    #[tokio::test]
    async fn a_list_key_names_its_enrolled_owner_and_another_key_none() {
        let (fixture, _prover) = served(Keypair::new_from_array([21; 32]).pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.enroll(&wallet, &NullifierKey::from_secret([11; 31]));
        let service = fixture.hub.service(Some(RING)).expect("service");
        let member =
            zolana_ring_policy::Member::owner_tag(wallet.pubkey().as_array()).expect("member");
        let list_key = |salt| {
            *zolana_ring_policy::Member::salted(&member, salt)
                .expect("list key")
                .as_bytes()
        };

        let owner = service
            .salted_owner(&list_key(&LIST_SALT))
            .await
            .expect("complete scan")
            .expect("enrolled owner");
        let other = service
            .salted_owner(&list_key(&[0; 32]))
            .await
            .expect("complete scan");

        assert_eq!((owner.owner, owner.list_salt), (wallet.pubkey(), LIST_SALT));
        assert!(other.is_none());
    }

    /// The sealed outputs never reach the check, another member's note fails before any proof.
    #[tokio::test]
    async fn a_sealed_note_no_requested_source_holds_is_refused() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;
        let mut victim = SppProofInputUtxo::dummy(0).expect("dummy");
        victim.utxo.owner = PublicKey::from_ed25519(&[12; 32]);
        victim.nullifier = [12; 32];
        *prover.inserted.lock().expect("inserted") = Some((1, victim));

        let refused = fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &delegate, address(&wallet, &escrowed)))
            .await
            .expect_err("a note of an unrequested owner is refused");

        assert_eq!(ErrorObjectOwned::from(refused).code(), -32228);
        assert!(prover.proven.lock().expect("proven").is_empty());
    }

    /// SPP authorizes an address on its own, it passes between the source's notes.
    #[tokio::test]
    async fn an_address_between_the_requested_notes_passes() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;
        let address_input =
            SppProofInputUtxo::new_address(PublicKey::from_ed25519(&[4; 32]), [5; 32], 0)
                .expect("address input");
        *prover.inserted.lock().expect("inserted") = Some((1, address_input));

        let step = fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &delegate, address(&wallet, &escrowed)))
            .await
            .expect("prepared transfer");

        assert!(matches!(step, RelayStep::SignMessage { .. }), "{step:?}");
        assert_eq!(prover.proven.lock().expect("proven").len(), 1);
    }

    #[tokio::test]
    async fn a_request_signed_by_another_key_is_refused() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2).await;
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
