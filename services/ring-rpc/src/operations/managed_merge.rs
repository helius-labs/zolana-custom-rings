use std::{
    collections::HashSet,
    num::NonZeroU32,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use custom_ring_interface::{cosign::CoSignDemand, RingMode};
use custom_ring_sdk::{select_merge_where, RingError, MAX_RING_MERGE_INPUTS};
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use spr_keypair::NullifierKey;
use spr_transaction::WalletUtxo;
use zolana_ring_client::rpc::{
    MergeSettings, MergeSettingsAttestation, SetMergeSettingsRequest, SetMergeSettingsResponse,
};
use zolana_ring_policy::Member;
use zolana_ring_transaction::RingAssets;

use crate::{
    audit::AuditService,
    authorize::WalletCheck,
    cosign::{CoSignDecision, CoSignPolicy, CoSignRequest},
    error::{redacted, RingRpcError},
    hub::Hub,
    merge_settings::{MergeSettingsBook, SignedMergeSettings, WalletMergeSettings},
    relay_submit::{CollectedSignature, RelaySubmit, RelayTransaction},
    replay::ReplayCheck,
    upstream::TransactionSource,
    utxos::SpendableNotes,
};

pub const MANAGED_MERGE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeTarget {
    pub note_count: NonZeroU32,
    pub min_average_amount: u64,
}

/// The owner's nullifier secret lives only for the build.
#[must_use]
pub struct OwnerMerge<'a> {
    pub ring: Address,
    pub owner: Address,
    pub nullifier_key: &'a NullifierKey,
    pub inputs: Vec<WalletUtxo>,
}

/// The fee payer the message names signs at relay.
pub struct BuiltMerge {
    pub message: VersionedMessage,
    pub co_signer: Option<Address>,
}

#[async_trait]
pub trait MergeBuilder: Send + Sync {
    async fn build(&self, merge: OwnerMerge<'_>) -> Result<BuiltMerge, RingRpcError>;
}

#[must_use]
pub struct ManagedMergeInit<S> {
    pub hub: Arc<Hub<S>>,
    pub builder: Arc<dyn MergeBuilder>,
    pub co_signer: Arc<dyn CoSignPolicy>,
    pub relay: Arc<dyn RelaySubmit>,
}

pub struct ManagedMerge<S> {
    hub: Arc<Hub<S>>,
    builder: Arc<dyn MergeBuilder>,
    co_signer: Arc<dyn CoSignPolicy>,
    relay: Arc<dyn RelaySubmit>,
    /// Nullifiers of sent merges, held back for the life of the process.
    pending: Mutex<HashSet<[u8; 32]>>,
}

struct RingPass<S> {
    service: AuditService<S>,
    assets: RingAssets,
}

impl MergeTarget {
    /// `None` for a zero target, a later request revokes with it.
    pub fn of(settings: &MergeSettings) -> Option<Self> {
        Some(Self {
            note_count: NonZeroU32::new(settings.target_note_count)?,
            min_average_amount: settings.min_average_amount,
        })
    }

    /// The smallest notes of the fullest tree, at most as many as the target needs.
    pub fn plan(&self, notes: &[WalletUtxo]) -> Option<Vec<WalletUtxo>> {
        let asset = notes.first()?.utxo.asset.asset;
        let total: u128 = notes.iter().map(|note| u128::from(note.utxo.amount)).sum();
        let by_average = match self.min_average_amount {
            0 => notes.len(),
            least => usize::try_from(total / u128::from(least))
                .unwrap_or(usize::MAX)
                .max(1),
        };
        let keep = by_average.min(usize::try_from(self.note_count.get()).unwrap_or(usize::MAX));
        let inputs = notes.len().checked_sub(keep)?.checked_add(1)?;
        if inputs < 2 {
            return None;
        }
        select_merge_where(
            notes,
            asset,
            inputs.min(MAX_RING_MERGE_INPUTS),
            &HashSet::new(),
            |_| true,
        )
        .ok()
    }
}

impl<S> ManagedMergeInit<S> {
    pub fn build(self) -> ManagedMerge<S> {
        ManagedMerge {
            hub: self.hub,
            builder: self.builder,
            co_signer: self.co_signer,
            relay: self.relay,
            pending: Mutex::new(HashSet::new()),
        }
    }
}

impl<S: TransactionSource> ManagedMerge<S> {
    /// Every `interval`, the first at once, merges each wallet above its signed target.
    pub async fn run(self, interval: Duration) {
        let mut ticks = tokio::time::interval(interval);
        loop {
            ticks.tick().await;
            if let Err(error) = self.merge_due().await {
                log::warn!("managed merge failed because {}", redacted(&error));
            }
        }
    }

    /// At most one merge for each wallet and mint, a failed ring or wallet only logs.
    pub async fn merge_due(&self) -> Result<Vec<Signature>, RingRpcError> {
        let book = self.hub.shared().merge_settings()?;
        let mut sent = Vec::new();
        for ring in book.rings().await? {
            match self.merge_ring(&book, ring).await {
                Ok(signatures) => sent.extend(signatures),
                Err(error) => log::warn!(
                    "managed merge of ring {ring} failed because {}",
                    redacted(&error)
                ),
            }
        }
        Ok(sent)
    }

    /// Only a `ConfidentialEscrow` ring escrows the secret a merge needs.
    async fn merge_ring(
        &self,
        book: &MergeSettingsBook<'_>,
        ring: Address,
    ) -> Result<Vec<Signature>, RingRpcError> {
        let service = self.hub.service(Some(ring))?;
        let shared = self.hub.shared();
        let escrowed = shared
            .source
            .ring_config(ring)
            .await?
            .is_some_and(|config| {
                config.mode == RingMode::ConfidentialEscrow
                    && config.auditor_pubkey == service.auditor_pubkey()
            });
        if !escrowed {
            return Ok(Vec::new());
        }
        let pass = RingPass {
            service,
            assets: shared.due_assets().await,
        };
        let mut sent = Vec::new();
        for wallet in book.active(ring).await? {
            match self.merge_wallet(&pass, wallet).await {
                Ok(Some(signature)) => sent.push(signature),
                Ok(None) => {}
                Err(error) => log::warn!(
                    "managed merge of {} on ring {ring} failed because {}",
                    wallet.owner,
                    redacted(&error)
                ),
            }
        }
        Ok(sent)
    }

    async fn merge_wallet(
        &self,
        pass: &RingPass<S>,
        wallet: WalletMergeSettings,
    ) -> Result<Option<Signature>, RingRpcError> {
        let Some(target) = MergeTarget::of(&wallet.settings) else {
            return Ok(None);
        };
        let ring = pass.service.ring();
        let owner_key = wallet.owner.to_bytes();
        // 1. The secret opens to the nullifier key the registry record binds.
        let Some(nullifier_key) = pass.service.escrowed_nullifier_key(&owner_key)? else {
            return Ok(None);
        };
        let notes = self.hub.shared().store(ring).spendable(SpendableNotes {
            ring,
            owner_key,
            mint: pass.assets.registry().mint(&wallet.settings.mint.0)?,
            nullifier_key: &nullifier_key,
        })?;
        // 2. Each candidate is unspent and in no merge already sent.
        let notes: Vec<WalletUtxo> = {
            let pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            notes
                .into_iter()
                .filter(|note| !pending.contains(&note.nullifier))
                .collect()
        };
        let Some(inputs) = target.plan(&notes) else {
            return Ok(None);
        };
        // 3. The secret leaves memory once the merge is proven.
        let nullifiers: Vec<[u8; 32]> = inputs.iter().map(|input| input.nullifier).collect();
        let built = self
            .builder
            .build(OwnerMerge {
                ring,
                owner: wallet.owner,
                nullifier_key: &nullifier_key,
                inputs,
            })
            .await?;
        drop(nullifier_key);
        // 4. A co-signer whose scope covers transfers signs, or the merge waits.
        let mut signatures = Vec::new();
        if let Some(signer) = built.co_signer {
            let decision = self
                .co_signer
                .decide(&CoSignRequest {
                    ring,
                    message: built.message.clone(),
                    sender: Member::owner_tag(&owner_key)
                        .map_err(|error| RingRpcError::MergeBuild(RingError::from(error).into()))?,
                    demand: CoSignDemand::transact(false, &[]),
                    flows: Vec::new(),
                })
                .await?;
            match decision {
                CoSignDecision::Signed(signature) => {
                    signatures.push(CollectedSignature { signer, signature })
                }
                CoSignDecision::Refused(refusal) => {
                    log::info!(
                        "co-signer refused the merge of {} as {refusal:?}",
                        wallet.owner
                    );
                    return Ok(None);
                }
            }
        }
        // 5. The inputs stay out of later merges once the relay accepts the merge.
        let signature = self
            .relay
            .submit(RelayTransaction {
                message: built.message,
                signatures,
            })
            .await?;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(nullifiers);
        Ok(Some(signature))
    }
}

impl<S: TransactionSource> Hub<S> {
    /// A replay or a request not later than the stored one fails.
    pub async fn set_merge_settings(
        &self,
        request: &SetMergeSettingsRequest,
    ) -> Result<SetMergeSettingsResponse, RingRpcError> {
        let shared = self.shared();
        let book = shared.merge_settings()?;
        let ring = request.ring.0;
        let owner = request.owner.0;
        let attestation = MergeSettingsAttestation {
            target: self.service(Some(ring))?.read_target(),
            owner,
            settings: request.settings,
        };
        let now = shared.clock.now()?;
        let nonce = WalletCheck {
            wallet: owner,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &attestation,
            now,
        }
        .decide()?;
        shared.replay.accept(ReplayCheck {
            ring,
            nonce,
            timestamp: request.timestamp,
            now,
        })?;
        let saved = book
            .save(SignedMergeSettings {
                ring,
                owner,
                settings: &request.settings,
                signed_at: request.timestamp,
            })
            .await?;
        if !saved {
            return Err(RingRpcError::StaleMergeSettings);
        }
        Ok(request.settings)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use custom_ring_interface::RingMode;
    use solana_keypair::Keypair;
    use solana_message::{v1, VersionedMessage};
    use solana_signer::Signer;
    use spr_client::{ClientError, GetShieldedTransactionsByTagsResponse};
    use spr_keypair::X25519Keypair;
    use spr_transaction::Mint;
    use zolana_ring_client::{
        rpc::{unix_now, MergeSettingsRequest, ReadTarget, RingChainStatus, SignedRequest},
        AuditError, CreatedUtxo, KnownUtxo, MergeAuditPage, NullifierKeyEnvelope, RingIndexerError,
        RingOrigin, UtxoOwner,
    };
    use zolana_ring_indexer::rpc::{
        GetRingMemberOpeningsRequest, GetRingMemberOpeningsResponse, GetRingMemberRecordsRequest,
        GetRingMemberRecordsResponse, GetRingRecordQueueResponse, GetStorageMemberOpeningsRequest,
        GetStorageMemberOpeningsResponse,
    };

    use super::*;
    use crate::{
        cosign::RefusingCoSigner,
        database::Store,
        upstream::{
            DepositHistory, DepositPage, MergeAuditRequest, RecordsRoot, RingConfiguration,
            RingHistoryPage, TransactionPage,
        },
        utxos::{CreatedIn, EscrowRoot, EscrowedOwner},
    };

    const RING: Address = Address::new_from_array([8; 32]);
    const GENESIS: [u8; 32] = [3; 32];
    const MINT: Address = Address::new_from_array([6; 32]);

    struct EscrowRingSource {
        config: RingConfiguration,
    }

    fn unused<T>() -> Result<T, ClientError> {
        Err(ClientError::Rpc("unused source".to_owned()))
    }

    impl TransactionSource for EscrowRingSource {
        async fn transactions_by_tag(
            &self,
            _request: TransactionPage<'_>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            unused()
        }

        async fn ring_history(
            &self,
            _request: RingHistoryPage<'_>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            unused()
        }

        async fn merge_audit_page(
            &self,
            _request: MergeAuditRequest<'_>,
        ) -> Result<MergeAuditPage, AuditError> {
            Err(AuditError::InvalidMemberRegistry)
        }

        async fn transaction_origin(
            &self,
            signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            Err(AuditError::Unavailable {
                signature,
                message: "unused source".to_owned(),
            })
        }

        async fn ring_deposits(&self, _page: DepositPage) -> Result<DepositHistory, ClientError> {
            unused()
        }

        async fn ring_config(
            &self,
            _ring: Address,
        ) -> Result<Option<RingConfiguration>, ClientError> {
            Ok(Some(self.config))
        }

        async fn ring_chain_status(&self, _ring: Address) -> Result<RingChainStatus, ClientError> {
            unused()
        }

        async fn ring_member_records(
            &self,
            _request: GetRingMemberRecordsRequest,
        ) -> Result<GetRingMemberRecordsResponse, RingIndexerError> {
            Ok(unused()?)
        }

        async fn ring_member_openings(
            &self,
            _request: GetRingMemberOpeningsRequest,
        ) -> Result<GetRingMemberOpeningsResponse, RingIndexerError> {
            Ok(unused()?)
        }

        async fn ring_record_queue(
            &self,
            _ring: Address,
        ) -> Result<GetRingRecordQueueResponse, RingIndexerError> {
            Ok(unused()?)
        }

        async fn records_root(&self, _ring: Address) -> Result<Option<RecordsRoot>, ClientError> {
            unused()
        }

        async fn storage_member_openings(
            &self,
            _request: GetStorageMemberOpeningsRequest,
        ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
            Ok(unused()?)
        }

        async fn upgrade_authority(
            &self,
            _program: Address,
        ) -> Result<Option<Address>, ClientError> {
            unused()
        }

        async fn health(&self) -> Result<(), ClientError> {
            Ok(())
        }

        async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
            Ok(GENESIS)
        }

        async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
            Ok(assets())
        }
    }

    #[derive(Default)]
    struct RecordingBuilder {
        owners: Mutex<Vec<(Address, usize)>>,
    }

    #[async_trait]
    impl MergeBuilder for RecordingBuilder {
        async fn build(&self, merge: OwnerMerge<'_>) -> Result<BuiltMerge, RingRpcError> {
            self.owners
                .lock()
                .expect("owners")
                .push((merge.owner, merge.inputs.len()));
            Ok(BuiltMerge {
                message: VersionedMessage::V1(v1::Message::default()),
                co_signer: None,
            })
        }
    }

    #[derive(Default)]
    struct RecordingRelay {
        sent: Mutex<usize>,
    }

    #[async_trait]
    impl RelaySubmit for RecordingRelay {
        fn fee_payer(&self) -> Address {
            Address::new_from_array([5; 32])
        }

        async fn submit(&self, _transaction: RelayTransaction) -> Result<Signature, RingRpcError> {
            *self.sent.lock().expect("sent") += 1;
            Ok(Signature::from([9; 64]))
        }
    }

    /// A leading zero byte keeps the commitment inside the field.
    fn commitment(owner: u8, index: u8) -> [u8; 32] {
        let mut commitment = [0; 32];
        commitment[1] = owner;
        commitment[2] = index;
        commitment
    }

    fn assets() -> RingAssets {
        RingAssets::new([Mint::new(MINT, 7)]).expect("assets")
    }

    struct Fixture {
        hub: Arc<Hub<EscrowRingSource>>,
        builder: Arc<RecordingBuilder>,
        relay: Arc<RecordingRelay>,
    }

    impl Fixture {
        async fn new() -> Self {
            let auditor = X25519Keypair::new();
            let source = EscrowRingSource {
                config: RingConfiguration {
                    auditor_pubkey: auditor.pubkey(),
                    authority: Address::new_from_array([2; 32]),
                    mode: RingMode::ConfidentialEscrow,
                },
            };
            let store = Store::open("sqlite::memory:", 1).await.expect("store");
            let hub = Hub::builder(source, GENESIS)
                .with_store(store)
                .local(RING, auditor)
                .expect("hub");
            Self {
                hub: Arc::new(hub),
                builder: Arc::default(),
                relay: Arc::default(),
            }
        }

        fn escrow_notes(&self, wallet: &Keypair, notes: u8) {
            let key = NullifierKey::from_secret([wallet.pubkey().to_bytes()[0]; 31]);
            let nullifier_pk = key.pubkey().expect("nullifier pk");
            let auditor = self
                .hub
                .service(Some(RING))
                .expect("service")
                .auditor_pubkey();
            let store = self.hub.shared().store(RING);
            let owner_key = wallet.pubkey().to_bytes();
            let owner = EscrowedOwner {
                owner_key,
                nullifier_pk,
                sealed: NullifierKeyEnvelope::new(&key, &auditor)
                    .expect("envelope")
                    .sealed,
            };
            store.update_escrow(
                EscrowRoot {
                    root: [1; 32],
                    applied: 0,
                },
                [(owner_key, Some(owner))],
            );
            let asset = *assets().fields().next().expect("field");
            store.record(
                CreatedIn {
                    slot: 1,
                    tx_signature: Signature::from([7; 64]),
                    event_index: 0,
                },
                (0..notes).map(|index| CreatedUtxo {
                    commitment: commitment(owner_key[0], index),
                    slot_index: u32::from(index),
                    utxo: KnownUtxo {
                        owner_key,
                        owner: UtxoOwner::Keyed { nullifier_pk },
                        asset: asset.0,
                        mint: Some(MINT),
                        amount: 10,
                        blinding: [index; 32],
                        data_hash: [0; 32],
                        ring_data_hash: [0; 32],
                        tree_id: 1,
                    },
                }),
            );
        }

        async fn settle(&self, wallet: &Keypair, target_note_count: u32) {
            let target = ReadTarget {
                cluster: GENESIS,
                service: self.hub.service_pubkey(),
                ring: RING,
            };
            let request: MergeSettingsRequest = SignedRequest::new(MergeSettingsAttestation {
                target,
                owner: wallet.pubkey(),
                settings: MergeSettings {
                    mint: MINT.into(),
                    target_note_count,
                    min_average_amount: 0,
                },
            });
            let signed = request
                .at(unix_now().expect("clock"))
                .sign(wallet)
                .expect("signed settings");
            self.hub
                .set_merge_settings(&signed)
                .await
                .expect("stored settings");
        }

        async fn merge_due(&self) -> Vec<Signature> {
            ManagedMergeInit {
                hub: self.hub.clone(),
                builder: self.builder.clone(),
                co_signer: Arc::new(RefusingCoSigner),
                relay: self.relay.clone(),
            }
            .build()
            .merge_due()
            .await
            .expect("merge pass")
        }
    }

    #[tokio::test]
    async fn a_wallet_above_its_target_count_is_merged() {
        let fixture = Fixture::new().await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.escrow_notes(&wallet, 3);
        fixture.settle(&wallet, 1).await;

        assert_eq!(fixture.merge_due().await.len(), 1);
        assert_eq!(*fixture.relay.sent.lock().expect("sent"), 1);
        assert_eq!(
            *fixture.builder.owners.lock().expect("owners"),
            vec![(wallet.pubkey(), 3)]
        );
    }

    #[tokio::test]
    async fn a_wallet_without_settings_is_left_alone() {
        let fixture = Fixture::new().await;
        let settled = Keypair::new_from_array([11; 32]);
        let unsettled = Keypair::new_from_array([12; 32]);
        fixture.escrow_notes(&settled, 1);
        fixture.escrow_notes(&unsettled, 3);
        fixture.settle(&settled, 1).await;

        assert!(fixture.merge_due().await.is_empty());
        assert_eq!(*fixture.relay.sent.lock().expect("sent"), 0);
    }
}
