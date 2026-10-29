use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::ClientError;
use spr_keypair::X25519Keypair;
use thiserror::Error;
use tokio::sync::{watch, Mutex as AsyncMutex, Semaphore, SemaphorePermit};
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{unix_now, KeyMode},
    ReaderKey,
};
use zolana_ring_transaction::RingAssets;

use crate::{
    audit::{AuditService, AuditServiceInit, ASSET_REFRESH_INTERVAL},
    authorize::Unauthorized,
    config::{ReaderGrantStore, RootSecret},
    cosign::{CoSignPolicy, RefusingCoSigner},
    cosign_limits::{LimitedCoSignerInit, MirroredLimits},
    database::Store,
    error::{redacted, RingRpcError},
    grant_rows::{GrantRowKey, GrantRows},
    grants::{GrantQuery, GrantSource, Grants, ReadScope, TreeGrants},
    keys::{
        co_signer_keypair, service_keypair, storage_authority_keypair, AuditorKeyDerivation,
        KeySource,
    },
    limits::{
        PublicRequest, RequestRate, MAX_CONCURRENT_AUTHENTICATIONS, MAX_CONCURRENT_DEPOSIT_SCANS,
        MAX_CONCURRENT_READS,
    },
    managed_merge::{ManagedMerge, ManagedMergeInit},
    merge_settings::MergeSettingsBook,
    origins::Origins,
    record_update::RecordUpdateRefusal,
    record_writer::{RecordWriter, WriterParts, RECORD_FLUSH_INTERVAL},
    relay::{Relay, RelayParts, ServedRings, RELAY_TRACK_INTERVAL},
    relay_services::{MergeParts, RelayServices},
    replay::ReplayGuard,
    storage_chain::StorageChain,
    upstream::{DepositHistory, DepositPage, TransactionSource},
    utxos::{AuditStore, UTXO_BACKFILL_INTERVAL},
};

const READINESS_CACHE_INTERVAL: Duration = Duration::from_secs(1);

pub struct Hub<S> {
    signer: Keypair,
    shared: Arc<Shared<S>>,
    keys: KeySource,
    writer: Option<Arc<RecordWriter>>,
    co_signer: Arc<dyn CoSignPolicy>,
    relay: Option<Arc<Relay>>,
    merge: Option<MergeParts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadinessStatus {
    Ready,
    Unavailable(&'static str),
}

/// Names the readiness check that failed, which `/ready` reports.
#[derive(Debug, Error)]
pub enum NotReady {
    #[error("upstream probe failed because {0}")]
    Upstream(#[source] RingRpcError),
    #[error("the local ring config is unusable because {0}")]
    AuditorKey(#[source] Unauthorized),
    #[error("the cluster genesis hash differs from the one captured at boot")]
    Cluster,
}

impl NotReady {
    pub fn check(&self) -> &'static str {
        match self {
            Self::Upstream(_) => "unavailable upstream",
            Self::AuditorKey(_) => "unavailable auditor key",
            Self::Cluster => "unavailable cluster",
        }
    }
}

/// Unix seconds for the auth skew rule and the nonce eviction window.
#[derive(Debug, Clone, Copy)]
pub enum Clock {
    System,
    Fixed(u64),
}

impl Clock {
    pub(crate) fn now(self) -> Result<u64, RingRpcError> {
        match self {
            Self::System => unix_now().map_err(|_| RingRpcError::StateUnavailable),
            Self::Fixed(now) => Ok(now),
        }
    }
}

/// Each lane has its own rate window, and all but `Public` a concurrency cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    Public,
    Deposits(usize),
    Authentication,
    /// Held for a whole transfer or merge page.
    Read,
}

#[must_use]
pub struct HubBuilder<S> {
    source: S,
    genesis_hash: [u8; 32],
    assets: Option<RingAssets>,
    origins: Origins,
    clock: Clock,
    store: Option<Store>,
    storage_chain: Option<Arc<dyn StorageChain>>,
    watched_registries: Vec<Address>,
    reader_grants: ReaderGrantStore,
    relay: Option<RelayParts>,
    merge: Option<MergeParts>,
}

pub(crate) struct Shared<S> {
    pub(crate) source: S,
    /// Captured at boot, every authority signature and derived key binds to it.
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) service: Address,
    pub(crate) clock: Clock,
    assets: AsyncMutex<AssetCache>,
    pub(crate) origins: Origins,
    pub(crate) replay: ReplayGuard,
    pub(crate) active_readers: Mutex<HashSet<(Address, ReaderKey)>>,
    lanes: [(RequestRate, Option<Semaphore>); 4],
    readiness: AsyncMutex<ReadinessCache>,
    /// One per ring an authorized read or the backfill opened.
    stores: Mutex<HashMap<Address, Arc<AuditStore>>>,
    pub(crate) grants: Grants,
    database: Option<Store>,
}

struct AssetCache {
    registry: RingAssets,
    refresh: RefreshState,
}

enum RefreshState {
    Never,
    Succeeded(Instant),
    Failed(Instant),
}

struct ReadinessCache {
    checked_at: Option<Instant>,
    status: ReadinessStatus,
    in_flight: Option<watch::Receiver<Option<ReadinessStatus>>>,
}

impl<S> Shared<S> {
    pub(crate) fn store(&self, ring: Address) -> Arc<AuditStore> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        stores.entry(ring).or_default().clone()
    }

    fn store_rings(&self) -> Vec<Address> {
        let stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        stores.keys().copied().collect()
    }

    pub(crate) fn merge_settings(&self) -> Result<MergeSettingsBook<'_>, RingRpcError> {
        let database = self
            .database
            .as_ref()
            .ok_or(RingRpcError::MergeSettingsUnavailable)?;
        Ok(MergeSettingsBook::new(database.connection()))
    }
}

impl<S: TransactionSource> Shared<S> {
    /// The config authority, or the upgrade authority while no config exists.
    pub(crate) async fn require_ring_authority(
        &self,
        ring: Address,
        signer: Address,
    ) -> Result<(), RingRpcError> {
        let ring_authority = match self.source.ring_config(ring).await? {
            Some(config) => Some(config.authority),
            None => self.source.upgrade_authority(ring).await?,
        };
        if ring_authority != Some(signer) {
            return Err(Unauthorized::NotRingAuthority.into());
        }
        Ok(())
    }

    pub(crate) async fn read_scope(&self, query: GrantQuery) -> Result<ReadScope, RingRpcError> {
        let granted = match &self.grants {
            Grants::Tree => {
                TreeGrants {
                    source: &self.source,
                }
                .grants(query)
                .await?
            }
            Grants::Database(rows) => rows.grants(query).await?,
        };
        if !granted {
            return Err(Unauthorized::NotGranted.into());
        }
        ReadScope::new(query.wallet)
    }

    pub(crate) async fn cached_assets(&self) -> RingAssets {
        self.assets.lock().await.registry.clone()
    }

    /// Delivered bodies name no mint, so a new mint arrives only through the interval refresh.
    pub(crate) async fn due_assets(&self) -> RingAssets {
        match self.refresh_assets().await {
            Ok(assets) => assets,
            Err(_) => self.cached_assets().await,
        }
    }

    /// At most one registry read per interval, a failed one blocks retries until it ends.
    pub(crate) async fn refresh_assets(&self) -> Result<RingAssets, RingRpcError> {
        let mut cache = self.assets.lock().await;
        let refresh_due = match cache.refresh {
            RefreshState::Never => true,
            RefreshState::Succeeded(at) | RefreshState::Failed(at) => {
                at.elapsed() >= ASSET_REFRESH_INTERVAL
            }
        };
        if refresh_due {
            cache.refresh = RefreshState::Failed(Instant::now());
            cache.registry = self.source.ring_assets().await?;
            cache.refresh = RefreshState::Succeeded(Instant::now());
        } else if matches!(cache.refresh, RefreshState::Failed(_)) {
            return Err(ClientError::Rpc("asset registry is unavailable".to_owned()).into());
        }
        Ok(cache.registry.clone())
    }
}

impl<S: TransactionSource> Hub<S> {
    pub fn builder(source: S, genesis_hash: [u8; 32]) -> HubBuilder<S> {
        HubBuilder {
            source,
            genesis_hash,
            assets: None,
            origins: Origins::default(),
            clock: Clock::System,
            store: None,
            storage_chain: None,
            watched_registries: Vec::new(),
            reader_grants: ReaderGrantStore::Tree,
            relay: None,
            merge: None,
        }
    }

    /// The rate unit is spent even when every slot is taken.
    pub(crate) fn admit(&self, lane: Lane) -> Result<Option<SemaphorePermit<'_>>, RingRpcError> {
        let (index, request) = match lane {
            Lane::Public => (0, PublicRequest::Standard),
            Lane::Deposits(signatures) => (1, PublicRequest::DepositScan { signatures }),
            Lane::Authentication => (2, PublicRequest::Standard),
            Lane::Read => (3, PublicRequest::Standard),
        };
        let (rate, slots) = &self.shared.lanes[index];
        rate.accept(Instant::now(), request)?;
        slots
            .as_ref()
            .map(|slots| slots.try_acquire().map_err(|_| RingRpcError::Busy))
            .transpose()
    }

    pub fn mode(&self) -> KeyMode {
        match self.keys {
            KeySource::Local { .. } => KeyMode::Local,
            KeySource::Derived(_) => KeyMode::Derived,
        }
    }

    /// Value entering the ring, which no auditor message announces.
    pub async fn ring_deposits(&self, page: DepositPage) -> Result<DepositHistory, RingRpcError> {
        Ok(self.shared.source.ring_deposits(page).await?)
    }

    pub fn service_pubkey(&self) -> Address {
        self.signer.pubkey()
    }

    pub fn record_writer(&self) -> Result<&Arc<RecordWriter>, RingRpcError> {
        self.writer
            .as_ref()
            .ok_or_else(|| RecordUpdateRefusal::Disabled.into())
    }

    pub fn co_signer_keypair(&self) -> Result<Keypair, RingRpcError> {
        co_signer_keypair(self.keys.service_secret().as_slice())
    }

    /// Signs under the asset record limits with a store, refuses without one.
    pub fn co_signer(&self) -> &Arc<dyn CoSignPolicy> {
        &self.co_signer
    }

    pub(crate) fn sign_attestation(&self, attestation: &[u8]) -> Signature {
        self.signer.sign_message(attestation)
    }

    pub fn origins(&self) -> &Origins {
        &self.shared.origins
    }

    pub fn relay(&self) -> Option<&Arc<Relay>> {
        self.relay.as_ref()
    }

    pub(crate) fn shared(&self) -> &Shared<S> {
        &self.shared
    }

    /// Pays through the relay fee payer, `None` without relay services.
    pub fn managed_merge(self: &Arc<Self>) -> Option<ManagedMerge<S>> {
        self.merge.as_ref().map(|merge| {
            ManagedMergeInit {
                hub: self.clone(),
                builder: merge.builder.clone(),
                relay: merge.submit.clone(),
            }
            .build()
        })
    }

    pub fn local_view_tag(&self) -> Option<[u8; 32]> {
        match &self.keys {
            KeySource::Local { auditor, .. } => Some(auditor_view_tag(&auditor.pubkey())),
            KeySource::Derived(_) => None,
        }
    }

    /// `None` names the one ring a local key serves.
    pub fn service(&self, ring: Option<Address>) -> Result<AuditService<S>, RingRpcError> {
        let (ring, auditor) = match &self.keys {
            KeySource::Local {
                ring: served,
                auditor,
            } => {
                self.validate_ring(ring.unwrap_or(*served))?;
                (*served, auditor.clone())
            }
            KeySource::Derived(root) => {
                let ring = ring.ok_or(RingRpcError::RingRequired)?;
                let auditor = AuditorKeyDerivation {
                    root,
                    genesis_hash: &self.shared.genesis_hash,
                    ring,
                }
                .derive()?;
                (ring, auditor)
            }
        };
        Ok(AuditServiceInit {
            ring,
            auditor,
            shared: self.shared.clone(),
        }
        .build())
    }

    pub(crate) fn validate_ring(&self, ring: Address) -> Result<(), RingRpcError> {
        match &self.keys {
            KeySource::Local { ring: served, .. } if ring != *served => {
                Err(RingRpcError::RingNotServed)
            }
            _ => Ok(()),
        }
    }

    /// Every `interval`, the first at once, backfills the local ring and every ring a read opened.
    pub async fn run_utxo_backfill(self: Arc<Self>, interval: Duration) {
        let mut ticks = tokio::time::interval(interval);
        loop {
            ticks.tick().await;
            for ring in self.backfill_rings() {
                let backfill = match self.service(Some(ring)) {
                    Ok(service) => service.backfill_utxos().await,
                    Err(error) => Err(error),
                };
                if let Err(error) = backfill {
                    log::warn!(
                        "UTXO backfill of ring {ring} failed because {}",
                        redacted(&error)
                    );
                }
            }
        }
    }

    fn backfill_rings(&self) -> Vec<Address> {
        let mut rings = self.shared.store_rings();
        if let KeySource::Local { ring, .. } = &self.keys {
            if !rings.contains(ring) {
                rings.push(*ring);
            }
        }
        rings
    }

    /// Local mode holds one key for one ring, so it also checks the config.
    pub async fn probe_upstreams(&self) -> Result<(), NotReady> {
        let upstream = |error: ClientError| NotReady::Upstream(error.into());
        let source = &self.shared.source;
        source.health().await.map_err(upstream)?;
        if source.genesis_hash().await.map_err(upstream)? != self.shared.genesis_hash {
            return Err(NotReady::Cluster);
        }
        if let KeySource::Local { ring, auditor } = &self.keys {
            let config = source
                .ring_config(*ring)
                .await
                .map_err(upstream)?
                .ok_or(NotReady::AuditorKey(Unauthorized::NoConfig))?;
            if config.auditor_pubkey != auditor.pubkey() {
                return Err(NotReady::AuditorKey(Unauthorized::AuditorKeyMismatch));
            }
        }
        Ok(())
    }

    /// One probe runs at a time in its own task, so a cancelled waiter never restarts it.
    pub(crate) async fn readiness(self: &Arc<Self>) -> ReadinessStatus
    where
        S: 'static,
    {
        let mut receiver = {
            let mut cache = self.shared.readiness.lock().await;
            if cache
                .checked_at
                .is_some_and(|at| at.elapsed() < READINESS_CACHE_INTERVAL)
            {
                return cache.status;
            }
            match cache
                .in_flight
                .clone()
                .filter(|probe| probe.has_changed().is_ok())
            {
                Some(probe) => probe,
                None => {
                    let (sender, probe) = watch::channel(None);
                    cache.in_flight = Some(probe.clone());
                    let hub = self.clone();
                    tokio::spawn(async move {
                        let status = match hub.probe_upstreams().await {
                            Ok(()) => ReadinessStatus::Ready,
                            Err(error) => {
                                log::error!("readiness probe failed because {}", redacted(&error));
                                ReadinessStatus::Unavailable(error.check())
                            }
                        };
                        *hub.shared.readiness.lock().await = ReadinessCache {
                            checked_at: Some(Instant::now()),
                            status,
                            in_flight: None,
                        };
                        let _ = sender.send(Some(status));
                    });
                    probe
                }
            }
        };
        let status = receiver
            .wait_for(Option::is_some)
            .await
            .map(|status| *status);
        match status {
            Ok(status) => status.unwrap_or(ReadinessStatus::Unavailable("unavailable probe")),
            Err(_) => ReadinessStatus::Unavailable("unavailable readiness task"),
        }
    }
}

impl<S: TransactionSource + 'static> Hub<S> {
    /// Every background worker except the managed merge, its caller picks the interval.
    pub fn spawn_workers(self: &Arc<Self>) {
        if let Some(relay) = self.relay() {
            tokio::spawn(relay.clone().run(RELAY_TRACK_INTERVAL));
        }
        tokio::spawn(self.clone().run_utxo_backfill(UTXO_BACKFILL_INTERVAL));
        if let Ok(writer) = self.record_writer() {
            tokio::spawn(writer.clone().run(RECORD_FLUSH_INTERVAL));
        }
    }
}

impl<S: TransactionSource + 'static> HubBuilder<S> {
    #[must_use = "use the updated builder"]
    pub fn with_assets(mut self, assets: RingAssets) -> Self {
        self.assets = Some(assets);
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_origins(mut self, origins: Origins) -> Self {
        self.origins = origins;
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }

    /// The writer signs with a storage authority key derived beside the service key.
    #[must_use = "use the updated builder"]
    pub fn with_storage_chain(mut self, chain: Arc<dyn StorageChain>) -> Self {
        self.storage_chain = Some(chain);
        self
    }

    /// The writer also syncs the subscribers of these curator registries.
    #[must_use = "use the updated builder"]
    pub fn with_watched_registries(mut self, registries: Vec<Address>) -> Self {
        self.watched_registries = registries;
        self
    }

    /// `Database` seals grant rows under a key the service secret derives, and needs a store.
    #[must_use = "use the updated builder"]
    pub fn with_reader_grants(mut self, store: ReaderGrantStore) -> Self {
        self.reader_grants = store;
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_relay(mut self, relay: RelayParts) -> Self {
        self.relay = Some(relay);
        self
    }

    #[must_use = "use the updated builder"]
    pub fn with_relay_services(mut self, services: RelayServices) -> Self {
        self.relay = Some(services.parts);
        self.merge = Some(services.merge);
        self
    }

    pub fn local(self, ring: Address, auditor: X25519Keypair) -> Result<Hub<S>, RingRpcError> {
        self.build(KeySource::Local { ring, auditor })
    }

    pub fn derived(self, root: RootSecret) -> Result<Hub<S>, RingRpcError> {
        self.build(KeySource::Derived(root))
    }

    fn build(self, keys: KeySource) -> Result<Hub<S>, RingRpcError> {
        let secret = keys.service_secret();
        let signer = service_keypair(secret.as_slice())?;
        let writer = self
            .store
            .clone()
            .zip(self.storage_chain)
            .map(|(store, chain)| {
                Ok::<_, RingRpcError>(Arc::new(
                    WriterParts {
                        store,
                        chain,
                        authority: storage_authority_keypair(secret.as_slice())?,
                        genesis_hash: self.genesis_hash,
                        watched: self.watched_registries,
                        rings: match &keys {
                            KeySource::Local { ring, .. } => ServedRings::One(*ring),
                            KeySource::Derived(_) => ServedRings::Any,
                        },
                        reader_grants: self.reader_grants,
                    }
                    .writer(),
                ))
            })
            .transpose()?;
        let grants = match self.reader_grants {
            ReaderGrantStore::Tree => Grants::Tree,
            ReaderGrantStore::Database => Grants::Database(Box::new(GrantRows::new(
                self.store.clone().ok_or(RingRpcError::GrantStoreMissing)?,
                GrantRowKey::derive(secret.as_slice())?,
            ))),
        };
        let assets = match self.assets {
            Some(assets) => assets,
            None => RingAssets::new([])?,
        };
        let lane = |count| (RequestRate::default(), Some(Semaphore::new(count)));
        let shared = Shared {
            source: self.source,
            genesis_hash: self.genesis_hash,
            service: signer.pubkey(),
            clock: self.clock,
            assets: AsyncMutex::new(AssetCache {
                registry: assets,
                refresh: RefreshState::Never,
            }),
            origins: self.origins,
            replay: ReplayGuard::default(),
            active_readers: Mutex::new(HashSet::new()),
            lanes: [
                (RequestRate::default(), None),
                lane(MAX_CONCURRENT_DEPOSIT_SCANS),
                lane(MAX_CONCURRENT_AUTHENTICATIONS),
                lane(MAX_CONCURRENT_READS),
            ],
            readiness: AsyncMutex::new(ReadinessCache {
                checked_at: None,
                status: ReadinessStatus::Unavailable("not checked"),
                in_flight: None,
            }),
            stores: Mutex::new(HashMap::new()),
            grants,
            database: self.store.clone(),
        };
        let shared = Arc::new(shared);
        let co_signer: Arc<dyn CoSignPolicy> = match self.store {
            Some(store) => Arc::new(
                LimitedCoSignerInit {
                    signer: co_signer_keypair(secret.as_slice())?,
                    limits: MirroredLimits(shared.clone()),
                    store: Arc::new(store),
                }
                .build(),
            ),
            None => Arc::new(RefusingCoSigner),
        };
        let relay = self
            .relay
            .map(|parts| Arc::new(Relay::new(parts).with_co_signer(co_signer.clone())));
        Ok(Hub {
            signer,
            shared,
            keys,
            writer,
            co_signer,
            relay,
            merge: self.merge,
        })
    }
}
