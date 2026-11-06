use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use spr_client::GetShieldedTransactionsByTagsResponse;
use spr_indexer_api::{Base64String, Hash, Limit, TransactionEvents};
use spr_keypair::{NullifierKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{instructions::transact::canonical_shape, ShieldedTransaction};
use zolana_ring_client::{
    auditor_view_tag, confirmed_merge,
    history::{HistoryCursor, HistoryPosition, HistoryQuery, HistoryStream, PageEnd},
    rpc::{
        cursor_in_bounds, limit_in_bounds, utxo_hashes_in_bounds, Attestation, AuditedMergesPage,
        AuditedUtxosAttestation, AuditedUtxosPage, AuditorKeyStatement, AuthorityAuth,
        ConfirmedAudit, DecryptedTransaction, DecryptedTransactionsPage, GetAuditedMergesResponse,
        GetAuditedUtxosRequest, GetAuditedUtxosResponse, GetDecryptedTransactionsResponse,
        GetSpendCoverageRequest, GetSpendCoverageResponse, GetWalletActivityResponse,
        GetWalletStatusRequest, GetWalletStatusResponse, PagedRead, ReadAttestation, ReadAuth,
        ReadTarget, ReaderGrantAction, ReaderGrantAttestation, RingChainStatus,
        SetReaderGrantRequest, SkippedReason, SkippedTransaction, SpendCoverageAttestation,
        WalletSnapshotReleaseAttestation, WalletStatusAttestation, AUDIT_PAGE_LIMIT,
    },
    AuditError, AuditedInput, AuditedTransaction, ConfirmedEventKind, ConfirmedMerge, InputOpening,
    ReaderKey, RingOrigin, RowDisposition, TransactionAudit,
};
use zolana_ring_policy::Member;

use crate::{
    authorize::{AuthorityCheck, AuthorityClaim, ReadCheck, ReadClaim, Unauthorized, WalletCheck},
    error::{redacted, GrantRefusal, RingRpcError},
    frame_repairs::RepairBook,
    grant_rows::{GrantPair, GrantRow},
    grants::{GrantQuery, Grants, ReadScope},
    hub::Shared,
    limits::ReaderPermit,
    projection_lease::{LeaseClaim, ProjectionLease},
    projection_reads::EnrollmentKey,
    record_writer::SaltedOwner,
    replay::ReplayCheck,
    spend_machine::{InputRead, Observation},
    spent_index::{LoadSpends, LoadedProjection, NoteSeal, ProjectionWriter},
    tracking::{
        HeldEnrollment, OwnerEnrollment, ScanEnd, TrackingCursor, TrackingScan, TrackingSource,
    },
    upstream::{
        Finality, MergeAuditRequest, RingConfiguration, RingFrame, RingHistoryPage,
        TransactionPage, TransactionSource,
    },
    utxos::{
        AuditStore, Backfill, CreatedIn, PageDelta, PageWork, WalletCursor, WalletStatusQuery,
        MAX_BACKFILL_PAGES,
    },
    wallet_snapshots::WalletSnapshotRelease,
};

pub(crate) const WALLET_NOTE_PAGE_LIMIT: usize = 100;
pub(crate) const ASSET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// The attested limit is what the reader signed, absent for the default page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    cursor: Option<Base64String>,
    history: Option<HistoryCursor>,
    limit: NonZeroU32,
    attested_limit: Option<Limit>,
}

pub struct AuditService<S> {
    ring: Address,
    auditor: X25519Keypair,
    view_tag: [u8; 32],
    shared: Arc<Shared<S>>,
}

#[must_use]
pub(crate) struct AuditServiceInit<S> {
    pub ring: Address,
    pub auditor: X25519Keypair,
    pub shared: Arc<Shared<S>>,
}

/// Its nonce is spent when the read executes.
struct Grant<'a, S> {
    service: &'a AuditService<S>,
    nonce: [u8; 32],
    timestamp: u64,
    /// The config read at authorization names the rail its frames parse under.
    mode: RingMode,
    scope: ReadScope,
    reader: ReaderKey,
    _reader: ReaderPermit<'a>,
}

pub(crate) struct AuthorizedRead<'a, S> {
    grant: Grant<'a, S>,
    page: &'a Page,
}

struct AuthorizedUtxos<'a, S> {
    grant: Grant<'a, S>,
    utxo_hashes: &'a [Hash],
}

#[must_use]
pub struct AuditRead<'a> {
    pub read: PagedRead,
    pub auth: &'a ReadAuth,
    pub page: &'a Page,
    /// Narrows the read to one wallet's rows.
    pub wallet: Option<Address>,
}

#[derive(Clone, Copy)]
struct BoundTransaction<'a> {
    transaction: &'a spr_client::ShieldedTransaction,
    origin: &'a RingOrigin,
    mode: RingMode,
}

enum Projection<'a> {
    /// No database, the mirror is the whole projection.
    Memory,
    Writer(ProjectionWriter<'a>),
    /// Another replica holds the lease, the local one reloaded its commits.
    Follower,
}

struct AuditedRows {
    items: Vec<DecryptedTransaction>,
    skipped: Vec<SkippedTransaction>,
    /// The first failure a retry can change, the backfill stops on it and a page read goes on.
    unfinished: Option<AuditError>,
}

impl Page {
    pub fn new(cursor: Option<Base64String>, limit: Option<Limit>) -> Result<Self, RingRpcError> {
        if cursor
            .as_ref()
            .is_some_and(|cursor| !cursor_in_bounds(&cursor.0))
            || limit.as_ref().is_some_and(|limit| !limit_in_bounds(limit))
        {
            return Err(RingRpcError::InvalidPage);
        }
        let count = limit.as_ref().map_or(AUDIT_PAGE_LIMIT, Limit::value);
        let history = cursor
            .as_ref()
            .map(|cursor| HistoryCursor::try_from(cursor.0.as_slice()))
            .transpose()
            .map_err(|_| RingRpcError::InvalidPage)?;
        Ok(Self {
            cursor,
            history,
            limit: u32::try_from(count)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or(RingRpcError::InvalidPage)?,
            attested_limit: limit,
        })
    }

    pub fn history_cursor(&self) -> Option<HistoryCursor> {
        self.history
    }

    fn position(&self, query: HistoryQuery) -> Result<HistoryPosition, RingRpcError> {
        query
            .position(self.history)
            .map_err(|_| RingRpcError::InvalidPage)
    }

    pub fn limit(&self) -> NonZeroU32 {
        self.limit
    }
}

impl<S> AuditServiceInit<S> {
    pub(crate) fn build(self) -> AuditService<S> {
        AuditService {
            ring: self.ring,
            view_tag: auditor_view_tag(&self.auditor.pubkey()),
            auditor: self.auditor,
            shared: self.shared,
        }
    }
}

impl<S: TransactionSource> AuditService<S> {
    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> X25519Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// The stored enrollment alone, no scan runs.
    pub(crate) async fn held_nullifier_key(
        &self,
        owner_key: &[u8; 32],
    ) -> Result<Option<NullifierKey>, RingRpcError> {
        let member = Member::owner_tag(owner_key)?;
        let held = self
            .shared
            .store(self.ring)
            .enrollment(EnrollmentKey::Member, member.as_bytes())
            .await?;
        Ok(held
            .map(|held| held.secrets(&self.auditor))
            .transpose()?
            .map(|secrets| secrets.nullifier_key))
    }

    pub(crate) async fn scanned_enrollment(
        &self,
        owner_key: &[u8; 32],
    ) -> Result<OwnerEnrollment, RingRpcError> {
        let member = Member::owner_tag(owner_key)?;
        self.scanned(EnrollmentKey::Member, member.as_bytes()).await
    }

    /// The owner whose list key `written_key` is, with the salt its enrollment seals.
    pub(crate) async fn salted_owner(
        &self,
        written_key: &[u8; 32],
    ) -> Result<Option<SaltedOwner>, RingRpcError> {
        let held = self
            .scanned(EnrollmentKey::ListKey, written_key)
            .await?
            .known()?;
        held.map(|held| {
            Ok(SaltedOwner {
                owner: Address::new_from_array(held.owner_key),
                list_salt: held.secrets(&self.auditor)?.list_salt,
            })
        })
        .transpose()
    }

    async fn scanned(
        &self,
        key: EnrollmentKey,
        value: &[u8; 32],
    ) -> Result<OwnerEnrollment, RingRpcError> {
        let store = self.shared.store(self.ring);
        // 1. The read claims a free lease, a follower answers from the holder's commits alone and
        //    never scans into its mirror.
        let scanned = {
            let mut guard = store.backfill.lock().await;
            let backfill = &mut *guard;
            let seal = self.note_seal()?;
            match self.projection(&store, backfill, &seal).await? {
                Projection::Memory => {
                    self.refresh_enrollments(&store, &mut backfill.tracking_cursor, None)
                        .await?
                }
                Projection::Writer(writer) => {
                    self.refresh_enrollments(&store, &mut backfill.tracking_cursor, Some(&writer))
                        .await?
                }
                // The cursor counts finalized leaves, so it compares against the finalized root.
                Projection::Follower => match self
                    .shared
                    .source
                    .root(self.ring, Finality::Finalized)
                    .await?
                {
                    Some(root) if backfill.tracking_cursor.next_leaf() < root.next_index => {
                        ScanEnd::Partial
                    }
                    _ => ScanEnd::Complete,
                },
            }
        };
        // 2. A held enrollment answers whatever the scan end, a missing one only after a complete scan.
        Ok(match (store.enrollment(key, value).await?, scanned) {
            (Some(held), _) => OwnerEnrollment::Held(Box::new(held)),
            (None, ScanEnd::Complete) => OwnerEnrollment::Absent,
            (None, ScanEnd::Partial) => OwnerEnrollment::Unknown,
        })
    }

    pub(crate) async fn enrolled_list_salt(
        &self,
        owner_key: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, RingRpcError> {
        let held = self.scanned_enrollment(owner_key).await?.known()?;
        Ok(held
            .map(|held| held.secrets(&self.auditor))
            .transpose()?
            .map(|secrets| secrets.list_salt))
    }

    pub(crate) async fn escrowed_key(
        &self,
        owner_key: &[u8; 32],
    ) -> Result<Option<NullifierKey>, RingRpcError> {
        let held = self.scanned_enrollment(owner_key).await?.known()?;
        Ok(held
            .map(|held| held.secrets(&self.auditor))
            .transpose()?
            .map(|secrets| secrets.nullifier_key))
    }

    /// `None` until the config exists, the config then fixes the key forever.
    pub async fn configured_auditor(&self) -> Result<Option<X25519Pubkey>, RingRpcError> {
        let config = self.shared.source.ring_config(self.ring).await?;
        Ok(config.map(|config| config.auditor_pubkey))
    }

    /// `None` unless the ring's config names the auditor key held here.
    pub(crate) async fn served_config(&self) -> Result<Option<RingConfiguration>, RingRpcError> {
        let config = self.shared.source.ring_config(self.ring).await?;
        Ok(config.filter(|config| config.auditor_pubkey == self.auditor.pubkey()))
    }

    pub async fn chain_status(&self) -> Result<RingChainStatus, RingRpcError> {
        Ok(self.shared.source.ring_chain_status(self.ring).await?)
    }

    pub async fn read(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.authorize(request).await?.execute().await
    }

    pub async fn wallet_activity(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetWalletActivityResponse, RingRpcError> {
        self.authorize(request)
            .await?
            .execute_wallet_activity()
            .await
    }

    /// Reads only the store's finalized state, the response names no other transaction.
    pub async fn wallet_status(
        &self,
        request: &GetWalletStatusRequest,
    ) -> Result<GetWalletStatusResponse, RingRpcError> {
        let cursor = request
            .cursor
            .as_ref()
            .map(|cursor| WalletCursor::decode(&cursor.0))
            .transpose()?;
        let wallet = request.wallet.0;
        let attestation = WalletStatusAttestation {
            target: self.read_target(),
            wallet,
            cursor: request.cursor.clone(),
        };
        let grant = self
            .grant(&request.auth, &attestation, Some(wallet))
            .await?;
        grant.spend().await?;
        // The owner's own authorization account answers, it needs no scan.
        let enrollment = self
            .shared
            .source
            .tracking_enrollment(self.ring, wallet)
            .await?;
        self.shared
            .store(self.ring)
            .wallet_status(WalletStatusQuery {
                principal: grant.reader.to_bytes(),
                now: self.shared.clock.now()?,
                enrollment,
                wallet,
                ring: self.ring,
                after: cursor,
                limit: WALLET_NOTE_PAGE_LIMIT,
            })
            .await
    }

    pub async fn release_wallet_snapshot(
        &self,
        request: &GetWalletStatusRequest,
    ) -> Result<bool, RingRpcError> {
        let encoded = request.cursor.as_ref().ok_or(RingRpcError::InvalidCursor)?;
        let cursor = WalletCursor::decode(&encoded.0)?;
        let wallet = request.wallet.0;
        let attestation = WalletSnapshotReleaseAttestation {
            target: self.read_target(),
            wallet,
            cursor: encoded.clone(),
        };
        let grant = self
            .grant(&request.auth, &attestation, Some(wallet))
            .await?;
        grant.spend().await?;
        self.shared
            .store(self.ring)
            .release_wallet_snapshot(WalletSnapshotRelease {
                ring: self.ring,
                wallet,
                principal: grant.reader.to_bytes(),
                cursor,
                now: self.shared.clock.now()?,
            })
            .await?;
        Ok(true)
    }

    /// The one read that names an unresolved spend, a reader grant never reaches it.
    pub async fn spend_coverage(
        &self,
        request: &GetSpendCoverageRequest,
    ) -> Result<GetSpendCoverageResponse, RingRpcError> {
        let authority = request.authority.0;
        let now = self.shared.clock.now()?;
        let nonce = WalletCheck {
            wallet: authority,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            signature: &request.signature,
            attestation: &SpendCoverageAttestation {
                target: self.read_target(),
                authority,
                cursor: request.cursor.clone(),
            },
            now,
        }
        .decide()?;
        self.shared
            .require_ring_authority(self.ring, authority)
            .await?;
        self.shared
            .replay
            .accept(ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: request.timestamp,
                now,
            })
            .await?;
        let cursor = request.cursor.as_ref().map_or_else(
            || Ok(crate::spend_coverage::CoverageCursor::new(self.ring)),
            |cursor| crate::spend_coverage::CoverageCursor::decode(&cursor.0, self.ring),
        )?;
        self.shared.store(self.ring).spend_coverage(cursor).await
    }

    /// A limited co-signer opens the frame it signs under the served ring's key.
    pub(crate) const fn auditor_keypair(&self) -> &X25519Keypair {
        &self.auditor
    }

    pub async fn audited_utxos(
        &self,
        request: &GetAuditedUtxosRequest,
    ) -> Result<GetAuditedUtxosResponse, RingRpcError> {
        self.authorize_utxos(request).await?.execute().await
    }

    /// The upgrade authority asks before `Initialize`, the policy authority after.
    pub async fn auditor_key_statement(
        &self,
        auth: &AuthorityAuth,
    ) -> Result<Vec<u8>, RingRpcError> {
        let now = self.shared.clock.now()?;
        let AuthorityClaim { authority, nonce } = AuthorityCheck {
            auth,
            ring: self.ring,
            genesis_hash: self.shared.genesis_hash,
            now,
        }
        .decide()?;
        self.shared
            .require_ring_authority(self.ring, authority)
            .await?;
        self.shared
            .replay
            .accept(ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: auth.timestamp,
                now: self.shared.clock.now()?,
            })
            .await?;
        Ok(AuditorKeyStatement {
            cluster: &self.shared.genesis_hash,
            ring: &self.ring,
            auditor_pubkey: &self.auditor.pubkey(),
            nonce: &nonce,
        }
        .message())
    }

    /// The service's own cluster, key and ring, a reader's signature carries to no other.
    pub(crate) fn read_target(&self) -> ReadTarget {
        ReadTarget {
            cluster: self.shared.genesis_hash,
            service: self.shared.service,
            ring: self.ring,
        }
    }

    pub(crate) async fn authorize<'a>(
        &'a self,
        request: AuditRead<'a>,
    ) -> Result<AuthorizedRead<'a, S>, RingRpcError> {
        let attestation = ReadAttestation {
            read: request.read,
            target: self.read_target(),
            cursor: request.page.cursor.clone(),
            limit: request.page.attested_limit.clone(),
            wallet: request.wallet,
        };
        Ok(AuthorizedRead {
            grant: self
                .grant(request.auth, &attestation, request.wallet)
                .await?,
            page: request.page,
        })
    }

    /// Refuses a count out of bounds before the signature is checked.
    async fn authorize_utxos<'a>(
        &'a self,
        request: &'a GetAuditedUtxosRequest,
    ) -> Result<AuthorizedUtxos<'a, S>, RingRpcError> {
        if !utxo_hashes_in_bounds(&request.utxo_hashes) {
            return Err(RingRpcError::InvalidUtxoRequest);
        }
        let wallet = request.wallet.map(|wallet| wallet.0);
        let attestation = AuditedUtxosAttestation {
            wallet,
            ..AuditedUtxosAttestation::new(self.read_target(), &request.utxo_hashes)
        };
        Ok(AuthorizedUtxos {
            grant: self.grant(&request.auth, &attestation, wallet).await?,
            utxo_hashes: &request.utxo_hashes,
        })
    }

    async fn grant<'a>(
        &'a self,
        auth: &ReadAuth,
        attestation: &impl Attestation,
        wallet: Option<Address>,
    ) -> Result<Grant<'a, S>, RingRpcError> {
        let ReadClaim { reader, nonce } = ReadCheck {
            auth,
            attestation,
            now: self.shared.clock.now()?,
            origins: &self.shared.origins,
        }
        .decide()?;
        let permit = ReaderPermit::acquire(&self.shared.active_readers, (self.ring, reader))?;
        let source = &self.shared.source;
        let config = source
            .ring_config(self.ring)
            .await?
            .ok_or(Unauthorized::NoConfig)?;
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        let scope = self
            .shared
            .read_scope(GrantQuery {
                ring: self.ring,
                reader,
                wallet,
            })
            .await?;
        Ok(Grant {
            service: self,
            nonce,
            timestamp: auth.timestamp,
            mode: config.mode,
            scope,
            reader,
            _reader: permit,
        })
    }

    /// Returns the action the store holds for the grant after the write.
    pub async fn set_reader_grant(
        &self,
        request: &SetReaderGrantRequest,
    ) -> Result<ReaderGrantAction, RingRpcError> {
        let Grants::Database(rows) = &self.shared.grants else {
            return Err(GrantRefusal::GrantsInTree.into());
        };
        let reader = <[u8; 34]>::try_from(request.reader.0.as_slice())
            .ok()
            .and_then(|tagged| ReaderKey::from_bytes(tagged).ok())
            .ok_or(Unauthorized::UnknownReaderKey)?;
        let wallet = request.wallet.map(|wallet| wallet.0);
        let signer = match wallet {
            Some(wallet) => wallet,
            None => {
                self.shared
                    .source
                    .ring_config(self.ring)
                    .await?
                    .ok_or(Unauthorized::NoConfig)?
                    .roles
                    .policy
            }
        };
        let attestation = ReaderGrantAttestation {
            target: self.read_target(),
            wallet,
            reader,
            action: request.action,
        };
        let nonce = WalletCheck {
            wallet: signer,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            signature: &request.signature,
            attestation: &attestation,
            now: self.shared.clock.now()?,
        }
        .decide()?;
        self.shared
            .replay
            .accept(ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: request.timestamp,
                now: self.shared.clock.now()?,
            })
            .await?;
        rows.write(GrantRow {
            pair: GrantPair {
                ring: self.ring,
                wallet,
                reader,
            },
            action: request.action,
            timestamp: request.timestamp,
        })
        .await
    }

    /// Opens the ring's transfers, audited deposits and merges from the durable position.
    pub async fn backfill_utxos(&self) -> Result<(), RingRpcError> {
        let store = self.shared.store(self.ring);
        let Some(config) = self.shared.source.ring_config(self.ring).await? else {
            return Ok(());
        };
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        let mut guard = store.backfill.lock().await;
        let backfill = &mut *guard;
        let seal = self.note_seal()?;
        match self.projection(&store, backfill, &seal).await? {
            Projection::Memory => self.read_history(&store, backfill, None, config.mode).await,
            Projection::Writer(writer) => {
                self.read_history(&store, backfill, Some(&writer), config.mode)
                    .await
            }
            Projection::Follower => Ok(()),
        }
    }

    /// A follower reloads the holder's commits on every pass, a new holder once.
    async fn projection<'a>(
        &'a self,
        store: &AuditStore,
        backfill: &mut Backfill,
        seal: &'a NoteSeal,
    ) -> Result<Projection<'a>, RingRpcError> {
        let Some(database) = self.shared.database.as_ref() else {
            return Ok(Projection::Memory);
        };
        let lease = LeaseClaim {
            db: database.connection(),
            ring: self.ring,
            holder: database.lease_holder(),
            now: self.shared.clock.now()?,
        }
        .claim()
        .await?;
        if lease.is_none() || lease != backfill.writer || backfill.history.is_none() {
            self.reload(store, backfill, seal).await?;
        }
        backfill.writer = lease;
        Ok(match self.writer(lease, seal) {
            Some(writer) => Projection::Writer(writer),
            None => Projection::Follower,
        })
    }

    /// `None` without a database or a held lease.
    fn writer<'a>(
        &'a self,
        lease: Option<ProjectionLease>,
        seal: &'a NoteSeal,
    ) -> Option<ProjectionWriter<'a>> {
        let database = self.shared.database.as_ref()?;
        lease.map(|lease| ProjectionWriter {
            db: database.connection(),
            ring: self.ring,
            seal,
            lease,
            clock: self.shared.clock,
        })
    }

    async fn reload(
        &self,
        store: &AuditStore,
        backfill: &mut Backfill,
        seal: &NoteSeal,
    ) -> Result<(), RingRpcError> {
        let Some(database) = self.shared.database.as_ref() else {
            return Ok(());
        };
        let LoadedProjection {
            spends,
            repairs,
            enrollments,
            tracking_cursor,
            revision,
        } = LoadSpends {
            db: database.connection(),
            ring: self.ring,
            seal,
            scope: store.history_scope(),
        }
        .load()
        .await?;
        // 1. The snapshot's unread frames replace the mirror's, a frame the holder read since leaves.
        let position = spends.checkpoint.position;
        store.refresh(spends, revision);
        // 2. Stored enrollments warm the cache, a row never changes once it committed.
        store.cache_enrollments(enrollments);
        backfill.history = Some(position);
        backfill.tracking_cursor = tracking_cursor;
        backfill.repairs = repairs.into_iter().collect();
        Ok(())
    }

    fn note_seal(&self) -> Result<NoteSeal, RingRpcError> {
        Ok(NoteSeal::derive(&self.auditor, self.ring)?)
    }

    /// The transaction commits before the mirror moves, a crash replays the page idempotently.
    async fn commit_page(
        &self,
        store: &AuditStore,
        durable: Option<&ProjectionWriter<'_>>,
        delta: PageDelta,
    ) -> Result<(), RingRpcError> {
        let delta = match durable {
            Some(writer) => {
                let revision = writer.commit_page(&delta).await?;
                delta.at_commit(revision)
            }
            None => delta,
        };
        store.commit(delta);
        Ok(())
    }

    /// An unreadable secret reads as absent, the note stays `Unknown` until it opens.
    fn open_enrollment(&self, held: &HeldEnrollment) -> Option<NullifierKey> {
        held.secrets(&self.auditor)
            .inspect_err(|error| {
                log::warn!("a held key failed to open because {error}");
            })
            .ok()
            .map(|secrets| secrets.nullifier_key)
    }

    /// Moves the position only past a page whose every row applied, a retry reads it again.
    async fn read_history(
        &self,
        store: &AuditStore,
        backfill: &mut Backfill,
        durable: Option<&ProjectionWriter<'_>>,
        mode: RingMode,
    ) -> Result<(), RingRpcError> {
        let source = &self.shared.source;
        let limit = Page::new(None, None)?.limit();
        let Backfill {
            history,
            tracking_cursor,
            repairs,
            ..
        } = backfill;
        let position = history.get_or_insert_default();
        // Read before the repairs, a frame unread for want of a key opens once its enrollment is held.
        self.refresh_or_warn(store, tracking_cursor, durable).await;
        self.repair_frames(store, repairs, durable, mode).await;
        let opener = |held: &HeldEnrollment| self.open_enrollment(held);
        for _ in 0..MAX_BACKFILL_PAGES {
            let response = source
                .ring_history(RingHistoryPage {
                    ring: self.ring,
                    position: *position,
                    limit,
                })
                .await?;
            let mut next = *position;
            let end = next
                .advance(&response, limit.get())
                .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
            self.validate_indexer_response(&response)?;
            // Read after the page, an enrollment finalized before a note on it is held unless the refresh stops early.
            self.refresh_or_warn(store, tracking_cursor, durable).await;
            let mut work = PageWork::new(store, &opener);
            work.late_keys();
            let rows = self.audit_rows(response, mode, &mut work, None).await?;
            if let Some(error) = rows.unfinished {
                return Err(error.into());
            }
            let terminal = match end {
                PageEnd::Terminal(context) => Some(context),
                PageEnd::More => None,
            };
            work.checkpoint(next, terminal);
            self.commit_page(store, durable, work.finish().await?)
                .await?;
            *position = next;
            if terminal.is_some() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Reads each due unread frame by its signature, a failure backs off its own frame alone.
    async fn repair_frames(
        &self,
        store: &AuditStore,
        repairs: &mut RepairBook,
        durable: Option<&ProjectionWriter<'_>>,
        mode: RingMode,
    ) {
        let now = match self.shared.clock.now() {
            Ok(now) => now,
            Err(error) => {
                log::warn!(
                    "frame repair of ring {} has no clock because {}",
                    self.ring,
                    redacted(&error)
                );
                return;
            }
        };
        let mut failed = Vec::new();
        let due = match store.due_repairs(repairs, now).await {
            Ok(due) => due,
            Err(error) => {
                log::warn!(
                    "frame repair of ring {} did not load because {}",
                    self.ring,
                    redacted(&error)
                );
                return;
            }
        };
        for frame in due {
            match self.repair_frame(store, durable, mode, frame).await {
                Ok(true) => repairs.forget(&frame),
                outcome => {
                    if let Err(error) = outcome {
                        log::warn!(
                            "repair of ring {} frame {}:{} failed because {}",
                            self.ring,
                            frame.tx_signature,
                            frame.event_index,
                            redacted(&error)
                        );
                    }
                    failed.push((frame, repairs.failed(frame, now)));
                }
            }
        }
        if let Some(writer) = durable.filter(|_| !failed.is_empty()) {
            if let Err(error) = writer.record_attempts(&failed).await {
                log::warn!(
                    "repair attempts of ring {} did not commit because {}",
                    self.ring,
                    redacted(&RingRpcError::from(error))
                );
            }
        }
    }

    /// `true` once the committed page marked the frame read.
    async fn repair_frame(
        &self,
        store: &AuditStore,
        durable: Option<&ProjectionWriter<'_>>,
        mode: RingMode,
        frame: CreatedIn,
    ) -> Result<bool, RingRpcError> {
        let events = self
            .shared
            .source
            .ring_frame(RingFrame {
                ring: self.ring,
                signature: frame.tx_signature,
                slot: frame.slot,
            })
            .await?;
        let response = GetShieldedTransactionsByTagsResponse {
            context: store.context(),
            output_tree_id: None,
            data: vec![TransactionEvents {
                slot: frame.slot,
                signature: frame.tx_signature,
                events,
            }],
            pagination_token: None,
        };
        self.validate_indexer_response(&response)?;
        let opener = |held: &HeldEnrollment| self.open_enrollment(held);
        let mut work = PageWork::new(store, &opener);
        work.late_keys();
        let rows = self
            .audit_rows(response, mode, &mut work, Some(frame))
            .await?;
        if let Some(error) = rows.unfinished {
            return Err(error.into());
        }
        let delta = work.finish().await?;
        let read = delta.read_frames().any(|read| *read == frame);
        self.commit_page(store, durable, delta).await?;
        Ok(read)
    }

    /// A failed refresh keeps every admitted page, the next pass resumes at its cursor.
    async fn refresh_or_warn(
        &self,
        store: &AuditStore,
        cursor: &mut TrackingCursor,
        durable: Option<&ProjectionWriter<'_>>,
    ) {
        if let Err(error) = self.refresh_enrollments(store, cursor, durable).await {
            log::warn!(
                "enrollment refresh of ring {} failed because {}",
                self.ring,
                redacted(&error)
            );
        }
    }

    /// The caller holds the backfill lock that owns `cursor`.
    async fn refresh_enrollments(
        &self,
        store: &AuditStore,
        cursor: &mut TrackingCursor,
        durable: Option<&ProjectionWriter<'_>>,
    ) -> Result<ScanEnd, RingRpcError> {
        if let Some(writer) = durable {
            store.replace_late_owners(writer.pending_owners().await?);
        }
        TrackingScan {
            ring: self.ring,
            auditor: &self.auditor,
            source: &self.shared.source,
            store,
            durable,
        }
        .run(cursor)
        .await
    }

    fn audit(&self, bound: BoundTransaction<'_>) -> Result<AuditedTransaction, AuditError> {
        TransactionAudit::new(bound.transaction, bound.origin.audit_frame(bound.mode)?)
            .run(&self.auditor)
    }

    /// A page read writes nothing, only the backfill's checkpoint feeds the index.
    async fn decrypted_transactions(
        &self,
        page: &Page,
        mode: RingMode,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let query = HistoryQuery {
            ring: self.ring,
            stream: HistoryStream::Tags,
        };
        let mut position = page.position(query)?;
        let limit = page.limit();
        let response = self
            .shared
            .source
            .transactions_by_tag(TransactionPage {
                ring: self.ring,
                tag: self.view_tag,
                position,
                limit,
            })
            .await?;
        let _ = position
            .advance(&response, limit.get())
            .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
        self.validate_indexer_response(&response)?;
        let context = response.context;
        let cursor = query.next_cursor(&position).map(Into::into);
        let store = self.shared.store(self.ring);
        let opener = |held: &HeldEnrollment| self.open_enrollment(held);
        let mut work = PageWork::new(&store, &opener);
        let rows = self.audit_rows(response, mode, &mut work, None).await?;
        Ok(GetDecryptedTransactionsResponse {
            context,
            value: DecryptedTransactionsPage {
                items: rows.items,
                skipped: rows.skipped,
                cursor,
            },
        })
    }

    /// Only a row of the served ring meets the shape check, a feature build can publish other shapes.
    fn validate_indexer_response(
        &self,
        response: &GetShieldedTransactionsByTagsResponse,
    ) -> Result<(), RingRpcError> {
        // Compact padding leaves trailing slots out, a transaction publishes at most its shape.
        let unsupported = response
            .data
            .iter()
            .flat_map(|item| &item.events)
            .any(|transaction| {
                transaction.ring_program_id == Some(self.ring)
                    && transaction
                        .messages
                        .iter()
                        .any(|message| message.view_tag == self.view_tag)
                    && (transaction.nullifiers.is_empty()
                        || canonical_shape(
                            transaction.nullifiers.len(),
                            transaction.output_slots.len(),
                        )
                        .is_err())
            });
        if unsupported {
            return Err(RingRpcError::InvalidIndexerResponse);
        }
        Ok(())
    }

    /// The record opens the output, its nullifiers mark the inputs through the machine.
    fn read_merge(&self, row: MergeRow<'_, '_>) {
        let MergeRow {
            tx,
            merge,
            created_in,
            work,
        } = row;
        let record = merge.disclosed();
        observe_all(work, tx, created_in, |position| {
            match tx
                .nullifiers
                .get(usize::from(position))
                .is_some_and(|nullifier| record.real_nullifiers.contains(nullifier))
            {
                true => InputRead::Real,
                false => InputRead::Padding,
            }
        });
        let note = merge.output().and_then(|output| output.created_utxo()).ok();
        match note {
            Some(note) => {
                work.open(created_in, [note]);
                work.mark_read(created_in);
            }
            None => work.mark_unread(created_in),
        }
    }

    /// `only` narrows a retry to its frame, a read failure leaves the frame to the next pass.
    async fn audit_rows(
        &self,
        response: GetShieldedTransactionsByTagsResponse,
        mode: RingMode,
        work: &mut PageWork<'_>,
        only: Option<CreatedIn>,
    ) -> Result<AuditedRows, RingRpcError> {
        let source = &self.shared.source;
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut unfinished = None;
        let mut origins: HashMap<(Signature, u16), RingOrigin> = HashMap::new();
        for mut tx in response.data.into_iter().flat_map(|item| item.events) {
            if tx.ring_program_id != Some(self.ring) {
                continue;
            }
            let event_index = tx.event_index.ok_or(RingRpcError::InvalidIndexerResponse)?;
            if only.is_some_and(|frame| {
                frame.tx_signature != tx.tx_signature || frame.event_index != event_index
            }) {
                continue;
            }
            let created_in = CreatedIn {
                slot: tx.slot,
                tx_signature: tx.tx_signature,
                event_index,
            };
            let origin = match origins.get(&(tx.tx_signature, event_index)) {
                Some(known) => known.clone(),
                None => {
                    match source
                        .transaction_origin(tx.tx_signature, event_index, self.ring)
                        .await
                    {
                        Ok(found) => {
                            origins.insert((tx.tx_signature, event_index), found.clone());
                            found
                        }
                        Err(error) if error.disposition() == RowDisposition::Retry => {
                            return Err(error.into())
                        }
                        Err(error) => {
                            log::warn!(
                                "ring {} event {}:{event_index} has no readable origin because {}",
                                self.ring,
                                tx.tx_signature,
                                redacted(&error)
                            );
                            work.mark_unread(created_in);
                            skipped.push(SkippedTransaction {
                                slot: tx.slot,
                                tx_signature: tx.tx_signature.into(),
                                event_index,
                                reason: SkippedReason::InvalidAuditData,
                            });
                            continue;
                        }
                    }
                }
            };
            if !origin.ring_invoked {
                continue;
            }
            let bound = origin.bind_transaction(&mut tx, self.ring);
            if bound.is_ok() && origin.event.kind() == ConfirmedEventKind::Merge {
                match confirmed_merge(&tx, event_index, &origin, &self.auditor) {
                    Ok(Some(merge)) => self.read_merge(MergeRow {
                        tx: &tx,
                        merge,
                        created_in,
                        work,
                    }),
                    Ok(None) => {
                        observe_all(work, &tx, created_in, |_| InputRead::Real);
                        work.mark_read(created_in);
                    }
                    Err(error) if error.disposition() == RowDisposition::Retry => {
                        unfinished.get_or_insert(error);
                    }
                    Err(error) => {
                        log::warn!(
                            "ring {} merge {}:{event_index} is unreadable because {}",
                            self.ring,
                            tx.tx_signature,
                            redacted(&error)
                        );
                        observe_all(work, &tx, created_in, |_| InputRead::Unreadable);
                        work.mark_unread(created_in);
                    }
                }
                continue;
            }
            if !origin.requires_audit() {
                if let Err(error) = bound {
                    log::warn!(
                        "ring {} event {}:{event_index} opened no UTXOs because {}",
                        self.ring,
                        tx.tx_signature,
                        redacted(&error)
                    );
                    if error.disposition() == RowDisposition::Retry {
                        unfinished.get_or_insert(error);
                    } else {
                        work.mark_unread(created_in);
                    }
                }
                continue;
            }
            let opened = bound.and_then(|()| {
                self.audit(BoundTransaction {
                    transaction: &tx,
                    origin: &origin,
                    mode,
                })
            });
            if let Ok(opened) = &opened {
                work.open(created_in, opened.utxos());
                for (position, input) in opened.inputs.iter().enumerate() {
                    work.observe(Observation {
                        nullifier: input.nullifier,
                        frame: created_in,
                        position: u16::try_from(position).unwrap_or(u16::MAX),
                        read: audited_input_read(input),
                        hit: None,
                    });
                }
                work.mark_read(created_in);
            }
            let result = opened.and_then(|opened| Ok((opened, origin.spenders(mode)?)));
            match result {
                Ok((opened, spenders)) => items.push(
                    ConfirmedAudit {
                        audited: opened,
                        event_index,
                        nullifiers: tx.nullifiers,
                        spenders,
                        signers: origin.signers,
                        withdrawals: origin.withdrawals,
                    }
                    .into(),
                ),
                Err(error) => {
                    if error.disposition() != RowDisposition::Retry {
                        if origin_is_bound(&origin, &tx) {
                            observe_all(work, &tx, created_in, |_| InputRead::Unreadable);
                        }
                        work.mark_unread(created_in);
                    }
                    skipped.push(SkippedTransaction {
                        slot: tx.slot,
                        tx_signature: tx.tx_signature.into(),
                        event_index,
                        reason: match error {
                            AuditError::MissingAuditorMessage => {
                                SkippedReason::MissingAuditorMessage
                            }
                            _ => SkippedReason::InvalidAuditData,
                        },
                    });
                    if error.disposition() == RowDisposition::Retry {
                        unfinished.get_or_insert(error);
                    }
                }
            }
        }
        Ok(AuditedRows {
            items,
            skipped,
            unfinished,
        })
    }
}

impl<S> Grant<'_, S> {
    /// The clock is read again, a nonce evicted while the read awaited stays spent.
    async fn spend(&self) -> Result<(), RingRpcError> {
        let service = self.service;
        service
            .shared
            .replay
            .accept(ReplayCheck {
                ring: service.ring,
                nonce: self.nonce,
                timestamp: self.timestamp,
                now: service.shared.clock.now()?,
            })
            .await
    }
}

impl<S: TransactionSource> AuthorizedRead<'_, S> {
    pub(crate) async fn execute(self) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let ReadScope::Ring = self.grant.scope else {
            return Err(GrantRefusal::WalletScope.into());
        };
        let service = self.grant.service;
        self.grant.spend().await?;
        service
            .decrypted_transactions(self.page, self.grant.mode)
            .await
    }

    pub(crate) async fn execute_wallet_activity(
        self,
    ) -> Result<GetWalletActivityResponse, RingRpcError> {
        let ReadScope::Wallet(scope) = self.grant.scope else {
            return Err(GrantRefusal::WalletScope.into());
        };
        let service = self.grant.service;
        self.grant.spend().await?;
        let response = service
            .decrypted_transactions(self.page, self.grant.mode)
            .await?;
        scope
            .activity(response, &service.shared.store(service.ring))
            .await
    }

    pub(crate) async fn execute_merges(self) -> Result<GetAuditedMergesResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend().await?;
        let page = service
            .shared
            .source
            .merge_audit_page(MergeAuditRequest {
                ring: service.ring,
                auditor: &service.auditor,
                page: self.page,
            })
            .await
            .map_err(|error| match error {
                AuditError::InvalidHistoryPage => RingRpcError::InvalidIndexerResponse,
                AuditError::HistoryCursor(_) => RingRpcError::InvalidPage,
                error => error.into(),
            })?;
        let store = service.shared.store(service.ring);
        let mut value = AuditedMergesPage {
            opened: Vec::new(),
            cursor: page.next_cursor.map(Into::into),
        };
        for merge in page.merges {
            // A merge the checkpoint has not opened stays out, no reader learns it is unresolved.
            if let Some(output) = store.merge_output(&merge).await? {
                value.opened.push((&output).into());
            }
        }
        self.grant.scope.merges(&mut value);
        Ok(GetAuditedMergesResponse {
            context: page.context,
            value,
        })
    }
}

impl<S: TransactionSource> AuthorizedUtxos<'_, S> {
    /// The store answers alone, a UTXO no page or backfill opened yet reads `null`.
    async fn execute(self) -> Result<GetAuditedUtxosResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend().await?;
        let store = service.shared.store(service.ring);
        let mut utxos = Vec::with_capacity(self.utxo_hashes.len());
        for hash in self.utxo_hashes.iter() {
            utxos.push(self.grant.scope.utxo(store.view(hash).await?));
        }
        Ok(GetAuditedUtxosResponse {
            context: store.context(),
            value: AuditedUtxosPage { utxos },
        })
    }
}

struct MergeRow<'a, 'w> {
    tx: &'a ShieldedTransaction,
    merge: ConfirmedMerge,
    created_in: CreatedIn,
    work: &'a mut PageWork<'w>,
}

fn observe_all(
    work: &mut PageWork<'_>,
    tx: &ShieldedTransaction,
    created_in: CreatedIn,
    read: impl Fn(u16) -> InputRead,
) {
    for (position, nullifier) in tx.nullifiers.iter().enumerate() {
        let position = u16::try_from(position).unwrap_or(u16::MAX);
        work.observe(Observation {
            nullifier: *nullifier,
            frame: created_in,
            position,
            read: read(position),
            hit: None,
        });
    }
}

/// The proven input map and default bits decide, the index names the note a real input spent.
fn audited_input_read(input: &AuditedInput) -> InputRead {
    match &input.opening {
        InputOpening::Dummy => InputRead::Padding,
        InputOpening::Address => InputRead::Address,
        InputOpening::External(_) => InputRead::External,
        InputOpening::Real => InputRead::Real,
    }
}

/// Only a row bound to its confirmed event publishes nullifiers.
fn origin_is_bound(origin: &RingOrigin, tx: &ShieldedTransaction) -> bool {
    let mut bound = tx.clone();
    origin
        .bind_transaction(&mut bound, tx.ring_program_id.unwrap_or_default())
        .is_ok()
}
