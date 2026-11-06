use std::{future::Future, num::NonZeroU32, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{
    storage::StorageRegistry,
    tracking::{TrackingAuthorization, TrackingRegistry, TRACKING_CAPACITY},
    CoSignScope, OwnerGrant, ReaderKeyBytes, RingAccount, RingMode, RingPolicy, RingRoles,
};
use custom_ring_sdk::{CustomRing, RingError};
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_loader_v3_interface::get_program_data_address;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as NonblockingRpcClient;
use solana_signature::Signature;
use spr_api::SprApi;
use spr_client::{
    rpc::ProgramAccountsFilter, AsyncRpc, AsyncSolanaRpc, AsyncSprIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, RingHistoryOptions,
};
use spr_interface::{
    pda,
    state::{discriminator::SPL_ASSET_REGISTRY, SplAssetRegistry},
    BPF_LOADER_UPGRADEABLE_ID, PROGRAM_ID_PUBKEY,
};
use spr_keypair::X25519Pubkey;
use spr_transaction::{AssetRegistry, Mint, ShieldedTransaction, SOL_MINT};
use zolana_ring_client::{
    history::HistoryPosition, program_data, AsyncRingIndexer, AuditError, MemberOpeningRead,
    MergeAudit, MergeAuditPage, RingIndexerError, RingOrigin, StorageTip, TransactionOrigin,
};
use zolana_ring_indexer::rpc::{
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
    GetStorageMemberRecordsRequest, GetStorageMemberRecordsResponse,
};
use zolana_ring_transaction::RingAssets;

use zolana_ring_client::rpc::{RingChainStatus, WalletEnrollment};
use zolana_ring_indexer::tracking::{GetTrackingRecordsRequest, GetTrackingRecordsResponse};

use crate::{
    audit::Page,
    cosign::CoSignError,
    error::RingRpcError,
    finalized_history::{
        FinalizedHistory, FinalizedPage, FinalizedUpstreams, HistorySelection, OriginRead,
    },
};

pub trait TransactionSource: Send + Sync {
    /// The authorities of the registries a salted list reads.
    fn salted_list_writers(
        &self,
        _ring: Address,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send {
        async { Ok(Vec::new()) }
    }

    fn transactions_by_tag(
        &self,
        request: TransactionPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    /// The events of one finalized ring signature, each bound to its confirmed origin.
    fn ring_frame(
        &self,
        frame: RingFrame,
    ) -> impl Future<Output = Result<Vec<ShieldedTransaction>, ClientError>> + Send;

    /// Rows strictly after the requested position, in history order.
    fn ring_history(
        &self,
        request: RingHistoryPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    fn merge_audit_page<'a>(
        &'a self,
        request: MergeAuditRequest<'a>,
    ) -> impl Future<Output = Result<MergeAuditPage, AuditError>> + Send + 'a;

    fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send;

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send;

    fn ring_chain_status(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RingChainStatus, ClientError>> + Send;

    fn slot(&self) -> impl Future<Output = Result<u64, ClientError>> + Send;

    fn records_root(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RecordsTip, ClientError>> + Send;

    fn storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberOpeningsResponse, RingIndexerError>> + Send;

    fn storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberRecordsResponse, RingIndexerError>> + Send;

    /// `None` for a program that is immutable or not deployed.
    fn upgrade_authority(
        &self,
        program: Address,
    ) -> impl Future<Output = Result<Option<Address>, ClientError>> + Send;

    fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Binds every derived auditor key to one cluster.
    fn genesis_hash(&self) -> impl Future<Output = Result<[u8; 32], ClientError>> + Send;

    fn ring_assets(&self) -> impl Future<Output = Result<RingAssets, ClientError>> + Send;

    /// The id a tree's commitments hash under.
    fn tree_id(&self, tree: Address) -> impl Future<Output = Result<u16, RingError>> + Send;

    /// The classes the ring's record of `signer` holds.
    fn co_signer_scope(
        &self,
        _ring: Address,
        _signer: Address,
    ) -> impl Future<Output = Result<Option<CoSignScope>, RingRpcError>> + Send {
        async { Ok(None) }
    }

    /// The newest root of the ring's pinned tracking registry at `finality`, `None` reads no
    /// owner's secret.
    fn tracking_root(
        &self,
        _ring: Address,
        _finality: Finality,
    ) -> impl Future<Output = Result<Option<TrackingRoot>, ClientError>> + Send {
        async { Ok(None) }
    }

    /// Unverified, `TrackingScan` checks every page against the registry root.
    fn tracking_records(
        &self,
        _request: GetTrackingRecordsRequest,
    ) -> impl Future<Output = Result<GetTrackingRecordsResponse, RingIndexerError>> + Send {
        async { Err(ClientError::Rpc("no tracking records".to_owned()).into()) }
    }

    /// The owner's own authorization under the ring's pinned registry, read from the account.
    fn tracking_enrollment(
        &self,
        _ring: Address,
        _owner: Address,
    ) -> impl Future<Output = Result<WalletEnrollment, ClientError>> + Send {
        async { Ok(WalletEnrollment::NotEnrolled) }
    }

    /// Whether the owner's own `OwnerGrant` account names `reader`, a PDA grants through CPI.
    fn owner_grant_held(
        &self,
        _ring: Address,
        _owner: Address,
        _reader: ReaderKeyBytes,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send {
        async { Ok(false) }
    }
}

/// Unverified, callers read openings through `VerifiedOpenings`.
pub(crate) trait OpeningFetch: Sync {
    fn fetch_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberOpeningsResponse, RingRpcError>> + Send;
}

impl<S: TransactionSource> OpeningFetch for S {
    async fn fetch_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError> {
        Ok(self.storage_member_openings(request).await?)
    }
}

/// No source overrides the opening check.
#[async_trait]
pub(crate) trait VerifiedOpenings: OpeningFetch {
    /// Refused unless every opening verifies under `tip`.
    async fn verified_openings(
        &self,
        tip: &StorageTip,
        members: &[[u8; 32]],
    ) -> Result<Vec<MemberOpeningRead>, RingRpcError>;
}

#[async_trait]
impl<S: OpeningFetch + ?Sized> VerifiedOpenings for S {
    async fn verified_openings(
        &self,
        tip: &StorageTip,
        members: &[[u8; 32]],
    ) -> Result<Vec<MemberOpeningRead>, RingRpcError> {
        let response = self.fetch_openings(tip.openings_request(members)).await?;
        tip.verify_openings(&response, members)
            .map_err(|_| RingRpcError::InvalidIndexerResponse)
    }
}

/// Only a finalized root feeds the stored projection, a retired root stays served past the
/// finalization lag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality {
    Confirmed,
    Finalized,
}

/// The newest root of a pinned tracking registry and the leaf count under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingRoot {
    pub registry: Address,
    pub root: [u8; 32],
    pub revision: u64,
    pub next_index: u64,
}

/// A pending enrollment grants nothing, and past capacity it never applies.
fn enrollment_of(
    authorization: Option<&TrackingAuthorization>,
    tree_full: bool,
) -> WalletEnrollment {
    match authorization {
        None => WalletEnrollment::NotEnrolled,
        Some(held) if !held.is_pending() => WalletEnrollment::Applied,
        Some(_) if tree_full => WalletEnrollment::PendingPastCapacity,
        Some(_) => WalletEnrollment::Pending,
    }
}

#[derive(Clone, Copy)]
#[must_use]
pub struct TransactionPage {
    pub ring: Address,
    pub tag: [u8; 32],
    pub position: HistoryPosition,
    pub limit: NonZeroU32,
}

/// A frame the history already returned, read again by its signature.
#[derive(Clone, Copy, Debug)]
pub struct RingFrame {
    pub ring: Address,
    pub signature: Signature,
    pub slot: u64,
}

#[derive(Clone, Copy)]
#[must_use]
pub struct RingHistoryPage {
    pub ring: Address,
    pub position: HistoryPosition,
    pub limit: NonZeroU32,
}

#[must_use]
pub struct MergeAuditRequest<'a> {
    pub ring: Address,
    pub auditor: &'a spr_keypair::X25519Keypair,
    pub page: &'a Page,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordsTip {
    NoPolicy,
    /// The ring's records address holds no initialized storage registry.
    NoRegistry,
    Newest(StorageTip),
}

#[derive(Clone, Copy)]
pub struct RingConfiguration {
    pub auditor_pubkey: X25519Pubkey,
    pub roles: RingRoles,
    pub mode: RingMode,
    pub delegate: Option<Address>,
}

#[must_use]
#[derive(Clone, Copy)]
pub struct Upstreams<'a> {
    pub indexer_url: &'a str,
    pub rpc_url: &'a str,
    pub timeout: Duration,
}

pub struct ChainSource {
    history: FinalizedHistory,
    indexer: AsyncSprIndexer,
    rpc: AsyncSolanaRpc,
}

/// The merge audit reads ring history and its registry through one source.
struct HistorySource<'a> {
    source: &'a ChainSource,
}

#[async_trait]
impl AsyncRpc for HistorySource<'_> {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.source.rpc.get_account(address).await
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let position = match options.pagination_token {
            Some(token) => HistoryPosition::resume(token),
            None => options
                .filters
                .slot
                .floor()
                .map_or_else(HistoryPosition::default, HistoryPosition::after_slot),
        };
        if options.filters.slot.lt.is_some() || options.filters.slot.lte.is_some() {
            return Err(ClientError::Rpc(
                "finalized history rejects an upper slot bound".into(),
            ));
        }
        let limit = options
            .limit
            .and_then(NonZeroU32::new)
            .ok_or_else(|| ClientError::Rpc("finalized history requires a page limit".into()))?;
        self.source
            .ring_history(RingHistoryPage {
                ring: options.ring_program_id,
                position,
                limit,
            })
            .await
    }
}

impl TransactionOrigin for HistorySource<'_> {
    async fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        self.source
            .transaction_origin(signature, event_index, ring)
            .await
    }
}

#[async_trait]
impl AsyncRingIndexer for HistorySource<'_> {
    async fn get_storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> Result<GetStorageMemberRecordsResponse, RingIndexerError> {
        self.source
            .indexer
            .get_storage_member_records(request)
            .await
    }
}

impl ChainSource {
    pub fn connect(upstreams: Upstreams<'_>) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(upstreams.timeout)
            .build()
            .map_err(|error| ClientError::Rpc(format!("http client: {error}")))?;
        Ok(Self {
            history: FinalizedHistory::default(),
            indexer: AsyncSprIndexer::with_api(SprApi::with_client(upstreams.indexer_url, http)),
            rpc: AsyncSolanaRpc::with_client(
                NonblockingRpcClient::new_with_timeout_and_commitment(
                    upstreams.rpc_url.to_owned(),
                    upstreams.timeout,
                    CommitmentConfig::confirmed(),
                ),
            ),
        })
    }

    pub fn rpc(&self) -> &AsyncSolanaRpc {
        &self.rpc
    }

    fn history(&self) -> HistorySource<'_> {
        HistorySource { source: self }
    }

    async fn account_at(
        &self,
        address: Address,
        finality: Finality,
    ) -> Result<Option<Account>, ClientError> {
        let commitment = match finality {
            Finality::Confirmed => CommitmentConfig::confirmed(),
            Finality::Finalized => CommitmentConfig::finalized(),
        };
        self.rpc
            .client()
            .get_account_with_commitment(&address, commitment)
            .await
            .map(|response| response.value)
            .map_err(|error| ClientError::Rpc(format!("get_account {address}: {error}")))
    }

    /// A foreign owner means the account does not exist for its program, not
    /// that it is broken.
    async fn owned_account(
        &self,
        address: Address,
        owner: Address,
    ) -> Result<Option<Account>, ClientError> {
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .filter(|account| account.owner == owner))
    }
}

impl TransactionSource for ChainSource {
    async fn tree_id(&self, tree: Address) -> Result<u16, RingError> {
        custom_ring_sdk::tree_id(&self.rpc, tree).await
    }

    async fn merge_audit_page<'a>(
        &'a self,
        request: MergeAuditRequest<'a>,
    ) -> Result<MergeAuditPage, AuditError> {
        MergeAudit::new(request.ring, request.auditor)
            .with_cursor(request.page.history_cursor())
            .with_page_size(request.page.limit())
            .page(&self.history(), &self.history())
            .await
    }

    async fn transactions_by_tag(
        &self,
        request: TransactionPage,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.history
            .page(
                FinalizedPage {
                    ring: request.ring,
                    position: request.position,
                    limit: request.limit,
                    selection: HistorySelection::Tag(request.tag),
                },
                &FinalizedUpstreams {
                    rpc: &self.rpc,
                    indexer: &self.indexer,
                },
            )
            .await
    }

    async fn ring_frame(&self, frame: RingFrame) -> Result<Vec<ShieldedTransaction>, ClientError> {
        FinalizedUpstreams {
            rpc: &self.rpc,
            indexer: &self.indexer,
        }
        .frame(frame)
        .await
    }

    async fn ring_history(
        &self,
        request: RingHistoryPage,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.history
            .page(
                FinalizedPage {
                    ring: request.ring,
                    position: request.position,
                    limit: request.limit,
                    selection: HistorySelection::Ring,
                },
                &FinalizedUpstreams {
                    rpc: &self.rpc,
                    indexer: &self.indexer,
                },
            )
            .await
    }

    async fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        FinalizedUpstreams {
            rpc: &self.rpc,
            indexer: &self.indexer,
        }
        .origins(OriginRead { ring, signature })
        .await?
        .origins
        .remove(&event_index)
        .ok_or(AuditError::InvalidEventIndex(event_index))
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(None);
        };
        CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .configuration()
        .map(Some)
    }

    async fn salted_list_writers(&self, ring: Address) -> Result<Vec<Address>, ClientError> {
        let (address, _) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(Vec::new());
        };
        let policy = RingPolicy::decode(&account.owner, &ring, &account.data)
            .ok_or_else(|| ClientError::Rpc(INVALID_POLICY.to_owned()))?;
        let mut writers = Vec::new();
        for registry in policy.salted_registries() {
            let account = self.rpc.get_account(registry).await?;
            writers.extend(
                account
                    .as_ref()
                    .and_then(|account| StorageRegistry::decode(&account.owner, &account.data))
                    .map(|registry| registry.authority),
            );
        }
        Ok(writers)
    }

    async fn ring_chain_status(&self, ring: Address) -> Result<RingChainStatus, ClientError> {
        RingChainStatus::read(&self.rpc, ring).await
    }

    async fn upgrade_authority(&self, program: Address) -> Result<Option<Address>, ClientError> {
        let loader = Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
        let address = get_program_data_address(&program);
        let Some(account) = self.owned_account(address, loader).await? else {
            return Ok(None);
        };
        let data = program_data(&account)
            .ok_or_else(|| ClientError::Rpc("program data account is invalid".to_owned()))?;
        Ok(data
            .upgrade_authority
            .filter(|key| *key != Address::default()))
    }

    async fn slot(&self) -> Result<u64, ClientError> {
        self.rpc.get_slot().await
    }

    async fn records_root(&self, ring: Address) -> Result<RecordsTip, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(RecordsTip::NoPolicy);
        };
        let records = CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .decode::<RingPolicy>()
        .ok_or_else(|| ClientError::Rpc(INVALID_POLICY.to_owned()))?
        .records;
        Ok(self
            .rpc
            .get_account(records)
            .await?
            .and_then(|account| StorageRegistry::decode(&account.owner, &account.data))
            .map_or(RecordsTip::NoRegistry, |registry| {
                RecordsTip::Newest(StorageTip::newest(records, &registry))
            }))
    }

    async fn co_signer_scope(
        &self,
        ring: Address,
        signer: Address,
    ) -> Result<Option<CoSignScope>, RingRpcError> {
        let record = CustomRing::new(ring)
            .co_signer(&HistorySource { source: self }, &signer)
            .await
            .map_err(|_| CoSignError::LimitsUnavailable)?;
        Ok(record.map(|record| record.scope))
    }

    /// The pin and the registry it names are read at one finality.
    async fn tracking_root(
        &self,
        ring: Address,
        finality: Finality,
    ) -> Result<Option<TrackingRoot>, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self
            .account_at(address, finality)
            .await?
            .filter(|account| account.owner == ring)
        else {
            return Ok(None);
        };
        let tracking = CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .decode::<RingPolicy>()
        .ok_or_else(|| ClientError::Rpc(INVALID_POLICY.to_owned()))?
        .tracking;
        // The pin names the registry, an account it does not decode to serves no root.
        Ok(self
            .account_at(tracking, finality)
            .await?
            .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data))
            .map(|registry| {
                let newest = registry.newest();
                TrackingRoot {
                    registry: tracking,
                    root: newest.hash,
                    revision: newest.revision.value(),
                    next_index: registry.next_index(),
                }
            }))
    }

    async fn tracking_records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, RingIndexerError> {
        self.indexer.get_tracking_records(request).await
    }

    async fn tracking_enrollment(
        &self,
        ring: Address,
        owner: Address,
    ) -> Result<WalletEnrollment, ClientError> {
        let Some(root) = self.tracking_root(ring, Finality::Confirmed).await? else {
            return Ok(WalletEnrollment::NotEnrolled);
        };
        let (address, _) = TrackingAuthorization::find_address(&root.registry, &owner);
        let authorization = self
            .rpc
            .get_account(address)
            .await?
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data));
        Ok(enrollment_of(
            authorization.as_ref(),
            root.next_index >= TRACKING_CAPACITY,
        ))
    }

    async fn owner_grant_held(
        &self,
        ring: Address,
        owner: Address,
        reader: ReaderKeyBytes,
    ) -> Result<bool, ClientError> {
        let Some(root) = self.tracking_root(ring, Finality::Confirmed).await? else {
            return Ok(false);
        };
        let (address, _) = OwnerGrant::find_address(&root.registry, &owner, &reader);
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .and_then(|account| OwnerGrant::decode(&account.owner, &account.data))
            .is_some_and(|grant| grant.is_active()))
    }

    async fn storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
        self.indexer.get_storage_member_openings(request).await
    }

    async fn storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> Result<GetStorageMemberRecordsResponse, RingIndexerError> {
        self.indexer.get_storage_member_records(request).await
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.indexer
            .get_shielded_transactions_by_tags(
                vec![[0; 32]],
                None,
                Some(1),
                HistoryPosition::default().filters(),
                None,
            )
            .await?;
        self.rpc.health().await
    }

    async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        self.rpc.genesis_hash().await
    }

    async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
        let filter =
            ProgramAccountsFilter::new(SplAssetRegistry::SIZE).with_memcmp(0, [SPL_ASSET_REGISTRY]);
        let accounts = self
            .rpc
            .get_program_accounts_filtered(PROGRAM_ID_PUBKEY, &filter)
            .await?;
        let mut assets = AssetRegistry::default();
        let mut mints = Vec::with_capacity(accounts.len());
        for (address, account) in accounts {
            let invalid = || ClientError::InvalidSplAssetRegistration { address };
            if account.owner != PROGRAM_ID_PUBKEY || !filter.matches(&account.data) {
                return Err(invalid());
            }
            let registration =
                SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
            if address != pda::spl_asset_registry(&registration.mint)
                || registration.mint == SOL_MINT
            {
                return Err(invalid());
            }
            assets
                .insert(registration.asset_id, registration.mint)
                .map_err(|_| invalid())?;
            mints.push(Mint::new(registration.mint, registration.asset_id));
        }
        RingAssets::new(mints).map_err(|error| ClientError::Rpc(error.to_string()))
    }
}

const INVALID_POLICY: &str = "custom ring policy account is invalid";

/// `bump` is the canonical bump of the address `account` was read from.
#[derive(Clone, Copy)]
#[must_use]
struct CanonicalAccount<'a> {
    account: &'a Account,
    ring: Address,
    bump: u8,
}

impl CanonicalAccount<'_> {
    fn decode<T: RingAccount>(self) -> Option<T> {
        T::decode(&self.account.owner, &self.ring, &self.account.data)
            .filter(|value| value.bump() == self.bump)
    }

    fn configuration(self) -> Result<RingConfiguration, ClientError> {
        let invalid = || ClientError::Rpc(INVALID_POLICY.to_owned());
        let config: RingPolicy = self.decode().ok_or_else(invalid)?;
        Ok(RingConfiguration {
            auditor_pubkey: X25519Pubkey::from_bytes(config.auditor_pubkey)
                .map_err(|_| invalid())?,
            roles: config.roles,
            mode: config.mode().map_err(|_| invalid())?,
            delegate: config.delegate().copied(),
        })
    }
}

#[cfg(test)]
#[path = "../../../../sdk-libs/client/tests/common/origin.rs"]
pub(crate) mod origin_fixture;

#[cfg(test)]
mod tests {
    use bytemuck::{bytes_of, Pod};
    use custom_ring_interface::{RING_POLICY, RING_POLICY_PDA_SEED};

    use super::*;

    fn account<T: Pod>(owner: Address, value: &T) -> Account {
        Account {
            lamports: 1,
            data: bytes_of(value).to_vec(),
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    const AUTHORITY: Address = Address::new_from_array([7; 32]);

    fn config_account(ring: Address, key: [u8; 33], bump: u8) -> Account {
        let mut config: Box<RingPolicy> = bytemuck::zeroed_box();
        config.discriminator = RING_POLICY;
        config.roles.policy = AUTHORITY;
        config.auditor_pubkey = key;
        config.bump = bump;
        account(ring, &*config)
    }

    #[test]
    fn config_accounts_require_the_canonical_layout() {
        let ring = Address::new_from_array([9; 32]);
        let bump = Address::find_program_address(&[RING_POLICY_PDA_SEED], &ring).1;
        let key = spr_keypair::X25519Keypair::new().pubkey();
        let valid = config_account(ring, *key.as_bytes(), bump);
        let configuration = |account: &Account, bump| {
            CanonicalAccount {
                account,
                ring,
                bump,
            }
            .configuration()
        };
        let config = configuration(&valid, bump).expect("config");
        assert_eq!(config.auditor_pubkey, key);
        assert_eq!(config.roles.policy, AUTHORITY);

        let mut wrong_owner = valid.clone();
        wrong_owner.owner = Address::new_from_array([8; 32]);
        let mut wrong_size = valid.clone();
        wrong_size.data.push(0);
        let mut wrong_discriminator = valid.clone();
        wrong_discriminator.data[0] = 0;
        for invalid in [wrong_owner, wrong_size, wrong_discriminator] {
            assert!(configuration(&invalid, bump).is_err());
        }
        assert!(configuration(&valid, bump.wrapping_add(1)).is_err());
        for invalid_key in [[2; 33], [0; 33]] {
            let invalid = config_account(ring, invalid_key, bump);
            assert!(configuration(&invalid, bump).is_err());
        }
    }
}
