//! Registry records, read under a root or signed as record updates.

use async_trait::async_trait;
use custom_ring_interface::{domain, tracking::TrackingAuthorization};
use solana_address::Address;
use solana_signer::Signer;
use spr_api::SprApi;
use spr_client::{AsyncRpc, ClientError};
use spr_indexer_api::Hash;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use zolana_ring_client::{
    records::{path_of, MemberOpeningRead, RecordPoolCheck, RecordPoolRead},
    resolver::tracking_record,
    rpc::{
        method::{GetRecordUpdateStatus, SubmitRecordUpdate},
        GetRecordUpdateStatusRequest, ReaderAccess, RecordUpdate, RecordUpdateEntry,
        RecordUpdateId, RecordUpdateStatus, SubmitRecordUpdateRequest, WalletGrant,
        AWAITABLE_LISTS,
    },
    AsyncRingIndexer, AuthorizationCheck, ReaderKey, RecipientResolver, ResolvedRecipient,
};
use zolana_ring_indexer::{
    rpc::{
        GetStorageMemberOpeningsRequest, GetStorageRecordPoolRequest, RingListWriteView,
        MAX_RING_MEMBER_PAGE_LIMIT,
    },
    tracking::{GetTrackingOpeningsRequest, GetTrackingRecordPoolRequest},
};
use zolana_ring_keys::RingAddress;
use zolana_ring_member_registry::{
    Canopy, OpeningCheck, PoolSubject, SharedPath, SharedProof, TrackingOpening, TrackingPool,
    TrackingRecord,
};
use zolana_ring_policy::{ListSet, ListWrite, Member, MintPolicy, Writer};

use crate::{submission::BoundRoot, CustomRing, RingError};

/// Members' records under the newest root of the ring's records registry.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRecords<'a> {
    pub ring: CustomRing,
    pub members: &'a [Member],
}

impl MemberRecords<'_> {
    /// One opening per member in member order, each verified against the root.
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<Vec<MemberOpeningRead>, RingError> {
        let members: Vec<[u8; 32]> = self
            .members
            .iter()
            .map(|member| *member.as_bytes())
            .collect();
        RecordReads {
            root: BoundRoot::newest(self.ring, rpc).await?,
            members: &members,
        }
        .read(rpc)
        .await
    }
}

pub(crate) struct RecordReads<'a> {
    pub root: BoundRoot,
    pub members: &'a [[u8; 32]],
}

impl RecordReads<'_> {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<Vec<MemberOpeningRead>, RingError> {
        let BoundRoot { registry, root, .. } = self.root;
        let mut reads = Vec::with_capacity(self.members.len());
        for chunk in self.members.chunks(MAX_RING_MEMBER_PAGE_LIMIT as usize) {
            let response = rpc
                .get_storage_member_openings(GetStorageMemberOpeningsRequest {
                    registry: registry.into(),
                    members: chunk.iter().copied().map(Hash).collect(),
                    expected_root: Hash(root),
                })
                .await?;
            if response.openings.len() != chunk.len() {
                return Err(RingError::InvalidRecordOpening);
            }
            for (member, view) in chunk.iter().zip(&response.openings) {
                reads.push(MemberOpeningRead::verify(view, &root, member)?);
            }
        }
        Ok(reads)
    }
}

/// Distinct members' records under a bound root, the canopy sized for `openings` paths.
pub(crate) struct PoolRead<'a> {
    pub root: BoundRoot,
    pub members: &'a [[u8; 32]],
    pub openings: usize,
}

impl PoolRead<'_> {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<RecordPoolRead, RingError> {
        let BoundRoot { registry, root, .. } = self.root;
        let response = rpc
            .get_storage_record_pool(GetStorageRecordPoolRequest {
                registry: registry.into(),
                members: self.members.iter().copied().map(Hash).collect(),
                expected_root: Hash(root),
                openings: self.openings as u64,
            })
            .await?;
        Ok(RecordPoolCheck {
            response: &response,
            root: &root,
            members: self.members,
            openings: self.openings,
        }
        .verify()?)
    }
}

/// `members` stay distinct, the canopy sized for `openings` paths.
pub(crate) struct TrackingRead<'a> {
    pub root: BoundRoot,
    pub members: &'a [[u8; 32]],
    pub openings: usize,
}

/// An absent subject reads its bracketing low row.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TrackingPoolRead {
    pool: TrackingPool,
}

impl TrackingRead<'_> {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<TrackingPoolRead, RingError> {
        let BoundRoot { registry, root, .. } = self.root;
        let response = rpc
            .get_tracking_record_pool(GetTrackingRecordPoolRequest {
                registry: registry.into(),
                members: self.members.iter().copied().map(Hash).collect(),
                expected_root: Hash(root),
                openings: self.openings as u64,
            })
            .await?;
        let canopy = Canopy::covering_tracking(self.openings)?;
        if response.root.root.0 != root
            || response.canopy.len() != canopy.width()
            || response.subjects.len() != self.members.len()
        {
            return Err(RingError::InvalidRecordOpening);
        }
        let pool = TrackingPool {
            records: response
                .records
                .iter()
                .map(|row| tracking_record(&row.record))
                .collect(),
            proof: SharedProof {
                canopy: response.canopy.iter().map(|node| node.0).collect(),
                paths: response
                    .records
                    .iter()
                    .map(|row| SharedPath {
                        index: row.path.index,
                        siblings: row
                            .path
                            .siblings
                            .iter()
                            .map(|level| level.clone().map(|sibling| sibling.0))
                            .collect(),
                    })
                    .collect(),
            },
            subjects: self
                .members
                .iter()
                .zip(&response.subjects)
                .map(|(member, record_index)| PoolSubject {
                    member: *member,
                    record_index: *record_index,
                })
                .collect(),
        };
        pool.verify(&root)
            .map_err(|_| RingError::InvalidRecordOpening)?;
        Ok(TrackingPoolRead { pool })
    }
}

impl TrackingPoolRead {
    pub fn pool(&self) -> &TrackingPool {
        &self.pool
    }

    /// `None` for an absent member or one outside the pool.
    pub fn record(&self, member: &[u8; 32]) -> Option<&TrackingRecord> {
        let subject = self
            .pool
            .subjects
            .iter()
            .find(|subject| subject.member == *member)?;
        self.pool
            .records
            .get(subject.record_index as usize)
            .filter(|record| record.member == *member)
    }
}

/// A salted entry reads only under the salt the owner's row commits, any other disarms it silently.
#[must_use]
pub struct SaltedOwnerCheck<'a> {
    pub ring: CustomRing,
    pub address: &'a RingAddress,
}

impl SaltedOwnerCheck<'_> {
    pub async fn run(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<ResolvedRecipient, RingError> {
        let policy = self.ring.require_policy(rpc).await?;
        let tracking = BoundRoot::tracking(&policy, rpc).await?;
        Ok(RecipientResolver {
            address: self.address,
            registry: tracking.registry,
            root: tracking.root,
        }
        .resolve(rpc)
        .await?)
    }
}

/// An entry under a salt the owner's tag does not open is one no proof reads.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct OwnerSaltCheck<'a> {
    pub ring: CustomRing,
    pub owner: &'a Address,
    pub list_salt: &'a [u8; 32],
}

impl OwnerSaltCheck<'_> {
    pub async fn run(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<(), RingError> {
        let member = *Member::owner_tag(self.owner.as_array())?.as_bytes();
        let policy = self.ring.require_policy(rpc).await?;
        let root = BoundRoot::tracking(&policy, rpc).await?;
        match (TrackingMemberRead { root, member }).read(rpc).await? {
            TrackingOpening::Present { record, .. }
                if domain::list_tag(self.list_salt)? == record.list_tag =>
            {
                Ok(())
            }
            TrackingOpening::Present { .. } => Err(RingError::ListSaltMismatch { member }),
            TrackingOpening::Absent { .. } => Err(RingError::ListSaltUnknown { member }),
        }
    }
}

pub(crate) struct TrackingMemberRead {
    pub root: BoundRoot,
    pub member: [u8; 32],
}

impl TrackingMemberRead {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<TrackingOpening, RingError> {
        let BoundRoot { registry, root, .. } = self.root;
        let response = rpc
            .get_tracking_openings(GetTrackingOpeningsRequest {
                registry: registry.into(),
                members: vec![Hash(self.member)],
                expected_root: Hash(root),
            })
            .await?;
        let [view] = response.openings.as_slice() else {
            return Err(RingError::InvalidRecordOpening);
        };
        let path = path_of(&view.path)?;
        let record = tracking_record(&view.record);
        let opening = match view.present {
            true => TrackingOpening::Present { record, path },
            false => TrackingOpening::Absent { low: record, path },
        };
        OpeningCheck {
            opening: &opening,
            root: &root,
            member: &self.member,
        }
        .verify()
        .map_err(|_| RingError::InvalidRecordOpening)?;
        Ok(opening)
    }
}

/// Mirror `AssertOutputOwners` in `prover/circuits/transfer/owners.go`.
pub(crate) struct OutputKey<'a> {
    pub row: Option<&'a TrackingRecord>,
    pub nullifier_pk: &'a [u8; 32],
    pub slot_index: usize,
}

impl OutputKey<'_> {
    pub(crate) fn check(self) -> Result<(), RingError> {
        let Self {
            row,
            nullifier_pk,
            slot_index,
        } = self;
        match (row, *nullifier_pk == ZERO_NULLIFIER_PUBKEY) {
            (None, true) => Ok(()),
            (None, false) => Err(RingError::RecipientNotEnrolled { slot_index }),
            (Some(_), true) => Err(RingError::EnrolledRecipientAtZeroKey { slot_index }),
            (Some(record), false) if record.nullifier_pk != *nullifier_pk => {
                Err(RingError::RecipientKeyMismatch { slot_index })
            }
            (Some(_), false) => Ok(()),
        }
    }
}

/// An output whose owner holds a tracking row, sealed to `viewing_u`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SealedOutput {
    pub slot_index: usize,
    /// The Solana owner the tracking member commits.
    pub owner: Address,
    pub viewing_u: [u8; 32],
}

/// Refuses an output sealed to a key other than its owner's authorization holds, a body sealed to it stays unread.
#[must_use]
pub(crate) struct RecipientViewingKeys<'a> {
    pub registry: Address,
    pub outputs: &'a [SealedOutput],
}

impl RecipientViewingKeys<'_> {
    /// Reads the authorization at `confirmed`. A rotation that lands after the read leaves the payment
    /// sealed to the key read, no program check reads a viewing key.
    pub async fn check(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<(), RingError> {
        if self.outputs.is_empty() {
            return Ok(());
        }
        let addresses = self
            .outputs
            .iter()
            .map(|output| TrackingAuthorization::find_address(&self.registry, &output.owner).0)
            .collect();
        let accounts = rpc.get_multiple_accounts(addresses).await?;
        for (index, output) in self.outputs.iter().enumerate() {
            let held = AuthorizationCheck {
                registry: self.registry,
                owner: output.owner,
                account: accounts.get(index).and_then(Option::as_ref),
            }
            .viewing_u()?;
            if held != output.viewing_u {
                return Err(RingError::RecipientViewingKeyStale {
                    slot_index: output.slot_index,
                });
            }
        }
        Ok(())
    }
}

/// The writer refuses the update after `valid_until_slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordUpdateTarget {
    /// The cluster the writer serves.
    pub genesis_hash: [u8; 32],
    pub ring: CustomRing,
    /// The ring's own `StorageRegistry`.
    pub registry: Address,
    pub valid_until_slot: u64,
}

/// Signed by the wallet, every entry names the wallet.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletRecordUpdate {
    draft: UpdateDraft,
    member: Member,
}

/// Signed by the policy authority, a write may name any record.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRecordUpdate {
    draft: UpdateDraft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpdateDraft {
    target: RecordUpdateTarget,
    signer: Address,
    entries: Vec<RecordUpdateEntry>,
    awaited_lists: ListSet,
}

#[async_trait]
pub trait RecordUpdateService: Send + Sync {
    /// Refuses before sending a request whose signature does not verify.
    async fn submit_record_update(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<RecordUpdateId, RingError>;

    async fn get_record_update_status(
        &self,
        update_id: RecordUpdateId,
    ) -> Result<RecordUpdateStatus, RingError>;
}

impl WalletRecordUpdate {
    pub fn new(target: RecordUpdateTarget, wallet: Address) -> Result<Self, RingError> {
        Ok(Self {
            draft: UpdateDraft::new(target, wallet),
            member: Member::owner_tag(wallet.as_array())?,
        })
    }

    pub fn with_lists(mut self, lists: ListWrite) -> Result<Self, RingError> {
        check_writer(lists, Writer::Member)?;
        self.draft
            .entries
            .push(RecordUpdateEntry::Write(list_write(self.member, lists)));
        Ok(self)
    }

    /// Sets or clears the `Reader` list of the record [`Member::wallet_grant`] keys.
    pub fn with_wallet_grant(
        mut self,
        reader: ReaderKey,
        access: ReaderAccess,
    ) -> Result<Self, RingError> {
        let reader = reader.member()?;
        Member::wallet_grant(&self.member, &reader)?;
        self.draft
            .entries
            .push(RecordUpdateEntry::WalletGrant(WalletGrant {
                wallet: Hash(*self.member.as_bytes()),
                reader: Hash(*reader.as_bytes()),
                access,
            }));
        Ok(self)
    }

    /// Puts the update pending list approval, the writer sends none of its writes until a policy authority update sets every list of `lists` on the member.
    pub fn awaiting_list_approval(mut self, lists: ListSet) -> Result<Self, RingError> {
        if lists.is_empty() || !lists.is_subset(AWAITABLE_LISTS) {
            return Err(RingError::InvalidAwaitedLists);
        }
        self.draft.awaited_lists = lists;
        Ok(self)
    }

    pub fn sign<S: Signer + ?Sized>(
        self,
        wallet: &S,
    ) -> Result<SubmitRecordUpdateRequest, RingError> {
        self.draft.sign(wallet)
    }
}

impl AuthorityRecordUpdate {
    pub const fn new(target: RecordUpdateTarget, authority: Address) -> Self {
        Self {
            draft: UpdateDraft::new(target, authority),
        }
    }

    /// `member` is any record key, an owner identity or an asset.
    pub fn with_write(mut self, member: Member, write: ListWrite) -> Result<Self, RingError> {
        check_writer(write, Writer::Authority)?;
        self.draft
            .entries
            .push(RecordUpdateEntry::Write(list_write(member, write)));
        Ok(self)
    }

    /// Replaces all mint settings, zero values clear them.
    pub fn with_mint_policy(mut self, member: Member, policy: MintPolicy) -> Self {
        self.draft
            .entries
            .push(RecordUpdateEntry::Write(RingListWriteView {
                mint_policy: Some(policy),
                member: Hash(*member.as_bytes()),
                mask: 0,
                value: 0,
            }));
        self
    }

    /// The writer refuses a signer other than the policy authority.
    pub fn sign<S: Signer + ?Sized>(
        self,
        authority: &S,
    ) -> Result<SubmitRecordUpdateRequest, RingError> {
        self.draft.sign(authority)
    }
}

impl UpdateDraft {
    const fn new(target: RecordUpdateTarget, signer: Address) -> Self {
        Self {
            target,
            signer,
            entries: Vec::new(),
            awaited_lists: ListSet::EMPTY,
        }
    }

    fn sign<S: Signer + ?Sized>(self, signer: &S) -> Result<SubmitRecordUpdateRequest, RingError> {
        if self.entries.is_empty() {
            return Err(RingError::EmptyListWrite);
        }
        if signer.pubkey() != self.signer {
            return Err(RingError::RecordUpdateSigner {
                expected: self.signer,
            });
        }
        Ok(RecordUpdate {
            genesis_hash: Hash(self.target.genesis_hash),
            ring: self.target.ring.program_id().into(),
            entries: self.entries,
            valid_until_slot: self.target.valid_until_slot,
            awaited_lists: self.awaited_lists.record_bits(),
        }
        .sign(self.target.registry, signer)?)
    }
}

#[async_trait]
impl RecordUpdateService for SprApi {
    async fn submit_record_update(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<RecordUpdateId, RingError> {
        let id = request.verify()?;
        let response = self
            .call::<SubmitRecordUpdate>(request)
            .await
            .map_err(|error| ClientError::Rpc(error.to_string()))?;
        if response.update_id != id {
            return Err(RingError::RecordUpdateIdMismatch);
        }
        Ok(id)
    }

    async fn get_record_update_status(
        &self,
        update_id: RecordUpdateId,
    ) -> Result<RecordUpdateStatus, RingError> {
        Ok(self
            .call::<GetRecordUpdateStatus>(GetRecordUpdateStatusRequest { update_id })
            .await
            .map_err(|error| ClientError::Rpc(error.to_string()))?)
    }
}

fn list_write(member: Member, write: ListWrite) -> RingListWriteView {
    RingListWriteView {
        mint_policy: None,
        member: Hash(*member.as_bytes()),
        mask: write.mask(),
        value: write.value(),
    }
}

fn check_writer(write: ListWrite, writer: Writer) -> Result<(), RingError> {
    let lists = write.set().union(write.clear());
    match lists.difference(writer.writable()).iter().next() {
        Some(list) => Err(RingError::ListNotWritable { list, writer }),
        None => Ok(()),
    }
}
