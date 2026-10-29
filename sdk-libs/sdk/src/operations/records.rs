//! Registry records, read under a root, applied from the record queue or signed as record updates.

use async_trait::async_trait;
use custom_ring_interface::SYSTEM_PROGRAM_ID;
use custom_ring_interface::{
    mint_policy_write, queue_chain, tag, ApplyRecordsIxData, AuthorityWriteRecordsIxData,
    CustomRingError, MemberRegistry, MemberWriteIxData, QueueEntry, RecordQueue, RecordWriteData,
    WriteRecordsIxData, APPLY_BATCH,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;
use spr_api::ZolanaApi;
use spr_client::{AsyncRpc, ClientError};
use spr_indexer_api::Hash;
use zolana_ring_client::{
    records::{
        apply_proof_inputs, EscrowedRecord, MemberOpeningRead, RecordPoolCheck, RecordPoolRead,
    },
    rpc::{
        method::{GetRecordUpdateStatus, SubmitRecordUpdate},
        EscrowRegistration, GetRecordUpdateStatusRequest, ReaderAccess, RecordUpdate,
        RecordUpdateEntry, RecordUpdateId, RecordUpdateStatus, SubmitRecordUpdateRequest,
        WalletGrant, ENROLMENT_LISTS,
    },
    AsyncRingIndexer,
};
use zolana_ring_indexer::rpc::{
    GetRingApplyProofInputsRequest, GetStorageMemberOpeningsRequest, GetStorageRecordPoolRequest,
    RingListWriteView, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_ring_member_registry::ApplyProofInputs;
use zolana_ring_policy::{ListSet, ListWrite, Member, MintPolicy, Writer};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    projection::retry_projection_lag, request::RecordOpeningRequest, submission::BoundRoot,
    CustomRing, CustomRingConfig, RingError, StorageApplyProof,
};

/// Members' records under the newest synced root of the ring's records.
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

pub(crate) struct MemberRead {
    pub root: BoundRoot,
    pub member: [u8; 32],
}

impl MemberRead {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<MemberOpeningRead, RingError> {
        RecordReads {
            root: self.root,
            members: core::slice::from_ref(&self.member),
        }
        .read(rpc)
        .await?
        .pop()
        .ok_or(RingError::InvalidRecordOpening)
    }
}

/// A member's opening read under a root the statement binds.
pub(crate) struct OwnerRead<'a> {
    pub owner: [u8; 32],
    pub read: &'a MemberOpeningRead,
}

impl<'a> OwnerRead<'a> {
    /// Refuses an owner whose record escrows no key for `nullifier_pk`.
    pub fn escrowed(self, nullifier_pk: &[u8; 32]) -> Result<EscrowedRecord<'a>, RingError> {
        match self.read.escrowed(nullifier_pk)? {
            Some(escrowed) => Ok(escrowed),
            None => Err(RingError::UnregisteredOutputKey {
                owner: Member::from_bytes(self.owner)?,
            }),
        }
    }
}

/// The owner's record under `root`, refused unless it escrows `nullifier_pk`.
#[derive(Clone, Copy)]
pub(crate) struct EscrowRead {
    pub root: BoundRoot,
    pub owner: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

pub(crate) struct EscrowOpening {
    pub opening: RecordOpeningRequest,
    pub ct_hash: [u8; 32],
}

impl EscrowRead {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<EscrowOpening, RingError> {
        let read = MemberRead {
            root: self.root,
            member: self.owner,
        }
        .read(rpc)
        .await?;
        let escrowed = OwnerRead {
            owner: self.owner,
            read: &read,
        }
        .escrowed(&self.nullifier_pk)?;
        Ok(EscrowOpening {
            opening: RecordOpeningRequest::present(escrowed.record, escrowed.path),
            ct_hash: escrowed.ct_hash()?,
        })
    }
}

/// A member's write of its own lists, queued without a proof.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberListWrite {
    pub ring: CustomRing,
    /// Pays the insert fee the config charges a member.
    pub payer: Address,
    pub member: Address,
    pub lists: ListWrite,
}

impl MemberListWrite {
    pub fn instruction(self, config: &CustomRingConfig) -> Result<Instruction, RingError> {
        check_writer(self.lists, Writer::Member)?;
        let write = MemberWrite {
            ring: self.ring,
            config,
            member: self.member,
            payer: self.payer,
        };
        let mut data = vec![tag::WRITE_RECORDS];
        data.extend_from_slice(bytemuck::bytes_of(&MemberWriteIxData {
            lists: WriteRecordsIxData::new(self.lists),
            max_fee: write.max_fee(),
        }));
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts: write.metas(),
            data,
        })
    }
}

/// Applied in one proof together with every pending member write.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityListWrite {
    ring: CustomRing,
    authority: Address,
    writes: Vec<RecordWriteData>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenRecordWrite {
    pub instruction: Instruction,
    pub(crate) bound: BoundQueue,
}

/// A later write or application moves the queue and root the statement binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundQueue {
    pub ring: CustomRing,
    pub tail: u64,
    pub chain_tail: [u8; 32],
    pub root: [u8; 32],
}

impl AuthorityListWrite {
    pub fn new(ring: CustomRing, authority: Address) -> Self {
        Self {
            ring,
            authority,
            writes: Vec::new(),
        }
    }

    /// `member` is any record key, an owner identity or an asset.
    pub fn with_write(mut self, member: Member, write: ListWrite) -> Result<Self, RingError> {
        check_writer(write, Writer::Authority)?;
        self.push(RecordWriteData {
            member: *member.as_bytes(),
            lists: WriteRecordsIxData::new(write),
            mint_policy: mint_policy_write(None),
        })?;
        Ok(self)
    }

    /// Replaces every mint setting under the same root as its lists.
    pub fn with_mint_policy(
        mut self,
        member: Member,
        policy: zolana_ring_policy::MintPolicy,
    ) -> Result<Self, RingError> {
        self.push(RecordWriteData {
            member: *member.as_bytes(),
            mint_policy: mint_policy_write(Some(policy)),
            ..RecordWriteData::default()
        })?;
        Ok(self)
    }

    fn push(&mut self, write: RecordWriteData) -> Result<(), RingError> {
        if self.writes.iter().any(|known| known.member == write.member) {
            return Err(RingError::DuplicateListWrite {
                member: Member::from_bytes(write.member)?,
            });
        }
        self.writes.push(write);
        Ok(())
    }

    pub fn writes(&self) -> &[RecordWriteData] {
        &self.writes
    }

    /// The first batch takes the room `pending` member writes leave.
    pub fn batches(&self, pending: u64) -> Vec<Self> {
        let first = APPLY_BATCH.saturating_sub(usize::try_from(pending).unwrap_or(APPLY_BATCH));
        let mut rest = self.writes.as_slice();
        let mut batches = Vec::new();
        let mut size = first;
        while !rest.is_empty() {
            // A full member share leaves the first batch empty, the writes start in the next.
            let (batch, tail) = rest.split_at(size.min(rest.len()));
            if !batch.is_empty() {
                batches.push(Self {
                    ring: self.ring,
                    authority: self.authority,
                    writes: batch.to_vec(),
                });
            }
            rest = tail;
            size = APPLY_BATCH;
        }
        batches
    }

    /// One batch against the registry and queue as the chain holds them.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<ProvenRecordWrite, RingError> {
        if self.writes.is_empty() {
            return Err(RingError::EmptyListWrite);
        }
        let config = self.ring.require_config(client.zolana()).await?;
        if config.authority != self.authority {
            return Err(CustomRingError::UnauthorizedAuthority.into());
        }
        let writes = &self.writes;
        let entries = writes
            .iter()
            .map(RecordWriteData::entry)
            .collect::<Result<Vec<_>, _>>()?;
        let (application, apply) = retry_projection_lag(|| async {
            let (registry, queue) = self.chain_state(client.zolana()).await?;
            let pending = queue.pending();
            if pending.saturating_add(writes.len() as u64) > APPLY_BATCH as u64 {
                return Err(RingError::AuthorityBatchSplit {
                    writes: writes.len(),
                    pending,
                    batches: self.batches(pending).len(),
                });
            }
            queue.admit_authority_writes(writes.len() as u64)?;
            let views = entries
                .iter()
                .map(|entry| RingListWriteView {
                    member: Hash(entry.member),
                    mask: entry.mask,
                    value: entry.value,
                    mint_policy: entry.mint_policy,
                })
                .collect();
            let inputs = Application::read(self.ring, client.zolana(), views).await?;
            let application = Application::new(self.ring, inputs, &registry, &queue, &entries)?;
            let apply = application.prove(client).await?;
            Ok((application, apply))
        })
        .await?;
        let mut data = vec![tag::AUTHORITY_WRITE_RECORDS];
        data.extend(
            AuthorityWriteRecordsIxData {
                writes,
                apply: &apply,
            }
            .encode()?,
        );
        Ok(ProvenRecordWrite {
            instruction: Instruction {
                program_id: self.ring.program_id(),
                accounts: record_accounts(self.ring, RecordSigner::Authority(self.authority)),
                data,
            },
            bound: application.bound,
        })
    }

    async fn chain_state(
        &self,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<(Box<MemberRegistry>, RecordQueue), RingError> {
        Ok((
            self.ring.require_registry(client).await?,
            self.ring.require_queue(client).await?,
        ))
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

/// Signed by the config authority, a write may name any record.
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
        reader: Member,
        access: ReaderAccess,
    ) -> Result<Self, RingError> {
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

    /// `registration` comes from [`KeyRegistration`](crate::KeyRegistration) for this wallet.
    pub fn with_escrow(mut self, registration: EscrowRegistration) -> Result<Self, RingError> {
        if registration.member.0 != *self.member.as_bytes() {
            return Err(RingError::EscrowMemberMismatch);
        }
        self.draft
            .entries
            .push(RecordUpdateEntry::Escrow(registration));
        Ok(self)
    }

    /// The writer holds the update until a config authority update sets every list of `lists` on the member.
    pub fn awaiting_authority(mut self, lists: ListSet) -> Result<Self, RingError> {
        if lists.is_empty() || !lists.is_subset(ENROLMENT_LISTS) {
            return Err(RingError::EnrolmentLists);
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

    /// The writer refuses a signer other than the config authority.
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
impl RecordUpdateService for ZolanaApi {
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

/// Permissionless, it applies every pending write.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordApplication {
    ring: CustomRing,
}

impl RecordApplication {
    pub const fn new(ring: CustomRing) -> Self {
        Self { ring }
    }

    /// `None` while the queue is not due, an authority write applies it sooner.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<Option<ProvenRecordWrite>, RingError> {
        retry_projection_lag(|| async {
            let registry = self.ring.require_registry(client.zolana()).await?;
            let queue = self.ring.require_queue(client.zolana()).await?;
            match queue.apply_due(client.get_slot().await?) {
                Ok(()) => {}
                Err(CustomRingError::ApplyNotDue | CustomRingError::ApplyTooSoon) => {
                    return Ok(None)
                }
                Err(error) => return Err(error.into()),
            }
            let inputs = Application::read(self.ring, client.zolana(), Vec::new()).await?;
            let application = Application::new(self.ring, inputs, &registry, &queue, &[])?;
            let apply = application.prove(client).await?;
            let mut data = vec![tag::APPLY_RECORDS];
            data.extend_from_slice(bytemuck::bytes_of(&apply));
            Ok(Some(ProvenRecordWrite {
                instruction: Instruction {
                    program_id: self.ring.program_id(),
                    accounts: vec![
                        AccountMeta::new(self.ring.registry_pda(), false),
                        AccountMeta::new(self.ring.queue_pda(), false),
                    ],
                    data,
                },
                bound: application.bound,
            }))
        })
        .await
    }
}

struct Application {
    inputs: ApplyProofInputs,
    bound: BoundQueue,
}

impl Application {
    async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        ring: CustomRing,
        client: &R,
        authority_writes: Vec<RingListWriteView>,
    ) -> Result<ApplyProofInputs, RingError> {
        let response = client
            .get_ring_apply_proof_inputs(GetRingApplyProofInputsRequest {
                ring_program_id: ring.program_id().into(),
                authority_writes,
            })
            .await?;
        Ok(apply_proof_inputs(&response)?)
    }

    /// Inputs off the chain's registry, queue or authority entries are a stale projection.
    fn new(
        ring: CustomRing,
        inputs: ApplyProofInputs,
        registry: &MemberRegistry,
        queue: &RecordQueue,
        authority: &[QueueEntry],
    ) -> Result<Self, RingError> {
        let pending =
            usize::try_from(queue.pending()).map_err(|_| RingError::RecordProjectionStale)?;
        let mut chain_end = queue.chain_tail();
        for entry in authority {
            chain_end = queue_chain(&chain_end, entry)?;
        }
        let tail_matches = inputs.writes.get(pending..).is_some_and(|tail| {
            tail.iter()
                .map(|write| write.entry)
                .eq(authority.iter().copied())
        });
        if inputs.old_root != registry.current_root()
            || inputs.old_next_index != u64::from(registry.next_index())
            || inputs.chain_start != queue.chain_head
            || inputs.chain_end != chain_end
            || inputs.writes.len() != pending + authority.len()
            || !tail_matches
        {
            return Err(RingError::RecordProjectionStale);
        }
        Ok(Self {
            bound: BoundQueue {
                ring,
                tail: queue.tail(),
                chain_tail: queue.chain_tail(),
                root: registry.current_root(),
            },
            inputs,
        })
    }
    async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<ApplyRecordsIxData, RingError> {
        StorageApplyProof {
            inputs: &self.inputs,
        }
        .prove(client)
        .await
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RecordSigner {
    Member(Address),
    Authority(Address),
}

/// `[signer, config, registry, queue]`, the authority's write also writes the registry.
pub(crate) fn record_accounts(ring: CustomRing, signer: RecordSigner) -> Vec<AccountMeta> {
    let (RecordSigner::Member(address) | RecordSigner::Authority(address)) = signer;
    vec![
        AccountMeta::new_readonly(address, true),
        AccountMeta::new_readonly(ring.config_pda(), false),
        match signer {
            RecordSigner::Authority(_) => AccountMeta::new(ring.registry_pda(), false),
            RecordSigner::Member(_) => AccountMeta::new_readonly(ring.registry_pda(), false),
        },
        AccountMeta::new(ring.queue_pda(), false),
    ]
}

#[must_use]
pub(crate) struct MemberWrite<'a> {
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub member: Address,
    pub payer: Address,
}

impl MemberWrite<'_> {
    /// The fee accounts follow when the config charges the member.
    pub(crate) fn metas(&self) -> Vec<AccountMeta> {
        let mut accounts = record_accounts(self.ring, RecordSigner::Member(self.member));
        if self.config.insert_fee_for(&self.member).is_some() {
            accounts.extend([
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.config.authority, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ]);
        }
        accounts
    }

    /// A fee raise before the write lands refuses it.
    pub(crate) fn max_fee(&self) -> [u8; 8] {
        self.config.insert_fee.to_le_bytes()
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
