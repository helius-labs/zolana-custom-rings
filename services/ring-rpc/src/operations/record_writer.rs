//! The one writer of a ring's records, it batches signed updates, proves each batch and sends it.
//!
//! A batch with salted owner writes proves each owner's applied tracking row in the same update that
//! moves the root, and Storage raises the source's tracking floor to the root's revision with it.
//! Without a wired private write source such a batch fails its flush and stays queued.
//!
//! Read after `operations/record_update.rs` and `custom_ring_sdk::PrivateStorageWrite`.
//! Read before `storage/update_queue.rs`.

use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use custom_ring_interface::{
    storage::Revision,
    storage::StorageRegistry,
    storage_instruction::{RecordWriteClassification, StorageUpdateIxData},
    ApplyRecordsIxData, CustomRingError, RecordWrite, RecordWriteData, RingAccount, RingPolicy,
};
use custom_ring_sdk::{
    CustomRing, InitializeStorage, PrivateStorageWrite, ProvenPrivateWrite, RingError,
    SaltedOwnerWrite, UpdateStorage,
};
use log::warn;
use sea_orm::DbErr;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, ComputeBudgetConfig};
use spr_indexer_api::Hash;
use zolana_ring_client::{
    rpc::{
        GetPendingListApprovalsRequest, GetPendingListApprovalsResponse,
        GetRecordUpdateStatusRequest, PendingListApproval, RecordUpdateId, RecordUpdateStatus,
        RefuseListApprovalRequest, SubmitRecordUpdateRequest, SubmitRecordUpdateResponse,
        PENDING_LIST_APPROVALS_PAGE_LIMIT,
    },
    StorageTip,
};
use zolana_ring_indexer::rpc::{GetStorageApplyProofInputsRequest, StorageWriteView};
use zolana_ring_member_registry::ApplyProofInputs;

use crate::{
    config::ReaderGrantStore,
    database::Store,
    error::{redacted, RingRpcError},
    keyed_tasks::{KeyedTasks, MAX_CONCURRENT_KEYED_TASKS},
    landing::{Attempt, ChainOutcome, Landing},
    record_update::{
        limits_within_bounds, ApplyInputsCheck, CheckedUpdate, ListApproval, QueuedCheck,
        QueuedState, QueuedUpdate, RecordUpdateCheck, RecordUpdateRefusal, UpdateContext,
    },
    storage_chain::StorageChain,
    update_queue::{
        ApprovalCandidates, ApprovalScope, BatchOutcome, NewBatch, NewUpdate, OpenBatch,
        PendingApprovalPage, UpdateQueue,
    },
    upstream::VerifiedOpenings,
};

pub const RECORD_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_BATCH_PLANS: usize = 2;
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// The apply proof pairing fits under the transaction ceiling.
pub(crate) const UPDATE_COMPUTE_UNITS: u32 = 1_400_000;
const CREATE_COMPUTE_UNITS: u32 = 100_000;

/// The owner and list salt behind a salted list key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SaltedOwner {
    pub owner: Address,
    pub list_salt: [u8; 32],
}

/// The service that holds a ring's enrollments and auditor key resolves and proves salted owner writes.
#[async_trait]
pub trait PrivateWrites: Send + Sync {
    /// `None` when no held enrollment of `ring` opens to `written_key`.
    async fn salted_owner(
        &self,
        ring: Address,
        written_key: [u8; 32],
    ) -> Result<Option<SaltedOwner>, RingRpcError>;

    async fn prove(&self, write: PrivateStorageWrite<'_>) -> Result<ProvenPrivateWrite, RingError>;
}

/// The one writer of every registry its authority key holds.
pub struct RecordWriter {
    store: Store,
    chain: Arc<dyn StorageChain>,
    authority: Keypair,
    genesis_hash: [u8; 32],
    reader_grants: ReaderGrantStore,
    /// Holds the queue check and the insert of one update together.
    submits: tokio::sync::Mutex<()>,
    /// One records creation at a time, a second request finds the first registry.
    creations: tokio::sync::Mutex<()>,
    private_writes: OnceLock<Arc<dyn PrivateWrites>>,
}

enum BatchProof {
    Public(Box<ApplyRecordsIxData>),
    Private(Box<ProvenPrivateWrite>),
}

#[must_use]
pub(crate) struct WriterParts {
    pub store: Store,
    pub chain: Arc<dyn StorageChain>,
    pub authority: Keypair,
    pub genesis_hash: [u8; 32],
    pub reader_grants: ReaderGrantStore,
}

impl WriterParts {
    pub fn writer(self) -> RecordWriter {
        RecordWriter {
            store: self.store,
            chain: self.chain,
            authority: self.authority,
            genesis_hash: self.genesis_hash,
            reader_grants: self.reader_grants,
            submits: tokio::sync::Mutex::default(),
            creations: tokio::sync::Mutex::default(),
            private_writes: OnceLock::new(),
        }
    }
}

impl RecordWriter {
    pub fn authority(&self) -> Address {
        self.authority.pubkey()
    }

    /// Set once, a second source is returned.
    pub fn serve_private_writes(
        &self,
        source: Arc<dyn PrivateWrites>,
    ) -> Result<(), Arc<dyn PrivateWrites>> {
        self.private_writes.set(source)
    }

    /// The writer authority owns and pays for the ring's records.
    pub(crate) async fn create_records(&self, ring: Address) -> Result<Address, RingRpcError> {
        let storage = InitializeStorage::records(CustomRing::new(ring), self.authority());
        let registry = storage.registry();
        let _creating = self.creations.lock().await;
        if self.registry(registry).await?.is_some() {
            return Ok(registry);
        }
        let latest = self.chain.latest_blockhash().await?;
        let message = compile_message(
            &self.authority(),
            &[storage.instruction()],
            latest.blockhash,
            ComputeBudgetConfig::new(CREATE_COMPUTE_UNITS),
        )?;
        let transaction = sign_transaction(message, &[&self.authority])?;
        let attempt = Attempt {
            signature: transaction.signatures[0],
            last_valid_block_height: latest.last_valid_block_height,
        };
        self.chain.send(&transaction).await?;
        loop {
            match attempt.landing(self.chain.as_ref()).await? {
                Landing::Pending => tokio::time::sleep(CONFIRM_POLL_INTERVAL).await,
                Landing::Landed(ChainOutcome::Confirmed { .. }) => return Ok(registry),
                Landing::Landed(ChainOutcome::Failed { .. }) | Landing::Expired => {
                    return Err(RecordUpdateRefusal::RecordsNotCreated.into())
                }
            }
        }
    }

    /// A resubmitted update returns the id it was queued under.
    pub async fn submit(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<SubmitRecordUpdateResponse, RingRpcError> {
        let queue = self.queue();
        // Precedes the id, an unpaired cap hashes to no statement.
        if !request.update.entries.iter().all(limits_within_bounds) {
            return Err(RecordUpdateRefusal::InvalidLimits.into());
        }
        let id = request
            .statement()
            .and_then(|statement| Ok(statement.id()?))
            .map_err(|_| RecordUpdateRefusal::InvalidEntry)?;
        if queue.contains(&id.0 .0).await? {
            return Ok(SubmitRecordUpdateResponse { update_id: id });
        }
        let ring = request.update.ring.0;
        let config = self
            .chain
            .ring_config(ring)
            .await?
            .ok_or(RecordUpdateRefusal::UnknownRing)?;
        let policy = self.policy(ring).await?;
        let registry = self
            .registry(request.registry.0)
            .await?
            .ok_or(RecordUpdateRefusal::RegistryNotServed)?;
        let slot = self.chain.slot().await?;
        let update = RecordUpdateCheck {
            request: &request,
            context: UpdateContext {
                genesis_hash: &self.genesis_hash,
                config: &config,
                policy: &policy,
                registry: &registry,
                writer: self.authority(),
                slot,
                reader_grants: self.reader_grants,
            },
        }
        .check()?;
        let records = StorageTip::newest(policy.records, &registry);
        self.check_limited_assets(&update, &records).await?;
        let _queueing = self.submits.lock().await;
        if queue.contains(&update.id.0 .0).await? {
            return Ok(SubmitRecordUpdateResponse {
                update_id: update.id,
            });
        }
        // An expired pending update joins no approval.
        queue.expire(request.registry.0, slot).await?;
        let grants = update.approval_grants()?;
        let approves = ListApproval {
            update: &update,
            pending: &queue
                .pending_approvals(ApprovalCandidates {
                    scope: ApprovalScope {
                        ring,
                        registry: request.registry.0,
                    },
                    grants: &grants,
                    slot,
                })
                .await?,
        }
        .decide()?;
        queue
            .insert(NewUpdate {
                request: &request,
                update: &update,
                queued_slot: slot,
                approves: &approves,
            })
            .await?;
        Ok(SubmitRecordUpdateResponse {
            update_id: update.id,
        })
    }

    pub async fn status(
        &self,
        request: GetRecordUpdateStatusRequest,
    ) -> Result<RecordUpdateStatus, RingRpcError> {
        self.queue()
            .status(&request.update_id.0 .0)
            .await?
            .ok_or_else(|| RecordUpdateRefusal::UnknownUpdate.into())
    }

    /// One page of the ring's updates pending list approval, oldest first.
    pub(crate) async fn pending_list_approvals(
        &self,
        signer: Address,
        request: &GetPendingListApprovalsRequest,
    ) -> Result<GetPendingListApprovalsResponse, RingRpcError> {
        let ring = request.ring.0;
        self.require_policy_authority(ring, signer).await?;
        let mut pending = self
            .queue()
            .pending_approval_page(PendingApprovalPage {
                scope: ApprovalScope {
                    ring,
                    registry: request.registry.0,
                },
                cursor: request.cursor.as_ref().map(|cursor| cursor.0 .0),
                limit: PENDING_LIST_APPROVALS_PAGE_LIMIT + 1,
            })
            .await?
            .ok_or(RecordUpdateRefusal::UnknownUpdate)?
            .into_iter()
            .map(|approval| PendingListApproval {
                update_id: RecordUpdateId(Hash(approval.id)),
                wallet: approval.wallet.into(),
                member: Hash(approval.member),
                awaited_lists: approval.lists.record_bits(),
                valid_until_slot: approval.valid_until_slot,
            })
            .collect::<Vec<_>>();
        let next_cursor = (pending.len() > PENDING_LIST_APPROVALS_PAGE_LIMIT).then(|| {
            pending.truncate(PENDING_LIST_APPROVALS_PAGE_LIMIT);
            pending[PENDING_LIST_APPROVALS_PAGE_LIMIT - 1]
                .update_id
                .clone()
        });
        Ok(GetPendingListApprovalsResponse {
            pending,
            next_cursor,
        })
    }

    pub(crate) async fn refuse_list_approval(
        &self,
        signer: Address,
        request: &RefuseListApprovalRequest,
    ) -> Result<RecordUpdateStatus, RingRpcError> {
        let scope = ApprovalScope {
            ring: request.ring.0,
            registry: request.registry.0,
        };
        self.require_policy_authority(scope.ring, signer).await?;
        let _queueing = self.submits.lock().await;
        if !self
            .queue()
            .refuse_pending_approval(scope, &request.update_id.0 .0)
            .await?
        {
            return Err(RecordUpdateRefusal::UnknownListApproval.into());
        }
        Ok(RecordUpdateStatus::Refused {
            reason: RecordUpdateRefusal::ListApprovalRefused.to_string(),
        })
    }

    /// Every `interval`, the first at once, each registry on its own task.
    ///
    /// A registry still flushing sits out the tick, a stalled send never holds another registry.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        let registries = KeyedTasks::new(MAX_CONCURRENT_KEYED_TASKS);
        let mut ticks = tokio::time::interval(interval);
        loop {
            ticks.tick().await;
            let due = match self.queue().registries().await {
                Ok(due) => due,
                Err(error) => {
                    warn!("record flush failed because {}", redacted(&error));
                    continue;
                }
            };
            registries.spawn_idle(due, |registry| {
                let writer = self.clone();
                async move { writer.flush_logged(registry).await }
            });
        }
    }

    /// One pass over every registry with work, a failing registry never holds up another.
    pub async fn flush(&self) -> Result<(), RingRpcError> {
        for registry in self.queue().registries().await? {
            self.flush_logged(registry).await;
        }
        Ok(())
    }

    async fn flush_logged(&self, registry: Address) {
        if let Err(error) = self.flush_registry(registry).await {
            warn!(
                "record flush of registry {registry} failed because {}",
                redacted(&error)
            );
        }
    }

    async fn flush_registry(&self, registry: Address) -> Result<(), RingRpcError> {
        let queue = self.queue();
        // 1. An open batch settles before the next one, so revisions stay in submit order.
        if let Some(batch) = queue.open_batch(registry).await? {
            return self.settle(batch).await;
        }
        let slot = self.chain.slot().await?;
        queue.expire(registry, slot).await?;
        // 2. One batch per flush, a refused update leaves the queue and the plan reads the heads
        //    again.
        for _ in 0..MAX_BATCH_PLANS {
            let Some(batch) = queue.plan(registry, slot).await? else {
                return Ok(());
            };
            // 3. Each planned signer still holds the role it signed as, an unread ring account
            //    holds the registry.
            let policies = self.queued_authorities(batch.iter()).await?;
            let mut refused = false;
            for update in &batch {
                let check = QueuedCheck {
                    update,
                    slot,
                    policy_authority: policies.get(&update.ring).copied().flatten(),
                };
                match check.check() {
                    Ok(QueuedState::Live) => {}
                    Ok(QueuedState::Deferred) => return Ok(()),
                    Err(refusal) => {
                        queue.refuse(&update.id, refusal).await?;
                        refused = true;
                    }
                }
            }
            if !refused {
                return self.prove_and_send(registry, &batch).await;
            }
        }
        Ok(())
    }

    async fn prove_and_send(
        &self,
        registry: Address,
        batch: &[QueuedUpdate],
    ) -> Result<(), RingRpcError> {
        // 1. The proof starts at the registry's current root and covers the batch in order.
        let writes: Vec<_> = batch
            .iter()
            .flat_map(|update| update.writes.iter().copied())
            .collect();
        let entries = writes
            .iter()
            .map(RecordWriteData::storage_entry)
            .collect::<Result<Vec<RecordWrite>, _>>()
            .map_err(|_| DbErr::Custom("stored record update writes are invalid".to_owned()))?;
        let state = self
            .registry(registry)
            .await?
            .ok_or(RecordUpdateRefusal::RegistryNotServed)?;
        let response = self
            .chain
            .apply_inputs(GetStorageApplyProofInputsRequest {
                registry: registry.into(),
                writes: entries.iter().map(StorageWriteView::from).collect(),
            })
            .await?;
        let checked = ApplyInputsCheck {
            response: &response,
            registry: &state,
            entries: &entries,
        }
        .check()?;
        // 2. A private batch names the tracking revision its rows opened under.
        let ring = batch
            .first()
            .map(|update| update.ring)
            .ok_or(DbErr::Custom("a planned batch holds no update".to_owned()))?;
        let proof = self
            .prove_batch(ring, &checked.inputs, &state, &entries)
            .await?;
        // 3. The storage update is the transaction's one instruction.
        let data = StorageUpdateIxData {
            revision: checked.revision,
            writes,
            asset_writes: Vec::new(),
            tracking_revision: proof.tracking_revision(),
            apply: proof.apply(),
        };
        let instruction = UpdateStorage {
            authority: self.authority(),
            registry,
            tracking_registry: state.tracking_registry,
            data,
        }
        .instruction()
        .map_err(|error| RingRpcError::StorageUpdate(error.into()))?;
        let latest = self.chain.latest_blockhash().await?;
        let message = compile_message(
            &self.authority(),
            &[instruction],
            latest.blockhash,
            ComputeBudgetConfig::new(UPDATE_COMPUTE_UNITS),
        )?;
        let policies = self.queued_authorities(batch.iter()).await?;
        let slot = self.chain.slot().await?;
        let mut rejected = false;
        for update in batch {
            match (QueuedCheck {
                update,
                slot,
                policy_authority: policies.get(&update.ring).copied().flatten(),
            })
            .check()
            {
                Ok(QueuedState::Live) => {}
                Ok(QueuedState::Deferred) => rejected = true,
                Err(refusal) => {
                    self.queue().refuse(&update.id, refusal).await?;
                    rejected = true;
                }
            }
        }
        if rejected {
            return Ok(());
        }
        let transaction = sign_transaction(message, &[&self.authority])?;
        // 4. The batch is durable before it is sent, a restart settles it by its signature.
        self.queue()
            .record_batch(NewBatch {
                registry,
                attempt: Attempt {
                    signature: transaction.signatures[0],
                    last_valid_block_height: latest.last_valid_block_height,
                },
                revision: checked.revision.value(),
                updates: batch,
            })
            .await?;
        self.chain.send(&transaction).await?;
        Ok(())
    }

    async fn queued_authorities<'a>(
        &self,
        updates: impl Iterator<Item = &'a QueuedUpdate>,
    ) -> Result<HashMap<Address, Option<Address>>, RingRpcError> {
        let mut authorities = HashMap::new();
        for update in updates {
            if let Entry::Vacant(ring) = authorities.entry(update.ring) {
                ring.insert(
                    self.ring_policy(update.ring)
                        .await?
                        .map(|policy| policy.roles.policy),
                );
            }
        }
        Ok(authorities)
    }

    async fn prove_batch(
        &self,
        ring: Address,
        inputs: &ApplyProofInputs,
        registry: &StorageRegistry,
        entries: &[RecordWrite],
    ) -> Result<BatchProof, RingRpcError> {
        let storage = |error: RingError| RingRpcError::StorageUpdate(Box::new(error));
        // 1. Storage derives the private writes from the masks, the writer reads them the same way.
        let private_writes = RecordWriteClassification {
            entries: entries.iter().map(|entry| Ok::<_, CustomRingError>(*entry)),
            asset_writes: &[],
        }
        .private_writes()
        .map_err(|error| storage(error.into()))?;
        if private_writes == 0 {
            let apply = self.chain.prove_apply(inputs, registry).await?;
            return Ok(BatchProof::Public(Box::new(apply)));
        }
        let source = self
            .private_writes
            .get()
            .ok_or(RecordUpdateRefusal::Disabled)?;
        // 2. Each salted key names its owner through an enrollment the auditor key opens.
        let mut owners = Vec::new();
        for (write_index, entry) in (0u8..).zip(entries) {
            if private_writes & (1 << write_index) == 0 {
                continue;
            }
            let owner = source
                .salted_owner(ring, entry.member)
                .await?
                .ok_or_else(|| storage(RingError::WriteOwnerNotEnrolled { write_index }))?;
            owners.push(SaltedOwnerWrite {
                write_index,
                owner: owner.owner,
                list_salt: owner.list_salt,
            });
        }
        // 3. The proof and the floor raise travel together in one update.
        let write = PrivateStorageWrite {
            ring: CustomRing::new(ring),
            inputs,
            registry,
            asset_writes: &[],
            owners: &owners,
        };
        let proven = source.prove(write).await.map_err(storage)?;
        Ok(BatchProof::Private(Box::new(proven)))
    }

    async fn settle(&self, batch: OpenBatch) -> Result<(), RingRpcError> {
        let outcome = match batch.attempt.landing(self.chain.as_ref()).await? {
            Landing::Pending => return Ok(()),
            Landing::Landed(ChainOutcome::Confirmed { .. }) => BatchOutcome::Applied,
            Landing::Landed(ChainOutcome::Failed { .. }) | Landing::Expired => {
                BatchOutcome::Requeued
            }
        };
        Ok(self.queue().settle(batch.id, outcome).await?)
    }

    async fn check_limited_assets(
        &self,
        update: &CheckedUpdate,
        records: &StorageTip,
    ) -> Result<(), RingRpcError> {
        let assets = update.limited_assets()?;
        if assets.is_empty() {
            return Ok(());
        }
        let openings = self.chain.verified_openings(records, &assets).await?;
        if openings.iter().any(|opening| opening.record().is_none()) {
            return Err(RecordUpdateRefusal::LimitsWithoutRecord.into());
        }
        Ok(())
    }

    async fn require_policy_authority(
        &self,
        ring: Address,
        signer: Address,
    ) -> Result<(), RingRpcError> {
        let config = self
            .chain
            .ring_config(ring)
            .await?
            .ok_or(RecordUpdateRefusal::UnknownRing)?;
        if config.roles.policy != signer {
            return Err(RecordUpdateRefusal::NotPolicyAuthority.into());
        }
        Ok(())
    }

    async fn policy(&self, ring: Address) -> Result<RingPolicy, RingRpcError> {
        self.ring_policy(ring)
            .await?
            .ok_or_else(|| RecordUpdateRefusal::RegistryNotServed.into())
    }

    async fn ring_policy(&self, ring: Address) -> Result<Option<RingPolicy>, RingRpcError> {
        let account = self
            .chain
            .account(CustomRing::new(ring).policy_pda())
            .await?;
        Ok(account.and_then(|account| RingPolicy::decode(&account.owner, &ring, &account.data)))
    }

    async fn registry(&self, address: Address) -> Result<Option<StorageRegistry>, RingRpcError> {
        Ok(self
            .chain
            .account(address)
            .await?
            .and_then(|account| StorageRegistry::decode(&account.owner, &account.data)))
    }

    fn queue(&self) -> UpdateQueue<'_> {
        UpdateQueue::new(self.store.connection())
    }
}

impl BatchProof {
    fn apply(&self) -> &ApplyRecordsIxData {
        match self {
            Self::Public(apply) => apply,
            Self::Private(proven) => &proven.apply,
        }
    }

    fn tracking_revision(&self) -> Option<Revision> {
        match self {
            Self::Public(_) => None,
            Self::Private(proven) => Some(proven.tracking_revision),
        }
    }
}
