use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
    time::Duration,
};

use custom_ring_interface::{
    storage::StorageRegistry, storage_instruction::StorageUpdateIxData, RingAccount, RingPolicy,
};
use custom_ring_sdk::{CustomRing, InitializeStorage, UpdateStorage};
use log::warn;
use sea_orm::DbErr;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, ComputeBudgetConfig};
use spr_indexer_api::Hash;
use zolana_ring_client::{
    rpc::{
        GetPendingEnrolmentsRequest, GetPendingEnrolmentsResponse, GetRecordUpdateStatusRequest,
        PendingEnrolment, RecordUpdateId, RecordUpdateStatus, SubmitRecordUpdateRequest,
        SubmitRecordUpdateResponse, PENDING_ENROLMENTS_PAGE_LIMIT,
    },
    StorageTip,
};
use zolana_ring_indexer::rpc::{GetStorageApplyProofInputsRequest, StorageWriteView};

use crate::{
    config::ReaderGrantStore,
    database::Store,
    error::{redacted, RingRpcError},
    record_update::{
        escrowed_members, limits_within_bounds, ApplyInputsCheck, BatchPlan, CheckedUpdate,
        EnrolmentApproval, EscrowUniqueness, ModeDecision, QueuedCheck, RecordUpdateCheck,
        RecordUpdateRefusal, UpdateContext,
    },
    storage_chain::{StorageChain, TransactionOutcome},
    update_queue::{AwaitingPage, BatchOutcome, NewBatch, NewUpdate, OpenBatch, UpdateQueue},
    upstream::VerifiedOpenings,
};

pub const RECORD_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// The apply proof pairing fits under the transaction ceiling.
const UPDATE_COMPUTE_UNITS: u32 = 1_400_000;
const CREATE_COMPUTE_UNITS: u32 = 100_000;

/// The one writer of every registry its authority key holds.
pub struct RecordWriter {
    store: Store,
    chain: Arc<dyn StorageChain>,
    authority: Keypair,
    genesis_hash: [u8; 32],
    reader_grants: ReaderGrantStore,
    /// Holds the escrow check and the insert of one update together.
    submits: tokio::sync::Mutex<()>,
    /// One records creation at a time, a second request finds the first registry.
    creations: tokio::sync::Mutex<()>,
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
        }
    }
}

impl RecordWriter {
    pub fn authority(&self) -> Address {
        self.authority.pubkey()
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
        let signature = self.chain.send(&transaction).await?;
        self.confirmed(signature, latest.last_valid_block_height)
            .await?;
        Ok(registry)
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
        // An expired enrolment joins no approval.
        queue.expire_awaiting(request.registry.0, slot).await?;
        self.check_escrows(&update, &records).await?;
        let approves = EnrolmentApproval {
            update: &update,
            awaiting: &queue
                .awaiting_members(ring, &update.written_members()?)
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

    /// One page of the ring's enrolments that await its policy authority, oldest first.
    pub(crate) async fn pending_enrolments(
        &self,
        signer: Address,
        request: &GetPendingEnrolmentsRequest,
    ) -> Result<GetPendingEnrolmentsResponse, RingRpcError> {
        let ring = request.ring.0;
        self.require_policy_authority(ring, signer).await?;
        let mut enrolments = self
            .queue()
            .awaiting_page(AwaitingPage {
                ring,
                cursor: request.cursor.as_ref().map(|cursor| cursor.0 .0),
                limit: PENDING_ENROLMENTS_PAGE_LIMIT + 1,
            })
            .await?
            .ok_or(RecordUpdateRefusal::UnknownUpdate)?
            .into_iter()
            .map(|enrolment| PendingEnrolment {
                update_id: RecordUpdateId(Hash(enrolment.id)),
                wallet: enrolment.wallet.into(),
                member: Hash(enrolment.member),
                awaited_lists: enrolment.lists.record_bits(),
                valid_until_slot: enrolment.valid_until_slot,
            })
            .collect::<Vec<_>>();
        let next_cursor = (enrolments.len() > PENDING_ENROLMENTS_PAGE_LIMIT).then(|| {
            enrolments.truncate(PENDING_ENROLMENTS_PAGE_LIMIT);
            enrolments[PENDING_ENROLMENTS_PAGE_LIMIT - 1]
                .update_id
                .clone()
        });
        Ok(GetPendingEnrolmentsResponse {
            enrolments,
            next_cursor,
        })
    }

    pub(crate) async fn refuse_enrolment(
        &self,
        ring: Address,
        signer: Address,
        update_id: &RecordUpdateId,
    ) -> Result<RecordUpdateStatus, RingRpcError> {
        self.require_policy_authority(ring, signer).await?;
        let _queueing = self.submits.lock().await;
        if !self.queue().refuse_awaiting(ring, &update_id.0 .0).await? {
            return Err(RecordUpdateRefusal::UnknownEnrolment.into());
        }
        Ok(RecordUpdateStatus::Refused {
            reason: RecordUpdateRefusal::EnrolmentRefused.to_string(),
        })
    }

    /// Every `interval`, the first at once.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        let mut ticks = tokio::time::interval(interval);
        loop {
            ticks.tick().await;
            if let Err(error) = self.flush().await {
                warn!("record flush failed because {}", redacted(&error));
            }
        }
    }

    /// One pass over every registry with work, a failing registry never holds up another.
    pub async fn flush(&self) -> Result<(), RingRpcError> {
        for registry in self.queue().registries().await? {
            if let Err(error) = self.flush_registry(registry).await {
                warn!(
                    "record flush of registry {registry} failed because {}",
                    redacted(&error)
                );
            }
        }
        Ok(())
    }

    async fn flush_registry(&self, registry: Address) -> Result<(), RingRpcError> {
        let queue = self.queue();
        // 1. An open batch settles before the next one, so revisions stay in submit order.
        if let Some(batch) = queue.open_batch(registry).await? {
            return self.settle(batch).await;
        }
        // 2. Each live update is within its valid until slot, an enrolment's own included, and its signer holds the role it signed as.
        let slot = self.chain.slot().await?;
        queue.expire_awaiting(registry, slot).await?;
        let queued = queue.queued(registry).await?;
        let mut policy_authorities = HashMap::new();
        for update in queued.iter().filter(|update| update.signer.is_authority()) {
            if let Entry::Vacant(ring) = policy_authorities.entry(update.ring) {
                let config = self.chain.ring_config(update.ring).await?;
                ring.insert(config.map(|config| config.roles.policy));
            }
        }
        let mut live = Vec::new();
        for update in queued {
            let check = QueuedCheck {
                update: &update,
                slot,
                policy_authority: policy_authorities.get(&update.ring).copied().flatten(),
            };
            match check.check() {
                Ok(()) => live.push(update),
                Err(refusal) => queue.refuse(&update.id, refusal).await?,
            }
        }
        let Some(plan) = (BatchPlan { queue: &live, slot }).decide()? else {
            return Ok(());
        };
        let batch = plan.updates.as_slice();
        // 3. The proof starts at the registry's current root and covers the batch in order.
        let writes: Vec<_> = batch
            .iter()
            .flat_map(|update| update.writes.iter().copied())
            .collect();
        let entries = writes
            .iter()
            .map(|write| write.entry())
            .collect::<Result<Vec<_>, _>>()
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
        let Some(mode) = (ModeDecision {
            inputs: &checked.inputs,
            registry: &state,
            slot,
        })
        .decide() else {
            return Ok(());
        };
        let apply = self.chain.prove_apply(&checked.inputs).await?;
        // 4. The storage update is the transaction's one instruction.
        let instruction = UpdateStorage {
            authority: self.authority(),
            registry,
            mode,
            data: StorageUpdateIxData {
                revision: checked.revision,
                writes,
                apply: &apply,
            },
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
        let transaction = sign_transaction(message, &[&self.authority])?;
        // 5. The batch is durable before it is sent, a restart settles it by its signature.
        queue
            .record_batch(NewBatch {
                registry,
                signature: transaction.signatures[0],
                revision: checked.revision.value(),
                last_valid_block_height: latest.last_valid_block_height,
                updates: batch,
            })
            .await?;
        self.chain.send(&transaction).await?;
        Ok(())
    }

    /// An unknown signature requeues only once its blockhash can no longer land.
    async fn settle(&self, batch: OpenBatch) -> Result<(), RingRpcError> {
        let outcome = match self.chain.outcome(batch.signature).await? {
            TransactionOutcome::Succeeded => BatchOutcome::Applied,
            TransactionOutcome::Failed => BatchOutcome::Requeued,
            TransactionOutcome::Unknown => {
                if self.chain.block_height().await? <= batch.last_valid_block_height {
                    return Ok(());
                }
                BatchOutcome::Requeued
            }
        };
        Ok(self.queue().settle(batch.id, outcome).await?)
    }

    async fn confirmed(
        &self,
        signature: Signature,
        last_valid_block_height: u64,
    ) -> Result<(), RingRpcError> {
        loop {
            match self.chain.outcome(signature).await? {
                TransactionOutcome::Succeeded => return Ok(()),
                TransactionOutcome::Failed => {
                    return Err(RecordUpdateRefusal::RecordsNotCreated.into())
                }
                TransactionOutcome::Unknown
                    if self.chain.block_height().await? > last_valid_block_height =>
                {
                    return Err(RecordUpdateRefusal::RecordsNotCreated.into())
                }
                TransactionOutcome::Unknown => tokio::time::sleep(CONFIRM_POLL_INTERVAL).await,
            }
        }
    }

    /// Refuses an escrow key for a member whose record or pending update holds one.
    async fn check_escrows(
        &self,
        update: &CheckedUpdate,
        records: &StorageTip,
    ) -> Result<(), RingRpcError> {
        let registering = escrowed_members(&update.writes)?;
        if registering.is_empty() {
            return Ok(());
        }
        let openings = self.chain.verified_openings(records, &registering).await?;
        let pending = self
            .queue()
            .pending_writes(records.registry, &registering)
            .await?;
        Ok(EscrowUniqueness {
            registering: &registering,
            records: &openings,
            pending: &pending,
        }
        .check()?)
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
