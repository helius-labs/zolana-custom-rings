use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use custom_ring_interface::{
    storage::{Root, StorageRegistry},
    storage_instruction::StorageUpdateIxData,
    RingAccount, RingPolicy, RootMirror, ROOT_HISTORY, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::{CustomRing, InitializeStorage, SyncRoots, UpdateStorage};
use log::warn;
use sea_orm::DbErr;
use solana_address::Address;
use solana_instruction::Instruction;
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
    error::{redacted, GrantRefusal, RingRpcError},
    record_update::{
        escrowed_members, ApplyInputsCheck, BatchPlan, CheckedUpdate, EnrolmentApproval,
        EscrowUniqueness, ModeDecision, QueuedUpdate, RecordUpdateCheck, RecordUpdateRefusal,
        UpdateContext,
    },
    relay::ServedRings,
    storage_chain::{StorageChain, TransactionOutcome},
    update_queue::{AwaitingPage, BatchOutcome, NewBatch, NewUpdate, OpenBatch, UpdateQueue},
    upstream::VerifiedOpenings,
};

pub const RECORD_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// The apply proof pairing and the root sync fit under the transaction ceiling.
const UPDATE_COMPUTE_UNITS: u32 = 1_400_000;
const SYNC_COMPUTE_UNITS: u32 = 200_000;
const CREATE_COMPUTE_UNITS: u32 = 100_000;
/// Subscriber `SyncRoots` instructions one transaction carries under the account limit.
const SYNCS_PER_TRANSACTION: usize = 16;

/// The one writer of every registry its authority key holds.
pub struct RecordWriter {
    store: Store,
    chain: Arc<dyn StorageChain>,
    authority: Keypair,
    genesis_hash: [u8; 32],
    watched: Vec<Address>,
    rings: ServedRings,
    reader_grants: ReaderGrantStore,
    /// Each registry's roots every subscriber mirrored at the last check.
    synced: Mutex<HashMap<Address, [Root; ROOT_HISTORY]>>,
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
    /// Curator registries whose subscribers the writer syncs.
    pub watched: Vec<Address>,
    pub rings: ServedRings,
    pub reader_grants: ReaderGrantStore,
}

impl WriterParts {
    pub fn writer(self) -> RecordWriter {
        RecordWriter {
            store: self.store,
            chain: self.chain,
            authority: self.authority,
            genesis_hash: self.genesis_hash,
            watched: self.watched,
            rings: self.rings,
            reader_grants: self.reader_grants,
            synced: Mutex::default(),
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
        let _queueing = self.submits.lock().await;
        if queue.contains(&update.id.0 .0).await? {
            return Ok(SubmitRecordUpdateResponse {
                update_id: update.id,
            });
        }
        // An expired enrolment joins no approval.
        queue.expire_awaiting(request.registry.0, slot).await?;
        self.check_escrows(&update, &policy).await?;
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
        let mut curated = self.queue().applied_registries().await?;
        curated.extend_from_slice(&self.watched);
        curated.sort_unstable();
        curated.dedup();
        for registry in &curated {
            if let Err(error) = self.sync_subscribers(*registry).await {
                warn!(
                    "subscriber sync of registry {registry} failed because {}",
                    redacted(&error)
                );
            }
        }
        for ring in self.written_rings().await? {
            if let Err(error) = self.follow_curator(ring, &curated).await {
                warn!(
                    "curator sync of ring {ring} failed because {}",
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
        // 2. No update goes out past its valid until slot, an enrolment's own included.
        let slot = self.chain.slot().await?;
        queue.expire_awaiting(registry, slot).await?;
        let mut live = Vec::new();
        for update in queue.queued(registry).await? {
            if slot > update.valid_until_slot {
                queue
                    .refuse(&update.id, &RecordUpdateRefusal::Expired.to_string())
                    .await?;
            } else {
                live.push(update);
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
        // 4. The same transaction mirrors the new root into every ring the batch writes for.
        let mut instructions = vec![UpdateStorage {
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
        .map_err(|error| RingRpcError::StorageUpdate(error.into()))?];
        for ring in rings(batch) {
            instructions.push(
                SyncRoots {
                    ring: CustomRing::new(ring),
                    registry,
                }
                .instruction(),
            );
        }
        let latest = self.chain.latest_blockhash().await?;
        let message = compile_message(
            &self.authority(),
            &instructions,
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
        policy: &RingPolicy,
    ) -> Result<(), RingRpcError> {
        let registering = escrowed_members(&update.writes)?;
        if registering.is_empty() {
            return Ok(());
        }
        let records = StorageTip::mirrored(policy).ok_or(GrantRefusal::RecordsUnsynced)?;
        let openings = self.chain.verified_openings(&records, &registering).await?;
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

    /// Sends `SyncRoots` to every subscriber whose curator mirror differs from the registry roots.
    async fn sync_subscribers(&self, registry: Address) -> Result<(), RingRpcError> {
        let Some(state) = self.registry(registry).await? else {
            return Ok(());
        };
        if self.synced_roots(registry) == Some(state.roots) {
            return Ok(());
        }
        let stale: Vec<_> = self
            .chain
            .subscribers(registry)
            .await?
            .into_iter()
            .filter(|subscriber| {
                subscriber.curator_roots
                    != RootMirror {
                        registry,
                        roots: state.roots,
                    }
            })
            .map(|subscriber| subscriber.ring)
            .collect();
        // The cache holds only roots every subscriber mirrors, a lost sync retries next pass.
        if stale.is_empty() {
            self.synced
                .lock()
                .map_err(|_| RingRpcError::StateUnavailable)?
                .insert(registry, state.roots);
        }
        self.send_syncs(registry, &stale).await
    }

    async fn follow_curator(&self, ring: Address, curated: &[Address]) -> Result<(), RingRpcError> {
        let Some(policy) = self.ring_policy(ring).await? else {
            return Ok(());
        };
        let Some(registry) = policy
            .curator()
            .filter(|curator| !curated.contains(curator))
        else {
            return Ok(());
        };
        let Some(state) = self.registry(registry).await? else {
            return Ok(());
        };
        let synced = RootMirror {
            registry,
            roots: state.roots,
        };
        if policy.curator_roots == synced {
            return Ok(());
        }
        self.send_syncs(registry, &[ring]).await
    }

    async fn send_syncs(&self, registry: Address, rings: &[Address]) -> Result<(), RingRpcError> {
        for rings in rings.chunks(SYNCS_PER_TRANSACTION) {
            let instructions: Vec<Instruction> = rings
                .iter()
                .map(|ring| {
                    SyncRoots {
                        ring: CustomRing::new(*ring),
                        registry,
                    }
                    .instruction()
                })
                .collect();
            let latest = self.chain.latest_blockhash().await?;
            let message = compile_message(
                &self.authority(),
                &instructions,
                latest.blockhash,
                ComputeBudgetConfig::new(SYNC_COMPUTE_UNITS),
            )?;
            let transaction = sign_transaction(message, &[&self.authority])?;
            self.chain.send(&transaction).await?;
        }
        Ok(())
    }

    /// Every ring the update queue holds, the local ring before its first update.
    async fn written_rings(&self) -> Result<Vec<Address>, RingRpcError> {
        let mut rings = self.queue().rings().await?;
        if let ServedRings::One(ring) = self.rings {
            if !rings.contains(&ring) {
                rings.push(ring);
            }
        }
        Ok(rings)
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

    fn synced_roots(&self, registry: Address) -> Option<[Root; ROOT_HISTORY]> {
        self.synced.lock().ok()?.get(&registry).copied()
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
            .filter(|account| account.owner == STORAGE_PROGRAM_ID)
            .and_then(|account| StorageRegistry::from_data(&account.data).copied()))
    }

    fn queue(&self) -> UpdateQueue<'_> {
        UpdateQueue::new(self.store.connection())
    }
}

/// Each ring once, in first use order.
fn rings(batch: &[&QueuedUpdate]) -> Vec<Address> {
    let mut rings = Vec::new();
    for update in batch {
        if !rings.contains(&update.ring) {
            rings.push(update.ring);
        }
    }
    rings
}
