use std::{sync::Arc, time::Duration};

use custom_ring_interface::{
    storage::StorageRegistry, storage_instruction::StorageUpdateIxData, RingAccount, RingPolicy,
    STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::{CustomRing, SyncRoots, UpdateStorage};
use log::warn;
use sea_orm::DbErr;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, ComputeBudgetConfig};
use spr_indexer_api::Hash;
use zolana_ring_client::rpc::{
    GetRecordUpdateStatusRequest, RecordUpdateStatus, SubmitRecordUpdateRequest,
    SubmitRecordUpdateResponse,
};
use zolana_ring_indexer::rpc::{GetStorageApplyProofInputsRequest, StorageWriteView};

use crate::{
    database::Store,
    error::{redacted, RingRpcError},
    record_update::{
        ApplyInputsCheck, BatchPlan, ModeDecision, QueuedUpdate, RecordUpdateCheck,
        RecordUpdateRefusal, UpdateContext,
    },
    storage_chain::{StorageChain, TransactionOutcome},
    update_queue::{BatchOutcome, NewBatch, NewUpdate, OpenBatch, UpdateQueue},
};

pub const RECORD_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
/// The apply proof pairing and the root sync fit under the transaction ceiling.
const UPDATE_COMPUTE_UNITS: u32 = 1_400_000;

/// The one writer of every registry its authority key holds.
pub struct RecordWriter {
    store: Store,
    chain: Arc<dyn StorageChain>,
    authority: Keypair,
}

impl RecordWriter {
    pub(crate) fn new(store: Store, chain: Arc<dyn StorageChain>, authority: Keypair) -> Self {
        Self {
            store,
            chain,
            authority,
        }
    }

    pub fn authority(&self) -> Address {
        self.authority.pubkey()
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
                config: &config,
                policy: &policy,
                registry: &registry,
                writer: self.authority(),
                slot,
            },
        }
        .check()?;
        queue
            .insert(NewUpdate {
                request: &request,
                update: &update,
                queued_slot: slot,
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
        // 2. No update goes out past its valid until slot.
        let slot = self.chain.slot().await?;
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
        let Some(plan) = (BatchPlan { queue: &live, slot }).decide() else {
            return Ok(());
        };
        let batch = &live[..plan.updates];
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
                writes: entries
                    .iter()
                    .map(|entry| StorageWriteView {
                        member: Hash(entry.member),
                        mask: entry.mask,
                        value: entry.value,
                        escrow_key: Hash(entry.escrow_key),
                        mint_policy: entry.mint_policy,
                    })
                    .collect(),
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
            urgent: plan.urgent,
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
                writes: &writes,
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

    async fn policy(&self, ring: Address) -> Result<RingPolicy, RingRpcError> {
        let account = self
            .chain
            .account(CustomRing::new(ring).policy_pda())
            .await?;
        account
            .and_then(|account| RingPolicy::decode(&account.owner, &ring, &account.data))
            .ok_or_else(|| RecordUpdateRefusal::RegistryNotServed.into())
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
fn rings(batch: &[QueuedUpdate]) -> Vec<Address> {
    let mut rings = Vec::new();
    for update in batch {
        if !rings.contains(&update.ring) {
            rings.push(update.ring);
        }
    }
    rings
}
