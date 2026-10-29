//! Member records read while the projection catches up, and the record queue applied once due.

use std::fmt::Display;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::{queue_chain, CustomRingError, QueueEntry, RecordQueue, RingPolicy};
use custom_ring_sdk::{CustomRing, CustomRingConfig, MemberRecords, RecordApplication, RingError};
use solana_address::Address;
use solana_signer::Signer;
use spr_client::{BlockingIndexer, BlockingRpc, Rpc};
use spr_indexer_api::Hash;
use zolana_ring_client::{records::MemberOpeningRead, RingIndexer};
use zolana_ring_indexer::rpc::{GetRingRecordQueueRequest, GetRingRecordQueueResponse};
use zolana_ring_member_registry::MemberRecord;
use zolana_ring_policy::Member;

use crate::{transact::SENDER_FEE_BUDGET, wait_for, Context, Landing, Probe, Zolana};

pub const NO_MEMBER_REGISTRY: &str =
    "the ring has no member registry, its authority must run `zolana-ring init` first";
pub const NO_RING_POLICY: &str =
    "the ring has no ring policy, its authority must run `zolana-ring init` first";

#[must_use]
pub struct Queued {
    ring: CustomRing,
    tail: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Applied,
    Queued,
    Unsent,
}

/// Bound by the on-chain hash chain, read before the applied record they lay over.
pub(crate) struct PendingWrites(Vec<QueueEntry>);

pub(crate) fn read<R: BlockingRpc, I: BlockingIndexer + RingIndexer>(
    zolana: &Zolana<R, I>,
    records: MemberRecords<'_>,
) -> Result<Vec<MemberOpeningRead>> {
    let label = format!("the member records of {}", records.ring.program_id());
    patiently(label, || zolana.block_on(records.read(zolana.as_async())))
}

pub(crate) fn read_one<R: BlockingRpc, I: BlockingIndexer + RingIndexer>(
    zolana: &Zolana<R, I>,
    records: MemberRecords<'_>,
) -> Result<MemberOpeningRead> {
    let [read] =
        <[_; 1]>::try_from(read(zolana, records)?).map_err(|_| RingError::InvalidRecordOpening)?;
    Ok(read)
}

/// `members` under the newest mirrored root of the curator registry.
pub(crate) fn read_curator(
    ctx: &Context,
    policy: &RingPolicy,
    members: &[Member],
) -> Result<Vec<MemberOpeningRead>> {
    use zolana_ring_indexer::rpc::{GetStorageMemberOpeningsRequest, MAX_RING_MEMBER_PAGE_LIMIT};
    let registry = policy.curator().context("the policy names no curator")?;
    let newest = policy.curator_roots.roots[0];
    ensure!(
        policy.curator_roots.registry == registry && newest.hash != [0; 32],
        "the policy mirrors no roots of curator registry {registry}, run `SyncRoots` for it"
    );
    let mut reads = Vec::with_capacity(members.len());
    for chunk in members.chunks(MAX_RING_MEMBER_PAGE_LIMIT as usize) {
        let response = ctx
            .zolana
            .indexer()
            .get_storage_member_openings(GetStorageMemberOpeningsRequest {
                registry: registry.into(),
                members: chunk.iter().map(|member| Hash(*member.as_bytes())).collect(),
                expected_root: Hash(newest.hash),
            })?;
        ensure!(
            response.openings.len() == chunk.len(),
            "the indexer served {} openings for {} members",
            response.openings.len(),
            chunk.len()
        );
        for (member, opening) in chunk.iter().zip(&response.openings) {
            reads.push(MemberOpeningRead::verify(
                opening,
                &newest.hash,
                member.as_bytes(),
            )?);
        }
    }
    Ok(reads)
}

/// Read again under the newest root while the projection lags the chain.
pub(crate) fn patiently<T>(
    label: impl Display,
    mut read: impl FnMut() -> Result<T, RingError>,
) -> Result<T> {
    wait_for(label, || match read() {
        Ok(value) => Ok(Probe::Ready(value)),
        Err(error) if error.is_projection_lag() => Ok(Probe::Retry(error.into())),
        Err(RingError::MissingMemberRegistry) => bail!(NO_MEMBER_REGISTRY),
        Err(RingError::MissingRingPolicy) => bail!(NO_RING_POLICY),
        Err(error) => Err(error.into()),
    })
}

impl Queued {
    pub fn now(zolana: &Zolana, ring: CustomRing) -> Result<Self> {
        Ok(Self {
            ring,
            tail: queue(zolana, ring)?.tail(),
        })
    }

    pub fn apply(self, zolana: &Zolana, payer: &(dyn Signer + Sync)) -> Result<()> {
        let due = wait_for("the record queue to come due", || {
            let queue = queue(zolana, self.ring)?;
            if queue.head() >= self.tail {
                return Ok(Probe::Ready(false));
            }
            match queue.apply_due(zolana.rpc().get_slot()?) {
                Ok(()) => Ok(Probe::Ready(true)),
                Err(CustomRingError::ApplyNotDue | CustomRingError::ApplyTooSoon) => {
                    Ok(Probe::NotYet)
                }
                Err(error) => Err(RingError::from(error).into()),
            }
        })?;
        if !due {
            return Ok(());
        }
        let applied = Landing {
            operation: RecordApplication::new(self.ring).into(),
            payer,
            signers: &[],
        }
        .settle(zolana);
        match applied {
            Ok(_) => Ok(()),
            // A rival application can land after the due check.
            Err(_) if queue(zolana, self.ring)?.head() >= self.tail => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl PendingWrites {
    /// Read again until the indexer serves the head and tail the chain holds.
    pub(crate) fn read(ctx: &Context) -> Result<Self> {
        wait_for("the indexer to serve the record queue", || {
            let queue = queue(&ctx.zolana, ctx.ring)?;
            let served = ctx
                .zolana
                .indexer()
                .get_ring_record_queue(GetRingRecordQueueRequest {
                    ring_program_id: ctx.ring.program_id().into(),
                })?;
            Ok(match Self::verified(&queue, &served)? {
                Some(pending) => Probe::Ready(pending),
                None => Probe::NotYet,
            })
        })
    }

    /// `None` while the indexer serves another head or tail.
    fn verified(queue: &RecordQueue, served: &GetRingRecordQueueResponse) -> Result<Option<Self>> {
        if served.head != queue.head() || served.tail != queue.tail() {
            return Ok(None);
        }
        let entries: Vec<QueueEntry> = served
            .entries
            .iter()
            .map(|entry| QueueEntry {
                member: entry.member.0,
                mask: entry.mask,
                value: entry.value,
                escrow_key: entry.escrow_key.0,
                mint_policy: entry.mint_policy,
            })
            .collect();
        let chain = entries
            .iter()
            .try_fold(queue.chain_head, |chain, entry| queue_chain(&chain, entry))?;
        ensure!(
            chain == queue.chain_tail(),
            "the indexer serves record queue writes the chain does not hold"
        );
        Ok(Some(Self(entries)))
    }

    /// The applied record with each pending write of `member` laid over it in queue order.
    pub(crate) fn record_after(
        &self,
        member: &Member,
        applied: Option<&MemberRecord>,
    ) -> MemberRecord {
        let unwritten = MemberRecord {
            member: *member.as_bytes(),
            ..MemberRecord::default()
        };
        self.0
            .iter()
            .filter(|entry| entry.member == *member.as_bytes())
            .fold(applied.copied().unwrap_or(unwritten), |record, entry| {
                record.written(entry)
            })
    }

    pub(crate) fn registers(&self, member: &Member) -> bool {
        self.record_after(member, None).escrow_key != [0; 32]
    }
}

pub(crate) fn insert_fee(config: &CustomRingConfig, writer: &Address) -> u64 {
    config.insert_fee_for(writer).unwrap_or(0)
}

pub(crate) fn write_budget(config: &CustomRingConfig, writer: &Address) -> u64 {
    SENDER_FEE_BUDGET.saturating_add(insert_fee(config, writer))
}

pub(crate) fn queue(zolana: &Zolana, ring: CustomRing) -> Result<RecordQueue> {
    Ok(zolana.block_on(ring.require_queue(zolana.as_async()))?)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::atomic::{AtomicU8, Ordering};

    use custom_ring_interface::{
        storage::{Revision, StorageRegistry},
        QueueEntry, RingPolicy,
    };
    use custom_ring_sdk::CustomRing;
    use solana_account::Account;
    use solana_address::Address;
    use spr_client::{AsyncProverClient, ClientError, Rpc, WitnessReader};

    use crate::{Zolana, ZolanaServices};
    use spr_indexer_api::{Base64String, Context as Page, Hash};
    use zolana_ring_client::SealedNullifierKey;
    use zolana_ring_indexer::rpc::{
        GetStorageMemberOpeningsResponse, RingMemberOpening, RingMemberRecordView,
        RingRecordPathView, StorageRootView,
    };
    use zolana_ring_member_registry::{MemberRegistryTree, RecordOpening, RecordStore, RecordTree};

    use super::*;

    pub(crate) fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    /// The ring's records `StorageRegistry`.
    pub(crate) const RECORDS: Address = Address::new_from_array([0x5a; 32]);

    pub(crate) fn tree(entries: &[QueueEntry]) -> MemberRegistryTree {
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply([0; 32], entries).unwrap();
        tree
    }

    /// `sealed` is served only beside a present record.
    pub(crate) struct IndexerAnswer<'a> {
        pub tree: &'a MemberRegistryTree,
        pub member: &'a [u8; 32],
        pub sealed: Option<&'a SealedNullifierKey>,
    }

    impl IndexerAnswer<'_> {
        pub(crate) fn openings(self) -> GetStorageMemberOpeningsResponse {
            let (present, record, path) = match self.tree.opening(self.member).unwrap() {
                RecordOpening::Present { record, path } => (true, record, path),
                RecordOpening::Absent { low, path } => (false, low, path),
            };
            let sealed = self.sealed.filter(|_| present);
            GetStorageMemberOpeningsResponse {
                context: Page::default(),
                root: StorageRootView {
                    root: Hash(self.tree.root().unwrap()),
                    revision: 1,
                    next_index: self.tree.next_index().unwrap(),
                },
                openings: vec![RingMemberOpening {
                    present,
                    record: RingMemberRecordView {
                        mint_policy: Default::default(),
                        member: Hash(record.member),
                        next: Hash(record.next),
                        lists: record.lists,
                        escrow_key: Hash(record.escrow_key),
                        owner_pubkey: None,
                        nullifier_pk: None,
                        eph_pk: sealed.map(|key| Base64String(key.eph_pk.as_bytes().to_vec())),
                        ciphertext: sealed.map(|key| Base64String(key.ciphertext.to_vec())),
                    },
                    path: RingRecordPathView {
                        index: path.index,
                        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
                    },
                }],
            }
        }
    }

    /// Serves the ring policy synced to `tree`, every read after the first to `advanced` when set.
    pub(crate) struct PolicyRpc {
        reads: AtomicU8,
        tree: MemberRegistryTree,
        advanced: Option<MemberRegistryTree>,
    }

    impl PolicyRpc {
        pub(crate) fn of(tree: MemberRegistryTree) -> Self {
            Self {
                reads: AtomicU8::new(0),
                tree,
                advanced: None,
            }
        }

        pub(crate) fn advancing_to(self, advanced: MemberRegistryTree) -> Self {
            Self {
                advanced: Some(advanced),
                ..self
            }
        }

        pub(crate) fn reads(&self) -> u8 {
            self.reads.load(Ordering::Relaxed)
        }
    }

    impl Rpc for PolicyRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            let (expected, bump) =
                Address::find_program_address(&[RingPolicy::SEED], &ring().program_id());
            assert_eq!(address, expected);
            let reads = self.reads.fetch_add(1, Ordering::Relaxed);
            let tree = match &self.advanced {
                Some(advanced) if reads > 0 => advanced,
                _ => &self.tree,
            };
            let mut records = StorageRegistry::new(Address::default(), 0);
            records.roots[0].hash = tree.root().unwrap();
            records.roots[0].revision = Revision::from(u64::from(reads) + 1);
            let mut policy = RingPolicy::new(bump, RECORDS);
            policy.sync(&RECORDS, &records).unwrap();
            Ok(Some(Account {
                lamports: 1,
                data: bytemuck::bytes_of(&*policy).to_vec(),
                owner: ring().program_id(),
                executable: false,
                rent_epoch: 0,
            }))
        }
    }

    pub(crate) fn zolana<I: Rpc + WitnessReader + Send + Sync + 'static>(
        rpc: PolicyRpc,
        indexer: I,
    ) -> Zolana<PolicyRpc, I> {
        ZolanaServices {
            rpc,
            indexer,
            prover: AsyncProverClient::local(),
            ring_prover: AsyncProverClient::local(),
        }
        .connect()
    }
}

#[cfg(test)]
mod tests {
    use spr_indexer_api::{Context as Page, Hash};
    use zolana_ring_indexer::rpc::RingQueueEntryView;
    use zolana_ring_policy::ListId;

    use super::*;

    fn write(member: u8, mask: u64, value: u64) -> QueueEntry {
        QueueEntry {
            mint_policy: Default::default(),
            member: *Member::owner_tag(&[member; 32]).unwrap().as_bytes(),
            mask,
            value,
            escrow_key: [0; 32],
        }
    }

    fn served(queue: &RecordQueue, writes: &[QueueEntry]) -> GetRingRecordQueueResponse {
        GetRingRecordQueueResponse {
            context: Page::default(),
            head: queue.head(),
            tail: queue.tail(),
            chain_head: Hash(queue.chain_head),
            entries: (queue.head()..)
                .zip(writes)
                .map(|(position, write)| RingQueueEntryView {
                    mint_policy: Default::default(),
                    position,
                    member: Hash(write.member),
                    mask: write.mask,
                    value: write.value,
                    escrow_key: Hash(write.escrow_key),
                    slot: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn the_served_queue_must_reproduce_the_chain() {
        let bit = ListId::RingViewing.record_bit();
        let writes = [write(1, bit, bit), write(2, bit, 0)];
        let mut queue = RecordQueue::new(0);
        for write in &writes {
            queue.push(write, 1).unwrap();
        }
        let pending = PendingWrites::verified(&queue, &served(&queue, &writes)).unwrap();
        assert_eq!(pending.map(|pending| pending.0), Some(writes.to_vec()));
        let mut forged = writes;
        forged[1].value = bit;
        assert!(PendingWrites::verified(&queue, &served(&queue, &forged)).is_err());
        assert!(PendingWrites::verified(&queue, &served(&queue, &writes[..1])).is_err());
        let mut lagging = served(&queue, &writes[..1]);
        lagging.tail -= 1;
        assert!(PendingWrites::verified(&queue, &lagging).unwrap().is_none());
    }

    #[test]
    fn pending_writes_lay_over_the_applied_record_in_queue_order() {
        let (viewing, recovery) = (
            ListId::RingViewing.record_bit(),
            ListId::Recovery.record_bit(),
        );
        let member = Member::owner_tag(&[1; 32]).unwrap();
        let applied = MemberRecord {
            member: *member.as_bytes(),
            lists: recovery,
            ..MemberRecord::default()
        };
        let (join, leave) = (write(1, viewing, viewing), write(1, viewing, 0));
        let lists = |writes: Vec<QueueEntry>| {
            PendingWrites(writes)
                .record_after(&member, Some(&applied))
                .lists
        };
        assert_eq!(lists(vec![join]), recovery | viewing);
        assert_eq!(lists(vec![join, leave]), recovery);
        assert_eq!(lists(vec![write(2, viewing, viewing)]), recovery);
        let escrow = ListId::Escrow.record_bit();
        let registration = QueueEntry {
            escrow_key: [7; 32],
            ..write(1, escrow, escrow)
        };
        assert!(PendingWrites(vec![join, registration]).registers(&member));
        assert!(!PendingWrites(vec![join]).registers(&member));
        let other = Member::owner_tag(&[2; 32]).unwrap();
        assert!(!PendingWrites(vec![registration]).registers(&other));
    }
}

/// All nonzero mint settings, authenticated under one complete registry snapshot.
pub(crate) fn mint_policies(
    ctx: &Context,
) -> Result<std::collections::BTreeMap<[u8; 32], zolana_ring_policy::MintPolicy>> {
    use zolana_ring_client::records::RegistryTip;
    use zolana_ring_indexer::rpc::{
        GetRingMemberRecordsRequest, RingMemberOpening, MAX_RING_MEMBER_PAGE_LIMIT,
    };
    let registry = ctx.block(ctx.ring.require_registry(ctx.chain()))?;
    let tip = RegistryTip {
        root: registry.current_root(),
        root_index: registry.history_cursor,
        next_index: u64::from(registry.next_index()),
    };
    let mut result = std::collections::BTreeMap::new();
    let mut index = 1;
    while index < tip.next_index {
        let page = ctx
            .zolana
            .indexer()
            .get_ring_member_records(GetRingMemberRecordsRequest {
                ring_program_id: ctx.ring.program_id().into(),
                expected_root: tip.root.into(),
                expected_next_index: tip.next_index,
                start_index: index,
                limit: MAX_RING_MEMBER_PAGE_LIMIT,
            })?;
        ensure!(
            tip.covers(&page, index),
            "the indexer served an incomplete registry page"
        );
        for row in page.records {
            let member = row.record.member.0;
            let read = MemberOpeningRead::verify(
                &RingMemberOpening {
                    present: true,
                    record: row.record,
                    path: row.path,
                },
                &tip.root,
                &member,
            )?;
            let policy = read.record().expect("verified present record").mint_policy;
            if policy != zolana_ring_policy::MintPolicy::EMPTY {
                result.insert(member, policy);
            }
            index += 1;
        }
    }
    Ok(result)
}

/// Authority writes are applied immediately, in the same batches as list changes.
pub(crate) fn write_mint_policies(
    ctx: &Context,
    desired: &std::collections::BTreeMap<[u8; 32], zolana_ring_policy::MintPolicy>,
) -> Result<()> {
    use custom_ring_sdk::AuthorityListWrite;
    let authority = ctx.funded_authority()?;
    let mut sent = 0;
    let changes: Vec<_> = desired.iter().collect();
    while sent < changes.len() {
        let writes = changes[sent..].iter().try_fold(
            AuthorityListWrite::new(ctx.ring, authority.pubkey()),
            |batch, (member, policy)| {
                batch.with_mint_policy(Member::from_bytes(**member)?, **policy)
            },
        )?;
        let batch = writes
            .batches(queue(&ctx.zolana, ctx.ring)?.pending())
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no mint write batch"))?;
        sent += batch.writes().len();
        ctx.submit(batch, authority, &[])?;
    }
    Ok(())
}
