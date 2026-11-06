use std::collections::BTreeSet;

use custom_ring_interface::QUAD_HEIGHT;
use sea_orm::ConnectionTrait;
use spr_indexer_api::Hash;
use zolana_ring_indexer::tree::{
    node_keys, Canopy, IndexedRecord, LoadedTree, MemberRead, MemberRecord, ReadRows, WritableLeaf,
    WrittenRows,
};

use crate::{
    indexer::{fault, from_storage, ApplyError},
    storage::{RegistryStore, StoredLeaf, TreeVersion},
};

pub(crate) struct LoadedRegistry<L = MemberRecord, const H: usize = QUAD_HEIGHT> {
    pub tree: LoadedTree<L, H>,
}

pub(crate) struct TreeRead<L = MemberRecord> {
    pub at: TreeVersion,
    pub records: RecordRead<L>,
    /// Empty leaves past `next_index` the read loads for new records.
    pub inserts: u64,
    pub canopy: Option<Canopy>,
}

pub(crate) enum RecordRead<L = MemberRecord> {
    /// Each member's record, the low record of an absent member.
    Members(BTreeSet<[u8; 32]>),
    Leaves(Vec<IndexedRecord<L>>),
}

impl<L: StoredLeaf> TreeRead<L> {
    /// Reads for applying `entries`, each entry may insert a record.
    pub fn batch<const H: usize>(at: TreeVersion, entries: &[L::Entry]) -> Self
    where
        L: WritableLeaf<H>,
    {
        Self {
            at,
            records: RecordRead::Members(
                entries
                    .iter()
                    .map(|entry| *<L as WritableLeaf<H>>::entry_member(entry))
                    .collect(),
            ),
            inserts: entries.len() as u64,
            canopy: None,
        }
    }

    pub async fn load<C: ConnectionTrait, const H: usize>(
        self,
        store: &RegistryStore<'_, C, L>,
    ) -> anyhow::Result<LoadedRegistry<L, H>> {
        let applied = self.at.version;
        let mut reads = Vec::new();
        let mut leaves = BTreeSet::new();
        match self.records {
            RecordRead::Members(members) => {
                for member in members {
                    let read = match store.record(&member, applied).await? {
                        Some(record) => {
                            leaves.insert(record.index);
                            MemberRead::Present(record)
                        }
                        None => {
                            let low = store.low_record(&member, applied).await?;
                            leaves.insert(low.index);
                            MemberRead::Absent { member, low }
                        }
                    };
                    reads.push(read);
                }
            }
            RecordRead::Leaves(rows) => {
                for row in rows {
                    reads.push(MemberRead::Present(row));
                    leaves.insert(row.index);
                }
            }
        }
        let next_index = self.at.next_index;
        let appended = next_index..(next_index + self.inserts).min(1 << (2 * H));
        let mut keys = node_keys::<H>(leaves.into_iter().chain(appended))?;
        keys.extend(self.canopy.into_iter().flat_map(Canopy::positions));
        let nodes = store.nodes(&keys, applied).await?;
        let rows = ReadRows {
            next_index,
            reads,
            nodes,
        };
        Ok(LoadedRegistry {
            tree: rows.into_tree(),
        })
    }
}

pub(crate) async fn plant_tree<C: ConnectionTrait, L: StoredLeaf, const H: usize>(
    store: &RegistryStore<'_, C, L>,
) -> anyhow::Result<()> {
    let rows = WrittenRows::<L>::fresh::<H>()?;
    let records = rows.records.values().copied().collect::<Vec<_>>();
    store.save_records(&records, 0).await?;
    store.save_nodes(&rows.nodes, 0).await
}

/// A proven batch, its rows save only once it reaches the root the program recorded.
#[must_use]
pub(crate) struct AppliedBatch<'a, L: WritableLeaf<H>, const H: usize> {
    pub at: TreeVersion,
    pub chain_start: [u8; 32],
    pub entries: &'a [L::Entry],
    pub new_root: [u8; 32],
    pub new_next_index: u64,
    pub revision: u64,
}

impl<L: StoredLeaf + WritableLeaf<H>, const H: usize> AppliedBatch<'_, L, H>
where
    L::Entry: Sync,
    L::WriteProof: Send,
{
    pub async fn save<C: ConnectionTrait>(
        self,
        store: &RegistryStore<'_, C, L>,
    ) -> Result<(), ApplyError> {
        let loaded: LoadedRegistry<L, H> = TreeRead::batch::<H>(self.at, self.entries)
            .load(store)
            .await
            .map_err(from_storage)?;
        let batch = loaded
            .tree
            .apply_batch(self.chain_start, self.entries)
            .map_err(|error| fault(format!("writes do not apply ({error})")))?;
        let recorded_next_index = self.new_next_index;
        if batch.inputs.new_root != self.new_root
            || batch.inputs.new_next_index != recorded_next_index
        {
            return Err(fault(format!(
                "applied root mismatch at revision {}, projected {} at {}, program {} at {}",
                self.revision,
                Hash(batch.inputs.new_root),
                batch.inputs.new_next_index,
                Hash(self.new_root),
                recorded_next_index
            )));
        }
        let records = batch.rows.records.values().copied().collect::<Vec<_>>();
        store.save_records(&records, self.revision).await?;
        store.save_nodes(&batch.rows.nodes, self.revision).await?;
        Ok(())
    }
}
