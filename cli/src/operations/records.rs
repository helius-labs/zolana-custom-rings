//! Member records read while the projection catches up.

use std::fmt::Display;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::RingPolicy;
use custom_ring_sdk::{AuthorityRecordUpdate, MemberRecords, RingError};
use solana_signer::Signer;
use spr_client::{BlockingIndexer, BlockingRpc};
use spr_indexer_api::Hash;
use zolana_ring_client::{records::MemberOpeningRead, RingIndexer};
use zolana_ring_policy::Member;

use crate::{wait_for, Context, Probe, Zolana};

pub const NO_RING_POLICY: &str =
    "the ring has no ring policy, its authority must run `zolana-ring init` first";

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
        let response =
            ctx.zolana
                .indexer()
                .get_storage_member_openings(GetStorageMemberOpeningsRequest {
                    registry: registry.into(),
                    members: chunk
                        .iter()
                        .map(|member| Hash(*member.as_bytes()))
                        .collect(),
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
        Err(RingError::MissingRingPolicy) => bail!(NO_RING_POLICY),
        Err(error) => Err(error.into()),
    })
}

/// All nonzero mint settings, authenticated under the newest mirrored root of the ring's records.
pub(crate) fn mint_policies(
    ctx: &Context,
) -> Result<std::collections::BTreeMap<[u8; 32], zolana_ring_policy::MintPolicy>> {
    let label = format!("the mint policies of {}", ctx.ring.program_id());
    patiently(label, || read_mint_policies(ctx))
}

fn read_mint_policies(
    ctx: &Context,
) -> Result<std::collections::BTreeMap<[u8; 32], zolana_ring_policy::MintPolicy>, RingError> {
    use zolana_ring_client::records::StorageTip;
    use zolana_ring_indexer::rpc::{
        GetStorageMemberRecordsRequest, RingMemberOpening, MAX_RING_MEMBER_PAGE_LIMIT,
    };
    let ring_policy = ctx.block(ctx.ring.require_policy(ctx.chain()))?;
    let tip = StorageTip::mirrored(&ring_policy).ok_or(RingError::UnsyncedRoots {
        registry: ring_policy.records,
    })?;
    let mut result = std::collections::BTreeMap::new();
    let mut start = Some(1);
    while let Some(index) = start {
        let page =
            ctx.zolana
                .indexer()
                .get_storage_member_records(GetStorageMemberRecordsRequest {
                    registry: tip.registry.into(),
                    expected_root: Hash(tip.root),
                    start_index: index,
                    limit: MAX_RING_MEMBER_PAGE_LIMIT,
                })?;
        start = tip.next_page(&page, index)?;
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
            let policy = read
                .record()
                .ok_or(RingError::InvalidRecordOpening)?
                .mint_policy;
            if policy != zolana_ring_policy::MintPolicy::EMPTY {
                result.insert(member, policy);
            }
        }
    }
    Ok(result)
}

/// One authority update carries every mint of `desired`.
pub(crate) fn write_mint_policies(
    ctx: &Context,
    desired: &std::collections::BTreeMap<[u8; 32], zolana_ring_policy::MintPolicy>,
) -> Result<()> {
    if desired.is_empty() {
        return Ok(());
    }
    let authority = ctx.authority()?;
    let update = desired.iter().try_fold(
        AuthorityRecordUpdate::new(ctx.record_update_target()?, authority.pubkey()),
        |update, (member, policy)| {
            Ok::<_, anyhow::Error>(update.with_mint_policy(Member::from_bytes(*member)?, *policy))
        },
    )?;
    ctx.ring_rpc()
        .apply_record_update(update.sign(authority)?)?;
    Ok(())
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
