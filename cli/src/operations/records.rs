//! Member records read while the projection catches up.

use std::fmt::Display;

use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_interface::RingPolicy;
use custom_ring_sdk::{live_registry, AuthorityRecordUpdate, MemberRecords, RingError};
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

/// `members` under the newest root of the live curator registry.
pub(crate) fn read_curator(
    ctx: &Context,
    policy: &RingPolicy,
    members: &[Member],
) -> Result<Vec<MemberOpeningRead>> {
    use zolana_ring_indexer::rpc::{GetStorageMemberOpeningsRequest, MAX_RING_MEMBER_PAGE_LIMIT};
    let registry = policy.curator().context("the policy names no curator")?;
    let newest = ctx.block(live_registry(registry, ctx.chain()))?.newest();
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
pub fn patiently<T>(
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

/// All nonzero mint settings, authenticated under the newest root of the ring's records.
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
    let records = ring_policy.records;
    let tip = StorageTip::newest(records, &ctx.block(live_registry(records, ctx.chain()))?);
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
