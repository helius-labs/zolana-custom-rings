use std::ops::Range;

use custom_ring_interface::{
    tagged_x25519,
    tracking::{tracking_chain_start, TrackingRegistry, TRACKING_QUAD_HEIGHT},
    APPLY_BATCH,
};
use sea_orm::{ConnectionTrait, DatabaseConnection};
use solana_address::Address;
use spr_indexer_api::{Base64String, Hash};
use zolana_ring_indexer::{
    tracking::{
        GetPendingEnrollmentsRequest, GetPendingEnrollmentsResponse,
        GetTrackingApplyProofInputsRequest, GetTrackingApplyProofInputsResponse,
        GetTrackingOpeningsRequest, GetTrackingOpeningsResponse, GetTrackingRecordPoolRequest,
        GetTrackingRecordPoolResponse, GetTrackingRecordsRequest, GetTrackingRecordsResponse,
        RingIndexedTrackingRecordView, RingPendingEnrollmentView, RingTrackingOpening,
        RingTrackingRecordView, RingTrackingSealView, RingTrackingWriteView,
    },
    tree::{Canopy, TrackingRecord, TrackingWriteProofInput},
};

use super::{
    check_members, check_openings, check_page_limit, internal, path_view, storage_root_view,
    validation, ChainSource, LeafPage, OpenedLeaf, Served, Snapshot,
};
use crate::{
    error::RingApiError,
    member_registry::{LoadedRegistry, TreeRead},
    storage::{Enrollment, RegistryState, StorageRoot, TrackingStore},
};

type TrackingSnapshot = Snapshot<RegistryState<TrackingRegistry>>;
type LoadedTracking = LoadedRegistry<TrackingRecord, TRACKING_QUAD_HEIGHT>;

pub(crate) async fn tracking_openings(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetTrackingOpeningsRequest,
) -> Result<GetTrackingOpeningsResponse, RingApiError> {
    check_members(&request.members)?;
    let read = TrackingSnapshot::registry(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let loaded: LoadedTracking = read.load(&request.members, None).await?;
    let store = read.snapshot.store();
    let mut openings = Vec::with_capacity(request.members.len());
    for member in &request.members {
        let opened = loaded.opening(&read.root.root, &member.0)?;
        openings.push(RingTrackingOpening {
            present: opened.present,
            record: sealed_view(&store, &opened.record).await?,
            path: opened.path,
        });
    }
    let root = read.root;
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
    Ok(GetTrackingOpeningsResponse {
        context,
        root: storage_root_view(&root),
        openings,
    })
}

/// Every leaf carries the seal its authorization retains.
pub(crate) async fn tracking_records(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetTrackingRecordsRequest,
) -> Result<GetTrackingRecordsResponse, RingApiError> {
    check_page_limit(request.limit)?;
    let read = TrackingSnapshot::registry(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let root = read.root;
    if !request.starts_within(root.next_index) {
        return Err(validation("invalid tracking page start"));
    }
    let leaves: Range<u64> = request.start_index
        ..request
            .start_index
            .saturating_add(request.limit)
            .min(root.next_index);
    let end = leaves.end;
    let store = read.snapshot.store();
    let opened = LeafPage {
        store: store.tree(),
        root: &root.root,
        at: root.tree(),
        leaves,
    }
    .read::<TRACKING_QUAD_HEIGHT>()
    .await?;
    let records = indexed_views(&store, opened).await?;
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
    Ok(GetTrackingRecordsResponse {
        context,
        root: storage_root_view(&root),
        records,
        next_leaf_index: (end < root.next_index).then_some(end),
    })
}

pub(crate) async fn tracking_record_pool(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetTrackingRecordPoolRequest,
) -> Result<GetTrackingRecordPoolResponse, RingApiError> {
    check_members(&request.members)?;
    check_openings(&request.members, request.openings, |pools| pools.tracking)?;
    let canopy = Canopy::covering_tracking(request.openings as usize).map_err(validation)?;
    let read = TrackingSnapshot::registry(db, &request.registry)
        .await?
        .at_root(&request.expected_root.0)
        .await?;
    let loaded: LoadedTracking = read.load(&request.members, Some(canopy)).await?;
    let pool = loaded.pool(&read.root.root, &request.members, canopy)?;
    let records = indexed_views(&read.snapshot.store(), pool.records).await?;
    let root = read.root;
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
    Ok(GetTrackingRecordPoolResponse {
        context,
        root: storage_root_view(&root),
        records,
        canopy: pool.canopy,
        subjects: pool.subjects,
    })
}

pub(crate) async fn pending_enrollments(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetPendingEnrollmentsRequest,
) -> Result<GetPendingEnrollmentsResponse, RingApiError> {
    check_page_limit(request.limit)?;
    let snapshot = TrackingSnapshot::registry(db, &request.registry).await?;
    let after = request.after.map(|owner| owner.0.to_bytes());
    let rows = snapshot
        .store()
        .pending(after.as_ref(), request.limit)
        .await
        .map_err(internal)?;
    let context = snapshot.confirm(chain, Served::Tip).await?;
    let next_after = rows
        .last()
        .filter(|_| rows.len() as u64 == request.limit)
        .map(|row| Address::new_from_array(row.owner).into());
    Ok(GetPendingEnrollmentsResponse {
        context,
        enrollments: rows.iter().map(pending_view).collect(),
        next_after,
    })
}

/// The owners apply from the current root, as the next `ApplyEnrollments` names them.
pub(crate) async fn tracking_apply_proof_inputs(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetTrackingApplyProofInputsRequest,
) -> Result<GetTrackingApplyProofInputsResponse, RingApiError> {
    if !(1..=APPLY_BATCH).contains(&request.owners.len()) {
        return Err(validation("invalid enrollment count"));
    }
    let snapshot = TrackingSnapshot::registry(db, &request.registry).await?;
    let root = StorageRoot::current(&*snapshot.state.account);
    let store = snapshot.store();
    let mut entries = Vec::with_capacity(request.owners.len());
    for (position, owner) in request.owners.iter().enumerate() {
        if request.owners[..position].contains(owner) {
            return Err(validation("an apply names an owner twice"));
        }
        let held = store
            .enrollment(&owner.0.to_bytes())
            .await
            .map_err(internal)?
            .ok_or_else(|| validation("an apply names no enrollment"))?;
        let entry = held
            .account(snapshot.state.registry)
            .apply()
            .map_err(validation)?;
        entries.push(entry);
    }
    let chain_start =
        tracking_chain_start(&request.registry.0, root.revision.into()).map_err(internal)?;
    let loaded: LoadedTracking = TreeRead::batch::<TRACKING_QUAD_HEIGHT>(root.tree(), &entries)
        .load(store.tree())
        .await
        .map_err(internal)?;
    let inputs = loaded
        .tree
        .apply_batch(chain_start, &entries)
        .map_err(internal)?
        .inputs;
    if inputs.old_root != root.root {
        return Err(internal("the loaded tree does not reach the current root"));
    }
    let context = snapshot.confirm(chain, Served::Current(&root)).await?;
    Ok(GetTrackingApplyProofInputsResponse {
        context,
        revision: root.revision,
        old_root: Hash(inputs.old_root),
        new_root: Hash(inputs.new_root),
        old_next_index: inputs.old_next_index,
        new_next_index: inputs.new_next_index,
        chain_start: Hash(inputs.chain_start),
        chain_end: Hash(inputs.chain_end),
        writes: inputs.writes.iter().map(write_view).collect(),
    })
}

async fn indexed_views<C: ConnectionTrait>(
    store: &TrackingStore<'_, C>,
    leaves: Vec<OpenedLeaf<TrackingRecord>>,
) -> Result<Vec<RingIndexedTrackingRecordView>, RingApiError> {
    let mut views = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        views.push(RingIndexedTrackingRecordView {
            record: sealed_view(store, &leaf.record).await?,
            path: leaf.path,
        });
    }
    Ok(views)
}

/// Serves a seal only under the ciphertext hash its leaf binds.
async fn sealed_view<C: ConnectionTrait>(
    store: &TrackingStore<'_, C>,
    record: &TrackingRecord,
) -> Result<RingTrackingRecordView, RingApiError> {
    if record.member == [0; 32] {
        return Ok(record_view(record));
    }
    let held = store
        .enrollment_of(&record.member)
        .await
        .map_err(internal)?
        .ok_or_else(|| internal("a tracking leaf has no enrollment"))?;
    if held.ct_hash != record.ct_hash {
        return Err(internal("a stored seal disagrees with its leaf"));
    }
    Ok(RingTrackingRecordView {
        seal: Some(RingTrackingSealView {
            owner: Address::new_from_array(held.owner).into(),
            eph_pk: Base64String(tagged_x25519(&held.eph_u).to_vec()),
            ciphertext: Base64String(held.ciphertext.to_vec()),
        }),
        ..record_view(record)
    })
}

fn record_view(record: &TrackingRecord) -> RingTrackingRecordView {
    RingTrackingRecordView {
        member: Hash(record.member),
        next: Hash(record.next),
        nullifier_pk: Hash(record.nullifier_pk),
        ct_hash: Hash(record.ct_hash),
        list_tag: Hash(record.list_tag),
        seal: None,
    }
}

fn write_view(write: &TrackingWriteProofInput) -> RingTrackingWriteView {
    RingTrackingWriteView {
        member: Hash(write.entry.member),
        nullifier_pk: Hash(write.entry.nullifier_pk),
        ct_hash: Hash(write.entry.ct_hash),
        list_tag: Hash(write.entry.list_tag),
        slot: path_view(write.slot.index, &write.slot.siblings),
        low: record_view(&write.low),
        low_path: path_view(write.low_path.index, &write.low_path.siblings),
    }
}

fn pending_view(row: &Enrollment) -> RingPendingEnrollmentView {
    RingPendingEnrollmentView {
        owner: Address::new_from_array(row.owner).into(),
        member: Hash(row.member),
        nullifier_pk: Hash(row.nullifier_pk),
        ct_hash: Hash(row.ct_hash),
        list_tag: Hash(row.list_tag),
    }
}
