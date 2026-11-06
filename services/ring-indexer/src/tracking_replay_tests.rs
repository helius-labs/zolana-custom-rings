use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::Revision,
    storage_instruction::{
        tag, ApplyEnrollmentsIxData, EnrollIxData, EnrollRequest, InitializeTrackingIxData,
    },
    tracking::{
        tracking_chain_start, TrackingAuthorization, TrackingEntry, TrackingRegistry,
        TRACKING_EMPTY_ROOT, TRACKING_QUAD_HEIGHT,
    },
    CustomRingProof, STORAGE_PROGRAM_ID, VIEWING_PUBKEY_TAG,
};
use sea_orm::TransactionTrait;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::Hash;
use zolana_ring_indexer::{
    rpc::RingRecordPathView,
    tracking::{
        GetPendingEnrollmentsRequest, GetTrackingApplyProofInputsRequest,
        GetTrackingOpeningsRequest, GetTrackingRecordPoolRequest, GetTrackingRecordsRequest,
        GetTrackingRecordsResponse, RingTrackingRecordView,
    },
    tree::{OpeningCheck, QuadPathOf, RecordOpening, RecordTree, TrackingRecord},
};
use zolana_ring_member_registry::TrackingTree;

use super::{account, block, replay_indexer, rpc, Chain};
use crate::{
    api,
    block::{BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo},
    indexer::Indexer,
    storage::{self, Enrollment, RingCursor, TrackingState, TrackingStore},
    tests::{database, field},
};

const OWNER: Address = Address::new_from_array([51; 32]);
const NEWEST_SLOT: u64 = 5_000;

struct Ledger {
    indexer: Indexer,
    cursor: RingCursor,
    chain: std::sync::Arc<std::sync::Mutex<Chain>>,
    handle: jsonrpsee::server::ServerHandle,
    registry: Address,
    authorization: Address,
}

fn ix_data(viewing: u8) -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: field(1),
        list_tag: field(2),
        viewing_u: field(viewing),
        eph_u: field(4),
        ciphertext: [5; 64],
    }
}

fn instruction(accounts: Vec<Address>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        data,
        accounts,
        stack_height: Some(1),
    }
}

impl Ledger {
    async fn new() -> Self {
        let creator = Address::new_from_array([50; 32]);
        let ring_id = field(9);
        let (registry, _) = TrackingRegistry::find_address(&creator, &ring_id);
        let (authorization, _) = TrackingAuthorization::find_address(&registry, &OWNER);
        let mut auditor_pubkey = [9; 33];
        auditor_pubkey[0] = VIEWING_PUBKEY_TAG;
        let data = InitializeTrackingIxData {
            ring_id,
            auditor_pubkey,
        };
        let chain = std::sync::Arc::new(std::sync::Mutex::new(Chain {
            blocks: [(NEWEST_SLOT, block(NEWEST_SLOT, vec![]))].into(),
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        let mut ledger = Self {
            indexer: replay_indexer(std::sync::Arc::new(database().await), rpc),
            cursor: RingCursor::new(0),
            chain,
            handle,
            registry,
            authorization,
        };
        let initialize = instruction(
            vec![creator, creator, registry],
            [&[tag::INITIALIZE_TRACKING][..], bytemuck::bytes_of(&data)].concat(),
        );
        ledger.land(1, initialize).await.unwrap();
        ledger
    }

    /// The account as the chain holds it now, whatever slot the replay reached.
    fn hold_account(&self, viewing: u8) {
        let account_image = TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            registry: self.registry,
            owner: OWNER,
            nullifier_pk: field(1),
            list_tag: field(2),
            viewing_u: field(viewing),
            eph_u: field(4),
            ciphertext: [5; 64],
            applied: 0,
        };
        self.chain.lock().unwrap().accounts.insert(
            self.authorization.to_string(),
            account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&account_image)),
        );
    }

    fn enroll(&self, viewing: u8, proof: Option<&CustomRingProof>) -> Instruction {
        let ix = ix_data(viewing);
        let request = EnrollRequest { ix: &ix, proof };
        instruction(
            vec![OWNER, OWNER, self.registry, self.authorization],
            [&[tag::ENROLL][..], &request.encode()].concat(),
        )
    }

    async fn land(&mut self, slot: u64, instruction: Instruction) -> anyhow::Result<()> {
        self.land_all(slot, vec![instruction]).await
    }

    async fn land_all(&mut self, slot: u64, instructions: Vec<Instruction>) -> anyhow::Result<()> {
        let transactions = instructions
            .into_iter()
            .map(|instruction| settled(instruction, vec![]))
            .collect();
        self.land_transactions(slot, transactions).await
    }

    async fn land_transactions(
        &mut self,
        slot: u64,
        transactions: Vec<TransactionInfo>,
    ) -> anyhow::Result<()> {
        let block = BlockInfo {
            metadata: BlockMetadata {
                slot,
                blockhash: Hash(field(slot as u8)),
                ..Default::default()
            },
            transactions,
        };
        let tx = self.indexer.db.begin().await?;
        self.indexer
            .apply_block(&tx, &block, &mut self.cursor)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The tracking entry of the account, the same at every viewing key.
    fn entry(&self) -> TrackingEntry {
        TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            registry: self.registry,
            owner: OWNER,
            nullifier_pk: field(1),
            list_tag: field(2),
            viewing_u: field(3),
            eph_u: field(4),
            ciphertext: [5; 64],
            applied: 0,
        }
        .entry()
        .unwrap()
    }

    /// The apply an honest applier proves at the projected revision.
    async fn apply(&self, tree: &mut TrackingTree, entries: &[TrackingEntry]) -> Instruction {
        self.apply_for(tree, entries, &[self.authorization]).await
    }

    /// The apply of `entries`, each authorization in entry order.
    async fn apply_for(
        &self,
        tree: &mut TrackingTree,
        entries: &[TrackingEntry],
        authorizations: &[Address],
    ) -> Instruction {
        let revision: Revision = self.state().await.account.newest().revision;
        let chain_start = tracking_chain_start(&self.registry, revision).unwrap();
        let applied = tree.clone().apply(chain_start, entries).unwrap();
        *tree = applied.tree;
        let inputs = applied.proof;
        let data = ApplyEnrollmentsIxData {
            revision,
            proof: Zeroable::zeroed(),
            new_root: inputs.new_root,
            new_next_index: inputs.new_next_index.to_le_bytes(),
        };
        instruction(
            [&[self.registry][..], authorizations].concat(),
            [&[tag::APPLY_ENROLLMENTS][..], bytemuck::bytes_of(&data)].concat(),
        )
    }

    /// The chain confirms the projection at `slot`.
    async fn serve(&mut self, slot: u64) {
        let state = self.state().await;
        {
            let mut chain = self.chain.lock().unwrap();
            chain.blocks.insert(slot, block(slot, vec![]));
            chain.accounts.insert(
                self.registry.to_string(),
                account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*state.account)),
            );
        }
        self.cursor.resume(self.indexer.db.as_ref()).await.unwrap();
    }

    fn member(&self) -> [u8; 32] {
        self.entry().member
    }

    fn store(&self) -> TrackingStore<'_, sea_orm::DatabaseConnection> {
        TrackingStore::new(self.indexer.db.as_ref(), self.registry.to_bytes())
    }

    async fn state(&self) -> TrackingState {
        self.store().state().await.unwrap().unwrap()
    }

    async fn enrollment(&self) -> Option<Enrollment> {
        self.enrollment_of(OWNER).await
    }

    async fn enrollment_of(&self, owner: Address) -> Option<Enrollment> {
        self.store().enrollment(&owner.to_bytes()).await.unwrap()
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

#[tokio::test]
async fn a_replayed_enrollment_takes_final_fields_from_the_account() {
    let mut ledger = Ledger::new().await;
    // The account may already hold a later rotation.
    ledger.hold_account(7);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let held = ledger.enrollment().await.unwrap();
    assert!(!held.applied);
    assert_eq!(
        (
            held.nullifier_pk,
            held.list_tag,
            held.eph_u,
            held.ciphertext
        ),
        (field(1), field(2), field(4), [5; 64])
    );
    assert_eq!(held.authorization, ledger.authorization.to_bytes());
    ledger.stop().await;
}

#[tokio::test]
async fn a_rotation_leaves_the_enrollment_the_pending_set_and_the_root_unchanged() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let first = ledger.enrollment().await.unwrap();
    let before = ledger.state().await;
    ledger.land(3, ledger.enroll(6, None)).await.unwrap();
    assert_eq!(ledger.enrollment().await.unwrap(), first);
    assert_eq!(ledger.store().pending(None, 8).await.unwrap(), [first]);
    assert_eq!(ledger.state().await, before);
    ledger.stop().await;
}

#[tokio::test]
async fn a_rotation_moving_a_final_field_stops_the_projection() {
    let mut ledger = enrolled().await;
    let ix = EnrollIxData {
        ciphertext: [6; 64],
        ..ix_data(6)
    };
    let request = EnrollRequest {
        ix: &ix,
        proof: None,
    };
    let rotation = instruction(
        vec![OWNER, OWNER, ledger.registry, ledger.authorization],
        [&[tag::ENROLL][..], &request.encode()].concat(),
    );
    ledger.land(3, rotation).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("rotation refused"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn a_first_enrollment_without_a_proof_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    ledger.land(2, ledger.enroll(3, None)).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("no proof"), "{fault}");
    assert_eq!(ledger.enrollment().await, None);
    ledger.stop().await;
}

#[tokio::test]
async fn an_unreadable_authorization_retries_and_quarantines_nothing() {
    let mut ledger = Ledger::new().await;
    let proof = CustomRingProof::zeroed();
    let error = ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("no tracking authorization"),
        "{error:#}"
    );
    assert!(ledger.state().await.fault.is_none());
    assert_eq!(ledger.enrollment().await, None);
    ledger.stop().await;
}

#[tokio::test]
async fn an_authorization_of_another_owner_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    let foreign = Address::new_from_array([52; 32]);
    let proof = CustomRingProof::zeroed();
    let ix = ix_data(3);
    let request = EnrollRequest {
        ix: &ix,
        proof: Some(&proof),
    };
    let enroll = instruction(
        vec![foreign, foreign, ledger.registry, ledger.authorization],
        [&[tag::ENROLL][..], &request.encode()].concat(),
    );
    ledger.land(2, enroll).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("another owner"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn a_rolled_back_enrollment_leaves_no_row() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let tx = ledger.indexer.db.begin().await.unwrap();
    storage::rollback(&tx, &mut ledger.cursor).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ledger.enrollment().await, None);
    let tx = ledger.indexer.db.begin().await.unwrap();
    storage::rollback(&tx, &mut ledger.cursor).await.unwrap();
    tx.commit().await.unwrap();
    assert!(ledger.store().state().await.unwrap().is_none());
    ledger.stop().await;
}

#[tokio::test]
async fn pending_enrollments_serve_first_enrollments_at_a_confirmed_tip() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    ledger.serve(2).await;
    let request = GetPendingEnrollmentsRequest {
        registry: ledger.registry.into(),
        after: None,
        limit: 1,
    };
    let read = |request| {
        api::pending_enrollments(
            ledger.indexer.db.as_ref(),
            ledger.indexer.rpc.as_ref(),
            request,
        )
    };
    let page = read(request.clone()).await.unwrap();
    let [row] = page.enrollments.as_slice() else {
        panic!("one owner is pending, {:?}", page.enrollments);
    };
    assert_eq!(row.owner, OWNER.into());
    assert_eq!(row.nullifier_pk, Hash(field(1)));
    assert_eq!(page.next_after, Some(OWNER.into()));
    let past = GetPendingEnrollmentsRequest {
        after: page.next_after,
        ..request.clone()
    };
    assert!(read(past).await.unwrap().enrollments.is_empty());
    let unbounded = GetPendingEnrollmentsRequest {
        limit: 0,
        ..request
    };
    assert!(matches!(
        read(unbounded).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    ledger.stop().await;
}

fn settled(
    outer_instruction: Instruction,
    inner_instructions: Vec<Instruction>,
) -> TransactionInfo {
    TransactionInfo {
        signature: Signature::from([1; 64]),
        error: None,
        instruction_groups: vec![InstructionGroup {
            outer_instruction,
            inner_instructions,
        }],
    }
}

fn wire_record(view: &RingTrackingRecordView) -> TrackingRecord {
    TrackingRecord {
        member: view.member.0,
        next: view.next.0,
        nullifier_pk: view.nullifier_pk.0,
        ct_hash: view.ct_hash.0,
        list_tag: view.list_tag.0,
    }
}

fn wire_path(path: &RingRecordPathView) -> QuadPathOf<TRACKING_QUAD_HEIGHT> {
    QuadPathOf {
        index: path.index,
        siblings: core::array::from_fn(|level| {
            path.siblings[level].clone().map(|sibling| sibling.0)
        }),
    }
}

/// An enrollment landed at slot 2, nothing applied.
async fn enrolled() -> Ledger {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    ledger
}

#[tokio::test]
async fn an_applied_enrollment_opens_under_the_program_root_with_its_seal() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry()]).await;
    ledger.land(3, apply).await.unwrap();
    let state = ledger.state().await;
    assert_eq!(state.fault, None);
    let root = tree.root().unwrap();
    assert_eq!(state.account.newest().hash, root);
    assert_eq!(state.account.next_index(), 2);
    assert_eq!(state.account.roots[1].hash, TRACKING_EMPTY_ROOT);
    ledger.serve(3).await;
    let member = ledger.member();
    let (db, rpc) = (ledger.indexer.db.as_ref(), ledger.indexer.rpc.as_ref());
    let registry = ledger.registry.into();
    let absent = field(77);
    let opened = api::tracking_openings(
        db,
        rpc,
        GetTrackingOpeningsRequest {
            registry,
            members: vec![Hash(member), Hash(absent)],
            expected_root: Hash(root),
        },
    )
    .await
    .unwrap();
    let [present, missing] = opened.openings.as_slice() else {
        panic!("two members open twice");
    };
    assert!(present.present && !missing.present);
    let verified = OpeningCheck {
        opening: &RecordOpening::Present {
            record: wire_record(&present.record),
            path: wire_path(&present.path),
        },
        root: &root,
        member: &member,
    }
    .verify()
    .unwrap();
    assert_eq!(verified.map(|record| record.nullifier_pk), Some(field(1)));
    let no_row = OpeningCheck {
        opening: &RecordOpening::Absent {
            low: wire_record(&missing.record),
            path: wire_path(&missing.path),
        },
        root: &root,
        member: &absent,
    }
    .verify()
    .unwrap();
    assert_eq!(no_row, None);
    let seal = present.record.seal.as_ref().unwrap();
    assert_eq!(seal.owner, OWNER.into());
    assert_eq!(seal.ciphertext.0, [5; 64]);
    assert_eq!(seal.eph_pk.0[1..], field(4));
    let page = api::tracking_records(
        db,
        rpc,
        GetTrackingRecordsRequest {
            registry,
            expected_root: Hash(root),
            start_index: 1,
            limit: 16,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].record, present.record);
    assert_eq!(page.next_leaf_index, None);
    let pool = api::tracking_record_pool(
        db,
        rpc,
        GetTrackingRecordPoolRequest {
            registry,
            members: vec![Hash(member)],
            expected_root: Hash(root),
            openings: 4,
        },
    )
    .await
    .unwrap();
    assert_eq!(pool.records[0].record, present.record);
    let pending = api::pending_enrollments(
        db,
        rpc,
        GetPendingEnrollmentsRequest {
            registry,
            after: None,
            limit: 8,
        },
    )
    .await
    .unwrap();
    assert!(pending.enrollments.is_empty());
    ledger.stop().await;
}

/// A rotation on either side of an apply in one block leaves the entry and the leaf as enrolled.
#[tokio::test]
async fn a_rotation_around_an_apply_leaves_the_leaf_and_nothing_pending() {
    for rotation_first in [true, false] {
        let mut ledger = enrolled().await;
        let mut tree = TrackingTree::new().unwrap();
        let apply = ledger.apply(&mut tree, &[ledger.entry()]).await;
        let block = match rotation_first {
            true => vec![ledger.enroll(6, None), apply],
            false => vec![apply, ledger.enroll(6, None)],
        };
        ledger.land_all(3, block).await.unwrap();
        let state = ledger.state().await;
        assert_eq!(state.fault, None);
        assert_eq!(state.account.newest().hash, tree.root().unwrap());
        assert!(ledger.enrollment().await.unwrap().applied);
        assert!(ledger.store().pending(None, 8).await.unwrap().is_empty());
        let leaf = ledger
            .store()
            .tree()
            .record(&ledger.member(), 1)
            .await
            .unwrap()
            .unwrap()
            .record;
        assert_eq!(leaf.nullifier_pk, field(1));
        ledger.stop().await;
    }
}

#[tokio::test]
async fn a_root_off_the_projected_entry_stops_the_projection_and_applies_nothing() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    // The proof names a ciphertext the account never holds.
    let forged = TrackingEntry {
        ct_hash: field(8),
        ..ledger.entry()
    };
    let apply = ledger.apply(&mut tree, &[forged]).await;
    ledger.land(3, apply).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("applied root mismatch"), "{fault}");
    assert!(!ledger.enrollment().await.unwrap().applied);
    ledger.stop().await;
}

#[tokio::test]
async fn a_second_apply_of_one_enrollment_stops_the_projection() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry()]).await;
    ledger.land(3, apply).await.unwrap();
    // The tree refuses a present owner, so the second apply names the current revision by hand.
    let data = ApplyEnrollmentsIxData {
        revision: ledger.state().await.account.newest().revision,
        proof: Zeroable::zeroed(),
        new_root: field(8),
        new_next_index: 3u64.to_le_bytes(),
    };
    let again = instruction(
        vec![ledger.registry, ledger.authorization],
        [&[tag::APPLY_ENROLLMENTS][..], bytemuck::bytes_of(&data)].concat(),
    );
    ledger.land(4, again).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("already applied"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn an_apply_naming_no_enrollment_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry()]).await;
    ledger.land(2, apply).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("names no enrollment"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn a_rolled_back_apply_replays_to_the_same_root() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry()]).await;
    ledger.land(3, apply.clone()).await.unwrap();
    let applied = ledger.state().await;
    let tx = ledger.indexer.db.begin().await.unwrap();
    storage::rollback(&tx, &mut ledger.cursor).await.unwrap();
    tx.commit().await.unwrap();
    let rewound = ledger.state().await;
    assert_eq!(rewound.account.newest().hash, TRACKING_EMPTY_ROOT);
    let member = ledger.member();
    let leaf = ledger.store().tree().record(&member, u64::MAX >> 1).await;
    assert_eq!(leaf.unwrap(), None);
    assert!(!ledger.enrollment().await.unwrap().applied);
    ledger.land(3, apply).await.unwrap();
    assert_eq!(ledger.state().await, applied);
    ledger.stop().await;
}

#[tokio::test]
async fn apply_proof_inputs_reach_the_root_the_program_records() {
    let mut ledger = enrolled().await;
    ledger.serve(2).await;
    let (db, rpc) = (ledger.indexer.db.clone(), ledger.indexer.rpc.clone());
    let registry = ledger.registry;
    let request = |owners: Vec<Address>| GetTrackingApplyProofInputsRequest {
        registry: registry.into(),
        owners: owners.into_iter().map(Into::into).collect(),
    };
    let unknown = request(vec![Address::new_from_array([60; 32])]);
    assert!(matches!(
        api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), unknown).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    let twice = request(vec![OWNER, OWNER]);
    assert!(matches!(
        api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), twice).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    let inputs = api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), request(vec![OWNER]))
        .await
        .unwrap();
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry()]).await;
    assert_eq!(inputs.new_root, Hash(tree.root().unwrap()));
    assert_eq!(inputs.old_root, Hash(TRACKING_EMPTY_ROOT));
    let [write] = inputs.writes.as_slice() else {
        panic!("one owner writes once");
    };
    assert_eq!(write.member, Hash(ledger.member()));
    ledger.land(3, apply).await.unwrap();
    ledger.serve(3).await;
    assert!(matches!(
        api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), request(vec![OWNER])).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    ledger.stop().await;
}

#[tokio::test]
async fn a_registry_off_its_canonical_address_is_not_indexed() {
    let mut ledger = Ledger::new().await;
    let forged = Address::new_from_array([70; 32]);
    let data = InitializeTrackingIxData {
        ring_id: field(9),
        auditor_pubkey: [9; 33],
    };
    let creator = Address::new_from_array([50; 32]);
    let initialize = instruction(
        vec![creator, creator, forged],
        [&[tag::INITIALIZE_TRACKING][..], bytemuck::bytes_of(&data)].concat(),
    );
    ledger.land(2, initialize).await.unwrap();
    let store: TrackingStore<'_, _> =
        TrackingStore::new(ledger.indexer.db.as_ref(), forged.to_bytes());
    assert!(store.state().await.unwrap().is_none());
    ledger.stop().await;
}

#[tokio::test]
async fn a_program_owner_enrolls_through_its_own_cross_program_call() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3);
    let proof = CustomRingProof::zeroed();
    let caller = Instruction {
        program_id: Address::new_from_array([61; 32]),
        data: vec![1],
        accounts: vec![],
        stack_height: Some(1),
    };
    let inner = ledger.enroll(3, Some(&proof));
    ledger
        .land_transactions(2, vec![settled(caller, vec![inner])])
        .await
        .unwrap();
    assert!(ledger.enrollment().await.is_some());
    ledger.stop().await;
}

#[tokio::test]
async fn a_failed_enrollment_leaves_no_row() {
    let mut ledger = Ledger::new().await;
    let proof = CustomRingProof::zeroed();
    let failed = TransactionInfo {
        error: Some("custom program error".into()),
        ..settled(ledger.enroll(3, Some(&proof)), vec![])
    };
    ledger.land_transactions(2, vec![failed]).await.unwrap();
    assert_eq!(ledger.enrollment().await, None);
    ledger.stop().await;
}

/// Serves the scan straight from the indexer's own `getTrackingRecords` handler.
struct Endpoint<'a>(&'a Ledger);

impl zolana_ring_rpc::TrackingSource for Endpoint<'_> {
    async fn root(
        &self,
        _ring: Address,
        _finality: zolana_ring_rpc::Finality,
    ) -> Result<Option<zolana_ring_rpc::TrackingRoot>, spr_client::ClientError> {
        let newest = self.0.state().await.account.newest();
        Ok(Some(zolana_ring_rpc::TrackingRoot {
            registry: self.0.registry,
            root: newest.hash,
            revision: newest.revision.value(),
            next_index: self.0.state().await.account.next_index(),
        }))
    }

    async fn records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, zolana_ring_client::RingIndexerError> {
        let indexer = &self.0.indexer;
        api::tracking_records(indexer.db.as_ref(), indexer.rpc.as_ref(), request)
            .await
            .map_err(|error| spr_client::ClientError::Rpc(error.to_string()).into())
    }
}

/// `owner`'s authorization sealed to `auditor`, as its `Enroll` leaves the account.
fn sealed_authorization(
    registry: Address,
    owner: Address,
    seed: u8,
    auditor: &spr_keypair::X25519Pubkey,
) -> TrackingAuthorization {
    let key = spr_keypair::NullifierKey::from_secret([seed; 31]);
    let mut list_salt = [seed; 32];
    list_salt[0] = 0;
    let sealed = zolana_ring_client::NullifierKeyEnvelope::new(&key, &list_salt, auditor)
        .unwrap()
        .sealed;
    TrackingAuthorization {
        discriminator: TrackingAuthorization::DISCRIMINATOR,
        registry,
        owner,
        nullifier_pk: key.pubkey().unwrap(),
        list_tag: custom_ring_interface::domain::list_tag(&list_salt).unwrap(),
        viewing_u: field(seed),
        eph_u: sealed.eph_pk.u(),
        ciphertext: sealed.ciphertext,
        applied: 0,
    }
}

#[tokio::test]
async fn a_fresh_auditor_scans_the_indexer_endpoint_from_the_first_leaf_and_holds_every_owner() {
    let mut ledger = Ledger::new().await;
    let auditor = spr_keypair::X25519Keypair::new();
    let owners = [
        Address::new_from_array([61; 32]),
        Address::new_from_array([62; 32]),
    ];
    let proof = CustomRingProof::zeroed();
    let mut entries = Vec::new();
    let mut authorizations = Vec::new();
    for (slot, owner) in (2..).zip(owners) {
        let held = sealed_authorization(ledger.registry, owner, slot as u8, &auditor.pubkey());
        let (authorization, _) = TrackingAuthorization::find_address(&ledger.registry, &owner);
        ledger.chain.lock().unwrap().accounts.insert(
            authorization.to_string(),
            account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&held)),
        );
        let ix = EnrollIxData {
            nullifier_pk: held.nullifier_pk,
            list_tag: held.list_tag,
            viewing_u: held.viewing_u,
            eph_u: held.eph_u,
            ciphertext: held.ciphertext,
        };
        let request = EnrollRequest {
            ix: &ix,
            proof: Some(&proof),
        };
        let enroll = instruction(
            vec![owner, owner, ledger.registry, authorization],
            [&[tag::ENROLL][..], &request.encode()].concat(),
        );
        ledger.land(slot, enroll).await.unwrap();
        entries.push(held.entry().unwrap());
        authorizations.push(authorization);
    }
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply_for(&mut tree, &entries, &authorizations).await;
    ledger.land(4, apply).await.unwrap();
    ledger.serve(4).await;

    let held = zolana_ring_rpc::tracking_fixture::fresh_scan(
        Address::new_from_array([60; 32]),
        &auditor,
        &Endpoint(&ledger),
        &owners,
    )
    .await
    .unwrap();
    for (owner, held) in owners.iter().zip(&held) {
        let member = zolana_ring_policy::Member::owner_tag(owner.as_array()).unwrap();
        assert_eq!(held.map(|held| held.member()), Some(*member.as_bytes()));
    }
    ledger.stop().await;
}
