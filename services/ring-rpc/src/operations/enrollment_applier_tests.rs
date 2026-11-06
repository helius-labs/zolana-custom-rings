use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
};

use async_trait::async_trait;
use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    storage_instruction::tag,
    ApplyRecordsIxData, RING_POLICY, ROOT_HISTORY, STORAGE_PROGRAM_ID,
};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use spr_indexer_api::{Context, Hash};
use tokio::sync::Notify;
use zolana_ring_indexer::{
    rpc::{
        GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
    },
    tracking::GetPendingEnrollmentsResponse,
};
use zolana_ring_member_registry::ApplyProofInputs;

use super::*;
use crate::{
    landing::{ChainOutcome, ChainSubmit, LatestBlockhash, Simulation},
    upstream::RingConfiguration,
};

const RING: Address = Address::new_from_array([1; 32]);
const REGISTRY: Address = Address::new_from_array([2; 32]);
const OTHER_RING: Address = Address::new_from_array([11; 32]);
const OTHER_REGISTRY: Address = Address::new_from_array([12; 32]);
const SLOT: u64 = 1_000;

#[derive(Default)]
struct StubChain {
    slot: AtomicU64,
    accounts: Mutex<HashMap<Address, Account>>,
    proofs: AtomicUsize,
    named: Mutex<Vec<Vec<Address>>>,
    sent: Mutex<Vec<VersionedTransaction>>,
    outcome: Mutex<Option<ChainOutcome>>,
    during_proof: Mutex<Option<DuringProof>>,
    /// A proof for the named registry waits for the notify.
    stalled: Mutex<Option<(Address, Arc<Notify>)>>,
    /// Owners a lagging indexer still lists after their apply.
    stale: Mutex<HashSet<Address>>,
}

type DuringProof = Box<dyn Fn(&StubChain) + Send + Sync>;

fn owner(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

fn stored(owner: Address, data: &[u8]) -> Account {
    Account {
        lamports: 1,
        data: data.to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

impl StubChain {
    fn new() -> Arc<Self> {
        let chain = Self::default();
        chain.slot.store(SLOT, Ordering::Relaxed);
        chain.ring(RING, REGISTRY);
        Arc::new(chain)
    }

    fn ring(&self, ring: Address, registry: Address) {
        let mut policy = RingPolicy::zeroed();
        policy.discriminator = RING_POLICY;
        policy.tracking = registry;
        self.accounts.lock().unwrap().insert(
            CustomRing::new(ring).policy_pda(),
            stored(ring, bytemuck::bytes_of(&policy)),
        );
        self.tracking_of(registry, |_| {});
    }

    fn tracking(&self, write: impl FnOnce(&mut TrackingRegistry)) {
        self.tracking_of(REGISTRY, write);
    }

    fn tracking_of(&self, registry: Address, write: impl FnOnce(&mut TrackingRegistry)) {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts.entry(registry).or_insert_with(|| {
            let mut registry = TrackingRegistry::zeroed();
            registry.discriminator = TrackingRegistry::DISCRIMINATOR;
            registry.next_index = 1u64.to_le_bytes();
            stored(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&registry))
        });
        write(bytemuck::from_bytes_mut(&mut account.data));
    }

    fn enroll(&self, owner: Address, applied: bool) {
        self.enroll_in(REGISTRY, owner, applied);
    }

    fn enroll_in(&self, registry: Address, owner: Address, applied: bool) {
        let mut authorization = TrackingAuthorization::zeroed();
        authorization.discriminator = TrackingAuthorization::DISCRIMINATOR;
        authorization.registry = registry;
        authorization.owner = owner;
        authorization.applied = u8::from(applied);
        self.accounts.lock().unwrap().insert(
            TrackingAuthorization::find_address(&registry, &owner).0,
            stored(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&authorization)),
        );
    }

    /// Writes a new viewing key into the account, the one field a rotation moves.
    fn rotate(&self, owner: Address, viewing: u8) {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .get_mut(&TrackingAuthorization::find_address(&REGISTRY, &owner).0)
            .expect("enrolled");
        let authorization: &mut TrackingAuthorization = bytemuck::from_bytes_mut(&mut account.data);
        authorization.viewing_u = [viewing; 32];
    }

    fn named(&self) -> Vec<Vec<Address>> {
        self.named.lock().unwrap().clone()
    }

    fn landed(&self, outcome: ChainOutcome) {
        *self.outcome.lock().unwrap() = Some(outcome);
    }
}

#[async_trait]
impl ChainSubmit for StubChain {
    async fn account_data(
        &self,
        _address: solana_address::Address,
    ) -> Result<Option<Vec<u8>>, RingRpcError> {
        Ok(None)
    }

    async fn rent_exempt_lamports(&self, _data_len: usize) -> Result<u64, RingRpcError> {
        Ok(0)
    }

    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.slot.load(Ordering::Relaxed))
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        Ok(LatestBlockhash {
            blockhash: solana_hash::Hash::new_from_array([7; 32]),
            last_valid_block_height: u64::MAX,
        })
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(0)
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.sent.lock().unwrap().push(transaction.clone());
        Ok(())
    }

    async fn outcome(&self, _signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        Ok(self.outcome.lock().unwrap().take())
    }

    async fn simulate(&self, _message: &VersionedMessage) -> Result<Simulation, RingRpcError> {
        unreachable!("an applier sends without a simulation")
    }
}

#[async_trait]
impl StorageChain for StubChain {
    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError> {
        Ok(self.accounts.lock().unwrap().get(&address).cloned())
    }

    async fn ring_config(&self, _ring: Address) -> Result<Option<RingConfiguration>, RingRpcError> {
        unreachable!("an applier reads no ring role")
    }

    async fn member_openings(
        &self,
        _request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError> {
        unreachable!("an applier reads no policy leaf")
    }

    async fn apply_inputs(
        &self,
        _request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError> {
        unreachable!("an applier writes no policy leaf")
    }

    async fn prove_apply(
        &self,
        _inputs: &ApplyProofInputs,
        _registry: &StorageRegistry,
    ) -> Result<ApplyRecordsIxData, RingRpcError> {
        unreachable!("an applier writes no policy leaf")
    }

    async fn pending_enrollments(
        &self,
        request: GetPendingEnrollmentsRequest,
    ) -> Result<GetPendingEnrollmentsResponse, RingRpcError> {
        let accounts = self.accounts.lock().unwrap();
        let mut pending: Vec<_> = accounts
            .values()
            .filter_map(|account| TrackingAuthorization::decode(&account.owner, &account.data))
            .filter(|authorization| {
                (authorization.is_pending()
                    || self.stale.lock().unwrap().contains(&authorization.owner))
                    && authorization.registry == request.registry.0
                    && request
                        .after
                        .is_none_or(|after| after.0.to_bytes() < authorization.owner.to_bytes())
            })
            .collect();
        pending.sort_by_key(|authorization| authorization.owner.to_bytes());
        pending.truncate(request.limit as usize);
        let hash = |bytes| Hash(bytes);
        Ok(GetPendingEnrollmentsResponse {
            context: Context::default(),
            next_after: pending
                .last()
                .filter(|_| pending.len() as u64 == request.limit)
                .map(|authorization| authorization.owner.into()),
            enrollments: pending
                .iter()
                .map(|authorization| RingPendingEnrollmentView {
                    owner: authorization.owner.into(),
                    member: hash([0; 32]),
                    nullifier_pk: hash(authorization.nullifier_pk),
                    ct_hash: hash([0; 32]),
                    list_tag: hash(authorization.list_tag),
                })
                .collect(),
        })
    }

    async fn prove_enrollments(
        &self,
        registry: Address,
        owners: &[Address],
    ) -> Result<ProvedEnrollments, RingRpcError> {
        let stall = self
            .stalled
            .lock()
            .unwrap()
            .clone()
            .filter(|(stalled, _)| *stalled == registry);
        if let Some((_, notify)) = stall {
            notify.notified().await;
        }
        self.proofs.fetch_add(1, Ordering::Relaxed);
        self.named.lock().unwrap().push(owners.to_vec());
        let revision = self
            .accounts
            .lock()
            .unwrap()
            .get(&registry)
            .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data))
            .expect("registry")
            .newest()
            .revision;
        if let Some(act) = self.during_proof.lock().unwrap().take() {
            act(self);
        }
        Ok(ProvedEnrollments {
            instruction: Instruction {
                program_id: STORAGE_PROGRAM_ID,
                accounts: vec![AccountMeta::new(registry, false)],
                data: vec![tag::APPLY_ENROLLMENTS],
            },
            revision,
        })
    }
}

fn applier(chain: &Arc<StubChain>) -> EnrollmentApplier {
    EnrollmentApplierParts {
        chain: chain.clone(),
        payer: Keypair::new_from_array([9; 32]),
        rings: vec![RING],
    }
    .applier()
}

/// Settles the sent apply as failed, its accounts stay pending for the next pass.
fn refused(chain: &StubChain) {
    chain.landed(ChainOutcome::Failed {
        reason: String::new(),
    });
}

#[tokio::test]
async fn an_apply_names_pending_accounts_under_the_payer_alone_and_waits_for_its_landing() {
    let chain = StubChain::new();
    chain.enroll(owner(4), false);
    chain.enroll(owner(3), false);
    chain.enroll(owner(5), true);
    let applier = applier(&chain);

    applier.flush().await;
    assert_eq!(chain.named(), [vec![owner(3), owner(4)]]);
    let sent = chain.sent.lock().unwrap().clone();
    let [transaction] = sent.as_slice() else {
        panic!("one apply, {sent:?}");
    };
    assert_eq!(transaction.signatures.len(), 1);
    assert_eq!(
        transaction.message.static_account_keys()[0],
        applier.payer()
    );

    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 1);

    refused(&chain);
    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 2);
}

/// A lagging indexer lists an applied account, the batch fills from the next page without it.
#[tokio::test]
async fn an_account_the_chain_holds_applied_stays_out_of_the_batch() {
    let chain = StubChain::new();
    (1..=APPLY_BATCH as u8 + 1).for_each(|byte| chain.enroll(owner(byte), false));
    chain.enroll(owner(1), true);
    chain.stale.lock().unwrap().insert(owner(1));
    applier(&chain).flush().await;
    let named = chain.named();
    let [batch] = named.as_slice() else {
        panic!("one proof, {named:?}");
    };
    assert_eq!(batch.len(), APPLY_BATCH);
    assert!(!batch.contains(&owner(1)));
    assert!(batch.contains(&owner(APPLY_BATCH as u8 + 1)));
}

/// A rotation of a pending or an applied account moves no root and lists nothing.
#[tokio::test]
async fn a_rotation_neither_stales_a_proof_nor_moves_the_pending_set() {
    let chain = StubChain::new();
    chain.enroll(owner(3), false);
    chain.enroll(owner(4), true);
    *chain.during_proof.lock().unwrap() = Some(Box::new(|chain: &StubChain| {
        chain.rotate(owner(3), 7);
        chain.rotate(owner(4), 7);
    }));
    let applier = applier(&chain);

    applier.flush().await;
    assert_eq!(chain.sent.lock().unwrap().len(), 1);

    refused(&chain);
    chain.rotate(owner(4), 8);
    applier.flush().await;
    assert_eq!(chain.named(), [vec![owner(3)], vec![owner(3)]]);
}

#[tokio::test]
async fn a_root_another_applier_moved_during_the_proof_sends_nothing() {
    let chain = StubChain::new();
    chain.enroll(owner(3), false);
    *chain.during_proof.lock().unwrap() = Some(Box::new(|chain: &StubChain| {
        chain.tracking(|registry| registry.roots[0].revision = Revision::from(1))
    }));
    let applier = applier(&chain);

    applier.flush().await;
    assert!(chain.sent.lock().unwrap().is_empty());

    applier.flush().await;
    assert_eq!(chain.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_full_tree_names_no_account() {
    let chain = StubChain::new();
    chain.tracking(|registry| registry.next_index = TRACKING_CAPACITY.to_le_bytes());
    chain.enroll(owner(3), false);
    applier(&chain).flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 0);
}

/// The program refuses an apply that would evict a root inside its grace.
#[tokio::test]
async fn an_unexpired_oldest_root_waits_without_a_proof_and_applies_once_it_expires() {
    let chain = StubChain::new();
    chain.enroll(owner(3), false);
    chain.tracking(|registry| {
        registry.roots[ROOT_HISTORY - 1].expires_at = (SLOT + 1).to_le_bytes()
    });
    let applier = applier(&chain);
    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 0);

    chain.slot.store(SLOT + 1, Ordering::Relaxed);
    applier.flush().await;
    assert_eq!(chain.sent.lock().unwrap().len(), 1);
}

/// The first ring's proof never returns, the second ring applies beside it on every tick.
#[tokio::test]
async fn a_stalled_ring_never_delays_another_rings_apply() {
    let chain = StubChain::new();
    chain.ring(OTHER_RING, OTHER_REGISTRY);
    chain.enroll(owner(3), false);
    chain.enroll_in(OTHER_REGISTRY, owner(4), false);
    let stall = Arc::new(Notify::new());
    *chain.stalled.lock().unwrap() = Some((REGISTRY, stall.clone()));
    let applier = EnrollmentApplierParts {
        chain: chain.clone(),
        payer: Keypair::new_from_array([9; 32]),
        rings: vec![RING, OTHER_RING],
    }
    .applier();
    let rings = KeyedTasks::new(2);
    let settle = || async {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    };

    applier.spawn_idle(&rings);
    settle().await;
    assert_eq!(chain.named(), [vec![owner(4)]]);

    refused(&chain);
    applier.spawn_idle(&rings);
    settle().await;
    assert_eq!(chain.named(), [vec![owner(4)], vec![owner(4)]]);

    stall.notify_one();
    settle().await;
    assert_eq!(chain.named().last().unwrap(), &[owner(3)]);
    assert_eq!(chain.sent.lock().unwrap().len(), 3);
}
