use custom_ring_interface::{
    domain,
    key_catalog::{RingCircuit, TransferSpend},
    RingRail,
};
use serde_json::json;
use spr_interface::N_PUBLIC_SLOTS;
use zolana_ring_policy::{ListId, SourceMap};

use super::{super::transfer_key, *};

const OWNER: [u8; 32] = [3; 32];
const SALT: [u8; 32] = [4; 32];
const CURATOR: [u8; 32] = [7; 32];

fn row(list_salt: &[u8; 32]) -> TrackingRecord {
    TrackingRecord {
        member: OWNER,
        next: [0; 32],
        nullifier_pk: [5; 32],
        ct_hash: [0; 32],
        list_tag: domain::list_tag(list_salt).unwrap(),
    }
}

fn known(list_salt: [u8; 32]) -> KnownSalts {
    KnownSalts::new(vec![SubjectListSalt {
        member: OWNER,
        list_salt,
    }])
}

fn gates(curated: bool) -> SourceGates {
    let registry = if curated { CURATOR } else { [0; 32] };
    SourceGates::of(
        &SourceMap::new(&[(ListId::Block, [0; 32]), (ListId::PrivateBlock, registry)]).unwrap(),
    )
}

fn salted_query() -> OwnerQuery {
    OwnerQuery {
        member: OWNER,
        tracking: 2,
        salted: known(SALT).salted_key(&OWNER, Some(&row(&SALT))).unwrap(),
    }
}

#[test]
fn an_enrolled_owner_with_no_salt_is_refused_by_name() {
    let refused = KnownSalts::default().salted_key(&OWNER, Some(&row(&SALT)));
    assert!(matches!(refused, Err(RingError::ListSaltUnknown { member }) if member == OWNER));
    let zero = known([0; 32]).salted_key(&OWNER, Some(&row(&SALT)));
    assert!(matches!(zero, Err(RingError::ListSaltUnknown { .. })));
}

#[test]
fn a_salt_of_another_list_tag_is_refused_by_name() {
    let refused = known([9; 32]).salted_key(&OWNER, Some(&row(&SALT)));
    assert!(matches!(refused, Err(RingError::ListSaltMismatch { .. })));
}

#[test]
fn a_subject_with_no_row_reads_no_salted_list() {
    assert!(KnownSalts::default()
        .salted_key(&OWNER, None)
        .unwrap()
        .is_none());
    let mut plan = RecordPlan::new(gates(false));
    let entry = plan.owner(OwnerQuery {
        member: OWNER,
        tracking: 1,
        salted: None,
    });
    assert_eq!(entry.list_salt, [0; 32]);
    assert_eq!(plan.own.len(), 1);
    assert_eq!(plan.lists(&OWNER, |_| 1, |_| 0).salted, 0);
}

#[test]
fn an_own_salted_source_opens_a_row_beside_the_public_one() {
    let mut plan = RecordPlan::new(gates(false));
    let entry = plan.owner(salted_query());
    let key = Member::salted(&Member::from_bytes(OWNER).unwrap(), &SALT).unwrap();
    assert_eq!(plan.own.opened(), [OWNER, *key.as_bytes()]);
    assert_eq!(plan.curator.len(), 0);
    assert_eq!((entry.entry.own, entry.own_salted), (0, 1));
    assert_eq!((entry.tracking, entry.list_salt), (2, SALT));
    let block = ListId::PrivateBlock.record_bit();
    let own = |member: &[u8; 32]| if member == key.as_bytes() { block } else { 0 };
    assert_eq!(plan.lists(&OWNER, own, |_| 0).salted, block);
}

#[test]
fn a_curated_salted_source_reads_only_its_key_in_the_curator_pool() {
    let mut plan = RecordPlan::new(gates(true));
    let entry = plan.owner(salted_query());
    let key = Member::salted(&Member::from_bytes(OWNER).unwrap(), &SALT).unwrap();
    assert_eq!(plan.own.opened(), [OWNER]);
    assert_eq!(plan.curator.opened(), [*key.as_bytes()]);
    assert_eq!(entry.own_salted, 0);
    assert_eq!(entry.curator_salted, [0]);
    let block = ListId::PrivateBlock.record_bit();
    let curator = |member: &[u8; 32]| if member == key.as_bytes() { block } else { 0 };
    assert_eq!(plan.lists(&OWNER, |_| block, curator).salted, block);
    assert_eq!(plan.lists(&OWNER, |_| block, |_| 0).salted, 0);
}

#[test]
fn an_owner_entry_carries_the_go_field_names() {
    let mut plan = RecordPlan::new(gates(true));
    let entry = serde_json::to_value(plan.owner(salted_query())).unwrap();
    let mut keys: Vec<_> = entry.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        json!(keys),
        json!([
            "curator",
            "curatorSalted",
            "listSalt",
            "own",
            "ownSalted",
            "tracking"
        ])
    );
}

#[test]
fn a_salted_row_past_a_narrow_pool_takes_the_wide_key() {
    let spend = |own: usize| TransferSpend {
        format: custom_ring_interface::DisclosureFormat::Standard,
        rail: RingRail::Confidential,
        inputs: 1,
        outputs: 2,
        spends_default_ring: false,
        legs: 0,
        owners: 1,
        pools: RecordPools {
            own,
            ..RecordPools::default()
        },
        wide: false,
    };
    let narrow = RingCircuit::transfer(spend(1)).unwrap();
    let width = narrow.record_pools().unwrap().own;
    let fits = transfer_key(spend(width)).unwrap();
    assert_eq!((fits.circuit, fits.wide), (narrow, false));
    assert!(transfer_key(spend(width + 1)).unwrap().wide);
    assert!(transfer_key(spend(usize::MAX)).is_none());
}

#[test]
fn output_and_settlement_subjects_fit_the_wide_record_pools() {
    let gates = SourceGates::of(
        &SourceMap::new(&[
            (ListId::Block, CURATOR),
            (ListId::PrivateBlock, [0; 32]),
            (ListId::PrivateAllow, CURATOR),
        ])
        .unwrap(),
    );
    let mut plan = RecordPlan::new(gates);
    let mut tracking = PoolSubjects::default();
    let member = |index: usize| {
        let mut member = [0; 32];
        member[31] = 0x10 + index as u8;
        member
    };
    for owner in (0..1 + 8 + 31).map(member) {
        let key = Member::salted(&Member::from_bytes(owner).unwrap(), &SALT).unwrap();
        plan.owner(OwnerQuery {
            member: owner,
            tracking: tracking.index(Some(owner)),
            salted: Some(SaltedKey {
                list_salt: SALT,
                key: *key.as_bytes(),
            }),
        });
    }
    let asset = |index: usize| [0xc0 + index as u8; 32];
    let withdrawn = |leg: usize| asset(8 + leg % N_PUBLIC_SLOTS);
    for slot in 0..8 {
        plan.asset(asset(slot));
    }
    for leg in 0..31 {
        plan.asset(withdrawn(leg));
    }
    for slot in 0..N_PUBLIC_SLOTS {
        plan.public_asset(withdrawn(slot));
    }
    plan.asset(asset(0));
    let spend = TransferSpend {
        format: custom_ring_interface::DisclosureFormat::Standard,
        rail: RingRail::Confidential,
        inputs: 1,
        outputs: 8,
        spends_default_ring: false,
        legs: 31,
        owners: 1,
        pools: plan.pools(&tracking),
        wide: false,
    };
    let keyed = transfer_key(spend).unwrap();
    assert!(keyed.wide);
    let capacity = keyed.circuit.record_pools().unwrap();
    assert!(spend.pools.own <= capacity.own);
    assert!(spend.pools.curator <= capacity.curator);
    assert_eq!(
        spend.pools,
        RecordPools {
            own: 91,
            curator: 91,
            tracking: 40
        }
    );
}
