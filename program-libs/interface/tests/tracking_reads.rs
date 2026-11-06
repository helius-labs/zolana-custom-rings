use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, Root, StorageRegistry},
    tracking::TrackingRegistry,
    CustomRingError, LiveRoots, NewRing, PolicyUpdate, RingMode, RingPolicy, RingRoles, RootRead,
    SourceSlot, N_SOURCE_SLOTS,
};
use solana_address::Address;
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, Subject};

fn key(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

fn ring() -> Box<RingPolicy> {
    NewRing {
        bump: 254,
        mode: RingMode::Confidential,
        roles: RingRoles {
            admin: key(1),
            policy: key(2),
            pauser: key(3),
            cosign_admin: key(4),
        },
        auditor_pubkey: [4; 33],
        created_slot: 0,
        records: Address::default(),
        tracking: key(9),
    }
    .account()
}

fn tracking_at(revisions: &[u64]) -> TrackingRegistry {
    let mut registry = TrackingRegistry::zeroed();
    for (slot, revision) in revisions.iter().enumerate() {
        registry.roots[slot] = Root {
            hash: [*revision as u8 + 1; 32],
            revision: Revision::from(*revision),
            expires_at: 100u64.to_le_bytes(),
        };
    }
    registry
}

fn source(paired: Address, floor: u64) -> StorageRegistry {
    let mut source = StorageRegistry::zeroed();
    source.tracking_registry = paired;
    source.tracking_floor = Revision::from(floor);
    source
}

fn read(
    tracking: &TrackingRegistry,
    tracking_floor: u64,
    revision: u64,
) -> Result<[u8; 32], CustomRingError> {
    LiveRoots {
        own: None,
        curator: None,
        tracking,
        tracking_floor: Revision::from(tracking_floor),
        slot: 1,
    }
    .tracking(Revision::from(revision))
}

#[test]
fn a_served_root_below_the_floor_is_refused() {
    let tracking = tracking_at(&[5, 4]);
    assert_eq!(read(&tracking, 5, 5), Ok([6; 32]));
    assert_eq!(
        read(&tracking, 5, 4),
        Err(CustomRingError::TrackingRootBelowFloor)
    );
}

#[test]
fn a_zero_floor_keeps_the_tracking_grace() {
    let tracking = tracking_at(&[5, 4]);
    assert_eq!(read(&tracking, 0, 4), Ok([5; 32]));
}

fn salted_ring(curator: Address) -> RingPolicy {
    let mut ring = *ring();
    ring.records = key(5);
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::PrivateBlock.slot()] = SourceSlot {
        list_id: ListId::PrivateBlock as u8,
        registry: curator,
    };
    ring.set_policy(PolicyUpdate {
        sources,
        rules: RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::PrivateBlock))
            .build()
            .encode(),
        slot: 5,
    })
    .unwrap();
    ring
}

#[test]
fn a_source_serving_a_salted_list_pins_the_tracking_registry() {
    let other = CustomRingError::SaltedSourceOtherTracking;
    for (ring, serving) in [
        (salted_ring(Address::default()), key(5)),
        (salted_ring(key(7)), key(7)),
    ] {
        assert_eq!(ring.check_source_pair(&serving, &source(key(9), 0)), Ok(()));
        for unpaired in [key(8), Address::default()] {
            assert_eq!(
                ring.check_source_pair(&serving, &source(unpaired, 0)),
                Err(other)
            );
        }
    }
}

fn public_ring(curator: Address) -> RingPolicy {
    let mut ring = *ring();
    ring.records = key(5);
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::Block.slot()] = SourceSlot {
        list_id: ListId::Block as u8,
        registry: curator,
    };
    ring.set_policy(PolicyUpdate {
        sources,
        rules: RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Block))
            .build()
            .encode(),
        slot: 5,
    })
    .unwrap();
    ring
}

#[test]
fn a_curated_public_ring_reads_a_source_pinned_to_another_registry() {
    let ring = public_ring(key(7));
    for pin in [Address::default(), key(8), key(9)] {
        assert_eq!(ring.check_source_pair(&key(7), &source(pin, 0)), Ok(()));
    }
}

#[test]
fn a_public_read_answers_to_no_floor_of_its_source() {
    let foreign = source(key(8), 100);
    assert_eq!(
        public_ring(key(7)).tracking_floor(&key(7), &foreign),
        Revision::from(0)
    );
    let own = source(key(9), 100);
    assert_eq!(
        public_ring(Address::default()).tracking_floor(&key(5), &own),
        Revision::from(0)
    );
}

#[test]
fn a_salted_read_answers_to_its_source_floor_and_no_other() {
    let ring = salted_ring(key(7));
    let source_floor = source(key(9), 100);
    assert_eq!(
        ring.tracking_floor(&key(7), &source_floor),
        Revision::from(100)
    );
    assert_eq!(
        ring.tracking_floor(&key(5), &source_floor),
        Revision::from(0)
    );
    assert_eq!(
        salted_ring(Address::default()).tracking_floor(&key(5), &source_floor),
        Revision::from(100)
    );
}

#[test]
fn the_salted_set_reads_the_slots_and_matches_the_source_map() {
    let mut ring = salted_ring(Address::default());
    assert_eq!(ring.salted(), ListSet::single(ListId::PrivateBlock));
    assert_eq!(ring.salted(), ring.source_map().unwrap().salted());
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::Block.slot()].list_id = ListId::Block as u8;
    ring.set_policy(PolicyUpdate {
        sources,
        rules: RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Block))
            .build()
            .encode(),
        slot: 6,
    })
    .unwrap();
    assert_eq!(ring.salted(), ListSet::EMPTY);
    assert_eq!(ring.source_map().unwrap().salted(), ListSet::EMPTY);
}

#[test]
fn a_transfer_reads_the_own_and_curator_roots_before_the_pinned_tracking_registry() {
    let ring = salted_ring(key(7));
    assert_eq!(
        ring.root_registries(RootRead::Policy).collect::<Vec<_>>(),
        vec![key(5), key(7), key(9)]
    );
    assert_eq!(
        ring.root_registries(RootRead::None).collect::<Vec<_>>(),
        vec![key(9)]
    );
}

#[test]
fn the_salted_registries_name_the_source_of_each_salted_list() {
    assert_eq!(salted_ring(key(9)).salted_registries(), vec![key(9)]);
}
