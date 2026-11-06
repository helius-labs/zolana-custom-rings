use bytemuck::Zeroable;
use custom_ring_interface::{
    domain,
    owner_grant::OwnerGrant,
    storage::{RegistryId, Revision, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{
        AssetWrite, EnrollIxData, EnrollRequest, InitializeIxData, InitializeTrackingIxData,
        OwnerGrantIxData, StorageUpdateIxData,
    },
    tracking::{
        tracking_chain_start, FirstEnrollment, TrackingAuthorization, TrackingEntry,
        TrackingRegistry, TrackingRootUpdate, TRACKING_CAPACITY, TRACKING_EMPTY_ROOT,
        TRACKING_GRACE_SLOTS,
    },
    ApplyRecordsIxData, CustomRingError, CustomRingProof, NewRing, PolicyUpdate, RecordWriteData,
    RingAccount, RingMode, RingPolicy, RingRole, RingRoles, SourceSlot, WriteRecordsIxData,
    MEMBER_REGISTRY_EMPTY_ROOT, N_SOURCE_SLOTS, READER_KEY_ED25519, ROOT_HISTORY,
    STORAGE_PROGRAM_ID, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG,
};
use serde_json::{json, Value};
use solana_address::Address;
use spr_hasher::{
    primitives::{hash_bytes, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_ring_policy::{ListId, ListSet, Member, Rule, RuleTable, Subject};

const PROGRAM: Address = Address::new_from_array([7; 32]);
const ENROLL_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/tracking_enroll.json"
);
fn key(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

fn roles() -> RingRoles {
    RingRoles {
        admin: key(1),
        policy: key(2),
        pauser: key(3),
        cosign_admin: key(4),
    }
}

fn ring(records: Address) -> Box<RingPolicy> {
    NewRing {
        bump: 254,
        mode: RingMode::Confidential,
        roles: roles(),
        auditor_pubkey: [4; 33],
        created_slot: 0,
        records,
        tracking: key(9),
    }
    .account()
}

#[test]
fn decode_needs_the_owner_the_length_and_the_discriminator() {
    let ring = ring(Address::default());
    let bytes = bytemuck::bytes_of(&*ring).to_vec();
    assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &bytes), Some(*ring));
    let other = Address::new_from_array([8; 32]);
    assert_eq!(RingPolicy::decode(&other, &PROGRAM, &bytes), None);
    assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &bytes[1..]), None);
    for unknown in [10, 13] {
        let mut stale = bytes.clone();
        stale[0] = unknown;
        assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &stale), None);
    }
}

#[test]
fn decode_refuses_values_no_setter_writes() {
    let mut mode = *ring(Address::default());
    mode.mode = 3;
    assert!(RingPolicy::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&mode)).is_none());
    assert_eq!(mode.mode(), Err(CustomRingError::InvalidRingMode));
}

#[test]
fn role_keys_stay_nonzero_and_apart_from_the_delegate() {
    assert_eq!(roles().check(None), Ok(()));
    assert_eq!(
        roles().check(Some(&key(2))),
        Err(CustomRingError::DuplicateRoleKey)
    );
    let mut ring = ring(Address::default());
    ring.rotate_role(RingRole::Pauser, key(1)).unwrap();
    assert_eq!(ring.check_role(RingRole::Pauser, &key(1)), Ok(()));
    assert_eq!(ring.check_role(RingRole::Admin, &key(1)), Ok(()));
    ring.rotate_role(RingRole::Pauser, key(3)).unwrap();
    ring.delegate = key(8);
    assert_eq!(
        ring.rotate_role(RingRole::Pauser, key(8)),
        Err(CustomRingError::DuplicateRoleKey)
    );
    assert_eq!(
        ring.rotate_role(RingRole::Pauser, Address::default()),
        Err(CustomRingError::ZeroRoleKey)
    );
    assert_eq!(ring.roles, roles());
    ring.rotate_role(RingRole::Pauser, key(9)).unwrap();
    assert_eq!(ring.roles.key(RingRole::Pauser), &key(9));
    assert_eq!(ring.check_role(RingRole::Policy, &key(2)), Ok(()));
    assert_eq!(
        ring.check_role(RingRole::Pauser, &key(2)),
        Err(CustomRingError::UnauthorizedAuthority)
    );
}

#[test]
fn a_policy_write_validates_and_repins_the_table() {
    let mut policy = ring(Address::default());
    assert_eq!(policy.policy_hash(), Err(CustomRingError::PolicyNotSet));
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build()
        .encode();
    let update = |sources, rules, slot| PolicyUpdate {
        sources,
        rules,
        slot,
    };
    assert_eq!(
        policy.set_policy(update(sources, table, 3)),
        Err(CustomRingError::InvalidSource)
    );
    sources[ListId::Allow.slot()].list_id = ListId::Allow as u8;
    policy.set_policy(update(sources, table, 3)).unwrap();
    let hash = *policy.policy_hash().unwrap();
    assert_eq!(hash, table.hash(&policy.source_map().unwrap()).unwrap());
    assert_eq!((policy.generation(), policy.generation_slot()), (1, 3));
    let mut padded = table;
    padded.rules[1][0] = 1;
    assert_eq!(
        policy.set_policy(update(sources, padded, 4)),
        Err(CustomRingError::InvalidPolicyRules)
    );
    assert_eq!(policy.policy_hash(), Ok(&hash));
}

#[test]
fn a_policy_write_refuses_each_table_form_and_keeps_the_pinned_table() {
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    for list_id in [ListId::Allow, ListId::Block, ListId::Frozen] {
        sources[list_id.slot()].list_id = list_id as u8;
    }
    let write = |rule: Rule, slot| PolicyUpdate {
        sources,
        rules: RuleTable::builder().rule(rule).build().encode(),
        slot,
    };
    let subject = Subject::OutputOwner;
    let allow = ListSet::single(ListId::Allow);
    let block = ListSet::single(ListId::Block);
    let mut policy = ring(Address::default());
    policy
        .set_policy(PolicyUpdate {
            rules: RuleTable::builder()
                .rule(Rule::require(subject, ListId::Allow))
                .rule(Rule::forbid(subject, ListId::Block))
                .rule(Rule::forbid(subject, ListId::Frozen))
                .build()
                .encode(),
            ..write(Rule::require(subject, ListId::Allow), 1)
        })
        .unwrap();
    let pinned = *policy;
    for (rule, refusal) in [
        (
            Rule::forbid_only_on_all(subject, ListSet::of(&[ListId::Block, ListId::Frozen])),
            CustomRingError::MultiListAbsenceRule,
        ),
        (
            Rule::require(subject, ListId::Block),
            CustomRingError::InvertedListPolarity,
        ),
        (
            Rule::forbid(subject, ListId::Allow),
            CustomRingError::InvertedListPolarity,
        ),
        (
            Rule::any_of(subject, allow, block),
            CustomRingError::MixedPolarityRule,
        ),
    ] {
        assert_eq!(policy.set_policy(write(rule, 2)), Err(refusal), "{rule:?}");
        assert_eq!(*policy, pinned);
    }
}

fn enroll_ix(viewing_u: [u8; 32]) -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: [0x14; 32],
        list_tag: [0x15; 32],
        viewing_u,
        eph_u: [0x16; 32],
        ciphertext: [0x17; 64],
    }
}

fn first_enrollment() -> TrackingAuthorization {
    FirstEnrollment {
        registry: key(0x11),
        owner: key(0x12),
        ix: &enroll_ix([0x18; 32]),
    }
    .account()
}

#[test]
fn the_entry_binds_every_field_and_comes_from_the_account() {
    let account = first_enrollment();
    let entry = account.entry().unwrap();
    assert_eq!(
        entry.member,
        solana_owner_identity(account.owner.as_array()).unwrap()
    );
    assert_eq!(entry.ct_hash, hash_bytes(&account.ciphertext).unwrap());
    assert_eq!(
        entry.hash().unwrap(),
        Poseidon::hashv(&[
            &domain::field(domain::TRACKING_ENTRY),
            &entry.member,
            &entry.nullifier_pk,
            &entry.ct_hash,
            &entry.list_tag,
        ])
        .unwrap()
    );
    let moved = [
        TrackingEntry {
            member: [9; 32],
            ..entry
        },
        TrackingEntry {
            nullifier_pk: [9; 32],
            ..entry
        },
        TrackingEntry {
            ct_hash: [9; 32],
            ..entry
        },
        TrackingEntry {
            list_tag: [9; 32],
            ..entry
        },
    ];
    for other in moved {
        assert_ne!(other.hash(), entry.hash());
    }
}

#[test]
fn an_enrollment_applies_once_and_a_rotation_never_reopens_it() {
    let mut account = first_enrollment();
    assert!(account.is_pending());
    let entry = account.apply().unwrap();
    assert_eq!(entry, first_enrollment().entry().unwrap());
    assert!(!account.is_pending());
    assert_eq!(account.apply(), Err(StorageError::EnrollmentAlreadyApplied));
    account.rotate(&enroll_ix([0x19; 32])).unwrap();
    assert!(!account.is_pending());
    assert_eq!(account.apply(), Err(StorageError::EnrollmentAlreadyApplied));
    // The entry holds no viewing key, a rotation leaves the row the apply chained.
    assert_eq!(account.entry().unwrap(), entry);
}

#[test]
fn a_rotation_refuses_every_final_field_and_moves_the_viewing_key_alone() {
    let mut account = first_enrollment();
    let rotated = enroll_ix([0x19; 32]);
    let before = account;
    for changed in [
        EnrollIxData {
            nullifier_pk: [9; 32],
            ..rotated
        },
        EnrollIxData {
            list_tag: [9; 32],
            ..rotated
        },
        EnrollIxData {
            eph_u: [9; 32],
            ..rotated
        },
        EnrollIxData {
            ciphertext: [9; 64],
            ..rotated
        },
    ] {
        assert_eq!(
            account.rotate(&changed),
            Err(StorageError::EnrollmentKeyFinal)
        );
    }
    assert_eq!(account, before);
    account.rotate(&rotated).unwrap();
    assert_eq!(
        account,
        TrackingAuthorization {
            viewing_u: [0x19; 32],
            ..before
        }
    );
}

#[test]
fn the_enrollment_checks_what_no_proof_binds_and_refuses_a_zero_key() {
    let check = |viewing_u| enroll_ix(viewing_u).check();
    assert_eq!(check([9; 32]), Ok(()));
    assert_eq!(check([0; 32]), Err(StorageError::NonCanonicalViewingKey));
    assert_eq!(check([0xff; 32]), Err(StorageError::NonCanonicalViewingKey));
    assert_eq!(
        EnrollIxData {
            nullifier_pk: spr_interface::ZERO_NULLIFIER_PUBKEY,
            ..enroll_ix([9; 32])
        }
        .check(),
        Err(StorageError::ZeroNullifierKey)
    );
    for not_canonical in [
        EnrollIxData {
            nullifier_pk: [0xff; 32],
            ..enroll_ix([9; 32])
        },
        EnrollIxData {
            list_tag: [0xff; 32],
            ..enroll_ix([9; 32])
        },
    ] {
        assert_eq!(
            not_canonical.check(),
            Err(StorageError::InvalidInstructionData)
        );
    }
}

#[test]
fn enroll_data_holds_the_fields_and_at_most_one_proof() {
    let ix = enroll_ix([9; 32]);
    let proof = CustomRingProof::zeroed();
    let rotation = EnrollRequest {
        ix: &ix,
        proof: None,
    };
    let first = EnrollRequest {
        ix: &ix,
        proof: Some(&proof),
    };
    assert_eq!(EnrollRequest::parse(&rotation.encode()), Ok(rotation));
    assert_eq!(EnrollRequest::parse(&first.encode()), Ok(first));
    let refused = Err(StorageError::InvalidInstructionData);
    assert_eq!(
        EnrollRequest::parse(&rotation.encode()[..EnrollIxData::SIZE - 1]),
        refused
    );
    assert_eq!(
        EnrollRequest::parse(&first.encode()[..EnrollIxData::SIZE + 1]),
        refused
    );
}

fn tracking_ix() -> InitializeTrackingIxData {
    let mut auditor_pubkey = [9; TAGGED_X25519_KEY_LEN];
    auditor_pubkey[0] = VIEWING_PUBKEY_TAG;
    InitializeTrackingIxData {
        ring_id: [1; 32],
        auditor_pubkey,
    }
}

#[test]
fn a_tracking_registry_starts_at_the_sentinel_and_pins_ring_and_auditor() {
    let ix = tracking_ix();
    assert_eq!(ix.check(), Ok(()));
    let registry = TrackingRegistry::new(&ix);
    assert_eq!(registry.ring_id, ix.ring_id);
    assert_eq!(registry.auditor_pubkey, ix.auditor_pubkey);
    assert_eq!(registry.newest().hash, TRACKING_EMPTY_ROOT);
    assert_eq!(registry.newest().revision, Revision::from(0));
    assert_eq!(registry.next_index(), 1);
    let bytes = bytemuck::bytes_of(&registry);
    assert_eq!(
        TrackingRegistry::decode(&STORAGE_PROGRAM_ID, bytes),
        Some(registry)
    );
    assert_eq!(TrackingRegistry::decode(&key(1), bytes), None);
    for (ring_id, auditor_pubkey, refusal) in [
        (
            [0; 32],
            ix.auditor_pubkey,
            StorageError::InvalidTrackingRegistry,
        ),
        (
            [0xff; 32],
            ix.auditor_pubkey,
            StorageError::InvalidTrackingRegistry,
        ),
        (
            ix.ring_id,
            [9; TAGGED_X25519_KEY_LEN],
            StorageError::InvalidAuditorKey,
        ),
    ] {
        assert_eq!(
            InitializeTrackingIxData {
                ring_id,
                auditor_pubkey
            }
            .check(),
            Err(refusal)
        );
    }
    let mut low_order = ix;
    low_order.auditor_pubkey[1..].fill(0);
    assert_eq!(low_order.check(), Err(StorageError::InvalidAuditorKey));
    low_order.auditor_pubkey[1] = 1;
    assert_eq!(low_order.check(), Err(StorageError::InvalidAuditorKey));
}

fn tracking_update(revision: u64, slot: u64, byte: u8) -> TrackingRootUpdate {
    TrackingRootUpdate {
        revision: revision.into(),
        slot,
        new_root: [byte; 32],
        new_next_index: 1,
    }
}

#[test]
fn a_tracking_update_serves_the_old_root_for_its_grace() {
    let mut registry = TrackingRegistry::new(&tracking_ix());
    registry.update(tracking_update(0, 10, 1)).unwrap();
    let first_root = TRACKING_EMPTY_ROOT;
    assert_eq!(registry.root(0.into(), 10), Ok(first_root));
    let lapse = 10 + TRACKING_GRACE_SLOTS;
    assert_eq!(registry.root(0.into(), lapse - 1), Ok(first_root));
    assert_eq!(
        registry.root(0.into(), lapse),
        Err(StorageError::RootExpired)
    );
    assert_eq!(
        registry.update(tracking_update(0, 11, 2)),
        Err(StorageError::RevisionChanged)
    );
}

/// The update that would evict the oldest unexpired root refuses and writes nothing, the same update applies once it lapses.
#[test]
fn a_tracking_update_waits_while_its_eviction_would_drop_an_unexpired_root() {
    let mut filled = TrackingRegistry::new(&tracking_ix());
    let full = ROOT_HISTORY as u64 - 1;
    for revision in 0..full {
        filled.update(tracking_update(revision, 10, 3)).unwrap();
    }
    assert_eq!(filled.root(0.into(), 11), Ok(TRACKING_EMPTY_ROOT));
    let before = filled;
    let lapse = 10 + TRACKING_GRACE_SLOTS;
    assert_eq!(
        filled.update(tracking_update(full, lapse - 1, 4)),
        Err(StorageError::RootHistoryRetained)
    );
    assert_eq!(filled, before);
    filled.update(tracking_update(full, lapse, 4)).unwrap();
    assert_eq!(filled.newest().revision, Revision::from(full + 1));
}

#[test]
fn a_tracking_tree_stays_valid_at_capacity_and_not_past_it() {
    let mut registry = TrackingRegistry::new(&tracking_ix());
    registry.next_index = TRACKING_CAPACITY.to_le_bytes();
    assert!(TrackingRegistry::from_data(bytemuck::bytes_of(&registry)).is_some());
    registry.next_index = (TRACKING_CAPACITY + 1).to_le_bytes();
    assert!(TrackingRegistry::from_data(bytemuck::bytes_of(&registry)).is_none());
}

#[test]
fn an_apply_fills_the_last_leaf_and_refuses_an_index_past_it() {
    let mut registry = TrackingRegistry::new(&tracking_ix());
    let past = TrackingRootUpdate {
        new_next_index: TRACKING_CAPACITY + 1,
        ..tracking_update(0, 10, 1)
    };
    let before = registry;
    assert_eq!(registry.update(past), Err(StorageError::TrackingTreeFull));
    assert_eq!(registry, before);
    registry
        .update(TrackingRootUpdate {
            new_next_index: TRACKING_CAPACITY,
            ..tracking_update(0, 10, 1)
        })
        .unwrap();
    assert_eq!(registry.next_index(), TRACKING_CAPACITY);
}

#[test]
fn the_grant_scopes_owner_and_reader_and_checks_its_scheme() {
    let reader = {
        let mut reader = [7; 34];
        reader[0] = READER_KEY_ED25519;
        reader
    };
    let (one, _) = OwnerGrant::find_address(&key(1), &key(2), &reader);
    let mut other_reader = reader;
    other_reader[33] = 8;
    for other in [
        OwnerGrant::find_address(&key(1), &key(3), &reader).0,
        OwnerGrant::find_address(&key(9), &key(2), &reader).0,
        OwnerGrant::find_address(&key(1), &key(2), &other_reader).0,
    ] {
        assert_ne!(one, other);
    }
    let ix = OwnerGrantIxData { reader, active: 1 };
    assert_eq!(ix.check(), Ok(()));
    let mut unknown = reader;
    unknown[0] = 9;
    assert_eq!(
        OwnerGrantIxData {
            reader: unknown,
            active: 1
        }
        .check(),
        Err(StorageError::InvalidReaderKey)
    );
    assert_eq!(
        OwnerGrantIxData { reader, active: 2 }.check(),
        Err(StorageError::InvalidInstructionData)
    );
}

fn apply_ix() -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        new_root: [8; 32],
        new_next_index: 1u32.to_le_bytes(),
        ..ApplyRecordsIxData::zeroed()
    }
}

fn restrictive_apply_ix() -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        restrictive: 1,
        ..apply_ix()
    }
}

fn list_write(list: ListId) -> RecordWriteData {
    RecordWriteData {
        member: [1; 32],
        lists: WriteRecordsIxData {
            mask: list.record_bit().to_le_bytes(),
            value: list.record_bit().to_le_bytes(),
        },
        mint_policy: custom_ring_interface::mint_policy_write(None),
    }
}

fn update_of<'a>(
    revision: u64,
    writes: Vec<RecordWriteData>,
    apply: &'a ApplyRecordsIxData,
) -> StorageUpdateIxData<'a> {
    let private = writes.iter().any(|write| {
        u64::from_le_bytes(write.lists.mask) & ListSet::PRIVATE_LISTS.record_bits() != 0
    });
    StorageUpdateIxData {
        revision: revision.into(),
        writes,
        asset_writes: Vec::new(),
        tracking_revision: private.then_some(Revision::from(0)),
        apply,
    }
}

fn update_data<'a>(
    revision: u64,
    list: ListId,
    apply: &'a ApplyRecordsIxData,
) -> StorageUpdateIxData<'a> {
    update_of(revision, vec![list_write(list)], apply)
}

fn public_registry(grace_slots: u64) -> StorageRegistry {
    StorageRegistry::new(
        key(1),
        &InitializeIxData {
            registry_id: RegistryId([1; 32]),
            grace_slots: grace_slots.to_le_bytes(),
            ring_id: [0; 32],
            tracking_registry: Address::default(),
        },
    )
}

fn pinned_registry(ring_id: [u8; 32]) -> StorageRegistry {
    StorageRegistry::new(
        key(1),
        &InitializeIxData {
            registry_id: RegistryId([1; 32]),
            grace_slots: 10u64.to_le_bytes(),
            ring_id,
            tracking_registry: key(5),
        },
    )
}

#[test]
fn an_allow_list_addition_keeps_grace_and_a_block_list_addition_ends_every_older_root() {
    let (permissive, restrictive) = (apply_ix(), restrictive_apply_ix());
    let mut registry = public_registry(10);
    registry
        .update(RootUpdate {
            slot: 1,
            data: &update_data(0, ListId::Allow, &permissive),
        })
        .unwrap();
    assert!(registry.root(0.into(), 1).is_ok());
    assert!(registry.root(0.into(), 10).is_ok());
    assert_eq!(registry.root(0.into(), 11), Err(StorageError::RootExpired));
    registry
        .update(RootUpdate {
            slot: 1,
            data: &update_data(1, ListId::Block, &restrictive),
        })
        .unwrap();
    assert_eq!(registry.root(1.into(), 1), Err(StorageError::RootExpired));
    assert_eq!(registry.root(0.into(), 1), Err(StorageError::RootExpired));
    assert!(registry.root(2.into(), 1).is_ok());
}

#[test]
fn a_permissive_update_over_a_full_history_evicts_the_oldest_root() {
    let apply = apply_ix();
    let mut registry = public_registry(u64::MAX);
    let newest = ROOT_HISTORY as u64;
    for revision in 0..newest {
        registry
            .update(RootUpdate {
                slot: 1,
                data: &update_data(revision, ListId::Allow, &apply),
            })
            .unwrap();
    }
    assert_eq!(registry.root(0.into(), 2), Err(StorageError::RootExpired));
    assert!(registry.root(1.into(), 2).is_ok());
    assert!(registry.root(newest.into(), 2).is_ok());
    registry
        .update(RootUpdate {
            slot: 2,
            data: &update_data(newest, ListId::Block, &restrictive_apply_ix()),
        })
        .unwrap();
    assert_eq!(
        registry.root(newest.into(), 2),
        Err(StorageError::RootExpired)
    );
}

#[test]
fn update_data_round_trips_and_refuses_no_writes() {
    let apply = apply_ix();
    let data = update_data(7, ListId::Block, &apply);
    let encoded = data.encode().unwrap();
    assert_eq!(StorageUpdateIxData::parse(&encoded), Ok(data));
    let mut no_writes = encoded;
    no_writes[8] = 0;
    assert_eq!(
        StorageUpdateIxData::parse(&no_writes),
        Err(StorageError::InvalidInstructionData)
    );
}

#[test]
fn a_mint_settings_tag_above_one_is_no_entry() {
    let apply = apply_ix();
    let mut data = update_data(0, ListId::Reader, &apply);
    data.writes[0].mint_policy[0] = 2;
    assert!(data.entries().next().unwrap().is_err());
}

#[test]
fn the_restrictive_byte_has_one_encoding() {
    let apply = restrictive_apply_ix();
    let encoded = update_data(0, ListId::Block, &apply).encode().unwrap();
    assert!(StorageUpdateIxData::parse(&encoded)
        .unwrap()
        .apply
        .restrictive());
    let mut two = encoded;
    *two.last_mut().unwrap() = 2;
    assert_eq!(
        StorageUpdateIxData::parse(&two),
        Err(StorageError::InvalidInstructionData)
    );
}

#[test]
fn private_writes_require_a_tracking_pin_before_any_root_changes() {
    let apply = restrictive_apply_ix();
    let data = update_data(0, ListId::PrivateBlock, &apply);
    let mut public = public_registry(10);
    let before = public;
    assert_eq!(
        public.update(RootUpdate {
            slot: 1,
            data: &data
        }),
        Err(StorageError::PrivateWriteWithoutTracking)
    );
    assert_eq!(public, before);
    for ring_id in [[3; 32], [0; 32]] {
        let mut source = pinned_registry(ring_id);
        let before = source;
        assert_eq!(source.newest().hash, MEMBER_REGISTRY_EMPTY_ROOT);
        let stale = update_data(1, ListId::PrivateBlock, &apply);
        assert_eq!(
            source.update(RootUpdate {
                slot: 1,
                data: &stale
            }),
            Err(StorageError::RevisionChanged)
        );
        assert_eq!(source, before);
    }
}

/// Own and curator sources alike, a stale tracking root must not outlive a new private entry.
#[test]
fn private_updates_keep_the_highest_tracking_floor_and_retire_old_roots() {
    let (apply, restrictive) = (apply_ix(), restrictive_apply_ix());
    for ring_id in [[3; 32], [0; 32]] {
        let mut source = pinned_registry(ring_id);
        for (revision, tracking, floor) in [(0, 5, 5), (1, 3, 5), (2, 8, 8)] {
            let mut data = update_data(revision, ListId::PrivateBlock, &restrictive);
            data.tracking_revision = Some(Revision::from(tracking));
            source
                .update(RootUpdate {
                    slot: 1,
                    data: &data,
                })
                .unwrap();
            assert_eq!(source.tracking_floor, Revision::from(floor));
            assert_eq!(
                source.root(revision.into(), 1),
                Err(StorageError::RootExpired)
            );
        }
        source
            .update(RootUpdate {
                slot: 1,
                data: &update_data(3, ListId::Block, &restrictive),
            })
            .unwrap();
        assert_eq!(source.tracking_floor, Revision::from(8));
        source
            .update(RootUpdate {
                slot: 1,
                data: &update_data(4, ListId::Reader, &apply),
            })
            .unwrap();
        assert_eq!(source.tracking_floor, Revision::from(8));
        assert_eq!(source.root(4.into(), 1), Ok(apply.new_root));
    }
}

#[test]
fn private_masks_need_a_tracking_row_even_when_the_write_clears_the_bit() {
    let apply = restrictive_apply_ix();
    let mut data = update_data(0, ListId::PrivateBlock, &apply);
    data.writes[0].lists.value = [0; 8];
    assert_eq!(data.private_writes(), Ok(1));
    assert!(StorageUpdateIxData::parse(&data.encode().unwrap()).is_ok());
    data.tracking_revision = None;
    assert_eq!(data.encode(), Err(StorageError::InvalidTrackingRegistry));
}

#[test]
fn asset_preimages_exempt_only_the_matching_private_write() {
    let apply = apply_ix();
    let mint = key(9);
    let mut asset = list_write(ListId::PrivateBlock);
    asset.member = *Member::asset(&mint).unwrap().as_bytes();
    let mut data = update_of(0, vec![asset, list_write(ListId::PrivateBlock)], &apply);
    data.asset_writes = vec![AssetWrite {
        write_index: 0,
        mint,
    }];
    assert_eq!(data.private_writes(), Ok(0b10));
    assert!(StorageUpdateIxData::parse(&data.encode().unwrap()).is_ok());
    data.writes.pop();
    data.tracking_revision = None;
    assert_eq!(data.private_writes(), Ok(0));
    assert!(StorageUpdateIxData::parse(&data.encode().unwrap()).is_ok());
    for invalid in [
        AssetWrite {
            write_index: 1,
            mint,
        },
        AssetWrite {
            write_index: 0,
            mint: key(8),
        },
    ] {
        data.asset_writes = vec![invalid];
        assert_eq!(data.private_writes(), Err(StorageError::InvalidAssetWrite));
    }
    data.asset_writes = vec![AssetWrite {
        write_index: 0,
        mint,
    }];
    data.writes[0].lists = list_write(ListId::Block).lists;
    assert!(data.entries().all(|entry| entry.is_ok()));
    assert_eq!(data.private_writes(), Err(StorageError::InvalidAssetWrite));
}

#[test]
fn asset_write_indices_are_distinct_and_in_increasing_order() {
    let apply = apply_ix();
    let mint = key(9);
    let mut asset = list_write(ListId::PrivateBlock);
    asset.member = *Member::asset(&mint).unwrap().as_bytes();
    let mut data = update_of(0, vec![asset, asset], &apply);
    for indexes in [[0, 0], [1, 0], [0, 2]] {
        data.asset_writes = indexes
            .map(|write_index| AssetWrite { write_index, mint })
            .to_vec();
        assert_eq!(data.private_writes(), Err(StorageError::InvalidAssetWrite));
    }
    data.asset_writes = [0, 1]
        .map(|write_index| AssetWrite { write_index, mint })
        .to_vec();
    data.tracking_revision = None;
    assert_eq!(data.private_writes(), Ok(0));
    assert!(data.encode().is_ok());
}

#[test]
fn a_public_update_carries_no_tracking_revision() {
    let apply = apply_ix();
    let mut data = update_data(0, ListId::Block, &apply);
    let encoded = data.encode().unwrap();
    data.tracking_revision = Some(Revision::from(0));
    assert_eq!(data.encode(), Err(StorageError::InvalidTrackingRegistry));
    let mut extended = encoded.clone();
    extended.extend_from_slice(&[0; 8]);
    assert_eq!(
        StorageUpdateIxData::parse(&extended),
        Err(StorageError::InvalidInstructionData)
    );
    assert!(StorageUpdateIxData::parse(&encoded[..encoded.len() - 1]).is_err());
}

#[test]
fn the_parser_reads_a_tracking_revision_exactly_when_a_write_is_private() {
    let apply = restrictive_apply_ix();
    let mut data = update_data(0, ListId::PrivateBlock, &apply);
    for revision in [0, u64::from(u32::MAX) + 1, u64::MAX] {
        data.tracking_revision = Some(Revision::from(revision));
        let encoded = data.encode().unwrap();
        let revision_offset = encoded.len() - core::mem::size_of::<ApplyRecordsIxData>() - 8;
        assert_eq!(
            &encoded[revision_offset..revision_offset + 8],
            revision.to_le_bytes()
        );
        assert_eq!(StorageUpdateIxData::parse(&encoded), Ok(data.clone()));
        for missing in 1..=8 {
            let mut truncated = encoded.clone();
            truncated.drain(revision_offset..revision_offset + missing);
            assert_eq!(
                StorageUpdateIxData::parse(&truncated),
                Err(StorageError::InvalidInstructionData)
            );
        }
    }
}

#[test]
fn public_update_wire_has_no_tracking_revision() {
    let apply = apply_ix();
    let data = update_data(7, ListId::Block, &apply);
    let mut expected = 7u64.to_le_bytes().to_vec();
    expected.push(1);
    expected.extend_from_slice(bytemuck::cast_slice(&data.writes));
    expected.push(0);
    expected.extend_from_slice(bytemuck::bytes_of(&apply));
    assert_eq!(data.encode().unwrap(), expected);
    assert_eq!(StorageUpdateIxData::parse(&expected), Ok(data));
}

fn enrollment_vector() -> Value {
    let registry = key(0x31);
    let owner = key(0x32);
    let ix = EnrollIxData {
        nullifier_pk: [0x23; 32],
        list_tag: [0x24; 32],
        viewing_u: [0x34; 32],
        eph_u: [0x35; 32],
        ciphertext: [0x36; 64],
    };
    let (authorization, bump) = TrackingAuthorization::find_address(&registry, &owner);
    let mut account = FirstEnrollment {
        registry,
        owner,
        ix: &ix,
    }
    .account();
    let entry = account.apply().unwrap();
    let chain_start = tracking_chain_start(&registry, Revision::from(0)).unwrap();
    json!({
        "description": "One enrollment and its permissionless apply. enroll_data follows tag 6, nullifier_pk || list_tag || viewing_u || eph_u || ciphertext, and a first enrollment appends a RegisterKey proof. The authorization PDA has seeds [tracking, registry, owner]. entry_hash is Poseidon(CRTQ, member, nullifier_pk, ct_hash, list_tag), chain_start is the hash chain of [CRTA, registry field, revision], chain_end is Poseidon(chain_start, entry_hash). account is the authorization after the apply. Produced by program-libs/interface/tests/accounts.rs.",
        "registry": hex::encode(registry),
        "owner": hex::encode(owner),
        "member": hex::encode(entry.member),
        "ct_hash": hex::encode(entry.ct_hash),
        "enroll_data": hex::encode(bytemuck::bytes_of(&ix)),
        "authorization": hex::encode(authorization),
        "bump": bump,
        "entry_hash": hex::encode(entry.hash().unwrap()),
        "chain_start": hex::encode(chain_start),
        "chain_end": hex::encode(entry.chained(&chain_start).unwrap()),
        "account": hex::encode(bytemuck::bytes_of(&account)),
    })
}

#[test]
fn the_enrollment_is_the_shared_vector() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(ENROLL_VECTOR).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, enrollment_vector());
}

#[test]
#[ignore = "rewrites test-vectors/registry/tracking_enroll.json"]
fn write_tracking_enroll_vector() {
    let json = serde_json::to_string_pretty(&enrollment_vector()).expect("json");
    std::fs::write(ENROLL_VECTOR, json + "\n").expect("write vector file");
}
