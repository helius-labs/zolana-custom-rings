use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, NewRing, RingAccount, RingMode, RingPolicy, RingRole, RingRoles, SourceSlot,
    N_SOURCE_SLOTS,
};
use solana_address::Address;
use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

const PROGRAM: Address = Address::new_from_array([7; 32]);

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
    for retired in [10, 13] {
        let mut stale = bytes.clone();
        stale[0] = retired;
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
fn role_keys_stay_nonzero_and_apart() {
    assert_eq!(roles().check(None), Ok(()));
    assert_eq!(
        roles().check(Some(&key(2))),
        Err(CustomRingError::DuplicateRoleKey)
    );
    let mut ring = ring(Address::default());
    assert_eq!(
        ring.rotate_role(RingRole::Pauser, key(1)),
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
    assert_eq!(
        policy.set_policy(sources, table, 3),
        Err(CustomRingError::InvalidSource)
    );
    sources[ListId::Allow.slot()].list_id = ListId::Allow as u8;
    policy.set_policy(sources, table, 3).unwrap();
    let hash = *policy.policy_hash().unwrap();
    assert_eq!(hash, table.hash(&policy.source_map().unwrap()).unwrap());
    assert_eq!((policy.generation(), policy.generation_slot()), (1, 3));
    let mut padded = table;
    padded.rules[1][0] = 1;
    assert_eq!(
        policy.set_policy(sources, padded, 4),
        Err(CustomRingError::InvalidPolicyRules)
    );
    assert_eq!(policy.policy_hash(), Ok(&hash));
}
