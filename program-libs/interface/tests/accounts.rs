use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, RingAccount, RingPolicy, RingProgramConfig, SourceSlot, N_SOURCE_SLOTS,
    RING_PROGRAM_CONFIG,
};
use solana_address::Address;
use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

const PROGRAM: Address = Address::new_from_array([7; 32]);

fn config() -> RingProgramConfig {
    let mut config: RingProgramConfig = Zeroable::zeroed();
    config.discriminator = RING_PROGRAM_CONFIG;
    config.authority = Address::new_from_array([1; 32]);
    config.auditor_pubkey = [4; 33];
    config.bump = 255;
    config.has_policy = 1;
    config
}

#[test]
fn decode_needs_the_owner_the_length_and_the_discriminator() {
    let bytes = bytemuck::bytes_of(&config()).to_vec();
    assert_eq!(
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, &bytes),
        Some(config())
    );
    let other = Address::new_from_array([8; 32]);
    assert_eq!(RingProgramConfig::decode(&other, &PROGRAM, &bytes), None);
    assert_eq!(
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, &bytes[1..]),
        None
    );
    let mut retired = bytes.clone();
    retired[0] = 1;
    assert_eq!(
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, &retired),
        None
    );
    assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &bytes), None);
}

#[test]
fn decode_refuses_values_no_setter_writes() {
    let decodes = |config: &RingProgramConfig| {
        RingProgramConfig::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(config)).is_some()
    };
    let mut mode = config();
    mode.mode = 3;
    assert!(!decodes(&mode));
    assert_eq!(mode.mode(), Err(CustomRingError::InvalidRingMode));
    let mut policy = config();
    policy.has_policy = 2;
    assert!(!decodes(&policy));
}

#[test]
fn a_policy_write_validates_and_repins_the_table() {
    let mut policy = RingPolicy::new(254, Address::default());
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
