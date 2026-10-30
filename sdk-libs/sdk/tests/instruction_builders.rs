//! Every proofless builder against the account order, privileges and data its processor parses.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use custom_ring_interface::{
    CustomRingMergeIxData, CustomRingMergeIxDataRef, InitializeIxData, MergeDisclosure,
    PolicyBindingIxData, PolicySourceIxData, RingRole, RingRoles, SetCoSignerRecordIxData,
    SetPausedIxData, SourceSpec, UpdateAuthorityIxData, UpdatePolicyIxData, AUDIT_CIPHERTEXT_LEN,
};
use custom_ring_sdk::{
    tag, ClearCoSigner, CoSignScope, CustomRing, CustomRingMergeInstruction, InitialPolicy,
    Initialize, PolicyRecords, PolicyTable, PolicyUpdate, RingError, RingKind, SetCoSigner,
    SetDelegate, SourceOwner, UpdateAuthority, UpdatePolicy,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_interface::{
    instruction::instruction_data::merge_transact::{
        MergeOutputEncryption, MergeProof, MergeTransactIxData,
    },
    pda, BPF_LOADER_UPGRADEABLE_ID,
};
use spr_keypair::X25519Keypair;
use spr_program::instruction::MergeRing;
use wincode::{config::DefaultConfig, SchemaRead};
use zolana_ring_client::ReaderKey;
use zolana_ring_policy::{
    ListId, PolicyTableError, Rule, RuleTable, RuleTableError, Subject, TableParts,
};

/// The system program is the all-zero address.
const SYSTEM: Address = Address::new_from_array([0; 32]);

fn program() -> Address {
    Address::new_from_array([10; 32])
}

fn ring() -> CustomRing {
    CustomRing::new(program())
}

fn payer() -> Address {
    Address::new_from_array([11; 32])
}

fn authority() -> Address {
    Address::new_from_array([12; 32])
}

/// SPP's own derivation, independent of the builder's.
fn ring_auth() -> Address {
    pda::ring_auth(&program()).0
}

/// The loader's derivation `UpgradeAuthorityCheck` reads the upgrade authority from.
fn program_data() -> Address {
    Address::find_program_address(
        &[program().as_ref()],
        &Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID),
    )
    .0
}

fn replace_rules(
    rules: &RuleTable,
    shared_sources: &[(ListId, Address)],
) -> Result<Instruction, RingError> {
    UpdatePolicy {
        ring: ring(),
        authority: authority(),
        update: PolicyUpdate::Rules(PolicyTable {
            rules,
            shared_sources,
        }),
    }
    .instruction()
}

fn policy_write() -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(authority(), true),
        AccountMeta::new(ring().policy_pda(), false),
    ]
}

fn roles() -> RingRoles {
    RingRoles {
        admin: Address::new_from_array([21; 32]),
        policy: Address::new_from_array([22; 32]),
        pauser: Address::new_from_array([23; 32]),
        cosign_admin: Address::new_from_array([24; 32]),
    }
}

fn split(instruction: &Instruction) -> (u8, &[u8]) {
    let (ix_tag, body) = instruction.data.split_first().unwrap();
    (*ix_tag, body)
}

/// The program's own decoder of a wincode body.
fn parse<'a, T: SchemaRead<'a, DefaultConfig, Dst = T>>(body: &'a [u8]) -> T {
    wincode::deserialize_exact(body).unwrap()
}

#[test]
fn initialize_runs_under_the_upgrade_authority_and_appends_the_records_only_with_a_policy() {
    let auditor_pubkey = X25519Keypair::from_bytes(&[5; 32]).pubkey();
    let accounts = vec![
        AccountMeta::new(payer(), true),
        AccountMeta::new_readonly(authority(), true),
        AccountMeta::new(ring().policy_pda(), false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new_readonly(program(), false),
        AccountMeta::new_readonly(program_data(), false),
        AccountMeta::new_readonly(pda::protocol_config(), false),
        AccountMeta::new(ring_auth(), false),
        AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
    ];
    let initialize = |kind, policy| {
        Initialize {
            ring: ring(),
            payer: payer(),
            authority: authority(),
            auditor_pubkey,
            kind,
            roles: roles(),
            policy,
        }
        .instruction()
        .unwrap()
    };
    let audit_only = initialize(RingKind::Anonymous, None);
    assert_eq!(audit_only.program_id, program());
    assert_eq!(audit_only.accounts, accounts);
    let (ix_tag, body) = split(&audit_only);
    assert_eq!(ix_tag, tag::INITIALIZE);
    assert_eq!(
        parse::<InitializeIxData>(body),
        InitializeIxData {
            auditor_pubkey: *auditor_pubkey.as_bytes(),
            kind: RingKind::Anonymous,
            roles: roles(),
            policy: None,
        }
    );
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .build();
    let curator = Address::new_from_array([36; 32]);
    let records = PolicyRecords {
        records: Address::new_from_array([37; 32]),
        storage_authority: Address::new_from_array([38; 32]),
    };
    let with_policy = initialize(
        RingKind::Policy,
        Some(InitialPolicy {
            records,
            table: PolicyTable {
                rules: &rules,
                shared_sources: &[(ListId::Allow, curator)],
            },
        }),
    );
    assert_eq!(
        with_policy.accounts,
        [
            accounts,
            vec![
                AccountMeta::new_readonly(records.records, false),
                AccountMeta::new_readonly(curator, false),
            ]
        ]
        .concat()
    );
    let (_, body) = split(&with_policy);
    let PolicyBindingIxData {
        storage_authority,
        table,
    } = parse::<InitializeIxData>(body).policy.unwrap();
    assert_eq!(storage_authority, records.storage_authority);
    assert_eq!(
        table.sources,
        [SourceSpec {
            list_id: ListId::Allow as u8,
            source: 1,
        }]
    );
}

#[test]
fn a_grant_takes_only_a_canonical_prime_order_ed25519_reader() {
    let mut small_order = [0; 32];
    small_order[0] = 1;
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    let mixed_torsion = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    for key in [small_order, noncanonical, mixed_torsion] {
        assert!(ReaderKey::ed25519(Address::new_from_array(key)).is_err());
    }
}

#[test]
fn update_authority_takes_both_signers_and_names_the_role() {
    let new_authority = Address::new_from_array([31; 32]);
    let instruction = UpdateAuthority {
        ring: ring(),
        admin: authority(),
        new_authority,
        role: RingRole::CosignAdmin,
    }
    .instruction()
    .unwrap();
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new_readonly(new_authority, true),
            AccountMeta::new(ring().policy_pda(), false),
        ]
    );
    let (ix_tag, body) = split(&instruction);
    assert_eq!(ix_tag, tag::UPDATE_AUTHORITY);
    assert_eq!(
        parse::<UpdateAuthorityIxData>(body).role,
        RingRole::CosignAdmin
    );
}

#[test]
fn pause_and_resume_reach_spp_through_the_ring_auth() {
    for (instruction, paused) in [
        (ring().pause(authority()).unwrap(), true),
        (ring().resume(authority()).unwrap(), false),
    ] {
        assert_eq!(
            instruction.accounts,
            vec![
                AccountMeta::new_readonly(authority(), true),
                AccountMeta::new_readonly(ring().policy_pda(), false),
                AccountMeta::new(ring_auth(), false),
                AccountMeta::new_readonly(pda::shielded_pool_program_id(), false),
            ]
        );
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::SET_PAUSED);
        assert_eq!(parse::<SetPausedIxData>(body), SetPausedIxData { paused });
    }
}

#[test]
fn co_signer_writes_name_the_signers_record() {
    let signer = Address::new_from_array([32; 32]);
    let record = AccountMeta::new(ring().co_signer_pda(&signer), false);
    let scope = CoSignScope::TRANSFERS | CoSignScope::WITHDRAWALS;
    let set = SetCoSigner {
        ring: ring(),
        payer: payer(),
        authority: authority(),
        signer,
        scope,
    }
    .instruction()
    .unwrap();
    assert_eq!(
        set.accounts,
        vec![
            AccountMeta::new(payer(), true),
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().policy_pda(), false),
            record.clone(),
            AccountMeta::new_readonly(Address::default(), false),
        ]
    );
    let (ix_tag, body) = split(&set);
    assert_eq!(ix_tag, tag::SET_CO_SIGNER);
    assert_eq!(
        parse::<SetCoSignerRecordIxData>(body),
        SetCoSignerRecordIxData {
            signer,
            scope: scope.bits(),
        }
    );
    let rent_recipient = Address::new_from_array([33; 32]);
    let clear = ClearCoSigner {
        ring: ring(),
        authority: authority(),
        signer,
        rent_recipient,
    }
    .instruction();
    assert_eq!(
        clear.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().policy_pda(), false),
            record,
            AccountMeta::new(rent_recipient, false),
        ]
    );
    assert_eq!(clear.data, [tag::CLEAR_CO_SIGNER]);
}

#[test]
fn set_delegate_runs_under_the_admin_and_the_delegate() {
    let delegate = Address::new_from_array([34; 32]);
    let instruction = SetDelegate {
        ring: ring(),
        authority: authority(),
        delegate,
    }
    .instruction();
    assert_eq!(
        instruction.accounts,
        vec![
            AccountMeta::new_readonly(authority(), true),
            AccountMeta::new(ring().policy_pda(), false),
            AccountMeta::new_readonly(delegate, true),
        ]
    );
    assert_eq!(instruction.data, [tag::SET_DELEGATE]);
}

#[test]
fn a_policy_source_names_a_curator_registry_only_when_shared() {
    let curator = Address::new_from_array([35; 32]);
    for (owner, source, curators) in [
        (SourceOwner::Own, 0, vec![]),
        (
            SourceOwner::Curator(curator),
            1,
            vec![AccountMeta::new_readonly(curator, false)],
        ),
    ] {
        let instruction = UpdatePolicy {
            ring: ring(),
            authority: authority(),
            update: PolicyUpdate::Source {
                list_id: ListId::Allow,
                source: owner,
            },
        }
        .instruction()
        .unwrap();
        assert_eq!(instruction.accounts, [policy_write(), curators].concat());
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::UPDATE_POLICY);
        assert_eq!(
            parse::<UpdatePolicyIxData>(body),
            UpdatePolicyIxData::Source(PolicySourceIxData {
                list_id: ListId::Allow as u8,
                source,
            })
        );
    }
}

#[test]
fn a_records_rebind_names_the_new_registry_and_its_storage_authority() {
    let records = PolicyRecords {
        records: Address::new_from_array([39; 32]),
        storage_authority: Address::new_from_array([38; 32]),
    };
    let instruction = UpdatePolicy {
        ring: ring(),
        authority: authority(),
        update: PolicyUpdate::Records(records),
    }
    .instruction()
    .unwrap();
    assert_eq!(
        instruction.accounts,
        [
            policy_write(),
            vec![AccountMeta::new_readonly(records.records, false)]
        ]
        .concat()
    );
    let (ix_tag, body) = split(&instruction);
    assert_eq!(ix_tag, tag::UPDATE_POLICY);
    assert_eq!(
        parse::<UpdatePolicyIxData>(body),
        UpdatePolicyIxData::Records {
            storage_authority: records.storage_authority,
        }
    );
}

#[test]
fn a_policy_table_names_its_curator_once_and_reproduces_the_pinned_table() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Block))
        .rule(Rule::forbid(Subject::OutputOwner, ListId::Frozen))
        .build();
    let curator = Address::new_from_array([36; 32]);
    let shared = [(ListId::Frozen, curator), (ListId::Allow, curator)];
    let replace = replace_rules(&rules, &shared).unwrap();
    assert_eq!(
        replace.accounts,
        [
            policy_write(),
            vec![AccountMeta::new_readonly(curator, false)]
        ]
        .concat()
    );
    let (found, body) = split(&replace);
    assert_eq!(found, tag::UPDATE_POLICY);
    let UpdatePolicyIxData::Rules(table) = parse(body) else {
        panic!("a rules update");
    };
    assert_eq!(
        table.sources,
        [(ListId::Allow, 1), (ListId::Block, 0), (ListId::Frozen, 1)].map(|(list_id, source)| {
            SourceSpec {
                list_id: list_id as u8,
                source,
            }
        })
    );
    let stored = TableParts { rows: &table.rules }.encode().unwrap();
    assert_eq!(stored, rules.encode());
}

#[test]
fn a_shared_source_for_a_list_no_rule_reads_is_refused() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .build();
    let curator = Address::new_from_array([37; 32]);
    assert!(matches!(
        replace_rules(&rules, &[(ListId::Reader, curator)]),
        Err(RingError::UnreferencedList(ListId::Reader))
    ));
}

#[test]
fn a_rule_over_a_list_members_write_is_refused_before_the_transaction() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::RingViewing))
        .build();
    assert!(matches!(
        replace_rules(&rules, &[]),
        Err(RingError::PolicyTable(PolicyTableError::Table(
            RuleTableError::MemberWrittenList
        )))
    ));
}

#[test]
fn an_anonymous_merge_names_no_registry() {
    let (input_tree, output_tree) = (pda::tree(1), pda::tree(2));
    let merge = MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [0; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [0; 16],
            ciphertext: [[0; 32]; 3],
        },
        private_tx_hash: [0; 32],
        nullifiers: vec![[1; 32]],
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        cache_slot: None,
    };
    let spp = MergeRing {
        input_tree,
        output_tree,
        ring_program_id: program(),
        payer: payer(),
        data: merge.clone(),
        output_ring_data_hash: [0; 32],
        cache: None,
    }
    .instruction();
    let instruction = CustomRingMergeInstruction {
        ring: ring(),
        input_tree,
        output_tree,
        payer: payer(),
        records: None,
        co_signer: None,
        data: CustomRingMergeIxData {
            own_revision: Default::default(),
            output_ring_data_hash: [0; 32],
            disclosure: zero_disclosure(),
            merge,
        },
    }
    .instruction()
    .unwrap();
    assert_eq!(
        instruction.accounts,
        [
            vec![AccountMeta::new_readonly(ring().policy_pda(), false)],
            spp.accounts
        ]
        .concat()
    );
}

#[test]
fn a_key_escrow_merge_names_the_ring_its_records_and_the_co_signer_ahead_of_spp() {
    let records = Address::new_from_array([0x5a; 32]);
    let (input_tree, output_tree) = (pda::tree(1), pda::tree(2));
    let data = CustomRingMergeIxData {
        own_revision: 3.into(),
        output_ring_data_hash: [9; 32],
        disclosure: zero_disclosure(),
        merge: MergeTransactIxData {
            expiry_unix_ts: u64::MAX,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [0; 16],
                ciphertext: [[0; 32]; 3],
            },
            private_tx_hash: [0; 32],
            nullifiers: vec![[1; 32], [2; 32]],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
    };
    let spp = MergeRing {
        input_tree,
        output_tree,
        ring_program_id: program(),
        payer: payer(),
        data: data.merge.clone(),
        output_ring_data_hash: data.output_ring_data_hash,
        cache: None,
    }
    .instruction();
    for co_signer in [None, Some(Address::new_from_array([50; 32]))] {
        let instruction = CustomRingMergeInstruction {
            ring: ring(),
            input_tree,
            output_tree,
            payer: payer(),
            records: Some(records),
            co_signer,
            data: data.clone(),
        }
        .instruction()
        .unwrap();
        let mut prefix = vec![
            AccountMeta::new_readonly(ring().policy_pda(), false),
            AccountMeta::new_readonly(records, false),
        ];
        prefix.extend(co_signer.into_iter().flat_map(|co_signer| {
            [
                AccountMeta::new_readonly(ring().co_signer_pda(&co_signer), false),
                AccountMeta::new_readonly(co_signer, true),
            ]
        }));
        assert_eq!(
            instruction.accounts,
            [prefix, spp.accounts.clone()].concat()
        );
        let (ix_tag, body) = split(&instruction);
        assert_eq!(ix_tag, tag::MERGE);
        let parsed = CustomRingMergeIxDataRef::from_bytes(body).unwrap();
        assert_eq!(
            (
                parsed.own_revision.value(),
                *parsed.output_ring_data_hash,
                parsed.disclosure.fields.len()
            ),
            (3, [9; 32], 1)
        );
    }
}

fn zero_disclosure() -> MergeDisclosure {
    MergeDisclosure {
        proof: bytemuck::Zeroable::zeroed(),
        eph_pk: [0; 33],
        ciphertext: [0; AUDIT_CIPHERTEXT_LEN],
        fields: vec![[0; 32]],
    }
}

#[test]
fn a_list_shared_twice_is_refused() {
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .build();
    let first = Address::new_from_array([38; 32]);
    let second = Address::new_from_array([39; 32]);
    assert!(matches!(
        replace_rules(&rules, &[(ListId::Allow, first), (ListId::Allow, second)]),
        Err(RingError::DuplicateSharedSource(ListId::Allow))
    ));
}
