//! Ring account and policy writes, their roles and their declared budgets.

use custom_ring_interface::{
    storage::StorageError, tag, tracking::TrackingRegistry, CoSignScope, CoSigner, CustomRingError,
    InitializeIxData, InstructionTag, PolicyBindingIxData, PolicySourceIxData, PolicyTableIxData,
    RingKind, RingMode, RingPolicy, RingRole, SetPausedIxData, SourceSpec, UpdatePolicyIxData,
    TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use spr_account_checks::AccountError;
use spr_interface::state::RingConfig;
use zolana_ring_policy::{ring_id_field, ListId, ListSet, Rule, Subject, TableParts};

use crate::common::{
    allow_list_table, auditor_pubkey, co_signer_record, list_table, policy_pda, program_data_of,
    refused, refused_with, ring_auth, root, rules_write, set_co_signer, set_delegate,
    tracking_registry, within_budget, ClearCoSignerIx, InitializeIx, Ring, Sent, SetCoSignerIx,
    Setup, UpdateAuthorityIx, UpdatePolicyIx, PROGRAM, RECORDS,
};
use crate::transact_rules::SPP;

const ROLES: [RingRole; 4] = [
    RingRole::Admin,
    RingRole::Policy,
    RingRole::Pauser,
    RingRole::CosignAdmin,
];

impl Ring {
    fn role_send(&mut self, role: RingRole, instruction: Instruction) -> Sent {
        let holder = self.holder(role);
        self.send(instruction, &[&holder])
    }
}

fn upgrade_send(ring: &mut Ring, instruction: Instruction) -> Sent {
    let authority = ring.authority.insecure_clone();
    ring.send(instruction, &[&authority])
}

/// The state before `Initialize`, the deployed program alone.
fn uninitialized(setup: Setup) -> Ring {
    let mut ring = Ring::new(setup);
    for account in [policy_pda(), ring_auth(), tracking_registry()] {
        ring.drain(&account);
    }
    ring
}

fn initialize(ring: &Ring, signer: &Address, data: InitializeIxData) -> Instruction {
    InitializeIx {
        payer: ring.payer.pubkey(),
        authority: *signer,
        data,
        curators: &[],
    }
    .instruction()
}

fn upgrade_initialize(ring: &mut Ring, data: InitializeIxData) -> Sent {
    let authority = ring.authority.pubkey();
    let instruction = initialize(ring, &authority, data);
    upgrade_send(ring, instruction)
}

fn policy_config(ring: &Ring) -> InitializeIxData {
    InitializeIxData {
        auditor_pubkey: auditor_pubkey(),
        kind: RingKind::Policy,
        roles: ring.roles.addresses(),
        policy: Some(PolicyBindingIxData {
            table: allow_list_table(Vec::new()),
        }),
    }
}

fn audit_only_config(ring: &Ring) -> InitializeIxData {
    InitializeIxData {
        auditor_pubkey: auditor_pubkey(),
        kind: RingKind::AuditOnly,
        roles: ring.roles.addresses(),
        policy: None,
    }
}

#[test]
fn initialize_creates_the_ring_and_spp_registration_under_the_upgrade_authority() {
    let mut ring = uninitialized(Setup::Policy);
    let stranger = Keypair::new();
    let data = policy_config(&ring);
    refused(
        ring.send(initialize(&ring, &stranger.pubkey(), data), &[&stranger]),
        CustomRingError::UnauthorizedInitializer,
    );
    assert_eq!(ring.lamports(&policy_pda()), 0);
    let mut low_order = policy_config(&ring);
    low_order.auditor_pubkey[1..].fill(0);
    refused(
        upgrade_initialize(&mut ring, low_order),
        CustomRingError::InvalidAuditorPubkey,
    );
    let data = policy_config(&ring);
    within_budget(
        InstructionTag::Initialize,
        upgrade_initialize(&mut ring, data),
    );
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.roles, ring.roles.addresses());
    assert_eq!(
        (account.co_signers.covered(), account.delegate()),
        (None, None)
    );
    assert_eq!(account.records, RECORDS);
    assert_eq!(account.tracking, tracking_registry());
    let tracking: TrackingRegistry = ring.read(&tracking_registry());
    assert_eq!(tracking.auditor_pubkey, auditor_pubkey());
    assert_eq!(tracking.ring_id, ring_id_field(PROGRAM.as_array()).unwrap());
    assert!(account.written_policy_hash().is_some());
    let registration: RingConfig = ring.read(&ring_auth());
    assert_eq!(
        (registration.program_id, registration.authority),
        (PROGRAM, ring_auth())
    );
}

/// Storage fixes the address from the ring PDA and the ring id, a client names no registry of its own.
#[test]
fn initialize_refuses_a_tracking_account_off_its_seeds() {
    let mut ring = uninitialized(Setup::Policy);
    let data = policy_config(&ring);
    let authority = ring.authority.pubkey();
    let mut instruction = initialize(&ring, &authority, data);
    let position = instruction
        .accounts
        .iter()
        .position(|meta| meta.pubkey == tracking_registry())
        .unwrap();
    instruction.accounts[position].pubkey = Address::new_unique();
    refused_with(
        upgrade_send(&mut ring, instruction),
        InstructionError::Custom(StorageError::InvalidTrackingRegistry as u32),
    );
    assert_eq!(ring.lamports(&policy_pda()), 0);
}

#[test]
fn initialize_refuses_a_zero_role_key_and_takes_a_shared_one() {
    let mut ring = uninitialized(Setup::AuditOnly);
    let mut zero = audit_only_config(&ring);
    zero.roles.pauser = Address::default();
    refused(
        upgrade_initialize(&mut ring, zero),
        CustomRingError::ZeroRoleKey,
    );
    assert_eq!(ring.lamports(&policy_pda()), 0);
    let mut shared = audit_only_config(&ring);
    shared.roles.policy = shared.roles.admin;
    shared.roles.pauser = shared.roles.admin;
    let roles = shared.roles;
    within_budget(
        InstructionTag::Initialize,
        upgrade_initialize(&mut ring, shared),
    );
    assert_eq!(ring.read::<RingPolicy>(&policy_pda()).roles, roles);
}

#[test]
fn the_upgrade_authority_comes_from_the_ring_programs_own_program_data() {
    let mut ring = uninitialized(Setup::AuditOnly);
    let stranger = Keypair::new();
    let stand_in = Address::new_unique();
    ring.deploy_stand_in(stand_in);
    ring.set_upgrade_authority(&stand_in, &stranger.pubkey());
    for program in [stand_in, PROGRAM] {
        let mut instruction = initialize(&ring, &stranger.pubkey(), audit_only_config(&ring));
        instruction.accounts[4] = AccountMeta::new_readonly(program, false);
        instruction.accounts[5] = AccountMeta::new_readonly(program_data_of(&stand_in), false);
        refused(
            ring.send(instruction, &[&stranger]),
            CustomRingError::UnauthorizedInitializer,
        );
    }
}

#[test]
fn the_ring_records_the_slot_it_was_created_in() {
    let mut ring = uninitialized(Setup::Anonymous);
    let created = 1_000_007;
    ring.warp(created);
    let data = InitializeIxData {
        kind: RingKind::Anonymous,
        policy: Some(PolicyBindingIxData {
            table: PolicyTableIxData {
                sources: Vec::new(),
                rules: Vec::new(),
            },
        }),
        ..audit_only_config(&ring)
    };
    upgrade_initialize(&mut ring, data).expect("the upgrade authority creates the ring");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.created_slot(), created);
}

#[test]
fn each_co_signer_lives_in_its_own_record() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let (payer, authority) = (ring.payer.pubkey(), ring.roles.cosign_admin.pubkey());
    let set = |signer, scope| {
        SetCoSignerIx {
            payer,
            authority,
            signer: Address::new_from_array(signer),
            scope,
        }
        .instruction()
    };
    let send = |ring: &mut Ring, instruction| ring.role_send(RingRole::CosignAdmin, instruction);
    refused(
        send(&mut ring, set([1; 32], 0)),
        CustomRingError::InvalidCoSignerScope,
    );
    refused(
        send(&mut ring, set([0; 32], 1)),
        CustomRingError::InvalidCoSigner,
    );
    within_budget(
        InstructionTag::SetCoSigner,
        send(&mut ring, set([1; 32], 4)),
    );
    within_budget(
        InstructionTag::SetCoSigner,
        send(&mut ring, set([1; 32], 5)),
    );
    let signer = Address::new_from_array([1; 32]);
    let record: CoSigner = ring.read(&co_signer_record(&signer));
    assert_eq!((record.signer, record.scope), (signer, 5));
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.co_signers.covered(), CoSignScope::new(5));
    within_budget(
        InstructionTag::ClearCoSigner,
        send(
            &mut ring,
            ClearCoSignerIx {
                authority,
                signer,
                rent_recipient: payer,
            }
            .instruction(),
        ),
    );
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.co_signers.covered(), None);
}

fn appoint(ring: &mut Ring, delegate: &Keypair) -> Sent {
    let admin = ring.holder(RingRole::Admin);
    ring.send(
        set_delegate(&admin.pubkey(), &delegate.pubkey()),
        &[&admin, delegate],
    )
}

#[test]
fn the_delegate_is_permanent_and_any_ring_takes_one() {
    let delegate = Keypair::new();
    let mut ring = Ring::new(Setup::Policy);
    let pauser = ring.holder(RingRole::Pauser);
    refused(
        appoint(&mut ring, &pauser),
        CustomRingError::DuplicateRoleKey,
    );
    within_budget(InstructionTag::SetDelegate, appoint(&mut ring, &delegate));
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.delegate(), Some(&delegate.pubkey()));
    assert_eq!(account.mode(), Ok(RingMode::Confidential));
    refused(
        appoint(&mut ring, &Keypair::new()),
        CustomRingError::DelegateAlreadySet,
    );
    for (setup, mode) in [
        (Setup::AnonymousPolicy, RingMode::Anonymous),
        (Setup::Anonymous, RingMode::Anonymous),
        (Setup::AuditOnly, RingMode::Confidential),
    ] {
        let mut ring = Ring::new(setup);
        within_budget(InstructionTag::SetDelegate, appoint(&mut ring, &delegate));
        let account: RingPolicy = ring.read(&policy_pda());
        assert_eq!(account.mode(), Ok(mode));
    }
}

#[test]
fn the_delegate_signs_its_appointment_and_no_data_names_it() {
    let mut ring = Ring::new(Setup::Policy);
    let admin = ring.holder(RingRole::Admin);
    let delegate = Keypair::new();
    let mut unsigned = set_delegate(&admin.pubkey(), &delegate.pubkey());
    unsigned.accounts[2].is_signer = false;
    refused_with(
        ring.send(unsigned, &[&admin]),
        InstructionError::Custom(u32::from(AccountError::InvalidSigner)),
    );
    let mut named = set_delegate(&admin.pubkey(), &delegate.pubkey());
    named.data.extend_from_slice(delegate.pubkey().as_ref());
    refused(
        ring.send(named, &[&admin, &delegate]),
        CustomRingError::InvalidInstructionData,
    );
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.delegate(), None);
}

#[test]
fn a_rotated_admin_appoints_the_delegate_and_the_old_one_cannot() {
    let mut ring = Ring::new(Setup::Policy);
    let successor = Keypair::new();
    let admin = ring.holder(RingRole::Admin);
    let handover = UpdateAuthorityIx {
        admin: admin.pubkey(),
        new_key: successor.pubkey(),
        role: RingRole::Admin,
    }
    .instruction();
    ring.send(handover, &[&admin, &successor])
        .expect("hand the admin role to a successor");
    let delegate = Keypair::new();
    refused(
        appoint(&mut ring, &delegate),
        CustomRingError::UnauthorizedAuthority,
    );
    ring.send(
        set_delegate(&successor.pubkey(), &delegate.pubkey()),
        &[&successor, &delegate],
    )
    .expect("the admin appoints the delegate");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.delegate(), Some(&delegate.pubkey()));
}

fn own_source_table(rules: &[Rule]) -> PolicyTableIxData {
    let referenced = rules
        .iter()
        .fold(ListSet::EMPTY, |set, rule| set.union(rule.referenced()));
    PolicyTableIxData {
        sources: referenced
            .iter()
            .map(|list_id| SourceSpec {
                list_id: list_id as u8,
                source: 0,
            })
            .collect(),
        rules: rules.iter().map(Rule::encoded).collect(),
    }
}

fn refused_table_forms() -> [(Rule, CustomRingError); 4] {
    let subject = Subject::OutputOwner;
    [
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
            Rule::any_of(
                subject,
                ListSet::single(ListId::Allow),
                ListSet::single(ListId::Block),
            ),
            CustomRingError::MixedPolarityRule,
        ),
    ]
}

#[test]
fn initialize_refuses_each_table_form() {
    for (rule, refusal) in refused_table_forms() {
        let mut ring = uninitialized(Setup::Policy);
        let mut data = policy_config(&ring);
        data.policy = Some(PolicyBindingIxData {
            table: own_source_table(&[rule]),
        });
        refused(upgrade_initialize(&mut ring, data), refusal);
        assert_eq!(ring.lamports(&policy_pda()), 0, "{rule:?}");
    }
}

#[test]
fn a_table_write_refuses_each_table_form() {
    for (rule, refusal) in refused_table_forms() {
        let mut ring = Ring::new(Setup::Policy);
        let policy = ring.roles.policy.pubkey();
        let before: RingPolicy = ring.read(&policy_pda());
        refused(
            ring.role_send(
                RingRole::Policy,
                rules_write(&policy, own_source_table(&[rule])),
            ),
            refusal,
        );
        let after: RingPolicy = ring.read(&policy_pda());
        assert_eq!(after, before, "{rule:?}");
    }
}

#[test]
fn a_source_write_refuses_each_table_form_it_would_store_again() {
    for (rule, refusal) in refused_table_forms() {
        let mut ring = Ring::new(Setup::Policy);
        let policy = ring.roles.policy.pubkey();
        let mut account: RingPolicy = ring.read(&policy_pda());
        account.rules = TableParts {
            rows: &[rule.encoded()],
        }
        .encode()
        .unwrap();
        let referenced = rule.referenced();
        for (slot, list_id) in account.sources.iter_mut().zip(ListId::ALL) {
            slot.list_id = match referenced.contains(list_id) {
                true => list_id as u8,
                false => 0,
            };
        }
        ring.write(&policy_pda(), &account);
        let list_id = referenced.iter().next().unwrap();
        let instruction = UpdatePolicyIx {
            authority: policy,
            update: UpdatePolicyIxData::Source(PolicySourceIxData {
                list_id: list_id as u8,
                source: 0,
            }),
            trailing: &[],
        }
        .instruction();
        refused(ring.role_send(RingRole::Policy, instruction), refusal);
    }
}

#[test]
fn both_policy_writes_take_a_grant_over_several_lists_and_one_denial_per_list() {
    let table = own_source_table(&[
        Rule::require_any(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Allow, ListId::Approval]),
        ),
        Rule::forbid(Subject::OutputOwner, ListId::Block),
        Rule::forbid(Subject::OutputOwner, ListId::PrivateBlock),
        Rule::forbid(Subject::Sender, ListId::Frozen),
    ]);
    let mut ring = uninitialized(Setup::Policy);
    let mut data = policy_config(&ring);
    data.policy = Some(PolicyBindingIxData {
        table: table.clone(),
    });
    upgrade_initialize(&mut ring, data).expect("consistent list operations");
    let mut ring = Ring::new(Setup::Policy);
    let policy = ring.roles.policy.pubkey();
    // The salted denial reads the own records, the write passes them for the pairing check.
    let write = UpdatePolicyIx {
        authority: policy,
        update: UpdatePolicyIxData::Rules(table),
        trailing: &[RECORDS],
    }
    .instruction();
    ring.role_send(RingRole::Policy, write)
        .expect("consistent list operations");
}

#[test]
fn a_rule_over_a_member_written_list_is_refused() {
    let mut ring = Ring::new(Setup::Policy);
    let policy = ring.roles.policy.pubkey();
    refused(
        ring.role_send(
            RingRole::Policy,
            rules_write(&policy, list_table(ListId::RingViewing, Vec::new())),
        ),
        CustomRingError::MemberWrittenListRule,
    );
}

#[test]
fn policy_writes_need_a_policy_ring_and_a_foreign_curator() {
    let mut audit_only = uninitialized(Setup::AuditOnly);
    let table_on_audit_only = InitializeIxData {
        kind: RingKind::AuditOnly,
        ..policy_config(&audit_only)
    };
    refused(
        upgrade_initialize(&mut audit_only, table_on_audit_only),
        CustomRingError::PolicyOnAuditOnlyRing,
    );
    let mut audit_only = Ring::new(Setup::AuditOnly);
    let policy = audit_only.roles.policy.pubkey();
    refused(
        audit_only.role_send(
            RingRole::Policy,
            rules_write(&policy, allow_list_table(Vec::new())),
        ),
        CustomRingError::PolicyNotSet,
    );

    let mut ring = Ring::new(Setup::Policy);
    let policy = ring.roles.policy.pubkey();
    let before: RingPolicy = ring.read(&policy_pda());
    let mut own = allow_list_table(Vec::new());
    own.sources[0].source = 1;
    let send = |ring: &mut Ring, instruction| ring.role_send(RingRole::Policy, instruction);
    send(
        &mut ring,
        UpdatePolicyIx {
            authority: policy,
            update: UpdatePolicyIxData::Rules(own),
            trailing: &[RECORDS],
        }
        .instruction(),
    )
    .expect("two pools read one tree");
    let mut unreferenced = allow_list_table(Vec::new());
    unreferenced.sources[0].list_id = ListId::Block as u8;
    refused(
        send(&mut ring, rules_write(&policy, unreferenced)),
        CustomRingError::InvalidSource,
    );
    let mut unsourced = allow_list_table(Vec::new());
    unsourced.sources.clear();
    refused(
        send(&mut ring, rules_write(&policy, unsourced)),
        CustomRingError::InvalidSource,
    );
    send(
        &mut ring,
        rules_write(&policy, allow_list_table(Vec::new())),
    )
    .expect("rewrite the table");
    let after: RingPolicy = ring.read(&policy_pda());
    assert_eq!(after.policy_hash, before.policy_hash);
    assert_eq!(after.generation(), before.generation() + 2);
}

#[test]
fn a_policy_ring_initializes_only_with_its_policy() {
    let mut ring = uninitialized(Setup::Policy);
    let unpinned = InitializeIxData {
        policy: None,
        ..policy_config(&ring)
    };
    refused(
        upgrade_initialize(&mut ring, unpinned),
        CustomRingError::PolicyNotSet,
    );
}

#[test]
fn update_policy_binds_records_late_on_an_audit_only_ring() {
    let mut ring = uninitialized(Setup::AuditOnly);
    let data = audit_only_config(&ring);
    upgrade_initialize(&mut ring, data).expect("the ring starts without records");
    let bind = UpdatePolicyIx {
        authority: ring.roles.policy.pubkey(),
        update: UpdatePolicyIxData::Records,
        trailing: &[RECORDS],
    }
    .instruction();
    ring.role_send(RingRole::Policy, bind)
        .expect("the policy authority binds the records");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.records, RECORDS);
    assert_eq!(account.written_policy_hash(), None);
}

#[test]
fn only_a_policy_ring_needs_a_records_registry() {
    let mut ring = uninitialized(Setup::AnonymousPolicy);
    let data = InitializeIxData {
        kind: Setup::AnonymousPolicy.kind(),
        policy: None,
        ..policy_config(&ring)
    };
    refused(
        upgrade_initialize(&mut ring, data),
        CustomRingError::PolicyNotSet,
    );
    let mut ring = uninitialized(Setup::Anonymous);
    let data = InitializeIxData {
        kind: Setup::Anonymous.kind(),
        policy: None,
        ..policy_config(&ring)
    };
    upgrade_initialize(&mut ring, data).expect("an anonymous ring takes no records");
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.records, Address::default());
    assert!(!account.thresholds_active());
}

/// A shared own registry would fail the second ring for an enrolled owner.
#[test]
fn initialize_refuses_records_of_another_ring() {
    let other_ring = [0x71; 32];
    for setup in [Setup::AuditOnly, Setup::Policy, Setup::Anonymous] {
        for ring_id in [other_ring, [0; 32]] {
            let mut ring = uninitialized(setup);
            let authority = ring.roles.policy.pubkey();
            ring.store_registry_of(ring_id, RECORDS, &authority, &[root(0, [0x0e; 32])]);
            let table = match setup.kind().has_policy() {
                true => allow_list_table(Vec::new()),
                false => PolicyTableIxData {
                    sources: Vec::new(),
                    rules: Vec::new(),
                },
            };
            let data = InitializeIxData {
                kind: setup.kind(),
                policy: Some(PolicyBindingIxData { table }),
                ..policy_config(&ring)
            };
            refused(
                upgrade_initialize(&mut ring, data),
                CustomRingError::RecordsRegistryOtherRing,
            );
        }
    }
}

#[test]
fn the_records_write_refuses_a_registry_of_another_ring() {
    let foreign = Address::new_from_array([0x5e; 32]);
    let mut ring = Ring::new(Setup::Anonymous);
    let authority = ring.roles.policy.pubkey();
    ring.store_registry_of([0x71; 32], foreign, &authority, &[root(0, [0x0e; 32])]);
    let rebind = |records: &[Address]| {
        UpdatePolicyIx {
            authority,
            update: UpdatePolicyIxData::Records,
            trailing: records,
        }
        .instruction()
    };
    refused(
        ring.role_send(RingRole::Policy, rebind(&[foreign])),
        CustomRingError::RecordsRegistryOtherRing,
    );
    // The zero address owns no registry, the write cannot clear an anonymous ring's records.
    refused(
        ring.role_send(RingRole::Policy, rebind(&[Address::default()])),
        CustomRingError::InvalidStorageRegistry,
    );
    refused(
        ring.role_send(RingRole::Policy, rebind(&[])),
        CustomRingError::InvalidStorageRegistry,
    );
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.records, RECORDS);
}

/// A curator source reads list columns, any registry serves.
#[test]
fn a_curator_source_may_name_any_ring_s_registry() {
    let curator = Address::new_from_array([0x5f; 32]);
    let mut ring = Ring::new(Setup::Policy);
    let policy = ring.roles.policy.pubkey();
    ring.store_registry_of([0x71; 32], curator, &policy, &[root(4, [0x0c; 32])]);
    let curated = PolicyTableIxData {
        sources: vec![SourceSpec {
            list_id: ListId::Allow as u8,
            source: 1,
        }],
        ..allow_list_table(Vec::new())
    };
    ring.role_send(
        RingRole::Policy,
        UpdatePolicyIx {
            authority: policy,
            update: UpdatePolicyIxData::Rules(curated),
            trailing: &[curator],
        }
        .instruction(),
    )
    .expect("a foreign ring's registry serves as a curator");
}

struct RoleWrite {
    role: RingRole,
    signer_slot: usize,
    instruction: fn(&Ring, &Address, &Keypair) -> Instruction,
}

const ROLE_WRITES: [RoleWrite; 8] = [
    RoleWrite {
        role: RingRole::Admin,
        signer_slot: 0,
        instruction: |_, signer, other| {
            UpdateAuthorityIx {
                admin: *signer,
                new_key: other.pubkey(),
                role: RingRole::Pauser,
            }
            .instruction()
        },
    },
    RoleWrite {
        role: RingRole::Admin,
        signer_slot: 0,
        instruction: |_, signer, other| set_delegate(signer, &other.pubkey()),
    },
    RoleWrite {
        role: RingRole::Policy,
        signer_slot: 0,
        instruction: |_, signer, _| rules_write(signer, allow_list_table(Vec::new())),
    },
    RoleWrite {
        role: RingRole::Policy,
        signer_slot: 0,
        instruction: |_, signer, _| {
            UpdatePolicyIx {
                authority: *signer,
                update: UpdatePolicyIxData::Source(PolicySourceIxData {
                    list_id: ListId::Allow as u8,
                    source: 0,
                }),
                trailing: &[],
            }
            .instruction()
        },
    },
    RoleWrite {
        role: RingRole::Policy,
        signer_slot: 0,
        instruction: |_, signer, _| {
            UpdatePolicyIx {
                authority: *signer,
                update: UpdatePolicyIxData::Records,
                trailing: &[RECORDS],
            }
            .instruction()
        },
    },
    RoleWrite {
        role: RingRole::Pauser,
        signer_slot: 0,
        instruction: |_, signer, _| set_paused(signer, ring_auth(), SPP),
    },
    RoleWrite {
        role: RingRole::CosignAdmin,
        signer_slot: 1,
        instruction: |ring, signer, _| {
            SetCoSignerIx {
                payer: ring.payer.pubkey(),
                authority: *signer,
                signer: Address::new_from_array([1; 32]),
                scope: 1,
            }
            .instruction()
        },
    },
    RoleWrite {
        role: RingRole::CosignAdmin,
        signer_slot: 0,
        instruction: |ring, signer, _| {
            ClearCoSignerIx {
                authority: *signer,
                signer: Address::new_from_array([1; 32]),
                rent_recipient: ring.payer.pubkey(),
            }
            .instruction()
        },
    },
];

#[test]
fn each_role_instruction_refuses_every_other_role_and_the_upgrade_authority() {
    let mut ring = Ring::new(Setup::Policy);
    set_co_signer(&mut ring, &Address::new_from_array([1; 32]), 1);
    let other = Keypair::new();
    let unauthorized = Err(TransactionError::InstructionError(
        0,
        InstructionError::Custom(CustomRingError::UnauthorizedAuthority as u32),
    ));
    for write in &ROLE_WRITES {
        let wrong = ROLES
            .into_iter()
            .filter(|role| *role != write.role)
            .map(|role| ring.holder(role))
            .chain([ring.authority.insecure_clone()]);
        for signer in wrong.collect::<Vec<_>>() {
            let instruction = (write.instruction)(&ring, &signer.pubkey(), &other);
            assert_eq!(
                instruction.accounts[write.signer_slot].pubkey,
                signer.pubkey()
            );
            let signs_too = instruction
                .accounts
                .iter()
                .any(|meta| meta.pubkey == other.pubkey());
            let signers: Vec<&Keypair> = [&signer]
                .into_iter()
                .chain(signs_too.then_some(&other))
                .collect();
            let sent = ring.send(instruction, &signers).map_err(|(error, _)| error);
            assert_eq!(sent, unauthorized, "{:?} signed by another key", write.role);
        }
    }
}

#[test]
fn update_authority_needs_the_new_keys_signature() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let successor = Keypair::new();
    let admin = ring.holder(RingRole::Admin);
    let handover = |new_key: &Address, role: RingRole, signs: bool| {
        let mut instruction = UpdateAuthorityIx {
            admin: admin.pubkey(),
            new_key: *new_key,
            role,
        }
        .instruction();
        instruction.accounts[1].is_signer = signs;
        instruction
    };
    refused_with(
        ring.send(
            handover(&successor.pubkey(), RingRole::Pauser, false),
            &[&admin],
        ),
        InstructionError::Custom(u32::from(AccountError::InvalidSigner)),
    );
    let mut unknown = handover(&successor.pubkey(), RingRole::Pauser, true);
    unknown.data[1] = ROLES.len() as u8;
    refused(
        ring.send(unknown, &[&admin, &successor]),
        CustomRingError::InvalidInstructionData,
    );
    assert_eq!(
        ring.read::<RingPolicy>(&policy_pda()).roles,
        ring.roles.addresses()
    );
    within_budget(
        InstructionTag::UpdateAuthority,
        ring.send(
            handover(&successor.pubkey(), RingRole::Pauser, true),
            &[&admin, &successor],
        ),
    );
    let mut rotated = ring.roles.addresses();
    rotated.pauser = successor.pubkey();
    assert_eq!(ring.read::<RingPolicy>(&policy_pda()).roles, rotated);
    within_budget(
        InstructionTag::UpdateAuthority,
        ring.send(
            handover(&admin.pubkey(), RingRole::CosignAdmin, true),
            &[&admin],
        ),
    );
    rotated.cosign_admin = admin.pubkey();
    assert_eq!(ring.read::<RingPolicy>(&policy_pda()).roles, rotated);
}

#[test]
fn unknown_tags_are_refused() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let instruction = |data: Vec<u8>| Instruction {
        program_id: PROGRAM,
        accounts: Vec::new(),
        data,
    };
    for unknown in [
        1,
        2,
        4,
        5,
        7,
        8,
        9,
        10,
        12,
        18,
        21,
        22,
        23,
        24,
        26,
        28,
        29,
        30,
        32,
        33,
        38,
        39,
        42,
        u8::MAX,
    ] {
        refused(
            ring.send(instruction(vec![unknown]), &[]),
            CustomRingError::InvalidInstructionData,
        );
    }
}

#[test]
fn operator_instructions_fit_their_declared_budgets() {
    let mut ring = Ring::new(Setup::Policy);
    let (policy, cosign_admin) = (ring.roles.policy.pubkey(), ring.roles.cosign_admin.pubkey());
    let payer = ring.payer.pubkey();
    within_budget(
        InstructionTag::UpdatePolicy,
        ring.role_send(
            RingRole::Policy,
            rules_write(&policy, allow_list_table(Vec::new())),
        ),
    );
    within_budget(
        InstructionTag::SetCoSigner,
        ring.role_send(
            RingRole::CosignAdmin,
            SetCoSignerIx {
                payer,
                authority: cosign_admin,
                signer: Address::new_from_array([1; 32]),
                scope: 4,
            }
            .instruction(),
        ),
    );
}

#[test]
fn initialize_takes_its_canonical_ring_address_once_beside_the_system_program() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let authority = ring.authority.pubkey();
    let again = initialize(&ring, &authority, audit_only_config(&ring));
    refused(
        upgrade_send(&mut ring, again),
        CustomRingError::RingPolicyAlreadyExists,
    );
    let mut elsewhere = initialize(&ring, &authority, audit_only_config(&ring));
    elsewhere.accounts[2] = AccountMeta::new(Address::new_unique(), false);
    refused(
        upgrade_send(&mut ring, elsewhere),
        CustomRingError::InvalidRingPolicy,
    );
    let mut impostor = initialize(&ring, &authority, audit_only_config(&ring));
    impostor.accounts[3] = AccountMeta::new_readonly(Address::new_unique(), false);
    refused(
        upgrade_send(&mut ring, impostor),
        CustomRingError::InvalidSystemProgram,
    );
}

#[test]
fn each_ring_kind_fixes_its_policy_flag_and_mode() {
    for (setup, has_policy, mode) in [
        (Setup::AuditOnly, false, RingMode::Confidential),
        (Setup::Policy, true, RingMode::Confidential),
        (Setup::Anonymous, false, RingMode::Anonymous),
        (Setup::AnonymousPolicy, true, RingMode::Anonymous),
    ] {
        let account: RingPolicy = Ring::new(setup).read(&policy_pda());
        assert_eq!(
            (account.has_policy(), account.mode()),
            (has_policy, Ok(mode))
        );
    }
    let mut ring = uninitialized(Setup::AuditOnly);
    let authority = ring.authority.pubkey();
    let mut unknown = initialize(&ring, &authority, audit_only_config(&ring));
    unknown.data[1 + TAGGED_X25519_KEY_LEN] = 4;
    refused(
        upgrade_send(&mut ring, unknown),
        CustomRingError::InvalidInstructionData,
    );
}

#[test]
fn a_source_write_names_a_known_list() {
    let mut ring = Ring::new(Setup::Policy);
    let policy = ring.roles.policy.pubkey();
    for list_id in [0, u8::MAX] {
        let instruction = UpdatePolicyIx {
            authority: policy,
            update: UpdatePolicyIxData::Source(PolicySourceIxData { list_id, source: 0 }),
            trailing: &[],
        }
        .instruction();
        refused(
            ring.role_send(RingRole::Policy, instruction),
            CustomRingError::InvalidListId,
        );
    }
}

#[test]
fn a_table_write_decodes_and_counts_its_generation_on_the_policy() {
    let mut ring = Ring::new(Setup::Policy);
    let policy = ring.roles.policy.pubkey();
    let send = |ring: &mut Ring, instruction| ring.role_send(RingRole::Policy, instruction);
    let mut malformed = allow_list_table(Vec::new());
    malformed.sources.clear();
    malformed.rules[0] = [0; 32];
    refused(
        send(&mut ring, rules_write(&policy, malformed)),
        CustomRingError::InvalidPolicyRules,
    );
    let mut records_as_ring = rules_write(&policy, allow_list_table(Vec::new()));
    records_as_ring.accounts[1] = AccountMeta::new(RECORDS, false);
    refused(
        send(&mut ring, records_as_ring),
        CustomRingError::InvalidRingPolicy,
    );
    let mut account: RingPolicy = ring.read(&policy_pda());
    account.generation = u32::MAX.to_le_bytes();
    ring.write(&policy_pda(), &account);
    refused(
        send(
            &mut ring,
            rules_write(&policy, allow_list_table(Vec::new())),
        ),
        CustomRingError::PolicyGenerationOverflow,
    );
}

fn set_paused(pauser: &Address, ring_auth: Address, spp: Address) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(*pauser, true),
            AccountMeta::new_readonly(policy_pda(), false),
            AccountMeta::new(ring_auth, false),
            AccountMeta::new_readonly(spp, false),
        ],
        data: [
            &[tag::SET_PAUSED][..],
            &wincode::serialize(&SetPausedIxData { paused: true }).unwrap(),
        ]
        .concat(),
    }
}

#[test]
fn only_the_pauser_pauses_through_the_ring_pda_and_the_pool() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let spp = SPP;
    ring.deploy_stand_in(spp);
    let pauser = ring.roles.pauser.pubkey();
    let no_pool = set_paused(&pauser, ring_auth(), Address::new_unique());
    refused(
        ring.role_send(RingRole::Pauser, no_pool),
        CustomRingError::InvalidShieldedPoolProgram,
    );
    let no_pda = set_paused(&pauser, Address::new_unique(), spp);
    refused(
        ring.role_send(RingRole::Pauser, no_pda),
        CustomRingError::MissingRingAuth,
    );
}

#[test]
fn a_ring_with_an_unknown_mode_reads_as_invalid() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut account: RingPolicy = ring.read(&policy_pda());
    account.mode = 3;
    ring.write(&policy_pda(), &account);
    let policy = ring.roles.policy.pubkey();
    let rules = rules_write(&policy, allow_list_table(Vec::new()));
    refused(
        ring.role_send(RingRole::Policy, rules),
        CustomRingError::InvalidRingPolicy,
    );
}

#[test]
fn an_spp_tag_with_its_forwarded_body_refuses_at_the_ring() {
    use spr_interface::instruction::tag::{RING_AUTHORITY_TRANSACT, RING_MERGE_TRANSACT};

    let mut ring = Ring::new(Setup::Policy);
    let admin = ring.holder(RingRole::Admin);
    let delegate = Keypair::new();
    let mut merge = set_delegate(&admin.pubkey(), &delegate.pubkey());
    merge.data = vec![RING_MERGE_TRANSACT, 1, 2, 3];
    refused(
        ring.send(merge, &[&admin, &delegate]),
        CustomRingError::InvalidInstructionData,
    );
    let cosigner = Address::new_from_array([1; 32]);
    set_co_signer(&mut ring, &cosigner, 4);
    let authority = ring.holder(RingRole::CosignAdmin);
    let mut transact = ClearCoSignerIx {
        authority: authority.pubkey(),
        signer: cosigner,
        rent_recipient: authority.pubkey(),
    }
    .instruction();
    transact.data = vec![RING_AUTHORITY_TRANSACT, 1, 2, 3];
    refused(
        ring.send(transact, &[&authority]),
        CustomRingError::InvalidInstructionData,
    );
}
