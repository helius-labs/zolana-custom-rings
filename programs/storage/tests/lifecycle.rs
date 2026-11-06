use bytemuck::Zeroable;
use custom_ring_interface::{
    key_catalog::{ApplyMode, RingCircuit},
    mint_policy_write,
    owner_grant::OwnerGrant,
    storage::{RegistryId, Revision, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{
        tag, ApplyEnrollmentsIxData, EnrollIxData, EnrollRequest, InitializeIxData,
        InitializeTrackingIxData, OwnerGrantIxData, StorageUpdateIxData,
    },
    tagged_x25519,
    tracking::{
        FirstEnrollment, TrackingAuthorization, TrackingRegistry, TRACKING_CAPACITY,
        TRACKING_EMPTY_ROOT, ZERO_NULLIFIER_PUBKEY,
    },
    verifying_key, ApplyRecordsIxData, CustomRingProof, PlainGroth16Proof, RecordWriteData,
    WriteRecordsIxData, READER_KEY_ED25519, ROOT_HISTORY, TAGGED_X25519_KEY_LEN,
    VIEWING_PUBKEY_TAG,
};
use litesvm::LiteSVM;
use serde_json::Value;
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use spr_client::{
    compile_message,
    prover::{Proof, ProofCompressed},
    sign_transaction, ComputeBudgetConfig,
};
use zolana_ring_policy::{ListId, ListSet};

const PROGRAM: Address = custom_ring_interface::STORAGE_PROGRAM_ID;
const GRACE: u64 = 10;
const REGISTRY_ID: RegistryId = RegistryId([1; 32]);
const CURATOR_ID: RegistryId = RegistryId([2; 32]);
const PRIVATE_ID: RegistryId = RegistryId([3; 32]);
const RING_ID: [u8; 32] = [7; 32];
const SYSTEM: Address = Address::new_from_array([0; 32]);
/// Any address serves the CPI owner.
const CPI_OWNER_PROGRAM: Address = Address::new_from_array([0x63; 32]);

fn auditor() -> [u8; TAGGED_X25519_KEY_LEN] {
    let mut key = [9; TAGGED_X25519_KEY_LEN];
    key[0] = VIEWING_PUBKEY_TAG;
    key
}

fn enroll_ix(viewing_u: [u8; 32]) -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: [3; 32],
        list_tag: [4; 32],
        viewing_u,
        eph_u: [5; 32],
        ciphertext: [6; 64],
    }
}

struct Store {
    svm: LiteSVM,
    authority: Keypair,
    payer: Keypair,
    registry: Address,
    tracking: Address,
    proofs: Value,
}

impl Store {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.warp_to_slot(0);
        svm.add_program(
            PROGRAM,
            &std::fs::read(deploy_dir().join("storage_program.so")).unwrap(),
        )
        .unwrap();
        let authority = Keypair::new_from_array([9; 32]);
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        let registry = StorageRegistry::find_address(&authority.pubkey(), &REGISTRY_ID).0;
        let tracking = TrackingRegistry::find_address(&authority.pubkey(), &RING_ID).0;
        let proofs: Value = serde_json::from_str(include_str!("proofs.json")).unwrap();
        // The apply proofs bind the registry address.
        assert_eq!(hex::encode(registry), proofs["registry"].as_str().unwrap());
        Self {
            svm,
            authority,
            payer,
            registry,
            tracking,
            proofs,
        }
    }

    fn initialize(&mut self, grace_slots: u64) {
        let (registry, data) = (
            self.registry,
            InitializeIxData {
                registry_id: REGISTRY_ID,
                grace_slots: grace_slots.to_le_bytes(),
                ring_id: RING_ID,
                tracking_registry: Address::default(),
            },
        );
        self.send_as_authority(self.initialize_instruction(registry, &data))
            .unwrap();
    }

    /// A source a salted list may read, `ring_id` zero makes it a curator's.
    fn initialize_pinned(&mut self, registry_id: RegistryId, ring_id: [u8; 32]) -> Address {
        let source = StorageRegistry::find_address(&self.authority.pubkey(), &registry_id).0;
        let data = InitializeIxData {
            registry_id,
            grace_slots: GRACE.to_le_bytes(),
            ring_id,
            tracking_registry: self.tracking,
        };
        self.send_as_authority(self.initialize_instruction(source, &data))
            .unwrap();
        source
    }

    fn initialize_instruction(&self, registry: Address, data: &InitializeIxData) -> Instruction {
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::INITIALIZE], bytemuck::bytes_of(data)].concat(),
        }
    }

    fn initialize_tracking_instruction(&self, data: &InitializeTrackingIxData) -> Instruction {
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(
                    TrackingRegistry::find_address(&self.authority.pubkey(), &data.ring_id).0,
                    false,
                ),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::INITIALIZE_TRACKING], bytemuck::bytes_of(data)].concat(),
        }
    }

    fn initialize_tracking(&mut self) {
        let data = InitializeTrackingIxData {
            ring_id: RING_ID,
            auditor_pubkey: auditor(),
        };
        self.send_as_authority(self.initialize_tracking_instruction(&data))
            .unwrap();
    }

    fn enroll(
        &self,
        owner: &Address,
        ix: &EnrollIxData,
        proof: Option<&CustomRingProof>,
    ) -> Instruction {
        let tracking = self.tracking;
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(tracking, false),
                AccountMeta::new(
                    TrackingAuthorization::find_address(&tracking, owner).0,
                    false,
                ),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::ENROLL][..], &EnrollRequest { ix, proof }.encode()].concat(),
        }
    }

    /// An enrollment the program could only create with a real proof, written directly.
    fn seed_enrollment(&mut self, owner: &Address) -> AccountMeta {
        let (address, _) = TrackingAuthorization::find_address(&self.tracking, owner);
        let account = FirstEnrollment {
            registry: self.tracking,
            owner: *owner,
            ix: &enroll_ix([8; 32]),
        }
        .account();
        self.seed(address, bytemuck::bytes_of(&account));
        AccountMeta::new(address, false)
    }

    fn seed(&mut self, address: Address, data: &[u8]) {
        let mut account = self.svm.get_account(&self.payer.pubkey()).unwrap();
        account.lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        account.data = data.to_vec();
        account.owner = PROGRAM;
        self.svm.set_account(address, account).unwrap();
    }

    fn apply_enrollments(&self, revision: u64, authorizations: &[AccountMeta]) -> Instruction {
        self.apply_enrollments_to(revision, 2, authorizations)
    }

    fn apply_enrollments_to(
        &self,
        revision: u64,
        new_next_index: u64,
        authorizations: &[AccountMeta],
    ) -> Instruction {
        let data = ApplyEnrollmentsIxData {
            revision: revision.into(),
            proof: CustomRingProof::zeroed(),
            new_root: [8; 32],
            new_next_index: new_next_index.to_le_bytes(),
        };
        Instruction {
            program_id: PROGRAM,
            accounts: [
                vec![AccountMeta::new(self.tracking, false)],
                authorizations.to_vec(),
            ]
            .concat(),
            data: [&[tag::APPLY_ENROLLMENTS], bytemuck::bytes_of(&data)].concat(),
        }
    }

    fn grant(&self, owner: &Address, reader: [u8; 34], active: u8) -> Instruction {
        let data = OwnerGrantIxData { reader, active };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(self.tracking, false),
                AccountMeta::new(
                    OwnerGrant::find_address(&self.tracking, owner, &reader).0,
                    false,
                ),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::OWNER_GRANT], bytemuck::bytes_of(&data)].concat(),
        }
    }

    /// An update at `revision` past every check ahead of the proof, the zero proof fails there.
    fn zero_proof_update(&self, revision: u64, list: ListId) -> Instruction {
        self.zero_proof_update_of(self.registry, revision, list)
    }

    /// A private list names the tracking revision zero and the pinned registry after the source.
    fn zero_proof_update_of(&self, registry: Address, revision: u64, list: ListId) -> Instruction {
        let apply = ApplyRecordsIxData {
            new_root: [8; 32],
            new_next_index: 2u32.to_le_bytes(),
            ..ApplyRecordsIxData::zeroed()
        };
        let private = ListSet::PRIVATE_LISTS.contains(list);
        let data = StorageUpdateIxData {
            revision: revision.into(),
            writes: vec![RecordWriteData {
                member: allow_write().member,
                lists: WriteRecordsIxData {
                    mask: list.record_bit().to_le_bytes(),
                    value: list.record_bit().to_le_bytes(),
                },
                mint_policy: mint_policy_write(None),
            }],
            asset_writes: Vec::new(),
            tracking_revision: private.then(Revision::default),
            apply: &apply,
        };
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority.pubkey(), true),
            AccountMeta::new(registry, false),
        ];
        if private {
            accounts.push(AccountMeta::new_readonly(self.tracking, false));
        }
        Instruction {
            program_id: PROGRAM,
            accounts,
            data: [vec![tag::UPDATE], data.encode().unwrap()].concat(),
        }
    }

    fn private_update(&self, registry: Address) -> Instruction {
        self.zero_proof_update_of(registry, 0, ListId::PrivateBlock)
    }

    fn update(&self, revision: u64) -> Instruction {
        let vector = &self.proofs[format!("update{revision}")];
        let writes = vector["writes"]
            .as_array()
            .unwrap()
            .iter()
            .map(write)
            .collect::<Vec<_>>();
        let apply = ApplyRecordsIxData {
            proof: proof(vector),
            new_root: field(&vector["root"]),
            new_next_index: u32::try_from(vector["nextIndex"].as_u64().unwrap())
                .unwrap()
                .to_le_bytes(),
            restrictive: u8::from(vector["restrictive"].as_bool().unwrap()),
        };
        let data = StorageUpdateIxData {
            revision: revision.into(),
            writes,
            asset_writes: Vec::new(),
            tracking_revision: None,
            apply: &apply,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
            ],
            data: [vec![tag::UPDATE], data.encode().unwrap()].concat(),
        }
    }

    fn update_authority(&self, authority: &Keypair, new_authority: &Keypair) -> Instruction {
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(new_authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
            ],
            data: vec![tag::UPDATE_AUTHORITY],
        }
    }

    fn registry(&self) -> StorageRegistry {
        *bytemuck::from_bytes(&self.svm.get_account(&self.registry).unwrap().data)
    }

    fn tracking_registry(&self) -> TrackingRegistry {
        *bytemuck::from_bytes(&self.svm.get_account(&self.tracking).unwrap().data)
    }

    fn set_tracking_registry(&mut self, registry: &TrackingRegistry) {
        self.seed(self.tracking, bytemuck::bytes_of(registry));
    }

    fn authorization(&self, owner: &Address) -> TrackingAuthorization {
        let address = TrackingAuthorization::find_address(&self.tracking, owner).0;
        *bytemuck::from_bytes(&self.svm.get_account(&address).unwrap().data)
    }

    fn root(&self, revision: u64) -> Result<[u8; 32], StorageError> {
        self.registry().root(
            Revision::from(revision),
            self.svm.get_sysvar::<solana_clock::Clock>().slot,
        )
    }

    fn send_as_authority(&mut self, instruction: Instruction) -> Result<(), TransactionError> {
        let authority = self.authority.insecure_clone();
        self.send(instruction, &[&authority])
    }

    fn send(
        &mut self,
        instruction: Instruction,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let signers = [&self.payer]
            .into_iter()
            .chain(signers.iter().copied())
            .map(|signer| signer as &dyn Signer)
            .collect::<Vec<_>>();
        let message = compile_message(
            &self.payer.pubkey(),
            &[instruction],
            self.svm.latest_blockhash(),
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap();
        let transaction = sign_transaction(message, &signers).unwrap();
        self.svm
            .send_transaction(transaction)
            .map(|_| ())
            .map_err(|failed| failed.err)
    }

    fn add_cpi_owner(&mut self) -> Address {
        self.svm
            .add_program(
                CPI_OWNER_PROGRAM,
                &std::fs::read(deploy_dir().join("storage_cpi_owner.so")).unwrap(),
            )
            .unwrap();
        Address::find_program_address(&[b"owner"], &CPI_OWNER_PROGRAM).0
    }
}

fn deploy_dir() -> std::path::PathBuf {
    std::env::var_os("SBF_OUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into())
}

/// Forwards `instruction` through the CPI owner, the owner signs its PDA.
fn through_cpi_owner(mut instruction: Instruction) -> Instruction {
    instruction.program_id = CPI_OWNER_PROGRAM;
    instruction.accounts[1].is_signer = false;
    instruction
        .accounts
        .push(AccountMeta::new_readonly(PROGRAM, false));
    instruction
}

/// A zero proof's refusal, a circuit with no key yet refuses earlier and never passes.
fn key_refusal(circuit: RingCircuit) -> StorageError {
    match verifying_key(circuit) {
        Some(_) => StorageError::ProofVerificationFailed,
        None => StorageError::UnsupportedBatch,
    }
}

fn allow_write() -> RecordWriteData {
    RecordWriteData {
        member: [1; 32],
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        mint_policy: mint_policy_write(None),
    }
}

fn refusal(code: impl Into<pinocchio::error::ProgramError>) -> Result<(), TransactionError> {
    let pinocchio::error::ProgramError::Custom(code) = code.into() else {
        panic!("expected a custom error");
    };
    Err(TransactionError::InstructionError(
        0,
        InstructionError::Custom(code),
    ))
}

fn write(entry: &Value) -> RecordWriteData {
    RecordWriteData {
        member: field(&entry["member"]),
        lists: WriteRecordsIxData {
            mask: entry["mask"].as_u64().unwrap().to_le_bytes(),
            value: entry["value"].as_u64().unwrap().to_le_bytes(),
        },
        mint_policy: mint_policy_write(None),
    }
}

fn field(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn proof(vector: &Value) -> CustomRingProof {
    let compressed =
        ProofCompressed::try_from(Proof::from_gnark_json(&vector["proof"].to_string()).unwrap())
            .unwrap();
    let commitment = compressed.commitment.unwrap();
    CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: compressed.a,
            proof_b: compressed.compressed_b().unwrap(),
            proof_c: compressed.c,
        },
        commitment: commitment.commitment,
        commitment_pok: commitment.commitment_pok,
    }
}

#[test]
fn authority_rotates_and_the_old_authority_is_refused() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let old = store.authority.insecure_clone();
    let new = Keypair::new();
    store
        .send(store.update_authority(&old, &new), &[&old, &new])
        .unwrap();
    assert_eq!(
        store.send(store.update_authority(&old, &old), &[&old]),
        refusal(StorageError::Unauthorized)
    );
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Reader)),
        refusal(StorageError::Unauthorized)
    );
    let mut update = store.zero_proof_update(0, ListId::Reader);
    update.accounts[0].pubkey = new.pubkey();
    assert_eq!(
        store.send(update, &[&new]),
        refusal(StorageError::ProofVerificationFailed)
    );
}

#[test]
fn unknown_tags_are_refused() {
    let mut store = Store::new();
    store.initialize(GRACE);
    for unknown in [2, 3, 5, 10] {
        let mut instruction = store.zero_proof_update(0, ListId::Block);
        instruction.data[0] = unknown;
        assert_eq!(
            store.send_as_authority(instruction),
            refusal(StorageError::InvalidInstructionData)
        );
    }
}

#[test]
fn an_update_reaches_the_proof_past_its_revision_and_authority() {
    let mut store = Store::new();
    store.initialize(GRACE);
    for list in [ListId::Reader, ListId::Block] {
        assert_eq!(
            store.send_as_authority(store.zero_proof_update(0, list)),
            refusal(StorageError::ProofVerificationFailed)
        );
    }
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(1, ListId::Reader)),
        refusal(StorageError::RevisionChanged)
    );
    let mut wrong_authority = store.zero_proof_update(0, ListId::Reader);
    wrong_authority.accounts[0].pubkey = store.payer.pubkey();
    assert_eq!(
        store.send(wrong_authority, &[]),
        refusal(StorageError::Unauthorized)
    );
}

/// A full history lets a graced update reach its proof, a failed proof writes nothing.
#[test]
fn a_failed_proof_leaves_the_full_history_unchanged() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut full = store.registry();
    full.roots[ROOT_HISTORY - 1].expires_at = GRACE.to_le_bytes();
    store.seed(store.registry, bytemuck::bytes_of(&full));
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Reader)),
        refusal(StorageError::ProofVerificationFailed)
    );
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Block)),
        refusal(StorageError::ProofVerificationFailed)
    );
    store.svm.warp_to_slot(GRACE);
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Reader)),
        refusal(StorageError::ProofVerificationFailed)
    );
    assert_eq!(store.registry(), full);
}

#[test]
fn a_tracking_registry_pins_ring_and_auditor_at_its_canonical_address() {
    let mut store = Store::new();
    store.initialize_tracking();
    let registry = store.tracking_registry();
    assert_eq!(registry.ring_id, RING_ID);
    assert_eq!(registry.auditor_pubkey, auditor());
    assert_eq!(registry.newest().hash, TRACKING_EMPTY_ROOT);
    assert_eq!(registry.next_index(), 1);
    let data = InitializeTrackingIxData {
        ring_id: RING_ID,
        auditor_pubkey: auditor(),
    };
    assert_eq!(
        store.send_as_authority(store.initialize_tracking_instruction(&data)),
        refusal(StorageError::AlreadyInitialized)
    );
    let mut unsigned = store.initialize_tracking_instruction(&data);
    unsigned.accounts[1].is_signer = false;
    assert_eq!(
        store.send(unsigned, &[]),
        refusal(StorageError::MissingSignature)
    );
    let other = InitializeTrackingIxData {
        ring_id: [8; 32],
        ..data
    };
    let mut misplaced = store.initialize_tracking_instruction(&other);
    misplaced.accounts[2].pubkey = store.tracking;
    assert_eq!(
        store.send_as_authority(misplaced),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    let untagged = InitializeTrackingIxData {
        ring_id: [8; 32],
        auditor_pubkey: [9; TAGGED_X25519_KEY_LEN],
    };
    assert_eq!(
        store.send_as_authority(store.initialize_tracking_instruction(&untagged)),
        refusal(StorageError::InvalidAuditorKey)
    );
    let mut low_order_u = [0; 32];
    low_order_u[0] = 1;
    let low_order = InitializeTrackingIxData {
        ring_id: [8; 32],
        auditor_pubkey: tagged_x25519(&low_order_u),
    };
    assert_eq!(
        store.send_as_authority(store.initialize_tracking_instruction(&low_order)),
        refusal(StorageError::InvalidAuditorKey)
    );
}

#[test]
fn a_first_enrollment_needs_the_owner_and_a_proof_the_pairing_accepts() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = Keypair::new();
    let proof = CustomRingProof::zeroed();
    let ix = enroll_ix([8; 32]);
    let mut unsigned = store.enroll(&owner.pubkey(), &ix, Some(&proof));
    unsigned.accounts[1].is_signer = false;
    assert_eq!(
        store.send(unsigned, &[]),
        refusal(StorageError::MissingSignature)
    );
    assert_eq!(
        store.send(store.enroll(&owner.pubkey(), &ix, None), &[&owner]),
        refusal(StorageError::EnrollmentProofShape)
    );
    assert_eq!(
        store.send(store.enroll(&owner.pubkey(), &ix, Some(&proof)), &[&owner]),
        refusal(StorageError::ProofVerificationFailed)
    );
    let address = TrackingAuthorization::find_address(&store.tracking, &owner.pubkey()).0;
    assert!(store
        .svm
        .get_account(&address)
        .is_none_or(|account| account.data.is_empty()));
    assert_eq!(
        store.send(
            store.enroll(
                &owner.pubkey(),
                &EnrollIxData {
                    nullifier_pk: ZERO_NULLIFIER_PUBKEY,
                    ..ix
                },
                Some(&proof)
            ),
            &[&owner]
        ),
        refusal(StorageError::ZeroNullifierKey)
    );
    assert_eq!(
        store.send(
            store.enroll(&owner.pubkey(), &enroll_ix([0; 32]), Some(&proof)),
            &[&owner]
        ),
        refusal(StorageError::NonCanonicalViewingKey)
    );
}

#[test]
fn a_first_enrollment_refuses_a_registry_that_is_no_tracking_registry() {
    let mut store = Store::new();
    store.initialize(GRACE);
    store.initialize_tracking();
    let owner = Keypair::new();
    let proof = CustomRingProof::zeroed();
    let ix = enroll_ix([8; 32]);
    let mut policy = store.enroll(&owner.pubkey(), &ix, Some(&proof));
    policy.accounts[2].pubkey = store.registry;
    assert_eq!(
        store.send(policy, &[&owner]),
        refusal(StorageError::InvalidTrackingRegistry)
    );
}

/// The runtime sets the signer flag a program's `invoke_signed` raises, one code path.
#[test]
fn a_program_owner_reaches_the_proof_through_cpi() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = store.add_cpi_owner();
    let proof = CustomRingProof::zeroed();
    let instruction = store.enroll(&owner, &enroll_ix([8; 32]), Some(&proof));
    assert_eq!(
        store.send(through_cpi_owner(instruction), &[]),
        refusal(StorageError::ProofVerificationFailed)
    );
    store.seed_enrollment(&owner);
    let rotation = store.enroll(&owner, &enroll_ix([9; 32]), None);
    store.send(through_cpi_owner(rotation), &[]).unwrap();
    assert_eq!(store.authorization(&owner).viewing_u, [9; 32]);
}

#[test]
fn a_rotation_moves_the_viewing_key_with_no_proof() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = Keypair::new();
    store.seed_enrollment(&owner.pubkey());
    let rotated = enroll_ix([9; 32]);
    let rotate = |store: &Store, ix: &EnrollIxData| store.enroll(&owner.pubkey(), ix, None);
    let proof = CustomRingProof::zeroed();
    assert_eq!(
        store.send(
            store.enroll(&owner.pubkey(), &rotated, Some(&proof)),
            &[&owner]
        ),
        refusal(StorageError::EnrollmentProofShape)
    );
    for changed in [
        EnrollIxData {
            nullifier_pk: [1; 32],
            ..rotated
        },
        EnrollIxData {
            ciphertext: [1; 64],
            ..rotated
        },
        EnrollIxData {
            list_tag: [1; 32],
            ..rotated
        },
    ] {
        assert_eq!(
            store.send(rotate(&store, &changed), &[&owner]),
            refusal(StorageError::EnrollmentKeyFinal)
        );
    }
    let tracking = store.tracking_registry();
    store.send(rotate(&store, &rotated), &[&owner]).unwrap();
    let account = store.authorization(&owner.pubkey());
    assert_eq!((account.viewing_u, account.applied), ([9; 32], 0));
    // An applied owner stays applied, the rotation leaves no tracking work and no new root.
    let mut applied = account;
    applied.applied = 1;
    store.seed(
        TrackingAuthorization::find_address(&store.tracking, &owner.pubkey()).0,
        bytemuck::bytes_of(&applied),
    );
    store
        .send(rotate(&store, &enroll_ix([7; 32])), &[&owner])
        .unwrap();
    let account = store.authorization(&owner.pubkey());
    assert_eq!((account.viewing_u, account.applied), ([7; 32], 1));
    assert!(!account.is_pending());
    assert_eq!(store.tracking_registry(), tracking);
}

#[test]
fn a_rotation_refuses_another_owner_and_another_registry() {
    let mut store = Store::new();
    store.initialize_tracking();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let meta = store.seed_enrollment(&owner.pubkey());
    let stranger = Keypair::new();
    let mut foreign = store.enroll(&stranger.pubkey(), &enroll_ix([9; 32]), None);
    foreign.accounts[3] = meta.clone();
    assert_eq!(
        store.send(foreign, &[&stranger]),
        refusal(StorageError::InvalidTrackingAuthorization)
    );
    let mut other_registry = store.enroll(&owner.pubkey(), &enroll_ix([9; 32]), None);
    other_registry.accounts[2].pubkey = store.registry;
    assert_eq!(
        store.send(other_registry, &[&owner]),
        refusal(StorageError::InvalidTrackingAuthorization)
    );
    let mut unsigned = store.enroll(&owner.pubkey(), &enroll_ix([9; 32]), None);
    unsigned.accounts[1].is_signer = false;
    assert_eq!(
        store.send(unsigned, &[]),
        refusal(StorageError::MissingSignature)
    );
}

/// No entry blocks another, a leaf past capacity stays pending and grants nothing.
#[test]
fn a_full_tree_leaves_enrollment_open_and_still_rotates() {
    let mut store = Store::new();
    store.initialize_tracking();
    let enrolled = Keypair::new();
    store.seed_enrollment(&enrolled.pubkey());
    let mut full = store.tracking_registry();
    full.next_index = TRACKING_CAPACITY.to_le_bytes();
    store.set_tracking_registry(&full);
    let stranger = Keypair::new();
    let proof = CustomRingProof::zeroed();
    assert_eq!(
        store.send(
            store.enroll(&stranger.pubkey(), &enroll_ix([8; 32]), Some(&proof)),
            &[&stranger]
        ),
        refusal(StorageError::ProofVerificationFailed)
    );
    store
        .send(
            store.enroll(&enrolled.pubkey(), &enroll_ix([9; 32]), None),
            &[&enrolled],
        )
        .unwrap();
}

/// The chain and the applied revision run ahead of the proof, past them only a key is missing.
fn past_every_apply_check(store: &mut Store, instruction: Instruction, count: u64) {
    let expected = key_refusal(RingCircuit::apply_enrollments(count));
    assert_eq!(store.send(instruction, &[]), refusal(expected));
}

#[test]
fn anyone_applies_named_enrollments_with_no_authority_signature() {
    let mut store = Store::new();
    store.initialize_tracking();
    let [first, second] = [Keypair::new(), Keypair::new()];
    let metas = [
        store.seed_enrollment(&first.pubkey()),
        store.seed_enrollment(&second.pubkey()),
    ];
    let instruction = store.apply_enrollments(0, &metas);
    past_every_apply_check(&mut store, instruction, 2);
    // In any order, no entry blocks another.
    let reversed = [metas[1].clone(), metas[0].clone()];
    let instruction = store.apply_enrollments(0, &reversed);
    past_every_apply_check(&mut store, instruction, 2);
    assert!(store.authorization(&first.pubkey()).is_pending());
}

#[test]
fn an_apply_refuses_what_it_cannot_chain() {
    let mut store = Store::new();
    store.initialize_tracking();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let meta = store.seed_enrollment(&owner.pubkey());
    assert_eq!(
        store.send(store.apply_enrollments(0, &[]), &[]),
        refusal(StorageError::NoEnrollmentsNamed)
    );
    assert_eq!(
        store.send(
            store.apply_enrollments(0, &[meta.clone(), meta.clone()]),
            &[]
        ),
        refusal(StorageError::EnrollmentAlreadyApplied)
    );
    assert_eq!(
        store.send(store.apply_enrollments(1, std::slice::from_ref(&meta)), &[]),
        refusal(StorageError::RevisionChanged)
    );
    let read_only = AccountMeta::new_readonly(meta.pubkey, false);
    assert_eq!(
        store.send(store.apply_enrollments(0, &[read_only]), &[]),
        refusal(StorageError::InvalidTrackingAuthorization)
    );
    let not_one = AccountMeta::new(store.registry, false);
    assert_eq!(
        store.send(store.apply_enrollments(0, &[not_one]), &[]),
        refusal(StorageError::InvalidTrackingAuthorization)
    );
    let too_many = (0..17)
        .map(|_| {
            let owner = Keypair::new();
            store.seed_enrollment(&owner.pubkey())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        store.send(store.apply_enrollments(0, &too_many), &[]),
        refusal(StorageError::BatchTooLarge)
    );
    let mut policy = store.apply_enrollments(0, std::slice::from_ref(&meta));
    policy.accounts[0].pubkey = store.registry;
    assert_eq!(
        store.send(policy, &[]),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    let mut applied = store.authorization(&owner.pubkey());
    applied.applied = 1;
    store.seed(meta.pubkey, bytemuck::bytes_of(&applied));
    assert_eq!(
        store.send(store.apply_enrollments(0, &[meta]), &[]),
        refusal(StorageError::EnrollmentAlreadyApplied)
    );
}

#[test]
fn an_authorization_of_another_registry_does_not_apply() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = Keypair::new();
    let meta = store.seed_enrollment(&owner.pubkey());
    let mut foreign = store.authorization(&owner.pubkey());
    foreign.registry = Address::new_from_array([1; 32]);
    store.seed(meta.pubkey, bytemuck::bytes_of(&foreign));
    assert_eq!(
        store.send(store.apply_enrollments(0, &[meta]), &[]),
        refusal(StorageError::InvalidTrackingAuthorization)
    );
}

/// An apply that would evict an unexpired root waits, its accounts stay pending until the oldest root expires.
#[test]
fn an_apply_over_unexpired_roots_waits_until_the_oldest_expires() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = Keypair::new();
    let meta = store.seed_enrollment(&owner.pubkey());
    let expiry = store.svm.get_sysvar::<solana_clock::Clock>().slot + 10;
    let mut registry = store.tracking_registry();
    registry.roots[ROOT_HISTORY - 1].hash = [5; 32];
    registry.roots[ROOT_HISTORY - 1].expires_at = expiry.to_le_bytes();
    store.set_tracking_registry(&registry);
    assert_eq!(
        store.send(store.apply_enrollments(0, std::slice::from_ref(&meta)), &[]),
        refusal(StorageError::RootHistoryRetained)
    );
    assert_eq!(store.tracking_registry(), registry);
    assert!(store.authorization(&owner.pubkey()).is_pending());
    store.svm.warp_to_slot(expiry);
    let instruction = store.apply_enrollments(0, &[meta]);
    past_every_apply_check(&mut store, instruction, 1);
    assert_eq!(store.tracking_registry(), registry);
}

/// The leaf at index 2^32 - 1 is the last one a path opens, an apply past it names no leaf.
#[test]
fn an_apply_past_two_to_the_thirty_two_leaves_is_refused() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = Keypair::new();
    let meta = store.seed_enrollment(&owner.pubkey());
    let before = store.tracking_registry();
    assert_eq!(
        store.send(
            store.apply_enrollments_to(0, TRACKING_CAPACITY + 1, std::slice::from_ref(&meta)),
            &[]
        ),
        refusal(StorageError::TrackingTreeFull)
    );
    assert_eq!(store.tracking_registry(), before);
    let instruction = store.apply_enrollments_to(0, TRACKING_CAPACITY, &[meta]);
    past_every_apply_check(&mut store, instruction, 1);
}

fn reader(byte: u8) -> [u8; 34] {
    let mut key = [byte; 34];
    key[0] = READER_KEY_ED25519;
    key
}

#[test]
fn an_owner_grants_and_revokes_a_reader_alone() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = Keypair::new();
    let granted = reader(7);
    store
        .send(store.grant(&owner.pubkey(), granted, 1), &[&owner])
        .unwrap();
    let (address, _) = OwnerGrant::find_address(&store.tracking, &owner.pubkey(), &granted);
    let read = |store: &Store| {
        let account = store.svm.get_account(&address).unwrap();
        OwnerGrant::decode(&account.owner, &account.data).unwrap()
    };
    assert!(read(&store).is_active());
    store
        .send(store.grant(&owner.pubkey(), granted, 0), &[&owner])
        .unwrap();
    assert!(!read(&store).is_active());
    store
        .send(store.grant(&owner.pubkey(), granted, 1), &[&owner])
        .unwrap();
    assert!(read(&store).is_active());
}

#[test]
fn a_grant_refuses_a_stranger_and_a_malformed_reader() {
    let mut store = Store::new();
    store.initialize_tracking();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let mut unsigned = store.grant(&owner.pubkey(), reader(7), 1);
    unsigned.accounts[1].is_signer = false;
    assert_eq!(
        store.send(unsigned, &[]),
        refusal(StorageError::MissingSignature)
    );
    let stranger = Keypair::new();
    let mut foreign = store.grant(&stranger.pubkey(), reader(7), 1);
    foreign.accounts[3].pubkey =
        OwnerGrant::find_address(&store.tracking, &owner.pubkey(), &reader(7)).0;
    assert_eq!(
        store.send(foreign, &[&stranger]),
        refusal(StorageError::InvalidOwnerGrant)
    );
    let mut unknown_scheme = reader(7);
    unknown_scheme[0] = 9;
    assert_eq!(
        store.send(store.grant(&owner.pubkey(), unknown_scheme, 1), &[&owner]),
        refusal(StorageError::InvalidReaderKey)
    );
    assert_eq!(
        store.send(store.grant(&owner.pubkey(), reader(7), 2), &[&owner]),
        refusal(StorageError::InvalidInstructionData)
    );
    let mut policy = store.grant(&owner.pubkey(), reader(7), 1);
    policy.accounts[2].pubkey = store.registry;
    assert_eq!(
        store.send(policy, &[&owner]),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    let mut grant_at_registry = store.grant(&owner.pubkey(), reader(7), 1);
    grant_at_registry.accounts[3].pubkey = store.registry;
    assert_eq!(
        store.send(grant_at_registry, &[&owner]),
        refusal(StorageError::InvalidOwnerGrant)
    );
}

/// A grant address names one tracking registry, another registry's grant is a separate account.
#[test]
fn owner_grants_are_bound_to_their_tracking_registry() {
    let mut store = Store::new();
    store.initialize_tracking();
    let other = InitializeTrackingIxData {
        ring_id: [8; 32],
        auditor_pubkey: auditor(),
    };
    store
        .send_as_authority(store.initialize_tracking_instruction(&other))
        .unwrap();
    let other_registry = TrackingRegistry::find_address(&store.authority.pubkey(), &[8; 32]).0;
    let owner = Keypair::new();
    let mut crossed = store.grant(&owner.pubkey(), reader(7), 1);
    crossed.accounts[2].pubkey = other_registry;
    assert_eq!(
        store.send(crossed, &[&owner]),
        refusal(StorageError::InvalidOwnerGrant)
    );
    store
        .send(store.grant(&owner.pubkey(), reader(7), 1), &[&owner])
        .unwrap();
    let other_grant = OwnerGrant::find_address(&other_registry, &owner.pubkey(), &reader(7)).0;
    assert!(store.svm.get_account(&other_grant).is_none());
}

#[test]
fn a_program_owner_writes_its_grant_through_cpi() {
    let mut store = Store::new();
    store.initialize_tracking();
    let owner = store.add_cpi_owner();
    let instruction = store.grant(&owner, reader(7), 1);
    store.send(through_cpi_owner(instruction), &[]).unwrap();
    let address = OwnerGrant::find_address(&store.tracking, &owner, &reader(7)).0;
    let account = store.svm.get_account(&address).unwrap();
    assert!(OwnerGrant::decode(&account.owner, &account.data)
        .unwrap()
        .is_active());
}

#[test]
fn a_curator_initializes_without_a_ring() {
    let mut store = Store::new();
    let curator = StorageRegistry::find_address(&store.authority.pubkey(), &CURATOR_ID).0;
    let data = InitializeIxData {
        registry_id: CURATOR_ID,
        grace_slots: GRACE.to_le_bytes(),
        ring_id: [0; 32],
        tracking_registry: Address::default(),
    };
    store
        .send_as_authority(store.initialize_instruction(curator, &data))
        .unwrap();
    assert_eq!(
        store.send_as_authority(store.initialize_instruction(curator, &data)),
        refusal(StorageError::AlreadyInitialized)
    );
}

#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn record_writes_apply_with_a_real_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    store.send_as_authority(store.update(0)).unwrap();
    store.send_as_authority(store.update(1)).unwrap();
    assert_eq!(store.root(1), Err(StorageError::RootExpired));
    // The approval grant tightens nothing and keeps the block list root served.
    store.send_as_authority(store.update(2)).unwrap();
    assert_eq!(store.root(3), Ok(field(&store.proofs["update2"]["root"])));
    assert_eq!(store.root(2), Ok(field(&store.proofs["update1"]["root"])));
}

#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn a_block_list_addition_claimed_permissive_fails_the_real_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    store.send_as_authority(store.update(0)).unwrap();
    let mut permissive = store.update(1);
    *permissive.data.last_mut().unwrap() = 0;
    assert_eq!(
        store.send_as_authority(permissive),
        refusal(StorageError::ProofVerificationFailed)
    );
}

#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn a_forged_root_fails_the_real_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut forged = store.update(0);
    let root_end = forged.data.len() - 5;
    forged.data[root_end - 1] ^= 1;
    assert_eq!(
        store.send_as_authority(forged),
        refusal(StorageError::ProofVerificationFailed)
    );
    store.send_as_authority(store.update(0)).unwrap();
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::RevisionChanged)
    );
}

/// The indexer projects every update through `StorageRegistry::update`.
#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn the_program_rotates_roots_as_the_indexer_projects_them() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut projected = store.registry();
    for revision in 0..3 {
        let slot = revision + 1;
        store.svm.warp_to_slot(slot);
        let instruction = store.update(revision);
        let data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        projected.update(RootUpdate { slot, data: &data }).unwrap();
        store.send_as_authority(instruction).unwrap();
        assert_eq!(store.registry(), projected);
    }
}

fn private_key_refusal() -> StorageError {
    key_refusal(RingCircuit::apply_records(1, ApplyMode::Private))
}

#[test]
fn a_private_write_requires_a_registry_pinned_to_a_tracking_registry() {
    let mut store = Store::new();
    store.initialize(GRACE);
    store.initialize_tracking();
    let before = store.registry();
    assert_eq!(
        store.send_as_authority(store.private_update(store.registry)),
        refusal(StorageError::PrivateWriteWithoutTracking)
    );
    assert_eq!(store.registry(), before);
}

#[test]
fn a_private_write_refuses_a_missing_or_substituted_tracking_registry() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    let before = store.svm.get_account(&registry).unwrap();
    // The pinned registry does not exist yet, nothing answers for its address.
    assert_eq!(
        store.send_as_authority(store.private_update(registry)),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    store.initialize_tracking();
    let mut missing = store.private_update(registry);
    missing.accounts.pop();
    assert_eq!(
        store.send_as_authority(missing),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    let mut substituted = store.private_update(registry);
    substituted.accounts[2].pubkey = store.registry;
    assert_eq!(
        store.send_as_authority(substituted),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    let mut extra = store.private_update(registry);
    extra
        .accounts
        .push(AccountMeta::new_readonly(store.registry, false));
    assert_eq!(
        store.send_as_authority(extra),
        refusal(StorageError::InvalidTrackingRegistry)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn a_private_write_names_a_tracking_root_the_registry_serves() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.initialize_tracking();
    let before = store.svm.get_account(&registry).unwrap();
    let mut unserved = store.private_update(registry);
    let mut data = StorageUpdateIxData::parse(&unserved.data[1..]).unwrap();
    data.tracking_revision = Some(Revision::from(5));
    unserved.data = [vec![tag::UPDATE], data.encode().unwrap()].concat();
    assert_eq!(
        store.send_as_authority(unserved),
        refusal(StorageError::RootExpired)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn private_proof_failure_and_stale_revision_keep_the_root_and_floor() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.initialize_tracking();
    let mut pinned: StorageRegistry =
        *bytemuck::from_bytes(&store.svm.get_account(&registry).unwrap().data);
    pinned.tracking_floor = Revision::from(4);
    store.seed(registry, bytemuck::bytes_of(&pinned));
    let before = store.svm.get_account(&registry).unwrap();
    assert_eq!(
        store.send_as_authority(store.private_update(registry)),
        refusal(private_key_refusal())
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
    let mut stale = store.private_update(registry);
    let mut data = StorageUpdateIxData::parse(&stale.data[1..]).unwrap();
    data.revision = Revision::from(1);
    stale.data = [vec![tag::UPDATE], data.encode().unwrap()].concat();
    assert_eq!(
        store.send_as_authority(stale),
        refusal(StorageError::RevisionChanged)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

/// A public write reads no tracking registry, on a pinned source as on any other.
#[test]
fn public_writes_refuse_an_extra_tracking_account() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let pinned = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.initialize_tracking();
    for registry in [store.registry, pinned] {
        let before = store.svm.get_account(&registry).unwrap();
        let mut instruction = store.zero_proof_update_of(registry, 0, ListId::Block);
        instruction
            .accounts
            .push(AccountMeta::new_readonly(store.tracking, false));
        assert_eq!(
            store.send_as_authority(instruction),
            refusal(StorageError::InvalidTrackingRegistry)
        );
        assert_eq!(
            store.send_as_authority(store.zero_proof_update_of(registry, 0, ListId::Block)),
            refusal(StorageError::ProofVerificationFailed)
        );
        assert_eq!(store.svm.get_account(&registry).unwrap(), before);
    }
}

/// Skips the checks `StorageUpdateIxData::encode` runs.
fn set_first_write_lists(instruction: &mut Instruction, bits: u64) {
    let write = 1 + 8 + 1;
    let lists = write + core::mem::offset_of!(RecordWriteData, lists);
    for field in [
        core::mem::offset_of!(WriteRecordsIxData, mask),
        core::mem::offset_of!(WriteRecordsIxData, value),
    ] {
        instruction.data[lists + field..lists + field + 8].copy_from_slice(&bits.to_le_bytes());
    }
}

/// The written masks alone decide whether the tracking revision is present, no flag names the mode.
#[test]
fn a_tracking_revision_follows_exactly_a_private_owner_write() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.initialize_tracking();
    let before = store.svm.get_account(&registry).unwrap();
    for list in ListSet::PRIVATE_LISTS.iter() {
        let mut instruction = store.zero_proof_update_of(registry, 0, ListId::Block);
        set_first_write_lists(&mut instruction, list.record_bit());
        assert_eq!(
            store.send_as_authority(instruction),
            refusal(StorageError::InvalidInstructionData)
        );
    }
    let mut declared = store.private_update(registry);
    set_first_write_lists(&mut declared, ListId::Block.record_bit());
    assert_eq!(
        store.send_as_authority(declared),
        refusal(StorageError::InvalidInstructionData)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn each_mode_reaches_its_own_apply_key() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.initialize_tracking();
    let before = store.svm.get_account(&registry).unwrap();
    // The public key has a verifying key, the zero proof fails its pairing.
    assert_eq!(
        store.send_as_authority(store.zero_proof_update_of(registry, 0, ListId::Block)),
        refusal(StorageError::ProofVerificationFailed)
    );
    // The same write count with a private owner write looks up the private key instead.
    assert_eq!(
        store.send_as_authority(store.private_update(registry)),
        refusal(private_key_refusal())
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}
