use custom_ring_interface::{
    storage::{RegistryId, Revision, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{
        tag, EscrowWriteData, InitializeIxData, StorageUpdateIxData, StorageWriteData, UpdateMode,
    },
    ApplyRecordsIxData, CustomRingProof, PlainGroth16Proof, RecordWriteData, WriteRecordsIxData,
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

const PROGRAM: Address = custom_ring_interface::STORAGE_PROGRAM_ID;
const GRACE: u64 = 10;
const REGISTRY_ID: RegistryId = RegistryId([1; 32]);

struct Store {
    svm: LiteSVM,
    authority: Keypair,
    payer: Keypair,
    registry: Address,
    proofs: Value,
}

impl Store {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.warp_to_slot(0);
        let program = std::env::var_os("SBF_OUT_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into())
            .join("storage_program.so");
        svm.add_program(PROGRAM, &std::fs::read(program).unwrap())
            .unwrap();
        let authority = Keypair::new_from_array([9; 32]);
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        let registry = StorageRegistry::find_address(&authority.pubkey(), &REGISTRY_ID).0;
        let proofs: Value = serde_json::from_str(include_str!("proofs.json")).unwrap();
        // The apply proofs bind the registry address.
        assert_eq!(hex::encode(registry), proofs["registry"].as_str().unwrap());
        Self {
            svm,
            authority,
            payer,
            registry,
            proofs,
        }
    }

    fn initialize(&mut self, grace_slots: u64) {
        let data = InitializeIxData {
            registry_id: REGISTRY_ID,
            grace_slots: grace_slots.to_le_bytes(),
        };
        let instruction = Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
                AccountMeta::new_readonly(Address::new_from_array([0; 32]), false),
            ],
            data: [&[tag::INITIALIZE], bytemuck::bytes_of(&data)].concat(),
        };
        self.send_as_authority(instruction).unwrap();
    }

    fn update(&self, revision: u64) -> Instruction {
        self.update_with(revision, UpdateMode::Graced)
    }

    fn update_with(&self, revision: u64, mode: UpdateMode) -> Instruction {
        let vector = &self.proofs[format!("update{revision}")];
        let writes = vector["writes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| write(vector, entry))
            .collect::<Vec<_>>();
        let apply = ApplyRecordsIxData {
            proof: proof(vector),
            new_root: field(&vector["root"]),
            new_next_index: u32::try_from(vector["nextIndex"].as_u64().unwrap())
                .unwrap()
                .to_le_bytes(),
        };
        let data = StorageUpdateIxData {
            revision: revision.into(),
            writes,
            apply: &apply,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
            ],
            data: [vec![mode.tag()], data.encode().unwrap()].concat(),
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
}

fn refusal(code: u32) -> Result<(), TransactionError> {
    Err(TransactionError::InstructionError(
        0,
        InstructionError::Custom(code),
    ))
}

fn write(vector: &Value, entry: &Value) -> StorageWriteData {
    if field(&entry["escrowKey"]) != [0; 32] {
        let escrow = &vector["escrow"];
        return StorageWriteData::Escrow(EscrowWriteData {
            owner: Address::new_from_array(field(&escrow["owner"])),
            nullifier_pk: field(&escrow["nullifierPk"]),
            eph_u: field(&escrow["ephU"]),
            ciphertext: field(&escrow["ciphertext"]),
        });
    }
    StorageWriteData::Record(RecordWriteData {
        member: field(&entry["member"]),
        lists: WriteRecordsIxData {
            mask: entry["mask"].as_u64().unwrap().to_le_bytes(),
            value: entry["value"].as_u64().unwrap().to_le_bytes(),
        },
        mint_policy: custom_ring_interface::mint_policy_write(None),
    })
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
        refusal(StorageError::Unauthorized as u32)
    );
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::Unauthorized as u32)
    );
    let mut update = store.update(0);
    update.accounts[0].pubkey = new.pubkey();
    store.send(update, &[&new]).unwrap();
}

#[test]
fn an_escrow_write_applies() {
    let mut store = Store::new();
    store.initialize(GRACE);
    for revision in 0..3 {
        store.send_as_authority(store.update(revision)).unwrap();
    }
    assert_eq!(store.root(3), Ok(field(&store.proofs["update2"]["root"])));
}

#[test]
fn updates_retire_roots_by_mode() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut wrong_authority = store.update(0);
    wrong_authority.accounts[0].pubkey = store.payer.pubkey();
    assert_eq!(
        store.send(wrong_authority, &[]),
        refusal(StorageError::Unauthorized as u32)
    );
    let mut forged = store.update(0);
    *forged.data.last_mut().unwrap() ^= 1;
    assert_eq!(
        store.send_as_authority(forged),
        refusal(StorageError::ProofVerificationFailed as u32)
    );
    store.send_as_authority(store.update(0)).unwrap();
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::RevisionChanged as u32)
    );

    let seeded = store.svm.clone();
    for mode in [UpdateMode::Graced, UpdateMode::Immediate] {
        store.svm = seeded.clone();
        store.send_as_authority(store.update_with(1, mode)).unwrap();
        if mode == UpdateMode::Graced {
            store.svm.warp_to_slot(GRACE - 1);
            assert!(store.root(1).is_ok());
            store.svm.warp_to_slot(GRACE);
        }
        assert_eq!(store.root(1), Err(StorageError::RootExpired));
        store.send_as_authority(store.update(2)).unwrap();
        assert_eq!(store.root(1), Err(StorageError::RootExpired));
    }
}

#[test]
fn unbounded_grace_keeps_both_update_modes() {
    let mut store = Store::new();
    store.initialize(u64::MAX);
    store.svm.warp_to_slot(1);
    store.send_as_authority(store.update(0)).unwrap();
    store
        .send_as_authority(store.update_with(1, UpdateMode::Immediate))
        .unwrap();
}

#[test]
fn a_graced_update_never_evicts_a_root_that_still_verifies() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut account = store.svm.get_account(&store.registry).unwrap();
    let oldest = bytemuck::from_bytes_mut::<StorageRegistry>(&mut account.data)
        .roots
        .last_mut()
        .unwrap();
    oldest.expires_at = GRACE.to_le_bytes();
    store.svm.set_account(store.registry, account).unwrap();
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::HistoryFull as u32)
    );
    let full = store.svm.clone();
    store
        .send_as_authority(store.update_with(0, UpdateMode::Immediate))
        .unwrap();
    store.svm = full;
    // Evictable from the slot `RootExpired` starts refusing it.
    store.svm.warp_to_slot(GRACE);
    store.send_as_authority(store.update(0)).unwrap();
}

/// The indexer projects every update through `StorageRegistry::update`.
#[test]
fn the_program_rotates_roots_as_the_indexer_projects_them() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut projected = store.registry();
    for (revision, mode) in [
        (0, UpdateMode::Graced),
        (1, UpdateMode::Graced),
        (2, UpdateMode::Immediate),
    ] {
        let slot = revision + 1;
        store.svm.warp_to_slot(slot);
        let instruction = store.update_with(revision, mode);
        let data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        projected
            .update(RootUpdate {
                mode,
                slot,
                data: &data,
            })
            .unwrap();
        store.send_as_authority(instruction).unwrap();
        assert_eq!(store.registry(), projected);
    }
}
