use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    compute_unit_limit,
    storage::{Revision, Root, StorageRegistry},
    tag, CustomRingError, InitializeIxData, InstructionTag, PolicyBindingIxData, PolicyTableIxData,
    RingKind, SetCoSignerRecordIxData, SourceSpec, UpdatePolicyIxData, CONFIG_PDA_SEED,
    CO_SIGNER_PDA_SEED, RING_POLICY_PDA_SEED, STORAGE_PROGRAM_ID,
};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_decompress_be;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_message::{v1, VersionedMessage};
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use spr_interface::{
    pda::protocol_config,
    state::{discriminator::PROTOCOL_CONFIG, ProtocolConfig},
    BPF_LOADER_UPGRADEABLE_ID, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_ring_policy::{ListId, Member, OutflowLimit, Rule, RuleTable, Subject};

/// Any address serves as the ring program.
pub const PROGRAM: Address = Address::new_from_array([0x52; 32]);
pub const SYSTEM: Address = Address::new_from_array([0; 32]);
/// The ring's own `StorageRegistry`, written in place of a storage program `Update`.
pub const RECORDS: Address = Address::new_from_array([0x5a; 32]);
const LOADER: Address = Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
const SHIELDED_POOL: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
const SOL: u64 = 1_000_000_000;
const UNITS: u32 = compute_unit_limit(InstructionTag::Transfer);
const LOADED_ACCOUNTS_DATA: u32 = 64 * 1024 * 1024;

pub fn pda(seed: &[u8]) -> Address {
    Address::find_program_address(&[seed], &PROGRAM).0
}

pub fn config_pda() -> Address {
    pda(CONFIG_PDA_SEED)
}

pub fn policy_pda() -> Address {
    pda(RING_POLICY_PDA_SEED)
}

pub fn ring_auth() -> Address {
    pda(RING_AUTH_PDA_SEED)
}

pub fn program_data() -> Address {
    program_data_of(&PROGRAM)
}

pub fn program_data_of(program: &Address) -> Address {
    Address::find_program_address(&[program.as_ref()], &LOADER).0
}

#[derive(Clone, Copy)]
pub enum Setup {
    AuditOnly,
    Policy,
    /// A policy with an outflow limit row, the approval flag needs one.
    LimitedPolicy,
    Anonymous,
    AnonymousPolicy,
}

impl Setup {
    pub const fn kind(self) -> RingKind {
        match self {
            Self::AuditOnly => RingKind::AuditOnly,
            Self::Policy | Self::LimitedPolicy => RingKind::Policy,
            Self::Anonymous => RingKind::Anonymous,
            Self::AnonymousPolicy => RingKind::AnonymousPolicy,
        }
    }
}

pub type Sent = Result<u64, (TransactionError, u64)>;

pub struct Ring {
    svm: LiteSVM,
    pub payer: Keypair,
    pub authority: Keypair,
}

impl Ring {
    /// A deployed ring whose config, policy and SPP registration came through their instructions.
    pub fn new(setup: Setup) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(PROGRAM, &program_bytes())
            .expect("load the ring program");
        svm.add_program(SHIELDED_POOL, &shielded_pool_bytes())
            .expect("load the shielded pool");
        let payer = Keypair::new();
        let authority = Keypair::new();
        for wallet in [&payer, &authority] {
            svm.airdrop(&wallet.pubkey(), 100 * SOL)
                .expect("fund the wallet");
        }
        let mut ring = Self {
            svm,
            payer,
            authority,
        };
        let protocol = ProtocolConfig {
            discriminator: PROTOCOL_CONFIG,
            ..Zeroable::zeroed()
        };
        ring.store(
            protocol_config(),
            SHIELDED_POOL,
            bytemuck::bytes_of(&protocol).to_vec(),
        );
        let authority = ring.authority.insecure_clone();
        ring.set_upgrade_authority(&PROGRAM, &authority.pubkey());
        let limits = match setup {
            Setup::LimitedPolicy => vec![OutflowLimit::of(
                &Member::asset(&Address::new_from_array([7; 32])).expect("asset member"),
            )
            .with_cosign_above(1_000)],
            _ => Vec::new(),
        };
        ring.store_registry(RECORDS, &authority.pubkey(), &[root(0, [0x0e; 32])]);
        let table = match setup.kind().has_policy() {
            true => allow_list_table(limits),
            false => PolicyTableIxData {
                sources: Vec::new(),
                rules: Vec::new(),
            },
        };
        let initialize = InitializeIx {
            payer: ring.payer.pubkey(),
            authority: authority.pubkey(),
            data: InitializeIxData {
                auditor_pubkey: auditor_pubkey(),
                kind: setup.kind(),
                policy: Some(PolicyBindingIxData {
                    storage_authority: Address::default(),
                    table,
                }),
            },
            curators: &[],
        }
        .instruction();
        within_budget(
            InstructionTag::Initialize,
            ring.send(initialize, &[&authority]),
        );
        within_budget(
            InstructionTag::SyncRoots,
            ring.send(sync_roots(&RECORDS), &[]),
        );
        ring
    }

    /// A `StorageRegistry` of `authority` holding `roots` newest first.
    pub fn store_registry(&mut self, address: Address, authority: &Address, roots: &[Root]) {
        let mut registry = StorageRegistry::new(*authority, 0);
        registry.roots[..roots.len()].copy_from_slice(roots);
        self.store(
            address,
            STORAGE_PROGRAM_ID,
            bytemuck::bytes_of(&registry).to_vec(),
        );
    }

    pub fn send(&mut self, instruction: Instruction, signers: &[&Keypair]) -> Sent {
        self.svm.expire_blockhash();
        let message = v1::Message::try_compile_with_config(
            &self.payer.pubkey(),
            &[instruction],
            self.svm.latest_blockhash(),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(UNITS)
                .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA),
        )
        .expect("compile the v1 message");
        let mut keys: Vec<&dyn Signer> = vec![&self.payer];
        for signer in signers {
            if !keys.iter().any(|key| key.pubkey() == signer.pubkey()) {
                keys.push(*signer);
            }
        }
        let transaction = VersionedTransaction::try_new(VersionedMessage::V1(message), &keys)
            .expect("sign the v1 transaction");
        self.svm
            .send_transaction(transaction)
            .map(|meta| meta.compute_units_consumed)
            .map_err(|failed| (failed.err, failed.meta.compute_units_consumed))
    }

    pub fn read<T: Pod>(&self, address: &Address) -> T {
        let account = self.svm.get_account(address).expect("account exists");
        *bytemuck::from_bytes(&account.data)
    }

    pub fn lamports(&self, address: &Address) -> u64 {
        self.svm.get_balance(address).unwrap_or_default()
    }

    /// Replaces a program account's data, the state a sequence of instructions would reach.
    pub fn write<T: Pod>(&mut self, address: &Address, value: &T) {
        self.store(*address, PROGRAM, bytemuck::bytes_of(value).to_vec());
    }

    pub fn store(&mut self, address: Address, owner: Address, data: Vec<u8>) {
        let account = Account {
            lamports: self.svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        };
        self.svm
            .set_account(address, account)
            .expect("store the account");
    }

    /// Leaves `address` an empty system account.
    pub fn drain(&mut self, address: &Address) {
        self.svm
            .set_account(*address, Account::default())
            .expect("drain the account");
    }

    /// An executable account at `address`, for refusals that precede any CPI into it.
    pub fn deploy_stand_in(&mut self, address: Address) {
        self.svm
            .add_program(address, &program_bytes())
            .expect("load the stand-in");
    }

    pub fn warp(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }

    /// litesvm deploys with no upgrade authority, `Initialize` needs one.
    pub fn set_upgrade_authority(&mut self, program: &Address, authority: &Address) {
        let program_data = program_data_of(program);
        let mut account = self
            .svm
            .get_account(&program_data)
            .expect("the deploy writes program data");
        let metadata = bincode::serde::encode_to_vec(
            UpgradeableLoaderState::ProgramData {
                slot: 0,
                upgrade_authority_address: Some(*authority),
            },
            bincode::config::legacy(),
        )
        .expect("encode the loader state");
        account.data[..metadata.len()].copy_from_slice(&metadata);
        self.svm
            .set_account(program_data, account)
            .expect("store the program data");
    }
}

/// The `b` point of groth16-solana's own proof fixture, big-endian and uncompressed.
pub fn on_curve_g2() -> [u8; 128] {
    hex::decode("2839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b038101ad21412517a8e683efba9628d15fd3282b60f216de41f4fb75893ae6c04160e81a80650f6fe64da835e31f7d303f516c8b15b3c9093ae5a1113bd3e939812")
        .unwrap()
        .try_into()
        .unwrap()
}

pub fn off_curve_g2() -> [u8; 64] {
    off_curve(|point| alt_bn128_g2_decompress_be(point).is_ok())
}

/// A canonical compressed `x` off the curve.
fn off_curve<const N: usize>(on_curve: impl Fn(&[u8; N]) -> bool) -> [u8; N] {
    (1..=u8::MAX)
        .map(|x| {
            let mut point = [0u8; N];
            point[N - 1] = x;
            point
        })
        .find(|point| !on_curve(point))
        .expect("a canonical x off the curve")
}

/// The SBF build, `SBF_OUT_DIR` when set, else the workspace deploy directory.
fn program_bytes() -> Vec<u8> {
    let dir = std::env::var("SBF_OUT_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into());
    let path = format!("{dir}/custom_ring_program.so");
    std::fs::read(&path).unwrap_or_else(|_| panic!("build the ring program into {path}"))
}

/// `ZOLANA_SPP_PROGRAM_SO` when set, else the zolana deploy directory.
fn shielded_pool_bytes() -> Vec<u8> {
    let path = std::env::var("ZOLANA_SPP_PROGRAM_SO").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../zolana/target/deploy/shielded_pool_program.so"
        )
        .into()
    });
    std::fs::read(&path).unwrap_or_else(|_| panic!("build the shielded pool into {path}"))
}

pub fn auditor_pubkey() -> [u8; 33] {
    let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    custom_ring_interface::tagged_x25519(x25519_dalek::PublicKey::from(&secret).as_bytes())
}

pub fn allow_list_table(limits: Vec<OutflowLimit>) -> PolicyTableIxData {
    list_table(ListId::Allow, limits)
}

/// One rule requiring `list` of every output owner, sourced from the ring's own registry.
pub fn list_table(list: ListId, _limits: Vec<OutflowLimit>) -> PolicyTableIxData {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, list))
        .build()
        .encode();
    PolicyTableIxData {
        sources: vec![SourceSpec {
            list_id: list as u8,
            source: 0,
        }],
        rules: table.rules[..usize::from(table.rule_count)].to_vec(),
    }
}

pub fn refused(sent: Sent, error: CustomRingError) {
    refused_with(sent, InstructionError::Custom(error as u32));
}

pub fn refused_with(sent: Sent, error: InstructionError) {
    let expected = TransactionError::InstructionError(0, error);
    match sent {
        Err((actual, _)) => assert_eq!(actual, expected),
        Ok(units) => panic!("accepted after {units} units, expected {expected:?}"),
    }
}

pub fn within_budget(tag: InstructionTag, sent: Sent) -> u64 {
    let units = sent.unwrap_or_else(|refusal| panic!("{tag:?} refused {refusal:?}"));
    assert!(
        units <= u64::from(compute_unit_limit(tag)),
        "{tag:?} spent {units}"
    );
    units
}

/// Valid only while it is the newest root.
pub fn root(revision: u64, hash: [u8; 32]) -> Root {
    retired(revision, hash, 0)
}

pub fn retired(revision: u64, hash: [u8; 32], expires_at: u64) -> Root {
    Root {
        hash,
        revision: Revision::from(revision),
        expires_at: expires_at.to_le_bytes(),
    }
}

/// Only a ring proof check raises either code, every earlier check passed.
pub fn reaches_verification(sent: Sent) -> u64 {
    let proof_check = [
        CustomRingError::InvalidRingProofPoint,
        CustomRingError::ProofVerificationFailed,
    ];
    match sent {
        Err((TransactionError::InstructionError(0, InstructionError::Custom(code)), units))
            if proof_check.iter().any(|error| *error as u32 == code) =>
        {
            units
        }
        other => panic!("expected the proof check, got {other:?}"),
    }
}

fn instruction(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

fn tagged(tag: u8, body: &[u8]) -> Vec<u8> {
    [&[tag][..], body].concat()
}

/// `Initialize`, the policy accounts follow the SPP program only with a policy.
pub struct InitializeIx<'a> {
    pub payer: Address,
    pub authority: Address,
    pub data: InitializeIxData,
    pub curators: &'a [Address],
}

impl InitializeIx<'_> {
    pub fn instruction(self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.payer, true),
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(PROGRAM, false),
            AccountMeta::new_readonly(program_data(), false),
            AccountMeta::new_readonly(protocol_config(), false),
            AccountMeta::new(ring_auth(), false),
            AccountMeta::new_readonly(SHIELDED_POOL, false),
        ];
        if self.data.policy.is_some() {
            accounts.extend([
                AccountMeta::new(policy_pda(), false),
                AccountMeta::new_readonly(RECORDS, false),
            ]);
            accounts.extend(
                self.curators
                    .iter()
                    .map(|curator| AccountMeta::new_readonly(*curator, false)),
            );
        }
        instruction(
            accounts,
            tagged(tag::INITIALIZE, &wincode::serialize(&self.data).unwrap()),
        )
    }
}

pub fn sync_roots(registry: &Address) -> Instruction {
    instruction(
        vec![
            AccountMeta::new(policy_pda(), false),
            AccountMeta::new_readonly(*registry, false),
        ],
        vec![tag::SYNC_ROOTS],
    )
}

/// `UpdatePolicy`, the trailing accounts follow the policy.
pub struct UpdatePolicyIx<'a> {
    pub authority: Address,
    pub update: UpdatePolicyIxData,
    pub trailing: &'a [Address],
}

impl UpdatePolicyIx<'_> {
    pub fn instruction(self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(policy_pda(), false),
        ];
        accounts.extend(
            self.trailing
                .iter()
                .map(|account| AccountMeta::new_readonly(*account, false)),
        );
        instruction(
            accounts,
            tagged(
                tag::UPDATE_POLICY,
                &wincode::serialize(&self.update).unwrap(),
            ),
        )
    }
}

/// A rules update without curators.
pub fn rules_write(authority: &Address, table: PolicyTableIxData) -> Instruction {
    UpdatePolicyIx {
        authority: *authority,
        update: UpdatePolicyIxData::Rules(table),
        trailing: &[],
    }
    .instruction()
}

pub fn config_write(
    tag: u8,
    authority: &Address,
    extra: &[AccountMeta],
    body: &[u8],
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new(config_pda(), false),
    ];
    accounts.extend_from_slice(extra);
    instruction(accounts, tagged(tag, body))
}

pub fn co_signer_record(signer: &Address) -> Address {
    Address::find_program_address(&[CO_SIGNER_PDA_SEED, signer.as_ref()], &PROGRAM).0
}

/// The `[co_signer_record, co_signer]` slot of a demanded co-signature.
#[derive(Clone, Copy)]
pub struct CoSignerSlot {
    pub record_of: Address,
    pub signer: Address,
}

impl CoSignerSlot {
    pub const fn own(signer: Address) -> Self {
        Self {
            record_of: signer,
            signer,
        }
    }

    pub fn signed(self) -> Vec<AccountMeta> {
        self.metas(true)
    }

    pub fn unsigned(self) -> Vec<AccountMeta> {
        self.metas(false)
    }

    fn metas(self, signs: bool) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(co_signer_record(&self.record_of), false),
            AccountMeta::new_readonly(self.signer, signs),
        ]
    }
}

pub struct SetCoSignerIx {
    pub payer: Address,
    pub authority: Address,
    pub signer: Address,
    pub scope: u8,
}

impl SetCoSignerIx {
    pub fn instruction(self) -> Instruction {
        let data = SetCoSignerRecordIxData {
            signer: self.signer,
            scope: self.scope,
        };
        instruction(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(config_pda(), false),
                AccountMeta::new(co_signer_record(&self.signer), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            tagged(tag::SET_CO_SIGNER, &wincode::serialize(&data).unwrap()),
        )
    }
}

pub struct ClearCoSignerIx {
    pub authority: Address,
    pub signer: Address,
    pub rent_recipient: Address,
}

impl ClearCoSignerIx {
    pub fn instruction(self) -> Instruction {
        instruction(
            vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(config_pda(), false),
                AccountMeta::new(co_signer_record(&self.signer), false),
                AccountMeta::new(self.rent_recipient, false),
            ],
            tagged(tag::CLEAR_CO_SIGNER, &[]),
        )
    }
}

pub fn set_co_signer(ring: &mut Ring, co_signer: &Address, scope: u8) {
    let authority = ring.authority.insecure_clone();
    let set = SetCoSignerIx {
        payer: ring.payer.pubkey(),
        authority: authority.pubkey(),
        signer: *co_signer,
        scope,
    }
    .instruction();
    ring.send(set, &[&authority]).expect("set the co-signer");
}

pub fn transact(tag: u8, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    instruction(accounts, tagged(tag, &data))
}

pub fn set_delegate(authority: &Address, delegate: &Address) -> Instruction {
    config_write(
        tag::SET_DELEGATE,
        authority,
        &[
            AccountMeta::new_readonly(*delegate, true),
            AccountMeta::new_readonly(policy_pda(), false),
        ],
        &[],
    )
}

/// A policy ring whose delegate put it in `ConfidentialEscrow` mode.
pub fn delegate_ring(delegate: &Keypair) -> Ring {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.authority.insecure_clone();
    within_budget(
        InstructionTag::SetDelegate,
        ring.send(
            set_delegate(&authority.pubkey(), &delegate.pubkey()),
            &[&authority, delegate],
        ),
    );
    ring
}
