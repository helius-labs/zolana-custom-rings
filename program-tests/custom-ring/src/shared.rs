//! Localnet bring-up shared by the custom-ring test binaries.
//!
//! Mirrors `sdk-tests/zk-program-swap/test/tests/shared.rs`. SOL settles
//! through `spr_interface::SOL_INTERFACE`, a system-owned PDA with a
//! hardcoded address that no instruction has to create, and
//! `AssetRegistry::default()` already carries SOL as asset id 1. The bring-up
//! also registers one SPL mint, named USDC in the tests, under asset id 2,
//! with the mint authority parked on the payer.

use std::{
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use custom_ring_cli::{localnet::GENESIS_PROGRAMS, Zolana, ZolanaServices};
use custom_ring_interface::RingRoles;
use custom_ring_sdk::{
    compute_unit_limit, CustomRing, InitialPolicy, Initialize, InitializeStorage, InstructionTag,
    MemberRecords, PolicyTable, RingError, RingKind, SyncRoots,
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    compile_message,
    prover::{indexed::ProofDataSource, SERVER_ADDRESS},
    sign_transaction, AsyncProverClient, ClientError, ComputeBudgetConfig, IndexerRequirement,
    ProverClient, ProverLaunch, Rpc, SolanaRpc, ZolanaIndexer,
};
use spr_interface::{
    pda,
    state::{default_tree_fees, nullifier_tree_params, SplAssetCounter},
    SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::{ShieldedKeypair, X25519Pubkey};
use spr_program_test::{
    create_tree_instructions,
    localnet::{LocalnetPorts, LocalnetValidator, UpgradeableProgram},
};
use spr_protocol_instructions::{CreateProtocolConfig, SetRingActivation};
use spr_test_utils::wallet::{KeypairWalletAuthority, Wallet, DEFAULT_TAG_WINDOW};
use spr_test_utils::{
    localnet::{isolated_temp_path, localnet_indexer_url, localnet_rpc_url, WorkspaceArtifacts},
    prover::spawn_workspace_prover,
    smart_account::{self, ProtocolSigners, StandardSigners},
    spl::{create_mint, RegisterSplAsset},
};
use spr_transaction::{AssetRegistry, Mint, ShieldedTransaction};
use spr_user_registry_interface::user_registry_program_id;
use zolana_ring_client::{MemberOpeningRead, RingConfidentialScan};
use zolana_ring_policy::{ListId, Member, RuleTable};
use zolana_ring_transaction::RingAssets;

use crate::ring_indexer::RingIndexerLaunch;

/// Funds the fee payer for the whole bootstrap (smart accounts, protocol
/// config, tree allocation) plus every deposit a test drives through it.
pub const PAYER_AIRDROP: u64 = 10_000_000_000_000;
/// Each protocol signer only ever pays transaction fees.
pub const SIGNER_AIRDROP: u64 = 1_000_000_000;
/// The Squads protocol vault pays rent for the accounts its `execute_sync`
/// instructions create.
pub const PROTOCOL_VAULT_AIRDROP: u64 = 5_000_000_000;
/// Each actor signs its own ring deposits and transacts, and the deposits move
/// real lamports out of this balance.
pub const ACTOR_AIRDROP: u64 = 10_000_000_000;
/// The bring-up registers USDC first.
pub const USDC_ASSET_ID: u64 = SplAssetCounter::FIRST_ASSET_ID;
/// A live localnet with the protocol bootstrapped and two funded actors. The
/// custom-ring program's own config account is NOT created here: that is the
/// first step of the lifecycle under test.
pub struct TestEnv {
    pub client: Zolana,
    pub rpc_url: String,
    pub indexer_url: String,
    /// Fee payer for bootstrap and for instructions no actor must sign, also
    /// the USDC mint authority.
    pub payer: Keypair,
    pub tree: Address,
    pub usdc_mint: Address,
    pub assets: AssetRegistry,
    pub sender: TestWallet,
    pub recipient: TestWallet,
    tree_creation_authority: Keypair,
    ring_creation_authority: Keypair,
    standard_accounts: smart_account::StandardAccounts,
}

impl TestEnv {
    /// Governance enables the authority rail for `ring` through the ring vault.
    pub fn enable_authority_rail(&self, ring: CustomRing) -> Result<()> {
        let activation = SetRingActivation {
            authority: self.standard_accounts.ring_vault,
            ring_config: ring.ring_auth_pda(),
            activated: true,
            ring_authority_transact_is_enabled: true,
        }
        .instruction();
        let sync = smart_account::execute_sync_ix(
            &self.standard_accounts.ring_settings,
            0,
            &[self.ring_creation_authority.pubkey()],
            &[activation],
        );
        self.client.rpc().create_and_send_transaction(
            &[sync],
            self.payer.pubkey(),
            &[&self.payer, &self.ring_creation_authority],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
        Ok(())
    }

    /// Allocate and register a second SPP tree owned by the shielded pool.
    pub fn create_registered_tree(&self) -> Result<Address> {
        let rpc = self.client.rpc();
        SolanaRpc::new(self.rpc_url.clone()).airdrop(&self.payer.pubkey(), PAYER_AIRDROP)?;
        let params = nullifier_tree_params();
        let creation = create_tree_instructions(
            rpc,
            &self.payer.pubkey(),
            &self.standard_accounts.tree_vault,
            params,
            default_tree_fees(params.input_queue_zkp_batch_size).expect("default tree fees"),
        )?;
        let syncs = smart_account::execute_sync_each(
            &self.standard_accounts.tree_settings,
            0,
            &[self.tree_creation_authority.pubkey()],
            &creation.instructions,
        );
        rpc.create_and_send_transaction(
            &syncs,
            self.payer.pubkey(),
            &[&self.payer, &self.tree_creation_authority],
            ComputeBudgetConfig::for_instruction_count(syncs.len()),
        )?;
        Ok(creation.tree)
    }

    /// The raw id a tree hashes its UTXOs under.
    pub fn tree_id(&self, tree: Address) -> Result<u16> {
        Ok(self.run(custom_ring_sdk::tree_id(self.client.as_async(), tree))?)
    }

    /// Runs an SDK operation on the blocking client.
    pub fn run<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, RingError>>,
    ) -> Result<T, RingError> {
        self.client.block_on(operation)
    }

    /// SOL and the suite's USDC mint.
    pub fn ring_assets(&self) -> Result<RingAssets> {
        Ok(RingAssets::new([Mint::new(self.usdc_mint, USDC_ASSET_ID)])?)
    }

    /// The same services behind `prover`.
    pub fn client_with(&self, prover: impl Fn() -> AsyncProverClient) -> Zolana {
        ZolanaServices {
            rpc: SolanaRpc::new(self.rpc_url.clone()),
            indexer: ZolanaIndexer::new(self.indexer_url.clone()),
            prover: prover(),
            ring_prover: prover(),
        }
        .connect()
    }

    /// The tree the cli names by default.
    pub fn register_default_tree(&self) -> Result<Address> {
        Ok(self.tree)
    }

    pub fn fund(&self, recipient: Address, lamports: u64) -> Result<()> {
        send(
            self.client.rpc(),
            &self.payer,
            &[solana_system_interface::instruction::transfer(
                &self.payer.pubkey(),
                &recipient,
                lamports,
            )],
        )?;
        Ok(())
    }

    pub fn funded_keypair(&self) -> Result<Keypair> {
        let keypair = Keypair::new();
        self.fund(keypair.pubkey(), SIGNER_AIRDROP)?;
        Ok(keypair)
    }

    pub fn member_record(&self, ring: CustomRing, member: Member) -> Result<MemberOpeningRead> {
        let records = MemberRecords {
            ring,
            members: &[member],
        };
        let [read] = <[_; 1]>::try_from(self.run(records.read(self.client.as_async()))?)
            .map_err(|reads| anyhow!("{} records of {member:?}", reads.len()))?;
        Ok(read)
    }
}

/// Each actor is one eddsa identity: `ShieldedKeypair` implements
/// `solana_signer::Signer` over the same key, so it is both the shielded owner
/// and the Solana fee payer for its own transactions.
pub struct TestWallet {
    pub wallet: Wallet,
    pub keypair: ShieldedKeypair,
}

impl std::ops::Deref for TestWallet {
    type Target = Wallet;
    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl std::ops::DerefMut for TestWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}

/// zolana's wallet sync, then the scheme 10 ring notes and ring deposits it skips.
pub struct WalletSync<'a> {
    pub wallet: &'a mut Wallet,
    pub keys: &'a ShieldedKeypair,
    pub assets: &'a RingAssets,
    pub transactions: &'a [ShieldedTransaction],
}

impl WalletSync<'_> {
    pub fn sync(self) -> Result<()> {
        let authority = KeypairWalletAuthority::new(Address::default(), self.keys);
        self.wallet
            .sync(&authority, self.transactions, 0, DEFAULT_TAG_WINDOW)?;
        let notes = RingConfidentialScan::new(self.keys, self.assets).open(self.transactions)?;
        for utxo in notes.owned.utxos {
            if !self
                .wallet
                .utxos
                .iter()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                self.wallet.utxos.push(utxo);
            }
        }
        Ok(())
    }
}

pub enum Tier {
    AuditOnly,
    AnonymousAuditOnly,
    Policy {
        rules: &'static RuleTable,
        shared_sources: Vec<(ListId, CustomRing)>,
    },
    AnonymousPolicy {
        rules: &'static RuleTable,
        shared_sources: Vec<(ListId, CustomRing)>,
    },
}

impl Tier {
    /// Every referenced list served from the ring's own registry.
    pub fn policy(rules: &'static RuleTable) -> Self {
        Self::Policy {
            rules,
            shared_sources: Vec::new(),
        }
    }

    pub fn anonymous_policy(rules: &'static RuleTable) -> Self {
        Self::AnonymousPolicy {
            rules,
            shared_sources: Vec::new(),
        }
    }

    fn kind(&self) -> RingKind {
        match self {
            Self::AuditOnly => RingKind::AuditOnly,
            Self::AnonymousAuditOnly => RingKind::Anonymous,
            Self::Policy { .. } => RingKind::Policy,
            Self::AnonymousPolicy { .. } => RingKind::AnonymousPolicy,
        }
    }

    fn shared_sources(&self) -> &[(ListId, CustomRing)] {
        match self {
            Self::Policy { shared_sources, .. } | Self::AnonymousPolicy { shared_sources, .. } => {
                shared_sources
            }
            Self::AuditOnly | Self::AnonymousAuditOnly => &[],
        }
    }
}

/// Derived from the payer, every helper finds the same role keys.
pub struct RingRoleKeys {
    pub admin: Keypair,
    pub pauser: Keypair,
    pub cosign_admin: Keypair,
}

impl RingRoleKeys {
    pub fn of(payer: &Keypair) -> Self {
        let derive = |role: u8| {
            let mut secret = *payer.secret_bytes();
            secret[31] ^= role;
            Keypair::new_from_array(secret)
        };
        Self {
            admin: derive(1),
            pauser: derive(2),
            cosign_admin: derive(3),
        }
    }

    /// `payer` holds the policy role.
    pub fn roles(&self, payer: &Keypair) -> RingRoles {
        RingRoles {
            admin: self.admin.pubkey(),
            policy: payer.pubkey(),
            pauser: self.pauser.pubkey(),
            cosign_admin: self.cosign_admin.pubkey(),
        }
    }
}

/// The payer doubles as the upgrade authority and the policy authority.
pub struct RegisterRing<'a> {
    pub ring: CustomRing,
    pub payer: &'a Keypair,
    pub auditor_pubkey: X25519Pubkey,
    pub tier: Tier,
}

impl RegisterRing<'_> {
    pub fn send(self, client: &Zolana) -> Result<()> {
        self.create_records(client.rpc())?;
        let initialize = self.initialize(client)?;
        send(client.rpc(), self.payer, &[initialize])?;
        self.complete(client)
    }

    /// The records registry `Initialize` binds.
    pub fn create_records(&self, rpc: &SolanaRpc) -> Result<()> {
        send(rpc, self.payer, &[self.storage().instruction()])?;
        Ok(())
    }

    /// Every ring binds its records, an audit-only ring with an empty table.
    pub fn initialize(&self, client: &Zolana) -> Result<Instruction> {
        let authority = self.payer.pubkey();
        let empty = RuleTable::empty();
        let rules = match &self.tier {
            Tier::Policy { rules, .. } | Tier::AnonymousPolicy { rules, .. } => *rules,
            Tier::AuditOnly | Tier::AnonymousAuditOnly => &empty,
        };
        let shared_sources = self.curator_records(client)?;
        Ok(Initialize {
            ring: self.ring,
            payer: authority,
            authority,
            auditor_pubkey: self.auditor_pubkey,
            kind: self.tier.kind(),
            roles: RingRoleKeys::of(self.payer).roles(self.payer),
            policy: Some(InitialPolicy {
                records: self.storage().registry(),
                table: PolicyTable {
                    rules,
                    shared_sources: &shared_sources,
                },
            }),
        }
        .instruction()?)
    }

    /// After `Initialize`, the `SyncRoots` of every bound registry.
    pub fn complete(&self, client: &Zolana) -> Result<()> {
        let curators = self.curator_records(client)?;
        let mut registries: Vec<Address> = core::iter::once(self.storage().registry())
            .chain(curators.iter().map(|(_, registry)| *registry))
            .collect();
        registries.sort();
        registries.dedup();
        let instructions: Vec<Instruction> = registries
            .into_iter()
            .map(|registry| {
                SyncRoots {
                    ring: self.ring,
                    registry,
                }
                .instruction()
            })
            .collect();
        send(client.rpc(), self.payer, &instructions)?;
        Ok(())
    }

    fn storage(&self) -> InitializeStorage {
        InitializeStorage::records(self.ring, self.payer.pubkey())
    }

    fn curator_records(&self, client: &Zolana) -> Result<Vec<(ListId, Address)>> {
        self.tier
            .shared_sources()
            .iter()
            .map(|&(list_id, curator)| {
                let policy = client.block_on(curator.require_policy(client.as_async()))?;
                Ok((list_id, policy.records))
            })
            .collect()
    }
}

/// URL the prover client talks to. Mirrors the client's own resolution
/// (`ZOLANA_PROVER_URL` overrides the default) so a per-clone port offset is
/// respected here too.
pub fn prover_url() -> String {
    match std::env::var("ZOLANA_PROVER_URL") {
        Ok(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => SERVER_ADDRESS.to_string(),
    }
}

/// Bound the exhaustive shape sweep's key cache without resetting chain state.
/// Only the prover recorded by the isolated test harness may be stopped.
pub fn restart_prover() -> Result<()> {
    let scope = PathBuf::from(std::env::var_os("ZOLANA_PROCESS_SCOPE_DIR").context("test scope")?);
    let receipt = std::fs::read_to_string(scope.join("prover-server.owner"))?;
    let pid = receipt.lines().next().context("prover ownership receipt")?;
    let port = crate::ring_indexer::port(&prover_url())?;
    let listener = Command::new("lsof")
        .args(["-t", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .output()?;
    ensure!(
        String::from_utf8_lossy(&listener.stdout).trim() == pid,
        "the test scope does not own the prover on port {port}"
    );
    crate::ring_indexer::stop_listener(port)?;
    // A closed socket does not mean the CLI's ownership receipt is dead yet.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = Command::new("ps")
            .args(["-p", pid, "-o", "stat="])
            .output()?;
        if !state.status.success()
            || String::from_utf8_lossy(&state.stdout)
                .trim()
                .starts_with('Z')
        {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "the previous prover has not exited"
        );
        thread::sleep(Duration::from_millis(100));
    }
    start_prover(Path::new(&std::env::var("ZOLANA_CLI_BIN")?))
}

fn start_prover(cli: &Path) -> Result<()> {
    // A prover that takes its proof data from the client needs no indexer.
    let indexer = match ProverClient::local().proof_data_source() {
        ProofDataSource::Client => IndexerRequirement::Optional,
        ProofDataSource::Prover => IndexerRequirement::Required,
    };
    if let Some(keys) = std::env::var_os("ZOLANA_PROVER_KEYS_DIR") {
        ProverLaunch::new_with_cli(cli)
            .and_then(|launch| launch.with_keys_dir(keys))
            .and_then(|launch| match indexer {
                IndexerRequirement::Required => {
                    launch.with_indexer(localnet_indexer_url(), indexer).spawn()
                }
                IndexerRequirement::Optional => launch.spawn(),
            })
            .context("start the isolated ring prover")?;
    } else {
        spawn_workspace_prover(indexer);
    }
    Ok(())
}

pub fn setup() -> Result<TestEnv> {
    setup_with_extra_rings(&[])
}

/// Every extra address deploys the same ring image again as a full second ring,
/// every PDA derives from the runtime program id.
pub fn setup_with_extra_rings(extra_ring_programs: &[Address]) -> Result<TestEnv> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../zolana");
    let artifacts = WorkspaceArtifacts::new(root);
    let ring_artifacts = ring_artifacts();
    let cli =
        std::env::var("ZOLANA_CLI_BIN").unwrap_or_else(|_| artifacts.path("target/debug/zolana"));
    let ring_program = custom_ring_program_id()?;
    let ring_program_so = PathBuf::from(ring_program_so());
    let spp_program = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let smart_account = smart_account::SMART_ACCOUNT_PROGRAM_ID;

    let payer = Keypair::new();
    let payer_address = payer.pubkey();
    let accounts = smart_account::standard_accounts();
    let account_dir = isolated_temp_path("zolana-custom-ring-smart-accounts");
    smart_account::write_program_config_fixture(&account_dir);
    let validator = LocalnetValidator {
        // The Squads smart-account program is loaded for the protocol bootstrap
        // only: `CreateProtocolConfig` and `CreateTree` check authorities that the
        // bootstrap parks in Squads vaults, so both are wrapped in
        // `execute_sync_ix`. The custom-ring program never touches a smart account.
        cli_bin: cli.into(),
        working_dir: artifacts.root().into(),
        ports: LocalnetPorts::checkout()?,
        account_dir: account_dir.into(),
        log_dir: artifacts.path("test-ledger").into(),
        programs: [
            (
                user_registry_program_id(),
                artifacts.path("target/deploy/spr_user_registry.so").into(),
            ),
            (
                smart_account,
                artifacts
                    .path("target/deploy/squads_smart_account_program.so")
                    .into(),
            ),
        ]
        .into_iter()
        .chain(
            GENESIS_PROGRAMS
                .iter()
                .map(|program| (program.address, ring_artifacts.path(program.path).into())),
        )
        .collect(),
        slot_time: None,
    };
    let deployments: Vec<UpgradeableProgram> = std::iter::once(UpgradeableProgram {
        address: spp_program,
        path: artifacts
            .path("target/deploy/shielded_pool_program.so")
            .into(),
        authority: accounts.protocol_vault,
    })
    .chain(
        std::iter::once(ring_program)
            .chain(extra_ring_programs.iter().copied())
            .map(|address| UpgradeableProgram {
                address,
                path: ring_program_so.clone(),
                authority: payer_address,
            }),
    )
    .collect();
    validator.start_with_upgradeable_programs(&deployments)?;
    RingIndexerLaunch {
        indexer_url: &localnet_indexer_url(),
        photon_url: &validator.ports.photon_url(),
        rpc_url: &localnet_rpc_url(),
        log_dir: &validator.log_dir,
    }
    .spawn()
    .context("start the ring indexer")?;

    start_prover(&validator.cli_bin)?;

    let rpc_url = localnet_rpc_url();
    let indexer_url = localnet_indexer_url();
    let mut rpc = SolanaRpc::new(rpc_url.clone());
    let indexer = ZolanaIndexer::new(indexer_url.clone());

    let authority = ProtocolSigners::new();
    let forester_authority = Keypair::new();
    let merge_authority = Keypair::new();
    let tree_creation_authority = Keypair::new();
    let ring_creation_authority = Keypair::new();
    rpc.airdrop(&payer.pubkey(), PAYER_AIRDROP)?;
    for member in authority.pubkeys() {
        rpc.airdrop(&member, SIGNER_AIRDROP)?;
    }
    rpc.airdrop(&forester_authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&merge_authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&tree_creation_authority.pubkey(), SIGNER_AIRDROP)?;
    rpc.airdrop(&ring_creation_authority.pubkey(), SIGNER_AIRDROP)?;

    for ix in accounts.create_ixs(
        &payer.pubkey(),
        StandardSigners {
            protocol: authority.pubkeys(),
            forester: forester_authority.pubkey(),
            merge: merge_authority.pubkey(),
            tree: tree_creation_authority.pubkey(),
            ring: ring_creation_authority.pubkey(),
        },
    ) {
        rpc.create_and_send_transaction(
            &[ix],
            payer_address,
            &[&payer],
            ComputeBudgetConfig::for_instruction_count(1),
        )?;
    }

    rpc.airdrop(&accounts.protocol_vault, PROTOCOL_VAULT_AIRDROP)?;

    // `ring_activation_is_permissionless` is the one bootstrap setting this
    // example needs to differ from the swap harness: with it set, the
    // custom-ring program can register its `ring_auth` PDA as an SPP ring
    // config with a plain payer, instead of the ring Squads vault having to
    // co-sign `create_ring_config`. Same precedent as the ring suite's
    // `BootstrapConfig` (program-tests/test-utils/src/ring/mod.rs).
    let create_config_ix = CreateProtocolConfig {
        fee_payer: payer.pubkey(),
        initialization_authority: accounts.protocol_vault,
        protocol_authority: accounts.protocol_vault.to_bytes().into(),
        fee_authority: accounts.protocol_vault.to_bytes().into(),
        tree_creation_authority: accounts.tree_vault.to_bytes().into(),
        tree_creation_is_permissionless: false,
        forester_authority: accounts.forester_vault.to_bytes().into(),
        ring_creation_authority: accounts.ring_vault.to_bytes().into(),
        ring_activation_is_permissionless: true,
        spl_interface_creation_is_permissionless: false,
    }
    .instruction();
    let create_config_sync =
        authority.execute_sync(&accounts.protocol_settings, &[create_config_ix]);
    rpc.create_and_send_transaction(
        &[create_config_sync],
        payer_address,
        &authority.dyn_with_fee_payer(&payer),
        ComputeBudgetConfig::for_instruction_count(1),
    )?;

    let tree_creation = create_tree_instructions(
        &rpc,
        &payer.pubkey(),
        &accounts.tree_vault,
        nullifier_tree_params(),
        default_tree_fees(nullifier_tree_params().input_queue_zkp_batch_size)
            .expect("default tree fees"),
    )?;
    let create_tree_syncs = smart_account::execute_sync_each(
        &accounts.tree_settings,
        0,
        &[tree_creation_authority.pubkey()],
        &tree_creation.instructions,
    );
    rpc.create_and_send_transaction(
        &create_tree_syncs,
        payer_address,
        &[&payer, &tree_creation_authority],
        ComputeBudgetConfig::for_instruction_count(create_tree_syncs.len()),
    )?;

    let tree = tree_creation.tree;

    let usdc_mint = create_mint(&rpc, &payer)?;
    RegisterSplAsset {
        payer: &payer,
        authority: &authority,
        protocol_settings: accounts.protocol_settings,
        protocol_vault: accounts.protocol_vault,
        mint: usdc_mint,
        token_program: pda::spl_token_program_id(),
    }
    .send(&rpc)?;

    let mut assets = AssetRegistry::default();
    assets.insert(USDC_ASSET_ID, usdc_mint)?;

    let sender = new_actor(&mut rpc, &assets)?;
    let recipient = new_actor(&mut rpc, &assets)?;

    let client = ZolanaServices {
        rpc,
        indexer,
        prover: AsyncProverClient::default(),
        ring_prover: AsyncProverClient::default(),
    }
    .connect();

    Ok(TestEnv {
        client,
        rpc_url,
        indexer_url,
        payer,
        tree,
        usdc_mint,
        assets,
        sender,
        recipient,
        tree_creation_authority,
        ring_creation_authority,
        standard_accounts: accounts,
    })
}

pub fn custom_ring_program_id() -> Result<Address> {
    let id = std::env::var("CUSTOM_RING_PROGRAM_ID")
        .map_err(|_| anyhow!("CUSTOM_RING_PROGRAM_ID is unset, run the suite through just"))?;
    id.trim()
        .parse()
        .map_err(|e| anyhow!("CUSTOM_RING_PROGRAM_ID {id} failed {e}"))
}

pub fn ring_program_so() -> String {
    std::env::var("CUSTOM_RING_PROGRAM_SO")
        .unwrap_or_else(|_| ring_artifacts().path("target/deploy/custom_ring_program.so"))
}

fn ring_artifacts() -> WorkspaceArtifacts {
    WorkspaceArtifacts::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// A fresh eddsa actor: one keypair funded on chain, its shielded address,
/// and an empty wallet over the shared asset registry.
fn new_actor(rpc: &mut SolanaRpc, assets: &AssetRegistry) -> Result<TestWallet> {
    let keypair = ShieldedKeypair::new_ed25519()?;
    rpc.airdrop(&keypair.pubkey(), ACTOR_AIRDROP)?;
    let address = keypair
        .shielded_address()
        .map_err(|e| anyhow!("actor address failed {e:?}"))?;
    let wallet =
        Wallet::new(address, assets.clone()).map_err(|e| anyhow!("actor wallet failed {e:?}"))?;
    Ok(TestWallet { wallet, keypair })
}

/// Send instructions as a transaction **v1** message paid and signed by
/// `payer`. The compute ceilings ride in the message header, so nothing is
/// prepended and the caller's first instruction stays at index 0.
pub fn send(rpc: &SolanaRpc, payer: &dyn Signer, ixs: &[Instruction]) -> Result<Signature> {
    Ok(rpc.create_and_send_transaction(
        ixs,
        payer.pubkey(),
        &[payer],
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer)),
    )?)
}

/// [`send`] with the role key the instructions name as their signer.
#[must_use]
pub struct SendAs<'a> {
    pub rpc: &'a SolanaRpc,
    pub payer: &'a dyn Signer,
    pub holder: &'a dyn Signer,
}

impl SendAs<'_> {
    pub fn send(self, ixs: &[Instruction]) -> Result<Signature> {
        Ok(self.rpc.create_and_send_transaction(
            ixs,
            self.payer.pubkey(),
            &[self.payer, self.holder],
            ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer)),
        )?)
    }
}

/// Sends a transaction that must be rejected and returns the runtime's typed failure,
/// the instruction sits at index 0 of a v1 message.
pub fn send_expecting_rejection(
    rpc: &SolanaRpc,
    payer: &dyn Signer,
    ix: Instruction,
) -> Result<ClientError> {
    RejectedTransact {
        payer,
        signers: &[],
        instruction: ix,
    }
    .send(rpc)
}

/// [`send_expecting_rejection`] with the signers a co-signed or delegated transact needs.
#[must_use]
pub struct RejectedTransact<'a> {
    pub payer: &'a dyn Signer,
    pub signers: &'a [&'a dyn Signer],
    pub instruction: Instruction,
}

impl RejectedTransact<'_> {
    pub fn send(self, rpc: &SolanaRpc) -> Result<ClientError> {
        let (blockhash, _) = rpc.get_latest_blockhash()?;
        let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer));
        let message =
            compile_message(&self.payer.pubkey(), &[self.instruction], blockhash, budget)?;
        let signers: Vec<&dyn Signer> = std::iter::once(self.payer)
            .chain(self.signers.iter().copied())
            .collect();
        let tx = sign_transaction(message, &signers)?;
        match rpc.client().send_and_confirm_transaction(&tx) {
            Ok(signature) => Err(anyhow!(
                "transaction {signature} was expected to be rejected but landed"
            )),
            Err(source) => Ok(ClientError::SolanaRpcTransaction {
                operation: "send v1",
                source,
            }),
        }
    }
}

/// Over [`send`], the failing instruction sits at index 0: a v1 message carries
/// its compute ceilings in the header, not in a prepended instruction.
#[must_use]
pub struct ExpectRejection<'a> {
    pub payer: &'a dyn Signer,
    pub instructions: &'a [Instruction],
}

impl ExpectRejection<'_> {
    pub fn send(self, rpc: &SolanaRpc) -> Result<ClientError> {
        match send(rpc, self.payer, self.instructions) {
            Ok(signature) => Err(anyhow!(
                "transaction {signature} was expected to be rejected but landed"
            )),
            Err(error) => error.downcast::<ClientError>(),
        }
    }
}
