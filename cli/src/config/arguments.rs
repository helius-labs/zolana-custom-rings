//! Command-line arguments and subcommands.

use super::*;

#[derive(Debug, Parser)]
#[command(name = "zolana-ring", about = "Operate a custom ring")]
pub struct Cli {
    /// Path to ring.toml.
    #[arg(long, default_value = RING_TOML, global = true)]
    pub config: PathBuf,
    /// Cluster for one command instead of the one ring.toml records.
    #[arg(long, global = true, env = "RING_TARGET")]
    pub target: Option<Target>,
    /// A curator catalogue file or URL instead of the bundled one.
    #[arg(long, global = true, env = "RING_CATALOGUE")]
    pub catalogue: Option<String>,
    /// Require the prover to attest to the TEE policy in FILE, bare or as a {"deployment": ...}
    /// pin file, in place of the release pin.
    #[arg(
        long,
        value_name = "FILE",
        global = true,
        env = "RING_PROVER_TEE_POLICY"
    )]
    pub prover_tee_policy: Option<PathBuf>,
    /// Pays the member operations of an anonymous ring, never the hidden owner.
    #[arg(
        long,
        value_name = "FILE",
        global = true,
        env = "RING_FEE_PAYER_KEYPAIR"
    )]
    pub fee_payer_keypair: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the ring directory with ring.toml and the program keypair.
    New(NewArgs),
    /// Recorded answers and on-chain state.
    Status,
    /// Record the cluster the ring acts on in ring.toml.
    Target { target: Target },
    /// Print one service URL of the active target.
    Url { service: Service },
    /// Record devnet in ring.toml and probe the deployed services.
    Devnet,
    /// Record localnet in ring.toml and start the validator, Photon, the prover and the ring rpc.
    #[command(alias = "dev")]
    Localnet(LocalnetArgs),
    /// Deploy the released program under the authority, or upgrade it in place.
    Deploy(DeployArgs),
    /// Create the config with the auditor key, pin the policy and register the ring with SPP.
    Init(InitArgs),
    /// Deploy, init, check the ring rpc, grant the authority and transact.
    Pipeline(DeployArgs),
    /// Two ring deposits and one custom-ring transfer, read back from the ring RPC.
    Transact(TransactArgs),
    /// Pay recipients inside the ring from fresh deposits or from the sender's notes.
    Transfer(TransferArgs),
    /// Deposit into the sender's ring balance, every deposit carries its audit proof.
    Deposit(DepositArgs),
    /// Consolidate existing notes of one asset into one note.
    Merge(MergeArgs),
    /// Confirm the ring RPC in `ring.toml` is up and holds the ring's auditor key.
    RpcCheck,
    /// Transfer or renounce the program's upgrade authority.
    #[command(subcommand)]
    Authority(AuthorityCommand),
    /// Grant or revoke reads on the ring RPC.
    #[command(subcommand)]
    Reader(ReaderCommand),
    /// Set, clear or show the ring's co-signer.
    #[command(subcommand)]
    Cosigner(CoSignerCommand),
    /// Set or show the lamports a member's record write pays the config authority.
    #[command(subcommand)]
    InsertFee(InsertFeeCommand),
    /// Set or show the permanent delegate, or move a note as the delegate.
    #[command(subcommand)]
    Delegate(DelegateCommand),
    /// Escrow the member's nullifier key in its record of the ring member registry.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Read and write the list bits of member records and apply the record queue.
    #[command(subcommand)]
    List(ListCommand),
    /// Read, check and replace the pinned rule table.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Print the local auditor key's public key, or create the key file.
    AuditorKey(AuditorKeyArgs),
    /// Open the ring's transactions with the auditor key, read from the indexer.
    Audit(AuditArgs),
    /// Mint a `zolana:` payment request for the member on an anonymous ring.
    Address(AddressArgs),
}

#[derive(Debug, Subcommand)]
pub enum ListCommand {
    /// Set the list bit of each member's record, the pending writes apply in the same proof.
    Add(EntryArgs),
    /// Clear the list bit of each member's record.
    Clear(EntryArgs),
    /// Print whether each member's record carries the list.
    Show(EntryArgs),
    /// Point the list at the ring's own registry or a curator ring's.
    SetSource {
        #[arg(value_enum)]
        list_id: ListName,
        /// Curator ring program id or catalogue name.
        #[arg(long, conflicts_with = "own", required_unless_present = "own")]
        curator: Option<String>,
        /// The ring's own registry.
        #[arg(long)]
        own: bool,
    },
    /// Apply the queued member writes once the queue is full or aged, anyone may.
    Apply,
    /// Set a list the sender writes on its own record, it applies with the queue.
    Join {
        #[arg(value_enum)]
        list: MemberList,
    },
    /// Clear a list the sender writes on its own record.
    Leave {
        #[arg(value_enum)]
        list: MemberList,
    },
}

#[derive(Debug, Args)]
pub struct EntryArgs {
    #[arg(value_enum)]
    pub list_id: ListName,
    #[command(flatten)]
    pub members: MemberArgs,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// The pinned rows, hash, generation and sources.
    Show,
    /// Compare ring.toml with the chain, exits non-zero on a difference.
    Check,
    /// Replace the pinned table with ring.toml under the config authority.
    Set {
        /// Confirms the replacement, proofs built against the old table are refused from now on.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum CoSignerCommand {
    /// Create or replace the co-signer, flags absent means the `[cosigner]` table of ring.toml.
    Set {
        /// The Solana key that signs beside the sender.
        #[arg(long)]
        signer: Option<Address>,
        /// Operation classes the co-signer gates.
        #[arg(long, value_delimiter = ',', requires = "signer")]
        scope: Vec<CoSignClass>,
        /// `<mint>=<amount>` per mint, `sol` for the native token, withdrawals above it need the co-signer.
        #[arg(long, requires = "signer")]
        threshold: Vec<ThresholdSpec>,
    },
    /// Close the co-signer account, the rent returns to the authority.
    Clear,
    Show,
}

#[derive(Debug, Subcommand)]
pub enum InsertFeeCommand {
    /// Zero lets members write their records free.
    Set {
        lamports: u64,
    },
    Show,
}

#[derive(Debug, Subcommand)]
pub enum DelegateCommand {
    /// Set the delegate once, signed by the delegate and by the upgrade authority holding the ring
    /// auditor key.
    Set {
        /// The delegate's keypair, it signs the set and every later move.
        #[arg(long)]
        delegate_keypair: PathBuf,
    },
    Show,
    /// Move a source member's ring balance to shielded addresses over the delegate rail.
    Move(Box<DelegateMoveArgs>),
}

#[derive(Debug, Args)]
pub struct DelegateMoveArgs {
    /// Each recipient's base58 shielded address, every one receives the amount.
    #[arg(required = true, num_args = 1..)]
    pub to: Vec<ShieldedAddress>,
    /// The source member's base58 shielded address, its ring notes fund the move.
    #[arg(long)]
    pub source: ShieldedAddress,
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
    /// The mint moved, `sol` by default.
    #[arg(long)]
    pub mint: Option<Mint>,
    #[arg(long)]
    pub delegate_keypair: PathBuf,
    /// The X25519 auditor read key, separate from the Solana delegate signer.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub auditor_key: PathBuf,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

/// The co-signer of a ring whose scope covers the operation.
#[derive(Debug, Default, Args)]
pub struct CosignerArg {
    /// The co-signer keypair when the ring's co-signer scope covers the operation.
    #[arg(long)]
    pub cosigner_keypair: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Seal the member's nullifier key to the ring auditor and register it, `transfer` does it on first use.
    Register,
}

#[derive(Debug, Subcommand)]
pub enum ReaderCommand {
    /// A base58 Solana key or the 66-hex P-256 key of a passkey.
    Grant { reader: ReaderKey },
    /// Close the reader's record, the rent returns to the authority.
    Revoke { reader: ReaderKey },
}

#[derive(Debug, Subcommand)]
pub enum AuthorityCommand {
    /// Hand the program to another key, then set `upgrade_authority_keypair`.
    Transfer {
        new_authority: Address,
        /// Confirms the new key, nobody else can hand the program back.
        #[arg(long)]
        yes: bool,
    },
    /// Hand the ring config authority to another keypair, both keys sign.
    TransferConfig { new_authority_keypair: PathBuf },
    /// Stop every deposit, transfer and merge of the ring.
    Pause,
    /// Open the ring again after a pause.
    Resume,
    /// Make the program immutable, irreversible.
    Renounce {
        /// Confirms the irreversible step.
        #[arg(long)]
        yes: bool,
        /// The binary the deployment must match, the released ring program by default.
        #[arg(long)]
        program_so: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct NewArgs {
    /// Ring name in kebab-case, also the directory name, asked when absent.
    pub name: Option<String>,
    /// Parent directory the ring is created in.
    #[arg(long, default_value = ".")]
    pub dest: PathBuf,
    /// Answer every question with its default.
    #[arg(long)]
    pub silent: bool,
    /// Recorded in ring.toml, `~` stays literal for other machines.
    #[arg(long, default_value = new::DEFAULT_AUTHORITY_KEYPAIR)]
    pub authority_keypair: String,
    /// A `ring.toml` or any toml file with a `[policy]` table, replaces the policy questions.
    #[arg(long)]
    pub policy_from: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct LocalnetArgs {
    /// Record the target and print the URLs, start nothing.
    #[arg(long)]
    pub no_start: bool,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// The X25519 auditor read key the ring config pins.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub auditor_key: PathBuf,
    /// Continue from the hex cursor an earlier run printed.
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Debug, Args)]
pub struct AuditorKeyArgs {
    /// The auditor secret a local ring rpc serves, its `.pub` sits beside it.
    #[arg(long, default_value = AUDITOR_KEY_FILE)]
    pub key_file: PathBuf,
    /// Create the key and its `.pub` instead of reading it, refuses to overwrite.
    #[arg(long)]
    pub create: bool,
}

#[derive(Debug, Args)]
pub struct AddressArgs {
    /// The member's Solana keypair, `keys/sender-keypair.json` by default.
    #[arg(long)]
    pub keypair: Option<PathBuf>,
    /// Requested amount in base units, unauthenticated like the mint and label.
    #[arg(long)]
    pub amount: Option<u64>,
    #[arg(long)]
    pub mint: Option<Mint>,
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// A local binary instead of the released ring program.
    #[arg(long)]
    pub program_so: Option<PathBuf>,
    #[arg(long, default_value = PROGRAM_KEYPAIR_FILE)]
    pub program_keypair: PathBuf,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Hex tagged X25519 auditor key, created by the ring RPC and written here when absent.
    #[arg(long, default_value = AUDITOR_PUBKEY_FILE)]
    pub auditor_pubkey_file: PathBuf,
    /// Accept the ring RPC's auditor key without a pinned service key in ring.toml.
    #[arg(long)]
    pub trust_ring_rpc: bool,
    /// Pin the key in `keys/` even though the ring RPC is not on this machine.
    /// Only a ring RPC holding that key can ever open the ring.
    #[arg(long)]
    pub local_auditor: bool,
}

#[derive(Debug, Args)]
pub struct TransactArgs {
    /// Lamports the recipient receives, deposited twice by the authority.
    #[arg(long, default_value_t = DEFAULT_TRANSACT_AMOUNT)]
    pub amount: u64,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

#[derive(Debug, Args)]
pub struct TransferArgs {
    /// Each recipient, a base58 shielded address on a confidential ring, a `zolana:` request
    /// on an anonymous one, or a shielded address with `--default-ring`.
    #[arg(required = true, num_args = 1..)]
    pub to: Vec<Recipient>,
    /// Base units each recipient receives, a request's own amount or the default when absent.
    #[arg(long)]
    pub amount: Option<u64>,
    /// Registered mint, a request's own mint or `sol` when absent.
    #[arg(long)]
    pub mint: Option<Mint>,
    /// Payer's SPL funding account, its ATA by default.
    #[arg(long)]
    pub token_account: Option<Address>,
    /// `deposit` funds the payments with two fresh deposits, `held` spends the sender's notes
    /// of the ring, and of the default ring on a confidential ring.
    #[arg(long, value_enum, default_value_t = Funding::Deposit)]
    pub funding: Funding,
    /// Spending default-ring notes publishes the hidden owner's key, `allow` lets `--funding held`
    /// spend them in place of ring notes that fall short.
    #[arg(long, value_enum, default_value_t = EntrySpendName::Refuse)]
    pub entry_spend: EntrySpendName,
    /// The fewest output slots, dummies fill what the payments and the change leave.
    #[arg(long)]
    pub outputs: Option<usize>,
    /// An anonymous ring pays each shielded recipient a default-ring note, the value leaves the ring.
    #[arg(long)]
    pub default_ring: bool,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

#[derive(Debug, Args)]
pub struct DepositArgs {
    /// Base units the authority deposits into the sender's ring balance.
    #[arg(
        long,
        default_value_t = DEFAULT_TRANSACT_AMOUNT,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub amount: u64,
    /// Registered mint, `sol` by default.
    #[arg(long)]
    pub mint: Option<Mint>,
    /// Payer's SPL funding account, its ATA by default.
    #[arg(long)]
    pub token_account: Option<Address>,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Mint to merge, `sol` by default.
    #[arg(long)]
    pub mint: Option<Mint>,
    /// Maximum number of notes to merge, from 2 through 50.
    #[arg(
        long,
        default_value_t = MERGE_DEFAULT_INPUT_COUNT as u64,
        value_parser = clap::value_parser!(u64).range(2..=custom_ring_sdk::MAX_RING_MERGE_INPUTS as u64)
    )]
    pub count: u64,
    #[command(flatten)]
    pub cosigner: CosignerArg,
}

/// The arguments a command defaults to, what the pipeline runs each step with.
pub fn defaults<T: Args + FromArgMatches>() -> T {
    let command = T::augment_args(clap::Command::new("defaults"));
    T::from_arg_matches(&command.get_matches_from(["defaults"]))
        .expect("every argument has a default")
}
