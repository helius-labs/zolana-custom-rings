//! Every command but `new` reads `ring.toml`, the answers `new` recorded.

mod macros;

#[path = "config/arguments.rs"]
mod arguments;
pub use arguments::*;

#[path = "runtime/context.rs"]
mod context;
#[cfg(test)]
use context::resolve;
pub use context::*;

#[path = "runtime/chain.rs"]
mod chain;

#[path = "commands/wallet/identity/address.rs"]
pub mod address;
#[path = "commands/wallet/assets.rs"]
pub mod assets;
#[path = "commands/wallet/notes/audit.rs"]
pub mod audit;
#[path = "commands/ring/authority.rs"]
pub mod authority;
#[path = "config/catalogue.rs"]
pub mod catalogue;
#[path = "config/ring_config.rs"]
pub mod config;
#[path = "commands/ring/controls.rs"]
pub mod controls;
#[path = "commands/membership/delegate.rs"]
pub mod delegate;
#[path = "commands/ring/deploy.rs"]
pub mod deploy;
#[path = "commands/membership/enrolment.rs"]
pub mod enrolment;
#[path = "runtime/file.rs"]
pub mod file;
#[path = "commands/wallet/notes/fund.rs"]
pub mod fund;
#[path = "commands/ring/init.rs"]
pub mod init;
#[path = "commands/wallet/identity/keys.rs"]
pub mod keys;
#[path = "commands/wallet/notes/list.rs"]
pub mod list;
#[path = "commands/ring/localnet.rs"]
pub mod localnet;
#[path = "commands/membership/member.rs"]
pub mod member;
#[path = "commands/wallet/notes/merge.rs"]
pub mod merge;
#[path = "commands/ring/new.rs"]
pub mod new;
#[path = "operations/pipeline.rs"]
pub mod pipeline;
#[path = "commands/policy/mod.rs"]
pub mod policy;
#[path = "runtime/probe.rs"]
pub mod probe;
#[path = "operations/records.rs"]
mod records;
#[path = "commands/ring/release.rs"]
pub mod release;
#[path = "runtime/ring_rpc.rs"]
pub mod ring_rpc;
#[path = "commands/ring/status.rs"]
pub mod status;
#[path = "runtime/tool.rs"]
pub mod tool;
#[path = "commands/wallet/notes/transact.rs"]
pub mod transact;
#[path = "ui/terminal.rs"]
pub mod ui;
#[path = "commands/wallet/mod.rs"]
pub mod wallet;
#[path = "ui/wizard.rs"]
pub mod wizard;
#[path = "runtime/workspace.rs"]
mod workspace;

use std::{
    cell::{OnceCell, RefCell},
    fmt::Display,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context as _, Result};
use clap::{Args, FromArgMatches, Parser, Subcommand};
use custom_ring_interface::{compute_unit_limit, CustomRingError, InstructionTag};
use custom_ring_sdk::{
    CustomRing, CustomRingConfig, RingError, RingMode, RingOperation, RingSubmission,
    SettledSubmission, MERGE_DEFAULT_INPUT_COUNT,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use spr_api::BlockingInsideRuntime;
use spr_client::{
    prover::tee::TeePolicy, Blocking, ClientError, ComputeBudgetConfig, IndexerPollConfig, Rpc,
    SolanaRpc, ZolanaIndexer,
};
use spr_interface::error::ShieldedPoolError;
use spr_keypair::ShieldedAddress;
use zolana_ring_client::ReaderKey;

pub use crate::{
    chain::{transaction_error, Chain, Zolana, ZolanaServices},
    config::{CoSignClass, Mint, ModeName, RingConfig, Service, Target, ThresholdSpec, RING_TOML},
    list::{MemberArgs, MemberList},
    policy::ListName,
    records::Queued,
    ring_rpc::{RingRpcClient, Trust},
    transact::{EntrySpendName, Funding, Recipient},
    ui::{line, Ask},
};

pub const PROGRAM_KEYPAIR_FILE: &str = "keys/program-keypair.json";
pub const AUDITOR_KEY_FILE: &str = "keys/auditor.key";
pub const AUDITOR_PUBKEY_FILE: &str = "keys/auditor.key.pub";
pub const SENDER_KEYPAIR_FILE: &str = "keys/sender-keypair.json";
pub const DEFAULT_TRANSACT_AMOUNT: u64 = 100_000_000;
/// What localnet tops an account up to.
const LOCALNET_BALANCE: u64 = 100_000_000_000;
const MAX_COMPUTE_UNITS: u32 = 1_400_000;
const WAIT_TIMEOUT: Duration = Duration::from_secs(120);
const WAIT_POLL: Duration = Duration::from_millis(500);
/// About two and a half minutes, the backoff doubling to four seconds.
const INDEXER_POLL: IndexerPollConfig = IndexerPollConfig {
    num_retries: 40,
    delay_ms: 500,
    max_delay_ms: 4_000,
};

/// What a program refusal means for the operator.
fn hint(error: &ClientError) -> Option<&'static str> {
    let Some(TransactionError::InstructionError(_, InstructionError::Custom(code))) =
        transaction_error(error)
    else {
        return None;
    };
    [
        (CustomRingError::UnauthorizedInitializer as u32, "the program was deployed with an upgrade authority and only that key may create the config"),
        (CustomRingError::UnauthorizedAuthority as u32, "the config is held by another authority, `status` shows it"),
        (CustomRingError::InvalidPolicyRules as u32, "the program refuses the compiled rows, the program log names the refusal"),
        (CustomRingError::QueueFull as u32, "the record queue holds its member share, `zolana-ring list apply` applies it once it is due"),
        (ShieldedPoolError::UnauthorizedCaller as u32, "ring creation on this cluster is gated by the SPP ring creation authority"),
    ]
    .into_iter()
    .find_map(|(known, hint)| (known == code).then_some(hint))
}

/// An `Err` from `probe` is final, the last `Retry` explains a timeout.
pub fn wait_for<T>(label: impl Display, mut probe: impl FnMut() -> Result<Probe<T>>) -> Result<T> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match probe()? {
            Probe::Ready(value) => return Ok(value),
            Probe::NotYet => {}
            Probe::Retry(error) => last = Some(error),
        }
        thread::sleep(WAIT_POLL);
    }
    let timeout = format!("timed out waiting for {label}");
    Err(match last {
        Some(error) => error.context(timeout),
        None => anyhow::anyhow!(timeout),
    })
}

/// Only an error the indexer calls transient is polled again.
pub fn wait_for_indexed_transaction<R, I: Rpc + Send + Sync + 'static>(
    zolana: &Zolana<R, I>,
    signature: Signature,
) -> Result<()> {
    zolana
        .block_on(chain::wait_for_indexed_transaction(
            zolana.as_async().indexer(),
            signature,
            INDEXER_POLL,
        ))
        .with_context(|| format!("the indexer did not index {signature}"))
}

pub fn parse_and_run() -> Result<()> {
    run(Cli::parse())
}

/// `New` runs before any ring.toml exists, `Target` and `Url` before any RPC client.
pub fn run(cli: Cli) -> Result<()> {
    let silent = matches!(&cli.command, Command::New(args) if args.silent);
    let mut ask = ui::ask_for(silent);
    if let Command::New(args) = cli.command {
        return new::run(args, ask.as_mut(), cli.catalogue.as_deref());
    }
    let mut config = RingConfig::load(&cli.config)?;
    let recorded = match &cli.command {
        Command::Target { target } => Some(*target),
        Command::Devnet => Some(Target::Devnet),
        Command::Localnet(_) => Some(Target::Localnet),
        _ => None,
    };
    if let Some(target) = recorded {
        RingConfig::set_target(&cli.config, target)?;
        config.target = target;
    } else if let Some(target) = cli.target {
        config.target = target;
    }
    match cli.command {
        Command::Target { target } => line("target", target),
        Command::Devnet => probe::run_devnet(&config)?,
        Command::Localnet(args) => localnet::run(&cli.config, &config, args)?,
        Command::Url { service } => println!("{}", config.urls().service(service)),
        command => {
            let prover_tee_policy = cli
                .prover_tee_policy
                .as_deref()
                .map(config::read_tee_policy)
                .transpose()?;
            let mut ctx = ContextSetup {
                config_path: cli.config,
                config,
                ask,
                catalogue: cli.catalogue,
                prover_tee_policy,
                fee_payer_keypair: cli.fee_payer_keypair,
            }
            .open()?;
            dispatch(&mut ctx, command)?;
        }
    }
    Ok(())
}

fn dispatch(ctx: &mut Context, command: Command) -> Result<()> {
    match command {
        Command::Status => status::run(ctx),
        Command::Deploy(args) => {
            localnet::ensure(ctx)?;
            deploy::run(ctx, args)
        }
        Command::Init(args) => init::run(ctx, args),
        Command::Pipeline(args) => pipeline::run(ctx, args),
        Command::Transact(args) => transact::run(ctx, args),
        Command::Transfer(args) => transact::run_transfer(ctx, args),
        Command::Deposit(args) => transact::run_deposit(ctx, args),
        Command::Merge(args) => merge::run(ctx, args),
        Command::RpcCheck => ring_rpc::run_check(ctx),
        Command::Authority(command) => authority::run(ctx, command),
        Command::Reader(command) => controls::reader(ctx, command),
        Command::Cosigner(command) => controls::cosigner(ctx, command),
        Command::InsertFee(command) => controls::insert_fee(ctx, command),
        Command::Delegate(command) => controls::delegate(ctx, command),
        Command::Key(command) => member::key(ctx, command),
        Command::Enrolment(command) => enrolment::run(ctx, command),
        Command::List(command) => list::run(ctx, command),
        Command::Policy(command) => policy::run(ctx, command),
        Command::AuditorKey(args) => keys::run(&ctx.path(&args.key_file), args.create),
        Command::Audit(args) => audit::run(ctx, args),
        Command::Address(args) => address::run(ctx, args),
        Command::New(_)
        | Command::Target { .. }
        | Command::Url { .. }
        | Command::Devnet
        | Command::Localnet(_) => bail!("handled before the context loads"),
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, ValueEnum};
    use zolana_ring_policy::{ListId, Writer};

    use super::*;

    #[test]
    fn the_list_arg_names_every_authority_written_list() {
        let arms: Vec<ListId> = ListName::value_variants()
            .iter()
            .map(|arm| arm.id())
            .collect();
        let authority_written: Vec<ListId> = ListId::ALL
            .into_iter()
            .filter(|list_id| matches!(list_id.writer(), Writer::Authority))
            .collect();
        assert_eq!(arms, authority_written);
        for name in ListName::value_variants() {
            assert_eq!(
                ListName::from_str(name.as_str(), false).expect("parses"),
                *name
            );
        }
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn delegate_set_signs_with_the_delegate_keypair() {
        let parse = |args: &[&str]| {
            let argv = ["zolana-ring", "delegate", "set"]
                .iter()
                .chain(args)
                .copied();
            Cli::try_parse_from(argv).map(|cli| cli.command)
        };
        assert!(matches!(
            parse(&["--delegate-keypair", "keys/delegate.json"]),
            Ok(Command::Delegate(DelegateCommand::Set { delegate_keypair }))
                if delegate_keypair == Path::new("keys/delegate.json")
        ));
        let address = Address::new_from_array([7; 32]).to_string();
        assert!(parse(&["--delegate", &address]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn dev_uses_the_localnet_command() {
        assert!(matches!(
            Cli::try_parse_from(["zolana-ring", "dev", "--no-start"])
                .unwrap()
                .command,
            Command::Localnet(LocalnetArgs { no_start: true })
        ));
    }

    #[test]
    fn merge_takes_an_optional_mint_in_any_spelling_and_a_bounded_count() {
        let mint = Address::new_from_array([7; 32]);
        let parse = |args: &[&str]| {
            let argv = ["zolana-ring", "merge"].iter().chain(args).copied();
            match Cli::try_parse_from(argv).map(|cli| cli.command) {
                Ok(Command::Merge(args)) => Ok(args),
                Ok(_) => panic!("merge"),
                Err(error) => Err(error),
            }
        };
        let args = parse(&["--mint", &mint.to_string(), "--count", "4"]).expect("parses");
        assert_eq!((args.mint, args.count), (Some(Mint(mint)), 4));
        for sol in ["sol", "SOL"] {
            let args = parse(&["--mint", sol]).expect("sol");
            assert_eq!(args.mint, Some(Mint(spr_transaction::SOL_MINT)));
        }
        assert_eq!(parse(&[]).expect("defaults").count, 24);
        assert!(parse(&["--count", "24"]).is_ok());
        assert!(parse(&["--count", "25"]).is_err());
        assert!(parse(&["--count", "52"]).is_err());
        assert!(parse(&["--count", "1"]).is_err());
    }

    pub(crate) fn transfer_args(args: &[&str]) -> Result<TransferArgs, clap::Error> {
        let argv = ["zolana-ring", "transfer"].iter().chain(args).copied();
        match Cli::try_parse_from(argv).map(|cli| cli.command) {
            Ok(Command::Transfer(args)) => Ok(args),
            Ok(_) => panic!("transfer"),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn transfer_takes_several_recipients_a_mint_and_its_funding() {
        let mint = Address::new_from_array([7; 32]);
        let token = Address::new_from_array([8; 32]);
        let to = |seed: u8| {
            spr_keypair::ShieldedKeypair::from_keypair(spr_keypair::SigningKey::from_ed25519_bytes(
                &[seed; 32],
            ))
            .unwrap()
            .shielded_address()
            .unwrap()
        };
        let parse = transfer_args;
        let (first, second) = (to(1).to_string(), to(2).to_string());
        let args = parse(&[
            &first,
            &second,
            "--amount",
            "123",
            "--mint",
            &mint.to_string(),
            "--token-account",
            &token.to_string(),
            "--outputs",
            "8",
        ])
        .expect("parses");
        assert_eq!(
            args.to,
            [Recipient::Shielded(to(1)), Recipient::Shielded(to(2))]
        );
        assert_eq!(args.mint, Some(Mint(mint)));
        assert_eq!(args.token_account, Some(token));
        assert_eq!((args.amount, args.outputs), (Some(123), Some(8)));
        assert_eq!(args.funding, Funding::Deposit);
        let held = parse(&[&first, "--funding", "held"]).expect("held");
        assert_eq!((held.funding, held.amount), (Funding::Held, None));
        assert!(parse(&[]).is_err(), "a transfer names a recipient");
        assert!(parse(&[&first, "--funding", "faucet"]).is_err());
        assert!(parse(&[&first, "--entry-spend", "always"]).is_err());
    }

    #[test]
    fn a_deposit_moves_a_nonzero_amount() {
        let deposit = |amount: &str| {
            Cli::try_parse_from(["zolana-ring", "deposit", "--amount", amount])
                .map(|cli| cli.command)
        };
        assert!(deposit("0").is_err());
        assert!(matches!(
            deposit("1"),
            Ok(Command::Deposit(DepositArgs { amount: 1, .. }))
        ));
    }

    #[test]
    fn the_pipeline_runs_init_with_the_command_defaults() {
        let pipeline: InitArgs = defaults();
        let Command::Init(command) = Cli::try_parse_from(["zolana-ring", "init"])
            .expect("parses")
            .command
        else {
            panic!("init");
        };
        assert_eq!(command.auditor_pubkey_file, pipeline.auditor_pubkey_file);
        assert_eq!(command.trust_ring_rpc, pipeline.trust_ring_rpc);
        assert_eq!(command.local_auditor, pipeline.local_auditor);
        assert_eq!(
            resolve(Path::new("ring"), &pipeline.auditor_pubkey_file),
            Path::new("ring/keys/auditor.key.pub")
        );
        let transact: TransactArgs = defaults();
        assert_eq!(transact.amount, DEFAULT_TRANSACT_AMOUNT);
        assert!(transact.cosigner.cosigner_keypair.is_none());
    }

    fn transaction_error(error: TransactionError) -> ClientError {
        ClientError::SolanaRpcTransaction {
            operation: "test",
            source: solana_rpc_client_api::client_error::Error {
                request: None,
                kind: Box::new(
                    solana_rpc_client_api::client_error::ErrorKind::TransactionError(error),
                ),
            },
        }
    }

    #[test]
    fn only_a_known_custom_instruction_error_yields_a_hint() {
        let custom = |code| {
            transaction_error(TransactionError::InstructionError(
                1,
                InstructionError::Custom(code),
            ))
        };
        assert!(hint(&custom(CustomRingError::UnauthorizedAuthority as u32))
            .is_some_and(|hint| hint.contains("another authority")));
        assert_eq!(hint(&custom(1)), None);
        assert_eq!(
            hint(&transaction_error(TransactionError::AlreadyProcessed)),
            None
        );
        assert_eq!(hint(&ClientError::Rpc(String::new())), None);
    }

    #[test]
    fn the_indexer_wait_retries_only_a_transient_failure() {
        use std::sync::atomic::{AtomicU8, Ordering};

        use spr_client::{
            AsyncProverClient, GetShieldedTransactionsBySignatureResponse,
            IndexedShieldedTransaction, IndexerRpcConfig, ShieldedTransaction, WitnessReader,
        };

        /// Fails once, transiently when `transient`, then indexes the signature.
        struct Indexer {
            calls: AtomicU8,
            transient: bool,
        }

        impl WitnessReader for Indexer {}

        impl Rpc for Indexer {
            fn should_retry(&self, error: &ClientError) -> bool {
                matches!(error, ClientError::IndexerUnavailable(_))
            }

            fn get_shielded_transactions_by_signature(
                &self,
                _signature: Signature,
                _config: Option<IndexerRpcConfig>,
            ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
                if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(match self.transient {
                        true => ClientError::IndexerUnavailable("restarting".to_owned()),
                        false => ClientError::Rpc("refused".to_owned()),
                    });
                }
                Ok(GetShieldedTransactionsBySignatureResponse {
                    context: spr_client::Context {
                        block_time: 0,
                        slot: 1,
                    },
                    output_tree_id: None,
                    transactions: vec![IndexedShieldedTransaction {
                        event_index: 0,
                        transaction: ShieldedTransaction {
                            slot: 1,
                            tx_signature: Signature::default(),
                            event_index: None,
                            tx_viewing_pk: None,
                            salt: None,
                            output_slots: Vec::new(),
                            messages: Vec::new(),
                            nullifiers: Vec::new(),
                            proofless: true,
                            ring_config: None,
                            ring_program_id: None,
                        },
                    }],
                })
            }
        }

        struct NoRpc;
        impl Rpc for NoRpc {}

        let client = |transient| {
            ZolanaServices {
                rpc: NoRpc,
                indexer: Indexer {
                    calls: AtomicU8::new(0),
                    transient,
                },
                prover: AsyncProverClient::local(),
                ring_prover: AsyncProverClient::local(),
            }
            .connect()
        };
        let transient = client(true);
        wait_for_indexed_transaction(&transient, Signature::default()).expect("indexed");
        assert_eq!(transient.indexer().calls.load(Ordering::Relaxed), 2);
        let permanent = client(false);
        assert!(wait_for_indexed_transaction(&permanent, Signature::default()).is_err());
        assert_eq!(permanent.indexer().calls.load(Ordering::Relaxed), 1);
    }
}
