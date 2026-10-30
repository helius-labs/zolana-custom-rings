use std::{
    net::IpAddr,
    num::{NonZeroU32, NonZeroU64},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use rand::RngCore;
use solana_address::Address;
use solana_keypair::Keypair;
use thiserror::Error;
use zeroize::Zeroizing;
use zolana_ring_client::rpc::{auditor_keypair, KeyFileError};
use zolana_secret_file::{create_new, read_key32, Access, SecretFileError, Visibility};

use crate::{
    client_rate::ClientLimitArgs, keys::KeySource, origins::OriginTransport, server::BindPolicy,
};

#[derive(Debug, Parser)]
#[command(
    name = "ring-rpc",
    about = "Ring RPC for a custom ring with an auditor"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve(Box<ServeArgs>),
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long, env = "RING_RPC_BIND", default_value = "127.0.0.1")]
    pub bind: IpAddr,
    #[arg(long, env = "RING_RPC_PORT", default_value_t = 8785)]
    pub port: u16,
    #[arg(
        long,
        env = "RING_RPC_INDEXER_URL",
        default_value = "http://127.0.0.1:8784"
    )]
    pub indexer_url: String,
    #[arg(
        long,
        env = "RING_RPC_SOLANA_RPC_URL",
        default_value = "http://127.0.0.1:8899"
    )]
    pub rpc_url: String,
    /// Lowercase hex X25519 secret bytes.
    #[arg(
        long,
        env = "RING_RPC_AUDITOR_KEY_FILE",
        conflicts_with = "root_secret_file",
        required_unless_present = "root_secret_file"
    )]
    pub auditor_key_file: Option<PathBuf>,
    #[arg(long, env = "RING_RPC_RING_PROGRAM_ID", requires = "auditor_key_file")]
    pub ring_program_id: Option<Address>,
    /// Lowercase hex root secret.
    #[arg(long, env = "RING_RPC_ROOT_SECRET_FILE")]
    pub root_secret_file: Option<PathBuf>,
    /// Lowercase hex Ed25519 seed, every read and auditor key attestation binds its public key.
    #[arg(long, env = "RING_RPC_SERVICE_KEY_FILE")]
    pub service_key_file: PathBuf,
    /// Lowercase hex Ed25519 seed of the `StorageRegistry` authority the record writer signs as.
    #[arg(
        long,
        env = "RING_RPC_STORAGE_AUTHORITY_KEY_FILE",
        requires = "store_url"
    )]
    pub storage_authority_key_file: Option<PathBuf>,
    /// Lowercase hex Ed25519 seed, turns on co-signing under the asset limits.
    #[arg(long, env = "RING_RPC_CO_SIGNER_KEY_FILE", requires = "store_url")]
    pub co_signer_key_file: Option<PathBuf>,
    /// Lowercase hex secret the grant row cipher and lookup keys expand from.
    #[arg(long, env = "RING_RPC_GRANT_ROWS_KEY_FILE")]
    pub grant_rows_key_file: Option<PathBuf>,
    #[arg(
        long = "allow-origin",
        env = "RING_RPC_ALLOW_ORIGINS",
        value_delimiter = ','
    )]
    pub allow_origins: Vec<String>,
    #[arg(long, env = "RING_RPC_WEBAUTHN_RP_ID")]
    pub webauthn_rp_id: Option<String>,
    #[arg(long, env = "RING_RPC_MAX_CONNECTIONS", default_value = "256")]
    pub max_connections: NonZeroU32,
    #[arg(long, env = "RING_RPC_REQUEST_TIMEOUT_SECS", default_value = "30")]
    pub request_timeout_secs: NonZeroU64,
    #[arg(long, env = "RING_RPC_UPSTREAM_TIMEOUT_SECS", default_value = "10")]
    pub upstream_timeout_secs: NonZeroU64,
    #[arg(long, env = "RING_RPC_ALLOW_SHARED_KEY_FILE")]
    pub allow_shared_key_file: bool,
    /// Lowercase hex Ed25519 seed, set to relay transfers and pay their fees.
    #[arg(
        long,
        env = "RING_RPC_FEE_PAYER_KEY_FILE",
        requires_all = ["store_url", "prover_url"]
    )]
    pub fee_payer_key_file: Option<PathBuf>,
    /// `postgres://` or `sqlite://` URL of the service store, also turns the record writer on.
    #[arg(
        long,
        env = "RING_RPC_STORE_URL",
        requires_all = ["prover_url", "storage_authority_key_file"]
    )]
    pub store_url: Option<String>,
    /// Serves the ring keys the record writer and the relay prove with.
    #[arg(long, env = "RING_RPC_PROVER_URL", requires = "store_url")]
    pub prover_url: Option<String>,
    /// Serve plain HTTP on a public address and accept plain HTTP origins, test deployments only.
    #[arg(long, env = "RING_RPC_INSECURE_PUBLIC_BIND")]
    pub insecure_public_bind: bool,
    /// The one store the service reads reader grants from.
    #[arg(
        long,
        env = "RING_RPC_READER_GRANTS",
        value_enum,
        default_value_t = ReaderGrantStore::Tree,
        requires_ifs([("database", "store_url"), ("database", "grant_rows_key_file")])
    )]
    pub reader_grants: ReaderGrantStore,
    #[command(flatten)]
    pub client_limits: ClientLimitArgs,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ReaderGrantStore {
    /// `Reader` lists of the ring's own storage tree.
    #[default]
    Tree,
    /// Sealed rows of the service store, signed through `setReaderGrant`.
    Database,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, value_enum, default_value_t = KeyKind::Auditor)]
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KeyKind {
    Auditor,
    Root,
    FeePayer,
    Service,
    StorageAuthority,
    CoSigner,
    GrantRows,
}

impl KeyKind {
    pub const fn role(self) -> &'static str {
        match self {
            Self::Auditor => "auditor",
            Self::Root => "root secret",
            Self::FeePayer => "fee payer",
            Self::Service => "service",
            Self::StorageAuthority => "storage authority",
            Self::CoSigner => "co-signer",
            Self::GrantRows => "grant rows",
        }
    }

    pub const fn flag(self) -> &'static str {
        match self {
            Self::Auditor => "--auditor-key-file",
            Self::Root => "--root-secret-file",
            Self::FeePayer => "--fee-payer-key-file",
            Self::Service => "--service-key-file",
            Self::StorageAuthority => "--storage-authority-key-file",
            Self::CoSigner => "--co-signer-key-file",
            Self::GrantRows => "--grant-rows-key-file",
        }
    }
}

/// No two roles share a secret.
pub struct ServeKeys {
    pub auditor: KeySource,
    pub service: Keypair,
    pub storage_authority: Option<Keypair>,
    pub co_signer: Option<Keypair>,
    pub grant_rows: Option<GrantRowsSecret>,
    pub fee_payer: Option<Keypair>,
}

#[derive(Debug, Error)]
pub enum ServeKeyError {
    #[error("{flag} is unusable because {source}")]
    File {
        flag: &'static str,
        #[source]
        source: SecretFileError,
    },
    #[error("{0} holds a zero key")]
    Zero(&'static str),
    #[error("auditor key is unusable because {0}")]
    Auditor(#[from] KeyFileError),
    #[error("pass exactly one of --auditor-key-file and --root-secret-file")]
    AuditorMode,
    #[error("--ring-program-id must name the served ring")]
    RingMissing,
    #[error("{0} and {1} hold the same key")]
    Shared(&'static str, &'static str),
}

pub struct GrantRowsSecret(Zeroizing<[u8; 32]>);

impl ServeArgs {
    pub fn origin_transport(&self) -> OriginTransport {
        if self.insecure_public_bind {
            OriginTransport::InsecureHttp
        } else {
            OriginTransport::SecureOnly
        }
    }

    pub fn bind_policy(&self) -> BindPolicy {
        if self.insecure_public_bind {
            BindPolicy::InsecurePublic
        } else {
            BindPolicy::LoopbackOnly
        }
    }

    pub fn key_access(&self) -> Access {
        if self.allow_shared_key_file {
            Access::Shared
        } else {
            Access::OwnerOnly
        }
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.get())
    }

    pub fn upstream_timeout(&self) -> Duration {
        Duration::from_secs(self.upstream_timeout_secs.get())
    }

    pub fn read_keys(&self) -> Result<ServeKeys, ServeKeyError> {
        let read = |kind: KeyKind, path: Option<&Path>| {
            path.map(|path| read_role_secret(kind, path, self.key_access()))
                .transpose()
        };
        let auditor = read(KeyKind::Auditor, self.auditor_key_file.as_deref())?;
        let root = read(KeyKind::Root, self.root_secret_file.as_deref())?;
        let service =
            read_role_secret(KeyKind::Service, &self.service_key_file, self.key_access())?;
        let storage_authority = read(
            KeyKind::StorageAuthority,
            self.storage_authority_key_file.as_deref(),
        )?;
        let co_signer = read(KeyKind::CoSigner, self.co_signer_key_file.as_deref())?;
        let grant_rows = read(KeyKind::GrantRows, self.grant_rows_key_file.as_deref())?;
        let fee_payer = read(KeyKind::FeePayer, self.fee_payer_key_file.as_deref())?;
        refuse_shared(&[
            (KeyKind::Auditor, auditor.as_deref()),
            (KeyKind::Root, root.as_deref()),
            (KeyKind::Service, Some(&*service)),
            (KeyKind::StorageAuthority, storage_authority.as_deref()),
            (KeyKind::CoSigner, co_signer.as_deref()),
            (KeyKind::GrantRows, grant_rows.as_deref()),
            (KeyKind::FeePayer, fee_payer.as_deref()),
        ])?;
        let auditor = match (auditor, root) {
            (Some(secret), None) => KeySource::Local {
                ring: self.ring_program_id.ok_or(ServeKeyError::RingMissing)?,
                auditor: auditor_keypair(&secret)?,
            },
            (None, Some(secret)) => KeySource::Derived(
                RootSecret::from_bytes(*secret)
                    .map_err(|_| ServeKeyError::Zero(KeyKind::Root.flag()))?,
            ),
            _ => return Err(ServeKeyError::AuditorMode),
        };
        let keypair = |seed: Zeroizing<[u8; 32]>| Keypair::new_from_array(*seed);
        Ok(ServeKeys {
            auditor,
            service: keypair(service),
            storage_authority: storage_authority.map(keypair),
            co_signer: co_signer.map(keypair),
            grant_rows: grant_rows.map(GrantRowsSecret),
            fee_payer: fee_payer.map(keypair),
        })
    }
}

/// Public keys of two key types never match, the raw secrets do.
fn refuse_shared(secrets: &[(KeyKind, Option<&[u8; 32]>)]) -> Result<(), ServeKeyError> {
    let named: Vec<_> = secrets
        .iter()
        .filter_map(|(kind, secret)| secret.map(|secret| (*kind, secret)))
        .collect();
    for (index, (first, first_secret)) in named.iter().enumerate() {
        for (second, second_secret) in &named[index + 1..] {
            if bool::from(first_secret.ct_eq(second_secret.as_slice())) {
                return Err(ServeKeyError::Shared(first.flag(), second.flag()));
            }
        }
    }
    Ok(())
}

fn read_role_secret(
    kind: KeyKind,
    path: &Path,
    access: Access,
) -> Result<Zeroizing<[u8; 32]>, ServeKeyError> {
    let secret = read_key32(path, access).map_err(|source| ServeKeyError::File {
        flag: kind.flag(),
        source,
    })?;
    if *secret == [0; 32] {
        return Err(ServeKeyError::Zero(kind.flag()));
    }
    Ok(secret)
}

pub struct RootSecret(Zeroizing<[u8; 32]>);

#[derive(Debug, Error)]
pub enum RootSecretError {
    #[error("root secret cannot be zero")]
    Zero,
    #[error(transparent)]
    File(#[from] SecretFileError),
}

impl RootSecret {
    pub fn random() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            if let Ok(root) = Self::from_bytes(bytes) {
                return root;
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RootSecretError> {
        if bytes == [0; 32] {
            return Err(RootSecretError::Zero);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn read_root_secret(path: &Path, access: Access) -> Result<RootSecret, RootSecretError> {
    RootSecret::from_bytes(*read_key32(path, access)?)
}

pub fn write_root_secret(out: &Path) -> Result<(), RootSecretError> {
    let root = Zeroizing::new(hex::encode(RootSecret::random().as_bytes()));
    Ok(create_new(out, root.as_bytes(), Visibility::Secret)?)
}

impl GrantRowsSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn write_keypair(out: &Path) -> Result<Keypair, SecretFileError> {
    Ok(Keypair::new_from_array(*write_random_key32(out)?))
}

pub fn write_grant_rows_secret(out: &Path) -> Result<(), SecretFileError> {
    write_random_key32(out).map(drop)
}

fn write_random_key32(out: &Path) -> Result<Zeroizing<[u8; 32]>, SecretFileError> {
    let mut secret = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(secret.as_mut_slice());
    create_new(
        out,
        Zeroizing::new(hex::encode(*secret)).as_bytes(),
        Visibility::Secret,
    )?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use solana_signer::Signer;

    use super::*;
    use crate::{
        database::Store,
        hub::{Hub, ServiceIdentity},
        storage_chain::LiveStorageChain,
        upstream::{ChainSource, Upstreams},
    };

    const UNREACHABLE: &str = "http://127.0.0.1:1";

    /// `serve` with a store and a prover, an `@name` flag resolves under `dir`.
    fn serve_args(dir: &Path, flags: &[&str]) -> Result<ServeArgs, clap::Error> {
        let path = |name: &str| dir.join(name).display().to_string();
        let mut argv = vec!["ring-rpc".to_owned(), "serve".to_owned()];
        argv.extend(
            [
                "--store-url",
                "sqlite::memory:",
                "--prover-url",
                UNREACHABLE,
            ]
            .map(String::from),
        );
        argv.extend(flags.iter().map(|flag| match flag.strip_prefix('@') {
            Some(name) => path(name),
            None => (*flag).to_owned(),
        }));
        match Cli::try_parse_from(argv)?.command {
            Command::Serve(args) => Ok(*args),
            Command::Keygen(_) => panic!("serve parses as keygen"),
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn a_zero_or_malformed_root_secret_is_refused() {
        let dir = temp_dir("zero");
        let zero = dir.join("zero.key");
        create_new(&zero, "00".repeat(32).as_bytes(), Visibility::Secret).expect("zero");
        assert!(matches!(
            read_root_secret(&zero, Access::OwnerOnly),
            Err(RootSecretError::Zero)
        ));
        let upper = dir.join("upper.key");
        create_new(&upper, "AA".repeat(32).as_bytes(), Visibility::Secret).expect("upper");
        assert!(matches!(
            read_root_secret(&upper, Access::OwnerOnly),
            Err(RootSecretError::File(SecretFileError::Hex))
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn root_keygen_writes_a_nonzero_private_secret() {
        let dir = temp_dir("root-keygen");
        let secret = dir.join("nested/root.key");
        write_root_secret(&secret).expect("keygen");
        let root = read_root_secret(&secret, Access::OwnerOnly).expect("root");
        assert!(root.as_bytes().iter().any(|byte| *byte != 0));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn the_same_key_file_for_two_roles_is_refused() {
        let dir = temp_dir("shared-role");
        write_keypair(&dir.join("shared.key")).expect("shared");
        write_keypair(&dir.join("storage.key")).expect("storage");
        write_root_secret(&dir.join("root.key")).expect("root");
        let ed25519 = serve_args(
            &dir,
            &[
                "--root-secret-file",
                "@root.key",
                "--service-key-file",
                "@shared.key",
                "--storage-authority-key-file",
                "@storage.key",
                "--co-signer-key-file",
                "@shared.key",
            ],
        )
        .expect("args");
        assert!(matches!(
            ed25519.read_keys(),
            Err(ServeKeyError::Shared(
                "--service-key-file",
                "--co-signer-key-file"
            ))
        ));
        let secret = serve_args(
            &dir,
            &[
                "--root-secret-file",
                "@root.key",
                "--service-key-file",
                "@shared.key",
                "--storage-authority-key-file",
                "@storage.key",
                "--grant-rows-key-file",
                "@root.key",
            ],
        )
        .expect("args");
        assert!(matches!(
            secret.read_keys(),
            Err(ServeKeyError::Shared(
                "--root-secret-file",
                "--grant-rows-key-file"
            ))
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[tokio::test]
    async fn each_role_signs_with_the_key_of_its_own_file() {
        let dir = temp_dir("own-file");
        write_root_secret(&dir.join("root.key")).expect("root");
        let service = write_keypair(&dir.join("service.key")).expect("service");
        let storage = write_keypair(&dir.join("storage.key")).expect("storage");
        let co_signer = write_keypair(&dir.join("co-signer.key")).expect("co-signer");
        let keys = serve_args(
            &dir,
            &[
                "--root-secret-file",
                "@root.key",
                "--service-key-file",
                "@service.key",
                "--storage-authority-key-file",
                "@storage.key",
                "--co-signer-key-file",
                "@co-signer.key",
            ],
        )
        .expect("args")
        .read_keys()
        .expect("keys");
        let KeySource::Derived(root) = keys.auditor else {
            panic!("a root secret serves derived keys");
        };
        let upstreams = Upstreams {
            indexer_url: UNREACHABLE,
            rpc_url: UNREACHABLE,
            timeout: Duration::from_secs(1),
        };
        let chain = LiveStorageChain::connect(upstreams, UNREACHABLE).expect("chain");
        let identity = ServiceIdentity {
            genesis_hash: [1; 32],
            service: keys.service,
        };
        let hub = Hub::builder(ChainSource::connect(upstreams).expect("source"), identity)
            .with_store(Store::open("sqlite::memory:", 1).await.expect("store"))
            .with_storage_chain(Arc::new(chain), keys.storage_authority.expect("storage"))
            .with_co_signer(keys.co_signer.expect("co-signer"))
            .derived(root)
            .expect("hub");

        assert_eq!(hub.service_pubkey(), service.pubkey());
        assert_eq!(
            hub.record_writer().expect("writer").authority(),
            storage.pubkey()
        );
        assert_eq!(hub.co_signer().signer(), Some(co_signer.pubkey()));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn database_reader_grants_need_the_grant_rows_key_file() {
        let dir = temp_dir("grant-rows");
        let refused = serve_args(
            &dir,
            &[
                "--root-secret-file",
                "@root.key",
                "--service-key-file",
                "@service.key",
                "--storage-authority-key-file",
                "@storage.key",
                "--reader-grants",
                "database",
            ],
        )
        .expect_err("database grants without a grant rows key");
        assert!(refused.to_string().contains("--grant-rows-key-file"));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
