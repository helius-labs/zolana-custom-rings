//! `localnet`, the `zolana` cli's validator plus the ring rpc of the release of the binary.

use std::{
    env,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::STORAGE_PROGRAM_ID;
use serde::Deserialize;
use solana_address::Address;
use zolana_cli_common::{
    config_dir,
    process::{answers, process_scope, spawn_owned, stop_owned_listener, wait_until},
    release::{host_platform, make_executable, Asset},
};

use crate::{
    config::{RingConfig, Target, Urls},
    file, keys, line, probe,
    release::{RingKey, RingRelease, RING_KEYS},
    tool::{Tool, SOLANA_TEST_VALIDATOR, ZOLANA},
    ui::{self, icon},
    workspace::{Workspace, WRONG_TARGET},
    Context, LocalnetArgs, AUDITOR_KEY_FILE,
};

/// A fixed id with no deploy keypair.
pub struct GenesisProgram {
    pub address: Address,
    /// Relative to the workspace root.
    pub path: &'static str,
    pub release_section: &'static str,
}

/// Mirrored by ring-genesis-programs in justfile.
pub const GENESIS_PROGRAMS: [GenesisProgram; 1] = [GenesisProgram {
    address: STORAGE_PROGRAM_ID,
    path: "target/deploy/storage_program.so",
    release_section: "storage_program",
}];

#[derive(Debug)]
struct GenesisFile {
    address: Address,
    path: PathBuf,
}

/// SIMD-0500 off, the ring program deploys as SBPF v0 like on devnet.
const SBPF_V0_FEATURE: &str = "B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g";
const RING_RPC: Tool = Tool::new(
    "ring-rpc serve",
    "rerun `zolana-ring localnet`, it downloads the ring rpc of the release",
);
const READY_TIMEOUT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct ProverHealth {
    circuits: Vec<String>,
}

/// The target is recorded first, a failed bring-up still leaves ring.toml on localnet.
pub fn run(config_path: &Path, config: &RingConfig, args: LocalnetArgs) -> Result<()> {
    probe::print_urls(config);
    if !args.no_start {
        bring_up(config, &config_path.with_file_name(AUDITOR_KEY_FILE), true)?;
        println!("\nlocalnet ready, next `zolana-ring pipeline`");
    }
    Ok(())
}

/// Localnet only, `devnet` probes its services instead of starting them.
pub fn ensure(ctx: &Context) -> Result<()> {
    if ctx.config.target == Target::Localnet {
        bring_up(&ctx.config, &ctx.path(Path::new(AUDITOR_KEY_FILE)), false)?;
    }
    Ok(())
}

/// A live validator keeps its ledger, the ring rpc is replaced only on request.
fn bring_up(config: &RingConfig, auditor_key: &Path, replace: bool) -> Result<()> {
    if let Some(workspace) = Workspace::from_env()? {
        return bring_up_workspace(&workspace, config, auditor_key, replace);
    }
    let urls = config.urls();
    let [rpc, photon, prover, ring_rpc] = ports(urls)?;
    let release = RingRelease::from_lock()?;
    if answers(local(rpc)) {
        line("validator", format_args!("{} answers", urls.rpc));
    } else {
        ZOLANA.check_installed()?;
        SOLANA_TEST_VALIDATOR.check_installed()?;
        let keys_dir = prover_keys_dir()?;
        for key in RING_KEYS {
            release.ensure_as(release.key(key)?, &keys_dir.join(key.file_name()))?;
        }
        let genesis = genesis_files(&release, |asset| release.ensure(asset))?;
        line("validator", "zolana dev start");
        let start = ReleaseDevStart {
            ports: [rpc, photon, prover],
            genesis,
        };
        ZOLANA.named("zolana dev start").run(&mut start.command())?;
    }
    check_prover_serves_custom_ring(&urls.prover)?;
    if !replace && answers(local(ring_rpc)) {
        line("ring rpc", format_args!("{} answers", urls.ring_rpc));
        return Ok(());
    }
    keys::ensure(auditor_key)?;
    let (os, arch) = host_platform()?;
    let binary = release.ensure(release.binary("ring_rpc", os, arch)?)?;
    make_executable(&binary)?;
    let command = serve(&binary, config, ring_rpc, auditor_key);
    start_ring_rpc(command, config, ring_rpc, &scope()?)
}

/// Every service from the workspace build, the ring rpc in the foreground.
fn bring_up_workspace(
    workspace: &Workspace,
    config: &RingConfig,
    auditor_key: &Path,
    replace: bool,
) -> Result<()> {
    ensure!(config.target == Target::Localnet, WRONG_TARGET);
    workspace.check_artifacts()?;
    let urls = config.urls();
    let services = [&urls.rpc, &urls.indexer, &urls.prover, &urls.ring_rpc];
    for url in services {
        ensure!(
            Urls::is_local(url),
            "workspace services require a loopback URL, found {url}"
        );
    }
    let ports = ports(urls)?;
    let [rpc, indexer, prover, ring_rpc] = ports;
    if !replace {
        answering(ports.into_iter().zip(services))?;
        return check_prover_serves_custom_ring(&urls.prover);
    }
    let addr = local(ring_rpc);
    ensure!(!answers(addr), "{addr} stays busy, stop the listener on it");
    let photon = workspace.photon_port(indexer)?;
    let fresh_chain = !answers(local(rpc));
    if fresh_chain {
        let snapshots = workspace.account_snapshots()?;
        let mut command = workspace.command()?;
        command
            .args(["dev", "start", "--local", "--skip-prover"])
            .args(["--rpc-port", &rpc.to_string()])
            .args(["--photon-port", &photon.to_string()])
            .args(["--photon-start-slot", "0", "--account-dir"])
            .arg(snapshots)
            .arg("--sbf-program")
            .arg(spr_interface::pda::shielded_pool_program_id().to_string())
            .arg(workspace.shielded_pool_so()?);
        for program in &GENESIS_PROGRAMS {
            command
                .arg("--sbf-program")
                .arg(program.address.to_string())
                .arg(workspace.artifact(program.path)?);
        }
        command.args(["--", "--deactivate-feature", SBPF_V0_FEATURE]);
        ZOLANA
            .named("workspace zolana dev start")
            .run(&mut command)?;
    }
    answering([(photon, &format!("http://127.0.0.1:{photon}"))])?;
    RingIndexer {
        workspace,
        urls,
        port: indexer,
        photon,
        fresh_chain,
    }
    .start()?;
    if !answers(local(prover)) {
        let mut command = workspace.command()?;
        command
            .args(["dev", "prover", "start"])
            .args(["--prover-port", &prover.to_string()])
            .args(["--indexer-url", &urls.indexer]);
        ZOLANA
            .named("workspace zolana dev prover start")
            .run(&mut command)?;
    }
    check_prover_serves_custom_ring(&urls.prover)?;
    keys::ensure(auditor_key)?;
    ui::heading(icon::RING, "workspace services ready");
    let next = "zolana-ring pipeline in a second terminal with the same environment";
    line("next", next);
    let ring_rpc_binary = workspace.ring_rpc()?;
    RING_RPC.run(&mut serve(&ring_rpc_binary, config, ring_rpc, auditor_key))
}

struct RingIndexer<'a> {
    workspace: &'a Workspace,
    urls: &'a Urls,
    port: u16,
    photon: u16,
    /// A new chain needs a new index.
    fresh_chain: bool,
}

impl RingIndexer<'_> {
    /// Replaces a ring indexer the cli started, a listener it did not start is refused.
    fn start(self) -> Result<()> {
        let scope = self.workspace.scope();
        stop_owned_listener(scope, self.port)?;
        let data = scope.join("ring-indexer");
        if self.fresh_chain {
            file::remove_dir_all(&data)?;
        }
        file::create_dir_all(&data)?;
        let log = data.join("ring-indexer.log");
        let shown = log.display();
        let open = || {
            File::options()
                .create(true)
                .append(true)
                .open(&log)
                .with_context(|| format!("cannot open the log {shown}"))
        };
        let db_url = format!("sqlite://{}?mode=rwc", data.join("index.db").display());
        let mut command = Command::new(self.workspace.ring_indexer()?);
        command
            .args(["--db-url", &db_url, "--rpc-url", &self.urls.rpc])
            .args(["--photon-url", &format!("http://127.0.0.1:{}", self.photon)])
            .args(["--port", &self.port.to_string(), "--start-slot", "0"])
            .stdin(Stdio::null())
            .stdout(open()?)
            .stderr(open()?);
        spawn_owned(scope, "ring-indexer", &mut command)?;
        let ready = probe::service_url(&self.urls.indexer, "/ready");
        let http = probe::http(POLL, POLL);
        let served = wait_until(READY_TIMEOUT, POLL, || {
            http.get(&ready)
                .send()
                .is_ok_and(|response| response.status().is_success())
        });
        let addr = local(self.port);
        ensure!(
            served,
            "the ring indexer did not answer on {addr} within {READY_TIMEOUT:?}, see {shown}"
        );
        let (url, photon) = (&self.urls.indexer, self.photon);
        line(
            "indexer",
            format_args!("{url} in front of photon on port {photon}"),
        );
        Ok(())
    }
}

fn answering<'a>(services: impl IntoIterator<Item = (u16, &'a String)>) -> Result<()> {
    for (port, url) in services {
        let next = "run `zolana-ring dev` first";
        ensure!(
            answers(local(port)),
            "local workspace service is unavailable at {url}, {next}"
        );
    }
    Ok(())
}

fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// RPC, Photon, prover and ring rpc, in that order.
fn ports(urls: &Urls) -> Result<[u16; 4]> {
    let port = |url: &str| {
        let hint = "localnet URLs are http://127.0.0.1:<port>";
        Urls::port(url).with_context(|| format!("{url} carries no port, {hint}"))
    };
    let [rpc, indexer, prover, ring_rpc] = [&urls.rpc, &urls.indexer, &urls.prover, &urls.ring_rpc];
    Ok([port(rpc)?, port(indexer)?, port(prover)?, port(ring_rpc)?])
}

fn genesis_files(
    release: &RingRelease,
    fetch: impl Fn(&Asset) -> Result<PathBuf>,
) -> Result<Vec<GenesisFile>> {
    GENESIS_PROGRAMS
        .iter()
        .map(|program| {
            Ok(GenesisFile {
                address: program.address,
                path: fetch(release.genesis_program(program.release_section)?)?,
            })
        })
        .collect()
}

#[must_use]
struct ReleaseDevStart {
    /// RPC, Photon and prover, in that order.
    ports: [u16; 3],
    genesis: Vec<GenesisFile>,
}

impl ReleaseDevStart {
    fn command(self) -> Command {
        let mut command = Command::new("zolana");
        command.args(["dev", "start"]);
        for (flag, port) in ["--rpc-port", "--photon-port", "--prover-port"]
            .iter()
            .zip(self.ports)
        {
            command.arg(flag).arg(port.to_string());
        }
        command.args(["--", "--deactivate-feature", SBPF_V0_FEATURE]);
        // A zolana `--sbf-program` turns off its release artifacts.
        for program in self.genesis {
            command
                .arg("--bpf-program")
                .arg(program.address.to_string())
                .arg(program.path);
        }
        command
    }
}

/// Local mode, `init` pins the key from `keys/`.
fn serve(binary: &Path, config: &RingConfig, port: u16, auditor_key: &Path) -> Command {
    let urls = config.urls();
    let mut command = Command::new(binary);
    command
        .args(["serve", "--port", &port.to_string()])
        .args(["--indexer-url", &urls.indexer, "--rpc-url", &urls.rpc])
        .arg("--auditor-key-file")
        .arg(auditor_key)
        .args(["--ring-program-id", &config.program_id.to_string()]);
    command
}

/// Receipts of the services the cli started, the task scope when one is set.
fn scope() -> Result<PathBuf> {
    if let Some(scope) = process_scope()? {
        return Ok(scope);
    }
    let scope = config_dir().join("localnet/scope");
    file::create_dir_all(&scope)?;
    Ok(scope)
}

/// Replaces a ring rpc the cli started, a listener it did not start is refused.
fn start_ring_rpc(
    mut command: Command,
    config: &RingConfig,
    port: u16,
    scope: &Path,
) -> Result<()> {
    stop_owned_listener(scope, port)?;
    let log_dir = config_dir().join("localnet");
    file::create_dir_all(&log_dir)?;
    let log = log_dir.join("ring-rpc.log");
    let shown = log.display();
    let open = || File::create(&log).with_context(|| format!("cannot open the log {shown}"));
    command.stdin(Stdio::null()).stdout(open()?).stderr(open()?);
    spawn_owned(scope, "ring-rpc", &mut command)?;
    let addr = local(port);
    let ready = wait_until(READY_TIMEOUT, POLL, || answers(addr));
    ensure!(
        ready,
        "the ring rpc did not answer on {addr} within {READY_TIMEOUT:?}, see {shown}"
    );
    let (url, program) = (&config.urls().ring_rpc, config.program_id);
    line("ring rpc", format_args!("{url} serving {program}, {shown}"));
    Ok(())
}

/// Mirrors the `zolana` cli, `ZOLANA_CONFIG_DIR` does not move it.
fn prover_keys_dir() -> Result<PathBuf> {
    if let Some(dir) = env::var_os("ZOLANA_PROVER_KEYS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/zolana/proving-keys"))
}

/// The prover of an older `zolana` release answers health without the ring circuit.
fn check_prover_serves_custom_ring(prover_url: &str) -> Result<()> {
    let url = probe::service_url(prover_url, "/health");
    let health: ProverHealth = probe::http(POLL, READY_TIMEOUT)
        .get(&url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(reqwest::blocking::Response::json)
        .with_context(|| format!("cannot read the prover health at {url}"))?;
    let serves = |key: &RingKey| health.circuits.iter().any(|name| name == key.name);
    let newer = "install the zolana cli of a newer localnet release";
    ensure!(
        RING_KEYS.iter().all(serves),
        "the prover at {url} serves no custom-ring circuit, {newer}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn a_foreign_listener_on_the_ring_rpc_port_is_refused_and_left_running() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config: RingConfig = toml::from_str(&format!(
            "name = \"x\"\ntarget = \"localnet\"\nprogram_id = \"11111111111111111111111111111111\"\nauthority_keypair = \"a.json\"\n\n[localnet]\nrpc = \"r\"\nindexer = \"i\"\nprover = \"p\"\nring_rpc = \"http://{addr}\"\n\n[devnet]\nrpc = \"r\"\nindexer = \"i\"\nprover = \"p\"\nring_rpc = \"g\"\n"
        ))
        .expect("ring.toml");
        let scope = env::temp_dir().join(format!("ring-localnet-scope-{}", std::process::id()));
        file::create_dir_all(&scope).expect("scope");
        let command = serve(
            Path::new("/nonexistent/ring-rpc"),
            &config,
            addr.port(),
            Path::new("k"),
        );
        let error =
            start_ring_rpc(command, &config, addr.port(), &scope).expect_err("foreign listener");
        assert_eq!(
            error.to_string(),
            format!(
                "port {} is held by a process the cli did not start",
                addr.port()
            )
        );
        assert!(
            TcpStream::connect(addr).is_ok(),
            "the foreign listener still answers"
        );
        std::fs::remove_dir_all(scope).expect("cleanup");
    }

    #[test]
    fn localnet_ports_come_from_each_service_url() {
        let urls = Urls {
            rpc: "http://127.0.0.1:8899".to_owned(),
            indexer: "http://127.0.0.1:8784".to_owned(),
            prover: "http://127.0.0.1:3001".to_owned(),
            ring_rpc: "http://127.0.0.1:8785".to_owned(),
            ring_rpc_pubkey: None,
            prover_tee_policy: None,
        };
        assert_eq!(ports(&urls).expect("ports"), [8899, 8784, 3001, 8785]);
        let portless = Urls {
            ring_rpc: "http://localhost".to_owned(),
            ..urls
        };
        let error = ports(&portless).expect_err("no port").to_string();
        assert!(
            error.starts_with("http://localhost carries no port"),
            "{error}"
        );
    }

    #[test]
    fn the_release_localnet_loads_every_genesis_program_from_the_lock() {
        let release = RingRelease::parse(
            r#"{
                "release_tag": "v1",
                "storage_program": {"asset": "storage-program-v1.so", "size": 1, "sha256": "x"}
            }"#,
        )
        .expect("parses");
        let genesis =
            genesis_files(&release, |asset| Ok(PathBuf::from(&asset.name))).expect("genesis");
        let command = ReleaseDevStart {
            ports: [8899, 8784, 3001],
            genesis,
        }
        .command();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|arg| arg == "--sbf-program"), "{args:?}");
        let validator = &args[args.iter().position(|arg| arg == "--").expect("--")..];
        let loaded: Vec<_> = validator
            .windows(3)
            .filter(|flag| flag[0] == "--bpf-program")
            .map(|flag| [flag[1].clone(), flag[2].clone()])
            .collect();
        let expected: Vec<_> = GENESIS_PROGRAMS
            .iter()
            .map(|program| {
                let asset = release.genesis_program(program.release_section);
                [
                    program.address.to_string(),
                    asset.expect("pinned").name.clone(),
                ]
            })
            .collect();
        assert_eq!(loaded, expected);
        let bare = RingRelease::parse(r#"{"release_tag": "v1"}"#).expect("parses");
        let missing = genesis_files(&bare, |_| unreachable!())
            .expect_err("no storage program")
            .to_string();
        assert_eq!(
            missing,
            "release v1 ships no storage_program, use a complete custom-rings release"
        );
    }

    #[test]
    fn the_justfile_loads_every_genesis_program() {
        let flags = GENESIS_PROGRAMS
            .iter()
            .map(|program| format!("--sbf-program {} {}", program.address, program.path))
            .collect::<Vec<_>>()
            .join(" ");
        let variable = format!("ring-genesis-programs := \"{flags}\"");
        assert!(
            include_str!("../../../../justfile").contains(&variable),
            "the justfile misses {variable}"
        );
    }
}
