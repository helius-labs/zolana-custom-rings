//! The ring indexer each localnet bring-up starts beside Photon.

use std::{
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use spr_test_utils::localnet::isolated_temp_path;

const BINARY_ENV: &str = "RING_INDEXER_BIN";
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(250);

pub struct RingIndexerLaunch<'a> {
    /// Clients read every indexer method here.
    pub indexer_url: &'a str,
    pub photon_url: &'a str,
    pub rpc_url: &'a str,
    pub log_dir: &'a Path,
}

impl RingIndexerLaunch<'_> {
    /// Replaces the indexer of an earlier bring-up, its index belongs to the stopped chain.
    pub fn spawn(self) -> Result<()> {
        let Self {
            indexer_url,
            photon_url,
            rpc_url,
            log_dir,
        } = self;
        if indexer_url.trim_end_matches('/') == photon_url.trim_end_matches('/') {
            bail!("set ZOLANA_INDEXER_URL to the ring indexer, {photon_url} serves Photon");
        }
        let binary = std::env::var_os(BINARY_ENV)
            .map(PathBuf::from)
            .with_context(|| format!("set {BINARY_ENV} to the ring indexer binary"))?;
        let port = port(indexer_url)?;
        stop_listener(port)?;
        let data = PathBuf::from(isolated_temp_path(&format!("zolana-ring-indexer-{port}")));
        match fs::remove_dir_all(&data) {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("clear {}", data.display()))
            }
            _ => {}
        }
        fs::create_dir_all(&data)?;
        fs::create_dir_all(log_dir)?;
        let log_path = log_dir.join("ring-indexer.log");
        let log = File::create(&log_path)?;
        Command::new(&binary)
            .arg("--db-url")
            .arg(format!(
                "sqlite://{}?mode=rwc",
                data.join("index.db").display()
            ))
            .args(["--rpc-url", rpc_url])
            .args(["--photon-url", photon_url])
            .args(["--port", &port.to_string()])
            .args(["--start-slot", "latest"])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .with_context(|| format!("start {}", binary.display()))?;
        let deadline = Instant::now() + READY_TIMEOUT;
        while !ready(port) {
            if Instant::now() > deadline {
                bail!(
                    "the ring indexer on port {port} is not ready, see {}",
                    log_path.display()
                );
            }
            thread::sleep(POLL);
        }
        Ok(())
    }
}

pub(crate) fn port(url: &str) -> Result<u16> {
    url.rsplit_once(':')
        .and_then(|(_, port)| port.trim_end_matches('/').parse().ok())
        .with_context(|| format!("{url} names no port"))
}

pub(crate) fn stop_listener(port: u16) -> Result<()> {
    let listeners = Command::new("lsof")
        .args(["-t", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .output()
        .context("lsof is required to stop an earlier ring indexer")?;
    for pid in String::from_utf8_lossy(&listeners.stdout).split_whitespace() {
        Command::new("kill").arg(pid).status()?;
    }
    let deadline = Instant::now() + READY_TIMEOUT;
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        if Instant::now() > deadline {
            bail!("port {port} stays busy");
        }
        thread::sleep(POLL);
    }
    Ok(())
}

fn ready(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let mut status = [0; 12];
    stream
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .and_then(|()| stream.read_exact(&mut status))
        .is_ok_and(|()| status.ends_with(b" 200"))
}
