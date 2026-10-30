use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use custom_ring_interface::{key_catalog::RING_KEYS, proving_key_hashes};
use serde_json::{json, Value};
use xtask::create_release::{
    self, binary_json, build_rust_binary, pinned_sha256, read_json, release_targets, repo_root,
    require_file, stage_file, stage_program, CliBinary, Options, ProgramSource, ReleaseSet,
    PROVING_KEYS_DIR,
};

const RING_KEYS_LOCK: &str = "prover/ring/proving-keys.lock";

const PROGRAM_SOURCES: [ProgramSource; 2] = [
    // Deployed per ring under its own id.
    ProgramSource {
        role: "ring_program",
        file: "custom_ring_program.so",
        asset_stem: "custom-ring-program",
    },
    ProgramSource {
        role: "storage_program",
        file: "storage_program.so",
        asset_stem: "storage-program",
    },
];

struct CustomRings;

impl ReleaseSet for CustomRings {
    fn lock_path(&self) -> &'static str {
        "cli/release-artifacts.lock"
    }

    fn title(&self, tag: &str) -> String {
        format!("custom-rings {tag}")
    }

    fn notes(&self, tag: &str) -> String {
        format!("Zolana custom ring artifacts {tag}")
    }

    fn cli_binaries(&self) -> &'static [CliBinary] {
        &[CliBinary {
            package: "custom-ring-cli",
            bin: "zolana-ring",
            asset_stem: "zolana-ring",
        }]
    }

    fn lock(&self, options: &Options, staging: &Path, host: (&str, &str)) -> Result<Value> {
        let repo = repo_root()?;
        let zolana = repo.join("zolana");
        let ring_lock = read_json(&repo.join(RING_KEYS_LOCK))?;
        validate_ring_key_pins(&ring_lock)?;
        let mut lock = json!({ "release_tag": options.tag });
        for source in &PROGRAM_SOURCES {
            let path = options.deploy_dir.join(source.file);
            require_file(&path, "run `just build-programs` first")?;
            zolana_cli_common::release::verify_program_keys(
                &std::fs::read(&path)?,
                proving_key_hashes(),
            )?;
            lock[source.role] = stage_program(source, &path, &options.tag, staging)?;
        }
        for source in RING_KEYS {
            let file_name = source.file_name();
            let key_source = zolana.join(PROVING_KEYS_DIR).join(&file_name);
            require_file(&key_source, "run `just fetch-custom-ring-keys` first")?;
            let asset = source.asset(&options.tag);
            let staged = stage_file(&key_source, &staging.join(&asset))?;
            let pinned = pinned_sha256(&ring_lock, &file_name)?;
            if staged.sha256 != pinned {
                bail!(
                    "{file_name} hashes to {}, {RING_KEYS_LOCK} pins {pinned}",
                    staged.sha256
                );
            }
            lock[source.section()] = json!({
                "asset": asset,
                "size": staged.size,
                "sha256": staged.sha256,
            });
        }
        let mut binaries = Vec::new();
        for (os, arch) in release_targets(host) {
            let asset = format!("ring-rpc-{os}-{arch}-{}", options.tag);
            let path = staging.join(&asset);
            build_rust_binary(
                &repo,
                "zolana-ring-rpc",
                "ring-rpc",
                &path,
                (os, arch) == host,
            )?;
            binaries.push(binary_json("ring_rpc", os, arch, &asset, &path)?);
        }
        lock["binaries"] = json!(binaries);
        Ok(lock)
    }
}

/// A stale release tool must not pair its old SBF with a newly rotated lock.
fn validate_ring_key_pins(ring_lock: &Value) -> Result<()> {
    let keys = ring_lock["keys"]
        .as_object()
        .context("ring proving-key lock has no keys")?;
    ensure!(
        keys.len() == RING_KEYS.len(),
        "ring key catalog differs from this release tool, rebuild ring-xtask"
    );
    for (file, hash) in proving_key_hashes() {
        ensure!(
            pinned_sha256(ring_lock, file)? == hex::encode(hash),
            "{file} differs from this release tool's compiled verifier, rebuild ring-xtask and the program"
        );
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("create-release") => {
            if let Err(error) =
                create_release::run(Options::parse(args.collect(), &CustomRings), &CustomRings)
            {
                eprintln!("create-release failed: {error:?}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: ring-xtask create-release --tag <tag> [options]");
            std::process::exit(2);
        }
    }
}
