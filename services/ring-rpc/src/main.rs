use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use log::info;
use solana_signer::Signer;
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{public_key_path, read_auditor_key, write_auditor_key, KeyMode},
};
use zolana_ring_rpc::{
    read_fee_payer, read_root_secret, run_server, write_fee_payer, write_root_secret, ChainSource,
    Cli, Command, Hub, KeyKind, KeygenArgs, LiveStorageChain, OriginPolicy, RelayServices,
    RelayServicesInit, ServeArgs, ServedRings, ServerOptions, Store, TransactionSource, Upstreams,
    MANAGED_MERGE_INTERVAL, STORE_CONNECTIONS,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match Cli::parse().command {
        Command::Serve(args) => serve(*args).await,
        Command::Keygen(args) => keygen(args),
    }
}

fn keygen(args: KeygenArgs) -> anyhow::Result<()> {
    match args.kind {
        KeyKind::Auditor => {
            let key = write_auditor_key(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("secret      {}", args.out.display());
            println!("public key  {}", public_key_path(&args.out)?.display());
            println!("auditor pk  {}", hex::encode(key.pubkey().as_bytes()));
            println!(
                "view tag    {}",
                hex::encode(auditor_view_tag(&key.pubkey()))
            );
        }
        KeyKind::Root => {
            write_root_secret(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("root secret {}", args.out.display());
        }
        KeyKind::FeePayer => {
            let fee_payer = write_fee_payer(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("secret      {}", args.out.display());
            println!("fee payer   {}", fee_payer.pubkey());
        }
    }
    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let upstreams = Upstreams {
        indexer_url: &args.indexer_url,
        rpc_url: &args.rpc_url,
        timeout: args.upstream_timeout(),
    };
    let source = ChainSource::connect(upstreams)?;
    let genesis_hash = source
        .genesis_hash()
        .await
        .context("reading the cluster genesis hash")?;
    let options = ServerOptions {
        bind: args.bind,
        bind_policy: args.bind_policy(),
        port: args.port,
        max_connections: args.max_connections.get(),
        request_timeout: args.request_timeout(),
        client_limits: args.client_limits.client_limits(),
    };
    let store = match &args.store_url {
        Some(url) => Some(
            Store::open(url, STORE_CONNECTIONS)
                .await
                .context("opening the service store")?,
        ),
        None => None,
    };
    let relay_services = relay_services(&args, store.clone())?;
    let origin_transport = args.origin_transport();
    let access = args.key_access();
    let mut origin_policy = OriginPolicy::new(args.allow_origins).with_transport(origin_transport);
    if let Some(relying_party_id) = args.webauthn_rp_id {
        origin_policy = origin_policy.with_relying_party_id(relying_party_id);
    }
    let mut builder = Hub::builder(source, genesis_hash)
        .with_origins(origin_policy.build()?)
        .with_reader_grants(args.reader_grants);
    if let Some(store) = store {
        builder = builder.with_store(store);
    }
    if let Some(prover_url) = &args.prover_url {
        let chain = LiveStorageChain::connect(upstreams, prover_url)?;
        builder = builder
            .with_storage_chain(Arc::new(chain))
            .with_watched_registries(args.watch_registry.clone());
    }
    if let Some(services) = relay_services {
        builder = builder.with_relay_services(services);
    }
    let hub = match (&args.auditor_key_file, &args.root_secret_file) {
        (Some(path), None) => {
            let ring = args
                .ring_program_id
                .ok_or_else(|| anyhow::anyhow!("--ring-program-id must name the served ring"))?;
            let auditor = read_auditor_key(path, access)
                .with_context(|| format!("loading {}", path.display()))?;
            builder.local(ring, auditor)?
        }
        (None, Some(path)) => {
            let root = read_root_secret(path, access)
                .with_context(|| format!("loading {}", path.display()))?;
            builder.derived(root)?
        }
        _ => anyhow::bail!("pass exactly one of --auditor-key-file and --root-secret-file"),
    };
    let hub = Arc::new(hub);
    info!("service pubkey {}", hub.service_pubkey());
    if let Some(relay) = hub.relay() {
        info!("relay fee payer {}", relay.fee_payer());
        anyhow::ensure!(
            relay.fee_payer() != hub.service_pubkey(),
            "the fee payer key must differ from the service key"
        );
    }
    if let Some(merge) = hub.managed_merge() {
        tokio::spawn(merge.run(MANAGED_MERGE_INTERVAL));
    }
    info!("co-signer pubkey {}", hub.co_signer_keypair()?.pubkey());
    match (hub.mode(), hub.local_view_tag()) {
        (KeyMode::Local, Some(tag)) => info!(
            "ring-rpc listening on {}:{} for auditor tag {}",
            args.bind,
            args.port,
            hex::encode(tag)
        ),
        _ => info!(
            "ring-rpc listening on {}:{}, auditor keys derived per ring",
            args.bind, args.port
        ),
    }
    if let Ok(writer) = hub.record_writer() {
        info!("storage authority {}", writer.authority());
    }
    hub.spawn_workers();
    let handle = run_server(hub, options).await?;
    tokio::signal::ctrl_c().await?;
    info!("stopping");
    handle.stop()?;
    handle.stopped().await;
    Ok(())
}

/// One ring with a local auditor key, any ring with derived keys.
fn relay_services(args: &ServeArgs, store: Option<Store>) -> anyhow::Result<Option<RelayServices>> {
    let Some(fee_payer_key_file) = &args.fee_payer_key_file else {
        return Ok(None);
    };
    let fee_payer = read_fee_payer(fee_payer_key_file, args.key_access())
        .with_context(|| format!("loading {}", fee_payer_key_file.display()))?;
    let (Some(store), Some(prover_url)) = (store, &args.prover_url) else {
        anyhow::bail!("--fee-payer-key-file needs --store-url and --prover-url");
    };
    Ok(Some(
        RelayServicesInit {
            fee_payer,
            store,
            rpc_url: &args.rpc_url,
            indexer_url: &args.indexer_url,
            prover_url,
            rings: match args.ring_program_id {
                Some(ring) => ServedRings::One(ring),
                None => ServedRings::Any,
            },
        }
        .build(),
    ))
}
