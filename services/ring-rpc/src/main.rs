use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use log::info;
use solana_signer::Signer;
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{public_key_path, write_auditor_key, KeyMode},
};
use zolana_ring_rpc::{
    run_server, write_grant_rows_secret, write_keypair, write_root_secret, ChainSource, Cli,
    Command, Hub, KeyKind, KeySource, KeygenArgs, LiveStorageChain, OriginPolicy,
    RelayServicesInit, ServeArgs, ServeKeys, ServedRings, ServerOptions, ServiceIdentity, Store,
    TransactionSource, Upstreams, MANAGED_MERGE_INTERVAL, STORE_CONNECTIONS,
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
        KeyKind::GrantRows => {
            write_grant_rows_secret(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("{:<11} {}", args.kind.role(), args.out.display());
        }
        KeyKind::FeePayer | KeyKind::Service | KeyKind::StorageAuthority | KeyKind::CoSigner => {
            let key = write_keypair(&args.out)
                .with_context(|| format!("writing {}", args.out.display()))?;
            println!("secret      {}", args.out.display());
            println!("{:<11} {}", args.kind.role(), key.pubkey());
        }
    }
    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let ServeKeys {
        auditor,
        service,
        storage_authority,
        co_signer,
        grant_rows,
        fee_payer,
    } = args.read_keys()?;
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
    let relay_services = fee_payer
        .map(|fee_payer| {
            let (Some(store), Some(prover_url)) = (store.clone(), &args.prover_url) else {
                anyhow::bail!("--fee-payer-key-file needs --store-url and --prover-url");
            };
            Ok(RelayServicesInit {
                fee_payer,
                store,
                rpc_url: &args.rpc_url,
                indexer_url: &args.indexer_url,
                prover_url,
                // One ring with a local auditor key, any ring with derived keys.
                rings: match args.ring_program_id {
                    Some(ring) => ServedRings::One(ring),
                    None => ServedRings::Any,
                },
            }
            .build())
        })
        .transpose()?;
    let origin_transport = args.origin_transport();
    let mut origin_policy = OriginPolicy::new(args.allow_origins).with_transport(origin_transport);
    if let Some(relying_party_id) = args.webauthn_rp_id {
        origin_policy = origin_policy.with_relying_party_id(relying_party_id);
    }
    let identity = ServiceIdentity {
        genesis_hash,
        service,
    };
    let mut builder = Hub::builder(source, identity)
        .with_origins(origin_policy.build()?)
        .with_reader_grants(args.reader_grants);
    if let Some(store) = store {
        builder = builder.with_store(store);
    }
    if let (Some(prover_url), Some(authority)) = (&args.prover_url, storage_authority) {
        let chain = LiveStorageChain::connect(upstreams, prover_url)?;
        builder = builder.with_storage_chain(Arc::new(chain), authority);
    }
    if let Some(secret) = grant_rows {
        builder = builder.with_grant_rows_key(secret);
    }
    if let Some(signer) = co_signer {
        builder = builder.with_co_signer(signer);
    }
    if let Some(services) = relay_services {
        builder = builder.with_relay_services(services);
    }
    let hub = Arc::new(match auditor {
        KeySource::Local { ring, auditor } => builder.local(ring, auditor)?,
        KeySource::Derived(root) => builder.derived(root)?,
    });
    info!("service pubkey {}", hub.service_pubkey());
    if let Some(relay) = hub.relay() {
        info!("relay fee payer {}", relay.fee_payer());
    }
    if let Some(merge) = hub.managed_merge() {
        tokio::spawn(merge.run(MANAGED_MERGE_INTERVAL));
    }
    if let Some(co_signer) = hub.co_signer().signer() {
        info!("co-signer pubkey {co_signer}");
    }
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
