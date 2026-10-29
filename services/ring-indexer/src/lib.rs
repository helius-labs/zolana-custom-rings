//! Indexes custom ring member registries and forwards every other JSON-RPC
//! call to Photon.

#[path = "rpc/api.rs"]
mod api;
#[path = "ingest/block.rs"]
mod block;
mod error;
#[path = "ingest/indexer.rs"]
mod indexer;
#[path = "ingest/member_registry.rs"]
mod member_registry;
#[path = "storage/migration/mod.rs"]
mod migration;
#[path = "rpc/solana.rs"]
mod rpc;
#[path = "rpc/server/mod.rs"]
mod server;
#[path = "storage/database.rs"]
mod storage;
#[path = "ingest/storage_registry.rs"]
mod storage_registry;

use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use clap::Parser;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

pub use error::RingApiError;
pub use indexer::{Readiness, StartSlot};
pub use migration::Migrator;
pub use server::{PhotonUrl, RING_METHODS};

use indexer::Indexer;
use rpc::{BlockHeaders, SolanaRpc};
use server::Server;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    /// `postgres://` or `sqlite://` URL of a database the indexer owns.
    #[arg(long, env = "RING_INDEXER_DB_URL")]
    pub db_url: String,

    /// Solana RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    pub rpc_url: String,

    /// Photon URL, it serves every call but the ring methods.
    #[arg(long)]
    pub photon_url: PhotonUrl,

    #[arg(long, default_value_t = 8786)]
    pub port: u16,

    /// First slot an empty index scans, a slot or `latest`, a stored index refuses another.
    #[arg(long)]
    pub start_slot: Option<StartSlot>,

    /// Concurrent `getBlock` requests.
    #[arg(long, default_value_t = 20)]
    pub block_fetches: usize,

    #[arg(long, default_value_t = 10)]
    pub max_db_connections: u32,

    /// Concurrent HTTP connections.
    #[arg(long, default_value_t = 1024)]
    pub max_connections: u32,

    /// Accept Surfpool synthetic block headers from a loopback RPC.
    #[arg(
        long,
        env = "ZOLANA_RING_SURFPOOL_FIXTURE",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub surfpool_fixture: bool,
}

pub async fn run(args: Args) -> Result<()> {
    let db = Arc::new(connect(&args.db_url, args.max_db_connections).await?);
    Migrator::up(db.as_ref(), None)
        .await
        .context("ring indexer migrations failed")?;
    let rpc =
        Arc::new(SolanaRpc::new(args.rpc_url.clone()).with_block_headers(block_headers(&args)?));
    let readiness = Readiness::default();
    let indexer = Indexer {
        db: db.clone(),
        rpc: rpc.clone(),
        start: args.start_slot,
        block_fetches: args.block_fetches,
        readiness: readiness.clone(),
    };
    // An empty index without a start slot or a foreign start fails here, not in the loop.
    indexer.cursor().await?;
    let indexing = indexer.spawn();
    let (address, server) = Server {
        db,
        rpc,
        photon: args.photon_url,
        readiness,
        max_connections: args.max_connections,
    }
    .start(SocketAddr::from(([0, 0, 0, 0], args.port)))
    .await?;
    log::info!("ring indexer listens on {address}");
    tokio::select! {
        () = server.stopped() => bail!("the ring indexer server stopped"),
        joined = indexing => bail!("the ring indexer loop stopped ({joined:?})"),
        signal = tokio::signal::ctrl_c() => Ok(signal?),
    }
}

async fn connect(url: &str, max_connections: u32) -> Result<DatabaseConnection> {
    let db = Database::connect(
        ConnectOptions::new(url)
            .max_connections(max_connections)
            .sqlx_logging(false)
            .to_owned(),
    )
    .await
    .context("cannot connect to the ring indexer database")?;
    if db.get_database_backend() == DatabaseBackend::Sqlite {
        // Lookups read while the indexer writes.
        db.execute_unprepared("PRAGMA journal_mode=WAL").await?;
    }
    Ok(db)
}

fn block_headers(args: &Args) -> Result<BlockHeaders> {
    if !args.surfpool_fixture {
        return Ok(BlockHeaders::Chain);
    }
    surfpool_fixture(&args.rpc_url)
}

#[cfg(not(feature = "surfpool-fixture"))]
fn surfpool_fixture(_rpc_url: &str) -> Result<BlockHeaders> {
    bail!("the Surfpool fixture needs a binary built with the surfpool-fixture feature")
}

#[cfg(feature = "surfpool-fixture")]
fn surfpool_fixture(rpc_url: &str) -> Result<BlockHeaders> {
    let loopback = reqwest::Url::parse(rpc_url).ok().is_some_and(|url| {
        url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    });
    if !loopback {
        bail!("the Surfpool fixture accepts loopback RPC only");
    }
    Ok(BlockHeaders::SurfpoolFixture)
}

#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod tests;
