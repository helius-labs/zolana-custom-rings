use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

use crate::{error::RingRpcError, migration::Migrator};

/// Migrated when opened, clones share one pool.
#[derive(Clone)]
pub struct Store {
    db: DatabaseConnection,
}

impl Store {
    /// `url` is a `postgres://` or `sqlite://` URL.
    pub async fn open(url: &str, max_connections: u32) -> Result<Self, RingRpcError> {
        let db = Database::connect(
            ConnectOptions::new(url)
                .max_connections(max_connections)
                .sqlx_logging(false)
                .to_owned(),
        )
        .await?;
        if db.get_database_backend() == DatabaseBackend::Sqlite {
            // Readers run beside the writer.
            db.execute_unprepared("PRAGMA journal_mode=WAL").await?;
        }
        Migrator::up(&db, None).await?;
        Ok(Self { db })
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }
}
