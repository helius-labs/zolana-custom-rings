//! The store relay tests run over, Postgres when the recipe names one.

use sea_orm_migration::MigratorTrait;

use super::{Migrator, Store, STORE_CONNECTIONS};

/// A Postgres store is emptied for the calling test, so those tests run one at a time.
pub async fn test_store() -> Store {
    match std::env::var("RING_RPC_TEST_POSTGRES_URL") {
        Ok(url) => {
            let store = Store::open(&url, STORE_CONNECTIONS).await.expect("store");
            Migrator::fresh(store.connection()).await.expect("emptied");
            store
        }
        Err(_) => Store::open("sqlite::memory:", 1).await.expect("store"),
    }
}
