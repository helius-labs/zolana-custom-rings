use sea_orm_migration::prelude::*;

mod records_000001_queue;
mod grants;
mod relay_000001_relays;
mod cosign_m20261029_000001_usage;
mod merge_0001_settings;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(records_000001_queue::Migration),
            Box::new(grants::Migration),
            Box::new(relay_000001_relays::Migration),
            Box::new(cosign_m20261029_000001_usage::Migration),
            Box::new(merge_0001_settings::Migration),
        ]
    }
}
