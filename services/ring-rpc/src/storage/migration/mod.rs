use sea_orm_migration::prelude::*;

mod records_000001_queue;
mod grants;
mod relay_000001_relays;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(records_000001_queue::Migration),
            Box::new(grants::Migration),
            Box::new(relay_000001_relays::Migration),
        ]
    }
}
