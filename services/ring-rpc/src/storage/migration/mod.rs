use sea_orm_migration::prelude::*;

mod cosign_m20261029_000001_usage;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(cosign_m20261029_000001_usage::Migration)]
    }
}
