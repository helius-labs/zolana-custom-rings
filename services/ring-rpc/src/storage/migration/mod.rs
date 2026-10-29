use sea_orm_migration::prelude::*;

mod merge_0001_settings;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(merge_0001_settings::Migration)]
    }
}
