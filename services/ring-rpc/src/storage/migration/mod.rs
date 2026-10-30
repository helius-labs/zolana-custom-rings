use sea_orm_migration::prelude::*;

mod cosign_m20261029_000001_usage;
mod grants;
mod merge2_000001_inputs;
mod merge_0001_settings;
mod records2_000001_attempts;
mod records3_000001_enrolments;
mod records_000001_queue;
mod relay_000001_relays;

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
            Box::new(records2_000001_attempts::Migration),
            Box::new(records3_000001_enrolments::Migration),
            Box::new(merge2_000001_inputs::Migration),
        ]
    }
}
