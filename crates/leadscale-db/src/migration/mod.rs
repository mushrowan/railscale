//! database migrations for leadscale

pub use sea_orm_migration::prelude::*;

mod m20260106_000001_create_users;
mod m20260106_000002_create_preauth_keys;
mod m20260106_000003_create_nodes;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260106_000001_create_users::Migration),
            Box::new(m20260106_000002_create_preauth_keys::Migration),
            Box::new(m20260106_000003_create_nodes::Migration),
        ]
    }
}
