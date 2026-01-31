//! database migrations for railscale.

pub use sea_orm_migration::prelude::*;

mod m20260106_000001_create_users;
mod m20260106_000002_create_preauth_keys;
mod m20260106_000003_create_nodes;
mod m20260106_000004_create_api_keys;
mod m20260130_000005_create_tka_state;
mod m20260130_000006_add_genesis_aum;
mod m20260131_000007_create_tka_aums;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260106_000001_create_users::Migration),
            Box::new(m20260106_000002_create_preauth_keys::Migration),
            Box::new(m20260106_000003_create_nodes::Migration),
            Box::new(m20260106_000004_create_api_keys::Migration),
            Box::new(m20260130_000005_create_tka_state::Migration),
            Box::new(m20260130_000006_add_genesis_aum::Migration),
            Box::new(m20260131_000007_create_tka_aums::Migration),
        ]
    }
}
