//! database migrations for railscale.

pub use sea_orm_migration::prelude::*;

mod m20260106_000001_create_users;
mod m20260106_000002_create_preauth_keys;
mod m20260106_000003_create_nodes;
mod m20260106_000004_create_api_keys;
mod m20260130_000005_create_tka_state;
mod m20260130_000006_add_genesis_aum;
mod m20260131_000007_create_tka_aums;
mod m20260131_000008_add_posture_attributes;
mod m20260131_000009_add_last_seen_country;
mod m20260201_000010_add_node_ephemeral;
mod m20260205_000011_add_unique_name_and_node_key_index;

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
            Box::new(m20260131_000008_add_posture_attributes::Migration),
            Box::new(m20260131_000009_add_last_seen_country::Migration),
            Box::new(m20260201_000010_add_node_ephemeral::Migration),
            Box::new(m20260205_000011_add_unique_name_and_node_key_index::Migration),
        ]
    }
}
