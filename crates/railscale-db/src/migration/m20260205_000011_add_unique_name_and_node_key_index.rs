//! add unique constraint on users.name and index on nodes.node_key

use sea_orm_migration::prelude::*;

use super::m20260106_000001_create_users::Users;
use super::m20260106_000003_create_nodes::Nodes;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // drop the old non-unique index on users.name
        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_name")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        // create a unique index on users.name
        manager
            .create_index(
                Index::create()
                    .name("idx_users_name_unique")
                    .table(Users::Table)
                    .col(Users::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // add index on nodes.node_key for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_nodes_node_key")
                    .table(Nodes::Table)
                    .col(Nodes::NodeKey)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // drop node_key index
        manager
            .drop_index(
                Index::drop()
                    .name("idx_nodes_node_key")
                    .table(Nodes::Table)
                    .to_owned(),
            )
            .await?;

        // drop unique name index
        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_name_unique")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        // recreate the old non-unique index
        manager
            .create_index(
                Index::create()
                    .name("idx_users_name")
                    .table(Users::Table)
                    .col(Users::Name)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
