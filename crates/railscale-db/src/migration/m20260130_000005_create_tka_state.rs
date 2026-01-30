//! create tka_state table and add key_signature to nodes.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // create tka_state table (single row for tailnet tka state)
        manager
            .create_table(
                Table::create()
                    .table(TkaState::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TkaState::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TkaState::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(TkaState::Head).string())
                    .col(ColumnDef::new(TkaState::StateCheckpoint).binary())
                    .col(ColumnDef::new(TkaState::DisablementSecrets).binary())
                    .col(
                        ColumnDef::new(TkaState::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TkaState::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // add key_signature column to nodes table
        manager
            .alter_table(
                Table::alter()
                    .table(Nodes::Table)
                    .add_column(ColumnDef::new(Nodes::KeySignature).binary())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // remove key_signature from nodes
        manager
            .alter_table(
                Table::alter()
                    .table(Nodes::Table)
                    .drop_column(Nodes::KeySignature)
                    .to_owned(),
            )
            .await?;

        // drop tka_state table
        manager
            .drop_table(Table::drop().table(TkaState::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum TkaState {
    Table,
    Id,
    Enabled,
    Head,
    StateCheckpoint,
    DisablementSecrets,
    CreatedAt,
    UpdatedAt,
}

/// reference to nodes table for alter
#[derive(DeriveIden)]
enum Nodes {
    Table,
    KeySignature,
}
