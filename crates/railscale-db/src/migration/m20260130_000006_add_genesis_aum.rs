//! add genesis_aum column to tka_state table.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TkaState::Table)
                    .add_column(ColumnDef::new(TkaState::GenesisAum).binary())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TkaState::Table)
                    .drop_column(TkaState::GenesisAum)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum TkaState {
    Table,
    GenesisAum,
}
