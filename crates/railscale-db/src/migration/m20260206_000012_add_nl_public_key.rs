//! add nl_public_key column to nodes table for tka rotation keys

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Nodes::Table)
                    .add_column(ColumnDef::new(Nodes::NlPublicKey).binary().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Nodes::Table)
                    .drop_column(Nodes::NlPublicKey)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Nodes {
    Table,
    NlPublicKey,
}
