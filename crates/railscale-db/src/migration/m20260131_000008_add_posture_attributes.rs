//! add posture_attributes column to nodes table

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
                    .add_column(
                        ColumnDef::new(Nodes::PostureAttributes)
                            .text()
                            .null()
                            .default("{}"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Nodes::Table)
                    .drop_column(Nodes::PostureAttributes)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    PostureAttributes,
}
