//! add last_seen_country column to nodes table for geoip posture checks

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
                    .add_column(ColumnDef::new(Nodes::LastSeenCountry).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Nodes::Table)
                    .drop_column(Nodes::LastSeenCountry)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    LastSeenCountry,
}
