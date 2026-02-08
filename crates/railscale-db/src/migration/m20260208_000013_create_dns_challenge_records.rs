//! create dns_challenge_records table migration

use sea_orm_migration::prelude::*;

use super::m20260106_000003_create_nodes::Nodes;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DnsChallengeRecords::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(DnsChallengeRecords::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(DnsChallengeRecords::NodeId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DnsChallengeRecords::RecordName)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DnsChallengeRecords::RecordId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(DnsChallengeRecords::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_dns_challenge_records_node")
                            .from(DnsChallengeRecords::Table, DnsChallengeRecords::NodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // index on node_id for listing records by node
        manager
            .create_index(
                Index::create()
                    .name("idx_dns_challenge_records_node_id")
                    .table(DnsChallengeRecords::Table)
                    .col(DnsChallengeRecords::NodeId)
                    .to_owned(),
            )
            .await?;

        // index on created_at for stale record cleanup
        manager
            .create_index(
                Index::create()
                    .name("idx_dns_challenge_records_created_at")
                    .table(DnsChallengeRecords::Table)
                    .col(DnsChallengeRecords::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(DnsChallengeRecords::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub(super) enum DnsChallengeRecords {
    Table,
    Id,
    NodeId,
    RecordName,
    RecordId,
    CreatedAt,
}
