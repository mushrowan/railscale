//! create audit_logs table migration

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
                    .table(AuditLogs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuditLogs::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuditLogs::NodeId).big_integer().not_null())
                    .col(ColumnDef::new(AuditLogs::Action).string().not_null())
                    .col(
                        ColumnDef::new(AuditLogs::Details)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(AuditLogs::ClientTimestamp)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(AuditLogs::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_audit_logs_node")
                            .from(AuditLogs::Table, AuditLogs::NodeId)
                            .to(Nodes::Table, Nodes::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // index on node_id for listing by node
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_node_id")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::NodeId)
                    .to_owned(),
            )
            .await?;

        // index on action for querying by action type
        manager
            .create_index(
                Index::create()
                    .name("idx_audit_logs_action")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditLogs::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum AuditLogs {
    Table,
    Id,
    NodeId,
    Action,
    Details,
    ClientTimestamp,
    CreatedAt,
}
