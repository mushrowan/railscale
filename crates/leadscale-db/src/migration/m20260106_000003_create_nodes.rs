//! create nodes table migration

use sea_orm_migration::prelude::*;

use super::m20260106_000001_create_users::Users;
use super::m20260106_000002_create_preauth_keys::PreauthKeys;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Nodes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Nodes::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Nodes::MachineKey).var_binary(256).not_null())
                    .col(ColumnDef::new(Nodes::NodeKey).var_binary(256).not_null())
                    .col(ColumnDef::new(Nodes::DiscoKey).var_binary(256).not_null())
                    .col(
                        ColumnDef::new(Nodes::Endpoints)
                            .text()
                            .not_null()
                            .default("[]"),
                    )
                    .col(ColumnDef::new(Nodes::Hostinfo).text())
                    .col(ColumnDef::new(Nodes::Ipv4).string())
                    .col(ColumnDef::new(Nodes::Ipv6).string())
                    .col(ColumnDef::new(Nodes::Hostname).string().not_null())
                    .col(ColumnDef::new(Nodes::GivenName).string().not_null())
                    .col(ColumnDef::new(Nodes::UserId).big_integer())
                    .col(
                        ColumnDef::new(Nodes::RegisterMethod)
                            .string()
                            .not_null()
                            .default("authkey"),
                    )
                    .col(
                        ColumnDef::new(Nodes::Tags)
                            .text()
                            .not_null()
                            .default("[]"),
                    )
                    .col(ColumnDef::new(Nodes::AuthKeyId).big_integer())
                    .col(ColumnDef::new(Nodes::Expiry).timestamp_with_time_zone())
                    .col(ColumnDef::new(Nodes::LastSeen).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(Nodes::ApprovedRoutes)
                            .text()
                            .not_null()
                            .default("[]"),
                    )
                    .col(
                        ColumnDef::new(Nodes::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Nodes::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Nodes::DeletedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_nodes_user")
                            .from(Nodes::Table, Nodes::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_nodes_auth_key")
                            .from(Nodes::Table, Nodes::AuthKeyId)
                            .to(PreauthKeys::Table, PreauthKeys::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        // index on user_id for listing nodes by user
        manager
            .create_index(
                Index::create()
                    .name("idx_nodes_user_id")
                    .table(Nodes::Table)
                    .col(Nodes::UserId)
                    .to_owned(),
            )
            .await?;

        // index on machine_key for registration lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_nodes_machine_key")
                    .table(Nodes::Table)
                    .col(Nodes::MachineKey)
                    .to_owned(),
            )
            .await?;

        // index for soft deletes
        manager
            .create_index(
                Index::create()
                    .name("idx_nodes_deleted_at")
                    .table(Nodes::Table)
                    .col(Nodes::DeletedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Nodes::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Nodes {
    Table,
    Id,
    MachineKey,
    NodeKey,
    DiscoKey,
    Endpoints,
    Hostinfo,
    Ipv4,
    Ipv6,
    Hostname,
    GivenName,
    UserId,
    RegisterMethod,
    Tags,
    AuthKeyId,
    Expiry,
    LastSeen,
    ApprovedRoutes,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}
