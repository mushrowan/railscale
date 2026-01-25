//! create api_keys table migration.

use sea_orm_migration::prelude::*;

use super::m20260106_000001_create_users::Users;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ApiKeys::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ApiKeys::Selector).string().not_null())
                    .col(ColumnDef::new(ApiKeys::VerifierHash).string().not_null())
                    .col(ColumnDef::new(ApiKeys::Name).string().not_null())
                    .col(ColumnDef::new(ApiKeys::UserId).big_integer().not_null())
                    .col(ColumnDef::new(ApiKeys::Expiration).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(ApiKeys::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ApiKeys::LastUsedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(ApiKeys::DeletedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_keys_user")
                            .from(ApiKeys::Table, ApiKeys::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // unique index on selector for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_selector")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Selector)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // index on user_id for listing keys by user
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_user_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::UserId)
                    .to_owned(),
            )
            .await?;

        // index for soft deletes
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_deleted_at")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::DeletedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ApiKeys::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum ApiKeys {
    #[sea_orm(iden = "api_keys")]
    Table,
    Id,
    Selector,
    VerifierHash,
    Name,
    UserId,
    Expiration,
    CreatedAt,
    LastUsedAt,
    DeletedAt,
}
