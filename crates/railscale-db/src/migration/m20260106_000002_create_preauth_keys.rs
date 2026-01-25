//! create preauth_keys table migration.

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
                    .table(PreauthKeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PreauthKeys::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(PreauthKeys::KeyPrefix).string().not_null())
                    .col(ColumnDef::new(PreauthKeys::KeyHash).string().not_null())
                    .col(ColumnDef::new(PreauthKeys::UserId).big_integer().not_null())
                    .col(
                        ColumnDef::new(PreauthKeys::Reusable)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(PreauthKeys::Ephemeral)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(PreauthKeys::Used)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(PreauthKeys::Tags)
                            .text()
                            .not_null()
                            .default("[]"),
                    )
                    .col(ColumnDef::new(PreauthKeys::Expiration).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(PreauthKeys::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PreauthKeys::DeletedAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_preauth_keys_user")
                            .from(PreauthKeys::Table, PreauthKeys::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // index on key_prefix for listing/display (not unique - prefixes could theoretically collide)
        manager
            .create_index(
                Index::create()
                    .name("idx_preauth_keys_key_hash")
                    .table(PreauthKeys::Table)
                    .col(PreauthKeys::KeyHash)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // index on key_prefix for listing/display (not unique - prefixes could theoretically collide)
        manager
            .create_index(
                Index::create()
                    .name("idx_preauth_keys_key_prefix")
                    .table(PreauthKeys::Table)
                    .col(PreauthKeys::KeyPrefix)
                    .to_owned(),
            )
            .await?;

        // index on user_id for listing keys by user
        manager
            .create_index(
                Index::create()
                    .name("idx_preauth_keys_user_id")
                    .table(PreauthKeys::Table)
                    .col(PreauthKeys::UserId)
                    .to_owned(),
            )
            .await?;

        // index for soft deletes
        manager
            .create_index(
                Index::create()
                    .name("idx_preauth_keys_deleted_at")
                    .table(PreauthKeys::Table)
                    .col(PreauthKeys::DeletedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PreauthKeys::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum PreauthKeys {
    #[sea_orm(iden = "preauth_keys")]
    Table,
    Id,
    KeyPrefix,
    KeyHash,
    UserId,
    Reusable,
    Ephemeral,
    Used,
    Tags,
    Expiration,
    CreatedAt,
    DeletedAt,
}
