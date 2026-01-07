//! create users table migration

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Users::Name).string().not_null())
                    .col(ColumnDef::new(Users::DisplayName).string())
                    .col(ColumnDef::new(Users::Email).string())
                    .col(ColumnDef::new(Users::ProviderIdentifier).string())
                    .col(ColumnDef::new(Users::Provider).string())
                    .col(ColumnDef::new(Users::ProfilePicUrl).string())
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Users::DeletedAt).timestamp_with_time_zone())
                    .to_owned(),
            )
            .await?;

        // index for soft deletes
        manager
            .create_index(
                Index::create()
                    .name("idx_users_deleted_at")
                    .table(Users::Table)
                    .col(Users::DeletedAt)
                    .to_owned(),
            )
            .await?;

        // unique index on name for local users (no provider_identifier)
        manager
            .create_index(
                Index::create()
                    .name("idx_users_name")
                    .table(Users::Table)
                    .col(Users::Name)
                    .to_owned(),
            )
            .await?;

        // index on provider_identifier for oidc users
        manager
            .create_index(
                Index::create()
                    .name("idx_users_provider_identifier")
                    .table(Users::Table)
                    .col(Users::ProviderIdentifier)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Name,
    DisplayName,
    Email,
    ProviderIdentifier,
    Provider,
    ProfilePicUrl,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}
