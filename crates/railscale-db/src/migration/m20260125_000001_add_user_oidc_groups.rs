//! add oidc_groups column to users table
//!
//! stores oidc group memberships as a json array string
//! this enables mapping oidc groups to policy groups for grants evaluation

use sea_orm_migration::prelude::*;

use super::m20260106_000001_create_users::Users;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // add oidc_groups column as nullable TEXT (json array string)
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Alias::new("oidc_groups")).text())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Alias::new("oidc_groups"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
