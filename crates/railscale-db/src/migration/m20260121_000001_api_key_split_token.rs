//! migration to convert api keys to split-token pattern
//!
//! this migration replaces the plaintext `key` column with:
//! - `selector`: hex-encoded lookup key (indexed for O(1) lookup)
//! - `verifier_hash`: SHA-256 hash of the verifier portion
//!
//! existing api keys will be invalidated and need to be recreated

use sea_orm_migration::prelude::*;

use super::m20260106_000004_create_api_keys::ApiKeys;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // drop the old unique index on key
        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_keys_key")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        // drop the old key column
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::Key)
                    .to_owned(),
            )
            .await?;

        // add selector column (hex-encoded, 32 chars for 16 bytes)
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(Alias::new("selector")).string().not_null())
                    .to_owned(),
            )
            .await?;

        // add verifier_hash column (hex-encoded SHA-256, 64 chars)
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(
                        ColumnDef::new(Alias::new("verifier_hash"))
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // create unique index on selector for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_selector")
                    .table(ApiKeys::Table)
                    .col(Alias::new("selector"))
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // drop the new index
        manager
            .drop_index(
                Index::drop()
                    .name("idx_api_keys_selector")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        // drop the new columns
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(Alias::new("selector"))
                    .drop_column(Alias::new("verifier_hash"))
                    .to_owned(),
            )
            .await?;

        // restore the old key column
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::Key).string().not_null())
                    .to_owned(),
            )
            .await?;

        // restore the old index
        manager
            .create_index(
                Index::create()
                    .name("idx_api_keys_key")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::Key)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
