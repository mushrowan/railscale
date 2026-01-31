//! create tka_aums table for storing the AUM chain.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // create tka_aums table for storing the full AUM chain
        manager
            .create_table(
                Table::create()
                    .table(TkaAums::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TkaAums::Hash)
                            .string_len(64) // hex-encoded 32-byte hash
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TkaAums::PrevHash).string_len(64), // nullable for genesis
                    )
                    .col(ColumnDef::new(TkaAums::AumData).binary().not_null())
                    .col(
                        ColumnDef::new(TkaAums::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // create index on prev_hash for chain traversal
        manager
            .create_index(
                Index::create()
                    .name("idx_tka_aums_prev_hash")
                    .table(TkaAums::Table)
                    .col(TkaAums::PrevHash)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TkaAums::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum TkaAums {
    Table,
    Hash,
    PrevHash,
    AumData,
    CreatedAt,
}
