//! tka state entity for database storage.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;

/// tka state database model.
///
/// stores the tailnet key authority state. there should only ever be
/// one row in this table (id=1).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "tka_state")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,

    /// whether tka is enabled for this tailnet
    pub enabled: bool,

    /// current head aum hash (hex string)
    pub head: Option<String>,

    /// cbor-serialized tka::State checkpoint
    #[sea_orm(column_type = "VarBinary(StringLen::None)", nullable)]
    pub state_checkpoint: Option<Vec<u8>>,

    /// cbor-serialized list of hashed disablement secrets
    #[sea_orm(column_type = "VarBinary(StringLen::None)", nullable)]
    pub disablement_secrets: Option<Vec<u8>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
