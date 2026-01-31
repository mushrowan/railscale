//! tka aum entity for storing the AUM chain.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;

/// tka aum database model.
///
/// stores individual AUMs (Authority Update Messages) that form the TKA chain.
/// each AUM is keyed by its hash and contains a reference to its predecessor.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "tka_aums")]
pub struct Model {
    /// hex-encoded BLAKE2s hash of the AUM (primary key)
    #[sea_orm(primary_key, auto_increment = false)]
    pub hash: String,

    /// hex-encoded hash of the previous AUM (null for genesis)
    pub prev_hash: Option<String>,

    /// CBOR-serialized AUM data
    #[sea_orm(column_type = "VarBinary(StringLen::None)")]
    pub aum_data: Vec<u8>,

    pub created_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
