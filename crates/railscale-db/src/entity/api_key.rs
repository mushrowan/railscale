//! apikey entity for database storage.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::NotSet, Set};

use railscale_types::{ApiKey, UserId};

/// apikey database model.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// selector portion for database lookup (hex-encoded, 32 chars).
    pub selector: String,
    /// sha-256 hash of the verifier (hex-encoded, 64 chars).
    pub verifier_hash: String,
    pub name: String,
    pub user_id: i64,
    pub expiration: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for ApiKey {
    fn from(model: Model) -> Self {
        ApiKey {
            id: model.id as u64,
            selector: model.selector,
            verifier_hash: model.verifier_hash,
            name: model.name,
            user_id: UserId::from(model.user_id),
            expiration: model.expiration,
            created_at: model.created_at,
            last_used_at: model.last_used_at,
        }
    }
}

impl From<&ApiKey> for ActiveModel {
    fn from(key: &ApiKey) -> Self {
        ActiveModel {
            id: if key.id == 0 {
                NotSet
            } else {
                Set(key.id as i64)
            },
            selector: Set(key.selector.clone()),
            verifier_hash: Set(key.verifier_hash.clone()),
            name: Set(key.name.clone()),
            user_id: Set(key.user_id.as_i64()),
            expiration: Set(key.expiration),
            created_at: Set(key.created_at),
            last_used_at: Set(key.last_used_at),
            deleted_at: NotSet,
        }
    }
}
