//! preauthkey entity for database storage.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::NotSet, Set};

use railscale_types::{PreAuthKey, Tag, UserId};

/// preauthkey database model.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "preauth_keys")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub key: String,
    pub user_id: i64,
    pub reusable: bool,
    pub ephemeral: bool,
    pub used: bool,
    /// json-serialized vec<string>
    #[sea_orm(column_type = "Text")]
    pub tags: String,
    pub expiration: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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
    #[sea_orm(has_many = "super::node::Entity")]
    Nodes,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Nodes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for PreAuthKey {
    fn from(model: Model) -> Self {
        // parse tags - invalid tags from legacy data are filtered out
        let tags: Vec<Tag> = serde_json::from_str::<Vec<String>>(&model.tags)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        PreAuthKey {
            id: model.id as u64,
            key: model.key,
            user_id: UserId(model.user_id as u64),
            reusable: model.reusable,
            ephemeral: model.ephemeral,
            used: model.used,
            tags,
            expiration: model.expiration,
            created_at: model.created_at,
        }
    }
}

impl From<&PreAuthKey> for ActiveModel {
    fn from(key: &PreAuthKey) -> Self {
        let tags_json = serde_json::to_string(&key.tags).unwrap_or_else(|_| "[]".to_string());

        ActiveModel {
            id: if key.id == 0 {
                NotSet
            } else {
                Set(key.id as i64)
            },
            key: Set(key.key.clone()),
            user_id: Set(key.user_id.0 as i64),
            reusable: Set(key.reusable),
            ephemeral: Set(key.ephemeral),
            used: Set(key.used),
            tags: Set(tags_json),
            expiration: Set(key.expiration),
            created_at: Set(key.created_at),
            deleted_at: NotSet,
        }
    }
}
