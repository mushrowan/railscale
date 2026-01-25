//! user entity for database storage.

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::NotSet, Set};

use railscale_types::{User, UserId};

/// user database model.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub provider_identifier: Option<String>,
    pub provider: Option<String>,
    pub profile_pic_url: Option<String>,
    /// oidc groups stored as json array string (e.g., `["engineering", "admins"]`).
    pub oidc_groups: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::node::Entity")]
    Nodes,
    #[sea_orm(has_many = "super::preauth_key::Entity")]
    PreAuthKeys,
}

impl Related<super::node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Nodes.def()
    }
}

impl Related<super::preauth_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PreAuthKeys.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for User {
    fn from(model: Model) -> Self {
        // parse oidc groups from json string, defaulting to empty vec
        let oidc_groups = model
            .oidc_groups
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        User {
            id: UserId(model.id as u64),
            name: model.name,
            display_name: model.display_name,
            email: model.email,
            provider_identifier: model.provider_identifier,
            provider: model.provider,
            profile_pic_url: model.profile_pic_url,
            oidc_groups,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<&User> for ActiveModel {
    fn from(user: &User) -> Self {
        // serialize oidc groups to json string, none if empty
        let oidc_groups = if user.oidc_groups.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&user.oidc_groups).unwrap_or_default())
        };

        ActiveModel {
            id: if user.id.0 == 0 {
                NotSet
            } else {
                Set(user.id.0 as i64)
            },
            name: Set(user.name.clone()),
            display_name: Set(user.display_name.clone()),
            email: Set(user.email.clone()),
            provider_identifier: Set(user.provider_identifier.clone()),
            provider: Set(user.provider.clone()),
            profile_pic_url: Set(user.profile_pic_url.clone()),
            oidc_groups: Set(oidc_groups),
            created_at: Set(user.created_at),
            updated_at: Set(user.updated_at),
            deleted_at: NotSet,
        }
    }
}
