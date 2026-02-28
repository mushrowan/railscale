//! audit log entity for database storage

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::NotSet, Set};

use railscale_types::NodeId;

use crate::AuditLog;

/// audit log database model
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub node_id: i64,
    pub action: String,
    pub details: String,
    pub client_timestamp: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::node::Entity",
        from = "Column::NodeId",
        to = "super::node::Column::Id"
    )]
    Node,
}

impl Related<super::node::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Node.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for AuditLog {
    fn from(model: Model) -> Self {
        AuditLog {
            id: model.id as u64,
            node_id: NodeId::from(model.node_id),
            action: model.action,
            details: model.details,
            client_timestamp: model.client_timestamp,
            created_at: model.created_at,
        }
    }
}

impl From<&AuditLog> for ActiveModel {
    fn from(log: &AuditLog) -> Self {
        ActiveModel {
            id: if log.id == 0 {
                NotSet
            } else {
                Set(log.id as i64)
            },
            node_id: Set(log.node_id.as_i64()),
            action: Set(log.action.clone()),
            details: Set(log.details.clone()),
            client_timestamp: Set(log.client_timestamp),
            created_at: Set(log.created_at),
        }
    }
}
