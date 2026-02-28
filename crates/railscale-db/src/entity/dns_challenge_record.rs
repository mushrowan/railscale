//! dns challenge record entity for database storage

use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::NotSet, Set};

use railscale_types::NodeId;

use crate::DnsChallengeRecord;

/// dns challenge record database model
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "dns_challenge_records")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub node_id: i64,
    pub record_name: String,
    pub record_id: String,
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

impl From<Model> for DnsChallengeRecord {
    fn from(model: Model) -> Self {
        DnsChallengeRecord {
            id: model.id as u64,
            node_id: NodeId::from(model.node_id),
            record_name: model.record_name,
            record_id: model.record_id,
            created_at: model.created_at,
        }
    }
}

impl From<&DnsChallengeRecord> for ActiveModel {
    fn from(record: &DnsChallengeRecord) -> Self {
        ActiveModel {
            id: if record.id == 0 {
                NotSet
            } else {
                Set(record.id as i64)
            },
            node_id: Set(record.node_id.as_i64()),
            record_name: Set(record.record_name.clone()),
            record_id: Set(record.record_id.clone()),
            created_at: Set(record.created_at),
        }
    }
}
