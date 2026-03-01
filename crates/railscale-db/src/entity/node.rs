//! node entity for database storage.

use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue::NotSet, Set};
use tracing::warn;

use railscale_types::{
    DiscoKey, HostInfo, MachineKey, Node, NodeId, NodeKey, RegisterMethod, Tag, UserId,
};
use std::collections::HashMap;

/// node database model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "nodes")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,

    /// machine key bytes
    #[sea_orm(column_type = "VarBinary(StringLen::None)")]
    pub machine_key: Vec<u8>,

    /// node key bytes
    #[sea_orm(column_type = "VarBinary(StringLen::None)")]
    pub node_key: Vec<u8>,

    /// disco key bytes
    #[sea_orm(column_type = "VarBinary(StringLen::None)")]
    pub disco_key: Vec<u8>,

    /// json-serialized vec<socketaddr>
    #[sea_orm(column_type = "Text")]
    pub endpoints: String,

    /// json-serialized hostinfo
    #[sea_orm(column_type = "Text", nullable)]
    pub hostinfo: Option<String>,

    /// ipv4 address as string
    pub ipv4: Option<String>,

    /// ipv6 address as string
    pub ipv6: Option<String>,

    pub hostname: String,
    pub given_name: String,

    pub user_id: Option<i64>,

    /// registermethod as string
    pub register_method: String,

    /// json-serialized vec<string>
    #[sea_orm(column_type = "Text")]
    pub tags: String,

    pub auth_key_id: Option<i64>,

    /// whether this is an ephemeral node
    pub ephemeral: bool,

    pub expiry: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,

    /// json-serialized vec<ipnet>
    #[sea_orm(column_type = "Text")]
    pub approved_routes: String,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,

    /// tka node-key signature (cbor-encoded)
    #[sea_orm(column_type = "VarBinary(StringLen::None)", nullable)]
    pub key_signature: Option<Vec<u8>>,

    /// custom posture attributes (json object)
    #[sea_orm(column_type = "Text", nullable)]
    pub posture_attributes: Option<String>,

    /// ISO 3166-1 alpha-2 country code from geoip lookup
    pub last_seen_country: Option<String>,

    /// network lock public key (raw ed25519, 32 bytes)
    #[sea_orm(column_type = "VarBinary(StringLen::None)", nullable)]
    pub nl_public_key: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::preauth_key::Entity",
        from = "Column::AuthKeyId",
        to = "super::preauth_key::Column::Id"
    )]
    AuthKey,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::preauth_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuthKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for Node {
    fn from(model: Model) -> Self {
        let endpoints: Vec<SocketAddr> = match serde_json::from_str(&model.endpoints) {
            Ok(v) => v,
            Err(e) => {
                warn!(node_id = model.id, error = %e, "failed to parse node endpoints JSON, using empty list");
                Vec::new()
            }
        };
        let hostinfo: Option<HostInfo> =
            model
                .hostinfo
                .as_ref()
                .and_then(|s| match serde_json::from_str(s) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        warn!(node_id = model.id, error = %e, "failed to parse node hostinfo JSON");
                        None
                    }
                });
        // parse tags - invalid tags from legacy data are filtered out
        let tags: Vec<Tag> = match serde_json::from_str::<Vec<String>>(&model.tags) {
            Ok(v) => v.into_iter().filter_map(|s| s.parse().ok()).collect(),
            Err(e) => {
                warn!(node_id = model.id, error = %e, "failed to parse node tags JSON, using empty list");
                Vec::new()
            }
        };
        let approved_routes: Vec<IpNet> = match serde_json::from_str(&model.approved_routes) {
            Ok(v) => v,
            Err(e) => {
                warn!(node_id = model.id, error = %e, "failed to parse node approved_routes JSON, using empty list");
                Vec::new()
            }
        };

        let ipv4: Option<IpAddr> = model.ipv4.as_ref().and_then(|s| s.parse().ok());
        let ipv6: Option<IpAddr> = model.ipv6.as_ref().and_then(|s| s.parse().ok());

        let register_method = match model.register_method.as_str() {
            "oidc" => RegisterMethod::Oidc,
            "cli" => RegisterMethod::Cli,
            _ => RegisterMethod::AuthKey,
        };

        let posture_attributes: HashMap<String, serde_json::Value> = model
            .posture_attributes
            .as_ref()
            .and_then(|s| match serde_json::from_str(s) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(node_id = model.id, error = %e, "failed to parse posture_attributes JSON");
                    None
                }
            })
            .unwrap_or_default();

        let machine_key = MachineKey::try_from_bytes(&model.machine_key).unwrap_or_default();
        let node_key = NodeKey::try_from_bytes(&model.node_key).unwrap_or_default();
        let disco_key = DiscoKey::try_from_bytes(&model.disco_key).unwrap_or_default();

        let mut builder = Node::builder(machine_key, node_key, model.hostname)
            .id(NodeId::from(model.id))
            .disco_key(disco_key)
            .endpoints(endpoints)
            .given_name(
                railscale_types::NodeName::sanitise(&model.given_name)
                    .unwrap_or_else(|| "node".parse().unwrap()),
            )
            .register_method(register_method)
            .tags(tags)
            .ephemeral(model.ephemeral)
            .approved_routes(approved_routes)
            .created_at(model.created_at)
            .updated_at(model.updated_at)
            .posture_attributes(posture_attributes);

        if let Some(hi) = hostinfo {
            builder = builder.hostinfo(hi);
        }
        if let Some(ip) = ipv4 {
            builder = builder.ipv4(ip);
        }
        if let Some(ip) = ipv6 {
            builder = builder.ipv6(ip);
        }
        if let Some(uid) = model.user_id {
            builder = builder.user_id(UserId::from(uid));
        }
        if let Some(id) = model.auth_key_id {
            builder = builder.auth_key_id(id as u64);
        }
        if let Some(exp) = model.expiry {
            builder = builder.expiry(exp);
        }
        if let Some(ls) = model.last_seen {
            builder = builder.last_seen(ls);
        }
        if let Some(country) = model.last_seen_country {
            builder = builder.last_seen_country(country);
        }
        if let Some(key) = model.nl_public_key {
            builder = builder.nl_public_key(key);
        }

        builder.build()
    }
}

impl From<&Node> for ActiveModel {
    fn from(node: &Node) -> Self {
        let endpoints_json =
            serde_json::to_string(node.endpoints()).unwrap_or_else(|_| "[]".to_string());
        let hostinfo_json = node.hostinfo().and_then(|h| serde_json::to_string(h).ok());
        let tags_json = serde_json::to_string(node.tags()).unwrap_or_else(|_| "[]".to_string());
        let approved_routes_json =
            serde_json::to_string(node.approved_routes()).unwrap_or_else(|_| "[]".to_string());
        let posture_attributes_json = if node.posture_attributes().is_empty() {
            None
        } else {
            serde_json::to_string(node.posture_attributes()).ok()
        };

        let register_method = match node.register_method() {
            RegisterMethod::AuthKey => "authkey",
            RegisterMethod::Oidc => "oidc",
            RegisterMethod::Cli => "cli",
        };

        ActiveModel {
            id: if node.id().as_u64() == 0 {
                NotSet
            } else {
                Set(node.id().as_i64())
            },
            machine_key: Set(node.machine_key().as_bytes().to_vec()),
            node_key: Set(node.node_key().as_bytes().to_vec()),
            disco_key: Set(node.disco_key().as_bytes().to_vec()),
            endpoints: Set(endpoints_json),
            hostinfo: Set(hostinfo_json),
            ipv4: Set(node.ipv4().map(|ip| ip.to_string())),
            ipv6: Set(node.ipv6().map(|ip| ip.to_string())),
            hostname: Set(node.hostname().to_string()),
            given_name: Set(node.given_name().to_string()),
            user_id: Set(node.user_id().map(|id| id.as_i64())),
            register_method: Set(register_method.to_string()),
            tags: Set(tags_json),
            auth_key_id: Set(node.auth_key_id().map(|id| id as i64)),
            ephemeral: Set(node.ephemeral()),
            expiry: Set(node.expiry()),
            last_seen: Set(node.last_seen()),
            approved_routes: Set(approved_routes_json),
            created_at: Set(node.created_at()),
            updated_at: Set(node.updated_at()),
            deleted_at: NotSet,
            key_signature: NotSet, // managed separately via TKA operations
            posture_attributes: Set(posture_attributes_json),
            last_seen_country: Set(node.last_seen_country().map(str::to_owned)),
            nl_public_key: Set(node.nl_public_key().map(|k| k.to_vec())),
        }
    }
}
