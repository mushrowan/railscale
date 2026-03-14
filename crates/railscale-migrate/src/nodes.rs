//! convert headscale nodes to railscale nodes

use chrono::{DateTime, Datelike, Utc};
use serde::Deserialize;

use railscale_types::{DiscoKey, MachineKey, Node, NodeKey, RegisterMethod, Tag, UserId};

/// a node row from headscale's sqlite database
///
/// keys are stored as prefixed hex strings (e.g. "mkey:abc123...")
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "cli", derive(sqlx::FromRow))]
pub struct HeadscaleNode {
    pub id: i64,
    pub machine_key: String,
    pub node_key: String,
    pub disco_key: String,
    /// json array of socket addresses
    pub endpoints: String,
    /// json-encoded hostinfo blob
    pub host_info: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub hostname: String,
    pub given_name: String,
    pub user_id: Option<i64>,
    pub register_method: String,
    /// json array of tag strings like ["tag:server"]
    pub tags: Option<String>,
    pub auth_key_id: Option<i64>,
    pub last_seen: Option<DateTime<Utc>>,
    pub expiry: Option<DateTime<Utc>>,
    /// json array of cidr strings
    pub approved_routes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// error converting a headscale node
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("invalid machine key: {0}")]
    MachineKey(String),
    #[error("invalid node key: {0}")]
    NodeKey(String),
}

/// parse a prefixed hex key string like "mkey:abc123" into raw bytes
fn parse_hex_key(s: &str) -> Result<[u8; 32], String> {
    let hex_part = s.split_once(':').map(|(_, hex)| hex).unwrap_or(s);
    let bytes = hex::decode(hex_part).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "key must be 32 bytes".to_string())
}

/// convert a headscale node to a railscale node
pub fn convert_node(hs: &HeadscaleNode) -> Result<Node, ConvertError> {
    let machine_key = MachineKey::from_bytes(
        parse_hex_key(&hs.machine_key).map_err(|e| ConvertError::MachineKey(e))?,
    );
    let node_key =
        NodeKey::from_bytes(parse_hex_key(&hs.node_key).map_err(|e| ConvertError::NodeKey(e))?);
    let disco_key = parse_hex_key(&hs.disco_key)
        .map(DiscoKey::from_bytes)
        .unwrap_or_default();

    let register_method = match hs.register_method.as_str() {
        "oidc" => RegisterMethod::Oidc,
        "cli" => RegisterMethod::Cli,
        _ => RegisterMethod::AuthKey,
    };

    let tags: Vec<Tag> = hs
        .tags
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let approved_routes: Vec<ipnet::IpNet> = hs
        .approved_routes
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let endpoints: Vec<std::net::SocketAddr> =
        serde_json::from_str(&hs.endpoints).unwrap_or_default();

    let given_name = railscale_types::NodeName::sanitise(&hs.given_name)
        .unwrap_or_else(|| "node".parse().unwrap());

    let mut builder = Node::builder(machine_key, node_key, hs.hostname.clone())
        .id(railscale_types::NodeId::from(hs.id as u64))
        .disco_key(disco_key)
        .endpoints(endpoints)
        .given_name(given_name)
        .register_method(register_method)
        .tags(tags)
        .approved_routes(approved_routes)
        .created_at(hs.created_at)
        .updated_at(hs.updated_at);

    if let Some(ref s) = hs.ipv4 {
        if let Ok(ip) = s.parse() {
            builder = builder.ipv4(ip);
        }
    }
    if let Some(ref s) = hs.ipv6 {
        if let Ok(ip) = s.parse() {
            builder = builder.ipv6(ip);
        }
    }
    if let Some(uid) = hs.user_id {
        builder = builder.user_id(UserId::from(uid));
    }
    if let Some(id) = hs.auth_key_id {
        builder = builder.auth_key_id(id as u64);
    }
    if let Some(ls) = hs.last_seen {
        builder = builder.last_seen(ls);
    }
    if let Some(exp) = hs.expiry {
        // headscale uses 0001-01-01 to mean "no expiry"
        if exp.year() > 1 {
            builder = builder.expiry(exp);
        }
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn sample_node() -> HeadscaleNode {
        HeadscaleNode {
            id: 101,
            machine_key: "mkey:aa".to_string() + &"bb".repeat(31),
            node_key: "nodekey:cc".to_string() + &"dd".repeat(31),
            disco_key: "discokey:ee".to_string() + &"ff".repeat(31),
            endpoints: r#"["203.0.113.5:41641","10.0.0.1:41641"]"#.into(),
            host_info: None,
            ipv4: Some("100.64.0.1".into()),
            ipv6: Some("fd7a:115c:a1e0::1".into()),
            hostname: "ml-worker".into(),
            given_name: "ml-worker".into(),
            user_id: Some(2),
            register_method: "authkey".into(),
            tags: Some(r#"["tag:ml","tag:server"]"#.into()),
            auth_key_id: Some(53),
            last_seen: Some("2026-03-11T20:40:27Z".parse().unwrap()),
            expiry: None,
            approved_routes: Some(r#"["0.0.0.0/0","::/0"]"#.into()),
            created_at: "2026-01-15T10:00:00Z".parse().unwrap(),
            updated_at: "2026-03-11T20:40:27Z".parse().unwrap(),
        }
    }

    fn oidc_node() -> HeadscaleNode {
        HeadscaleNode {
            id: 123,
            machine_key: "mkey:11".to_string() + &"22".repeat(31),
            node_key: "nodekey:33".to_string() + &"44".repeat(31),
            disco_key: "discokey:55".to_string() + &"66".repeat(31),
            endpoints: r#"["198.51.100.10:41641"]"#.into(),
            host_info: None,
            ipv4: Some("100.64.0.18".into()),
            ipv6: Some("fd7a:115c:a1e0::12".into()),
            hostname: "laptop-abc123".into(),
            given_name: "ros-laptop".into(),
            user_id: Some(14),
            register_method: "oidc".into(),
            tags: None,
            auth_key_id: None,
            last_seen: Some("2026-03-11T20:40:27Z".parse().unwrap()),
            expiry: Some("2026-08-24T09:26:41Z".parse().unwrap()),
            approved_routes: None,
            created_at: "2026-02-01T12:00:00Z".parse().unwrap(),
            updated_at: "2026-03-11T20:40:27Z".parse().unwrap(),
        }
    }

    #[test]
    fn convert_tagged_node() {
        let hs = sample_node();
        let node = convert_node(&hs).unwrap();

        assert_eq!(node.id().as_u64(), 101);
        assert_eq!(node.hostname(), "ml-worker");
        assert_eq!(node.given_name().as_str(), "ml-worker");
        assert_eq!(node.user_id(), Some(UserId::from(2i64)));
        assert!(!node.machine_key().is_zero());
        assert!(!node.node_key().is_zero());
    }

    #[test]
    fn convert_node_keys_parsed() {
        let hs = sample_node();
        let node = convert_node(&hs).unwrap();

        // first byte of machine key should be 0xaa
        assert_eq!(node.machine_key().as_bytes()[0], 0xaa);
        // first byte of node key should be 0xcc
        assert_eq!(node.node_key().as_bytes()[0], 0xcc);
        // first byte of disco key should be 0xee
        assert_eq!(node.disco_key().as_bytes()[0], 0xee);
    }

    #[test]
    fn convert_node_ips() {
        let hs = sample_node();
        let node = convert_node(&hs).unwrap();

        assert_eq!(node.ipv4(), Some("100.64.0.1".parse::<IpAddr>().unwrap()));
        assert_eq!(
            node.ipv6(),
            Some("fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn convert_node_tags() {
        let hs = sample_node();
        let node = convert_node(&hs).unwrap();

        assert!(node.is_tagged());
        assert!(node.has_tag("tag:ml"));
        assert!(node.has_tag("tag:server"));
    }

    #[test]
    fn convert_node_register_method() {
        let tagged = convert_node(&sample_node()).unwrap();
        assert_eq!(tagged.register_method(), RegisterMethod::AuthKey);

        let oidc = convert_node(&oidc_node()).unwrap();
        assert_eq!(oidc.register_method(), RegisterMethod::Oidc);
    }

    #[test]
    fn convert_node_approved_routes() {
        let hs = sample_node();
        let node = convert_node(&hs).unwrap();

        let routes = node.approved_routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn convert_oidc_node_with_expiry() {
        let hs = oidc_node();
        let node = convert_node(&hs).unwrap();

        assert_eq!(node.id().as_u64(), 123);
        assert!(!node.is_tagged());
        assert!(node.expiry().is_some());
        assert_eq!(node.given_name().as_str(), "ros-laptop");
    }

    #[test]
    fn convert_node_preserves_timestamps() {
        let hs = sample_node();
        let node = convert_node(&hs).unwrap();

        assert_eq!(node.created_at(), hs.created_at);
        assert_eq!(node.updated_at(), hs.updated_at);
        assert_eq!(node.last_seen(), hs.last_seen);
    }

    #[test]
    fn parse_hex_key_strips_prefix() {
        let hex = "mkey:".to_string() + &"ab".repeat(32);
        let bytes = parse_hex_key(&hex).unwrap();
        assert_eq!(bytes[0], 0xab);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn parse_hex_key_bad_length() {
        let hex = "mkey:aabb";
        assert!(parse_hex_key(hex).is_err());
    }
}
