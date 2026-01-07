//! nodes are the core entity in railscale - they represent devices
//!
//! nodes are the core entity in railscale - they represent devices
//! connected to the tailnet.

use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::keys::{DiscoKey, MachineKey, NodeKey};
use crate::user::UserId;

/// unique identifier for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

impl NodeId {
    /// convert to a stable id string (used in tailscale protocol).
    pub fn stable_id(&self) -> String {
        self.0.to_string()
    }
}

impl From<u64> for NodeId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// a railscale node representing a tailscale client.
///
/// nodes can be either:
/// - **user-owned**: belong to a specific user, no tags
/// - **tagged**: identity defined by tags, not user ownership
///
/// this is the "tags-as-identity" model where tags and user ownership
/// are mutually exclusive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// unique identifier.
    pub id: NodeId,

    /// machine key - identifies the physical device.
    pub machine_key: MachineKey,

    /// node key - identifies the current session (can rotate).
    pub node_key: NodeKey,

    /// disco key - used for peer discovery.
    pub disco_key: DiscoKey,

    /// network endpoints where this node can be reached.
    pub endpoints: Vec<SocketAddr>,

    /// host information from the tailscale client.
    pub hostinfo: Option<HostInfo>,

    /// ipv4 address assigned to this node.
    pub ipv4: Option<IpAddr>,

    /// ipv6 address assigned to this node.
    pub ipv6: Option<IpAddr>,

    /// hostname reported by the tailscale client during registration.
    pub hostname: String,

    /// dns-safe name for the node.
    /// either auto-generated from hostname or manually set.
    pub given_name: String,

    /// user id for tracking "created by".
    ///
    /// for tagged nodes: informational only (tag is the owner).
    /// for user-owned nodes: identifies the owner.
    pub user_id: Option<UserId>,

    /// how the node was registered (authkey, oidc, cli).
    pub register_method: RegisterMethod,

    /// tags defining the node's identity (for tagged nodes).
    ///
    /// when non-empty, the node is "tagged" and tags define its identity.
    /// empty for user-owned nodes.
    /// tags cannot be removed once set (one-way transition).
    pub tags: Vec<String>,

    /// preauthkey id used to register this node.
    pub auth_key_id: Option<u64>,

    /// when the node registration expires.
    pub expiry: Option<DateTime<Utc>>,

    /// last time the node contacted the server.
    pub last_seen: Option<DateTime<Utc>>,

    /// routes this node is approved to announce as a subnet router.
    pub approved_routes: Vec<IpNet>,

    /// when the node was created.
    pub created_at: DateTime<Utc>,

    /// when the node was last updated.
    pub updated_at: DateTime<Utc>,

    /// whether the node is currently online (not persisted).
    #[serde(skip)]
    pub is_online: Option<bool>,
}

impl Node {
    /// returns whether the node registration has expired.
    pub fn is_expired(&self) -> bool {
        match &self.expiry {
            None => false,
            Some(expiry) => Utc::now() > *expiry,
        }
    }

    /// returns whether this is a tagged node.
    ///
    /// tagged nodes have their identity defined by tags, not user ownership.
    pub fn is_tagged(&self) -> bool {
        !self.tags.is_empty()
    }

    /// returns whether this is a user-owned node.
    ///
    /// user-owned nodes have no tags and belong to a specific user.
    pub fn is_user_owned(&self) -> bool {
        !self.is_tagged()
    }

    /// returns whether the node has a specific tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// returns all ip addresses assigned to this node.
    pub fn ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::with_capacity(2);
        if let Some(ip) = self.ipv4 {
            ips.push(ip);
        }
        if let Some(ip) = self.ipv6 {
            ips.push(ip);
        }
        ips
    }

    /// returns the routes this node is currently announcing.
    pub fn announced_routes(&self) -> &[IpNet] {
        self.hostinfo
            .as_ref()
            .map(|h| h.routable_ips.as_slice())
            .unwrap_or(&[])
    }

    /// returns the subnet routes (excluding exit routes) that are approved.
    pub fn subnet_routes(&self) -> Vec<IpNet> {
        self.announced_routes()
            .iter()
            .filter(|route| !is_exit_route(route) && self.approved_routes.contains(route))
            .cloned()
            .collect()
    }

    /// returns the exit routes if enabled.
    pub fn exit_routes(&self) -> Vec<IpNet> {
        self.announced_routes()
            .iter()
            .filter(|route| is_exit_route(route) && self.approved_routes.contains(route))
            .cloned()
            .collect()
    }

    /// returns whether this node is an exit node.
    pub fn is_exit_node(&self) -> bool {
        !self.exit_routes().is_empty()
    }

    /// returns whether this node is a subnet router.
    pub fn is_subnet_router(&self) -> bool {
        !self.subnet_routes().is_empty()
    }
}

/// check if a route is an exit route (0.0.0.0/0 or ::/0).
fn is_exit_route(route: &IpNet) -> bool {
    match route {
        IpNet::V4(net) => net.prefix_len() == 0,
        IpNet::V6(net) => net.prefix_len() == 0,
    }
}

/// host information reported by the tailscale client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    /// operating system (e.g., "linux", "windows", "darwin").
    pub os: Option<String>,

    /// os version.
    pub os_version: Option<String>,

    /// device model.
    pub device_model: Option<String>,

    /// tailscale client version.
    pub tailscale_version: Option<String>,

    /// routes this node wants to advertise.
    pub routable_ips: Vec<IpNet>,

    /// tags the node is requesting (for acl tag owners).
    pub request_tags: Vec<String>,

    /// network information.
    pub net_info: Option<NetInfo>,
}

/// network information for a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetInfo {
    /// preferred derp region.
    pub preferred_derp: i32,

    /// latency to each derp region in seconds.
    pub derp_latency: std::collections::HashMap<String, f64>,
}

/// how a node was registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RegisterMethod {
    /// registered via pre-authentication key.
    #[default]
    AuthKey,
    /// registered via oidc.
    Oidc,
    /// registered via cli.
    Cli,
}

/// an immutable view of a node for safe concurrent access.
///
/// this mirrors go's copy-on-write pattern used in nodestore.
#[derive(Debug, Clone)]
pub struct NodeView {
    inner: std::sync::Arc<Node>,
}

impl NodeView {
    /// create a new nodeview from a node.
    pub fn new(node: Node) -> Self {
        Self {
            inner: std::sync::Arc::new(node),
        }
    }

    /// get the node id.
    pub fn id(&self) -> NodeId {
        self.inner.id
    }

    /// check if this view is valid.
    pub fn valid(&self) -> bool {
        true // Always valid if we have an Arc
    }

    /// get the underlying node reference.
    pub fn as_ref(&self) -> &Node {
        &self.inner
    }
}

impl std::ops::Deref for NodeView {
    type Target = Node;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> Node {
        Node {
            id: NodeId(1),
            machine_key: MachineKey::default(),
            node_key: NodeKey::default(),
            disco_key: DiscoKey::default(),
            endpoints: vec![],
            hostinfo: None,
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: Some("fd7a:115c:a1e0::1".parse().unwrap()),
            hostname: "test-node".to_string(),
            given_name: "test-node".to_string(),
            user_id: Some(UserId(1)),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            expiry: None,
            last_seen: None,
            approved_routes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_online: None,
        }
    }

    #[test]
    fn test_node_ips() {
        let node = test_node();
        let ips = node.ips();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_node_is_tagged() {
        let mut node = test_node();
        assert!(!node.is_tagged());
        assert!(node.is_user_owned());

        node.tags = vec!["tag:server".to_string()];
        assert!(node.is_tagged());
        assert!(!node.is_user_owned());
    }

    #[test]
    fn test_node_has_tag() {
        let mut node = test_node();
        node.tags = vec!["tag:server".to_string(), "tag:web".to_string()];

        assert!(node.has_tag("tag:server"));
        assert!(node.has_tag("tag:web"));
        assert!(!node.has_tag("tag:database"));
    }

    #[test]
    fn test_node_not_expired() {
        let node = test_node();
        assert!(!node.is_expired());
    }

    #[test]
    fn test_node_expired() {
        let mut node = test_node();
        node.expiry = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(node.is_expired());
    }
}
