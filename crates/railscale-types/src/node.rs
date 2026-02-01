//! node type representing a tailscale client/device.
//!
//! nodes are the core entity in railscale - they represent devices
//! connected to the tailnet.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::keys::{DiscoKey, MachineKey, NodeKey};
use crate::tag::Tag;
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
    pub tags: Vec<Tag>,

    /// preauthkey id used to register this node.
    pub auth_key_id: Option<u64>,

    /// whether this is an ephemeral node (auto-deleted when inactive).
    pub ephemeral: bool,

    /// when the node registration expires.
    pub expiry: Option<DateTime<Utc>>,

    /// last time the node contacted the server.
    pub last_seen: Option<DateTime<Utc>>,

    /// ISO 3166-1 alpha-2 country code from geoip lookup of connection IP.
    /// used for ip:country posture checks. updated when node connects.
    pub last_seen_country: Option<String>,

    /// routes this node is approved to announce as a subnet router.
    pub approved_routes: Vec<IpNet>,

    /// when the node was created.
    pub created_at: DateTime<Utc>,

    /// when the node was last updated.
    pub updated_at: DateTime<Utc>,

    /// whether the node is currently online (not persisted).
    #[serde(skip)]
    pub is_online: Option<bool>,

    /// custom posture attributes for access control
    ///
    /// key-value pairs in the `custom:` namespace (e.g., `custom:tier`, `custom:managed`).
    /// values can be strings, numbers, or booleans.
    #[serde(default)]
    pub posture_attributes: HashMap<String, serde_json::Value>,
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
///
/// field names match tailscale's go struct (pascalcase in json).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo {
    /// tailscale client version (e.g., "1.80.0").
    #[serde(rename = "IPNVersion", default)]
    pub ipn_version: Option<String>,

    /// frontend log id.
    #[serde(rename = "FrontendLogID", default)]
    pub frontend_log_id: Option<String>,

    /// backend log id.
    #[serde(rename = "BackendLogID", default)]
    pub backend_log_id: Option<String>,

    /// operating system (e.g., "linux", "windows", "darwin").
    #[serde(rename = "OS", default)]
    pub os: Option<String>,

    /// os version (e.g., "6.18.4" for linux kernel).
    #[serde(rename = "OSVersion", default)]
    pub os_version: Option<String>,

    /// whether running in a container.
    #[serde(default)]
    pub container: Option<bool>,

    /// environment type (e.g., "kn" for kubernetes).
    #[serde(default)]
    pub env: Option<String>,

    /// linux distribution (e.g., "debian", "ubuntu", "nixos").
    #[serde(default)]
    pub distro: Option<String>,

    /// distribution version (e.g., "24.11").
    #[serde(default)]
    pub distro_version: Option<String>,

    /// distribution codename (e.g., "jammy", "bullseye").
    #[serde(default)]
    pub distro_code_name: Option<String>,

    /// app identifier for tsnet apps (e.g., "k8s-operator").
    #[serde(default)]
    pub app: Option<String>,

    /// whether a desktop environment is present.
    #[serde(default)]
    pub desktop: Option<bool>,

    /// package type (e.g., "choco", "appstore").
    #[serde(default)]
    pub package: Option<String>,

    /// device model (e.g., "pixel 3a", "iphone12,3").
    #[serde(default)]
    pub device_model: Option<String>,

    /// hostname of the device.
    #[serde(default)]
    pub hostname: Option<String>,

    /// whether the host blocks incoming connections.
    #[serde(default)]
    pub shields_up: bool,

    /// whether this node is shared to the current user.
    #[serde(default)]
    pub sharee_node: bool,

    /// user opted out of logs/support.
    #[serde(default)]
    pub no_logs_no_support: bool,

    /// machine type (uname -m).
    #[serde(default)]
    pub machine: Option<String>,

    /// goarch of the binary.
    #[serde(default)]
    pub go_arch: Option<String>,

    /// goarm, goamd64, etc.
    #[serde(default)]
    pub go_arch_var: Option<String>,

    /// go version used to build the binary.
    #[serde(default)]
    pub go_version: Option<String>,

    /// routes this node wants to advertise.
    #[serde(rename = "RoutableIPs", default)]
    pub routable_ips: Vec<IpNet>,

    /// tags the node is requesting (for acl tag owners).
    #[serde(default)]
    pub request_tags: Vec<String>,

    /// network information.
    #[serde(default)]
    pub net_info: Option<NetInfo>,

    /// ssh host keys.
    #[serde(rename = "sshHostKeys", default)]
    pub ssh_host_keys: Vec<String>,

    /// cloud provider (e.g., "aws", "gcp").
    #[serde(default)]
    pub cloud: Option<String>,

    /// whether running in userspace (netstack) mode.
    #[serde(default)]
    pub userspace: Option<bool>,

    /// whether subnet router is in userspace mode.
    #[serde(default)]
    pub userspace_router: Option<bool>,

    /// whether running app-connector service.
    #[serde(default)]
    pub app_connector: Option<bool>,

    /// services advertised by this node (e.g., peerapi ports).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
}

/// a service running on a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    /// service protocol type.
    pub proto: ServiceProto,

    /// port number.
    pub port: u16,

    /// textual description (e.g., process name).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// service protocol type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProto {
    /// tcp service
    Tcp,
    /// udp service
    Udp,
    /// peerapi on IPv4
    #[serde(rename = "peerapi4")]
    PeerApi4,
    /// peerapi on IPv6
    #[serde(rename = "peerapi6")]
    PeerApi6,
    /// peerapi DNS proxy
    #[serde(rename = "peerapi-dns-proxy")]
    PeerApiDnsProxy,
    /// unknown protocol (forward compatibility)
    #[serde(untagged)]
    Other(String),
}

/// network information for a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetInfo {
    /// preferred derp region.
    #[serde(rename = "PreferredDERP", default)]
    pub preferred_derp: i32,

    /// latency to each derp region in seconds.
    #[serde(rename = "DERPLatency", default)]
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
}

impl AsRef<Node> for NodeView {
    fn as_ref(&self) -> &Node {
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
    use crate::test_utils::TestNodeBuilder;

    #[test]
    fn test_hostinfo_deserialize_tailscale_format() {
        // tailscale client sends pascalcase field names
        let json = r#"{
            "OS": "linux",
            "OSVersion": "6.18.4",
            "DeviceModel": "",
            "IPNVersion": "1.80.0",
            "RoutableIPs": ["192.168.1.0/24", "10.0.0.0/8"],
            "RequestTags": ["tag:server"],
            "NetInfo": {
                "PreferredDERP": 1,
                "DERPLatency": {"1": 0.025, "2": 0.050}
            },
            "Hostname": "test-node",
            "GoArch": "amd64",
            "Distro": "nixos",
            "DistroVersion": "24.11"
        }"#;

        let hostinfo: HostInfo = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(hostinfo.os, Some("linux".to_string()));
        assert_eq!(hostinfo.os_version, Some("6.18.4".to_string()));
        assert_eq!(hostinfo.routable_ips.len(), 2);
        assert_eq!(hostinfo.request_tags, vec!["tag:server".to_string()]);
        assert!(hostinfo.net_info.is_some());
        let net_info = hostinfo.net_info.unwrap();
        assert_eq!(net_info.preferred_derp, 1);
    }

    fn test_node() -> Node {
        TestNodeBuilder::new(1)
            .with_hostname("test-node")
            .with_ipv6("fd7a:115c:a1e0::1".parse().unwrap())
            .build()
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

        node.tags = vec!["tag:server".parse().unwrap()];
        assert!(node.is_tagged());
        assert!(!node.is_user_owned());
    }

    #[test]
    fn test_node_has_tag() {
        let mut node = test_node();
        node.tags = vec!["tag:server".parse().unwrap(), "tag:web".parse().unwrap()];

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
