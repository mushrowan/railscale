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
use crate::node_name::NodeName;
use crate::tag::Tag;
use crate::user::UserId;

/// unique identifier for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(u64);

impl NodeId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// convert to a stable id string (used in tailscale protocol).
    pub fn stable_id(&self) -> String {
        self.0.to_string()
    }

    /// get the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// convert to i64 for database storage.
    pub fn as_i64(self) -> i64 {
        self.0 as i64
    }
}

impl From<u64> for NodeId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<i64> for NodeId {
    fn from(id: i64) -> Self {
        Self(id as u64)
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
    pub(crate) id: NodeId,
    pub(crate) machine_key: MachineKey,
    pub(crate) node_key: NodeKey,
    pub(crate) disco_key: DiscoKey,
    pub(crate) endpoints: Vec<SocketAddr>,
    pub(crate) hostinfo: Option<HostInfo>,
    pub(crate) ipv4: Option<IpAddr>,
    pub(crate) ipv6: Option<IpAddr>,
    pub(crate) hostname: String,
    pub(crate) given_name: NodeName,
    pub(crate) user_id: Option<UserId>,
    pub(crate) register_method: RegisterMethod,
    pub(crate) tags: Vec<Tag>,
    pub(crate) auth_key_id: Option<u64>,
    pub(crate) ephemeral: bool,
    pub(crate) expiry: Option<DateTime<Utc>>,
    pub(crate) last_seen: Option<DateTime<Utc>>,
    pub(crate) last_seen_country: Option<String>,
    pub(crate) approved_routes: Vec<IpNet>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    #[serde(skip)]
    pub(crate) is_online: Option<bool>,
    #[serde(default)]
    pub(crate) posture_attributes: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nl_public_key: Option<Vec<u8>>,
}

/// builder for constructing Node values
///
/// required fields: machine_key, node_key, hostname.
/// all other fields have sensible defaults.
pub struct NodeBuilder {
    node: Node,
}

impl NodeBuilder {
    pub fn new(machine_key: MachineKey, node_key: NodeKey, hostname: String) -> Self {
        let given_name = NodeName::sanitise(&hostname).unwrap_or_else(|| "node".parse().unwrap());
        let now = Utc::now();
        Self {
            node: Node {
                id: NodeId::new(0),
                machine_key,
                node_key,
                disco_key: DiscoKey::default(),
                endpoints: vec![],
                hostinfo: None,
                ipv4: None,
                ipv6: None,
                hostname,
                given_name,
                user_id: None,
                register_method: RegisterMethod::default(),
                tags: vec![],
                auth_key_id: None,
                ephemeral: false,
                expiry: None,
                last_seen: None,
                last_seen_country: None,
                approved_routes: vec![],
                created_at: now,
                updated_at: now,
                is_online: None,
                posture_attributes: HashMap::new(),
                nl_public_key: None,
            },
        }
    }

    pub fn id(mut self, id: NodeId) -> Self {
        self.node.id = id;
        self
    }

    pub fn disco_key(mut self, key: DiscoKey) -> Self {
        self.node.disco_key = key;
        self
    }

    pub fn endpoints(mut self, endpoints: Vec<SocketAddr>) -> Self {
        self.node.endpoints = endpoints;
        self
    }

    pub fn hostinfo(mut self, hostinfo: HostInfo) -> Self {
        self.node.hostinfo = Some(hostinfo);
        self
    }

    pub fn ipv4(mut self, ip: IpAddr) -> Self {
        self.node.ipv4 = Some(ip);
        self
    }

    pub fn ipv6(mut self, ip: IpAddr) -> Self {
        self.node.ipv6 = Some(ip);
        self
    }

    pub fn given_name(mut self, name: NodeName) -> Self {
        self.node.given_name = name;
        self
    }

    pub fn user_id(mut self, id: UserId) -> Self {
        self.node.user_id = Some(id);
        self
    }

    pub fn register_method(mut self, method: RegisterMethod) -> Self {
        self.node.register_method = method;
        self
    }

    pub fn tags(mut self, tags: Vec<Tag>) -> Self {
        self.node.tags = tags;
        self
    }

    pub fn auth_key_id(mut self, id: u64) -> Self {
        self.node.auth_key_id = Some(id);
        self
    }

    pub fn ephemeral(mut self, ephemeral: bool) -> Self {
        self.node.ephemeral = ephemeral;
        self
    }

    pub fn expiry(mut self, expiry: DateTime<Utc>) -> Self {
        self.node.expiry = Some(expiry);
        self
    }

    pub fn last_seen(mut self, last_seen: DateTime<Utc>) -> Self {
        self.node.last_seen = Some(last_seen);
        self
    }

    pub fn last_seen_country(mut self, country: String) -> Self {
        self.node.last_seen_country = Some(country);
        self
    }

    pub fn approved_routes(mut self, routes: Vec<IpNet>) -> Self {
        self.node.approved_routes = routes;
        self
    }

    pub fn created_at(mut self, time: DateTime<Utc>) -> Self {
        self.node.created_at = time;
        self
    }

    pub fn updated_at(mut self, time: DateTime<Utc>) -> Self {
        self.node.updated_at = time;
        self
    }

    pub fn posture_attributes(mut self, attrs: HashMap<String, serde_json::Value>) -> Self {
        self.node.posture_attributes = attrs;
        self
    }

    pub fn nl_public_key(mut self, key: Vec<u8>) -> Self {
        self.node.nl_public_key = Some(key);
        self
    }

    pub fn build(self) -> Node {
        self.node
    }
}

impl Node {
    pub fn builder(machine_key: MachineKey, node_key: NodeKey, hostname: String) -> NodeBuilder {
        NodeBuilder::new(machine_key, node_key, hostname)
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn machine_key(&self) -> &MachineKey {
        &self.machine_key
    }

    pub fn node_key(&self) -> &NodeKey {
        &self.node_key
    }

    pub fn disco_key(&self) -> &DiscoKey {
        &self.disco_key
    }

    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    pub fn hostinfo(&self) -> Option<&HostInfo> {
        self.hostinfo.as_ref()
    }

    pub fn ipv4(&self) -> Option<IpAddr> {
        self.ipv4
    }

    pub fn ipv6(&self) -> Option<IpAddr> {
        self.ipv6
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn given_name(&self) -> &NodeName {
        &self.given_name
    }

    pub fn user_id(&self) -> Option<UserId> {
        self.user_id
    }

    pub fn register_method(&self) -> RegisterMethod {
        self.register_method
    }

    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }

    pub fn auth_key_id(&self) -> Option<u64> {
        self.auth_key_id
    }

    pub fn ephemeral(&self) -> bool {
        self.ephemeral
    }

    pub fn expiry(&self) -> Option<DateTime<Utc>> {
        self.expiry
    }

    pub fn last_seen(&self) -> Option<DateTime<Utc>> {
        self.last_seen
    }

    pub fn last_seen_country(&self) -> Option<&str> {
        self.last_seen_country.as_deref()
    }

    pub fn approved_routes(&self) -> &[IpNet] {
        &self.approved_routes
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn is_online(&self) -> Option<bool> {
        self.is_online
    }

    pub fn posture_attributes(&self) -> &HashMap<String, serde_json::Value> {
        &self.posture_attributes
    }

    pub fn nl_public_key(&self) -> Option<&[u8]> {
        self.nl_public_key.as_deref()
    }

    pub fn set_disco_key(&mut self, key: DiscoKey) {
        self.disco_key = key;
    }

    pub fn set_hostinfo(&mut self, hostinfo: HostInfo) {
        self.hostinfo = Some(hostinfo);
    }

    pub fn set_last_seen_country(&mut self, country: String) {
        self.last_seen_country = Some(country);
    }

    pub fn set_approved_routes(&mut self, routes: Vec<IpNet>) {
        self.approved_routes = routes;
    }

    pub fn set_expiry(&mut self, expiry: DateTime<Utc>) {
        self.expiry = Some(expiry);
    }

    pub fn set_given_name(&mut self, name: NodeName) {
        self.given_name = name;
    }

    pub fn set_tags(&mut self, tags: Vec<Tag>) {
        self.tags = tags;
    }

    pub fn posture_attributes_mut(&mut self) -> &mut HashMap<String, serde_json::Value> {
        &mut self.posture_attributes
    }

    pub fn set_ipv4(&mut self, ip: IpAddr) {
        self.ipv4 = Some(ip);
    }

    pub fn set_user_id(&mut self, user_id: UserId) {
        self.user_id = Some(user_id);
    }

    pub fn set_is_online(&mut self, online: bool) {
        self.is_online = Some(online);
    }

    pub fn set_node_key(&mut self, key: NodeKey) {
        self.node_key = key;
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
    }

    pub fn set_endpoints(&mut self, endpoints: Vec<SocketAddr>) {
        self.endpoints = endpoints;
    }

    pub fn set_last_seen(&mut self, last_seen: DateTime<Utc>) {
        self.last_seen = Some(last_seen);
    }

    pub fn set_id(&mut self, id: NodeId) {
        self.id = id;
    }

    pub fn set_nl_public_key(&mut self, key: Option<Vec<u8>>) {
        self.nl_public_key = key;
    }

    pub fn set_ephemeral(&mut self, ephemeral: bool) {
        self.ephemeral = ephemeral;
    }

    pub fn set_auth_key_id(&mut self, id: u64) {
        self.auth_key_id = Some(id);
    }

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

    /// the dns-safe display name: given_name if set, otherwise hostname.
    pub fn display_hostname(&self) -> &str {
        self.given_name.as_str()
    }

    /// returns all ip addresses assigned to this node.
    pub fn ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4.into_iter().chain(self.ipv6)
    }

    /// returns the routes this node is currently announcing.
    pub fn announced_routes(&self) -> &[IpNet] {
        self.hostinfo
            .as_ref()
            .map(|h| h.routable_ips.as_slice())
            .unwrap_or(&[])
    }

    /// returns the subnet routes (excluding exit routes) that are approved.
    pub fn subnet_routes(&self) -> impl Iterator<Item = &IpNet> {
        self.announced_routes()
            .iter()
            .filter(|route| !is_exit_route(route) && self.approved_routes.contains(route))
    }

    /// returns the exit routes if enabled.
    pub fn exit_routes(&self) -> impl Iterator<Item = &IpNet> {
        self.announced_routes()
            .iter()
            .filter(|route| is_exit_route(route) && self.approved_routes.contains(route))
    }

    /// returns whether this node is an exit node.
    pub fn is_exit_node(&self) -> bool {
        self.exit_routes().next().is_some()
    }

    /// returns whether this node is a subnet router.
    pub fn is_subnet_router(&self) -> bool {
        self.subnet_routes().next().is_some()
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
        assert_eq!(node.ips().count(), 2);
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
