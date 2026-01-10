//! maprequest and mapresponse types for the tailscale control protocol.
//!
//! these are the core messages exchanged between tailscale clients and
//! the control server for network coordination.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use railscale_types::{HostInfo, NodeKey};

use crate::CapabilityVersion;

/// a maprequest from a tailscale client.
///
/// clients send maprequests periodically (every 15-60 seconds) to:
/// - report their current state (endpoints, hostinfo)
/// - request the current network map (list of peers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapRequest {
    /// client's capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// client's disco key (for peer discovery).
    pub disco_key: Option<Vec<u8>>,

    /// client's current endpoints.
    pub endpoints: Vec<SocketAddr>,

    /// client's host information.
    pub hostinfo: Option<HostInfo>,

    /// whether to omit peers in the response (for lightweight keepalives).
    pub omit_peers: bool,

    /// whether this is a streaming request.
    pub stream: bool,

    /// debug flags.
    pub debug_flags: Vec<String>,
}

impl MapRequest {
    /// check if this is a read-only request (just wants the map, no updates).
    pub fn is_read_only(&self) -> bool {
        self.endpoints.is_empty() && self.hostinfo.is_none()
    }
}

/// a mapresponse sent to tailscale clients.
///
/// contains the network map: list of peers, dns config, derp map, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapResponse {
    /// whether to keep the connection alive for streaming updates.
    pub keep_alive: bool,

    /// the node's own information.
    pub node: Option<MapResponseNode>,

    /// list of peer nodes.
    pub peers: Vec<MapResponseNode>,

    /// dns configuration.
    pub dns_config: Option<DnsConfig>,

    /// derp map for relay servers.
    pub derp_map: Option<DerpMap>,

    /// packet filter rules (simplified for now).
    pub packet_filter: Vec<FilterRule>,

    /// user profiles for display.
    pub user_profiles: Vec<UserProfile>,

    /// control server time (for clock sync).
    pub control_time: Option<String>,
}

impl MapResponse {
    /// create an empty keepalive response.
    pub fn keepalive() -> Self {
        Self {
            keep_alive: true,
            node: None,
            peers: vec![],
            dns_config: None,
            derp_map: None,
            packet_filter: vec![],
            user_profiles: vec![],
            control_time: None,
        }
    }
}

/// node information in a mapresponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapResponseNode {
    /// node id.
    pub id: u64,

    /// stable node id (string form).
    pub stable_id: String,

    /// node's display name.
    pub name: String,

    /// node key.
    pub node_key: Vec<u8>,

    /// machine key.
    pub machine_key: Vec<u8>,

    /// disco key.
    pub disco_key: Vec<u8>,

    /// assigned addresses.
    pub addresses: Vec<String>,

    /// allowed ips (addresses + routes).
    pub allowed_ips: Vec<String>,

    /// network endpoints.
    pub endpoints: Vec<String>,

    /// preferred derp region.
    pub derp: String,

    /// host information.
    pub hostinfo: Option<HostInfo>,

    /// whether the node is online.
    pub online: Option<bool>,

    /// tags on this node.
    pub tags: Vec<String>,

    /// primary routes this node serves.
    pub primary_routes: Vec<String>,

    /// when the node key expires.
    pub key_expiry: Option<String>,

    /// whether the node is expired.
    pub expired: bool,

    /// user id that owns this node.
    pub user: u64,
}

/// dns configuration for clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// nameservers to use.
    pub nameservers: Vec<String>,

    /// search domains.
    pub domains: Vec<String>,

    /// whether to use the routes for dns.
    pub routes: std::collections::HashMap<String, Vec<String>>,
}

/// derp map for relay servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpMap {
    /// derp regions.
    pub regions: std::collections::HashMap<i32, DerpRegion>,
}

/// a derp region.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpRegion {
    /// region id.
    #[serde(rename = "RegionID")]
    pub region_id: i32,

    /// region code (e.g., "nyc", "sfo").
    pub region_code: String,

    /// region name.
    pub region_name: String,

    /// derp nodes in this region.
    pub nodes: Vec<DerpNode>,
}

/// a derp node/server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DerpNode {
    /// node name.
    pub name: String,

    /// derp port (0 means 443)
    #[serde(rename = "RegionID")]
    pub region_id: i32,

    /// whether the node can serve on port 80 (for captive portal checks)
    pub host_name: String,

    /// ipv4 address.
    #[serde(rename = "IPv4", default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,

    /// ipv6 address.
    #[serde(rename = "IPv6", default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,

    /// stun port (0 means 3478, -1 means disabled).
    #[serde(rename = "STUNPort", default)]
    pub stun_port: i32,

    /// whether stun-only (no derp relay).
    #[serde(rename = "STUNOnly", default)]
    pub stun_only: bool,

    /// derp port (0 means 443).
    #[serde(rename = "DERPPort", default)]
    pub derp_port: i32,

    /// whether the node can serve on port 80 (for captive portal checks).
    #[serde(rename = "CanPort80", default)]
    pub can_port_80: bool,
}

/// a packet filter rule (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    /// source cidrs.
    pub src_ips: Vec<String>,

    /// destination ports.
    pub dst_ports: Vec<PortRange>,
}

/// a port range for filter rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    /// ip (can be cidr).
    pub ip: String,

    /// port range.
    pub ports: (u16, u16),
}

/// user profile for display in clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// user id.
    pub id: u64,

    /// login name / username.
    pub login_name: String,

    /// display name.
    pub display_name: String,

    /// profile picture url.
    pub profile_pic_url: Option<String>,
}
