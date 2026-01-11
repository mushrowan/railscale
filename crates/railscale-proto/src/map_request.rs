//! maprequest and mapresponse types for the tailscale control protocol.
//!
//! these are the core messages exchanged between tailscale clients and
//! the control server for network coordination.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use railscale_types::{DiscoKey, HostInfo, MachineKey, NodeKey};

use crate::CapabilityVersion;

/// a maprequest from a tailscale client.
///
/// clients send maprequests periodically (every 15-60 seconds) to:
/// - report their current state (endpoints, hostinfo)
/// - request the current network map (list of peers)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    /// client's capability version.
    pub version: CapabilityVersion,

    /// client's current node key.
    pub node_key: NodeKey,

    /// client's disco key (for peer discovery).
    #[serde(default)]
    pub disco_key: Option<DiscoKey>,

    /// client's current endpoints.
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,

    /// client's host information.
    #[serde(default)]
    pub hostinfo: Option<HostInfo>,

    /// whether to omit peers in the response (for lightweight keepalives).
    #[serde(default)]
    pub omit_peers: bool,

    /// whether this is a streaming request.
    #[serde(rename = "Stream", default)]
    pub stream: bool,

    /// debug flags.
    #[serde(default)]
    pub debug_flags: Vec<String>,

    /// compression format for response ("zstd" or empty for no compression).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse {
    /// whether to keep the connection alive for streaming updates.
    pub keep_alive: bool,

    /// the node's own information.
    pub node: Option<MapResponseNode>,

    /// list of peer nodes.
    pub peers: Vec<MapResponseNode>,

    /// dns configuration.
    #[serde(rename = "DNSConfig", default, skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<DnsConfig>,

    /// derp map for relay servers.
    #[serde(rename = "DERPMap", default, skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<DerpMap>,

    /// packet filter rules (simplified for now).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packet_filter: Vec<FilterRule>,

    /// user profiles for display.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_profiles: Vec<UserProfile>,

    /// control server time (for clock sync).
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponseNode {
    /// node id.
    #[serde(rename = "ID")]
    pub id: u64,

    /// stable node id (string form).
    #[serde(rename = "StableID")]
    pub stable_id: String,

    /// node's display name.
    pub name: String,

    /// node key (serialized as prefixed hex, e.g., "nodekey:...").
    #[serde(rename = "Key")]
    pub node_key: NodeKey,

    /// machine key (serialized as prefixed hex, e.g., "mkey:...").
    #[serde(rename = "Machine")]
    pub machine_key: MachineKey,

    /// disco key (serialized as prefixed hex, e.g., "discokey:...").
    pub disco_key: DiscoKey,

    /// assigned addresses.
    pub addresses: Vec<String>,

    /// allowed ips (addresses + routes).
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<String>,

    /// network endpoints.
    pub endpoints: Vec<String>,

    /// preferred derp region.
    #[serde(rename = "DERP")]
    pub derp: String,

    /// host information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<HostInfo>,

    /// whether the node is online.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,

    /// tags on this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// primary routes this node serves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_routes: Vec<String>,

    /// when the node key expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,

    /// whether the node is expired.
    #[serde(default)]
    pub expired: bool,

    /// user id that owns this node.
    pub user: u64,
}

/// a dns resolver entry (matches tailscale's dnstype.resolver).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DnsResolver {
    /// resolver address (ip, ip:port, or https://... for doh).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub addr: String,
}

impl DnsResolver {
    /// create a new dns resolver from an address string.
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }
}

/// dns configuration for clients.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DnsConfig {
    /// dns resolvers to use, in order of preference.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<DnsResolver>,

    /// search domains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,

    /// split dns routes: maps dns name suffixes to resolvers.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub routes: std::collections::HashMap<String, Vec<DnsResolver>>,
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

    /// region id.
    #[serde(rename = "RegionID")]
    pub region_id: i32,

    /// hostname.
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct FilterRule {
    /// source cidrs.
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,

    /// first port in range
    pub dst_ports: Vec<NetPortRange>,
}

/// a port range (matches tailscale's tailcfg.portrange).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PortRange {
    /// first port in range.
    pub first: u16,
    /// last port in range (inclusive).
    pub last: u16,
}

impl PortRange {
    /// create a port range for all ports
    pub fn single(port: u16) -> Self {
        Self {
            first: port,
            last: port,
        }
    }

    /// create a port range for all ports.
    pub fn any() -> Self {
        Self {
            first: 0,
            last: 65535,
        }
    }
}

/// a network port range for filter rules (matches tailscale's tailcfg.netportrange).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct NetPortRange {
    /// ip (can be cidr, range, or "*").
    #[serde(rename = "IP")]
    pub ip: String,

    /// port range.
    pub ports: PortRange,
}

/// user profile for display in clients.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile {
    /// user id.
    #[serde(rename = "ID")]
    pub id: u64,

    /// login name / username.
    pub login_name: String,

    /// display name.
    pub display_name: String,

    /// profile picture url.
    #[serde(
        rename = "ProfilePicURL",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_pic_url: Option<String>,
}
