//! maprequest and mapresponse types for the tailscale control protocol.
//!
//! these are the core messages exchanged between tailscale clients and
//! the control server for network coordination.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// helper to skip serializing zero values.
fn is_zero(n: &i32) -> bool {
    *n == 0
}

use railscale_tka::MarshaledSignature;
use railscale_types::{DiscoKey, HostInfo, MachineKey, NodeKey};

use crate::CapabilityVersion;
use crate::ssh::SshPolicy;
use crate::tka::TkaInfo;

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

    /// ssh policy for incoming connections
    #[serde(rename = "SSHPolicy", default, skip_serializing_if = "Option::is_none")]
    pub ssh_policy: Option<SshPolicy>,

    /// tailnet key authority (tka) state.
    ///
    /// nil means no change (for delta responses).
    /// non-nil with head means tka is enabled.
    /// non-nil with disabled=true means tka should be disabled.
    #[serde(rename = "TKAInfo", default, skip_serializing_if = "Option::is_none")]
    pub tka_info: Option<TkaInfo>,
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
            ssh_policy: None,
            tka_info: None,
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
    /// skipped if empty to avoid sending "discokey:" which clients can't parse.
    #[serde(default, skip_serializing_if = "DiscoKey::is_empty")]
    pub disco_key: DiscoKey,

    /// assigned addresses.
    pub addresses: Vec<String>,

    /// allowed ips (addresses + routes).
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<String>,

    /// network endpoints.
    pub endpoints: Vec<String>,

    /// preferred derp region (legacy string format "127.3.3.40:n").
    /// deprecated: use home_derp instead.
    #[serde(rename = "DERP", default, skip_serializing_if = "String::is_empty")]
    pub derp: String,

    /// home derp region id (modern integer format).
    /// NOTE: json field is "homederp" (all caps derp) per go struct.
    #[serde(rename = "HomeDERP", default, skip_serializing_if = "is_zero")]
    pub home_derp: i32,

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

    /// tka signature for this node's key.
    ///
    /// this is the serialized NodeKeySignature that proves this node's
    /// key was signed by a trusted tka key.
    #[serde(default, skip_serializing_if = "MarshaledSignature::is_empty")]
    pub key_signature: MarshaledSignature,

    /// whether the node is expired.
    #[serde(default)]
    pub expired: bool,

    /// user id that owns this node.
    pub user: u64,

    /// whether this node's machine is authorized.
    /// defaults to false if not present.
    #[serde(default)]
    pub machine_authorized: bool,
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DerpMap {
    /// derp regions.
    pub regions: std::collections::HashMap<i32, DerpRegion>,

    /// whether to omit tailscale's default regions.
    /// NOTE: this uses camelcase (not pascalcase) per tailscale's go struct tag.
    #[serde(rename = "omitDefaultRegions", default)]
    pub omit_default_regions: bool,
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

    /// optional certificate fingerprint or dns name to pin.
    #[serde(rename = "CertName", default, skip_serializing_if = "Option::is_none")]
    pub cert_name: Option<String>,

    /// allow skipping tls verification (tests only).
    #[serde(rename = "InsecureForTests", default)]
    pub insecure_for_tests: bool,
}

/// a packet filter rule (simplified).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct FilterRule {
    /// source cidrs.
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,

    /// destination ports.
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
    /// create a port range for a single port.
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid 32-byte key data
    fn valid_key_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 32)
    }

    // strategy for maprequest
    fn map_request_strategy() -> impl Strategy<Value = MapRequest> {
        (
            any::<u32>(),                      // version
            valid_key_bytes(),                 // node_key
            any::<bool>(),                     // omit_peers
            any::<bool>(),                     // stream
            prop::collection::vec(".*", 0..3), // debug_flags
        )
            .prop_map(
                |(version, node_key_bytes, omit_peers, stream, debug_flags)| MapRequest {
                    version: CapabilityVersion(version),
                    node_key: NodeKey::from_bytes(node_key_bytes),
                    disco_key: None,
                    endpoints: vec![],
                    hostinfo: None,
                    omit_peers,
                    stream,
                    debug_flags,
                    compress: None,
                },
            )
    }

    // strategy for portrange
    fn port_range_strategy() -> impl Strategy<Value = PortRange> {
        (any::<u16>(), any::<u16>()).prop_map(|(first, last)| {
            let (first, last) = if first <= last {
                (first, last)
            } else {
                (last, first)
            };
            PortRange { first, last }
        })
    }

    // strategy for filterrule
    fn filter_rule_strategy() -> impl Strategy<Value = FilterRule> {
        (
            prop::collection::vec(
                "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/[0-9]{1,2}",
                0..3,
            ),
            prop::collection::vec(
                (
                    "[*]|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
                    port_range_strategy(),
                ),
                0..3,
            ),
        )
            .prop_map(|(src_ips, dst_ports)| FilterRule {
                src_ips,
                dst_ports: dst_ports
                    .into_iter()
                    .map(|(ip, ports)| NetPortRange { ip, ports })
                    .collect(),
            })
    }

    // strategy for mapresponse
    fn map_response_strategy() -> impl Strategy<Value = MapResponse> {
        (
            any::<bool>(),                                       // keep_alive
            prop::collection::vec(filter_rule_strategy(), 0..3), // packet_filter
        )
            .prop_map(|(keep_alive, packet_filter)| MapResponse {
                keep_alive,
                node: None,
                peers: vec![],
                dns_config: None,
                derp_map: None,
                packet_filter,
                user_profiles: vec![],
                control_time: None,
                ssh_policy: None,
                tka_info: None,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn map_request_serde_roundtrips(req in map_request_strategy()) {
            let json = serde_json::to_string(&req).unwrap();
            let parsed: MapRequest = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(req.version.0, parsed.version.0);
            prop_assert_eq!(req.omit_peers, parsed.omit_peers);
            prop_assert_eq!(req.stream, parsed.stream);
            prop_assert_eq!(req.debug_flags, parsed.debug_flags);
        }

        #[test]
        fn map_response_serde_roundtrips(resp in map_response_strategy()) {
            let json = serde_json::to_string(&resp).unwrap();
            let parsed: MapResponse = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(resp.keep_alive, parsed.keep_alive);
            prop_assert_eq!(resp.packet_filter.len(), parsed.packet_filter.len());
        }

        #[test]
        fn port_range_serde_roundtrips(pr in port_range_strategy()) {
            let json = serde_json::to_string(&pr).unwrap();
            let parsed: PortRange = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(pr.first, parsed.first);
            prop_assert_eq!(pr.last, parsed.last);
        }

        #[test]
        fn port_range_single_correct(port in any::<u16>()) {
            let pr = PortRange::single(port);
            prop_assert_eq!(pr.first, port);
            prop_assert_eq!(pr.last, port);
        }

        #[test]
        fn port_range_any_covers_all(_: ()) {
            let pr = PortRange::any();
            prop_assert_eq!(pr.first, 0);
            prop_assert_eq!(pr.last, 65535);
        }

        #[test]
        fn filter_rule_serde_roundtrips(rule in filter_rule_strategy()) {
            let json = serde_json::to_string(&rule).unwrap();
            let parsed: FilterRule = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(rule.src_ips, parsed.src_ips);
            prop_assert_eq!(rule.dst_ports.len(), parsed.dst_ports.len());
        }

        #[test]
        fn arbitrary_json_object_does_not_panic(
            keep_alive in any::<bool>(),
            version in any::<i32>(),
        ) {
            // well-formed json with various field combinations shouldn't panic
            let json = format!(
                r#"{{"KeepAlive": {}, "Version": {}, "Peers": []}}"#,
                keep_alive, version
            );
            let result: Result<MapResponse, _> = serde_json::from_str(&json);
            // should either succeed or fail gracefully (no panic)
            let _ = result;
        }

        #[test]
        fn map_request_is_read_only_correct(req in map_request_strategy()) {
            let expected = req.endpoints.is_empty() && req.hostinfo.is_none();
            prop_assert_eq!(req.is_read_only(), expected);
        }
    }
}
