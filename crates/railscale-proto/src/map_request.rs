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

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

use railscale_tka::MarshaledSignature;
use railscale_types::{DiscoKey, HostInfo, MachineKey, NodeKey};

use crate::CapabilityVersion;
use crate::ssh::SshPolicy;
use crate::tka::TkaInfo;

/// node capability for file sharing (taildrop).
///
/// when present in a node's CapMap, enables same-user file sharing between
/// devices. the tailscale client checks `self.CapMap().Contains(CapabilityFileSharing)`
/// to determine if taildrop is available.
///
/// note: the tailscale client also supports cross-user file sharing via peer
/// capabilities (PeerCapabilityFileSharingTarget, PeerCapabilityFileSharingSend)
/// granted through CapGrant on FilterRules. the client checks:
/// - IsSelfUntagged(): both sender/receiver untagged + same user
/// - OR PeerHasCap(PeerCapabilityFileSharingTarget) for cross-user
///
/// same-user sharing works automatically. cross-user sharing requires an
/// explicit grant with `cap/file-sharing-target` app capability in the policy,
/// emitted as CapGrant on FilterRule
pub const CAP_FILE_SHARING: &str = "https://tailscale.com/cap/file-sharing";

/// node capability enabling ssh environment variable forwarding.
///
/// when present, the client's ssh server will filter client-proposed env vars
/// through the AcceptEnv patterns on matching SSH rules
pub const CAP_SSH_ENV_VARS: &str = "ssh-env-vars";

// -- peer capabilities (for FilterRule.CapGrant) --

/// peer can receive files via taildrop
pub const PEER_CAP_FILE_SHARING_TARGET: &str = "https://tailscale.com/cap/file-sharing-target";

/// peer can send files via taildrop
pub const PEER_CAP_FILE_SEND: &str = "https://tailscale.com/cap/file-send";

/// peer can be debugged
pub const PEER_CAP_DEBUG_PEER: &str = "https://tailscale.com/cap/debug-peer";

/// peer can use wake-on-lan
pub const PEER_CAP_WAKE_ON_LAN: &str = "https://tailscale.com/cap/wake-on-lan";

/// peer can accept ingress traffic
pub const PEER_CAP_INGRESS: &str = "https://tailscale.com/cap/ingress";

// -- node capabilities (for self node CapMap) --

/// node capability for app connectors.
///
/// when present in a node's CapMap, the value is a list of `AppConnectorAttr`
/// that tells the client which domains to proxy and which routes to advertise
pub const CAP_APP_CONNECTORS: &str = "tailscale.com/app-connectors";

/// node capability telling the client to persist app connector routes across restarts
pub const CAP_STORE_APPC_ROUTES: &str = "store-appc-routes";

/// node capability enabling wildcard DNS resolution and wildcard certs
///
/// when set on a node (via nodeAttrs), the tailscale client will:
/// - resolve subdomains of that node's MagicDNS name to the node's IPs
/// - allow `tailscale cert *.hostname.base_domain` for wildcard TLS certs
pub const CAP_DNS_SUBDOMAIN_RESOLVE: &str = "dns-subdomain-resolve";

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
/// supports both full and delta-encoded responses for streaming sessions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse {
    /// opaque handle identifying this streaming session.
    /// only sent on the first response in a stream. clients use this
    /// in MapRequest.MapSessionHandle to resume after reconnect.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,

    /// sequence number within a named map session. used by clients
    /// in MapRequest.MapSessionSeq to resume after a given message.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub seq: i64,

    /// whether to keep the connection alive for streaming updates.
    pub keep_alive: bool,

    /// the node's own information.
    pub node: Option<MapResponseNode>,

    /// complete list of peer nodes (full sync).
    /// when non-empty, PeersChanged/PeersRemoved/PeersChangedPatch are ignored.
    pub peers: Vec<MapResponseNode>,

    /// nodes that have changed or been added since the last update.
    /// used for delta encoding when Peers is empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed: Vec<MapResponseNode>,

    /// node IDs that are no longer in the peer list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_removed: Vec<u64>,

    /// lightweight peer mutations (online, derp, endpoints, keys).
    /// applied after PeersChanged/PeersRemoved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed_patch: Vec<PeerChange>,

    /// online status changes. key is NodeID, value is new online state.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub peer_seen_change: std::collections::HashMap<u64, bool>,

    /// online status changes (lighter than PeersChangedPatch).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub online_change: std::collections::HashMap<u64, bool>,

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

    /// tailnet domain name.
    ///
    /// used by clients for display and MagicDNS FQDN construction.
    /// e.g. "example.com" or "user@gmail.com".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,

    /// debug settings from control server.
    /// used by headscale to disable logtail, or to throttle spinning clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<DebugSettings>,

    /// health warnings from control plane.
    ///
    /// nil means no change. non-nil zero-length slice restores health to good.
    /// non-zero length slice is the list of problems the control plane sees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Vec<String>>,
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

impl MapResponse {
    /// create an empty keepalive response.
    pub fn keepalive() -> Self {
        Self {
            keep_alive: true,
            ..Default::default()
        }
    }
}

/// lightweight peer mutation for delta map responses.
///
/// only fields that changed are set; absent (None/zero) fields mean no change.
/// matches tailscale's `tailcfg.PeerChange`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PeerChange {
    /// node ID being mutated.
    #[serde(rename = "NodeID")]
    pub node_id: u64,

    /// new home DERP region (0 means no change).
    #[serde(
        rename = "DERPRegion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub derp_region: Option<i32>,

    /// new capability version (0 means no change).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<u32>,

    /// new capability map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_map: Option<std::collections::HashMap<String, Vec<serde_json::Value>>>,

    /// new UDP endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<std::net::SocketAddr>>,

    /// new wireguard public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<NodeKey>,

    /// new disco key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<DiscoKey>,

    /// new online status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,

    /// new last-seen time (RFC3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,

    /// new key expiry (RFC3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,

    /// new TKA key signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_signature: Option<MarshaledSignature>,
}

/// debug settings sent from control server to clients.
///
/// matches tailscale's `tailcfg.Debug`. used by headscale to disable
/// logtail, or as a safety measure to throttle spinning clients.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DebugSettings {
    /// request that the client sleep for this many seconds.
    /// the client can (and should) clamp the value (e.g. max 5 minutes).
    /// exists as a safety measure to slow down spinning clients.
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub sleep_seconds: f64,

    /// disable the logtail package. once disabled it can't be re-enabled.
    /// primarily used by headscale.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_log_tail: bool,

    /// request that the client exit with this code.
    /// safety measure in case a client is crash-looping or in an unsafe state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
}

fn is_zero_f64(n: &f64) -> bool {
    *n == 0.0
}

fn is_false(b: &bool) -> bool {
    !*b
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

    /// capability version of this node.
    ///
    /// tells peers what protocol features this node supports.
    /// zero means unknown (old server didn't send it).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cap: u32,

    /// node capability map.
    ///
    /// maps capability URLs to optional parameter arrays. capabilities with no
    /// params use an empty array. example:
    /// ```json
    /// {"https://tailscale.com/cap/file-sharing": []}
    /// ```
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_map: Option<std::collections::HashMap<String, Vec<serde_json::Value>>>,
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

    /// FQDNs for which the control plane will provision TLS certs via dns-01 ACME.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_domains: Vec<String>,
}

/// request from a node to update its posture attributes.
///
/// sent by the tailscale client to `/machine/set-device-attr` as a PATCH
/// over the noise transport. attributes not in the map are left unchanged.
/// a null value deletes the attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetDeviceAttributesRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// node key identifying the requesting node.
    pub node_key: NodeKey,

    /// map of posture attributes to update.
    /// values can be string, number, bool, or null (to delete).
    pub update: std::collections::HashMap<String, serde_json::Value>,
}

/// request from a node to set a dns record (used for ACME dns-01 challenges).
///
/// sent by the tailscale client to `/machine/set-dns` over the noise transport.
/// the control server creates the specified record in public DNS so that
/// let's encrypt can verify domain ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetDNSRequest {
    /// client capability version.
    pub version: CapabilityVersion,

    /// the requesting node's current node key.
    pub node_key: NodeKey,

    /// dns record name, e.g. "_acme-challenge.mynode.tail.example.com".
    pub name: String,

    /// dns record type, typically "TXT".
    #[serde(rename = "Type")]
    pub record_type: String,

    /// dns record value (the ACME challenge token).
    pub value: String,
}

/// response to a SetDNSRequest. empty on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetDNSResponse {}

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

/// a packet filter rule.
///
/// `dst_ports` and `cap_grant` are mutually exclusive: a rule is either
/// network-level (ports) or application-level (capabilities), never both.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct FilterRule {
    /// source cidrs (or "*" for all).
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,

    /// destination port ranges. mutually exclusive with cap_grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_ports: Vec<NetPortRange>,

    /// ip protocol numbers to match.
    ///
    /// empty means tcp, udp, and icmp (the client default).
    /// when a specific protocol is set (e.g. icmp only), contains those
    /// iana protocol numbers. icmp includes both v4 (1) and v6 (58).
    #[serde(rename = "IPProto", default, skip_serializing_if = "Vec::is_empty")]
    pub ip_proto: Vec<i32>,

    /// application capability grants. mutually exclusive with dst_ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_grant: Vec<CapGrant>,
}

/// grants application-level capabilities from src to dst IPs.
///
/// used for taildrop (file sharing), app connectors, ingress, etc.
/// the capabilities are opaque URLs resolved at runtime by the client
/// via the WhoIs API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct CapGrant {
    /// destination IP prefixes this grant applies to.
    pub dsts: Vec<String>,

    /// capability map: capability URL -> list of opaque json values.
    ///
    /// preferred over the deprecated `caps` field.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub cap_map: std::collections::HashMap<String, Vec<serde_json::Value>>,
}

/// app connector configuration sent to nodes via CapMap.
///
/// tells the client which domains to intercept DNS for and proxy,
/// and which routes to pre-advertise. matches tailscale's
/// `appctype.AppConnectorAttr`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppConnectorAttr {
    /// name of this app connector configuration
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,

    /// domain names to intercept (e.g. "example.com", "*.example.com")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,

    /// pre-configured route prefixes (e.g. "192.0.2.0/24")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,

    /// selectors for which nodes act as connectors (e.g. "tag:connector", "*")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connectors: Vec<String>,
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
mod set_dns_tests {
    use super::*;

    #[test]
    fn set_dns_request_serde_roundtrip() {
        let req = SetDNSRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![1u8; 32]),
            name: "_acme-challenge.mynode.tail.example.com".to_string(),
            record_type: "TXT".to_string(),
            value: "abc123-challenge-token".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: SetDNSRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version.0, 106);
        assert_eq!(parsed.name, "_acme-challenge.mynode.tail.example.com");
        assert_eq!(parsed.record_type, "TXT");
        assert_eq!(parsed.value, "abc123-challenge-token");
    }

    #[test]
    fn set_dns_request_uses_pascal_case() {
        let req = SetDNSRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![1u8; 32]),
            name: "_acme-challenge.test.example.com".to_string(),
            record_type: "TXT".to_string(),
            value: "token".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"Version\""),
            "expected PascalCase Version: {json}"
        );
        assert!(
            json.contains("\"NodeKey\""),
            "expected PascalCase NodeKey: {json}"
        );
        assert!(
            json.contains("\"Name\""),
            "expected PascalCase Name: {json}"
        );
        assert!(
            json.contains("\"Type\""),
            "expected PascalCase Type: {json}"
        );
        assert!(
            json.contains("\"Value\""),
            "expected PascalCase Value: {json}"
        );
    }

    #[test]
    fn set_dns_response_is_empty_json_object() {
        let resp = SetDNSResponse {};
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn dns_config_cert_domains_roundtrip() {
        let config = DnsConfig {
            resolvers: vec![],
            domains: vec![],
            routes: Default::default(),
            cert_domains: vec![
                "mynode.tail.example.com".to_string(),
                "other.tail.example.com".to_string(),
            ],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains("\"CertDomains\""),
            "expected CertDomains field: {json}"
        );

        let parsed: DnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cert_domains.len(), 2);
        assert_eq!(parsed.cert_domains[0], "mynode.tail.example.com");
    }

    #[test]
    fn dns_config_cert_domains_omitted_when_empty() {
        let config = DnsConfig {
            resolvers: vec![],
            domains: vec![],
            routes: Default::default(),
            cert_domains: vec![],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(
            !json.contains("CertDomains"),
            "empty cert_domains should be omitted: {json}"
        );
    }

    #[test]
    fn set_dns_request_from_tailscale_json() {
        // simulate what a real tailscale client sends
        let json = r#"{
            "Version": 131,
            "NodeKey": "nodekey:0101010101010101010101010101010101010101010101010101010101010101",
            "Name": "_acme-challenge.mynode.tail.example.com",
            "Type": "TXT",
            "Value": "dGVzdC1jaGFsbGVuZ2UtdmFsdWU"
        }"#;

        let req: SetDNSRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.version.0, 131);
        assert_eq!(req.name, "_acme-challenge.mynode.tail.example.com");
        assert_eq!(req.record_type, "TXT");
        assert_eq!(req.value, "dGVzdC1jaGFsbGVuZ2UtdmFsdWU");
    }
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
                ip_proto: vec![],
                cap_grant: vec![],
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
                packet_filter,
                ..Default::default()
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

    #[test]
    fn cap_map_serialises_as_pascal_case() {
        use std::collections::HashMap;

        let mut cap_map = HashMap::new();
        cap_map.insert(CAP_FILE_SHARING.to_string(), vec![]);

        let node = MapResponseNode {
            cap_map: Some(cap_map),
            ..Default::default()
        };

        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("CapMap"), "expected CapMap in json: {}", json);
        assert!(
            json.contains(CAP_FILE_SHARING),
            "expected capability in json: {}",
            json
        );
    }

    #[test]
    fn cap_map_empty_vec_serialises_correctly() {
        // tailscale uses empty arrays for capabilities with no params
        // e.g. {"https://tailscale.com/cap/file-sharing": []}
        use std::collections::HashMap;

        let mut cap_map = HashMap::new();
        cap_map.insert(CAP_FILE_SHARING.to_string(), vec![]);

        let node = MapResponseNode {
            cap_map: Some(cap_map),
            ..Default::default()
        };

        let json = serde_json::to_string(&node).unwrap();
        // should contain the capability with empty array
        assert!(
            json.contains(r#""https://tailscale.com/cap/file-sharing":[]"#),
            "expected empty array for capability: {}",
            json
        );
    }

    #[test]
    fn cap_map_none_omitted_from_json() {
        let node = MapResponseNode {
            cap_map: None,
            ..Default::default()
        };

        let json = serde_json::to_string(&node).unwrap();
        assert!(
            !json.contains("CapMap"),
            "expected CapMap to be omitted: {}",
            json
        );
    }

    #[test]
    fn cap_map_roundtrips() {
        use std::collections::HashMap;

        let mut cap_map = HashMap::new();
        cap_map.insert(CAP_FILE_SHARING.to_string(), vec![]);

        let node = MapResponseNode {
            id: 123,
            stable_id: "stable123".to_string(),
            name: "test-node".to_string(),
            node_key: NodeKey::from_bytes(vec![1u8; 32]),
            machine_key: MachineKey::from_bytes(vec![2u8; 32]),
            disco_key: DiscoKey::from_bytes(vec![3u8; 32]),
            addresses: vec!["100.64.0.1".to_string()],
            allowed_ips: vec!["100.64.0.1/32".to_string()],
            endpoints: vec![],
            derp: String::new(),
            home_derp: 1,
            hostinfo: None,
            online: Some(true),
            tags: vec![],
            primary_routes: vec![],
            key_expiry: None,
            key_signature: Default::default(),
            expired: false,
            user: 1,
            machine_authorized: true,
            cap: 106,
            cap_map: Some(cap_map),
        };

        let json = serde_json::to_string(&node).unwrap();
        let parsed: MapResponseNode = serde_json::from_str(&json).unwrap();

        assert!(parsed.cap_map.is_some());
        let parsed_cap_map = parsed.cap_map.unwrap();
        assert!(parsed_cap_map.contains_key(CAP_FILE_SHARING));
        assert_eq!(parsed.cap, 106);
    }

    #[test]
    fn cap_grant_serialises_as_pascal_case() {
        use std::collections::HashMap;

        let mut cap_map = HashMap::new();
        cap_map.insert(PEER_CAP_FILE_SHARING_TARGET.to_string(), vec![]);

        let grant = CapGrant {
            dsts: vec!["100.64.0.0/10".to_string()],
            cap_map,
        };

        let json = serde_json::to_string(&grant).unwrap();
        assert!(json.contains("\"Dsts\""), "expected Dsts: {}", json);
        assert!(json.contains("\"CapMap\""), "expected CapMap: {}", json);
        assert!(
            json.contains(PEER_CAP_FILE_SHARING_TARGET),
            "expected peer cap: {}",
            json
        );
    }

    #[test]
    fn cap_grant_roundtrips() {
        use std::collections::HashMap;

        let mut cap_map = HashMap::new();
        cap_map.insert(
            PEER_CAP_FILE_SHARING_TARGET.to_string(),
            vec![serde_json::json!({"maxSize": 1073741824})],
        );

        let grant = CapGrant {
            dsts: vec![
                "100.64.0.1/32".to_string(),
                "fd7a:115c:a1e0::1/128".to_string(),
            ],
            cap_map,
        };

        let json = serde_json::to_string(&grant).unwrap();
        let parsed: CapGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, parsed);
    }

    #[test]
    fn filter_rule_with_cap_grant_omits_dst_ports() {
        use std::collections::HashMap;

        let mut cap_map = HashMap::new();
        cap_map.insert(PEER_CAP_FILE_SHARING_TARGET.to_string(), vec![]);

        let rule = FilterRule {
            src_ips: vec!["*".to_string()],
            dst_ports: vec![],
            ip_proto: vec![],
            cap_grant: vec![CapGrant {
                dsts: vec!["100.64.0.0/10".to_string()],
                cap_map,
            }],
        };

        let json = serde_json::to_string(&rule).unwrap();
        // dst_ports should be omitted (empty), cap_grant should be present
        assert!(
            !json.contains("DstPorts"),
            "DstPorts should be omitted: {}",
            json
        );
        assert!(
            json.contains("CapGrant"),
            "CapGrant should be present: {}",
            json
        );
    }

    #[test]
    fn app_connector_attr_serialises_as_camel_case() {
        let attr = AppConnectorAttr {
            name: "github".to_string(),
            domains: vec!["github.com".to_string(), "*.github.com".to_string()],
            routes: vec!["192.0.2.0/24".to_string()],
            connectors: vec!["tag:connector".to_string()],
        };

        let json = serde_json::to_string(&attr).unwrap();
        // tailscale uses camelCase for AppConnectorAttr
        assert!(json.contains("\"name\""), "expected name: {}", json);
        assert!(json.contains("\"domains\""), "expected domains: {}", json);
        assert!(json.contains("\"routes\""), "expected routes: {}", json);
        assert!(
            json.contains("\"connectors\""),
            "expected connectors: {}",
            json
        );
    }

    #[test]
    fn app_connector_attr_roundtrips() {
        let attr = AppConnectorAttr {
            name: "example-app".to_string(),
            domains: vec!["example.com".to_string()],
            routes: vec![],
            connectors: vec!["tag:example-connector".to_string()],
        };

        let json = serde_json::to_string(&attr).unwrap();
        let parsed: AppConnectorAttr = serde_json::from_str(&json).unwrap();
        assert_eq!(attr, parsed);
    }

    #[test]
    fn app_connector_attr_omits_empty_fields() {
        let attr = AppConnectorAttr {
            name: "minimal".to_string(),
            domains: vec!["example.com".to_string()],
            routes: vec![],
            connectors: vec![],
        };

        let json = serde_json::to_string(&attr).unwrap();
        assert!(
            !json.contains("routes"),
            "routes should be omitted: {}",
            json
        );
        assert!(
            !json.contains("connectors"),
            "connectors should be omitted: {}",
            json
        );
    }

    #[test]
    fn app_connector_attr_in_cap_map() {
        // verify AppConnectorAttr can be serialised into a CapMap value
        let attrs = vec![AppConnectorAttr {
            name: "github".to_string(),
            domains: vec!["github.com".to_string()],
            routes: vec![],
            connectors: vec!["tag:connector".to_string()],
        }];

        let cap_value = serde_json::to_value(&attrs).unwrap();

        let mut cap_map = std::collections::HashMap::new();
        cap_map.insert(CAP_APP_CONNECTORS.to_string(), vec![cap_value]);

        let json = serde_json::to_string(&cap_map).unwrap();
        assert!(json.contains("tailscale.com/app-connectors"));
        assert!(json.contains("github.com"));
    }

    #[test]
    fn filter_rule_with_dst_ports_omits_cap_grant() {
        let rule = FilterRule {
            src_ips: vec!["100.64.0.1".to_string()],
            dst_ports: vec![NetPortRange {
                ip: "100.64.0.2".to_string(),
                ports: PortRange::single(443),
            }],
            ip_proto: vec![],
            cap_grant: vec![],
        };

        let json = serde_json::to_string(&rule).unwrap();
        assert!(
            json.contains("DstPorts"),
            "DstPorts should be present: {}",
            json
        );
        assert!(
            !json.contains("CapGrant"),
            "CapGrant should be omitted: {}",
            json
        );
    }

    #[test]
    fn test_dns_subdomain_resolve_capability_value() {
        // must match the tailscale NodeAttrDNSSubdomainResolve constant
        assert_eq!(super::CAP_DNS_SUBDOMAIN_RESOLVE, "dns-subdomain-resolve");
    }
}

#[cfg(test)]
mod delta_tests {
    use super::*;

    #[test]
    fn peer_change_serialises_with_pascal_case() {
        let pc = PeerChange {
            node_id: 42,
            derp_region: Some(1),
            online: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_string(&pc).unwrap();
        assert!(json.contains("\"NodeID\":42"), "expected NodeID: {json}");
        assert!(
            json.contains("\"DERPRegion\":1"),
            "expected DERPRegion: {json}"
        );
        assert!(json.contains("\"Online\":true"), "expected Online: {json}");
    }

    #[test]
    fn peer_change_omits_none_fields() {
        let pc = PeerChange {
            node_id: 1,
            ..Default::default()
        };
        let json = serde_json::to_string(&pc).unwrap();
        assert!(
            !json.contains("DERPRegion"),
            "DERPRegion should be omitted: {json}"
        );
        assert!(!json.contains("Online"), "Online should be omitted: {json}");
        assert!(
            !json.contains("Endpoints"),
            "Endpoints should be omitted: {json}"
        );
        assert!(!json.contains("Key"), "Key should be omitted: {json}");
        assert!(
            !json.contains("DiscoKey"),
            "DiscoKey should be omitted: {json}"
        );
        assert!(
            !json.contains("KeyExpiry"),
            "KeyExpiry should be omitted: {json}"
        );
        assert!(
            !json.contains("KeySignature"),
            "KeySignature should be omitted: {json}"
        );
        assert!(!json.contains("Cap\""), "Cap should be omitted: {json}");
        assert!(!json.contains("CapMap"), "CapMap should be omitted: {json}");
        assert!(
            !json.contains("LastSeen"),
            "LastSeen should be omitted: {json}"
        );
    }

    #[test]
    fn peer_change_roundtrips() {
        let pc = PeerChange {
            node_id: 99,
            derp_region: Some(3),
            cap: Some(106),
            endpoints: Some(vec!["1.2.3.4:5678".parse().unwrap()]),
            key: Some(NodeKey::from_bytes(vec![0xAA; 32])),
            disco_key: Some(DiscoKey::from_bytes(vec![0xBB; 32])),
            online: Some(false),
            last_seen: Some("2026-01-01T00:00:00Z".to_string()),
            key_expiry: Some("2027-01-01T00:00:00Z".to_string()),
            key_signature: Some(MarshaledSignature::from(vec![0xCC; 8])),
            cap_map: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("test-cap".to_string(), vec![]);
                m
            }),
        };
        let json = serde_json::to_string(&pc).unwrap();
        let parsed: PeerChange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.node_id, 99);
        assert_eq!(parsed.derp_region, Some(3));
        assert_eq!(parsed.cap, Some(106));
        assert_eq!(parsed.online, Some(false));
    }

    #[test]
    fn map_response_delta_fields_serialise() {
        let resp = MapResponse {
            peers_changed: vec![MapResponseNode {
                id: 10,
                name: "changed-node".to_string(),
                ..Default::default()
            }],
            peers_removed: vec![20, 30],
            peers_changed_patch: vec![PeerChange {
                node_id: 40,
                online: Some(true),
                ..Default::default()
            }],
            online_change: {
                let mut m = std::collections::HashMap::new();
                m.insert(50, true);
                m.insert(60, false);
                m
            },
            peer_seen_change: {
                let mut m = std::collections::HashMap::new();
                m.insert(70, true);
                m
            },
            map_session_handle: "session-abc".to_string(),
            seq: 5,
            ..Default::default()
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("PeersChanged"),
            "expected PeersChanged: {json}"
        );
        assert!(
            json.contains("PeersRemoved"),
            "expected PeersRemoved: {json}"
        );
        assert!(
            json.contains("PeersChangedPatch"),
            "expected PeersChangedPatch: {json}"
        );
        assert!(
            json.contains("OnlineChange"),
            "expected OnlineChange: {json}"
        );
        assert!(
            json.contains("PeerSeenChange"),
            "expected PeerSeenChange: {json}"
        );
        assert!(
            json.contains("MapSessionHandle"),
            "expected MapSessionHandle: {json}"
        );
        assert!(json.contains("\"Seq\":5"), "expected Seq: {json}");
    }

    #[test]
    fn debug_settings_serialises_with_pascal_case() {
        let debug = DebugSettings {
            sleep_seconds: 5.0,
            disable_log_tail: true,
            exit: None,
        };
        let json = serde_json::to_string(&debug).unwrap();
        assert!(
            json.contains("\"SleepSeconds\":5"),
            "expected SleepSeconds: {json}"
        );
        assert!(
            json.contains("\"DisableLogTail\":true"),
            "expected DisableLogTail: {json}"
        );
        assert!(
            !json.contains("Exit"),
            "Exit should be omitted when None: {json}"
        );
    }

    #[test]
    fn debug_settings_omits_default_fields() {
        let debug = DebugSettings::default();
        let json = serde_json::to_string(&debug).unwrap();
        assert_eq!(json, "{}", "default debug should be empty: {json}");
    }

    #[test]
    fn health_on_map_response_present_when_set() {
        let resp = MapResponse {
            health: Some(vec!["your key expires soon".to_string()]),
            ..Default::default()
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"Health\""), "expected Health: {json}");
        assert!(
            json.contains("your key expires soon"),
            "expected warning: {json}"
        );
    }

    #[test]
    fn health_omitted_when_none() {
        let resp = MapResponse::keepalive();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("Health"), "Health should be omitted: {json}");
    }

    #[test]
    fn health_empty_vec_means_all_clear() {
        let resp = MapResponse {
            health: Some(vec![]),
            ..Default::default()
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"Health\":[]"),
            "expected empty Health array: {json}"
        );
    }

    #[test]
    fn debug_settings_on_map_response() {
        let resp = MapResponse {
            debug: Some(DebugSettings {
                disable_log_tail: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"Debug\""), "expected Debug field: {json}");
        assert!(
            json.contains("DisableLogTail"),
            "expected DisableLogTail: {json}"
        );
    }

    #[test]
    fn debug_omitted_from_keepalive() {
        let resp = MapResponse::keepalive();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("Debug"),
            "Debug should be omitted from keepalive: {json}"
        );
    }

    #[test]
    fn set_device_attributes_request_roundtrips() {
        let mut update = std::collections::HashMap::new();
        update.insert("node:os".to_string(), serde_json::json!("linux"));
        update.insert("node:tsVersion".to_string(), serde_json::json!("1.80.0"));
        update.insert("custom:diskEncrypted".to_string(), serde_json::json!(true));
        update.insert("old:attr".to_string(), serde_json::Value::Null);

        let req = SetDeviceAttributesRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![1u8; 32]),
            update,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"Version\""), "expected PascalCase: {json}");
        assert!(json.contains("\"Update\""), "expected Update: {json}");
        assert!(json.contains("\"node:os\""), "expected attr key: {json}");

        let parsed: SetDeviceAttributesRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.update.len(), 4);
        assert_eq!(parsed.update["node:os"], serde_json::json!("linux"));
        assert!(parsed.update["old:attr"].is_null());
    }

    #[test]
    fn map_response_delta_fields_omitted_when_empty() {
        let resp = MapResponse::keepalive();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            !json.contains("PeersChanged"),
            "PeersChanged should be omitted: {json}"
        );
        assert!(
            !json.contains("PeersRemoved"),
            "PeersRemoved should be omitted: {json}"
        );
        assert!(
            !json.contains("PeersChangedPatch"),
            "PeersChangedPatch should be omitted: {json}"
        );
        assert!(
            !json.contains("OnlineChange"),
            "OnlineChange should be omitted: {json}"
        );
        assert!(
            !json.contains("PeerSeenChange"),
            "PeerSeenChange should be omitted: {json}"
        );
        assert!(
            !json.contains("MapSessionHandle"),
            "MapSessionHandle should be omitted: {json}"
        );
        assert!(!json.contains("\"Seq\""), "Seq should be omitted: {json}");
    }
}
