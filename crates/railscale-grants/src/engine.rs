//! the main grants evaluation engine.

use std::net::IpAddr;
use std::sync::Arc;

use railscale_proto::{
    CapGrant, FilterRule, NetPortRange, PortRange, SshAction, SshPolicy, SshPrincipal, SshRule,
};
use railscale_types::{Node, UserId};

use crate::capability::NetworkCapability;
use crate::geoip::GeoIpResolver;
use crate::grant::Grant;
use crate::policy::Policy;
use crate::posture::{PostureContext, PostureExpr};
use crate::selector::{Autogroup, Selector};
use crate::ssh::build_ssh_users_map;

/// trait for resolving user information during policy evaluation.
pub trait UserResolver {
    /// resolve a user id to an email/username.
    fn resolve_user(&self, user_id: &UserId) -> Option<String>;

    /// resolve a user id to a list of groups they belong to.
    fn resolve_groups(&self, user_id: &UserId) -> Vec<String>;
}

/// a no-op resolver for testing or when user info is not available.
pub struct EmptyResolver;

impl UserResolver for EmptyResolver {
    fn resolve_user(&self, _user_id: &UserId) -> Option<String> {
        None
    }

    fn resolve_groups(&self, _user_id: &UserId) -> Vec<String> {
        Vec::new()
    }
}

/// thread-safe grants evaluation engine.
///
/// wraps a policy in arc for cheap cloning and concurrent access.
/// all evaluation methods take &self, making it safe for use in
/// async handlers.
pub struct GrantsEngine {
    policy: Arc<Policy>,
}

impl GrantsEngine {
    /// create a new engine with the given policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }

    /// create an engine with an empty policy (deny all).
    pub fn empty() -> Self {
        Self::new(Policy::empty())
    }

    /// update the policy atomically.
    pub fn update_policy(&mut self, policy: Policy) {
        self.policy = Arc::new(policy);
    }

    /// get the current policy (for serialisation).
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// check if src_node can see dst_node.
    ///
    /// returns true if any grant allows src to access dst.
    pub fn can_see<R: UserResolver>(&self, src: &Node, dst: &Node, resolver: &R) -> bool {
        self.matching_grants::<R, crate::geoip::NoopGeoIpResolver>(src, dst, resolver, None, None)
            .any(|g| !g.ip.is_empty() || !g.app.is_empty())
    }

    /// check if src_node can see dst_node with geoip context.
    ///
    /// like `can_see` but includes client IP for geolocation-based posture checks.
    pub fn can_see_with_ip<R: UserResolver, G: GeoIpResolver>(
        &self,
        src: &Node,
        dst: &Node,
        resolver: &R,
        client_ip: Option<IpAddr>,
        geoip: &G,
    ) -> bool {
        self.matching_grants(src, dst, resolver, client_ip, Some(geoip))
            .any(|g| !g.ip.is_empty() || !g.app.is_empty())
    }

    /// get network capabilities that src has when accessing dst.
    ///
    /// returns the union of all `ip` fields from matching grants.
    pub fn get_network_capabilities<R: UserResolver>(
        &self,
        src: &Node,
        dst: &Node,
        resolver: &R,
    ) -> Vec<NetworkCapability> {
        let mut caps = Vec::new();
        for grant in self
            .matching_grants::<R, crate::geoip::NoopGeoIpResolver>(src, dst, resolver, None, None)
        {
            caps.extend(grant.ip.iter().cloned());
        }
        caps
    }

    /// get all visible peers for a node.
    ///
    /// returns nodes that `src` can see according to any grant.
    pub fn get_visible_peers<'a, R: UserResolver>(
        &self,
        src: &Node,
        all_nodes: &'a [Node],
        resolver: &R,
    ) -> Vec<&'a Node> {
        all_nodes
            .iter()
            .filter(|dst| dst.id != src.id && self.can_see(src, dst, resolver))
            .collect()
    }

    /// generate filter rules for the mapresponse.
    ///
    /// returns rules that define which peers can access this node and on which ports.
    pub fn generate_filter_rules<R: UserResolver>(
        &self,
        node: &Node,
        peers: &[Node],
        resolver: &R,
    ) -> Vec<FilterRule> {
        let mut rules = Vec::new();

        // for each peer that can access this node
        for peer in peers {
            let caps = self.get_network_capabilities(peer, node, resolver);
            if caps.is_empty() {
                continue;
            }

            // get source ips from peer
            let src_ips: Vec<String> = peer.ips().iter().map(|ip| ip.to_string()).collect();
            if src_ips.is_empty() {
                continue;
            }

            // convert capabilities to port ranges
            let dst_ports = self.capabilities_to_port_ranges(&caps, &node.ips());
            if dst_ports.is_empty() {
                continue;
            }

            rules.push(FilterRule {
                src_ips,
                dst_ports,
                cap_grant: vec![],
            });
        }

        rules
    }

    /// generate capability grant filter rules for the mapresponse.
    ///
    /// returns filter rules with `cap_grant` entries for peers that have
    /// application-level capabilities towards this node (e.g. taildrop,
    /// app connectors). these are separate from network-level port rules.
    pub fn generate_cap_grant_rules<R: UserResolver>(
        &self,
        node: &Node,
        peers: &[Node],
        resolver: &R,
    ) -> Vec<FilterRule> {
        let mut rules = Vec::new();

        for peer in peers {
            let app_caps = self.get_app_capabilities(peer, node, resolver);
            if app_caps.is_empty() {
                continue;
            }

            let src_ips: Vec<String> = peer.ips().iter().map(|ip| ip.to_string()).collect();
            if src_ips.is_empty() {
                continue;
            }

            // build dst prefixes from node's IPs
            let dsts: Vec<String> = node
                .ips()
                .iter()
                .map(|ip| match ip {
                    std::net::IpAddr::V4(_) => format!("{}/32", ip),
                    std::net::IpAddr::V6(_) => format!("{}/128", ip),
                })
                .collect();

            if dsts.is_empty() {
                continue;
            }

            // build cap_map from app capabilities
            let mut cap_map = std::collections::HashMap::new();
            for app_cap in &app_caps {
                cap_map.insert(app_cap.name.clone(), app_cap.params.clone());
            }

            rules.push(FilterRule {
                src_ips,
                dst_ports: vec![],
                cap_grant: vec![CapGrant { dsts, cap_map }],
            });
        }

        rules
    }

    /// get application capabilities that src has when accessing dst.
    ///
    /// returns the union of all `app` fields from matching grants.
    pub fn get_app_capabilities<R: UserResolver>(
        &self,
        src: &Node,
        dst: &Node,
        resolver: &R,
    ) -> Vec<crate::capability::AppCapability> {
        let mut caps = Vec::new();
        for grant in self
            .matching_grants::<R, crate::geoip::NoopGeoIpResolver>(src, dst, resolver, None, None)
        {
            caps.extend(grant.app.iter().cloned());
        }
        caps
    }

    /// generate taildrop (file-sharing) capability grant rules.
    ///
    /// same-user untagged peers always get file-sharing-target.
    /// cross-user peers get it only if there's an explicit app grant
    /// with `cap/file-sharing-target` in the policy.
    pub fn generate_taildrop_rules<R: UserResolver>(
        &self,
        node: &Node,
        all_nodes: &[Node],
        _resolver: &R,
    ) -> Vec<FilterRule> {
        // taildrop only applies to user-owned (untagged) nodes
        if node.is_tagged() || node.user_id.is_none() {
            return vec![];
        }
        let node_user = node.user_id.unwrap();

        // build dst prefixes from node's IPs
        let dsts: Vec<String> = node
            .ips()
            .iter()
            .map(|ip| match ip {
                std::net::IpAddr::V4(_) => format!("{}/32", ip),
                std::net::IpAddr::V6(_) => format!("{}/128", ip),
            })
            .collect();

        if dsts.is_empty() {
            return vec![];
        }

        // collect same-user peer IPs
        let mut src_ips = Vec::new();
        for peer in all_nodes {
            if peer.id == node.id || peer.is_tagged() {
                continue;
            }
            if peer.user_id == Some(node_user) {
                for ip in peer.ips() {
                    src_ips.push(ip.to_string());
                }
            }
        }

        if src_ips.is_empty() {
            return vec![];
        }

        let mut cap_map = std::collections::HashMap::new();
        cap_map.insert(
            railscale_proto::PEER_CAP_FILE_SHARING_TARGET.to_string(),
            vec![],
        );

        vec![FilterRule {
            src_ips,
            dst_ports: vec![],
            cap_grant: vec![CapGrant { dsts, cap_map }],
        }]
    }

    /// convert network capabilities to port ranges.
    fn capabilities_to_port_ranges(
        &self,
        caps: &[NetworkCapability],
        dst_ips: &[std::net::IpAddr],
    ) -> Vec<NetPortRange> {
        let mut port_ranges = Vec::new();

        for dst_ip in dst_ips {
            for cap in caps {
                match cap {
                    NetworkCapability::Wildcard => {
                        // all ports on all protocols (simplify to common protocols)
                        port_ranges.push(NetPortRange {
                            ip: dst_ip.to_string(),
                            ports: PortRange::any(),
                        });
                    }
                    NetworkCapability::Port(port) => {
                        port_ranges.push(NetPortRange {
                            ip: dst_ip.to_string(),
                            ports: PortRange::single(*port),
                        });
                    }
                    NetworkCapability::PortRange { start, end } => {
                        port_ranges.push(NetPortRange {
                            ip: dst_ip.to_string(),
                            ports: PortRange {
                                first: *start,
                                last: *end,
                            },
                        });
                    }
                    NetworkCapability::ProtocolPort { protocol: _, port } => {
                        // for now, ignore protocol distinction in filter rules
                        port_ranges.push(NetPortRange {
                            ip: dst_ip.to_string(),
                            ports: PortRange::single(*port),
                        });
                    }
                    NetworkCapability::ProtocolPortRange {
                        protocol: _,
                        start,
                        end,
                    } => {
                        port_ranges.push(NetPortRange {
                            ip: dst_ip.to_string(),
                            ports: PortRange {
                                first: *start,
                                last: *end,
                            },
                        });
                    }
                    NetworkCapability::ProtocolWildcard { protocol: _ } => {
                        // all ports for this protocol
                        port_ranges.push(NetPortRange {
                            ip: dst_ip.to_string(),
                            ports: PortRange::any(),
                        });
                    }
                }
            }
        }

        port_ranges
    }

    /// find all grants where src matches src selectors and dst matches dst selectors.
    fn matching_grants<'a, R: UserResolver, G: GeoIpResolver>(
        &'a self,
        src: &Node,
        dst: &Node,
        resolver: &R,
        client_ip: Option<IpAddr>,
        geoip: Option<&G>,
    ) -> impl Iterator<Item = &'a Grant> {
        let src_posture_ctx = self.build_posture_context(src, client_ip, geoip);
        self.policy.grants.iter().filter(move |grant| {
            self.node_matches_selectors(src, &grant.src, resolver, Some(dst))
                && self.node_matches_selectors(dst, &grant.dst, resolver, Some(src))
                && self.check_posture(grant, &src_posture_ctx)
        })
    }

    /// build a posture context from a node's hostinfo and custom attributes
    fn build_posture_context<G: GeoIpResolver>(
        &self,
        node: &Node,
        client_ip: Option<IpAddr>,
        geoip: Option<&G>,
    ) -> PostureContext {
        let mut ctx = PostureContext::new();

        // populate ip:country - prefer live geoip lookup, fall back to cached
        let country = if let (Some(ip), Some(resolver)) = (client_ip, geoip) {
            resolver.lookup_country(ip)
        } else {
            // use cached country from node's last connection
            node.last_seen_country.clone()
        };
        if let Some(country) = country {
            ctx.set("ip:country", country);
        }

        // populate node:* attributes from hostinfo
        if let Some(ref hostinfo) = node.hostinfo {
            if let Some(ref os) = hostinfo.os {
                ctx.set("node:os", os);
            }
            if let Some(ref os_version) = hostinfo.os_version {
                ctx.set("node:osVersion", os_version);
            }
            if let Some(ref ipn_version) = hostinfo.ipn_version {
                ctx.set("node:tsVersion", ipn_version);
            }
            // tsReleaseTrack - derive from version string
            if let Some(ref version) = hostinfo.ipn_version {
                let track = if version.contains("unstable") || version.contains("-") {
                    "unstable"
                } else {
                    "stable"
                };
                ctx.set("node:tsReleaseTrack", track);
            }
            // tsAutoUpdate - not available in hostinfo, skip for now
        }

        // populate custom:* attributes from posture_attributes
        for (key, value) in &node.posture_attributes {
            let attr_key = format!("custom:{}", key);
            // convert json value to string for comparison
            let str_value = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => continue, // skip null, arrays, objects
            };
            ctx.set(&attr_key, str_value);
        }

        ctx
    }

    /// check if a grant's posture conditions are satisfied
    fn check_posture(&self, grant: &Grant, ctx: &PostureContext) -> bool {
        // determine which postures to check
        let posture_names = if grant.src_posture.is_empty() {
            &self.policy.default_src_posture
        } else {
            &grant.src_posture
        };

        // if no postures defined, grant passes
        if posture_names.is_empty() {
            return true;
        }

        // OR semantics: any matching posture is sufficient
        posture_names.iter().any(|name| {
            if let Some(conditions) = self.policy.postures.get(name) {
                self.evaluate_posture_conditions(conditions, ctx)
            } else {
                false // undefined posture fails
            }
        })
    }

    /// evaluate a list of posture conditions (AND semantics)
    fn evaluate_posture_conditions(&self, conditions: &[String], ctx: &PostureContext) -> bool {
        conditions.iter().all(|condition| {
            if let Ok(expr) = condition.parse::<PostureExpr>() {
                expr.evaluate(ctx)
            } else {
                false // invalid expression fails
            }
        })
    }

    /// check if a node matches any of the given selectors.
    fn node_matches_selectors<R: UserResolver>(
        &self,
        node: &Node,
        selectors: &[Selector],
        resolver: &R,
        peer: Option<&Node>,
    ) -> bool {
        selectors
            .iter()
            .any(|s| self.node_matches_selector(node, s, resolver, peer))
    }

    /// check if a node matches a single selector.
    fn node_matches_selector<R: UserResolver>(
        &self,
        node: &Node,
        selector: &Selector,
        resolver: &R,
        peer: Option<&Node>,
    ) -> bool {
        match selector {
            Selector::Wildcard => true,
            Selector::Tag(tag) => node.has_tag(&format!("tag:{}", tag)),
            Selector::Autogroup(Autogroup::Tagged) => node.is_tagged(),
            Selector::Autogroup(Autogroup::Member) => !node.is_tagged(),
            Selector::Autogroup(Autogroup::SelfDevices) => {
                if let Some(peer) = peer {
                    // both nodes must be user-owned and have the same user id
                    !node.is_tagged()
                        && !peer.is_tagged()
                        && node.user_id.is_some()
                        && node.user_id == peer.user_id
                } else {
                    false
                }
            }
            Selector::Cidr(net) => {
                // check if any of node's ips are in the cidr
                node.ips().iter().any(|ip| net.contains(ip))
            }
            Selector::User(email) => node
                .user_id
                .and_then(|uid| resolver.resolve_user(&uid))
                .map(|user_email| user_email == *email)
                .unwrap_or(false),
            Selector::Group(group) => {
                if let Some(uid) = node.user_id {
                    return resolver.resolve_groups(&uid).iter().any(|g| g == group);
                }
                false
            }
            // other autogroups require role resolution (future)
            Selector::Autogroup(_) => false,
        }
    }

    /// compile ssh policy for a specific node
    ///
    /// returns the ssh policy that should be sent to this node in mapresponse
    /// tagged nodes receive no ssh policy (ssh only applies to user-owned devices)
    pub fn compile_ssh_policy<R: UserResolver>(
        &self,
        node: &Node,
        all_nodes: &[Node],
        resolver: &R,
    ) -> Option<SshPolicy> {
        // tagged nodes don't get ssh policies
        if node.is_tagged() {
            return None;
        }

        let mut rules = Vec::new();

        for ssh_rule in &self.policy.ssh {
            // parse destination selectors
            let dst_selectors: Vec<Selector> = ssh_rule
                .dst
                .iter()
                .filter_map(|s| Selector::parse(s).ok())
                .collect();

            // check if this node is in the destination set
            let has_self_dst = dst_selectors
                .iter()
                .any(|s| matches!(s, Selector::Autogroup(Autogroup::SelfDevices)));

            // for autogroup:self destinations, node must be untagged with a user_id
            // for other selectors, use normal matching
            let node_matches_dst = dst_selectors.iter().any(|selector| {
                match selector {
                    Selector::Autogroup(Autogroup::SelfDevices) => {
                        // node is a valid autogroup:self destination if it's untagged with user
                        !node.is_tagged() && node.user_id.is_some()
                    }
                    _ => self.node_matches_selector(node, selector, resolver, None),
                }
            });

            if !node_matches_dst {
                continue;
            }

            // parse source selectors
            let src_selectors: Vec<Selector> = ssh_rule
                .src
                .iter()
                .filter_map(|s| Selector::parse(s).ok())
                .collect();

            // find all source nodes that match
            let mut source_ips: Vec<String> = Vec::new();

            for src_node in all_nodes {
                if src_node.id == node.id {
                    continue; // Can't SSH to self
                }

                // for autogroup:self destinations, only same-user untagged nodes are sources
                if has_self_dst {
                    if src_node.is_tagged() || node.user_id != src_node.user_id {
                        continue;
                    }
                }

                // check if this source node matches any source selector
                let matches_src = src_selectors.iter().any(|selector| {
                    self.node_matches_selector(src_node, selector, resolver, Some(node))
                });

                if matches_src {
                    // add all ips from this source node
                    for ip in src_node.ips() {
                        source_ips.push(ip.to_string());
                    }
                }
            }

            if source_ips.is_empty() {
                continue; // No sources match, skip this rule
            }

            // build principals from source ips
            let principals: Vec<SshPrincipal> = source_ips
                .into_iter()
                .map(|ip| SshPrincipal {
                    node: None,
                    node_ip: Some(ip),
                    user_login: None,
                    any: None,
                })
                .collect();

            // build ssh users map
            let ssh_users = build_ssh_users_map(&ssh_rule.users);

            // build action
            let action = SshAction {
                message: None,
                reject: None,
                accept: Some(true),
                session_duration: ssh_rule.check_period,
                allow_agent_forwarding: Some(true),
                hold_and_delegate: None,
                allow_local_port_forwarding: Some(true),
                allow_remote_port_forwarding: Some(true),
                recorders: None,
                on_recording_failure: None,
            };

            rules.push(SshRule {
                rule_expires: None,
                principals,
                ssh_users,
                action,
                accept_env: ssh_rule.accept_env.clone(),
            });
        }

        if rules.is_empty() {
            None
        } else {
            Some(SshPolicy { rules })
        }
    }
}

impl Clone for GrantsEngine {
    fn clone(&self) -> Self {
        Self {
            policy: Arc::clone(&self.policy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Grant;
    use railscale_types::{UserId, test_utils::TestNodeBuilder};
    use std::collections::HashMap;

    struct MockResolver {
        users: HashMap<UserId, String>,
        groups: HashMap<UserId, Vec<String>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                users: HashMap::new(),
                groups: HashMap::new(),
            }
        }
    }

    impl UserResolver for MockResolver {
        fn resolve_user(&self, user_id: &UserId) -> Option<String> {
            self.users.get(user_id).cloned()
        }

        fn resolve_groups(&self, user_id: &UserId) -> Vec<String> {
            self.groups.get(user_id).cloned().unwrap_or_default()
        }
    }

    fn test_node(id: u64, tags: Vec<&str>) -> Node {
        let tags = tags.into_iter().filter_map(|t| t.parse().ok()).collect();
        TestNodeBuilder::new(id).with_tags(tags).build()
    }

    #[test]
    fn test_empty_policy_denies_all() {
        let engine = GrantsEngine::empty();
        let resolver = EmptyResolver;
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        assert!(!engine.can_see(&node1, &node2, &resolver));
        assert!(!engine.can_see(&node2, &node1, &resolver));
    }

    #[test]
    fn test_wildcard_grant_allows_all() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        assert!(engine.can_see(&node1, &node2, &resolver));
        assert!(engine.can_see(&node2, &node1, &resolver));
    }

    #[test]
    fn test_tag_grant_selective_access() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Tag("web".to_string())],
            dst: vec![Selector::Tag("database".to_string())],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let web_node = test_node(1, vec!["tag:web"]);
        let db_node = test_node(2, vec!["tag:database"]);
        let other_node = test_node(3, vec![]);

        // web can see database
        assert!(engine.can_see(&web_node, &db_node, &resolver));

        // database cannot see web (grant is directional)
        assert!(!engine.can_see(&db_node, &web_node, &resolver));

        // other node cannot see database
        assert!(!engine.can_see(&other_node, &db_node, &resolver));
    }

    #[test]
    fn test_autogroup_tagged() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Autogroup(Autogroup::Tagged)],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let tagged_node = test_node(1, vec!["tag:server"]);
        let user_node = test_node(2, vec![]);

        // user node can see tagged node
        assert!(engine.can_see(&user_node, &tagged_node, &resolver));

        // user node cannot see other user nodes (not tagged)
        assert!(!engine.can_see(&user_node, &user_node, &resolver));
    }

    #[test]
    fn test_cidr_selector() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Cidr("100.64.0.0/24".parse().unwrap())],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let node_in_range = test_node(1, vec![]);
        let mut node_out_of_range = test_node(2, vec![]);
        node_out_of_range.ipv4 = Some("100.65.0.1".parse().unwrap());

        // node with ip in cidr range is accessible
        assert!(engine.can_see(&node_in_range, &node_in_range, &resolver));

        // node with ip out of range is not accessible
        assert!(!engine.can_see(&node_in_range, &node_out_of_range, &resolver));
    }

    #[test]
    fn test_get_network_capabilities_union() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Port(80)],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Port(443)],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        let caps = engine.get_network_capabilities(&node1, &node2, &resolver);
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&NetworkCapability::Port(80)));
        assert!(caps.contains(&NetworkCapability::Port(443)));
    }

    #[test]
    fn test_get_visible_peers() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Tag("web".to_string())],
            dst: vec![Selector::Tag("database".to_string())],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let web_node = test_node(1, vec!["tag:web"]);
        let db_node = test_node(2, vec!["tag:database"]);
        let other_node = test_node(3, vec!["tag:other"]);

        let all_nodes = vec![web_node.clone(), db_node.clone(), other_node.clone()];
        let visible = engine.get_visible_peers(&web_node, &all_nodes, &resolver);

        // web node should only see database node (not itself, not other)
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, db_node.id);
    }

    #[test]
    fn test_user_selector() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::User("alice@example.com".to_string())],
            dst: vec![Selector::User("bob@example.com".to_string())],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let mut resolver = MockResolver::new();
        resolver
            .users
            .insert(UserId(1), "alice@example.com".to_string());
        resolver
            .users
            .insert(UserId(2), "bob@example.com".to_string());
        resolver
            .users
            .insert(UserId(3), "charlie@example.com".to_string());

        let alice_node = test_node(1, vec![]);
        let bob_node = test_node(2, vec![]);
        let charlie_node = test_node(3, vec![]);

        // alice can see bob
        assert!(engine.can_see(&alice_node, &bob_node, &resolver));

        // bob cannot see alice (directional)
        assert!(!engine.can_see(&bob_node, &alice_node, &resolver));

        // charlie cannot see anyone
        assert!(!engine.can_see(&charlie_node, &bob_node, &resolver));
    }

    #[test]
    fn test_group_selector() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Group("engineering".to_string())],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let mut resolver = MockResolver::new();
        resolver
            .groups
            .insert(UserId(1), vec!["engineering".to_string()]);
        resolver.groups.insert(UserId(2), vec!["sales".to_string()]);

        let engineer_node = test_node(1, vec![]);
        let sales_node = test_node(2, vec![]);

        // engineer can see sales
        assert!(engine.can_see(&engineer_node, &sales_node, &resolver));

        // sales cannot see engineer
        assert!(!engine.can_see(&sales_node, &engineer_node, &resolver));
    }

    #[test]
    fn test_autogroup_member() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Autogroup(Autogroup::Member)],
            dst: vec![Selector::Tag("server".to_string())],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;
        let user_node = test_node(1, vec![]);
        let tagged_node = test_node(2, vec!["tag:server"]);
        let other_tagged_node = test_node(3, vec!["tag:client"]);

        // user node (member) can see tagged server
        assert!(engine.can_see(&user_node, &tagged_node, &resolver));

        // tagged node (not member) cannot see tagged server (unless separate grant)
        assert!(!engine.can_see(&other_tagged_node, &tagged_node, &resolver));
    }

    #[test]
    fn test_autogroup_self() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Autogroup(Autogroup::Member)],
            dst: vec![Selector::Autogroup(Autogroup::SelfDevices)],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        // two nodes for user 1
        let node1_u1 = test_node(1, vec![]); // User 1

        // we need to override user_id to simulate same user
        let mut node2_u1 = test_node(2, vec![]);
        node2_u1.user_id = Some(UserId(1));

        // node for user 2
        let node3_u2 = test_node(3, vec![]); // User 3

        // user 1 can see their own device
        assert!(engine.can_see(&node1_u1, &node2_u1, &resolver));

        // user 1 cannot see user 3's device
        assert!(!engine.can_see(&node1_u1, &node3_u2, &resolver));
    }

    #[test]
    fn test_update_policy_changes_access() {
        // start with empty policy (deny all)
        let mut engine = GrantsEngine::empty();
        let resolver = EmptyResolver;
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        // initially denied
        assert!(!engine.can_see(&node1, &node2, &resolver));

        // update to allow-all policy
        let mut new_policy = Policy::empty();
        new_policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });
        engine.update_policy(new_policy);

        // now allowed
        assert!(engine.can_see(&node1, &node2, &resolver));

        // update back to empty policy
        engine.update_policy(Policy::empty());

        // denied again
        assert!(!engine.can_see(&node1, &node2, &resolver));
    }

    // ssh policy compiler tests

    #[test]
    fn test_compile_ssh_policy_empty() {
        let policy = Policy::empty();
        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let node = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let all_nodes = vec![node.clone()];

        let ssh_policy = engine.compile_ssh_policy(&node, &all_nodes, &resolver);
        assert!(ssh_policy.is_none());
    }

    #[test]
    fn test_compile_ssh_policy_tagged_node_skipped() {
        let mut policy = Policy::empty();
        policy.ssh.push(crate::ssh::SshPolicyRule {
            action: crate::ssh::SshActionType::Accept,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec!["*".to_string()],
            users: vec!["autogroup:nonroot".to_string()],
            accept_env: None,
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        // tagged node should not get ssh policy
        let tagged_node = test_node(1, vec!["tag:server"]);
        let all_nodes = vec![tagged_node.clone()];

        let ssh_policy = engine.compile_ssh_policy(&tagged_node, &all_nodes, &resolver);
        assert!(ssh_policy.is_none());
    }

    #[test]
    fn test_compile_ssh_policy_basic() {
        let mut policy = Policy::empty();
        policy.ssh.push(crate::ssh::SshPolicyRule {
            action: crate::ssh::SshActionType::Accept,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec!["*".to_string()],
            users: vec!["ubuntu".to_string()],
            accept_env: None,
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let node2 = test_node_with_user(2, vec![], Some(UserId::from(2)));
        let all_nodes = vec![node1.clone(), node2.clone()];

        // compile ssh policy for node1
        let ssh_policy = engine.compile_ssh_policy(&node1, &all_nodes, &resolver);
        assert!(ssh_policy.is_some());

        let policy = ssh_policy.unwrap();
        assert_eq!(policy.rules.len(), 1);

        let rule = &policy.rules[0];
        assert!(rule.action.accept.unwrap_or(false));
        assert_eq!(rule.ssh_users.get("ubuntu"), Some(&"ubuntu".to_string()));

        // should have principal for node2's ip
        assert_eq!(rule.principals.len(), 1);
        assert!(rule.principals[0].node_ip.is_some());
    }

    #[test]
    fn test_compile_ssh_policy_autogroup_self() {
        let mut policy = Policy::empty();
        policy.ssh.push(crate::ssh::SshPolicyRule {
            action: crate::ssh::SshActionType::Accept,
            check_period: None,
            src: vec!["autogroup:member".to_string()],
            dst: vec!["autogroup:self".to_string()],
            users: vec!["autogroup:nonroot".to_string()],
            accept_env: None,
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        // user 1's devices
        let user1_node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let user1_node2 = test_node_with_user(2, vec![], Some(UserId::from(1)));

        // user 2's device
        let user2_node = test_node_with_user(3, vec![], Some(UserId::from(2)));

        let all_nodes = vec![user1_node1.clone(), user1_node2.clone(), user2_node.clone()];

        // compile ssh policy for user1_node1
        let ssh_policy = engine.compile_ssh_policy(&user1_node1, &all_nodes, &resolver);
        assert!(ssh_policy.is_some());

        let policy = ssh_policy.unwrap();
        assert_eq!(policy.rules.len(), 1);

        let rule = &policy.rules[0];
        // should only have principal for user1_node2, not user2_node
        assert_eq!(rule.principals.len(), 1);

        // check ssh_users map has nonroot pattern
        assert_eq!(rule.ssh_users.get("*"), Some(&"=".to_string()));
        assert_eq!(rule.ssh_users.get("root"), Some(&String::new())); // denied
    }

    fn test_node_with_user(id: u64, tags: Vec<&str>, user_id: Option<UserId>) -> Node {
        let tags = tags.into_iter().filter_map(|t| t.parse().ok()).collect();
        let mut builder = TestNodeBuilder::new(id).with_tags(tags);
        if let Some(uid) = user_id {
            builder = builder.with_user_id(uid);
        }
        builder.build()
    }

    // posture integration tests

    use railscale_types::HostInfo;

    fn test_node_with_hostinfo(id: u64, os: &str, ts_version: &str) -> Node {
        let hostinfo = HostInfo {
            os: Some(os.to_string()),
            ipn_version: Some(ts_version.to_string()),
            ..Default::default()
        };
        TestNodeBuilder::new(id).with_hostinfo(hostinfo).build()
    }

    #[test]
    fn test_posture_blocks_non_matching() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:latestMac".to_string(),
            vec!["node:os == 'macos'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:latestMac".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        // linux node should be blocked by posture
        let linux_node = test_node_with_hostinfo(1, "linux", "1.50.0");
        let dst_node = test_node(2, vec![]);

        assert!(!engine.can_see(&linux_node, &dst_node, &resolver));
    }

    #[test]
    fn test_posture_allows_matching() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:latestMac".to_string(),
            vec!["node:os == 'macos'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:latestMac".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        // macos node should pass posture check
        let mac_node = test_node_with_hostinfo(1, "macos", "1.50.0");
        let dst_node = test_node(2, vec![]);

        assert!(engine.can_see(&mac_node, &dst_node, &resolver));
    }

    #[test]
    fn test_multiple_postures_or_semantics() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:mac".to_string(),
            vec!["node:os == 'macos'".to_string()],
        );
        policy.postures.insert(
            "posture:linux".to_string(),
            vec!["node:os == 'linux'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            // either mac OR linux posture is ok
            src_posture: vec!["posture:mac".to_string(), "posture:linux".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let mac_node = test_node_with_hostinfo(1, "macos", "1.50.0");
        let linux_node = test_node_with_hostinfo(2, "linux", "1.50.0");
        let windows_node = test_node_with_hostinfo(3, "windows", "1.50.0");
        let dst_node = test_node(4, vec![]);

        assert!(engine.can_see(&mac_node, &dst_node, &resolver));
        assert!(engine.can_see(&linux_node, &dst_node, &resolver));
        assert!(!engine.can_see(&windows_node, &dst_node, &resolver));
    }

    #[test]
    fn test_default_src_posture_applied() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:baseline".to_string(),
            vec!["node:os IN ['macos', 'linux']".to_string()],
        );
        policy.default_src_posture = vec!["posture:baseline".to_string()];
        // grant without explicit srcPosture - should use default
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![], // empty - uses defaultSrcPosture
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let linux_node = test_node_with_hostinfo(1, "linux", "1.50.0");
        let windows_node = test_node_with_hostinfo(2, "windows", "1.50.0");
        let dst_node = test_node(3, vec![]);

        // linux passes default posture
        assert!(engine.can_see(&linux_node, &dst_node, &resolver));
        // windows fails default posture
        assert!(!engine.can_see(&windows_node, &dst_node, &resolver));
    }

    #[test]
    fn test_explicit_posture_overrides_default() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:strict".to_string(),
            vec!["node:os == 'macos'".to_string()],
        );
        policy.postures.insert(
            "posture:relaxed".to_string(),
            vec!["node:os IN ['macos', 'linux', 'windows']".to_string()],
        );
        policy.default_src_posture = vec!["posture:strict".to_string()];
        // grant with explicit srcPosture overrides default
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:relaxed".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        // windows would fail strict default, but this grant uses relaxed
        let windows_node = test_node_with_hostinfo(1, "windows", "1.50.0");
        let dst_node = test_node(2, vec![]);

        assert!(engine.can_see(&windows_node, &dst_node, &resolver));
    }

    #[test]
    fn test_posture_version_comparison() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:latest".to_string(),
            vec!["node:tsVersion >= '1.50'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:latest".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let new_node = test_node_with_hostinfo(1, "linux", "1.60.0");
        let old_node = test_node_with_hostinfo(2, "linux", "1.40.0");
        let dst_node = test_node(3, vec![]);

        assert!(engine.can_see(&new_node, &dst_node, &resolver));
        assert!(!engine.can_see(&old_node, &dst_node, &resolver));
    }

    // custom posture attribute tests

    fn test_node_with_custom_attrs(
        id: u64,
        attrs: std::collections::HashMap<String, serde_json::Value>,
    ) -> Node {
        let mut node = TestNodeBuilder::new(id).build();
        node.posture_attributes = attrs;
        node
    }

    #[test]
    fn test_custom_posture_attribute_string() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:managed".to_string(),
            vec!["custom:tier == 'prod'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:managed".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let mut prod_attrs = std::collections::HashMap::new();
        prod_attrs.insert("tier".to_string(), serde_json::json!("prod"));

        let mut dev_attrs = std::collections::HashMap::new();
        dev_attrs.insert("tier".to_string(), serde_json::json!("dev"));

        let prod_node = test_node_with_custom_attrs(1, prod_attrs);
        let dev_node = test_node_with_custom_attrs(2, dev_attrs);
        let no_attr_node = test_node(3, vec![]);
        let dst_node = test_node(4, vec![]);

        assert!(engine.can_see(&prod_node, &dst_node, &resolver));
        assert!(!engine.can_see(&dev_node, &dst_node, &resolver));
        assert!(!engine.can_see(&no_attr_node, &dst_node, &resolver));
    }

    #[test]
    fn test_custom_posture_attribute_is_set() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:has_mdm".to_string(),
            vec!["custom:mdm_managed IS SET".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:has_mdm".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let mut managed_attrs = std::collections::HashMap::new();
        managed_attrs.insert("mdm_managed".to_string(), serde_json::json!(true));

        let managed_node = test_node_with_custom_attrs(1, managed_attrs);
        let unmanaged_node = test_node(2, vec![]);
        let dst_node = test_node(3, vec![]);

        assert!(engine.can_see(&managed_node, &dst_node, &resolver));
        assert!(!engine.can_see(&unmanaged_node, &dst_node, &resolver));
    }

    #[test]
    fn test_custom_posture_attribute_boolean() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:compliant".to_string(),
            vec!["custom:compliant == 'true'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:compliant".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let mut compliant_attrs = std::collections::HashMap::new();
        compliant_attrs.insert("compliant".to_string(), serde_json::json!(true));

        let mut non_compliant_attrs = std::collections::HashMap::new();
        non_compliant_attrs.insert("compliant".to_string(), serde_json::json!(false));

        let compliant_node = test_node_with_custom_attrs(1, compliant_attrs);
        let non_compliant_node = test_node_with_custom_attrs(2, non_compliant_attrs);
        let dst_node = test_node(3, vec![]);

        assert!(engine.can_see(&compliant_node, &dst_node, &resolver));
        assert!(!engine.can_see(&non_compliant_node, &dst_node, &resolver));
    }

    // geoip posture tests
    use crate::geoip::GeoIpResolver;

    struct MockGeoIpResolver {
        mappings: std::collections::HashMap<std::net::IpAddr, String>,
    }

    impl MockGeoIpResolver {
        fn with_mapping(ip: &str, country: &str) -> Self {
            let mut mappings = std::collections::HashMap::new();
            mappings.insert(ip.parse().unwrap(), country.to_string());
            Self { mappings }
        }
    }

    impl GeoIpResolver for MockGeoIpResolver {
        fn lookup_country(&self, ip: std::net::IpAddr) -> Option<String> {
            self.mappings.get(&ip).cloned()
        }
    }

    #[test]
    fn test_ip_country_posture_condition() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:us_only".to_string(),
            vec!["ip:country == 'US'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:us_only".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let user_resolver = EmptyResolver;
        let geoip = MockGeoIpResolver::with_mapping("8.8.8.8", "US");

        let src_node = test_node(1, vec![]);
        let dst_node = test_node(2, vec![]);

        // US IP should pass
        let us_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert!(engine.can_see_with_ip(&src_node, &dst_node, &user_resolver, Some(us_ip), &geoip));

        // non-US IP should fail
        let other_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!engine.can_see_with_ip(
            &src_node,
            &dst_node,
            &user_resolver,
            Some(other_ip),
            &geoip
        ));
    }

    #[test]
    fn test_compile_ssh_policy_accept_env_propagated() {
        let mut policy = Policy::empty();
        policy.ssh.push(crate::ssh::SshPolicyRule {
            action: crate::ssh::SshActionType::Accept,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec!["*".to_string()],
            users: vec!["ubuntu".to_string()],
            accept_env: Some(vec!["GIT_*".to_string(), "LANG".to_string()]),
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let node2 = test_node_with_user(2, vec![], Some(UserId::from(2)));
        let all_nodes = vec![node1.clone(), node2.clone()];

        let ssh_policy = engine.compile_ssh_policy(&node1, &all_nodes, &resolver);
        let policy = ssh_policy.unwrap();
        let rule = &policy.rules[0];

        // accept_env should be propagated from policy rule
        assert_eq!(
            rule.accept_env,
            Some(vec!["GIT_*".to_string(), "LANG".to_string()])
        );
    }

    #[test]
    fn test_compile_ssh_policy_accept_env_none_when_unset() {
        let mut policy = Policy::empty();
        policy.ssh.push(crate::ssh::SshPolicyRule {
            action: crate::ssh::SshActionType::Accept,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec!["*".to_string()],
            users: vec!["ubuntu".to_string()],
            accept_env: None,
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let node2 = test_node_with_user(2, vec![], Some(UserId::from(2)));
        let all_nodes = vec![node1.clone(), node2.clone()];

        let ssh_policy = engine.compile_ssh_policy(&node1, &all_nodes, &resolver);
        let policy = ssh_policy.unwrap();
        let rule = &policy.rules[0];

        // accept_env should remain None when not configured
        assert_eq!(rule.accept_env, None);
    }

    #[test]
    fn test_generate_cap_grant_rules_from_app_caps() {
        use crate::capability::AppCapability;

        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![],
            app: vec![AppCapability {
                name: "https://tailscale.com/cap/file-sharing-target".to_string(),
                params: vec![],
            }],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let node2 = test_node_with_user(2, vec![], Some(UserId::from(2)));
        let all_nodes = vec![node1.clone(), node2.clone()];

        let rules = engine.generate_cap_grant_rules(&node1, &all_nodes, &resolver);
        assert!(!rules.is_empty(), "should generate cap grant rules");

        // should be a filter rule with cap_grant, not dst_ports
        let rule = &rules[0];
        assert!(
            rule.dst_ports.is_empty(),
            "cap grant rules should have no dst_ports"
        );
        assert!(!rule.cap_grant.is_empty(), "should have cap_grant entries");

        // the cap grant should reference node1's IPs and include the file-sharing-target cap
        let grant = &rule.cap_grant[0];
        assert!(!grant.dsts.is_empty());
        assert!(
            grant
                .cap_map
                .contains_key("https://tailscale.com/cap/file-sharing-target")
        );
    }

    #[test]
    fn test_generate_cap_grant_rules_empty_without_app_caps() {
        let mut policy = Policy::empty();
        // grant with only network caps, no app caps
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let resolver = EmptyResolver;

        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let node2 = test_node_with_user(2, vec![], Some(UserId::from(2)));
        let all_nodes = vec![node1.clone(), node2.clone()];

        let rules = engine.generate_cap_grant_rules(&node1, &all_nodes, &resolver);
        assert!(
            rules.is_empty(),
            "no cap grant rules for network-only grants"
        );
    }

    #[test]
    fn test_generate_taildrop_rules_same_user() {
        let engine = GrantsEngine::empty();
        let resolver = EmptyResolver;

        // two nodes owned by the same user
        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let mut node2 = test_node_with_user(2, vec![], Some(UserId::from(1)));
        node2.user_id = Some(UserId::from(1));

        // different user
        let node3 = test_node_with_user(3, vec![], Some(UserId::from(2)));

        let all_nodes = vec![node1.clone(), node2.clone(), node3.clone()];

        let rules = engine.generate_taildrop_rules(&node1, &all_nodes, &resolver);
        assert!(
            !rules.is_empty(),
            "should have taildrop rules for same-user peer"
        );

        // should only include node2 (same user), not node3 (different user)
        let rule = &rules[0];
        assert_eq!(rule.src_ips.len(), 1, "only one same-user peer");
        assert!(!rule.cap_grant.is_empty());
        assert!(
            rule.cap_grant[0]
                .cap_map
                .contains_key("https://tailscale.com/cap/file-sharing-target")
        );
    }

    #[test]
    fn test_generate_taildrop_rules_no_cross_user() {
        let engine = GrantsEngine::empty();
        let resolver = EmptyResolver;

        // nodes owned by different users
        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let node2 = test_node_with_user(2, vec![], Some(UserId::from(2)));
        let all_nodes = vec![node1.clone(), node2.clone()];

        let rules = engine.generate_taildrop_rules(&node1, &all_nodes, &resolver);
        assert!(
            rules.is_empty(),
            "no taildrop rules for cross-user without grants"
        );
    }

    #[test]
    fn test_generate_taildrop_rules_tagged_nodes_excluded() {
        let engine = GrantsEngine::empty();
        let resolver = EmptyResolver;

        let node1 = test_node_with_user(1, vec![], Some(UserId::from(1)));
        let tagged = test_node(2, vec!["tag:server"]);
        let all_nodes = vec![node1.clone(), tagged.clone()];

        let rules = engine.generate_taildrop_rules(&node1, &all_nodes, &resolver);
        assert!(
            rules.is_empty(),
            "tagged nodes should not get taildrop rules"
        );
    }

    #[test]
    fn test_ip_country_uses_cached_last_seen_country() {
        let mut policy = Policy::empty();
        policy.postures.insert(
            "posture:us_only".to_string(),
            vec!["ip:country == 'US'".to_string()],
        );
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec!["posture:us_only".to_string()],
            via: vec![],
        });

        let engine = GrantsEngine::new(policy);
        let user_resolver = EmptyResolver;

        // create node with cached country
        let mut us_node = test_node(1, vec![]);
        us_node.last_seen_country = Some("US".to_string());

        let mut uk_node = test_node(2, vec![]);
        uk_node.last_seen_country = Some("UK".to_string());

        let mut no_country_node = test_node(3, vec![]);
        no_country_node.last_seen_country = None;

        let dst_node = test_node(4, vec![]);

        // US node should be able to see dst (using cached country)
        assert!(engine.can_see(&us_node, &dst_node, &user_resolver));

        // UK node should NOT be able to see dst
        assert!(!engine.can_see(&uk_node, &dst_node, &user_resolver));

        // node with no cached country should NOT be able to see dst (fail closed)
        assert!(!engine.can_see(&no_country_node, &dst_node, &user_resolver));
    }
}
