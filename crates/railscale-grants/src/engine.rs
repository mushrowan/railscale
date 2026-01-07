//! the main grants evaluation engine.

use std::sync::Arc;

use railscale_proto::{FilterRule, PortRange};
use railscale_types::Node;

use crate::capability::{NetworkCapability, Protocol};
use crate::grant::Grant;
use crate::policy::Policy;
use crate::selector::{Autogroup, Selector};

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
    pub fn can_see(&self, src: &Node, dst: &Node) -> bool {
        self.matching_grants(src, dst)
            .any(|g| !g.ip.is_empty() || !g.app.is_empty())
    }

    /// get network capabilities that src has when accessing dst.
    ///
    /// returns the union of all `ip` fields from matching grants.
    pub fn get_network_capabilities(
        &self,
        src: &Node,
        dst: &Node,
    ) -> Vec<NetworkCapability> {
        let mut caps = Vec::new();
        for grant in self.matching_grants(src, dst) {
            caps.extend(grant.ip.iter().cloned());
        }
        caps
    }

    /// get all visible peers for a node.
    ///
    /// returns nodes that `src` can see according to any grant.
    pub fn get_visible_peers<'a>(&self, src: &Node, all_nodes: &'a [Node]) -> Vec<&'a Node> {
        all_nodes
            .iter()
            .filter(|dst| dst.id != src.id && self.can_see(src, dst))
            .collect()
    }

    /// generate filter rules for the mapresponse.
    ///
    /// returns rules that define which peers can access this node and on which ports.
    pub fn generate_filter_rules(&self, node: &Node, peers: &[Node]) -> Vec<FilterRule> {
        let mut rules = Vec::new();

        // for each peer that can access this node
        for peer in peers {
            let caps = self.get_network_capabilities(peer, node);
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

            rules.push(FilterRule { src_ips, dst_ports });
        }

        rules
    }

    /// convert network capabilities to port ranges.
    fn capabilities_to_port_ranges(
        &self,
        caps: &[NetworkCapability],
        dst_ips: &[std::net::IpAddr],
    ) -> Vec<PortRange> {
        let mut port_ranges = Vec::new();

        for dst_ip in dst_ips {
            for cap in caps {
                match cap {
                    NetworkCapability::Wildcard => {
                        // all ports on all protocols (simplify to common protocols)
                        port_ranges.push(PortRange {
                            ip: dst_ip.to_string(),
                            ports: (0, 65535),
                        });
                    }
                    NetworkCapability::Port(port) => {
                        port_ranges.push(PortRange {
                            ip: dst_ip.to_string(),
                            ports: (*port, *port),
                        });
                    }
                    NetworkCapability::PortRange { start, end } => {
                        port_ranges.push(PortRange {
                            ip: dst_ip.to_string(),
                            ports: (*start, *end),
                        });
                    }
                    NetworkCapability::ProtocolPort { protocol: _, port } => {
                        // for now, ignore protocol distinction in filter rules
                        port_ranges.push(PortRange {
                            ip: dst_ip.to_string(),
                            ports: (*port, *port),
                        });
                    }
                    NetworkCapability::ProtocolPortRange {
                        protocol: _,
                        start,
                        end,
                    } => {
                        port_ranges.push(PortRange {
                            ip: dst_ip.to_string(),
                            ports: (*start, *end),
                        });
                    }
                    NetworkCapability::ProtocolWildcard { protocol: _ } => {
                        // all ports for this protocol
                        port_ranges.push(PortRange {
                            ip: dst_ip.to_string(),
                            ports: (0, 65535),
                        });
                    }
                }
            }
        }

        port_ranges
    }

    /// find all grants where src matches src selectors and dst matches dst selectors.
    fn matching_grants<'a>(&'a self, src: &Node, dst: &Node) -> impl Iterator<Item = &'a Grant> {
        self.policy.grants.iter().filter(move |grant| {
            self.node_matches_selectors(src, &grant.src)
                && self.node_matches_selectors(dst, &grant.dst)
        })
    }

    /// check if a node matches any of the given selectors.
    fn node_matches_selectors(&self, node: &Node, selectors: &[Selector]) -> bool {
        selectors
            .iter()
            .any(|s| self.node_matches_selector(node, s))
    }

    /// check if a node matches a single selector.
    fn node_matches_selector(&self, node: &Node, selector: &Selector) -> bool {
        match selector {
            Selector::Wildcard => true,
            Selector::Tag(tag) => node.has_tag(&format!("tag:{}", tag)),
            Selector::Autogroup(Autogroup::Tagged) => node.is_tagged(),
            Selector::Cidr(net) => {
                // check if any of node's ips are in the cidr
                node.ips().iter().any(|ip| net.contains(ip))
            }
            // user/group matching requires user resolution (future)
            Selector::User(_) | Selector::Group(_) => false,
            // other autogroups require role resolution (future)
            Selector::Autogroup(_) => false,
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
    use railscale_types::{MachineKey, NodeId, NodeKey, UserId};

    fn test_node(id: u64, tags: Vec<String>) -> Node {
        Node {
            id: NodeId(id),
            machine_key: MachineKey::default(),
            node_key: NodeKey::default(),
            disco_key: Default::default(),
            endpoints: vec![],
            hostinfo: None,
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: None,
            hostname: format!("node-{}", id),
            given_name: format!("node-{}", id),
            user_id: if tags.is_empty() {
                Some(UserId(1))
            } else {
                None
            },
            tags,
            register_method: railscale_types::RegisterMethod::AuthKey,
            auth_key_id: None,
            approved_routes: vec![],
            expiry: None,
            last_seen: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_online: None,
        }
    }

    #[test]
    fn test_empty_policy_denies_all() {
        let engine = GrantsEngine::empty();
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        assert!(!engine.can_see(&node1, &node2));
        assert!(!engine.can_see(&node2, &node1));
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
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        assert!(engine.can_see(&node1, &node2));
        assert!(engine.can_see(&node2, &node1));
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
        let web_node = test_node(1, vec!["tag:web".to_string()]);
        let db_node = test_node(2, vec!["tag:database".to_string()]);
        let other_node = test_node(3, vec![]);

        // web can see database
        assert!(engine.can_see(&web_node, &db_node));

        // database cannot see web (grant is directional)
        assert!(!engine.can_see(&db_node, &web_node));

        // other node cannot see database
        assert!(!engine.can_see(&other_node, &db_node));
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
        let tagged_node = test_node(1, vec!["tag:server".to_string()]);
        let user_node = test_node(2, vec![]);

        // user node can see tagged node
        assert!(engine.can_see(&user_node, &tagged_node));

        // user node cannot see other user nodes (not tagged)
        assert!(!engine.can_see(&user_node, &user_node));
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
        let node_in_range = test_node(1, vec![]);
        let mut node_out_of_range = test_node(2, vec![]);
        node_out_of_range.ipv4 = Some("100.65.0.1".parse().unwrap());

        // node with ip in cidr range is accessible
        assert!(engine.can_see(&node_in_range, &node_in_range));

        // node with ip out of range is not accessible
        assert!(!engine.can_see(&node_in_range, &node_out_of_range));
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
        let node1 = test_node(1, vec![]);
        let node2 = test_node(2, vec![]);

        let caps = engine.get_network_capabilities(&node1, &node2);
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
        let web_node = test_node(1, vec!["tag:web".to_string()]);
        let db_node = test_node(2, vec!["tag:database".to_string()]);
        let other_node = test_node(3, vec!["tag:other".to_string()]);

        let all_nodes = vec![web_node.clone(), db_node.clone(), other_node.clone()];
        let visible = engine.get_visible_peers(&web_node, &all_nodes);

        // web node should only see database node (not itself, not other)
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, db_node.id);
    }
}
