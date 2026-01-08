//! the main grants evaluation engine.

use std::sync::Arc;

use railscale_proto::{FilterRule, PortRange};
use railscale_types::{Node, UserId};

use crate::capability::NetworkCapability;
use crate::grant::Grant;
use crate::policy::Policy;
use crate::selector::{Autogroup, Selector};

/// a no-op resolver for testing or when user info is not available
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
        self.matching_grants(src, dst, resolver)
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
        for grant in self.matching_grants(src, dst, resolver) {
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
    fn matching_grants<'a, R: UserResolver>(
        &'a self,
        src: &Node,
        dst: &Node,
        resolver: &R,
    ) -> impl Iterator<Item = &'a Grant> {
        self.policy.grants.iter().filter(move |grant| {
            self.node_matches_selectors(src, &grant.src, resolver, Some(dst))
                && self.node_matches_selectors(dst, &grant.dst, resolver, Some(src))
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
            Selector::User(email) => {
                if let Some(uid) = node.user_id {
                    if let Some(user_email) = resolver.resolve_user(&uid) {
                        return user_email == *email;
                    }
                }
                false
            }
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
                Some(UserId(id)) // Use ID as UserID for simplicity in tests unless overwritten
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
        let web_node = test_node(1, vec!["tag:web".to_string()]);
        let db_node = test_node(2, vec!["tag:database".to_string()]);
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
        let tagged_node = test_node(1, vec!["tag:server".to_string()]);
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
        let web_node = test_node(1, vec!["tag:web".to_string()]);
        let db_node = test_node(2, vec!["tag:database".to_string()]);
        let other_node = test_node(3, vec!["tag:other".to_string()]);

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

            resolver

                .groups

                .insert(UserId(2), vec!["sales".to_string()]);

    

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

            let tagged_node = test_node(2, vec!["tag:server".to_string()]);

            let other_tagged_node = test_node(3, vec!["tag:client".to_string()]);

    

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

    }

    