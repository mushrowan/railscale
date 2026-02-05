//! test utilities for creating test nodes and other fixtures.
//!
//! this module provides builder patterns for creating test instances
//! of railscale types without needing to specify all fields.

use chrono::Utc;

use crate::{DiscoKey, HostInfo, MachineKey, Node, NodeId, NodeKey, RegisterMethod, Tag, UserId};

/// builder for creating test [`node`] instances.
///
/// # example
/// ```
/// use railscale_types::test_utils::TestNodeBuilder;
///
/// let node = TestNodeBuilder::new(1).build();
/// let tagged = TestNodeBuilder::new(2)
///     .with_tags(vec!["tag:server".parse().unwrap()])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct TestNodeBuilder {
    id: u64,
    tags: Vec<Tag>,
    user_id: Option<UserId>,
    hostname: Option<String>,
    ipv4: Option<std::net::IpAddr>,
    ipv6: Option<std::net::IpAddr>,
    machine_key: Option<MachineKey>,
    node_key: Option<NodeKey>,
    disco_key: Option<DiscoKey>,
    hostinfo: Option<HostInfo>,
    last_seen_country: Option<String>,
    ephemeral: bool,
    nl_public_key: Option<Vec<u8>>,
}

impl TestNodeBuilder {
    /// create a new builder with the given node id.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            tags: vec![],
            user_id: None,
            hostname: None,
            ipv4: None,
            ipv6: None,
            machine_key: None,
            node_key: None,
            disco_key: None,
            hostinfo: None,
            last_seen_country: None,
            ephemeral: false,
            nl_public_key: None,
        }
    }

    /// set tags for the node.
    ///
    /// if tags are set, the node will be tagged (not user-owned).
    pub fn with_tags(mut self, tags: Vec<Tag>) -> Self {
        self.tags = tags;
        self
    }

    /// set the user id for the node.
    ///
    /// only applies to non-tagged nodes.
    pub fn with_user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// set a custom hostname.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// set ipv4 address.
    pub fn with_ipv4(mut self, ip: std::net::IpAddr) -> Self {
        self.ipv4 = Some(ip);
        self
    }

    /// set ipv6 address.
    pub fn with_ipv6(mut self, ip: std::net::IpAddr) -> Self {
        self.ipv6 = Some(ip);
        self
    }

    /// set machine key.
    pub fn with_machine_key(mut self, key: MachineKey) -> Self {
        self.machine_key = Some(key);
        self
    }

    /// set node key.
    pub fn with_node_key(mut self, key: NodeKey) -> Self {
        self.node_key = Some(key);
        self
    }

    /// set disco key.
    pub fn with_disco_key(mut self, key: DiscoKey) -> Self {
        self.disco_key = Some(key);
        self
    }

    /// set host info (os, version, etc.).
    pub fn with_hostinfo(mut self, hostinfo: HostInfo) -> Self {
        self.hostinfo = Some(hostinfo);
        self
    }

    /// set last seen country (ISO 3166-1 alpha-2 code).
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.last_seen_country = Some(country.into());
        self
    }

    /// set ephemeral flag.
    pub fn with_ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }

    /// mark as ephemeral (shorthand for `.with_ephemeral(true)`).
    pub fn ephemeral(self) -> Self {
        self.with_ephemeral(true)
    }

    /// set network lock public key (raw ed25519 bytes).
    pub fn with_nl_public_key(mut self, key: Vec<u8>) -> Self {
        self.nl_public_key = Some(key);
        self
    }

    /// build the [`node`].
    pub fn build(self) -> Node {
        let hostname = self.hostname.unwrap_or_else(|| format!("node-{}", self.id));

        // for tagged nodes, user_id should be none
        // for user-owned nodes, default to userid(self.id) if not specified
        let user_id = if self.tags.is_empty() {
            self.user_id.or(Some(UserId(self.id)))
        } else {
            None
        };

        let now = Utc::now();

        Node {
            id: NodeId(self.id),
            machine_key: self.machine_key.unwrap_or_default(),
            node_key: self.node_key.unwrap_or_default(),
            disco_key: self.disco_key.unwrap_or_default(),
            endpoints: vec![],
            hostinfo: self.hostinfo,
            ipv4: self.ipv4.or_else(|| Some("100.64.0.1".parse().unwrap())),
            ipv6: self.ipv6,
            hostname: hostname.clone(),
            given_name: hostname,
            user_id,
            register_method: RegisterMethod::AuthKey,
            tags: self.tags,
            auth_key_id: None,
            ephemeral: self.ephemeral,
            expiry: None,
            last_seen: Some(now),
            last_seen_country: self.last_seen_country,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
            posture_attributes: std::collections::HashMap::new(),
            nl_public_key: self.nl_public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let node = TestNodeBuilder::new(1).build();
        assert_eq!(node.id.0, 1);
        assert_eq!(node.hostname, "node-1");
        assert!(!node.is_tagged());
        assert_eq!(node.user_id, Some(UserId(1)));
    }

    #[test]
    fn test_builder_with_tags() {
        let node = TestNodeBuilder::new(2)
            .with_tags(vec!["tag:server".parse().unwrap()])
            .build();
        assert!(node.is_tagged());
        assert!(node.has_tag("tag:server"));
        assert_eq!(node.user_id, None);
    }

    #[test]
    fn test_builder_with_custom_user() {
        let node = TestNodeBuilder::new(3).with_user_id(UserId(100)).build();
        assert_eq!(node.user_id, Some(UserId(100)));
    }

    #[test]
    fn test_builder_with_custom_hostname() {
        let node = TestNodeBuilder::new(4).with_hostname("my-server").build();
        assert_eq!(node.hostname, "my-server");
        assert_eq!(node.given_name, "my-server");
    }
}
