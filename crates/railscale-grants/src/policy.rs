//! policy container holding all grants.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use serde_json::Value;

use crate::error::Error;
use crate::grant::Grant;
use crate::selector::Selector;
use crate::ssh::SshPolicyRule;

/// auto-approver policy for subnet routes and exit nodes.
///
/// maps route prefixes to lists of selectors that identify which nodes
/// can self-approve those routes. when a node advertises a route and
/// matches a selector, the route is automatically approved.
///
/// # Example
///
/// ```json
/// {
///   "routes": {
///     "10.0.0.0/8": ["tag:infra"],
///     "0.0.0.0/0": ["tag:exit-node"]
///   },
///   "exitNode": ["tag:exit-node"]
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoApproverPolicy {
    /// route prefix -> selectors that can auto-approve.
    #[serde(default)]
    pub routes: HashMap<String, Vec<Selector>>,

    /// selectors that can auto-approve exit node routes (0.0.0.0/0, ::/0).
    #[serde(default, rename = "exitNode")]
    pub exit_node: Vec<Selector>,
}

/// the complete policy document.
///
/// policies define access control through grants and can include group definitions
/// for organizing users. Groups are referenced in grants using `group:name` selectors.
/// ssh rules define who can ssh to which nodes
///
/// # Example
///
/// ```json
/// {
///   "groups": {
///     "group:engineering": ["alice@example.com", "bob@example.com"]
///   },
///   "grants": [
///     {"src": ["group:engineering"], "dst": ["tag:servers"], "ip": ["*"]}
///   ],
/// example ssh rule in doc comment
///     {"action": "accept", "src": ["group:engineering"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]}
///   ]
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    /// group definitions mapping group names to member emails.
    ///
    /// group names should include the `group:` prefix (e.g., `"group:engineering"`).
    /// members are identified by email address.
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,

    /// named posture definitions
    ///
    /// maps posture names (e.g., `"posture:latestMac"`) to lists of condition strings.
    /// each condition is a posture expression like `"node:os == 'macos'"`.
    #[serde(default)]
    pub postures: HashMap<String, Vec<String>>,

    /// default source posture applied to grants without explicit srcPosture
    ///
    /// list of posture names that are checked with OR semantics.
    #[serde(default, rename = "defaultSrcPosture")]
    pub default_src_posture: Vec<String>,

    /// all grants in this policy.
    #[serde(default)]
    pub grants: Vec<Grant>,

    /// ssh rules for controlling ssh access
    #[serde(default)]
    pub ssh: Vec<SshPolicyRule>,

    /// auto-approver policy for subnet routes and exit nodes.
    #[serde(default, rename = "autoApprovers")]
    pub auto_approvers: AutoApproverPolicy,

    /// node attribute rules.
    ///
    /// each entry targets a set of nodes (by selector) and assigns
    /// application-level attributes. used for app connectors, etc.
    #[serde(default, rename = "nodeAttrs")]
    pub node_attrs: Vec<NodeAttr>,
}

/// a node attribute rule assigning app-level config to matching nodes.
///
/// # Example
///
/// ```json
/// {
///   "target": ["tag:connector"],
///   "app": {
///     "tailscale.com/app-connectors": [
///       {"name": "github", "domains": ["github.com"], "connectors": ["tag:connector"]}
///     ]
///   }
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeAttr {
    /// selectors for which nodes this applies to (e.g. ["tag:connector"], ["*"])
    pub target: Vec<Selector>,

    /// application configuration map.
    ///
    /// keys are capability names (e.g. "tailscale.com/app-connectors"),
    /// values are opaque json arrays passed through to the node's CapMap
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub app: HashMap<String, Vec<Value>>,
}

impl Policy {
    /// create an empty policy.
    pub fn empty() -> Self {
        Self::default()
    }

    /// parse policy from json string.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let policy: Policy = serde_json::from_str(json)?;
        policy.validate()?;
        Ok(policy)
    }

    /// validate all grants and ssh rules in the policy
    pub fn validate(&self) -> Result<(), Error> {
        for (i, grant) in self.grants.iter().enumerate() {
            grant
                .validate()
                .map_err(|e| Error::InvalidGrant { index: i, cause: e })?;

            // validate posture references exist
            for posture_name in &grant.src_posture {
                if !self.postures.contains_key(posture_name) {
                    return Err(Error::InvalidPostureReference {
                        name: posture_name.clone(),
                    });
                }
            }
        }

        // validate default posture references
        for posture_name in &self.default_src_posture {
            if !self.postures.contains_key(posture_name) {
                return Err(Error::InvalidPostureReference {
                    name: posture_name.clone(),
                });
            }
        }

        for (i, ssh_rule) in self.ssh.iter().enumerate() {
            ssh_rule
                .validate()
                .map_err(|e| Error::InvalidSshRule { index: i, cause: e })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid group names
    fn group_name_strategy() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9-]{0,15}".prop_map(|name| format!("group:{}", name))
    }

    // strategy for valid email addresses
    fn email_strategy() -> impl Strategy<Value = String> {
        "[a-z]{3,8}@[a-z]{3,8}\\.[a-z]{2,4}"
    }

    // strategy for valid selector strings
    fn selector_string_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("*".to_string()),
            "[a-z]{3,10}".prop_map(|t| format!("tag:{}", t)),
            Just("autogroup:tagged".to_string()),
            "[a-z]{3,8}@[a-z]{3,8}\\.[a-z]{2,4}",
            "[a-z]{3,10}".prop_map(|g| format!("group:{}", g)),
        ]
    }

    // strategy for valid capability strings
    fn capability_string_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("*".to_string()),
            (1u16..65535).prop_map(|p| p.to_string()),
            (1u16..1000, 1000u16..65535).prop_map(|(a, b)| format!("{}-{}", a, b)),
            (1u16..65535).prop_map(|p| format!("tcp:{}", p)),
            (1u16..65535).prop_map(|p| format!("udp:{}", p)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn policy_serde_roundtrips_empty(
            groups in prop::collection::hash_map(group_name_strategy(), prop::collection::vec(email_strategy(), 0..3), 0..3)
        ) {
            let policy = Policy {
                groups,
                postures: HashMap::new(),
                default_src_posture: vec![],
                grants: vec![],
                ssh: vec![],
                auto_approvers: Default::default(),
                node_attrs: vec![],
            };

            let json = serde_json::to_string(&policy).unwrap();
            let parsed: Policy = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(policy.groups.len(), parsed.groups.len());
            for (key, value) in &policy.groups {
                prop_assert_eq!(Some(value), parsed.groups.get(key));
            }
        }

        #[test]
        fn policy_from_json_valid_grant(
            src in prop::collection::vec(selector_string_strategy(), 1..3),
            dst in prop::collection::vec(selector_string_strategy(), 1..3),
            ip in prop::collection::vec(capability_string_strategy(), 1..3),
        ) {
            let json = format!(
                r#"{{"grants": [{{"src": {:?}, "dst": {:?}, "ip": {:?}}}]}}"#,
                src, dst, ip
            );

            let result = Policy::from_json(&json);
            // should parse and validate successfully
            prop_assert!(result.is_ok(), "Failed to parse: {:?}", result);

            let policy = result.unwrap();
            prop_assert_eq!(policy.grants.len(), 1);
            prop_assert_eq!(policy.grants[0].src.len(), src.len());
            prop_assert_eq!(policy.grants[0].dst.len(), dst.len());
            prop_assert_eq!(policy.grants[0].ip.len(), ip.len());
        }

        #[test]
        fn policy_from_json_empty_src_rejected(
            dst in prop::collection::vec(selector_string_strategy(), 1..3),
            ip in prop::collection::vec(capability_string_strategy(), 1..3),
        ) {
            let json = format!(
                r#"{{"grants": [{{"src": [], "dst": {:?}, "ip": {:?}}}]}}"#,
                dst, ip
            );

            let result = Policy::from_json(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn policy_from_json_empty_dst_rejected(
            src in prop::collection::vec(selector_string_strategy(), 1..3),
            ip in prop::collection::vec(capability_string_strategy(), 1..3),
        ) {
            let json = format!(
                r#"{{"grants": [{{"src": {:?}, "dst": [], "ip": {:?}}}]}}"#,
                src, ip
            );

            let result = Policy::from_json(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn policy_from_json_no_capabilities_rejected(
            src in prop::collection::vec(selector_string_strategy(), 1..3),
            dst in prop::collection::vec(selector_string_strategy(), 1..3),
        ) {
            let json = format!(
                r#"{{"grants": [{{"src": {:?}, "dst": {:?}}}]}}"#,
                src, dst
            );

            let result = Policy::from_json(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn policy_from_json_invalid_via_rejected(
            src in prop::collection::vec(selector_string_strategy(), 1..3),
            dst in prop::collection::vec(selector_string_strategy(), 1..3),
            ip in prop::collection::vec(capability_string_strategy(), 1..3),
            via in "[a-z]+@[a-z]+\\.[a-z]+",  // email format, not tag:
        ) {
            let json = format!(
                r#"{{"grants": [{{"src": {:?}, "dst": {:?}, "ip": {:?}, "via": [{:?}]}}]}}"#,
                src, dst, ip, via
            );

            let result = Policy::from_json(&json);
            prop_assert!(result.is_err());
        }

        #[test]
        fn policy_from_json_valid_via_accepted(
            src in prop::collection::vec(selector_string_strategy(), 1..3),
            dst in prop::collection::vec(selector_string_strategy(), 1..3),
            ip in prop::collection::vec(capability_string_strategy(), 1..3),
            via_tag in "[a-z]{3,10}",
        ) {
            let via = format!("tag:{}", via_tag);
            let json = format!(
                r#"{{"grants": [{{"src": {:?}, "dst": {:?}, "ip": {:?}, "via": [{:?}]}}]}}"#,
                src, dst, ip, via
            );

            let result = Policy::from_json(&json);
            prop_assert!(result.is_ok(), "Failed with via tag '{}': {:?}", via, result);
        }

        #[test]
        fn arbitrary_json_string_never_panics(s in ".*") {
            // arbitrary strings should never panic policy::from_json
            let _ = Policy::from_json(&s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::NetworkCapability;
    use crate::selector::{Autogroup, Selector};

    #[test]
    fn test_from_json_with_groups() {
        let json = r#"{
            "groups": {
                "group:engineering": ["alice@example.com", "bob@example.com"],
                "group:admins": ["admin@example.com"]
            },
            "grants": [
                {
                    "src": ["group:engineering"],
                    "dst": ["tag:servers"],
                    "ip": ["*"]
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();

        // check groups parsed correctly
        assert_eq!(policy.groups.len(), 2);
        assert_eq!(
            policy.groups.get("group:engineering").unwrap(),
            &vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string()
            ]
        );
        assert_eq!(
            policy.groups.get("group:admins").unwrap(),
            &vec!["admin@example.com".to_string()]
        );

        // check grant parsed correctly
        assert_eq!(policy.grants.len(), 1);
        assert_eq!(
            policy.grants[0].src,
            vec![Selector::Group("engineering".to_string())]
        );
    }

    #[test]
    fn test_groups_default_empty() {
        let json = r#"{"grants": []}"#;
        let policy = Policy::from_json(json).unwrap();
        assert!(policy.groups.is_empty());
    }

    #[test]
    fn test_from_json_empty_policy() {
        let json = r#"{"grants": []}"#;
        let policy = Policy::from_json(json).unwrap();
        assert!(policy.grants.is_empty());
    }

    #[test]
    fn test_from_json_simple_grant() {
        let json = r#"{
            "grants": [
                {
                    "src": ["*"],
                    "dst": ["autogroup:tagged"],
                    "ip": ["*"]
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.grants.len(), 1);
        assert_eq!(policy.grants[0].src, vec![Selector::Wildcard]);
        assert_eq!(
            policy.grants[0].dst,
            vec![Selector::Autogroup(Autogroup::Tagged)]
        );
        assert_eq!(policy.grants[0].ip, vec![NetworkCapability::Wildcard]);
    }

    #[test]
    fn test_from_json_invalid_grant() {
        let json = r#"{
            "grants": [
                {
                    "src": [],
                    "dst": ["*"],
                    "ip": ["*"]
                }
            ]
        }"#;

        let result = Policy::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate() {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });

        let result = policy.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_with_ssh() {
        let json = r#"{
            "grants": [
                {"src": ["*"], "dst": ["*"], "ip": ["22"]}
            ],
            "ssh": [
                {
                    "action": "accept",
                    "src": ["group:admins"],
                    "dst": ["autogroup:self"],
                    "users": ["autogroup:nonroot"]
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.grants.len(), 1);
        assert_eq!(policy.ssh.len(), 1);
        assert_eq!(policy.ssh[0].src, vec!["group:admins"]);
        assert_eq!(policy.ssh[0].users, vec!["autogroup:nonroot"]);
    }

    #[test]
    fn test_validate_invalid_ssh_rule() {
        let json = r#"{
            "grants": [],
            "ssh": [
                {
                    "action": "accept",
                    "src": [],
                    "dst": ["*"],
                    "users": ["ubuntu"]
                }
            ]
        }"#;

        let result = Policy::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_policy_with_postures() {
        let json = r#"{
            "postures": {
                "posture:latestMac": [
                    "node:os == 'macos'",
                    "node:tsVersion >= '1.40'"
                ]
            },
            "grants": [
                {"src": ["*"], "dst": ["*"], "ip": ["*"]}
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.postures.len(), 1);
        assert!(policy.postures.contains_key("posture:latestMac"));
        assert_eq!(policy.postures["posture:latestMac"].len(), 2);
    }

    #[test]
    fn test_parse_grant_with_src_posture() {
        let json = r#"{
            "postures": {
                "posture:latestMac": ["node:os == 'macos'"]
            },
            "grants": [
                {
                    "src": ["*"],
                    "dst": ["tag:prod"],
                    "ip": ["*"],
                    "srcPosture": ["posture:latestMac"]
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.grants[0].src_posture, vec!["posture:latestMac"]);
    }

    #[test]
    fn test_parse_default_src_posture() {
        let json = r#"{
            "postures": {
                "posture:baseline": ["node:os IN ['macos', 'linux']"]
            },
            "defaultSrcPosture": ["posture:baseline"],
            "grants": [
                {"src": ["*"], "dst": ["*"], "ip": ["*"]}
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.default_src_posture, vec!["posture:baseline"]);
    }

    #[test]
    fn test_validate_posture_reference_exists() {
        let json = r#"{
            "postures": {},
            "grants": [
                {
                    "src": ["*"],
                    "dst": ["*"],
                    "ip": ["*"],
                    "srcPosture": ["posture:nonexistent"]
                }
            ]
        }"#;

        let result = Policy::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_default_posture_reference_exists() {
        let json = r#"{
            "postures": {},
            "defaultSrcPosture": ["posture:nonexistent"],
            "grants": []
        }"#;

        let result = Policy::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_node_attrs_with_app_connectors() {
        let json = r#"{
            "grants": [],
            "nodeAttrs": [
                {
                    "target": ["tag:connector"],
                    "app": {
                        "tailscale.com/app-connectors": [
                            {
                                "name": "github",
                                "domains": ["github.com", "*.github.com"],
                                "connectors": ["tag:connector"]
                            }
                        ]
                    }
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.node_attrs.len(), 1);
        assert_eq!(
            policy.node_attrs[0].target,
            vec![Selector::Tag("connector".to_string())]
        );
        assert!(
            policy.node_attrs[0]
                .app
                .contains_key("tailscale.com/app-connectors")
        );

        let app_connectors = &policy.node_attrs[0].app["tailscale.com/app-connectors"];
        assert_eq!(app_connectors.len(), 1);

        // verify the inner structure is preserved
        let attr = &app_connectors[0];
        assert_eq!(attr["name"], "github");
        assert_eq!(attr["domains"][0], "github.com");
    }

    #[test]
    fn test_node_attrs_defaults_empty() {
        let json = r#"{"grants": []}"#;
        let policy = Policy::from_json(json).unwrap();
        assert!(policy.node_attrs.is_empty());
    }

    #[test]
    fn test_node_attrs_multiple_targets() {
        let json = r#"{
            "grants": [],
            "nodeAttrs": [
                {
                    "target": ["*"],
                    "app": {
                        "tailscale.com/app-connectors": [
                            {"name": "app1", "domains": ["app1.example.com"], "connectors": ["tag:c1"]},
                            {"name": "app2", "domains": ["app2.example.com"], "connectors": ["tag:c2"]}
                        ]
                    }
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        assert_eq!(policy.node_attrs.len(), 1);
        assert_eq!(policy.node_attrs[0].target, vec![Selector::Wildcard]);

        let attrs = &policy.node_attrs[0].app["tailscale.com/app-connectors"];
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn test_node_attrs_roundtrip() {
        let json = r#"{
            "grants": [],
            "nodeAttrs": [
                {
                    "target": ["tag:connector"],
                    "app": {
                        "tailscale.com/app-connectors": [
                            {"name": "test", "domains": ["test.com"], "connectors": ["tag:connector"]}
                        ]
                    }
                }
            ]
        }"#;

        let policy = Policy::from_json(json).unwrap();
        let serialised = serde_json::to_string(&policy).unwrap();
        let reparsed = Policy::from_json(&serialised).unwrap();

        assert_eq!(policy.node_attrs.len(), reparsed.node_attrs.len());
        assert_eq!(policy.node_attrs[0].target, reparsed.node_attrs[0].target);
    }
}
