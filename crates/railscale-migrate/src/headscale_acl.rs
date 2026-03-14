//! convert headscale ACL json to railscale grants policy

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Deserialize;

use railscale_grants::policy::Policy;

/// headscale ACL policy file (acl.json)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadscaleAcl {
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub tag_owners: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub hosts: HashMap<String, IpAddr>,

    #[serde(default)]
    pub acls: Vec<AclRule>,

    #[serde(default)]
    pub ssh: Vec<SshRule>,
}

/// a single headscale ACL rule
#[derive(Debug, Deserialize)]
pub struct AclRule {
    pub action: String,
    #[serde(default)]
    pub proto: Option<String>,
    pub src: Vec<String>,
    pub dst: Vec<String>,
}

/// a headscale SSH rule
#[derive(Debug, Deserialize)]
pub struct SshRule {
    pub action: String,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub users: Vec<String>,
}

/// warning emitted during conversion for things that need manual review
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionWarning {
    pub context: String,
    pub message: String,
}

/// result of converting headscale ACL to railscale policy
#[derive(Debug)]
pub struct ConversionResult {
    pub policy: Policy,
    pub warnings: Vec<ConversionWarning>,
}

/// convert a headscale ACL to a railscale grants policy
pub fn convert(acl: &HeadscaleAcl) -> ConversionResult {
    let mut warnings = Vec::new();
    let mut grants = Vec::new();

    for (i, rule) in acl.acls.iter().enumerate() {
        if rule.action != "accept" {
            warnings.push(ConversionWarning {
                context: format!("acl[{}]", i),
                message: format!("skipping non-accept action: {}", rule.action),
            });
            continue;
        }

        // resolve src selectors
        let src: Vec<String> = rule
            .src
            .iter()
            .map(|s| resolve_target(s, &acl.hosts))
            .collect();

        // parse dst entries into selectors + capabilities
        let mut dst_selectors = Vec::new();
        let mut capabilities = Vec::new();

        for dst_entry in &rule.dst {
            let (target, port) = parse_acl_dst(dst_entry);
            let resolved = resolve_target(&target, &acl.hosts);
            dst_selectors.push(resolved);
            // collect the port/capability (dedup later)
            if !capabilities.contains(&port) {
                capabilities.push(port);
            }
        }

        // override capability for protocol-specific rules
        if let Some(proto) = &rule.proto {
            capabilities = vec![format!("{}:*", proto)];
        }

        // build the grant json and parse it through the real policy parser
        // so we get proper validation
        let grant_json = serde_json::json!({
            "src": src,
            "dst": dst_selectors,
            "ip": capabilities,
        });

        match serde_json::from_value(grant_json) {
            Ok(grant) => grants.push(grant),
            Err(e) => {
                warnings.push(ConversionWarning {
                    context: format!("acl[{}]", i),
                    message: format!("failed to convert grant: {}", e),
                });
            }
        }
    }

    // convert ssh rules
    let ssh = acl
        .ssh
        .iter()
        .filter_map(|rule| {
            let action = match rule.action.as_str() {
                "accept" => railscale_grants::ssh::SshActionType::Accept,
                "check" => railscale_grants::ssh::SshActionType::Check,
                other => {
                    warnings.push(ConversionWarning {
                        context: "ssh".into(),
                        message: format!("skipping unknown ssh action: {}", other),
                    });
                    return None;
                }
            };
            Some(railscale_grants::ssh::SshPolicyRule {
                action,
                check_period: None,
                src: rule.src.clone(),
                dst: rule.dst.clone(),
                users: rule.users.clone(),
                accept_env: None,
            })
        })
        .collect();

    let policy = Policy {
        hosts: acl.hosts.clone(),
        groups: acl.groups.clone(),
        postures: HashMap::new(),
        default_src_posture: vec![],
        grants,
        ssh,
        auto_approvers: Default::default(),
        node_attrs: vec![],
    };

    ConversionResult { policy, warnings }
}

/// parse a headscale dst entry like "target:port" into (selector_str, capability_str)
///
/// headscale dst format: "target:port" where port can be "*" or a number
/// special cases:
///   - "*:*" → ("*", "*")
///   - "tag:web:80" → ("tag:web", "80")
///   - "autogroup:internet:*" → ("autogroup:internet", "*")
///   - "blade-spark:11434" → needs host resolution
fn parse_acl_dst(dst: &str) -> (String, String) {
    // prefixed selectors like tag:name, group:name, autogroup:name contain
    // a colon in the target itself, so the port is the *third* segment.
    // we strip the known prefix, rsplit on the last colon for the port,
    // then reattach the prefix
    const PREFIXES: &[&str] = &["tag:", "autogroup:", "group:"];

    for prefix in PREFIXES {
        if let Some(rest) = dst.strip_prefix(prefix) {
            return match rest.rsplit_once(':') {
                Some((name, port)) => (format!("{prefix}{name}"), port.to_string()),
                None => (dst.to_string(), "*".to_string()),
            };
        }
    }

    // bare target:port (host alias, wildcard, ip, email)
    match dst.rsplit_once(':') {
        Some((target, port)) => (target.to_string(), port.to_string()),
        None => (dst.to_string(), "*".to_string()),
    }
}

/// resolve a headscale src/dst target to a railscale selector string
///
/// headscale uses bare host names from the hosts map, while railscale
/// uses `host:name` prefixed selectors
fn resolve_target(target: &str, hosts: &HashMap<String, IpAddr>) -> String {
    // already-prefixed selectors pass through
    if target == "*"
        || target.starts_with("tag:")
        || target.starts_with("group:")
        || target.starts_with("autogroup:")
        || target.starts_with("host:")
        || target.contains('@')
        || target.contains('/')
    {
        return target.to_string();
    }

    // bare ip addresses pass through
    if target.parse::<IpAddr>().is_ok() {
        return target.to_string();
    }

    // check if it's a known host alias
    if hosts.contains_key(target) {
        return format!("host:{}", target);
    }

    // unknown bare name - pass through but it'll likely fail validation
    target.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // --- parse_acl_dst tests ---

    #[test]
    fn parse_dst_wildcard() {
        assert_eq!(parse_acl_dst("*:*"), ("*".into(), "*".into()));
    }

    #[test]
    fn parse_dst_tag_with_port() {
        assert_eq!(parse_acl_dst("tag:web:80"), ("tag:web".into(), "80".into()));
    }

    #[test]
    fn parse_dst_tag_with_wildcard_port() {
        assert_eq!(
            parse_acl_dst("tag:spectral:*"),
            ("tag:spectral".into(), "*".into())
        );
    }

    #[test]
    fn parse_dst_autogroup_with_port() {
        assert_eq!(
            parse_acl_dst("autogroup:internet:*"),
            ("autogroup:internet".into(), "*".into())
        );
    }

    #[test]
    fn parse_dst_host_with_port() {
        assert_eq!(
            parse_acl_dst("blade-spark:11434"),
            ("blade-spark".into(), "11434".into())
        );
    }

    #[test]
    fn parse_dst_host_with_wildcard() {
        assert_eq!(parse_acl_dst("velvet:*"), ("velvet".into(), "*".into()));
    }

    #[test]
    fn parse_dst_group_with_port() {
        assert_eq!(
            parse_acl_dst("group:servers:443"),
            ("group:servers".into(), "443".into())
        );
    }

    // --- resolve_target tests ---

    fn test_hosts() -> HashMap<String, IpAddr> {
        let mut hosts = HashMap::new();
        hosts.insert("blade-spark".into(), "100.64.0.1".parse().unwrap());
        hosts.insert("velvet".into(), "100.64.0.28".parse().unwrap());
        hosts
    }

    #[test]
    fn resolve_known_host() {
        let hosts = test_hosts();
        assert_eq!(resolve_target("blade-spark", &hosts), "host:blade-spark");
    }

    #[test]
    fn resolve_tag_passthrough() {
        let hosts = test_hosts();
        assert_eq!(resolve_target("tag:web", &hosts), "tag:web");
    }

    #[test]
    fn resolve_group_passthrough() {
        let hosts = test_hosts();
        assert_eq!(resolve_target("group:admin", &hosts), "group:admin");
    }

    #[test]
    fn resolve_autogroup_passthrough() {
        let hosts = test_hosts();
        assert_eq!(
            resolve_target("autogroup:member", &hosts),
            "autogroup:member"
        );
    }

    #[test]
    fn resolve_wildcard_passthrough() {
        let hosts = test_hosts();
        assert_eq!(resolve_target("*", &hosts), "*");
    }

    #[test]
    fn resolve_email_passthrough() {
        let hosts = test_hosts();
        assert_eq!(
            resolve_target("user@example.com", &hosts),
            "user@example.com"
        );
    }

    // --- full conversion tests ---

    #[test]
    fn convert_simple_tag_grant() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "acls": [
                {"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432"]}
            ]
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        assert_eq!(result.policy.grants.len(), 1);

        let grant = &result.policy.grants[0];
        assert_eq!(
            serde_json::to_value(&grant.src).unwrap(),
            serde_json::json!(["tag:web"])
        );
        assert_eq!(
            serde_json::to_value(&grant.dst).unwrap(),
            serde_json::json!(["tag:db"])
        );
        assert_eq!(
            serde_json::to_value(&grant.ip).unwrap(),
            serde_json::json!(["5432"])
        );
    }

    #[test]
    fn convert_wildcard_grant() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "acls": [
                {"action": "accept", "src": ["group:admin"], "dst": ["*:*"]}
            ]
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        assert_eq!(result.policy.grants.len(), 1);

        let grant = &result.policy.grants[0];
        assert_eq!(
            serde_json::to_value(&grant.dst).unwrap(),
            serde_json::json!(["*"])
        );
        assert_eq!(
            serde_json::to_value(&grant.ip).unwrap(),
            serde_json::json!(["*"])
        );
    }

    #[test]
    fn convert_icmp_rule() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "acls": [
                {"action": "accept", "proto": "icmp", "src": ["*"], "dst": ["*:*"]}
            ]
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        assert_eq!(result.policy.grants.len(), 1);

        let grant = &result.policy.grants[0];
        assert_eq!(
            serde_json::to_value(&grant.ip).unwrap(),
            serde_json::json!(["icmp:*"])
        );
    }

    #[test]
    fn convert_host_alias_in_dst() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "hosts": {"blade-spark": "100.64.0.1"},
            "acls": [
                {"action": "accept", "src": ["tag:api"], "dst": ["blade-spark:11434"]}
            ]
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        let grant = &result.policy.grants[0];
        assert_eq!(
            serde_json::to_value(&grant.dst).unwrap(),
            serde_json::json!(["host:blade-spark"])
        );
        assert_eq!(
            serde_json::to_value(&grant.ip).unwrap(),
            serde_json::json!(["11434"])
        );
        // hosts map should be populated
        assert_eq!(
            result.policy.hosts.get("blade-spark"),
            Some(&"100.64.0.1".parse().unwrap())
        );
    }

    #[test]
    fn convert_host_alias_in_src() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "hosts": {"stowe-prod": "100.64.0.6"},
            "acls": [
                {"action": "accept", "src": ["stowe-prod"], "dst": ["*:*"]}
            ]
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        let grant = &result.policy.grants[0];
        assert_eq!(
            serde_json::to_value(&grant.src).unwrap(),
            serde_json::json!(["host:stowe-prod"])
        );
    }

    #[test]
    fn convert_groups_passed_through() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "groups": {
                "group:admin": ["ro@example.com", "alicja@example.com"]
            },
            "acls": []
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        assert_eq!(
            result.policy.groups.get("group:admin"),
            Some(&vec![
                "ro@example.com".to_string(),
                "alicja@example.com".to_string()
            ])
        );
    }

    #[test]
    fn convert_ssh_rules() {
        let acl: HeadscaleAcl = serde_json::from_str(
            r#"{
            "ssh": [
                {
                    "action": "accept",
                    "src": ["group:admin"],
                    "dst": ["autogroup:tagged"],
                    "users": ["root", "autogroup:nonroot"]
                }
            ]
        }"#,
        )
        .unwrap();

        let result = convert(&acl);
        assert_eq!(result.policy.ssh.len(), 1);
        assert_eq!(result.policy.ssh[0].src, vec!["group:admin"]);
        assert_eq!(result.policy.ssh[0].dst, vec!["autogroup:tagged"]);
        assert_eq!(
            result.policy.ssh[0].users,
            vec!["root", "autogroup:nonroot"]
        );
    }

    #[test]
    fn convert_real_headscale_acl() {
        let json = include_str!("../tests/fixtures/headscale-acl.json");
        let acl: HeadscaleAcl = serde_json::from_str(json).unwrap();
        let result = convert(&acl);

        // should produce 8 grants (one per ACL rule)
        assert_eq!(result.policy.grants.len(), 8);

        // groups should be preserved
        assert!(result.policy.groups.contains_key("group:admin"));
        assert!(result.policy.groups.contains_key("group:ml-team"));

        // hosts should be populated
        assert_eq!(result.policy.hosts.len(), 8);

        // ssh rules should be converted
        assert_eq!(result.policy.ssh.len(), 2);

        // policy should validate
        result.policy.validate().unwrap();
    }
}
