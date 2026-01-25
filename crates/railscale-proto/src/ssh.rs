//! ssh policy types for the tailscale control protocol.
//!
//! these types represent the ssh policy sent to clients in mapresponse.
//! the wire format uses lowercase/camelcase field names.

use std::collections::HashMap;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// ssh policy containing rules for incoming ssh connections.
///
/// rules are evaluated in order; the first matching rule wins.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SshPolicy {
    /// ssh rules to evaluate for incoming connections.
    pub rules: Vec<SshRule>,
}

/// a single ssh rule matching principals to actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SshRule {
    /// when this rule expires (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_expires: Option<DateTime<Utc>>,

    /// principals that can match this rule (or logic).
    pub principals: Vec<SshPrincipal>,

    /// ssh user to local user mapping.
    ///
    /// keys: ssh username or "*" for wildcard.
    /// values: local username, "=" for same-as-ssh-user, "" to deny.
    pub ssh_users: HashMap<String, String>,

    /// action to take when rule matches.
    pub action: SshAction,

    /// environment variables to accept (glob patterns like "git_*").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_env: Option<Vec<String>>,
}

/// principal identifying who can use an ssh rule.
///
/// any matching field causes a match (or logic).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SshPrincipal {
    /// stable node id (not used by railscale, but included for wire compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,

    /// node's tailnet ip address (primary matching method).
    #[serde(rename = "nodeIP", skip_serializing_if = "Option::is_none")]
    pub node_ip: Option<String>,

    /// user's login email.
    #[serde(rename = "userLogin", skip_serializing_if = "Option::is_none")]
    pub user_login: Option<String>,

    /// match any connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any: Option<bool>,
}

/// action to take for a matching ssh rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SshAction {
    /// message to display to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// reject the connection (takes priority over accept).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject: Option<bool>,

    /// accept the connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<bool>,

    /// session duration in nanoseconds.
    ///
    /// serialised as an integer (go's `format:nano` tag).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_duration_nanos",
        deserialize_with = "deserialize_duration_nanos",
        default
    )]
    pub session_duration: Option<std::time::Duration>,

    /// allow ssh agent forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_agent_forwarding: Option<bool>,

    /// url for hold-and-delegate authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_and_delegate: Option<String>,

    /// allow local port forwarding (-l).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_local_port_forwarding: Option<bool>,

    /// allow remote port forwarding (-r).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_remote_port_forwarding: Option<bool>,

    /// session recording endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorders: Option<Vec<SocketAddr>>,

    /// what to do if session recording fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_recording_failure: Option<SshRecorderFailureAction>,
}

/// action to take when session recording fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SshRecorderFailureAction {
    /// reject connections if recording fails.
    RejectConnections,
    /// allow connections even if recording fails.
    AllowConnections,
}

// custom serializer for duration as nanoseconds
fn serialize_duration_nanos<S>(
    duration: &Option<std::time::Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match duration {
        Some(d) => serializer.serialize_i64(d.as_nanos() as i64),
        None => serializer.serialize_none(),
    }
}

fn deserialize_duration_nanos<'de, D>(
    deserializer: D,
) -> Result<Option<std::time::Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let nanos: Option<i64> = Option::deserialize(deserializer)?;
    Ok(nanos.map(|n| std::time::Duration::from_nanos(n as u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_policy_empty_serializes() {
        let policy = SshPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, r#"{"rules":[]}"#);
    }

    #[test]
    fn test_ssh_principal_node_ip_only() {
        let principal = SshPrincipal {
            node_ip: Some("100.64.0.2".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&principal).unwrap();
        assert_eq!(json, r#"{"nodeIP":"100.64.0.2"}"#);
    }

    #[test]
    fn test_ssh_action_accept_with_duration() {
        let action = SshAction {
            accept: Some(true),
            session_duration: Some(std::time::Duration::from_secs(86400)), // 24 hours
            allow_agent_forwarding: Some(true),
            allow_local_port_forwarding: Some(true),
            allow_remote_port_forwarding: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_string(&action).unwrap();

        // sessionDuration should be in nanoseconds: 86400 * 1e9 = 86400000000000
        assert!(json.contains(r#""sessionDuration":86400000000000"#));
        assert!(json.contains(r#""accept":true"#));
        assert!(json.contains(r#""allowAgentForwarding":true"#));
    }

    #[test]
    fn test_ssh_action_duration_deserialize() {
        let json = r#"{"accept":true,"sessionDuration":86400000000000}"#;
        let action: SshAction = serde_json::from_str(json).unwrap();

        assert_eq!(action.accept, Some(true));
        assert_eq!(
            action.session_duration,
            Some(std::time::Duration::from_secs(86400))
        );
    }

    #[test]
    fn test_ssh_rule_full() {
        let rule = SshRule {
            rule_expires: None,
            principals: vec![SshPrincipal {
                node_ip: Some("100.64.0.2".to_string()),
                ..Default::default()
            }],
            ssh_users: [
                ("*".to_string(), "=".to_string()),
                ("root".to_string(), String::new()),
            ]
            .into_iter()
            .collect(),
            action: SshAction {
                accept: Some(true),
                allow_agent_forwarding: Some(true),
                allow_local_port_forwarding: Some(true),
                allow_remote_port_forwarding: Some(true),
                ..Default::default()
            },
            accept_env: None,
        };

        let json = serde_json::to_string(&rule).unwrap();

        // verify camelcase field names
        assert!(json.contains(r#""principals""#));
        assert!(json.contains(r#""sshUsers""#));
        assert!(json.contains(r#""nodeIP""#));
        assert!(json.contains(r#""allowAgentForwarding""#));
    }

    #[test]
    fn test_ssh_policy_roundtrip() {
        let policy = SshPolicy {
            rules: vec![SshRule {
                rule_expires: None,
                principals: vec![SshPrincipal {
                    node_ip: Some("100.64.0.5".to_string()),
                    ..Default::default()
                }],
                ssh_users: [("ubuntu".to_string(), "ubuntu".to_string())]
                    .into_iter()
                    .collect(),
                action: SshAction {
                    accept: Some(true),
                    ..Default::default()
                },
                accept_env: None,
            }],
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: SshPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(policy, parsed);
    }

    #[test]
    fn test_ssh_recorder_failure_action() {
        let action = SshRecorderFailureAction::RejectConnections;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#""rejectConnections""#);

        let action = SshRecorderFailureAction::AllowConnections;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#""allowConnections""#);
    }
}
