//! ssh policy input types for policy json
//!
//! these types represent the ssh section in the policy file, which is
//! transformed into wire-format sshpolicy for clients

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;

/// an ssh rule in the policy file.
///an ssh rule in the policy file
/// # Example
///# example
/// ```json
/// {
///   "action": "accept",
///   "src": ["group:admins"],
///   "dst": ["autogroup:self"],
///   "users": ["autogroup:nonroot"]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshPolicyRule {
    /// action to take: "accept" or "check".
    pub action: SshActionType,

    /// check period for "check" action (e.g., "24h", "1d").
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    pub check_period: Option<Duration>,

    /// source selectors (who can initiate ssh).
    pub src: Vec<String>,

    /// destination selectors (which nodes can be ssh'd to).
    pub dst: Vec<String>,

    /// ssh users allowed (usernames or "autogroup:nonroot").
    pub users: Vec<String>,
}

impl SshPolicyRule {
    /// validate the ssh rule.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.src.is_empty() {
            return Err(ValidationError::EmptySrc);
        }
        if self.dst.is_empty() {
            return Err(ValidationError::EmptyDst);
        }
        if self.users.is_empty() {
            return Err(ValidationError::EmptySshUsers);
        }
        if self.action == SshActionType::Check && self.check_period.is_none() {
            return Err(ValidationError::MissingCheckPeriod);
        }
        Ok(())
    }
}

/// ssh action type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshActionType {
    /// accept the connection immediately.
    Accept,
    /// require periodic re-authentication.
    Check,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_rule_accept() {
        let json = r#"{
            "action": "accept",
            "src": ["group:admins"],
            "dst": ["autogroup:self"],
            "users": ["autogroup:nonroot"]
        }"#;

        let rule: SshPolicyRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.action, SshActionType::Accept);
        assert_eq!(rule.src, vec!["group:admins"]);
        assert_eq!(rule.dst, vec!["autogroup:self"]);
        assert_eq!(rule.users, vec!["autogroup:nonroot"]);
        assert!(rule.check_period.is_none());
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_parse_ssh_rule_check() {
        let json = r#"{
            "action": "check",
            "checkPeriod": "24h",
            "src": ["group:admins"],
            "dst": ["tag:servers"],
            "users": ["root"]
        }"#;

        let rule: SshPolicyRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.action, SshActionType::Check);
        assert_eq!(rule.check_period, Some(Duration::from_secs(24 * 60 * 60)));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_src() {
        let rule = SshPolicyRule {
            action: SshActionType::Accept,
            check_period: None,
            src: vec![],
            dst: vec!["*".to_string()],
            users: vec!["ubuntu".to_string()],
        };
        assert!(matches!(rule.validate(), Err(ValidationError::EmptySrc)));
    }

    #[test]
    fn test_validate_empty_dst() {
        let rule = SshPolicyRule {
            action: SshActionType::Accept,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec![],
            users: vec!["ubuntu".to_string()],
        };
        assert!(matches!(rule.validate(), Err(ValidationError::EmptyDst)));
    }

    #[test]
    fn test_validate_empty_users() {
        let rule = SshPolicyRule {
            action: SshActionType::Accept,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec!["*".to_string()],
            users: vec![],
        };
        assert!(matches!(
            rule.validate(),
            Err(ValidationError::EmptySshUsers)
        ));
    }

    #[test]
    fn test_validate_check_without_period() {
        let rule = SshPolicyRule {
            action: SshActionType::Check,
            check_period: None,
            src: vec!["*".to_string()],
            dst: vec!["*".to_string()],
            users: vec!["ubuntu".to_string()],
        };
        assert!(matches!(
            rule.validate(),
            Err(ValidationError::MissingCheckPeriod)
        ));
    }

    #[test]
    fn test_roundtrip() {
        let rule = SshPolicyRule {
            action: SshActionType::Check,
            check_period: Some(Duration::from_secs(3600)),
            src: vec!["group:admins".to_string()],
            dst: vec!["tag:servers".to_string()],
            users: vec!["autogroup:nonroot".to_string(), "root".to_string()],
        };

        let json = serde_json::to_string(&rule).unwrap();
        let parsed: SshPolicyRule = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.action, rule.action);
        assert_eq!(parsed.check_period, rule.check_period);
        assert_eq!(parsed.src, rule.src);
        assert_eq!(parsed.dst, rule.dst);
        assert_eq!(parsed.users, rule.users);
    }
}
