//! policy container holding all grants.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::grant::Grant;

/// {
///"groups": {
/// "group:engineering": ["alice@example.com", "bob@example.com"]
/// },
///"grants": [
/// {"src": ["group:engineering"], "dst": ["tag:servers"], "ip": ["*"]}
///]
/// }
/// ```
/// group definitions mapping group names to member emails
///     "group:engineering": ["alice@example.com", "bob@example.com"]
/// group names should include the `group:` prefix (e.g., `"group:engineering"`)
/// members are identified by email address
///     {"src": ["group:engineering"], "dst": ["tag:servers"], "ip": ["*"]}
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

    /// all grants in this policy.
    #[serde(default)]
    pub grants: Vec<Grant>,
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

    /// validate all grants in the policy.
    pub fn validate(&self) -> Result<(), Error> {
        for (i, grant) in self.grants.iter().enumerate() {
            grant
                .validate()
                .map_err(|e| Error::InvalidGrant { index: i, cause: e })?;
        }
        Ok(())
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
}
