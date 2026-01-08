//! policy container holding all grants.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::grant::Grant;

/// the complete policy document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    /// all grants in this policy.
    #[serde(default)]
    pub grants: Vec<Grant>,
    // future: postures, hosts, groups definitions
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
