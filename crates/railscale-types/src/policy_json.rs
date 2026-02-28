//! validated policy json type with size limits
//!
//! policy json must not exceed the maximum size to prevent DoS attacks

use std::fmt;

use serde::{Deserialize, Serialize};

/// maximum size for policy json in bytes (1MB)
pub const MAX_POLICY_SIZE: usize = 1024 * 1024;

/// a validated policy json string with size limits
///
/// policyJson is guaranteed to:
/// - Not exceed [`MAX_POLICY_SIZE`] bytes
///
/// the actual json parsing and policy validation happens separately;
/// this type only enforces size limits at the transport layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyJson(String);

impl PolicyJson {
    /// create a new PolicyJson, validating size limits
    pub fn new(s: impl Into<String>) -> Result<Self, PolicyJsonError> {
        let s = s.into();
        if s.len() > MAX_POLICY_SIZE {
            return Err(PolicyJsonError::TooLarge(s.len()));
        }
        Ok(Self(s))
    }

    /// get the policy json as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// consume the PolicyJson and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for PolicyJson {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// serde: deserialize with validation
impl<'de> Deserialize<'de> for PolicyJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PolicyJson::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for PolicyJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// error type for policy json validation
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyJsonError {
    /// policy exceeds maximum size
    // intentionally generic - don't leak the actual size
    #[error("policy exceeds maximum size")]
    TooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_policy_json() {
        let json = r#"{"grants": []}"#;
        let policy = PolicyJson::new(json).unwrap();
        assert_eq!(policy.as_str(), json);
    }

    #[test]
    fn test_policy_json_at_limit() {
        // create json that's exactly at the limit
        let padding = "x".repeat(MAX_POLICY_SIZE - 20);
        let json = format!(r#"{{"data": "{}"}}"#, padding);
        assert!(json.len() <= MAX_POLICY_SIZE);
        assert!(PolicyJson::new(&json).is_ok());
    }

    #[test]
    fn test_policy_json_exceeds_limit() {
        let large = "x".repeat(MAX_POLICY_SIZE + 1);
        let err = PolicyJson::new(&large).unwrap_err();
        assert!(matches!(err, PolicyJsonError::TooLarge(_)));
        // error message should be generic (not leak size)
        assert_eq!(err.to_string(), "policy exceeds maximum size");
    }

    #[test]
    fn test_serde_valid() {
        let json = r#"{"grants": []}"#;
        let serialized = format!(r#""{}""#, json.replace('"', r#"\""#));
        let policy: PolicyJson = serde_json::from_str(&serialized).unwrap();
        assert_eq!(policy.as_str(), json);
    }

    #[test]
    fn test_serde_too_large() {
        let large = "x".repeat(MAX_POLICY_SIZE + 1);
        let serialized = format!(r#""{}""#, large);
        let result: Result<PolicyJson, _> = serde_json::from_str(&serialized);
        assert!(result.is_err());
        // check error message doesn't leak size info
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("policy exceeds maximum size"));
    }

    #[test]
    fn test_into_inner() {
        let json = r#"{"grants": []}"#;
        let policy = PolicyJson::new(json).unwrap();
        assert_eq!(policy.into_inner(), json);
    }
}
