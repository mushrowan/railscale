//! validated node name type for node identification.
//!
//! node names must:
//! - be 1-63 characters long (dns label compatible)
//! - Contain only lowercase alphanumeric characters and hyphens
//! - Not start or end with a hyphen

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// maximum length for a node name (dns label compatible).
pub const MAX_NODE_NAME_LEN: usize = 63;

/// a validated node name string.
///
/// node names are guaranteed to:
/// - Be 1-63 characters long
/// - Contain only lowercase alphanumeric characters and hyphens
/// - Not start or end with a hyphen
///
/// # Example
/// ```
/// use railscale_types::NodeName;
///
/// let name: NodeName = "my-server".parse().unwrap();
/// assert_eq!(name.as_str(), "my-server");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeName(String);

impl NodeName {
    /// create a new node name, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, NodeNameError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// sanitise an arbitrary string into a valid node name
    ///
    /// this normalises input by:
    /// - converting to lowercase
    /// - replacing invalid characters with hyphens
    /// - collapsing multiple hyphens
    /// - trimming leading/trailing hyphens
    /// - truncating to max length
    ///
    /// returns `None` if the result would be empty
    pub fn sanitise(s: &str) -> Option<Self> {
        // convert to lowercase and replace invalid chars with hyphens
        let sanitised: String = s
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    c
                } else {
                    '-'
                }
            })
            .collect();

        // collapse multiple hyphens and trim leading/trailing
        let mut result = String::new();
        let mut last_was_hyphen = true; // Treat start as if preceded by hyphen
        for c in sanitised.chars() {
            if c == '-' {
                if !last_was_hyphen && result.len() < MAX_NODE_NAME_LEN {
                    result.push(c);
                    last_was_hyphen = true;
                }
            } else if result.len() < MAX_NODE_NAME_LEN {
                result.push(c);
                last_was_hyphen = false;
            }
        }

        // trim trailing hyphen
        while result.ends_with('-') {
            result.pop();
        }

        if result.is_empty() {
            None
        } else {
            // this should always succeed given our sanitisation logic
            Self::new(result).ok()
        }
    }

    /// get the node name string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// consume the node name and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    fn validate(s: &str) -> Result<(), NodeNameError> {
        if s.is_empty() {
            return Err(NodeNameError::Empty);
        }

        if s.len() > MAX_NODE_NAME_LEN {
            return Err(NodeNameError::TooLong(s.len()));
        }

        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(NodeNameError::InvalidCharacters);
        }

        if s.starts_with('-') || s.ends_with('-') {
            return Err(NodeNameError::InvalidHyphenPosition);
        }

        Ok(())
    }
}

impl AsRef<str> for NodeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for NodeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for NodeName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for NodeName {
    type Err = NodeNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// serde: deserialize with validation
impl<'de> Deserialize<'de> for NodeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NodeName::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for NodeName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// error type for node name validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeNameError {
    /// node name cannot be empty.
    Empty,
    /// node name exceeds maximum length.
    TooLong(usize),
    /// node name contains invalid characters.
    InvalidCharacters,
    /// node name starts or ends with a hyphen.
    InvalidHyphenPosition,
}

impl fmt::Display for NodeNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeNameError::Empty => write!(f, "node name cannot be empty"),
            NodeNameError::TooLong(len) => {
                write!(
                    f,
                    "node name too long ({} chars, max {})",
                    len, MAX_NODE_NAME_LEN
                )
            }
            NodeNameError::InvalidCharacters => {
                write!(
                    f,
                    "node name must contain only lowercase letters, digits, and hyphens"
                )
            }
            NodeNameError::InvalidHyphenPosition => {
                write!(f, "node name cannot start or end with a hyphen")
            }
        }
    }
}

impl std::error::Error for NodeNameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_node_names() {
        assert!(NodeName::new("mynode").is_ok());
        assert!(NodeName::new("my-node").is_ok());
        assert!(NodeName::new("node123").is_ok());
        assert!(NodeName::new("a").is_ok());
        assert!(NodeName::new("123").is_ok());
        assert!(NodeName::new("a-b-c").is_ok());
    }

    #[test]
    fn test_empty_node_name() {
        assert_eq!(NodeName::new("").unwrap_err(), NodeNameError::Empty);
    }

    #[test]
    fn test_node_name_too_long() {
        let long = "a".repeat(MAX_NODE_NAME_LEN + 1);
        assert!(matches!(
            NodeName::new(long).unwrap_err(),
            NodeNameError::TooLong(_)
        ));

        // exactly max length should work
        let exact = "a".repeat(MAX_NODE_NAME_LEN);
        assert!(NodeName::new(exact).is_ok());
    }

    #[test]
    fn test_invalid_characters() {
        assert_eq!(
            NodeName::new("MyNode").unwrap_err(),
            NodeNameError::InvalidCharacters
        );
        assert_eq!(
            NodeName::new("my_node").unwrap_err(),
            NodeNameError::InvalidCharacters
        );
        assert_eq!(
            NodeName::new("my.node").unwrap_err(),
            NodeNameError::InvalidCharacters
        );
        assert_eq!(
            NodeName::new("my node").unwrap_err(),
            NodeNameError::InvalidCharacters
        );
    }

    #[test]
    fn test_hyphen_position() {
        assert_eq!(
            NodeName::new("-node").unwrap_err(),
            NodeNameError::InvalidHyphenPosition
        );
        assert_eq!(
            NodeName::new("node-").unwrap_err(),
            NodeNameError::InvalidHyphenPosition
        );
        assert_eq!(
            NodeName::new("-").unwrap_err(),
            NodeNameError::InvalidHyphenPosition
        );
    }

    #[test]
    fn test_as_str() {
        let name = NodeName::new("mynode").unwrap();
        assert_eq!(name.as_str(), "mynode");
    }

    #[test]
    fn test_into_inner() {
        let name = NodeName::new("mynode").unwrap();
        assert_eq!(name.into_inner(), "mynode");
    }

    #[test]
    fn test_partial_eq_str() {
        let name = NodeName::new("mynode").unwrap();
        assert_eq!(name, "mynode");
        assert_eq!(name, *"mynode");
    }

    #[test]
    fn test_display() {
        let name = NodeName::new("mynode").unwrap();
        assert_eq!(format!("{}", name), "mynode");
    }

    #[test]
    fn test_from_str() {
        let name: NodeName = "mynode".parse().unwrap();
        assert_eq!(name.as_str(), "mynode");

        let err: Result<NodeName, _> = "MyNode".parse();
        assert!(err.is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let name = NodeName::new("mynode").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"mynode\"");

        let parsed: NodeName = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, name);
    }

    #[test]
    fn test_serde_invalid() {
        let result: Result<NodeName, _> = serde_json::from_str("\"MyNode\"");
        assert!(result.is_err());

        let result: Result<NodeName, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitise_valid() {
        assert_eq!(NodeName::sanitise("mynode").unwrap().as_str(), "mynode");
        assert_eq!(NodeName::sanitise("my-node").unwrap().as_str(), "my-node");
    }

    #[test]
    fn test_sanitise_uppercase() {
        assert_eq!(NodeName::sanitise("MyNode").unwrap().as_str(), "mynode");
        assert_eq!(NodeName::sanitise("MY-NODE").unwrap().as_str(), "my-node");
    }

    #[test]
    fn test_sanitise_special_chars() {
        assert_eq!(
            NodeName::sanitise("my.node.local").unwrap().as_str(),
            "my-node-local"
        );
        assert_eq!(NodeName::sanitise("my_node").unwrap().as_str(), "my-node");
    }

    #[test]
    fn test_sanitise_leading_trailing() {
        assert_eq!(NodeName::sanitise(".mynode.").unwrap().as_str(), "mynode");
        assert_eq!(
            NodeName::sanitise("---mynode---").unwrap().as_str(),
            "mynode"
        );
    }

    #[test]
    fn test_sanitise_empty() {
        assert!(NodeName::sanitise("").is_none());
        assert!(NodeName::sanitise("...").is_none());
    }
}
