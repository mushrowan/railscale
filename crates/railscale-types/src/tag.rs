//! validated tag type for node and acl tagging
//!
//! tags must:
//! - Start with "tag:"
//! - Have a name of 1-50 lowercase alphanumeric characters (hyphens/underscores allowed)

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// maximum length for a tag name (after "tag:" prefix)
pub const MAX_TAG_NAME_LEN: usize = 50;

/// maximum number of tags per entity
pub const MAX_TAGS: usize = 100;

/// a validated tag string
///
/// tags are guaranteed to:
/// - Start with "tag:"
/// - Have a valid name portion (1-50 chars, lowercase alphanumeric with hyphens/underscores)
///
/// # Example
/// ```
/// use railscale_types::Tag;
///
/// let tag: Tag = "tag:server".parse().unwrap();
/// assert_eq!(tag.name(), "server");
/// assert_eq!(tag.as_str(), "tag:server");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag(String);

impl Tag {
    /// create a new tag, validating the format
    pub fn new(s: impl Into<String>) -> Result<Self, TagError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// get the full tag string (e.g., "tag:server")
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// get just the name portion (e.g., "server" from "tag:server")
    pub fn name(&self) -> &str {
        &self.0[4..] // Safe because we validated the "tag:" prefix
    }

    /// consume the tag and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }

    fn validate(s: &str) -> Result<(), TagError> {
        if !s.starts_with("tag:") {
            return Err(TagError::MissingPrefix);
        }

        let name = &s[4..];

        if name.is_empty() {
            return Err(TagError::EmptyName);
        }

        if name.len() > MAX_TAG_NAME_LEN {
            return Err(TagError::NameTooLong(name.len()));
        }

        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return Err(TagError::InvalidCharacters);
        }

        Ok(())
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Tag {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Tag {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Tag {
    type Err = TagError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// serde: deserialize with validation
impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Tag::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// error type for tag validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagError {
    /// tag must start with "tag:"
    MissingPrefix,
    /// tag name cannot be empty
    EmptyName,
    /// tag name exceeds maximum length
    NameTooLong(usize),
    /// tag name contains invalid characters
    InvalidCharacters,
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagError::MissingPrefix => write!(f, "tag must start with 'tag:'"),
            TagError::EmptyName => write!(f, "tag name cannot be empty"),
            TagError::NameTooLong(len) => {
                write!(
                    f,
                    "tag name too long ({} chars, max {})",
                    len, MAX_TAG_NAME_LEN
                )
            }
            TagError::InvalidCharacters => {
                write!(
                    f,
                    "tag name must be lowercase alphanumeric with hyphens or underscores"
                )
            }
        }
    }
}

impl std::error::Error for TagError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tags() {
        assert!(Tag::new("tag:server").is_ok());
        assert!(Tag::new("tag:web-server").is_ok());
        assert!(Tag::new("tag:db_server").is_ok());
        assert!(Tag::new("tag:prod123").is_ok());
        assert!(Tag::new("tag:a").is_ok());
    }

    #[test]
    fn test_invalid_tags() {
        assert_eq!(Tag::new("server").unwrap_err(), TagError::MissingPrefix);
        assert_eq!(Tag::new("tag:").unwrap_err(), TagError::EmptyName);
        assert_eq!(
            Tag::new("tag:Server").unwrap_err(),
            TagError::InvalidCharacters
        );
        assert_eq!(
            Tag::new("tag:has spaces").unwrap_err(),
            TagError::InvalidCharacters
        );
    }

    #[test]
    fn test_tag_too_long() {
        let long_name = "a".repeat(MAX_TAG_NAME_LEN + 1);
        let tag_str = format!("tag:{}", long_name);
        assert!(matches!(
            Tag::new(tag_str).unwrap_err(),
            TagError::NameTooLong(_)
        ));
    }

    #[test]
    fn test_tag_name() {
        let tag = Tag::new("tag:server").unwrap();
        assert_eq!(tag.name(), "server");
        assert_eq!(tag.as_str(), "tag:server");
    }

    #[test]
    fn test_serde_roundtrip() {
        let tag = Tag::new("tag:server").unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, "\"tag:server\"");

        let parsed: Tag = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tag);
    }

    #[test]
    fn test_serde_invalid() {
        let result: Result<Tag, _> = serde_json::from_str("\"invalid\"");
        assert!(result.is_err());
    }
}
