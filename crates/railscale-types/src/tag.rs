//! validated tag type for node and acl tagging.
//!
//! tags must:
//! - Start with "tag:"
//! - Have a name of 1-50 lowercase alphanumeric characters (hyphens/underscores allowed)

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// maximum length for a tag name (after "tag:" prefix).
pub const MAX_TAG_NAME_LEN: usize = 50;

/// maximum number of tags per entity.
pub const MAX_TAGS: usize = 100;

/// a validated tag string.
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
    /// create a new tag, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, TagError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// get the full tag string (e.g., "tag:server").
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// get just the name portion (e.g., "server" from "tag:server").
    pub fn name(&self) -> &str {
        &self.0[4..] // Safe because we validated the "tag:" prefix
    }

    /// consume the tag and return the inner string.
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

/// error type for tag validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    /// tag must start with "tag:".
    #[error("tag must start with 'tag:'")]
    MissingPrefix,
    /// tag name cannot be empty.
    #[error("tag name cannot be empty")]
    EmptyName,
    /// tag name exceeds maximum length.
    #[error("tag name too long ({0} chars, max {MAX_TAG_NAME_LEN})")]
    NameTooLong(usize),
    /// tag name contains invalid characters.
    #[error("tag name must be lowercase alphanumeric with hyphens or underscores")]
    InvalidCharacters,
    /// too many tags in collection.
    #[error("too many tags ({0} provided, max {MAX_TAGS})")]
    TooManyTags(usize),
}

/// a validated collection of tags with count limit enforcement.
///
/// guarantees that:
/// - all tags are valid (via `Tag` newtype)
/// - count does not exceed `MAX_TAGS`
///
/// use this in api request types to avoid manual validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tags(Vec<Tag>);

impl Tags {
    /// create a new tags collection, validating the count.
    pub fn new(tags: Vec<Tag>) -> Result<Self, TagError> {
        if tags.len() > MAX_TAGS {
            return Err(TagError::TooManyTags(tags.len()));
        }
        Ok(Self(tags))
    }

    /// get the inner vec.
    pub fn into_inner(self) -> Vec<Tag> {
        self.0
    }

    /// get a reference to the inner vec.
    pub fn as_slice(&self) -> &[Tag] {
        &self.0
    }

    /// check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// get the count.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsRef<[Tag]> for Tags {
    fn as_ref(&self) -> &[Tag] {
        &self.0
    }
}

impl std::ops::Deref for Tags {
    type Target = [Tag];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for Tags {
    type Item = Tag;
    type IntoIter = std::vec::IntoIter<Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Tags {
    type Item = &'a Tag;
    type IntoIter = std::slice::Iter<'a, Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de> Deserialize<'de> for Tags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let tags = Vec::<Tag>::deserialize(deserializer)?;
        Tags::new(tags).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Tags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

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

    #[test]
    fn test_tags_valid() {
        let tags = Tags::new(vec![
            Tag::new("tag:web").unwrap(),
            Tag::new("tag:prod").unwrap(),
        ])
        .unwrap();
        assert_eq!(tags.len(), 2);
        assert!(!tags.is_empty());
    }

    #[test]
    fn test_tags_empty() {
        let tags = Tags::new(vec![]).unwrap();
        assert!(tags.is_empty());
        assert_eq!(tags.len(), 0);
    }

    #[test]
    fn test_tags_too_many() {
        let many_tags: Vec<Tag> = (0..=MAX_TAGS)
            .map(|i| Tag::new(format!("tag:t{}", i)).unwrap())
            .collect();
        let result = Tags::new(many_tags);
        assert!(matches!(result.unwrap_err(), TagError::TooManyTags(_)));
    }

    #[test]
    fn test_tags_serde_roundtrip() {
        let tags = Tags::new(vec![
            Tag::new("tag:web").unwrap(),
            Tag::new("tag:prod").unwrap(),
        ])
        .unwrap();
        let json = serde_json::to_string(&tags).unwrap();
        let parsed: Tags = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tags);
    }

    #[test]
    fn test_tags_serde_too_many_rejected() {
        // create json with too many tags
        let many: Vec<String> = (0..=MAX_TAGS).map(|i| format!("tag:t{}", i)).collect();
        let json = serde_json::to_string(&many).unwrap();
        let result: Result<Tags, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid tag names: lowercase alphanumeric + hyphens/underscores
    fn valid_tag_name_strategy() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,49}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_tag_roundtrips(name in valid_tag_name_strategy()) {
            let input = format!("tag:{}", name);
            if let Ok(tag) = Tag::new(&input) {
                // verify invariants
                prop_assert!(tag.as_str().starts_with("tag:"));
                prop_assert!(tag.name().len() <= MAX_TAG_NAME_LEN);
                prop_assert!(tag.name().chars().all(|c|
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
                ));

                // roundtrip through serde
                let json = serde_json::to_string(&tag).unwrap();
                let parsed: Tag = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(parsed, tag);
            }
        }

        #[test]
        fn arbitrary_string_never_panics(s in ".*") {
            // parsing arbitrary strings should never panic
            let _ = Tag::new(&s);
        }

        #[test]
        fn missing_prefix_rejected(name in "[a-z]{1,10}") {
            // without "tag:" prefix
            let result = Tag::new(&name);
            prop_assert!(matches!(result.unwrap_err(), TagError::MissingPrefix));
        }

        #[test]
        fn too_long_rejected(n in (MAX_TAG_NAME_LEN + 1)..=100usize) {
            let name = "a".repeat(n);
            let input = format!("tag:{}", name);
            let result = Tag::new(&input);
            prop_assert!(matches!(result.unwrap_err(), TagError::NameTooLong(_)));
        }

        #[test]
        fn uppercase_rejected(name in "[A-Z][a-z]{0,10}") {
            let input = format!("tag:{}", name);
            let result = Tag::new(&input);
            prop_assert!(matches!(result.unwrap_err(), TagError::InvalidCharacters));
        }
    }
}
