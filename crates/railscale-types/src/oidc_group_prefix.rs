//! validated oidc group prefix type.
//!
//! when syncing oidc groups to policy groups, an optional prefix can be applied.
//! for example, with prefix "oidc-", an oidc group "engineering" becomes "oidc-engineering"
//! for matching against `group:oidc-engineering` in grants.
//!
//! prefixes must:
//! - Be 1-50 characters
//! - Not contain colons (reserved for selector syntax like `group:`)
//! - Contain only alphanumeric characters, hyphens, or underscores

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// maximum length for an oidc group prefix.
pub const MAX_OIDC_GROUP_PREFIX_LEN: usize = 50;

/// a validated oidc group prefix string.
///
/// used to namespace oidc groups when mapping them to policy groups.
/// for example, prefix "oidc-" transforms group "engineering" into "oidc-engineering".
///
/// # Example
/// ```
/// use railscale_types::OidcGroupPrefix;
///
/// let prefix: OidcGroupPrefix = "oidc-".parse().unwrap();
/// assert_eq!(prefix.apply("engineering"), "oidc-engineering");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Display, derive_more::AsRef)]
#[as_ref(str)]
pub struct OidcGroupPrefix(String);

impl OidcGroupPrefix {
    /// create a new oidc group prefix, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, OidcGroupPrefixError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// get the prefix string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// apply the prefix to a group name.
    ///
    /// # Example
    /// ```
    /// use railscale_types::OidcGroupPrefix;
    ///
    /// let prefix = OidcGroupPrefix::new("oidc-").unwrap();
    /// assert_eq!(prefix.apply("engineering"), "oidc-engineering");
    /// ```
    pub fn apply(&self, group: &str) -> String {
        format!("{}{}", self.0, group)
    }

    /// consume the prefix and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    fn validate(s: &str) -> Result<(), OidcGroupPrefixError> {
        if s.is_empty() {
            return Err(OidcGroupPrefixError::Empty);
        }

        if s.len() > MAX_OIDC_GROUP_PREFIX_LEN {
            return Err(OidcGroupPrefixError::TooLong(s.len()));
        }

        if s.contains(':') {
            return Err(OidcGroupPrefixError::ContainsColon);
        }

        // allow alphanumeric, hyphens, underscores (more permissive than tags)
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(OidcGroupPrefixError::InvalidCharacters);
        }

        Ok(())
    }
}

impl FromStr for OidcGroupPrefix {
    type Err = OidcGroupPrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// serde: deserialize with validation
impl<'de> Deserialize<'de> for OidcGroupPrefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        OidcGroupPrefix::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for OidcGroupPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// error type for oidc group prefix validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcGroupPrefixError {
    /// prefix cannot be empty.
    #[error("OIDC group prefix cannot be empty")]
    Empty,
    /// prefix exceeds maximum length.
    #[error("OIDC group prefix too long ({0} chars, max {MAX_OIDC_GROUP_PREFIX_LEN})")]
    TooLong(usize),
    /// prefix cannot contain colons (reserved for selector syntax).
    #[error("OIDC group prefix cannot contain colons")]
    ContainsColon,
    /// prefix contains invalid characters.
    #[error("OIDC group prefix must be alphanumeric with hyphens or underscores")]
    InvalidCharacters,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_prefixes() {
        assert!(OidcGroupPrefix::new("oidc-").is_ok());
        assert!(OidcGroupPrefix::new("oidc_").is_ok());
        assert!(OidcGroupPrefix::new("OIDC-").is_ok());
        assert!(OidcGroupPrefix::new("prefix123").is_ok());
        assert!(OidcGroupPrefix::new("a").is_ok());
    }

    #[test]
    fn test_invalid_prefixes() {
        // empty
        assert_eq!(
            OidcGroupPrefix::new("").unwrap_err(),
            OidcGroupPrefixError::Empty
        );

        // contains colon
        assert_eq!(
            OidcGroupPrefix::new("oidc:").unwrap_err(),
            OidcGroupPrefixError::ContainsColon
        );
        assert_eq!(
            OidcGroupPrefix::new("group:").unwrap_err(),
            OidcGroupPrefixError::ContainsColon
        );

        // invalid characters
        assert_eq!(
            OidcGroupPrefix::new("has spaces").unwrap_err(),
            OidcGroupPrefixError::InvalidCharacters
        );
        assert_eq!(
            OidcGroupPrefix::new("has.dot").unwrap_err(),
            OidcGroupPrefixError::InvalidCharacters
        );
    }

    #[test]
    fn test_prefix_too_long() {
        let long = "a".repeat(MAX_OIDC_GROUP_PREFIX_LEN + 1);
        assert!(matches!(
            OidcGroupPrefix::new(long).unwrap_err(),
            OidcGroupPrefixError::TooLong(_)
        ));
    }

    #[test]
    fn test_apply_prefix() {
        let prefix = OidcGroupPrefix::new("oidc-").unwrap();
        assert_eq!(prefix.apply("engineering"), "oidc-engineering");
        assert_eq!(prefix.apply("admins"), "oidc-admins");
    }

    #[test]
    fn test_serde_roundtrip() {
        let prefix = OidcGroupPrefix::new("oidc-").unwrap();
        let json = serde_json::to_string(&prefix).unwrap();
        assert_eq!(json, "\"oidc-\"");

        let parsed: OidcGroupPrefix = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, prefix);
    }

    #[test]
    fn test_serde_invalid() {
        // contains colon - should fail validation
        let result: Result<OidcGroupPrefix, _> = serde_json::from_str("\"group:\"");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid prefix patterns: alphanumeric + hyphens/underscores
    fn valid_prefix_strategy() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,50}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_prefix_roundtrips(prefix in valid_prefix_strategy()) {
            if let Ok(p) = OidcGroupPrefix::new(&prefix) {
                // verify invariants
                prop_assert!(!p.as_str().is_empty());
                prop_assert!(p.as_str().len() <= MAX_OIDC_GROUP_PREFIX_LEN);
                prop_assert!(!p.as_str().contains(':'));

                // roundtrip through serde
                let json = serde_json::to_string(&p).unwrap();
                let parsed: OidcGroupPrefix = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(parsed, p);
            }
        }

        #[test]
        fn apply_preserves_prefix(prefix in valid_prefix_strategy(), group in "[a-z]{1,20}") {
            if let Ok(p) = OidcGroupPrefix::new(&prefix) {
                let result = p.apply(&group);
                prop_assert!(result.starts_with(p.as_str()));
                prop_assert!(result.ends_with(&group));
            }
        }

        #[test]
        fn arbitrary_string_never_panics(s in ".*") {
            // parsing arbitrary strings should never panic
            let _ = OidcGroupPrefix::new(&s);
        }

        #[test]
        fn colon_rejected(s in "[a-z]{0,5}:[a-z]{0,5}") {
            let result = OidcGroupPrefix::new(&s);
            prop_assert!(matches!(result.unwrap_err(), OidcGroupPrefixError::ContainsColon));
        }

        #[test]
        fn too_long_rejected(n in (MAX_OIDC_GROUP_PREFIX_LEN + 1)..=100usize) {
            let long = "a".repeat(n);
            let result = OidcGroupPrefix::new(&long);
            prop_assert!(matches!(result.unwrap_err(), OidcGroupPrefixError::TooLong(_)));
        }
    }
}
