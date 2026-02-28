//! validated username type for user identification.
//!
//! usernames must:
//! - be 1-63 characters long (dns label compatible)
//! - Contain only lowercase alphanumeric characters and hyphens
//! - Not start or end with a hyphen

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// maximum length for a username (dns label compatible).
pub const MAX_USERNAME_LEN: usize = 63;

/// a validated username string.
///
/// usernames are guaranteed to:
/// - Be 1-63 characters long
/// - Contain only lowercase alphanumeric characters and hyphens
/// - Not start or end with a hyphen
///
/// # Example
/// ```
/// use railscale_types::Username;
///
/// let username: Username = "alicja".parse().unwrap();
/// assert_eq!(username.as_str(), "alicja");
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, derive_more::Display, derive_more::AsRef,
)]
#[as_ref(str)]
pub struct Username(String);

impl Username {
    /// create a new username, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, UsernameError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// sanitise an arbitrary string into a valid username
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
        crate::dns_label::sanitise(s, MAX_USERNAME_LEN).and_then(|r| Self::new(r).ok())
    }

    /// get the username string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// consume the username and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    fn validate(s: &str) -> Result<(), UsernameError> {
        crate::dns_label::validate(s, MAX_USERNAME_LEN).map_err(|e| match e {
            crate::dns_label::DnsLabelError::Empty => UsernameError::Empty,
            crate::dns_label::DnsLabelError::TooLong(len) => UsernameError::TooLong(len),
            crate::dns_label::DnsLabelError::InvalidCharacters => UsernameError::InvalidCharacters,
            crate::dns_label::DnsLabelError::InvalidHyphenPosition => {
                UsernameError::InvalidHyphenPosition
            }
        })
    }
}

impl PartialEq<str> for Username {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Username {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl FromStr for Username {
    type Err = UsernameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

// serde: deserialize with validation
impl<'de> Deserialize<'de> for Username {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Username::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Username {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// error type for username validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    /// username cannot be empty.
    #[error("username cannot be empty")]
    Empty,
    /// username exceeds maximum length.
    #[error("username too long ({0} chars, max {MAX_USERNAME_LEN})")]
    TooLong(usize),
    /// username contains invalid characters.
    #[error("username must contain only lowercase letters, digits, and hyphens")]
    InvalidCharacters,
    /// username starts or ends with a hyphen.
    #[error("username cannot start or end with a hyphen")]
    InvalidHyphenPosition,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(Username::new("alicja").is_ok());
        assert!(Username::new("alicja-ro").is_ok());
        assert!(Username::new("user123").is_ok());
        assert!(Username::new("a").is_ok());
        assert!(Username::new("123").is_ok());
        assert!(Username::new("a-b-c").is_ok());
    }

    #[test]
    fn test_empty_username() {
        assert_eq!(Username::new("").unwrap_err(), UsernameError::Empty);
    }

    #[test]
    fn test_username_too_long() {
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(matches!(
            Username::new(long).unwrap_err(),
            UsernameError::TooLong(_)
        ));

        // exactly max length should work
        let exact = "a".repeat(MAX_USERNAME_LEN);
        assert!(Username::new(exact).is_ok());
    }

    #[test]
    fn test_invalid_characters() {
        assert_eq!(
            Username::new("Alicja").unwrap_err(),
            UsernameError::InvalidCharacters
        );
        assert_eq!(
            Username::new("alice_bob").unwrap_err(),
            UsernameError::InvalidCharacters
        );
        assert_eq!(
            Username::new("alicja@example.com").unwrap_err(),
            UsernameError::InvalidCharacters
        );
        assert_eq!(
            Username::new("alicja ro").unwrap_err(),
            UsernameError::InvalidCharacters
        );
    }

    #[test]
    fn test_hyphen_position() {
        assert_eq!(
            Username::new("-alicja").unwrap_err(),
            UsernameError::InvalidHyphenPosition
        );
        assert_eq!(
            Username::new("alicja-").unwrap_err(),
            UsernameError::InvalidHyphenPosition
        );
        assert_eq!(
            Username::new("-").unwrap_err(),
            UsernameError::InvalidHyphenPosition
        );
    }

    #[test]
    fn test_as_str() {
        let username = Username::new("alicja").unwrap();
        assert_eq!(username.as_str(), "alicja");
    }

    #[test]
    fn test_into_inner() {
        let username = Username::new("alicja").unwrap();
        assert_eq!(username.into_inner(), "alicja");
    }

    #[test]
    fn test_partial_eq_str() {
        let username = Username::new("alicja").unwrap();
        assert_eq!(username, "alicja");
        assert_eq!(username, *"alicja");
    }

    #[test]
    fn test_display() {
        let username = Username::new("alicja").unwrap();
        assert_eq!(format!("{}", username), "alicja");
    }

    #[test]
    fn test_from_str() {
        let username: Username = "alicja".parse().unwrap();
        assert_eq!(username.as_str(), "alicja");

        let err: Result<Username, _> = "Alicja".parse();
        assert!(err.is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let username = Username::new("alicja").unwrap();
        let json = serde_json::to_string(&username).unwrap();
        assert_eq!(json, "\"alicja\"");

        let parsed: Username = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, username);
    }

    #[test]
    fn test_serde_invalid() {
        let result: Result<Username, _> = serde_json::from_str("\"Alicja\"");
        assert!(result.is_err());

        let result: Result<Username, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitise_valid() {
        // already valid
        assert_eq!(Username::sanitise("alicja").unwrap().as_str(), "alicja");
        assert_eq!(
            Username::sanitise("alicja-ro").unwrap().as_str(),
            "alicja-ro"
        );
    }

    #[test]
    fn test_sanitise_uppercase() {
        // uppercase converted to lowercase
        assert_eq!(Username::sanitise("Alicja").unwrap().as_str(), "alicja");
        assert_eq!(Username::sanitise("ALICJA").unwrap().as_str(), "alicja");
    }

    #[test]
    fn test_sanitise_special_chars() {
        // special chars become hyphens
        assert_eq!(
            Username::sanitise("alicja@example.com").unwrap().as_str(),
            "alicja-example-com"
        );
        assert_eq!(
            Username::sanitise("alicja_ro").unwrap().as_str(),
            "alicja-ro"
        );
        assert_eq!(
            Username::sanitise("alicja.ro").unwrap().as_str(),
            "alicja-ro"
        );
    }

    #[test]
    fn test_sanitise_leading_trailing() {
        // leading/trailing invalid chars trimmed
        assert_eq!(Username::sanitise("@alicja@").unwrap().as_str(), "alicja");
        assert_eq!(
            Username::sanitise("---alicja---").unwrap().as_str(),
            "alicja"
        );
    }

    #[test]
    fn test_sanitise_collapse_hyphens() {
        // multiple hyphens collapsed
        assert_eq!(
            Username::sanitise("alicja---ro").unwrap().as_str(),
            "alicja-ro"
        );
        assert_eq!(Username::sanitise("a   b   c").unwrap().as_str(), "a-b-c");
    }

    #[test]
    fn test_sanitise_empty() {
        // empty or all-invalid returns None
        assert!(Username::sanitise("").is_none());
        assert!(Username::sanitise("@@@").is_none());
        assert!(Username::sanitise("---").is_none());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid username patterns: [a-z0-9](-?[a-z0-9])*
    fn valid_username_strategy() -> impl Strategy<Value = String> {
        // start with alphanumeric, then optional groups of (hyphen + alphanumeric)
        "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?".prop_filter("no leading/trailing hyphens", |s| {
            !s.starts_with('-') && !s.ends_with('-')
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_username_roundtrips(name in valid_username_strategy()) {
            if let Ok(username) = Username::new(&name) {
                // verify invariants
                prop_assert!(username.as_str().len() <= MAX_USERNAME_LEN);
                prop_assert!(!username.as_str().starts_with('-'));
                prop_assert!(!username.as_str().ends_with('-'));
                prop_assert!(username.as_str().chars().all(|c|
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
                ));

                // roundtrip through serde
                let json = serde_json::to_string(&username).unwrap();
                let parsed: Username = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(parsed, username);
            }
        }

        #[test]
        fn arbitrary_string_never_panics(s in ".*") {
            // parsing arbitrary strings should never panic
            let _ = Username::new(&s);
        }

        #[test]
        fn too_long_rejected(n in (MAX_USERNAME_LEN + 1)..=200usize) {
            let long = "a".repeat(n);
            let result = Username::new(&long);
            prop_assert!(result.is_err());
        }

        #[test]
        fn uppercase_rejected(s in "[A-Z][a-z]{0,10}") {
            let result = Username::new(&s);
            prop_assert!(result.is_err());
        }

        #[test]
        fn leading_hyphen_rejected(s in "[a-z0-9]{1,10}") {
            let input = format!("-{}", s);
            let result = Username::new(&input);
            prop_assert!(matches!(result.unwrap_err(), UsernameError::InvalidHyphenPosition));
        }

        #[test]
        fn trailing_hyphen_rejected(s in "[a-z0-9]{1,10}") {
            let input = format!("{}-", s);
            let result = Username::new(&input);
            prop_assert!(matches!(result.unwrap_err(), UsernameError::InvalidHyphenPosition));
        }
    }
}
