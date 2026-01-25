//! validated username type for user identification.
//!
//! usernames must:
//! - be 1-63 characters long (dns label compatible)
//! - Contain only lowercase alphanumeric characters and hyphens
//! - Not start or end with a hyphen

use std::fmt;
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
/// let username: Username = "alice".parse().unwrap();
/// assert_eq!(username.as_str(), "alice");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
                if !last_was_hyphen && result.len() < MAX_USERNAME_LEN {
                    result.push(c);
                    last_was_hyphen = true;
                }
            } else if result.len() < MAX_USERNAME_LEN {
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

    /// get the username string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// consume the username and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    fn validate(s: &str) -> Result<(), UsernameError> {
        if s.is_empty() {
            return Err(UsernameError::Empty);
        }

        if s.len() > MAX_USERNAME_LEN {
            return Err(UsernameError::TooLong(s.len()));
        }

        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(UsernameError::InvalidCharacters);
        }

        if s.starts_with('-') || s.ends_with('-') {
            return Err(UsernameError::InvalidHyphenPosition);
        }

        Ok(())
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
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

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameError {
    /// username cannot be empty.
    Empty,
    /// username exceeds maximum length.
    TooLong(usize),
    /// username contains invalid characters.
    InvalidCharacters,
    /// username starts or ends with a hyphen.
    InvalidHyphenPosition,
}

impl fmt::Display for UsernameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsernameError::Empty => write!(f, "username cannot be empty"),
            UsernameError::TooLong(len) => {
                write!(
                    f,
                    "username too long ({} chars, max {})",
                    len, MAX_USERNAME_LEN
                )
            }
            UsernameError::InvalidCharacters => {
                write!(
                    f,
                    "username must contain only lowercase letters, digits, and hyphens"
                )
            }
            UsernameError::InvalidHyphenPosition => {
                write!(f, "username cannot start or end with a hyphen")
            }
        }
    }
}

impl std::error::Error for UsernameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(Username::new("alice").is_ok());
        assert!(Username::new("alice-bob").is_ok());
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
            Username::new("Alice").unwrap_err(),
            UsernameError::InvalidCharacters
        );
        assert_eq!(
            Username::new("alice_bob").unwrap_err(),
            UsernameError::InvalidCharacters
        );
        assert_eq!(
            Username::new("alice@example.com").unwrap_err(),
            UsernameError::InvalidCharacters
        );
        assert_eq!(
            Username::new("alice bob").unwrap_err(),
            UsernameError::InvalidCharacters
        );
    }

    #[test]
    fn test_hyphen_position() {
        assert_eq!(
            Username::new("-alice").unwrap_err(),
            UsernameError::InvalidHyphenPosition
        );
        assert_eq!(
            Username::new("alice-").unwrap_err(),
            UsernameError::InvalidHyphenPosition
        );
        assert_eq!(
            Username::new("-").unwrap_err(),
            UsernameError::InvalidHyphenPosition
        );
    }

    #[test]
    fn test_as_str() {
        let username = Username::new("alice").unwrap();
        assert_eq!(username.as_str(), "alice");
    }

    #[test]
    fn test_into_inner() {
        let username = Username::new("alice").unwrap();
        assert_eq!(username.into_inner(), "alice");
    }

    #[test]
    fn test_partial_eq_str() {
        let username = Username::new("alice").unwrap();
        assert_eq!(username, "alice");
        assert_eq!(username, *"alice");
    }

    #[test]
    fn test_display() {
        let username = Username::new("alice").unwrap();
        assert_eq!(format!("{}", username), "alice");
    }

    #[test]
    fn test_from_str() {
        let username: Username = "alice".parse().unwrap();
        assert_eq!(username.as_str(), "alice");

        let err: Result<Username, _> = "Alice".parse();
        assert!(err.is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let username = Username::new("alice").unwrap();
        let json = serde_json::to_string(&username).unwrap();
        assert_eq!(json, "\"alice\"");

        let parsed: Username = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, username);
    }

    #[test]
    fn test_serde_invalid() {
        let result: Result<Username, _> = serde_json::from_str("\"Alice\"");
        assert!(result.is_err());

        let result: Result<Username, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitise_valid() {
        // already valid
        assert_eq!(Username::sanitise("alice").unwrap().as_str(), "alice");
        assert_eq!(
            Username::sanitise("alice-bob").unwrap().as_str(),
            "alice-bob"
        );
    }

    #[test]
    fn test_sanitise_uppercase() {
        // uppercase converted to lowercase
        assert_eq!(Username::sanitise("Alice").unwrap().as_str(), "alice");
        assert_eq!(Username::sanitise("ALICE").unwrap().as_str(), "alice");
    }

    #[test]
    fn test_sanitise_special_chars() {
        // special chars become hyphens
        assert_eq!(
            Username::sanitise("alice@example.com").unwrap().as_str(),
            "alice-example-com"
        );
        assert_eq!(
            Username::sanitise("alice_bob").unwrap().as_str(),
            "alice-bob"
        );
        assert_eq!(
            Username::sanitise("alice.bob").unwrap().as_str(),
            "alice-bob"
        );
    }

    #[test]
    fn test_sanitise_leading_trailing() {
        // leading/trailing invalid chars trimmed
        assert_eq!(Username::sanitise("@alice@").unwrap().as_str(), "alice");
        assert_eq!(Username::sanitise("---alice---").unwrap().as_str(), "alice");
    }

    #[test]
    fn test_sanitise_collapse_hyphens() {
        // multiple hyphens collapsed
        assert_eq!(
            Username::sanitise("alice---bob").unwrap().as_str(),
            "alice-bob"
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
