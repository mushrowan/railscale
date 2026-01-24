//! validated pre-auth key token type
//!
//! preauthkeytokens must:
//! - Start with "tskey-auth-"
//! - Have exactly 48 hex characters (24 random bytes)

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// length of the hex portion (24 bytes = 48 hex chars)
pub const PREAUTH_KEY_HEX_LEN: usize = 48;

/// the prefix for all pre-auth key tokens
pub const PREAUTH_KEY_PREFIX: &str = "tskey-auth-";

/// a validated pre-auth key token string
///
/// preauthkeytokens are guaranteed to:
/// - Start with "tskey-auth-"
/// - Have exactly 48 hex characters after the prefix
///
/// # Example
/// ```
/// use railscale_types::preauthkeytoken;
///
/// let token: preauthkeytoken = "tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef".parse().unwrap();
/// assert_eq!(token.hex_part(), "0123456789abcdef0123456789abcdef0123456789abcdef");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreAuthKeyToken(String);

impl PreAuthKeyToken {
    /// create a new pre-auth key token, validating the format
    pub fn new(s: impl Into<String>) -> Result<Self, PreAuthKeyTokenError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// generate a new random pre-auth key token
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: [u8; 24] = rng.random();
        Self(format!("{}{}", PREAUTH_KEY_PREFIX, hex::encode(bytes)))
    }

    /// get the full token string (e.g., "tskey-auth-...")
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// get just the hex portion (48 characters)
    pub fn hex_part(&self) -> &str {
        &self.0[PREAUTH_KEY_PREFIX.len()..]
    }

    /// consume the token and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }

    fn validate(s: &str) -> Result<(), PreAuthKeyTokenError> {
        if !s.starts_with(PREAUTH_KEY_PREFIX) {
            return Err(PreAuthKeyTokenError::MissingPrefix);
        }

        let hex_part = &s[PREAUTH_KEY_PREFIX.len()..];

        if hex_part.len() != PREAUTH_KEY_HEX_LEN {
            return Err(PreAuthKeyTokenError::InvalidLength {
                expected: PREAUTH_KEY_HEX_LEN,
                got: hex_part.len(),
            });
        }

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PreAuthKeyTokenError::InvalidHex);
        }

        Ok(())
    }
}

impl fmt::Display for PreAuthKeyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PreAuthKeyToken {
    type Err = PreAuthKeyTokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for PreAuthKeyToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// error type for invalid pre-auth key tokens
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreAuthKeyTokenError {
    /// token does not start with "tskey-auth-"
    #[error("pre-auth key token must start with 'tskey-auth-'")]
    MissingPrefix,

    /// hex portion has wrong length
    #[error("pre-auth key token hex portion must be {expected} characters, got {got}")]
    InvalidLength {
        /// expected length
        expected: usize,
        /// actual length
        got: usize,
    },

    /// hex portion contains non-hex characters
    #[error("pre-auth key token hex portion contains invalid characters")]
    InvalidHex,
}

// serde implementation - deserialize with validation
impl<'de> Deserialize<'de> for PreAuthKeyToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for PreAuthKeyToken {
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
    fn test_valid_token() {
        let token =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        assert_eq!(
            token.hex_part(),
            "0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert!(token.as_str().starts_with(PREAUTH_KEY_PREFIX));
    }

    #[test]
    fn test_generate_valid() {
        let token = PreAuthKeyToken::generate();
        assert!(token.as_str().starts_with(PREAUTH_KEY_PREFIX));
        assert_eq!(token.hex_part().len(), PREAUTH_KEY_HEX_LEN);
        // verify it passes validation
        PreAuthKeyToken::new(token.as_str()).unwrap();
    }

    #[test]
    fn test_invalid_prefix() {
        let result =
            PreAuthKeyToken::new("invalid-0123456789abcdef0123456789abcdef0123456789abcdef");
        assert!(matches!(result, Err(PreAuthKeyTokenError::MissingPrefix)));
    }

    #[test]
    fn test_invalid_length_too_short() {
        let result = PreAuthKeyToken::new("tskey-auth-0123456789abcdef");
        assert!(matches!(
            result,
            Err(PreAuthKeyTokenError::InvalidLength { .. })
        ));
    }

    #[test]
    fn test_invalid_length_too_long() {
        let result =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef0000");
        assert!(matches!(
            result,
            Err(PreAuthKeyTokenError::InvalidLength { .. })
        ));
    }

    #[test]
    fn test_invalid_hex() {
        let result =
            PreAuthKeyToken::new("tskey-auth-ghij456789abcdef0123456789abcdef0123456789abcdef");
        assert!(matches!(result, Err(PreAuthKeyTokenError::InvalidHex)));
    }

    #[test]
    fn test_from_str() {
        let token: PreAuthKeyToken = "tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef"
            .parse()
            .unwrap();
        assert_eq!(
            token.hex_part(),
            "0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let token = PreAuthKeyToken::generate();
        let json = serde_json::to_string(&token).unwrap();
        let parsed: PreAuthKeyToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, parsed);
    }

    #[test]
    fn test_serde_invalid_rejected() {
        let json = r#""invalid-key""#;
        let result: Result<PreAuthKeyToken, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let token =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        assert_eq!(
            format!("{}", token),
            "tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }
}
