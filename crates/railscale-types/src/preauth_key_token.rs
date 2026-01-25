//! validated pre-auth key token type.
//!
//! preauthkeytokens must:
//! - Start with "tskey-auth-"
//! - Have exactly 48 hex characters (24 random bytes)

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// length of the hex portion (24 bytes = 48 hex chars).
pub const PREAUTH_KEY_HEX_LEN: usize = 48;

/// the prefix for all pre-auth key tokens.
pub const PREAUTH_KEY_PREFIX: &str = "tskey-auth-";

/// a validated pre-auth key token string.
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
    /// create a new pre-auth key token, validating the format.
    pub fn new(s: impl Into<String>) -> Result<Self, PreAuthKeyTokenError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// generate a new random pre-auth key token.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: [u8; 24] = rng.random();
        Self(format!("{}{}", PREAUTH_KEY_PREFIX, hex::encode(bytes)))
    }

    /// get the full token string (e.g., "tskey-auth-...").
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// get just the hex portion (48 characters).
    pub fn hex_part(&self) -> &str {
        &self.0[PREAUTH_KEY_PREFIX.len()..]
    }

    /// consume the token and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// get the prefix portion for display (tskey-auth- + first 12 hex chars).
    ///
    /// this is safe to display in logs and api responses as it does not
    /// contain enough entropy to reconstruct the full key.
    pub fn prefix(&self) -> &str {
        // "tskey-auth-" (11 chars) + 12 hex chars = 23 chars
        &self.0[..PREAUTH_KEY_PREFIX.len() + 12]
    }

    /// compute the sha-256 hash of the full token.
    ///
    /// this hash is suitable for secure storage and comparison.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        hasher.finalize().into()
    }

    /// verify that this token matches a stored hash using constant-time comparison.
    pub fn verify_hash(&self, stored_hash: &[u8]) -> bool {
        let computed = self.hash();
        computed.ct_eq(stored_hash).into()
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

/// error type for invalid pre-auth key tokens.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreAuthKeyTokenError {
    /// token does not start with "tskey-auth-".
    #[error("pre-auth key token must start with 'tskey-auth-'")]
    MissingPrefix,

    /// hex portion has wrong length.
    #[error("pre-auth key token hex portion must be {expected} characters, got {got}")]
    InvalidLength {
        /// expected length.
        expected: usize,
        /// actual length.
        got: usize,
    },

    /// hex portion contains non-hex characters.
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
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // strategy for valid 48-char hex strings
    fn valid_hex_strategy() -> impl Strategy<Value = String> {
        "[0-9a-f]{48}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_token_roundtrips(hex in valid_hex_strategy()) {
            let token_str = format!("{}{}", PREAUTH_KEY_PREFIX, hex);
            let token = PreAuthKeyToken::new(&token_str).unwrap();

            // check roundtrip
            prop_assert_eq!(token.as_str(), &token_str);
            prop_assert_eq!(token.hex_part(), &hex);

            // check serde roundtrip
            let json = serde_json::to_string(&token).unwrap();
            let parsed: PreAuthKeyToken = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(token.clone(), parsed);

            // check fromstr roundtrip
            let parsed2: PreAuthKeyToken = token_str.parse().unwrap();
            prop_assert_eq!(token, parsed2);
        }

        #[test]
        fn generated_tokens_are_valid(_seed in any::<u64>()) {
            let token = PreAuthKeyToken::generate();

            // hex part should be exactly 48 chars
            prop_assert!(token.as_str().starts_with(PREAUTH_KEY_PREFIX));

            // should be valid hex
            prop_assert_eq!(token.hex_part().len(), PREAUTH_KEY_HEX_LEN);

            // should pass validation
            prop_assert!(token.hex_part().chars().all(|c| c.is_ascii_hexdigit()));

            // should pass validation
            prop_assert!(PreAuthKeyToken::new(token.as_str()).is_ok());
        }

        #[test]
        fn missing_prefix_rejected(hex in valid_hex_strategy()) {
            // no prefix
            let result = PreAuthKeyToken::new(&hex);
            prop_assert!(matches!(result, Err(PreAuthKeyTokenError::MissingPrefix)));

            // wrong prefix
            let wrong_prefix = format!("tskey-wrong-{}", hex);
            let result2 = PreAuthKeyToken::new(&wrong_prefix);
            prop_assert!(matches!(result2, Err(PreAuthKeyTokenError::MissingPrefix)));
        }

        #[test]
        fn wrong_length_rejected(hex_len in 0usize..100) {
            prop_assume!(hex_len != PREAUTH_KEY_HEX_LEN);

            let hex: String = (0..hex_len).map(|i| char::from_digit((i % 16) as u32, 16).unwrap()).collect();
            let token_str = format!("{}{}", PREAUTH_KEY_PREFIX, hex);

            let result = PreAuthKeyToken::new(&token_str);
            match result {
                Err(PreAuthKeyTokenError::InvalidLength { expected: 48, got }) => {
                    prop_assert_eq!(got, hex_len);
                }
                _ => prop_assert!(false, "expected InvalidLength error"),
            }
        }

        #[test]
        fn arbitrary_string_never_panics(s in ".*") {
            // parsing arbitrary strings should never panic
            let _ = PreAuthKeyToken::new(&s);
            let _ = s.parse::<PreAuthKeyToken>();
        }

        #[test]
        fn hash_is_deterministic(hex in valid_hex_strategy()) {
            let token_str = format!("{}{}", PREAUTH_KEY_PREFIX, hex);
            let token1 = PreAuthKeyToken::new(&token_str).unwrap();
            let token2 = PreAuthKeyToken::new(&token_str).unwrap();

            prop_assert_eq!(token1.hash(), token2.hash());
        }

        #[test]
        fn verify_hash_works(hex in valid_hex_strategy()) {
            let token_str = format!("{}{}", PREAUTH_KEY_PREFIX, hex);
            let token = PreAuthKeyToken::new(&token_str).unwrap();
            let hash = token.hash();

            prop_assert!(token.verify_hash(&hash));
        }

        #[test]
        fn different_tokens_different_hashes(hex1 in valid_hex_strategy(), hex2 in valid_hex_strategy()) {
            prop_assume!(hex1 != hex2);

            let token1 = PreAuthKeyToken::new(format!("{}{}", PREAUTH_KEY_PREFIX, hex1)).unwrap();
            let token2 = PreAuthKeyToken::new(format!("{}{}", PREAUTH_KEY_PREFIX, hex2)).unwrap();

            prop_assert_ne!(token1.hash(), token2.hash());
        }

        #[test]
        fn prefix_method_returns_safe_portion(hex in valid_hex_strategy()) {
            let token_str = format!("{}{}", PREAUTH_KEY_PREFIX, hex);
            let token = PreAuthKeyToken::new(&token_str).unwrap();

            let prefix = token.prefix();
            // should be "tskey-auth-" (11 chars) + 12 hex chars = 23 chars
            prop_assert_eq!(prefix.len(), PREAUTH_KEY_PREFIX.len() + 12);
            prop_assert!(prefix.starts_with(PREAUTH_KEY_PREFIX));
        }
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

    #[test]
    fn test_prefix() {
        let token =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        // prefix is "tskey-auth-" + first 12 hex chars
        assert_eq!(token.prefix(), "tskey-auth-0123456789ab");
    }

    #[test]
    fn test_hash() {
        let token =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let hash = token.hash();
        // hash should be 32 bytes (sha-256)
        assert_eq!(hash.len(), 32);
        // same token should produce same hash
        let token2 =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        assert_eq!(token.hash(), token2.hash());
    }

    #[test]
    fn test_verify_hash() {
        let token =
            PreAuthKeyToken::new("tskey-auth-0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let hash = token.hash();
        // should verify correctly
        assert!(token.verify_hash(&hash));
        // different token should not verify
        let other_token = PreAuthKeyToken::generate();
        assert!(!other_token.verify_hash(&hash));
    }
}
