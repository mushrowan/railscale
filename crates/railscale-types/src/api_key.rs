//! api key type for authenticating api requests.
//!
//! api keys allow programmatic access to the railscale api for automation,
//! integrations, and tooling.
//!
//! ## Security Model
//!
//! api keys use a split-token pattern for secure storage:
//! - **Full key** (given to user once): `rsapi_{selector}_{verifier}`
//! - **Selector** (stored in DB, indexed): Used for O(1) lookup
//! - **Verifier hash** (stored in DB): SHA-256 hash for verification
//!
//! this design ensures:
//! - Database lookups are timing-safe (lookup by selector, not by comparing hashes)
//! - Keys cannot be recovered from database breach (only hash is stored)
//! - Verification uses constant-time comparison

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::user::UserId;

/// prefix for railscale api keys.
const API_KEY_PREFIX: &str = "rsapi_";

/// size of the selector in bytes (16 bytes = ~22 base64 chars).
const SELECTOR_BYTES: usize = 16;

/// size of the verifier in bytes (16 bytes = ~22 base64 chars).
const VERIFIER_BYTES: usize = 16;

/// a generated api key secret with its components for storage.
///
/// this struct is returned when generating a new api key. the `full_key` should
/// be shown to the user exactly once, while `selector` and `verifier_hash` are
/// stored in the database.
#[derive(Debug, Clone)]
pub struct ApiKeySecret {
    /// the full api key to give to the user (only shown once).
    /// format: `rsapi_{selector}_{verifier}`
    pub full_key: String,

    /// the selector portion (stored in db, used for lookup).
    pub selector: String,

    /// sha-256 hash of the verifier (stored in db, hex-encoded).
    pub verifier_hash: String,
}

impl ApiKeySecret {
    /// generate a new api key with cryptographically secure random values.
    ///
    /// returns the full key (for the user) and the components to store in the database.
    ///
    /// key format: `rsapi_{selector}_{verifier}` where both are hex-encoded.
    pub fn generate() -> Self {
        let mut rng = rand::rng();

        // generate random bytes
        let mut selector_bytes = [0u8; SELECTOR_BYTES];
        let mut verifier_bytes = [0u8; VERIFIER_BYTES];
        rng.fill_bytes(&mut selector_bytes);
        rng.fill_bytes(&mut verifier_bytes);

        // encode as hex (deterministic length, no separator conflicts)
        let selector = hex::encode(selector_bytes);
        let verifier = hex::encode(verifier_bytes);

        // hash the verifier for storage (hash the hex string, not raw bytes)
        let verifier_hash = hex::encode(Sha256::digest(verifier.as_bytes()));

        // build the full key
        let full_key = format!("{API_KEY_PREFIX}{selector}_{verifier}");

        Self {
            full_key,
            selector,
            verifier_hash,
        }
    }

    /// verify a user-provided token against stored selector and verifier hash.
    ///
    /// this function uses constant-time comparison to prevent timing attacks.
    pub fn verify(token: &str, stored_selector: &str, stored_verifier_hash: &str) -> bool {
        // must start with prefix
        let Some(without_prefix) = token.strip_prefix(API_KEY_PREFIX) else {
            return false;
        };

        // must have selector_verifier format (hex selector is 32 chars)
        let Some((selector, verifier)) = without_prefix.split_once('_') else {
            return false;
        };

        // check selector matches (this is what db lookup would do)
        if selector != stored_selector {
            return false;
        }

        // hash the provided verifier and compare with constant-time comparison
        let provided_hash = Sha256::digest(verifier.as_bytes());
        let Ok(expected_hash) = hex::decode(stored_verifier_hash) else {
            return false;
        };

        // constant-time comparison to prevent timing attacks
        provided_hash.ct_eq(&expected_hash[..]).into()
    }
}

/// an api key for authenticating api requests.
///
/// api keys are used for:
/// - CLI automation
/// this struct represents the stored form of an api key. The actual secret
/// is only available at creation time via [`ApiKeySecret`]
///selector portion for database lookup (hex-encoded)
/// this is safe to show in listings
/// is only available at creation time via [`ApiKeySecret`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// used for verification, never shown to users
    pub id: u64,

    /// selector portion for database lookup (hex-encoded).
    /// this is safe to show in listings.
    pub selector: String,

    /// sha-256 hash of the verifier (hex-encoded).
    /// used for verification, never shown to users.
    #[serde(skip_serializing)]
    pub verifier_hash: String,

    /// human-readable name/description for this key.
    pub name: String,

    /// user who owns this key.
    pub user_id: UserId,

    /// when this key expires (none = never).
    pub expiration: Option<DateTime<Utc>>,

    /// when this key was created.
    pub created_at: DateTime<Utc>,

    /// when this key was last used (for auditing).
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// create a new api key from an [`ApiKeySecret`].
    pub fn new(id: u64, secret: &ApiKeySecret, name: String, user_id: UserId) -> Self {
        Self {
            id,
            selector: secret.selector.clone(),
            verifier_hash: secret.verifier_hash.clone(),
            name,
            user_id,
            expiration: None,
            created_at: Utc::now(),
            last_used_at: None,
        }
    }

    /// check if this key is expired.
    pub fn is_expired(&self) -> bool {
        match &self.expiration {
            None => false,
            Some(exp) => Utc::now() > *exp,
        }
    }

    /// check if this key is valid for use.
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// generate a prefix for display.
    /// returns "rsapi_{first 8 chars of selector}" for identification.
    pub fn prefix(&self) -> String {
        let selector_prefix = if self.selector.len() >= 8 {
            &self.selector[..8]
        } else {
            &self.selector
        };
        format!("rsapi_{}", selector_prefix)
    }

    /// verify a user-provided token against this key.
    pub fn verify(&self, token: &str) -> bool {
        ApiKeySecret::verify(token, &self.selector, &self.verifier_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_valid() {
        let secret = ApiKeySecret::generate();
        let key = ApiKey::new(1, &secret, "My Key".to_string(), UserId(1));
        assert!(key.is_valid());
        assert!(!key.is_expired());
    }

    #[test]
    fn test_api_key_expired() {
        let secret = ApiKeySecret::generate();
        let mut key = ApiKey::new(1, &secret, "My Key".to_string(), UserId(1));
        key.expiration = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(key.is_expired());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_api_key_not_expired_with_future_expiration() {
        let secret = ApiKeySecret::generate();
        let mut key = ApiKey::new(1, &secret, "My Key".to_string(), UserId(1));
        key.expiration = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!key.is_expired());
        assert!(key.is_valid());
    }

    #[test]
    fn test_api_key_prefix() {
        let secret = ApiKeySecret::generate();
        let key = ApiKey::new(1, &secret, "My Key".to_string(), UserId(1));
        // prefix is "rsapi_" + first 8 hex chars = 14 chars total
        let prefix = key.prefix();
        assert!(prefix.starts_with("rsapi_"));
        assert_eq!(prefix.len(), 14); // "rsapi_" (6) + 8 hex chars
    }

    #[test]
    fn test_api_key_verify() {
        let secret = ApiKeySecret::generate();
        let key = ApiKey::new(1, &secret, "My Key".to_string(), UserId(1));

        // should verify with the correct full key
        assert!(key.verify(&secret.full_key));

        // should not verify with wrong key
        assert!(!key.verify("rsapi_wrong_key"));
    }

    // split-token api key tests

    #[test]
    fn test_api_key_secret_generate_format() {
        let secret = ApiKeySecret::generate();

        // should have rsapi_ prefix
        assert!(secret.full_key.starts_with("rsapi_"));

        // should have two underscore-separated parts after prefix
        let without_prefix = secret.full_key.strip_prefix("rsapi_").unwrap();
        let parts: Vec<&str> = without_prefix.split('_').collect();
        assert_eq!(parts.len(), 2, "Should have selector_verifier format");

        // selector should be non-empty and match stored selector
        assert!(!secret.selector.is_empty());
        assert_eq!(parts[0], secret.selector);

        // verifier hash should be non-empty (sha-256 = 32 bytes = 64 hex chars)
        assert_eq!(secret.verifier_hash.len(), 64);
    }

    #[test]
    fn test_api_key_secret_verify_valid() {
        let secret = ApiKeySecret::generate();

        // should verify with the correct full key
        assert!(ApiKeySecret::verify(
            &secret.full_key,
            &secret.selector,
            &secret.verifier_hash
        ));
    }

    #[test]
    fn test_api_key_secret_verify_wrong_verifier() {
        let secret = ApiKeySecret::generate();

        // tamper with the verifier portion
        let tampered = format!("rsapi_{}_{}", secret.selector, "wrongverifier123");

        assert!(!ApiKeySecret::verify(
            &tampered,
            &secret.selector,
            &secret.verifier_hash
        ));
    }

    #[test]
    fn test_api_key_secret_verify_wrong_selector() {
        let secret = ApiKeySecret::generate();

        // use a different selector
        assert!(!ApiKeySecret::verify(
            &secret.full_key,
            "wrongselector",
            &secret.verifier_hash
        ));
    }

    #[test]
    fn test_api_key_secret_verify_malformed_token() {
        let secret = ApiKeySecret::generate();

        // missing prefix
        assert!(!ApiKeySecret::verify(
            "not_a_valid_token",
            &secret.selector,
            &secret.verifier_hash
        ));

        // empty string
        assert!(!ApiKeySecret::verify(
            "",
            &secret.selector,
            &secret.verifier_hash
        ));

        // only prefix
        assert!(!ApiKeySecret::verify(
            "rsapi_",
            &secret.selector,
            &secret.verifier_hash
        ));
    }

    #[test]
    fn test_api_key_secret_uniqueness() {
        let secret1 = ApiKeySecret::generate();
        let secret2 = ApiKeySecret::generate();

        // each generation should produce unique values
        assert_ne!(secret1.full_key, secret2.full_key);
        assert_ne!(secret1.selector, secret2.selector);
        assert_ne!(secret1.verifier_hash, secret2.verifier_hash);
    }
}
