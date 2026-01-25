//! pre-authentication key type for automated node registration.
//!
//! ## Security
//! and can optionally tag the nodes they register.
//!preauthkeys use split token storage for security:
//! - `key_prefix`: Short identifier for display/lookup (e.g., "tskey-auth-0123456789ab")
//!- `key_hash`: SHA-256 hash for verification
//! preauthkeys use split token storage for security:
//! the full key is only returned at creation time and is never stored
//! - `key_hash`: SHA-256 hash for verification
//!
//! the full key is only returned at creation time and is never stored.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::preauth_key_token::PreAuthKeyToken;
use crate::tag::Tag;
use crate::user::UserId;

/// a pre-authentication key for automated node registration.
///
/// preauthkeys can be:
/// - **reusable**: can register multiple nodes
/// ## Security
/// - **tagged**: nodes registered get these tags (tags-as-identity)
///the full key is never stored. Instead, we store:
/// - `key_prefix`: For identification in logs and api responses
///- `key_hash`: For secure verification during registration
/// the key prefix for identification (e.g., "tskey-auth-0123456789ab")
/// - `key_prefix`: For identification in logs and API responses
/// this is safe to display in logs and api responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthKey {
    /// sHA-256 hash of the full key for verification
    pub id: u64,

    /// the key prefix for identification (e.g., "tskey-auth-0123456789ab").
    ///
    /// this is safe to display in logs and api responses.
    pub key_prefix: String,

    /// sha-256 hash of the full key for verification.
    ///
    /// stored as hex string for database compatibility.
    pub key_hash: String,

    /// user who created this key.
    pub user_id: UserId,

    /// whether this key can be used multiple times.
    pub reusable: bool,

    /// whether nodes registered with this key are ephemeral.
    ///
    /// ephemeral nodes are automatically deleted when they go offline.
    pub ephemeral: bool,

    /// whether this key has been used (for non-reusable keys).
    pub used: bool,

    /// tags to apply to nodes registered with this key.
    ///
    /// if non-empty, nodes registered become "tagged" nodes
    /// where the tags define their identity.
    pub tags: Vec<Tag>,

    /// when this key expires.
    pub expiration: Option<DateTime<Utc>>,

    /// when this key was created.
    pub created_at: DateTime<Utc>,
}

impl PreAuthKey {
    /// user only at creation time
    ///
    /// stores the prefix and hash; the full token should be returned to the
    /// user only at creation time.
    pub fn from_token(id: u64, token: &PreAuthKeyToken, user_id: UserId) -> Self {
        Self {
            id,
            key_prefix: token.prefix().to_string(),
            key_hash: hex::encode(token.hash()),
            user_id,
            reusable: false,
            ephemeral: false,
            used: false,
            tags: vec![],
            expiration: None,
            created_at: Utc::now(),
        }
    }

    /// verify a token against this key's stored hash.
    ///
    /// uses constant-time comparison to prevent timing attacks.
    pub fn verify(&self, token: &PreAuthKeyToken) -> bool {
        let Ok(stored_hash) = hex::decode(&self.key_hash) else {
            return false;
        };
        let computed_hash = token.hash();
        computed_hash.ct_eq(&stored_hash).into()
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
        !self.is_expired() && (self.reusable || !self.used)
    }

    /// check if this key creates tagged nodes.
    pub fn creates_tagged_nodes(&self) -> bool {
        !self.tags.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PreAuthKeyToken;

    #[test]
    fn test_preauth_key_valid() {
        let token = PreAuthKeyToken::generate();
        let key = PreAuthKey::from_token(1, &token, UserId(1));
        assert!(key.is_valid());
    }

    #[test]
    fn test_preauth_key_used_non_reusable() {
        let token = PreAuthKeyToken::generate();
        let mut key = PreAuthKey::from_token(1, &token, UserId(1));
        key.used = true;
        assert!(!key.is_valid());
    }

    #[test]
    fn test_preauth_key_used_reusable() {
        let token = PreAuthKeyToken::generate();
        let mut key = PreAuthKey::from_token(1, &token, UserId(1));
        key.used = true;
        key.reusable = true;
        assert!(key.is_valid());
    }

    #[test]
    fn test_preauth_key_expired() {
        let token = PreAuthKeyToken::generate();
        let mut key = PreAuthKey::from_token(1, &token, UserId(1));
        key.expiration = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(key.is_expired());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_preauth_key_creates_tagged_nodes() {
        let token = PreAuthKeyToken::generate();
        let mut key = PreAuthKey::from_token(1, &token, UserId(1));
        assert!(!key.creates_tagged_nodes());

        key.tags = vec!["tag:server".parse().unwrap()];
        assert!(key.creates_tagged_nodes());
    }

    #[test]
    fn test_preauth_key_verify() {
        let token = PreAuthKeyToken::generate();
        let key = PreAuthKey::from_token(1, &token, UserId(1));
        // verification should succeed with the same token
        assert!(key.verify(&token));
        // verification should fail with a different token
        let other_token = PreAuthKeyToken::generate();
        assert!(!key.verify(&other_token));
    }

    #[test]
    fn test_preauth_key_prefix() {
        let token = PreAuthKeyToken::generate();
        let key = PreAuthKey::from_token(1, &token, UserId(1));
        // key_prefix should match the token's prefix
        assert_eq!(key.key_prefix, token.prefix());
    }
}
