//! api key type for authenticating api requests
//!
//! api keys allow programmatic access to the railscale api for automation,
//! integrations, and tooling

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::user::UserId;

/// an api key for authenticating api requests
///
/// api keys are used for:
/// - cli automation
/// - External integrations
/// - Programmatic control plane access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// unique identifier
    pub id: u64,

    /// the secret key string used for authentication
    /// only shown once at creation time
    pub key: String,

    /// human-readable name/description for this key
    pub name: String,

    /// user who owns this key
    pub user_id: UserId,

    /// when this key expires (None = never)
    pub expiration: Option<DateTime<Utc>>,

    /// when this key was created
    pub created_at: DateTime<Utc>,

    /// when this key was last used (for auditing)
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// create a new api key
    pub fn new(id: u64, key: String, name: String, user_id: UserId) -> Self {
        Self {
            id,
            key,
            name,
            user_id,
            expiration: None,
            created_at: Utc::now(),
            last_used_at: None,
        }
    }

    /// check if this key is expired
    pub fn is_expired(&self) -> bool {
        match &self.expiration {
            None => false,
            Some(exp) => Utc::now() > *exp,
        }
    }

    /// check if this key is valid for use
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// generate a prefix for display (first 8 chars)
    pub fn prefix(&self) -> &str {
        if self.key.len() >= 8 {
            &self.key[..8]
        } else {
            &self.key
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_valid() {
        let key = ApiKey::new(
            1,
            "test-key-secret".to_string(),
            "My Key".to_string(),
            UserId(1),
        );
        assert!(key.is_valid());
        assert!(!key.is_expired());
    }

    #[test]
    fn test_api_key_expired() {
        let mut key = ApiKey::new(
            1,
            "test-key-secret".to_string(),
            "My Key".to_string(),
            UserId(1),
        );
        key.expiration = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(key.is_expired());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_api_key_not_expired_with_future_expiration() {
        let mut key = ApiKey::new(
            1,
            "test-key-secret".to_string(),
            "My Key".to_string(),
            UserId(1),
        );
        key.expiration = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!key.is_expired());
        assert!(key.is_valid());
    }

    #[test]
    fn test_api_key_prefix() {
        let key = ApiKey::new(
            1,
            "abcdefghijklmnop".to_string(),
            "My Key".to_string(),
            UserId(1),
        );
        assert_eq!(key.prefix(), "abcdefgh");
    }

    #[test]
    fn test_api_key_prefix_short() {
        let key = ApiKey::new(1, "abc".to_string(), "My Key".to_string(), UserId(1));
        assert_eq!(key.prefix(), "abc");
    }
}
