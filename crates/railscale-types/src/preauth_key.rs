//! pre-authentication key type for automated node registration
//!
//! preauthkeys allow nodes to register without interactive authentication,
//! and can optionally tag the nodes they register

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::user::UserId;

/// pre-authentication key for automated node registration
///
/// preauthkeys can be:
/// - **reusable**: can register multiple nodes
/// - **ephemeral**: nodes registered with this key are ephemeral
/// - **tagged**: nodes registered get these tags (tags-as-identity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthKey {
    /// unique identifier
    pub id: u64,

    /// key string used for authentication
    pub key: String,

    /// user who created this key
    pub user_id: UserId,

    /// key can be used multiple times
    pub reusable: bool,

    /// nodes registered with this key are ephemeral
    ///
    /// ephemeral nodes are automatically deleted when they go offline
    pub ephemeral: bool,

    /// key has been used (for non-reusable keys)
    pub used: bool,

    /// tags to apply to nodes registered with this key
    ///
    /// if non-empty, nodes registered become "tagged" nodes
    /// where the tags define their identity
    pub tags: Vec<String>,

    /// when this key expires
    pub expiration: Option<DateTime<Utc>>,

    /// when this key was created
    pub created_at: DateTime<Utc>,
}

impl PreAuthKey {
    /// create new pre-auth key
    pub fn new(id: u64, key: String, user_id: UserId) -> Self {
        Self {
            id,
            key,
            user_id,
            reusable: false,
            ephemeral: false,
            used: false,
            tags: vec![],
            expiration: None,
            created_at: Utc::now(),
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
        !self.is_expired() && (self.reusable || !self.used)
    }

    /// check if this key creates tagged nodes
    pub fn creates_tagged_nodes(&self) -> bool {
        !self.tags.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preauth_key_valid() {
        let key = PreAuthKey::new(1, "test-key".to_string(), UserId(1));
        assert!(key.is_valid());
    }

    #[test]
    fn test_preauth_key_used_non_reusable() {
        let mut key = PreAuthKey::new(1, "test-key".to_string(), UserId(1));
        key.used = true;
        assert!(!key.is_valid());
    }

    #[test]
    fn test_preauth_key_used_reusable() {
        let mut key = PreAuthKey::new(1, "test-key".to_string(), UserId(1));
        key.used = true;
        key.reusable = true;
        assert!(key.is_valid());
    }

    #[test]
    fn test_preauth_key_expired() {
        let mut key = PreAuthKey::new(1, "test-key".to_string(), UserId(1));
        key.expiration = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(key.is_expired());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_preauth_key_creates_tagged_nodes() {
        let mut key = PreAuthKey::new(1, "test-key".to_string(), UserId(1));
        assert!(!key.creates_tagged_nodes());

        key.tags = vec!["tag:server".to_string()];
        assert!(key.creates_tagged_nodes());
    }
}
