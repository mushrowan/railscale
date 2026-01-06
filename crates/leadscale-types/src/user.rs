//! user type representing a tailscale user/namespace
//!
//! in leadscale (like headscale), users are "bubbles" or namespaces
//! that contain nodes. users can be created via cli or oidc

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// unique identifier for a user
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub u64);

impl UserId {
    /// special user id for tagged devices
    ///
    /// tagged nodes don't belong to a real user - the tag is their identity
    /// used when rendering tagged nodes in the tailscale protocol
    pub const TAGGED_DEVICES: UserId = UserId(2147455555);
}

impl From<u64> for UserId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// leadscale user representing a namespace for nodes
///
/// users can own nodes (non-tagged devices) or create preauthkeys
/// that register tagged devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// unique identifier
    pub id: UserId,

    /// username - used if email is empty
    /// unique if provider_identifier is not set
    pub name: String,

    /// display name - typically the user's full name
    pub display_name: Option<String>,

    /// email address from oidc
    pub email: Option<String>,

    /// provider identifier from oidc (combination of `iss` and `sub` claims)
    /// unique if set
    pub provider_identifier: Option<String>,

    /// provider origin (e.g., "oidc", "cli")
    pub provider: Option<String>,

    /// profile picture url
    pub profile_pic_url: Option<String>,

    /// when the user was created
    pub created_at: DateTime<Utc>,

    /// when the user was last updated
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// create new user with the given name
    pub fn new(id: UserId, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            display_name: None,
            email: None,
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// username to use for display and policy evaluation
    ///
    /// priority: email > name > provider_identifier > id
    pub fn username(&self) -> &str {
        self.email
            .as_deref()
            .or(Some(&self.name))
            .filter(|s| !s.is_empty())
            .or(self.provider_identifier.as_deref())
            .unwrap_or_else(|| {
                // fallback to id string - bit awkward but matches go behavior
                Box::leak(self.id.to_string().into_boxed_str())
            })
    }

    /// display name or falls back to username
    pub fn display(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.username())
    }

    /// tagged devices sentinel user
    ///
    /// used in mapresponse for tagged nodes
    pub fn tagged_devices() -> Self {
        Self {
            id: UserId::TAGGED_DEVICES,
            name: "tagged-devices".to_string(),
            display_name: Some("Tagged Devices".to_string()),
            email: None,
            provider_identifier: None,
            provider: None,
            profile_pic_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_username_priority() {
        let mut user = User::new(UserId(1), "testuser".to_string());

        // name only
        assert_eq!(user.username(), "testuser");

        // email takes priority
        user.email = Some("test@example.com".to_string());
        assert_eq!(user.username(), "test@example.com");
    }

    #[test]
    fn test_user_display() {
        let mut user = User::new(UserId(1), "testuser".to_string());
        assert_eq!(user.display(), "testuser");

        user.display_name = Some("Test User".to_string());
        assert_eq!(user.display(), "Test User");
    }

    #[test]
    fn test_tagged_devices_id() {
        assert_eq!(UserId::TAGGED_DEVICES.0, 2147455555);
    }
}
